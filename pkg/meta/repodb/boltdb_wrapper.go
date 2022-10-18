package repodb

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	bolt "go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

const (
	SignaturesDirPath = "/tmp/zot/signatures"
	SigKey            = "dev.cosignproject.cosign/signature"
	NotationType      = "notation"
	CosignType        = "cosign"
)

type BoltDBParameters struct {
	RootDir string
}

type BoltDBWrapper struct {
	db  *bolt.DB
	log log.Logger
}

func NewBoltDBWrapper(params BoltDBParameters) (*BoltDBWrapper, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "repo.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	err = boltDB.Update(func(transaction *bolt.Tx) error {
		_, err := transaction.CreateBucketIfNotExists([]byte(ManifestDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(RepoMetadataBucket))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &BoltDBWrapper{
		db:  boltDB,
		log: log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (bdw BoltDBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData ManifestData) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestDataBucket))

		mdBlob, err := json.Marshal(manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", manifestDigest)
		}

		err = buck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest data with for digest %s", manifestDigest)
		}

		return nil
	})

	return err
}

func (bdw BoltDBWrapper) GetManifestData(manifestDigest godigest.Digest) (ManifestData, error) {
	var manifestData ManifestData

	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestDataBucket))

		mdBlob := buck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestDataNotFound
		}

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
		}

		return nil
	})

	return manifestData, err
}

func (bdw BoltDBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta ManifestMetadata,
) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		dataBuck := tx.Bucket([]byte(ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMeta := RepoMetadata{
			Name:       repo,
			Tags:       map[string]Descriptor{},
			Statistics: map[string]DescriptorStatistics{},
			Signatures: map[string]ManifestSignatures{},
		}

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}
		}

		mmBlob, err := json.Marshal(ManifestData{
			ManifestBlob: manifestMeta.ManifestBlob,
			ConfigBlob:   manifestMeta.ConfigBlob,
		})
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", manifestDigest)
		}

		err = dataBuck.Put([]byte(manifestDigest), mmBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest meta with for digest %s", manifestDigest)
		}

		updatedRepoMeta := updateManifestMeta(repoMeta, manifestDigest, manifestMeta)

		updatedRepoMetaBlob, err := json.Marshal(updatedRepoMeta)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for updated repo meta '%s'", repo)
		}

		return repoBuck.Put([]byte(repo), updatedRepoMetaBlob)
	})

	return err
}

func updateManifestMeta(repoMeta RepoMetadata, manifestDigest godigest.Digest, manifestMeta ManifestMetadata,
) RepoMetadata {
	updatedRepoMeta := repoMeta

	updatedStatistics := repoMeta.Statistics[manifestDigest.String()]
	updatedStatistics.DownloadCount = manifestMeta.DownloadCount
	updatedRepoMeta.Statistics[manifestDigest.String()] = updatedStatistics

	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = ManifestSignatures{}
	}

	updatedRepoMeta.Signatures[manifestDigest.String()] = manifestMeta.Signatures

	return updatedRepoMeta
}

func (bdw BoltDBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest) (ManifestMetadata, error) {
	var manifestMetadata ManifestMetadata

	err := bdw.db.View(func(tx *bolt.Tx) error {
		dataBuck := tx.Bucket([]byte(ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		mmBlob := dataBuck.Get([]byte(manifestDigest))

		if len(mmBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestData ManifestData

		err := json.Unmarshal(mmBlob, &manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
		}

		var repoMeta RepoMetadata

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err = json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
			}
		}

		manifestMetadata.ManifestBlob = manifestData.ManifestBlob
		manifestMetadata.ConfigBlob = manifestData.ConfigBlob
		manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

		manifestMetadata.Signatures = ManifestSignatures{}

		if repoMeta.Signatures[manifestDigest.String()] != nil {
			manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
		}

		return nil
	})

	return manifestMetadata, err
}

func (bdw BoltDBWrapper) SetRepoTag(repo string, tag string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if err := validateRepoTagInput(repo, tag, manifestDigest); err != nil {
		return err
	}

	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			// create a new object
			repoMeta := RepoMetadata{
				Name: repo,
				Tags: map[string]Descriptor{
					tag: {
						Digest:    manifestDigest.String(),
						MediaType: mediaType,
					},
				},
				Statistics: map[string]DescriptorStatistics{
					manifestDigest.String(): {DownloadCount: 0},
				},
				Signatures: map[string]ManifestSignatures{
					manifestDigest.String(): {},
				},
			}

			repoMetaBlob, err := json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}

		// object found
		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Tags[tag] = Descriptor{
			Digest:    manifestDigest.String(),
			MediaType: mediaType,
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func validateRepoTagInput(repo, tag string, manifestDigest godigest.Digest) error {
	if repo == "" {
		return errors.New("repodb: repo name can't be empty string")
	}

	if tag == "" {
		return errors.New("repodb: tag can't be empty string")
	}

	if manifestDigest == "" {
		return errors.New("repodb: manifest digest can't be empty string")
	}

	return nil
}

func (bdw BoltDBWrapper) GetRepoMeta(repo string) (RepoMetadata, error) {
	var repoMeta RepoMetadata

	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		// object found
		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		return nil
	})

	return repoMeta, err
}

func (bdw BoltDBWrapper) DeleteRepoTag(repo string, tag string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return nil
		}

		// object found
		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		delete(repoMeta.Tags, tag)

		if len(repoMeta.Tags) == 0 {
			return buck.Delete([]byte(repo))
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDBWrapper) IncrementRepoStars(repo string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Stars++

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDBWrapper) DecrementRepoStars(repo string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		if repoMeta.Stars > 0 {
			repoMeta.Stars--
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDBWrapper) GetRepoStars(repo string) (int, error) {
	stars := 0

	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		buck.Get([]byte(repo))
		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		stars = repoMeta.Stars

		return nil
	})

	return stars, err
}

func (bdw BoltDBWrapper) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta RepoMetadata) bool,
	requestedPage PageInput,
) ([]RepoMetadata, error) {
	var (
		foundRepos = make([]RepoMetadata, 0)
		pageFinder PageFinder
	)

	pageFinder, err := NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				pageFinder.Add(DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, _ = pageFinder.Page()

		return nil
	})

	return foundRepos, err
}

func (bdw BoltDBWrapper) IncrementImageDownloads(repo string, reference string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		manifestDigest := reference

		if !referenceIsDigest(reference) {
			// search digest for tag
			descriptor, found := repoMeta.Tags[reference]

			if !found {
				return zerr.ErrManifestMetaNotFound
			}

			manifestDigest = descriptor.Digest
		}

		manifestStatistics := repoMeta.Statistics[manifestDigest]
		manifestStatistics.DownloadCount++
		repoMeta.Statistics[manifestDigest] = manifestStatistics

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func referenceIsDigest(reference string) bool {
	_, err := godigest.Parse(reference)

	return err == nil
}

func (bdw BoltDBWrapper) verifyCosignSignatures(repo string, digest godigest.Digest) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		signatureInfo := []SignatureInfo{}

		layerSigPath := path.Join(SignaturesDirPath, fmt.Sprintf("%s@%s", repo, digest.String()))

		files, err := os.ReadDir(layerSigPath)
		if err != nil {
			return err
		}

		for _, sigInfo := range repoMeta.Signatures[digest.String()][CosignType] {
			layersInfo := []LayerInfo{}

			for _, layerInfo := range sigInfo.LayersInfo {
				signer := ""

				for _, file := range files {
					if !file.IsDir() {
						// cosign verify the image
						ctx := context.Background()
						keyRef := path.Join(layerSigPath, file.Name())
						hashAlgorithm := crypto.SHA256

						pubKey, err := sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, keyRef, hashAlgorithm)
						if err != nil {
							continue
						}

						pkcs11Key, ok := pubKey.(*pkcs11key.Key)
						if ok {
							defer pkcs11Key.Close()
						}

						verifier := pubKey

						b64sig := layerInfo.SignatureKey

						signature, err := base64.StdEncoding.DecodeString(b64sig)
						if err != nil {
							continue
						}

						compressed := io.NopCloser(bytes.NewReader(layerInfo.LayerContent))

						payload, err := io.ReadAll(compressed)
						if err != nil {
							continue
						}

						err = verifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx))

						if err == nil {
							publicKey, err := os.ReadFile(keyRef)
							if err != nil {
								continue
							}

							signer = string(publicKey)

							break
						}
					}
				}

				layerInfo.Signer = strings.TrimSuffix(signer, "\n")
				layersInfo = append(layersInfo, layerInfo)
			}

			signatureInfo = append(signatureInfo, SignatureInfo{
				SignatureManifestDigest: sigInfo.SignatureManifestDigest,
				LayersInfo:              layersInfo,
			})
		}

		repoMeta.Signatures[digest.String()][CosignType] = signatureInfo

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDBWrapper) verifyNotationSignatures() error {
	return nil
}

func (bdw BoltDBWrapper) VerifyManifestSignatures(repo string, manifestDigest godigest.Digest) error {
	notationSigs := false
	cosignSigs := true

	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		buck.Get([]byte(repo))
		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		_, cosignSigs = repoMeta.Signatures[manifestDigest.String()][CosignType]

		_, notationSigs = repoMeta.Signatures[manifestDigest.String()][NotationType]

		return nil
	})
	if err != nil {
		return err
	}

	if cosignSigs {
		err = bdw.verifyCosignSignatures(repo, manifestDigest)
		if err != nil {
			return err
		}
	}

	if notationSigs {
		err = bdw.verifyNotationSignatures()
	}

	return err
}

func (bdw BoltDBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta SignatureMetadata,
) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		var (
			manifestSignatures ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			manifestSignatures = ManifestSignatures{}
		}

		signatureSlice := manifestSignatures[sygMeta.SignatureType]
		if !signatureAlreadyExists(signatureSlice, sygMeta) {
			if sygMeta.SignatureType == NotationType {
				signatureSlice = append(signatureSlice, SignatureInfo{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				})
			} else if sygMeta.SignatureType == CosignType {
				signatureSlice = []SignatureInfo{{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				}}
			}
		}

		manifestSignatures[sygMeta.SignatureType] = signatureSlice

		repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func signatureAlreadyExists(signatureSlice []SignatureInfo, sm SignatureMetadata) bool {
	for _, sigInfo := range signatureSlice {
		if sm.SignatureDigest == sigInfo.SignatureManifestDigest {
			return true
		}
	}

	return false
}

func (bdw BoltDBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta SignatureMetadata,
) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		sigType := sigMeta.SignatureType

		var (
			manifestSignatures ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			return zerr.ErrManifestMetaNotFound
		}

		signatureSlice := manifestSignatures[sigType]

		newSignatureSlice := make([]SignatureInfo, 0, len(signatureSlice)-1)

		for _, sigDigest := range signatureSlice {
			if sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest {
				newSignatureSlice = append(newSignatureSlice, sigDigest)
			}
		}

		manifestSignatures[sigType] = newSignatureSlice

		repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDBWrapper) SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, PageInfo, error) {
	var (
		foundRepos               = make([]RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]ManifestMetadata)
		pageFinder               PageFinder
		pageInfo                 PageInfo
	)

	pageFinder, err := NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, PageInfo{}, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(ManifestDataBucket))
		)

		cursor := repoBuck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			var repoMeta RepoMetadata

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if score := ScoreRepoName(searchText, string(repoName)); score != -1 {
				var (
					// specific values used for sorting that need to be calculated based on all manifests from the repo
					repoDownloads     = 0
					repoLastUpdated   time.Time
					firstImageChecked = true
					osSet             = map[string]bool{}
					archSet           = map[string]bool{}
					isSigned          = false
				)

				for _, descriptor := range repoMeta.Tags {
					var manifestMeta ManifestMetadata

					manifestMeta, manifestDownloaded := manifestMetadataMap[descriptor.Digest]

					if !manifestDownloaded {
						manifestMetaBlob := manifestBuck.Get([]byte(descriptor.Digest))
						if manifestMetaBlob == nil {
							return zerr.ErrManifestMetaNotFound
						}

						err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmarshaling manifest metadata for digest %s", descriptor.Digest)
						}
					}

					// get fields related to filtering
					var configContent ispec.Image

					err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmarshaling config content for digest %s", descriptor.Digest)
					}

					osSet[configContent.OS] = true
					archSet[configContent.Architecture] = true

					// get fields related to sorting
					repoDownloads += repoMeta.Statistics[descriptor.Digest].DownloadCount

					imageLastUpdated, err := getImageLastUpdatedTimestamp(manifestMeta.ConfigBlob)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmarshaling image config referenced by digest %s",
							descriptor.Digest)
					}

					if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
						repoLastUpdated = imageLastUpdated
						firstImageChecked = false

						isSigned = checkIsSigned(repoMeta.Signatures[descriptor.Digest])
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				}

				repoFilterData := filterData{
					OsList:   getMapKeys(osSet),
					ArchList: getMapKeys(archSet),
					IsSigned: isSigned,
				}

				if !acceptedByFilter(filter, repoFilterData) {
					continue
				}

				pageFinder.Add(DetailedRepoMeta{
					RepoMeta:   repoMeta,
					Score:      score,
					Downloads:  repoDownloads,
					UpdateTime: repoLastUpdated,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, manifestDigest := range repoMeta.Tags {
				foundManifestMetadataMap[manifestDigest.Digest] = manifestMetadataMap[manifestDigest.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func checkIsSigned(signatures ManifestSignatures) bool {
	for _, signatures := range signatures {
		if len(signatures) > 0 {
			return true
		}
	}

	return false
}

func ScoreRepoName(searchText string, repoName string) int {
	searchTextSlice := strings.Split(searchText, "/")
	repoNameSlice := strings.Split(repoName, "/")

	if len(searchTextSlice) > len(repoNameSlice) {
		return -1
	}

	if len(searchTextSlice) == 1 {
		// check if it maches first or last name in path
		if index := strings.Index(repoNameSlice[len(repoNameSlice)-1], searchTextSlice[0]); index != -1 {
			return index + 1
		}

		// we'll make repos that match the first name in path less important than matching the last name in path
		if index := strings.Index(repoNameSlice[0], searchTextSlice[0]); index != -1 {
			return (index + 1) * 10
		}

		return -1
	}

	if len(searchTextSlice) < len(repoNameSlice) &&
		strings.HasPrefix(repoName, searchText) {
		return 1
	}

	// searchText and repoName match perfectly up until the last name in path
	for i := 0; i < len(searchTextSlice)-1; i++ {
		if searchTextSlice[i] != repoNameSlice[i] {
			return -1
		}
	}

	// check the last
	if index := strings.Index(repoNameSlice[len(repoNameSlice)-1], searchTextSlice[len(searchTextSlice)-1]); index != -1 {
		return (index + 1)
	}

	return -1
}

func (bdw BoltDBWrapper) FilterTags(ctx context.Context, filter FilterFunc,
	requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, PageInfo, error) {
	var (
		foundRepos               = make([]RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]ManifestMetadata)
		pageFinder               *ImagePageFinder
		pageInfo                 PageInfo
	)

	pageFinder, err := NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, PageInfo{}, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(ManifestDataBucket))
			cursor              = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.First()

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			matchedTags := make(map[string]Descriptor)
			// take all manifestMetas
			for tag, descriptor := range repoMeta.Tags {
				manifestDigest := descriptor.Digest
				matchedTags[tag] = descriptor

				// in case tags reference the same manifest we don't download from DB multiple times
				if manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]; manifestExists {
					manifestMetadataMap[manifestDigest] = manifestMeta

					continue
				}

				manifestMetaBlob := manifestBuck.Get([]byte(manifestDigest))
				if manifestMetaBlob == nil {
					return zerr.ErrManifestMetaNotFound
				}

				var manifestMeta ManifestMetadata

				err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
				if err != nil {
					return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				if !filter(repoMeta, manifestMeta) {
					delete(matchedTags, tag)
					delete(manifestMetadataMap, manifestDigest)

					continue
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func (bdw BoltDBWrapper) SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, PageInfo, error) {
	var (
		foundRepos               = make([]RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]ManifestMetadata)
		pageInfo                 PageInfo

		pageFinder *ImagePageFinder
	)

	pageFinder, err := NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, PageInfo{}, err
	}

	searchedRepo, searchedTag, err := getRepoTag(searchText)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, PageInfo{},
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(ManifestDataBucket))
			cursor              = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.Seek([]byte(searchedRepo))

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if string(repoName) == searchedRepo {
				matchedTags := make(map[string]Descriptor)
				// take all manifestMetas
				for tag, descriptor := range repoMeta.Tags {
					if !strings.HasPrefix(tag, searchedTag) {
						continue
					}

					matchedTags[tag] = descriptor

					// in case tags reference the same manifest we don't download from DB multiple times
					if manifestMeta, manifestExists := manifestMetadataMap[descriptor.Digest]; manifestExists {
						manifestMetadataMap[descriptor.Digest] = manifestMeta

						continue
					}

					manifestMetaBlob := manifestBuck.Get([]byte(descriptor.Digest))
					if manifestMetaBlob == nil {
						return zerr.ErrManifestMetaNotFound
					}

					var manifestMeta ManifestMetadata

					err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
					}

					var configContent ispec.Image

					err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
					}

					imageFilterData := filterData{
						OsList:   []string{configContent.OS},
						ArchList: []string{configContent.Architecture},
						IsSigned: false,
					}

					if !acceptedByFilter(filter, imageFilterData) {
						delete(matchedTags, tag)
						delete(manifestMetadataMap, descriptor.Digest)

						continue
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				}

				if len(matchedTags) == 0 {
					continue
				}

				repoMeta.Tags = matchedTags

				pageFinder.Add(DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

// acceptedByFilter checks that data contains at least 1 element of each filter
// criteria(os, arch) present in filter.
func acceptedByFilter(filter Filter, data filterData) bool {
	if filter.Arch != nil {
		foundArch := false
		for _, arch := range filter.Arch {
			foundArch = foundArch || containsString(data.ArchList, *arch)
		}

		if !foundArch {
			return false
		}
	}

	if filter.Os != nil {
		foundOs := false
		for _, os := range filter.Os {
			foundOs = foundOs || containsString(data.OsList, *os)
		}

		if !foundOs {
			return false
		}
	}

	if filter.HasToBeSigned != nil && *filter.HasToBeSigned != data.IsSigned {
		return false
	}

	return true
}

func containsString(strSlice []string, str string) bool {
	for _, val := range strSlice {
		if strings.EqualFold(val, str) {
			return true
		}
	}

	return false
}

func (bdw BoltDBWrapper) SearchDigests(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw BoltDBWrapper) SearchLayers(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw BoltDBWrapper) SearchForAscendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw BoltDBWrapper) SearchForDescendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func repoIsUserAvailable(ctx context.Context, repoName string) (bool, error) {
	authzCtxKey := localCtx.GetContextKey()

	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, ok := authCtx.(localCtx.AccessControlContext)
		if !ok {
			err := zerr.ErrBadCtxFormat

			return false, err
		}

		if acCtx.IsAdmin || matchesRepo(acCtx.GlobPatterns, repoName) {
			return true, nil
		}

		return false, nil
	}

	return true, nil
}

// returns either a user has or not rights on 'repository'.
func matchesRepo(globPatterns map[string]bool, repository string) bool {
	var longestMatchedPattern string

	// because of the longest path matching rule, we need to check all patterns from config
	for pattern := range globPatterns {
		matched, err := glob.Match(pattern, repository)
		if err == nil {
			if matched && len(pattern) > len(longestMatchedPattern) {
				longestMatchedPattern = pattern
			}
		}
	}

	allowed := globPatterns[longestMatchedPattern]

	return allowed
}

func getRepoTag(searchText string) (string, string, error) {
	const repoTagCount = 2

	splitSlice := strings.Split(searchText, ":")

	if len(splitSlice) != repoTagCount {
		return "", "", errors.New("invalid format for tag search, not following repo:tag")
	}

	repo := strings.TrimSpace(splitSlice[0])
	tag := strings.TrimSpace(splitSlice[1])

	return repo, tag, nil
}

func getMapKeys[K comparable, V any](genericMap map[K]V) []K {
	keys := make([]K, 0, len(genericMap))

	for k := range genericMap {
		keys = append(keys, k)
	}

	return keys
}

func getImageLastUpdatedTimestamp(configBlob []byte) (time.Time, error) {
	var (
		configContent ispec.Image
		timeStamp     *time.Time
	)

	err := json.Unmarshal(configBlob, &configContent)
	if err != nil {
		return time.Time{}, err
	}

	if configContent.Created != nil && !configContent.Created.IsZero() {
		return *configContent.Created, nil
	}

	if len(configContent.History) != 0 {
		timeStamp = configContent.History[len(configContent.History)-1].Created
	}

	if timeStamp == nil {
		timeStamp = &time.Time{}
	}

	return *timeStamp, nil
}
