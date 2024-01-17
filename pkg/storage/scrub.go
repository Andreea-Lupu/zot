package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
)

const (
	colImageNameIndex = iota
	colTagIndex
	colStatusIndex
	colAffectedBlobIndex
	colErrorIndex

	imageNameWidth    = 32
	tagWidth          = 24
	statusWidth       = 8
	affectedBlobWidth = 24
	errorWidth        = 8
)

type ScrubImageResult struct {
	ImageName    string `json:"imageName"`
	Tag          string `json:"tag"`
	Status       string `json:"status"`
	AffectedBlob string `json:"affectedBlob"`
	Error        string `json:"error"`
}

type ScrubResults struct {
	ScrubResults []ScrubImageResult `json:"scrubResults"`
}

func (sc StoreController) CheckAllBlobsIntegrity(ctx context.Context) (ScrubResults, error) {
	results := ScrubResults{}

	imageStoreList := make(map[string]storageTypes.ImageStore)
	if sc.SubStore != nil {
		imageStoreList = sc.SubStore
	}

	imageStoreList[""] = sc.DefaultStore

	for _, imgStore := range imageStoreList {
		imgStoreResults, err := CheckImageStoreBlobsIntegrity(ctx, imgStore)
		if err != nil {
			return results, err
		}

		results.ScrubResults = append(results.ScrubResults, imgStoreResults...)
	}

	return results, nil
}

func CheckImageStoreBlobsIntegrity(ctx context.Context, imgStore storageTypes.ImageStore) ([]ScrubImageResult, error) {
	results := []ScrubImageResult{}

	repos, err := imgStore.GetRepositories()
	if err != nil {
		return results, err
	}

	for _, repo := range repos {
		imageResults, err := CheckRepo(ctx, repo, imgStore)
		if err != nil {
			return results, err
		}

		results = append(results, imageResults...)
	}

	return results, nil
}

func CheckRepo(ctx context.Context, imageName string, imgStore storageTypes.ImageStore) ([]ScrubImageResult, error) {
	results := []ScrubImageResult{}

	indexContent, err := getIndex(imgStore, imageName)
	if err != nil {
		return results, err
	}

	var index ispec.Index
	if err := json.Unmarshal(indexContent, &index); err != nil {
		return results, errors.ErrRepoNotFound
	}

	scrubbedManifests := make(map[godigest.Digest]ScrubImageResult)

	for _, manifest := range index.Manifests {
		if common.IsContextDone(ctx) {
			return results, ctx.Err()
		}

		checkImage(ctx, manifest, imgStore, imageName, scrubbedManifests)

		if manifestRes, ok := scrubbedManifests[manifest.Digest]; ok {
			results = append(results, manifestRes)
		}
	}

	return results, nil
}

func checkImage(
	ctx context.Context, manifest ispec.Descriptor, imgStore storageTypes.ImageStore, imageName string,
	scrubbedManifests map[godigest.Digest]ScrubImageResult,
) {
	var lockLatency time.Time

	imgStore.RLock(&lockLatency)
	defer imgStore.RUnlock(&lockLatency)

	tag := manifest.Annotations[ispec.AnnotationRefName]

	buf, err := imgStore.GetBlobContent(imageName, manifest.Digest)
	if err != nil {
		// ignore if the manifest is not found(probably it was deleted after we got the list of manifests)
		return
	}

	scrubManifest(ctx, manifest, imgStore, imageName, tag, buf, scrubbedManifests)
}

func scrubManifest(
	ctx context.Context, manifest ispec.Descriptor, imgStore storageTypes.ImageStore, imageName, tag string,
	manifestContent []byte, scrubbedManifests map[godigest.Digest]ScrubImageResult,
) {
	res, ok := scrubbedManifests[manifest.Digest]
	if ok {
		scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, res.Status,
			res.AffectedBlob, res.Error)

		return
	}

	switch manifest.MediaType {
	case ispec.MediaTypeImageIndex:
		var idx ispec.Index
		if err := json.Unmarshal(manifestContent, &idx); err != nil {
			imgRes := getResult(imageName, tag, manifest.Digest, errors.ErrBadBlobDigest)
			scrubbedManifests[manifest.Digest] = imgRes

			return
		}

		// check all manifests
		for _, man := range idx.Manifests {
			buf, err := imgStore.GetBlobContent(imageName, man.Digest)
			if err != nil {
				imgRes := getResult(imageName, tag, man.Digest, err)
				scrubbedManifests[man.Digest] = imgRes

				continue
			}

			scrubManifest(ctx, man, imgStore, imageName, tag, buf, scrubbedManifests)

			// if the manifest is affected then this index is also affected
			if mRes, ok := scrubbedManifests[man.Digest]; ok && mRes.Error != "" {
				scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, mRes.Status,
					mRes.AffectedBlob, mRes.Error)

				return
			}
		}

		// at this point, before starting to check the subject we can consider the index is ok
		scrubbedManifests[manifest.Digest] = getResult(imageName, tag, "", nil)

		// check subject if exists
		if idx.Subject != nil {
			buf, err := imgStore.GetBlobContent(imageName, idx.Subject.Digest)
			if err != nil {
				imgRes := getResult(imageName, tag, idx.Subject.Digest, err)
				scrubbedManifests[idx.Subject.Digest] = imgRes

				return
			}

			scrubManifest(ctx, *idx.Subject, imgStore, imageName, tag, buf, scrubbedManifests)

			if subjectRes, ok := scrubbedManifests[idx.Subject.Digest]; ok {
				scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, subjectRes.Status,
					subjectRes.AffectedBlob, subjectRes.Error)
			}
		}
	case ispec.MediaTypeImageManifest:
		imgRes := CheckIntegrity(ctx, imageName, tag, manifest, manifestContent, imgStore)
		scrubbedManifests[manifest.Digest] = imgRes

		// if integrity ok then check subject if exists
		if imgRes.Error == "" {
			manifestContent, _ := imgStore.GetBlobContent(imageName, manifest.Digest)

			var man ispec.Manifest

			_ = json.Unmarshal(manifestContent, &man)

			if man.Subject != nil {
				buf, err := imgStore.GetBlobContent(imageName, man.Subject.Digest)
				if err != nil {
					imgRes := getResult(imageName, tag, man.Subject.Digest, err)
					scrubbedManifests[man.Subject.Digest] = imgRes

					return
				}

				scrubManifest(ctx, *man.Subject, imgStore, imageName, tag, buf, scrubbedManifests)

				if subjectRes, ok := scrubbedManifests[man.Subject.Digest]; ok {
					scrubbedManifests[manifest.Digest] = newScrubImageResult(imageName, tag, subjectRes.Status,
						subjectRes.AffectedBlob, subjectRes.Error)
				}
			}
		}
	default:
		scrubbedManifests[manifest.Digest] = getResult(imageName, tag, manifest.Digest, errors.ErrBadManifest)
	}
}

func CheckIntegrity(
	ctx context.Context, imageName, tagName string, manifest ispec.Descriptor, manifestContent []byte,
	imgStore storageTypes.ImageStore,
) ScrubImageResult {
	// check manifest and config
	if affectedBlob, err := CheckManifestAndConfig(imageName, manifest, manifestContent, imgStore); err != nil {
		return getResult(imageName, tagName, affectedBlob, err)
	}

	// check layers
	return CheckLayers(ctx, imageName, tagName, manifest, manifestContent, imgStore)
}

func CheckManifestAndConfig(
	imageName string, manifestDesc ispec.Descriptor, manifestContent []byte, imgStore storageTypes.ImageStore,
) (godigest.Digest, error) {
	// Q oras artifacts?
	if manifestDesc.MediaType != ispec.MediaTypeImageManifest {
		return manifestDesc.Digest, errors.ErrBadManifest
	}

	var manifest ispec.Manifest

	err := json.Unmarshal(manifestContent, &manifest)
	if err != nil {
		return manifestDesc.Digest, errors.ErrBadManifest
	}

	configContent, err := imgStore.GetBlobContent(imageName, manifest.Config.Digest)
	if err != nil {
		return manifest.Config.Digest, err
	}

	var config ispec.Image

	err = json.Unmarshal(configContent, &config)
	if err != nil {
		return manifest.Config.Digest, errors.ErrBadConfig
	}

	return "", nil
}

func CheckLayers(
	ctx context.Context, imageName, tagName string, manifest ispec.Descriptor, manifestContent []byte,
	imgStore storageTypes.ImageStore,
) ScrubImageResult {
	imageRes := ScrubImageResult{}

	var man ispec.Manifest
	if err := json.Unmarshal(manifestContent, &man); err != nil {
		imageRes = getResult(imageName, tagName, manifest.Digest, errors.ErrBadManifest)

		return imageRes
	}

	for _, layer := range man.Layers {
		if err := imgStore.VerifyBlobDigestValue(imageName, layer.Digest); err != nil {
			imageRes = getResult(imageName, tagName, layer.Digest, err)

			break
		}

		imageRes = getResult(imageName, tagName, "", nil)
	}

	return imageRes
}

func getIndex(imgStore storageTypes.ImageStore, imageName string) ([]byte, error) {
	var lockLatency time.Time

	imgStore.RLock(&lockLatency)
	defer imgStore.RUnlock(&lockLatency)

	// check image structure / layout
	ok, err := imgStore.ValidateRepo(imageName)
	if err != nil {
		return []byte{}, err
	}

	if !ok {
		return []byte{}, errors.ErrRepoBadLayout
	}

	// check "index.json" content
	indexContent, err := imgStore.GetIndexContent(imageName)
	if err != nil {
		return []byte{}, err
	}

	return indexContent, nil
}

func getResult(imageName, tag string, affectedBlobDigest godigest.Digest, err error) ScrubImageResult {
	if err != nil {
		return newScrubImageResult(imageName, tag, "affected", affectedBlobDigest.Encoded(), err.Error())
	}

	return newScrubImageResult(imageName, tag, "ok", "", "")
}

func newScrubImageResult(imageName, tag, status, affectedBlob, err string) ScrubImageResult {
	return ScrubImageResult{
		ImageName:    imageName,
		Tag:          tag,
		Status:       status,
		AffectedBlob: affectedBlob,
		Error:        err,
	}
}

func getScrubTableWriter(writer io.Writer) *tablewriter.Table {
	table := tablewriter.NewWriter(writer)

	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
	table.SetColMinWidth(colImageNameIndex, imageNameWidth)
	table.SetColMinWidth(colTagIndex, tagWidth)
	table.SetColMinWidth(colStatusIndex, statusWidth)
	table.SetColMinWidth(colErrorIndex, affectedBlobWidth)
	table.SetColMinWidth(colErrorIndex, errorWidth)

	return table
}

const tableCols = 5

func printScrubTableHeader(writer io.Writer) {
	table := getScrubTableWriter(writer)

	row := make([]string, tableCols)

	row[colImageNameIndex] = "REPOSITORY"
	row[colTagIndex] = "TAG"
	row[colStatusIndex] = "STATUS"
	row[colAffectedBlobIndex] = "AFFECTED BLOB"
	row[colErrorIndex] = "ERROR"

	table.Append(row)
	table.Render()
}

func printImageResult(imageResult ScrubImageResult) string {
	var builder strings.Builder

	table := getScrubTableWriter(&builder)
	table.SetColMinWidth(colImageNameIndex, imageNameWidth)
	table.SetColMinWidth(colTagIndex, tagWidth)
	table.SetColMinWidth(colStatusIndex, statusWidth)
	table.SetColMinWidth(colAffectedBlobIndex, affectedBlobWidth)
	table.SetColMinWidth(colErrorIndex, errorWidth)

	row := make([]string, tableCols)

	row[colImageNameIndex] = imageResult.ImageName
	row[colTagIndex] = imageResult.Tag
	row[colStatusIndex] = imageResult.Status
	row[colAffectedBlobIndex] = imageResult.AffectedBlob
	row[colErrorIndex] = imageResult.Error

	table.Append(row)
	table.Render()

	return builder.String()
}

func (results ScrubResults) PrintScrubResults(resultWriter io.Writer) {
	var builder strings.Builder

	printScrubTableHeader(&builder)
	fmt.Fprint(resultWriter, builder.String())

	for _, res := range results.ScrubResults {
		imageResult := printImageResult(res)
		fmt.Fprint(resultWriter, imageResult)
	}
}
