//go:build !imagetrust
// +build !imagetrust

package imagetrust

import (
	"time"

	godigest "github.com/opencontainers/go-digest"

	mTypes "zotregistry.io/zot/pkg/meta/types"
)

func NewLocalSigStore(dir string) (mTypes.SignatureStorage, error) {
	return &imageTrustDisabled{}, nil
}

func NewCloudSigStore(region, endpoint string) (mTypes.SignatureStorage, error) {
	return &imageTrustDisabled{}, nil
}

type imageTrustDisabled struct{}

func (sigStore *imageTrustDisabled) VerifySignature(
	signatureType string, rawSignature []byte, sigKey string, manifestDigest godigest.Digest, manifestContent []byte,
	repo string,
) (string, time.Time, bool, error) {
	return "", time.Time{}, false, nil
}
