package search

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/meta/repodb"
)

// UploadPublicKey is the resolver for the UploadPublicKey field.
func (r *mutationResolver) UploadPublicKey(ctx context.Context, input gql_generated.PublicKey) (*gql_generated.UploadResult, error) {
	if input.File.Filename == "" {
		return &gql_generated.UploadResult{Success: false}, errors.New("invalid name of file")
	}

	stream, err := io.ReadAll(input.File.File)
	if err != nil {
		return &gql_generated.UploadResult{Success: false}, err
	}

	const (
		dirPerms  = 0o700
		filePerms = 0o600
	)

	if _, err = os.Stat(repodb.SignaturesDirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(repodb.SignaturesDirPath, dirPerms); err != nil {
			r.log.Error().Err(err).Msg("unable to create signatures dir")

			return &gql_generated.UploadResult{Success: false}, err
		}
	}

	dirPath := path.Join(repodb.SignaturesDirPath, fmt.Sprintf("%s@%s", input.Repo, input.SignedManifest))

	if _, err = os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, dirPerms); err != nil {
			r.log.Error().Err(err).Msgf("unable to create signatures dir for manifest %s", input.SignedManifest)

			return &gql_generated.UploadResult{Success: false}, err
		}
	}

	fileName := godigest.FromBytes(stream).String()
	filePath := path.Join(dirPath, fileName)

	fileErr := os.WriteFile(filePath, stream, filePerms)

	if fileErr != nil {
		return &gql_generated.UploadResult{Success: false}, fileErr
	}

	err = r.repoDB.VerifyManifestSignatures(input.Repo, godigest.Digest(input.SignedManifest))
	if err != nil {
		r.log.Error().Err(err).Msg("unable to verify manifest signatures")

		return &gql_generated.UploadResult{Success: false}, err
	}

	return &gql_generated.UploadResult{Success: true}, nil
}

// CVEListForImage is the resolver for the CVEListForImage field.
func (r *queryResolver) CVEListForImage(ctx context.Context, image string) (*gql_generated.CVEResultForImage, error) {
	return getCVEListForImage(ctx, image, r.cveInfo, r.log)
}

// ImageListForCve is the resolver for the ImageListForCVE field.
func (r *queryResolver) ImageListForCve(ctx context.Context, id string, requestedPage *gql_generated.PageInput) ([]*gql_generated.ImageSummary, error) {
	return getImageListForCVE(ctx, id, r.cveInfo, requestedPage, r.repoDB, r.log)
}

// ImageListWithCVEFixed is the resolver for the ImageListWithCVEFixed field.
func (r *queryResolver) ImageListWithCVEFixed(ctx context.Context, id string, image string, requestedPage *gql_generated.PageInput) ([]*gql_generated.ImageSummary, error) {
	return getImageListWithCVEFixed(ctx, id, image, r.cveInfo, requestedPage, r.repoDB, r.log)
}

// ImageListForDigest is the resolver for the ImageListForDigest field.
func (r *queryResolver) ImageListForDigest(ctx context.Context, id string, requestedPage *gql_generated.PageInput) ([]*gql_generated.ImageSummary, error) {
	r.log.Info().Msg("extracting repositories")

	imgResultForDigest, err := getImageListForDigest(ctx, id, r.repoDB, r.cveInfo, requestedPage)

	return imgResultForDigest, err
}

// RepoListWithNewestImage is the resolver for the RepoListWithNewestImage field.
func (r *queryResolver) RepoListWithNewestImage(ctx context.Context, requestedPage *gql_generated.PageInput) (*gql_generated.PaginatedReposResult, error) {
	r.log.Info().Msg("extension api: finding image list")

	paginatedReposResult, err := repoListWithNewestImage(ctx, r.cveInfo, r.log, requestedPage, r.repoDB)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to retrieve repo list")

		return paginatedReposResult, err
	}

	return paginatedReposResult, nil
}

// ImageList is the resolver for the ImageList field.
func (r *queryResolver) ImageList(ctx context.Context, repo string, requestedPage *gql_generated.PageInput) ([]*gql_generated.ImageSummary, error) {
	r.log.Info().Msg("extension api: getting a list of all images")

	imageList, err := getImageList(ctx, repo, r.repoDB, r.cveInfo, requestedPage, r.log)
	if err != nil {
		r.log.Error().Err(err).Msgf("unable to retrieve image list for repo: %s", repo)
	}

	return imageList, nil
}

// ExpandedRepoInfo is the resolver for the ExpandedRepoInfo field.
func (r *queryResolver) ExpandedRepoInfo(ctx context.Context, repo string) (*gql_generated.RepoInfo, error) {
	repoInfo, err := expandedRepoInfo(ctx, repo, r.repoDB, r.cveInfo, r.log)

	return repoInfo, err
}

// GlobalSearch is the resolver for the GlobalSearch field.
func (r *queryResolver) GlobalSearch(ctx context.Context, query string, filter *gql_generated.Filter, requestedPage *gql_generated.PageInput) (*gql_generated.GlobalSearchResult, error) {
	if err := validateGlobalSearchInput(query, filter, requestedPage); err != nil {
		return &gql_generated.GlobalSearchResult{}, err
	}

	query = cleanQuery(query)
	filter = cleanFilter(filter)

	paginatedReposResult, images, layers, err := globalSearch(ctx, query, r.repoDB, filter, requestedPage, r.cveInfo, r.log)

	return &gql_generated.GlobalSearchResult{
		Page:   paginatedReposResult.Page,
		Images: images,
		Repos:  paginatedReposResult.Results,
		Layers: layers,
	}, err
}

// DependencyListForImage is the resolver for the DependencyListForImage field.
func (r *queryResolver) DerivedImageList(ctx context.Context, image string, requestedPage *gql_generated.PageInput) (*gql_generated.PaginatedImagesResult, error) {
	derivedList, err := derivedImageList(ctx, image, r.repoDB, requestedPage, r.cveInfo, r.log)

	return derivedList, err
}

// BaseImageList is the resolver for the BaseImageList field.
func (r *queryResolver) BaseImageList(ctx context.Context, image string, requestedPage *gql_generated.PageInput) (*gql_generated.PaginatedImagesResult, error) {
	imageList, err := baseImageList(ctx, image, r.repoDB, requestedPage, r.cveInfo, r.log)

	return imageList, err
}

// Image is the resolver for the Image field.
func (r *queryResolver) Image(ctx context.Context, image string) (*gql_generated.ImageSummary, error) {
	repo, tag := common.GetImageDirAndTag(image)

	return getImageSummary(ctx, repo, tag, r.repoDB, r.cveInfo, r.log)
}

// Mutation returns gql_generated.MutationResolver implementation.
func (r *Resolver) Mutation() gql_generated.MutationResolver { return &mutationResolver{r} }

// Query returns gql_generated.QueryResolver implementation.
func (r *Resolver) Query() gql_generated.QueryResolver { return &queryResolver{r} }

type (
	mutationResolver struct{ *Resolver }
	queryResolver    struct{ *Resolver }
)
