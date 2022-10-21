package repodb_test

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/meta/repodb"
)

func TestPagination(t *testing.T) {
	Convey("Repo Pagination", t, func() {
		Convey("reset", func() {
			paginator, err := repodb.NewBaseRepoPageFinder(1, 0, repodb.AlphabeticAsc)
			So(err, ShouldBeNil)
			So(paginator, ShouldNotBeNil)

			paginator.Add(repodb.DetailedRepoMeta{})
			paginator.Add(repodb.DetailedRepoMeta{})
			paginator.Add(repodb.DetailedRepoMeta{})

			paginator.Reset()

			result, _ := paginator.Page()
			So(result, ShouldBeEmpty)
		})
	})

	Convey("Image Pagination", t, func() {
		Convey("create new paginator errors", func() {
			paginator, err := repodb.NewBaseImagePageFinder(-1, 10, repodb.AlphabeticAsc)
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)

			paginator, err = repodb.NewBaseImagePageFinder(2, -1, repodb.AlphabeticAsc)
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)

			paginator, err = repodb.NewBaseImagePageFinder(2, 1, "wrong sorting criteria")
			So(paginator, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})

		Convey("Reset", func() {
			paginator, err := repodb.NewBaseImagePageFinder(1, 0, repodb.AlphabeticAsc)
			So(err, ShouldBeNil)
			So(paginator, ShouldNotBeNil)

			paginator.Add(repodb.DetailedRepoMeta{})
			paginator.Add(repodb.DetailedRepoMeta{})
			paginator.Add(repodb.DetailedRepoMeta{})

			paginator.Reset()

			result, _ := paginator.Page()
			So(result, ShouldBeEmpty)
		})

		Convey("Page", func() {
			Convey("no limit or offset", func() {
				paginator, err := repodb.NewBaseImagePageFinder(0, 0, repodb.AlphabeticAsc)
				So(err, ShouldBeNil)
				So(paginator, ShouldNotBeNil)

				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo1",
						Tags: map[string]repodb.Descriptor{
							"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
						},
					},
				})

				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo2",
						Tags: map[string]repodb.Descriptor{
							"Tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
							"Tag2": {Digest: "dig2", MediaType: ispec.MediaTypeImageManifest},
							"Tag3": {Digest: "dig3", MediaType: ispec.MediaTypeImageManifest},
							"Tag4": {Digest: "dig4", MediaType: ispec.MediaTypeImageManifest},
						},
					},
				})
				_, pageInfo := paginator.Page()
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 5)
			})
			Convey("limit < len(tags)", func() {
				paginator, err := repodb.NewBaseImagePageFinder(5, 2, repodb.AlphabeticAsc)
				So(err, ShouldBeNil)
				So(paginator, ShouldNotBeNil)

				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo1",
						Tags: map[string]repodb.Descriptor{
							"tag1": {
								Digest:    "dig1",
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					},
				})

				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo2",
						Tags: map[string]repodb.Descriptor{
							"Tag1": {
								Digest:    "dig1",
								MediaType: ispec.MediaTypeImageManifest,
							},
							"Tag2": {
								Digest:    "dig2",
								MediaType: ispec.MediaTypeImageManifest,
							},
							"Tag3": {
								Digest:    "dig3",
								MediaType: ispec.MediaTypeImageManifest,
							},
							"Tag4": {
								Digest:    "dig4",
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					},
				})
				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo3",
						Tags: map[string]repodb.Descriptor{
							"Tag11": {
								Digest:    "dig11",
								MediaType: ispec.MediaTypeImageManifest,
							},
							"Tag12": {
								Digest:    "dig12",
								MediaType: ispec.MediaTypeImageManifest,
							},
							"Tag13": {
								Digest:    "dig13",
								MediaType: ispec.MediaTypeImageManifest,
							},
							"Tag14": {
								Digest:    "dig14",
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					},
				})

				result, pageInfo := paginator.Page()
				So(result[0].Tags, ShouldContainKey, "Tag2")
				So(result[0].Tags, ShouldContainKey, "Tag3")
				So(result[0].Tags, ShouldContainKey, "Tag4")
				So(result[1].Tags, ShouldContainKey, "Tag11")
				So(result[1].Tags, ShouldContainKey, "Tag12")
				So(pageInfo.ItemCount, ShouldEqual, 5)
				So(pageInfo.TotalCount, ShouldEqual, 9)
			})

			Convey("limit > len(tags)", func() {
				paginator, err := repodb.NewBaseImagePageFinder(3, 0, repodb.AlphabeticAsc)
				So(err, ShouldBeNil)
				So(paginator, ShouldNotBeNil)

				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo1",
						Tags: map[string]repodb.Descriptor{
							"tag1": {
								Digest:    "dig1",
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					},
				})

				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo2",
						Tags: map[string]repodb.Descriptor{
							"Tag1": {
								Digest:    "dig1",
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					},
				})
				paginator.Add(repodb.DetailedRepoMeta{
					RepoMeta: repodb.RepoMetadata{
						Name: "repo3",
						Tags: map[string]repodb.Descriptor{
							"Tag11": {
								Digest:    "dig11",
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					},
				})

				result, _ := paginator.Page()
				So(result[0].Tags, ShouldContainKey, "tag1")
				So(result[1].Tags, ShouldContainKey, "Tag1")
				So(result[2].Tags, ShouldContainKey, "Tag11")
			})
		})
	})
}
