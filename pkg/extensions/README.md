
## Adding new extensions

As new requirements come and build time extensions need to be added, there are a few things that you have to make sure are present before commiting :

- files that should be included in the binary only with a specific extension must contain the following syntax at the beginning of the file :

//go:build sync will be added automatically by the linter, so only the second line is mandatory .

NOTE: the third line in the example should be blank, otherwise the build tag would be just another comment.

```
//go:build sync
// +build sync

package extensions
...................
```

- when adding a new tag, specify the new order in which multiple tags should be used (bottom of this page)

- for each and every new file that contains functions (functionalities) specific to an extension, one should create a corresponding file that  <b>must contain the exact same functions, but no functionalities included</b>. This file must begin with an  "anti-tag" (e.g. // +build !sync) which will include this file in binaries that don't include this extension ( in this example, the file won't be used in binaries that include sync extension ). See [extension-sync-disabled.go](extension-sync-disabled.go) for an example.

- when a new extension comes out, the developer should also write some blackbox tests, where a binary that contains the new extension should be tested in a real usage scenario. See [test/blackbox](test/blackbox/sync.bats) folder for multiple extensions examples.

- newly added blackbox tests should have targets in Makefile. You should also add them as Github Workflows, in [.github/workflows/ecosystem-tools.yaml](.github/workflows/ecosystem-tools.yaml)

- with every new extension, you should modify the EXTENSIONS variable in Makefile by adding the new extension. The EXTENSIONS variable represents all extensions and is used in Make targets that require them all (e.g make test).

- the available extensions that can be used at the moment are: <b>sync, scrub, metrics, search, ui_base </b>.
NOTE: When multiple extensions are used, they should be enlisted in the above presented order.
