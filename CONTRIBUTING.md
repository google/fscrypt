# How to Contribute to fscrypt

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines we ask you to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution,
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Reporting an Issue, Discussing Design, or Asking a Question

__IMPORTANT__: Any significant security issues should __NOT__ be reported in
the public issue tracker. Practice responsible disclosure by emailing
<joerichey@google.com> and <tyhicks@canonical.com> directly.

Any bugs, problems, or design discussion relating to fscrypt should be raised
in the [Github Issue Tracker](https://github.com/google/fscrypt/issues/new).

When reporting an issue or problem, be sure to give as much information as
possible. Also, make sure you are running the `fscrypt` and `pam_fscrypt.so`
built from the current `master` branch.

If reporting an issue around the fscrypt command-line tool, post the
relevant output from fscrypt, running with the `--verbose` flag. For the
`pam_fscrypt` module, use the `debug` option with the module and post the
relevant parts of the syslog (usually at `/var/log/syslog`).

Be sure to correctly tag your issue. The usage for the tags is as follows:
* `bug` - General problems with the program's behavior
	* The program crashes or hangs
	* Directories cannot be locked/unlocked
	* Metadata corruption
	* Data loss/corruption
* `documentation`
	* Typos or unclear explanations in `README.md` or man pages.
	* Outdated example output
	* Unclear or ambiguous error messages
* `enhancement` - Things you want in fscrypt
* `question` - You don't know how something works with fscrypt
	* This usually turns into a `documentation` issue.
* `testing` - Strange test failures or missing tests

## Submitting a Change to fscrypt

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

On every pull request, [Travis CI](https://travis-ci.org/google/fscrypt) runs
unit tests, integration tests, code formatters, and linters. To pass these
checks you should make sure that in your submission:
- `make` properly builds `fscrypt` and `pam_fscrypt.so`.
- All tests, including [integration tests](#running-integration-tests), should pass.
- `make format` has been run.
- If you made any changes to files ending in `.proto`, the corresponding
  `.pb.go` files should be regenerated with `make gen`.
- Any issues found by `make lint` have been addressed.
- If any dependencies have changed, run `go mod tidy` and `go mod vendor`.
- `make coverage.out` can be used to generate a coverage report for all of the
  tests, but isn't required for submission
  (ideally most code would be tested, we are far from that ideal).

Essentially, if you run:
```
make test-setup
make all
make test-teardown
go mod tidy
go mod vendor
```
and everything succeeds, and no files are changed, you're good to submit.

The `Makefile` should automatically download and build whatever it needs.
The only exceptions to this rule are:
  - `make format` requires
    [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html).
  - `make test-setup` requires
    [`e2fsprogs`](https://en.wikipedia.org/wiki/E2fsprogs) version 1.43
    or later (or any patched version that supports `-O encrypt`).

### Running Integration Tests

Running `make test` will build each package and run the unit tests, but will
skip the integration tests. To run the integration tests, you will need a
filesystem that supports encryption. If you already have some empty filesystem
at `/foo/bar` that supports filesystem encryption, just run:
```bash
make test MOUNT=/foo/bar
```

Otherwise, you can use the `make test-setup`/`make test-teardown` commands to
create/destroy a test filesystem for running integration tests. By default, a
filesystem will be created (then destroyed) at `/tmp/fscrypt-mount` (using an
image file at `/tmp/fscrypt-image`). To create/test/destroy a filesystem at a
custom mountpoint `/foo/bar`, run:
```bash
make test-setup MOUNT=/foo/bar
make test MOUNT=/foo/bar
make test-teardown MOUNT=/foo/bar
```
Running the commands without `MOUNT=/foo/bar` uses the default locations.

Note that the setup/teardown commands require `sudo` to mount/unmount the
test filesystem.

### Changing dependencies

fscrypt's dependencies are managed using the [Go 1.11 module system](https://github.com/golang/go/wiki/Modules).
If you add or remove a dependency, be sure to update `go.mod`, `go.sum`, and the
`vendor/` directory by running `go mod tidy` and `go mod vendor`. fscrypt still
vendor's it's dependencies for compatibility with older users, but this will
probobly be removed once the module system becomes widespread.

Also, when adding a dependency, the license of the package must be compatible
with [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the
[FSF's article](https://www.gnu.org/licenses/license-list.html) for more
information. This (unfortunately) means we cannot use external packages under
the [GPL](https://choosealicense.com/licenses/gpl-3.0) or
[LGPL](https://choosealicense.com/licenses/lgpl-3.0/). We also cannot use
packages with missing, misleading, or joke licenses (e.g.
[Unlicense](http://unlicense.org/), [WTFPL](http://www.wtfpl.net/),
[CC0](https://creativecommons.org/publicdomain/zero/1.0/)).

### Build System Details ###

Under the hood, the Makefile uses many go tools to generate, format, and lint
your code.

`make gen`:
  - Downloads [`protoc`](https://github.com/google/protobuf) to compile the
  `.proto` files.
  - Turns each `.proto` file into a matching `.pb.go` file using
    [`protoc-gen-go`](https://github.com/golang/protobuf/tree/master/protoc-gen-go)
    (built from source in `vendor/`).

`make format` runs:
  - [`goimports`](https://godoc.org/golang.org/x/tools/cmd/goimports)
    (built from source in `vendor/`) on the `.go` files.
  - [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html)
    on the `.c` and `.h` files.

`make lint` runs:
  - [`go vet`](https://golang.org/cmd/vet/) 
  - [`golint`](https://github.com/golang/lint) (built from source in `vendor/`)
  - [`staticcheck`](https://github.com/dominikh/go-tools/tree/master/cmd/staticcheck)
    (built from source in `vendor/`)
