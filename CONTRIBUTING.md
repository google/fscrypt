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

## Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

## Working on fscrypt

On every pull request, [Travis CI](https://travis-ci.org/google/fscrypt) runs
unit tests, integration tests, code formatters, and linters. You can also run
these commands when writing your code.

### Building and Testing

As mentioned in `README.md`, running `make` will build the fscrypt executable.
Running `make go` will build each package and run the tests, but just running
`make go` with nothing else will skip the integration tests.

To run the integration tests, you will need a filesystem that supports
encryption. If you already have some empty filesystem at `/foo/bar`, just run:
```bash
make go MOUNT=/foo/bar
```

Otherwise, you can use the `make test-setup` and `make test-teardown` commands
to create a fake filesystem for testing. Note that the commands require `sudo`,
and the `make test-setup` command requires `e2fsprogs` version 1.43 or later.
For example:
```bash
make test-setup
make go
make test-teardown
```

### Formatting and Linting

The `make format` command formats all the code in fscrypt with either `gofmt`
(for Go code) or [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html)
(for C code). `gofmt` comes with any Go distribution, and `clang-format` can be
installed with your package manager.

The `make lint` command runs a series of static analysis checks on your code.
This requires the
[megacheck](https://github.com/dominikh/go-tools/tree/master/cmd/megacheck) and
[golint](https://github.com/golang/lint) tools.

### Changing proto files

If you make any changes to files ending in `.proto`, the corresponding `.pb.go`
files have to be regenerated with `make gen`. This requires version 3.0.0 or
later of `protoc` the
[protobuf compiler](https://github.com/google/protobuf) and
[protoc-gen-go](https://github.com/golang/protobuf).

### Changing dependencies

fscrypt vendors all of it's Go dependencies. If you add or remove a dependency
on an external Go package, be sure to run `make update` to resync the `vendor/`
directory. This requires [govendor](https://github.com/kardianos/govendor).

Also, if adding in an external Go package, be sure that he license of the
package is compatible with the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0). See the
[FSF's article](https://www.gnu.org/licenses/license-list.html) for more
information. This (unfortunately) means we cannot use external packages under
the [GPL](https://choosealicense.com/licenses/gpl-3.0) or
[LGPL](https://choosealicense.com/licenses/lgpl-3.0/). We also cannot use
packages with missing or joke licenses (see [Unlicense](http://unlicense.org/), 
[WTFPL](http://www.wtfpl.net/), or
[CC0](https://creativecommons.org/publicdomain/zero/1.0/)).

### Putting it all together

Run `make go-tools` to install all the Go tools mentioned above (make sure that
`$GOPATH/bin` is in you `$PATH`). Install `protoc` and `clang-format` with your
system's package manager. In the case of `protoc`, your system's version might
be older than v3.0.0. In that case, just get the build
[directly from GitHub](https://github.com/google/protobuf/releases/latest).

After installing everything, running `make all` will run all the commands
mentioned above. As with `make test`, you can run the integration tests by
either using `make all MOUNT=/path/to/my/filesystem` or using the
`make test-setup` and `make test-teardown` commands.

`make all` should always be run before submitting a pull request.
