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

## Before you submit a pull request

If you are making changes to the `fscrypt` component, you will need to have
[govendor](https://github.com/kardianos/govendor) installed, and you will want
to use the following additional commands:
*   `make update` - Updates the dependencies in the `vendor/` directory and
    updates the `VENDOR_LICENSES` file.
*   `make go` - Generates, builds, and tests all the Go code. Requires
    [protoc (v3.0 or later)](https://github.com/google/protobuf/releases) and
    [protoc-gen-go](https://github.com/golang/protobuf).
*   `make format` - Formats all of the go code.
*   `make lint` - Checks the code for style errors. Requires
    [`golint`](https://github.com/golang/lint).
*   `make all` - Runs the above commands and builds `fscrypt`.

These commands should be run before submitting a pull request.

Make sure that `$GOPATH/bin` is in you `$PATH`. All the above dependencies can
be installed with:
``` bash
# Grab the latest version of protoc from github.com/google/protobuf/releases
> curl -L <download_link_for_your_architecture> > protoc.zip
> unzip protoc.zip -d protoc
> sudo mv protoc/bin/protoc /usr/local/bin/
> rm -rf protoc.zip protoc/
# Grab the go packages in the standard manner
> go get -u github.com/golang/protobuf/protoc-gen-go
> go get -u github.com/kardianos/govendor
> go get -u github.com/golang/lint/golint
```
