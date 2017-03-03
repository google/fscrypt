# fscrypt

<!-- TODO: Insert link to fscryptctl when it is released -->
`fscrypt` is a high-level tool [written in Go](https://golang.org) for the
management of [Linux filesystem encryption](https://lwn.net/Articles/639427).
This tool manages metadata, key generation, key wrapping, PAM integration, and
provides a uniform interface for creating and modifying encrypted directories.
For a small low-level tool that directly manipulates keys and policies, see
`fscryptctl`.

To use `fscrypt`, you must have a filesystem with encryption enabled and a
kernel that supports reading/writing from that filesystem. Currently,
[ext4](https://en.wikipedia.org/wiki/Ext4),
[F2FS](https://en.wikipedia.org/wiki/F2FS), and
[UBIFS](https://en.wikipedia.org/wiki/UBIFS) support Linux filesystem
encryption. Ext4 has supported Linux filesystem encryption
[since v4.1](https://lwn.net/Articles/639427), F2FS
[added support in v4.2](https://lwn.net/Articles/649652), and UBIFS
[added support in v4.10](https://lwn.net/Articles/707900). Note that only
certain configurations of the Linux kernel enable encryption, and other
filesystems may add support for encryption.

Most of the testing for `fscrypt` has been done with ext4 filesystems. However,
the kernel uses a common userspace interface, so this tool should work with all
existing and future filesystems which support for encryption. If there is a
problem using `fscrypt` with other filesystems, please open an issue.

### Other encryption solutions

It is important to distinguish Linux filesystem encryption from two other
encryption solutions: [eCryptfs](https://en.wikipedia.org/wiki/ECryptfs) and
[dm-crypt](https://en.wikipedia.org/wiki/Dm-crypt).

Currently, dm-crypt encrypts an entire block device with a single master key. If
you do not need the fine-grained controls of `fscrypt` or want to fully encrypt
your filesystem metadata, dm-crypt could be a simpler choice.

On the other hand, eCryptfs is another form of filesystem encryption on Linux;
it encrypts a filesystem directory with some key or passphrase. eCryptfs sits on
top of an existing filesystem. This make eCryptfs an alternative choice if your
filesystem or kernel does not support Linux filesystem encryption or you do not
want to modify your existing filesystem.

Also note that `fscrypt` does not support or setup either eCryptfs or dm-crypt.
For these tools, use
[ecryptfs-utils](https://packages.debian.org/source/jessie/ecryptfs-utils) for
eCryptfs or [cryptsetup](https://linux.die.net/man/8/cryptsetup) for dm-crypt.

## Features

`fscrypt` is intended to improve upon the work in
[e4crypt](http://man7.org/linux/man-pages/man8/e4crypt.8.html) by providing a
more managed environment and handling more functionality in the
background. `fscrypt` has a [design document](https://goo.gl/55cCrI) that
discusses many of the higher level design choices that were made.

<!-- TODO add in features when command-line interface is complete -->
Specifically, `fscrypt` contains the following functionality:
*   Telling the time (but this is a stub program)

## Building

`fscrypt` is written in Go, so to build the program you will need to
[setup Go](https://golang.org/doc/install),
[setup your `GOPATH`](https://golang.org/doc/code.html#GOPATH), and clone the
repository into the correct location by running
```shell <!-- TODO: Change git clone URL before public release -->
git clone [REDACTED] $GOPATH/src/fscrypt
```
You will also want to add `$GOPATH/bin` to your `$PATH`.

`fscrypt` has the following build dependencies:
*   `make`
*   A C compiler (`gcc` or `clang`)
*   Go
*   [Argon2 Passphrase Hash](https://github.com/P-H-C/phc-winner-argon2), a C
    library which can be installed (both the header `argon2.h` and library
    `libargon2`) by running:
    ```bash
    > git clone https://github.com/P-H-C/phc-winner-argon2 argon2
    > cd argon2
    > make
    > sudo make install
    ```

Once this is setup, you can run `make fscrypt` to build the executable in
`build/fscrypt`. Pass `"LDFLAGS += -static"` to `make` to get a static
executable. If a Go project contains C code, the go compiler produces a
dynamically linked binary by default.

## Running and Installing

`fscrypt` has the following runtime dependencies:
*   Kernel support for filesystem encryption (this will depend on your kernel
    configuration and specific filesystem)
*   `libargon2` (see the above installation instructions for Argon2), unless you
    built a static executable.

Installing it just requires placing it in your path or running `make install`.
Change `$GOBIN` to change the install location of `fscrypt`. By default,
`fscrypt` is installed to `$GOPATH/bin`.

## Example Usage

TODO

## Contributing

If you are making changes to the `fscrypt` component, you will need to have
[govendor](https://github.com/kardianos/govendor) installed, and you will want
to use the following additional commands:
*   `make update` - Updates the dependencies in the `vendor/` directory.
*   `make go` - Generates, builds, and tests all the Go code. Requires
    [protoc (v3.0 or later)](https://github.com/google/protobuf/releases) and
    [protoc-gen-go](https://github.com/golang/protobuf).
*   `make format` - Formats all of the go code.
*   `make lint` - Checks the code for style errors. Requires
    [`golint`](https://github.com/golang/lint).
*   `make all` - Runs the above commands and builds `fscrypt`.

These commands should be run before submitting any changes.

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

## Known Issues

None so far!

## License

Copyright 2017 Google Inc.

Author: Joe Richey <joerichey@google.com>

Distributed under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0); see the
`LICENSE` file for more information.
