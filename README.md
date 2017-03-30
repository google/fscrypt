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

Specifically, `fscrypt` contains the following functionality:
*   TODO

## Building

<!-- TODO: Change git clone URL before public release -->
Get the source by running `git clone [REDACTED] fscrypt`.
You need to [setup your `GOPATH`](https://golang.org/doc/code.html#GOPATH) and
clone the repository into `$GOPATH/src/fscrypt`.

## Running and Installing

TODO

## Example Usage

TODO

## Contributing

TODO

## Known Issues

None so far!

## License

Copyright 2017 Google Inc.

Author: Joe Richey <joerichey@google.com>

Distributed under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0); see the
`LICENSE` file for more information.
