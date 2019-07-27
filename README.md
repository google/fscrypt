# fscrypt [![GitHub version](https://badge.fury.io/go/github.com%2Fgoogle%2Ffscrypt.svg)](https://github.com/google/fscrypt/releases)

[![Build Status](https://travis-ci.org/google/fscrypt.svg?branch=master)](https://travis-ci.org/google/fscrypt)
[![Coverage Status](https://coveralls.io/repos/github/google/fscrypt/badge.svg?branch=master)](https://coveralls.io/github/google/fscrypt?branch=master)
[![GoDoc](https://godoc.org/github.com/google/fscrypt?status.svg)](https://godoc.org/github.com/google/fscrypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/fscrypt)](https://goreportcard.com/report/github.com/google/fscrypt)
[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

fscrypt is a high-level tool for the management of
[Linux filesystem encryption](https://lwn.net/Articles/639427).
This tool manages metadata, key generation, key wrapping, PAM integration, and
provides a uniform interface for creating and modifying encrypted directories.
For a small low-level tool that directly sets policies, see
[fscryptctl](https://github.com/google/fscryptctl).

To use fscrypt, you must have a filesystem with encryption enabled and a
kernel that supports reading/writing from that filesystem. Currently,
[ext4](https://en.wikipedia.org/wiki/Ext4),
[F2FS](https://en.wikipedia.org/wiki/F2FS), and
[UBIFS](https://en.wikipedia.org/wiki/UBIFS) support Linux filesystem
encryption. Ext4 has supported Linux filesystem encryption
[since v4.1](https://lwn.net/Articles/639427), F2FS
[added support in v4.2](https://lwn.net/Articles/649652), and UBIFS
[added support in v4.10](https://lwn.net/Articles/707900). Other filesystems
may add support for native encryption in the future. Filesystems may
additionally require certain kernel configuration options to be set to use
native encryption.

Most of the testing for fscrypt has been done with ext4 filesystems. However,
the kernel uses a common userspace interface, so this tool should work with all
existing and future filesystems which support encryption. If there is a problem
using fscrypt with other filesystems, please open an issue.

### Other encryption solutions

It is important to distinguish Linux filesystem encryption from two other
encryption solutions: [eCryptfs](https://en.wikipedia.org/wiki/ECryptfs) and
[dm-crypt](https://en.wikipedia.org/wiki/Dm-crypt).

Currently, dm-crypt encrypts an entire block device with a single master key.
dm-crypt can be used with or without fscrypt. All filesystem data (including all
filesystem metadata) is encrypted with this single key when using dm-crypt,
while fscrypt only encrypts the filenames and file contents in a specified
directory. Note that using both dm-crypt and fscrypt simultaneously will give
the protections and benefits of both; however, this may cause a decrease in
your performance, as file contents are encrypted twice.

One example of a reasonable setup could involve using dm-crypt with a TPM or
Secure boot key, while using fscrypt for the contents of a home directory. This
would still encrypt the entire drive, but would also tie the encryption of a
user's personal documents to their passphrase.

On the other hand, eCryptfs is another form of filesystem encryption on Linux;
it encrypts a filesystem directory with some key or passphrase. eCryptfs sits on
top of an existing filesystem. This makes eCryptfs an alternative choice if your
filesystem or kernel does not support native filesystem encryption.

Also note that fscrypt does not support or setup either eCryptfs or dm-crypt.
For these tools, use
[ecryptfs-utils](https://packages.debian.org/source/jessie/ecryptfs-utils) for
eCryptfs or [cryptsetup](https://linux.die.net/man/8/cryptsetup) for dm-crypt.

## Features

fscrypt is intended to improve upon the work in
[e4crypt](http://man7.org/linux/man-pages/man8/e4crypt.8.html) by providing a
more managed environment and handling more functionality in the
background. fscrypt has a [design document](https://goo.gl/55cCrI) specifying
the full architecture of fscrypt.

Briefly, fscrypt deals with protectors and policies. Protectors represent some
secret or information used to protect the confidentiality of your data. The
three currently supported protector types are:
1. Your login passphrase, through [PAM](http://www.linux-pam.org/Linux-PAM-html)
2. A custom passphrase
3. A raw key file

These protectors are mutable, so the information can change without needing to
update any of your encrypted directories.

Policies represent the actual key passed to the kernel. This "policy key" is
immutable and policies are (usually) applied to a single directory. Protectors
then protect policies, so that having one of the protectors for a policy is
enough to get the policy key and access the data. Which protectors protect a
policy can also be changed. This allows a user to change how a directory is
protected without needing to reencrypt the directory's contents.

Concretely, fscrypt contains the following functionality:
*   `fscrypt setup` - Initializes the `fscrypt.conf` file
    * This is the only functionality which requires root privileges
*   `fscrypt setup MOUNTPOINT` - Gets a filesystem ready for use with fscrypt
*   `fscrypt encrypt DIRECTORY` - Encrypts an empty directory
*   `fscrypt unlock DIRECTORY` - Unlocks an encrypted directory
*   `fscrypt purge MOUNTPOINT` - Removes keys for a filesystem before unmounting
*   `fscrypt status [PATH]` - Gets detailed info about filesystems or paths
*   `fscrypt metadata` - Manages policies or protectors directly

The following functionality is planned:
*   `fscrypt backup` - Manages backups of the fscrypt metadata
*   `fscrypt recovery` - Manages recovery keys for directories
*   `fscrypt cleanup` - Scans filesystem for unused policies/protectors

See the example usage section below or run `fscrypt COMMAND --help` for more
information about each of the commands.

## Building and Installing

fscrypt has a minimal set of build dependencies:
*   [Go](https://golang.org/doc/install) 1.10 or higher
*   A C compiler (`gcc` or `clang`)
*   `make`
*   Headers for [`libpam`](http://www.linux-pam.org/).
    Install them with the appropriate package manager:
    - Debian/Ubuntu: `sudo apt install libpam0g-dev`
    - Red Hat: `sudo yum install pam-devel`
    - Arch: [`pam`](https://www.archlinux.org/packages/core/x86_64/pam/)
      package (usually installed by default)

Once all the dependencies are installed, you can get the repository by running:
```shell
go get -d github.com/google/fscrypt/...
```
Running `make` in `$GOPATH/src/github.com/google/fscrypt` builds the
executable (`fscrypt`) and PAM module (`pam_fscrypt.so`) in the `bin/`
directory. Use `make bin/fscrypt` or `make bin/pam_fscrypt.so`
to build only one.

Running `sudo make install` installs `fscrypt` to `/usr/local/bin`,
`pam_fscrypt.so` to `/usr/local/lib/security`, and `pam_fscrypt/config` to
`/usr/local/share/pam-configs`. Use `make install-bin` to only install
`fscrypt`. Use `make install-pam` to only install the pam files.

See the `Makefile` for instructions on how to customize the build (e.g. installing
to a custom location, using different build flags, building a static binary,
etc ...)

Alternatively, if you only want to install the fscrypt binary to `$GOPATH/bin`,
simply run:
```shell
go get github.com/google/fscrypt/cmd/fscrypt
```

### Runtime Dependencies

fscrypt has very few runtime dependencies:
*   Kernel support for filesystem encryption (this will depend on your kernel
    configuration and specific filesystem)
*   `libpam.so` (almost certainly already on your system)

### Setting up the PAM module

Note that to make use of the installed PAM module, your
[PAM configuration files](http://www.linux-pam.org/Linux-PAM-html/sag-configuration.html)
in `/etc/pam.d` must be modified to add fscrypt.

#### Automatic setup on Ubuntu

fscrypt automatically installs the
[PAM config file](https://wiki.ubuntu.com/PAMConfigFrameworkSpec)
`pam_fscrypt/config` to `/usr/share/pam-configs/fscrypt`. This file contains
reasonable defaults for the PAM module. To automatically apply these changes,
run `sudo pam-auth-update` and follow the on-screen instructions.

#### Manual setup

The fscrypt PAM module implements the Auth, Session, and Password
[types](http://www.linux-pam.org/Linux-PAM-html/sag-configuration-file.html).

The Password functionality of `pam_fscrypt.so` is used to automatically rewrap
a user's login protector when their unix passphrase changes. An easy way to get
the working is to add the line:
```
password    optional    pam_fscrypt.so
```
after `pam_unix.so` in `/etc/pam.d/common-password` or similar.

The Auth and Session functionality of `pam_fscrypt.so` are used to automatically
unlock directories when logging in as a user. An easy way to get this working is
to add the line:
```
auth        optional    pam_fscrypt.so
```
after `pam_unix.so` in `/etc/pam.d/common-auth` or similar, and to add the
line:
```
session     optional    pam_fscrypt.so drop_caches lock_policies
```
after `pam_unix.so` in `/etc/pam.d/common-session` or similar. The
`lock_policies` option locks the directories protected with the user's login
passphrase when the last session ends. The `drop_caches` option tells fscrypt to
clear the filesystem caches when the last session closes, ensuring all the
locked data is inaccessible. All the types also support the `debug` option which
prints additional debug information to the syslog.

## Note about stability

fscrypt follows [semantic versioning](http://semver.org). As such, all versions
below `1.0.0` should be considered development versions. This means no
guarantees are make about the stability of APIs or formats of config files. As
the on-disk metadata structures use
[Protocol Buffers](https://github.com/google/protobuf), we don't expect to break
backwards compatibility for metadata, but we give no guarantees.

## Example Usage

All these examples assume we have ext4 filesystems mounted at `/` and
`/mnt/disk` which both support encryption and that `/mnt/disk` contains
directories we want to encrypt.

### Setting up fscrypt on a directory

```bash
# Check which directories on our system support encryption
>>>>> fscrypt status
2 filesystem(s) on this system support encryption

MOUNTPOINT            DEVICE     FILESYSTEM  STATUS
/                     /dev/sda1  ext4        encryption not enabled
/mnt/disk             /dev/sdb   ext4        not setup with fscrypt

# Create the global configuration file. Nothing else needs root.
>>>>> sudo fscrypt setup
Create "/etc/fscrypt.conf"? [Y/n] y
Customizing passphrase hashing difficulty for this system...
Created global config file at "/etc/fscrypt.conf".

# Start using fscrypt with our filesystem
>>>>> fscrypt setup /mnt/disk
Metadata directories created at "/mnt/disk/.fscrypt".
Filesystem "/mnt/disk" (/dev/sdb) ready for use with ext4 encryption.

# Initialize encryption on a new empty directory
>>>>> mkdir /mnt/disk/dir1
>>>>> fscrypt encrypt /mnt/disk/dir1
Should we create a new protector? [Y/n] y
Your data can be protected with one of the following sources:
1 - Your login passphrase (pam_passphrase)
2 - A custom passphrase (custom_passphrase)
3 - A raw 256-bit key (raw_key)
Enter the source number for the new protector [2 - custom_passphrase]: 2
Enter a name for the new protector: Super Secret
Enter custom passphrase for protector "Super Secret":
Confirm passphrase:
"/mnt/disk/dir1" is now encrypted, unlocked, and ready for use.

# We can see this created one policy and one protector for this directory
>>>>> fscrypt status /mnt/disk
ext4 filesystem "/mnt/disk" has 1 protector(s) and 1 policy(ies)

PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"

POLICY            UNLOCKED  PROTECTORS
7626382168311a9d  Yes       7626382168311a9d
```

#### Quiet Version
```bash
>>>>> sudo fscrypt setup --quiet --force
>>>>> fscrypt setup /mnt/disk --quiet
>>>>> echo "hunter2" | fscrypt encrypt /mnt/disk/dir1 --quiet --source=custom_passphrase  --name="Super Secret"
```

### Locking and unlocking a directory

As noted in the troubleshooting below, we (as of now) have to unmount a
filesystem after purging its keys to clear the necessary caches.

```bash
# Write a file to our encrypted directory.
>>>>> echo "Hello World" > /mnt/disk/dir1/secret.txt
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee
Unlocked: Yes

Protected with 1 protector(s):
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"

# Purging, unmounting, and remounting a filesystem locks all the files.
>>>>> fscrypt purge /mnt/disk
WARNING: This may make data encrypted with fscrypt inaccessible.
Purge all policy keys from "/mnt/disk" (this will lock all encrypted directories) [y/N] y
All keys purged for "/mnt/disk".
Filesystem "/mnt/disk" should now be unmounted.
>>>>> umount /mnt/disk
>>>>> mount /mnt/disk
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee
Unlocked: No

Protected with 1 protector(s):
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"

# Now the filenames and file contents are inaccessible
>>>>> ls /mnt/disk/dir1
u,k20l9HrtrizDjh0zGkw2dTfBkX4T0ZDUlsOhBLl4P
>>>>> cat /mnt/disk/dir1/u,k20l9HrtrizDjh0zGkw2dTfBkX4T0ZDUlsOhBLl4P
cat: /mnt/disk/dir1/u,k20l9HrtrizDjh0zGkw2dTfBkX4T0ZDUlsOhBLl4P: Required key not available

# Unlocking the directory makes the contents available
>>>>> fscrypt unlock /mnt/disk/dir1
Enter custom passphrase for protector "Super Secret":
"/mnt/disk/dir1" is now unlocked and ready for use.
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee
Unlocked: Yes

Protected with 1 protector(s):
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"
>>>>> cat /mnt/disk/dir1/secret.txt
Hello World
```

#### Quiet Version
```bash
>>>>> fscrypt purge /mnt/disk --quiet --force
>>>>> umount /mnt/disk
>>>>> mount /mnt/disk
>>>>> printf "hunter2" | fscrypt unlock /mnt/disk/dir1 --quiet
```

### Protecting a directory with your login passphrase

As noted above and in the troubleshooting below, fscrypt cannot (yet) detect
when your login passphrase changes. So if you protect a directory with your
login passphrase, you may have to do additional work when you change your system
passphrase.

```bash
# Login passphrases also require that fscrypt is setup on the root directory
>>>>> sudo fscrypt setup /
Filesystem "/" (/dev/dm-1) ready for use with ext4 encryption.

# Select your login passphrase as the desired source.
>>>>> mkdir /mnt/disk/dir2
>>>>> fscrypt encrypt /mnt/disk/dir2
Should we create a new protector? [Y/n] y
Your data can be protected with one of the following sources:
1 - Your login passphrase (pam_passphrase)
2 - A custom passphrase (custom_passphrase)
3 - A raw 256-bit key (raw_key)
Enter the source number for the new protector [2 - custom_passphrase]: 1
Enter login passphrase for joerichey:
"/mnt/disk/dir2" is now encrypted, unlocked, and ready for use.

# Note that the login protector actually sits on the root filesystem
>>>>> fscrypt status /mnt/disk/dir2
"/mnt/disk/dir2" is encrypted with fscrypt.

Policy:   fe1c92009abc1cff
Unlocked: Yes

Protected with 1 protector(s):
PROTECTOR         LINKED   DESCRIPTION
6891f0a901f0065e  Yes (/)  login protector for joerichey
>>>>> fscrypt status /mnt/disk
ext4 filesystem "/mnt/disk" has 3 protector(s) and 3 policy(ies)

PROTECTOR         LINKED   DESCRIPTION
7626382168311a9d  No       custom protector "Super Secret"
6891f0a901f0065e  Yes (/)  login protector for joerichey

POLICY            UNLOCKED  PROTECTORS
16382f282d7b29ee  Yes       7626382168311a9d
fe1c92009abc1cff  Yes       6891f0a901f0065e
>>>>> fscrypt status /
ext4 filesystem "/" has 1 protector(s) and 0 policy(ies)

PROTECTOR         LINKED  DESCRIPTION
6891f0a901f0065e  No      login protector for joerichey
```

#### Quiet Version
```bash
>>>>> mkdir /mnt/disk/dir2
>>>>> echo "password" | fscrypt encrypt /mnt/disk/dir1 --source=pam_passphrase --quiet
```

### Changing a custom passphrase
```bash
# First we have to figure out which protector we wish to change.
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee
Unlocked: Yes

Protected with 1 protector(s):
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"

# Now specify the protector directly to the metadata command
>>>>> fscrypt metadata change-passphrase --protector=/mnt/disk:7626382168311a9d
Enter old custom passphrase for protector "Super Secret":
Enter new custom passphrase for protector "Super Secret":
Confirm passphrase:
Passphrase for protector 7626382168311a9d successfully changed.
```

#### Quiet Version
```bash
>>>>> printf "hunter2\nhunter3" | fscrypt metadata change-passphrase --protector=/mnt/disk:7626382168311a9d --quiet
```

### Using a raw key protector

fscrypt also supports protectors which use raw key files as the user-provided
secret. These key files must be exactly 32 bytes long and contain the raw binary
data of the key. Obviously, make sure to store the key file securely (and not in
the directory you are encrypting with it). If generating the keys on Linux make
sure you are aware of
[how randomness works](http://man7.org/linux/man-pages/man7/random.7.html) and
[some common myths](https://www.2uo.de/myths-about-urandom/).

```bash
# Generate a 256-bit key file
>>>>> head --bytes=32 /dev/urandom > secret.key

# Now create a key file protector without using it on a directory. Note that we
# could also use `fscrypt encrypt --key=secret.key` to achieve the same thing.
>>>>> fscrypt metadata create protector /mnt/disk
Create new protector on "/mnt/disk" [Y/n] y
Your data can be protected with one of the following sources:
1 - Your login passphrase (pam_passphrase)
2 - A custom passphrase (custom_passphrase)
3 - A raw 256-bit key (raw_key)
Enter the source number for the new protector [2 - custom_passphrase]: 3
Enter a name for the new protector: Skeleton
Enter key file for protector "Skeleton": secret.key
Protector 2c75f519b9c9959d created on filesystem "/mnt/disk".
>>>>> fscrypt status /mnt/disk
ext4 filesystem "/mnt/disk" has 3 protectors and 3 policies

PROTECTOR         LINKED   DESCRIPTION
7626382168311a9d  No       custom protector "Super Secret"
2c75f519b9c9959d  No       raw key protector "Skeleton"
6891f0a901f0065e  Yes (/)  login protector for joerichey

POLICY            UNLOCKED  PROTECTORS
16382f282d7b29ee  Yes       7626382168311a9d
fe1c92009abc1cff  Yes       6891f0a901f0065e

# Finally, we could apply this key to a directory
>>>>> mkdir /mnt/disk/dir3
>>>>> fscrypt encrypt /mnt/disk/dir3 --protector=/mnt/disk:2c75f519b9c9959d
Enter key file for protector "Skeleton": secret.key
"/mnt/disk/dir3" is now encrypted, unlocked, and ready for use.
```

#### Quiet Version
```bash
>>>>> head --bytes=32 /dev/urandom > secret.key
>>>>> fscrypt encrypt /mnt/disk/dir3 --key=secret.key --source=raw_key --name=Skeleton
```

### Using multiple protectors for a policy

fscrypt supports the idea of of protecting a single directory with multiple
protectors. This means having access to any of the protectors is sufficient to
decrypt the directory. This is useful for sharing data or setting up access
control systems.

```bash
# Add an existing protector to the policy for some directory
>>>>> fscrypt status /mnt/disk
ext4 filesystem "/mnt/disk" has 3 protectors and 3 policies

PROTECTOR         LINKED   DESCRIPTION
7626382168311a9d  No       custom protector "Super Secret"
2c75f519b9c9959d  No       raw key protector "Skeleton"
6891f0a901f0065e  Yes (/)  login protector for joerichey

POLICY            UNLOCKED  PROTECTORS
d03fb894584a4318  No        2c75f519b9c9959d
16382f282d7b29ee  No        7626382168311a9d
fe1c92009abc1cff  No        6891f0a901f0065e
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee
Unlocked: No

Protected with 1 protector:
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"
>>>>> fscrypt metadata add-protector-to-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee
WARNING: All files using this policy will be accessible with this protector!!
Protect policy 16382f282d7b29ee with protector 2c75f519b9c9959d? [Y/n]
Enter key file for protector "Skeleton": secret.key
Enter custom passphrase for protector "Super Secret":
Protector 2c75f519b9c9959d now protecting policy 16382f282d7b29ee.
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee
Unlocked: No

Protected with 2 protectors:
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"
2c75f519b9c9959d  No      raw key protector "Skeleton"

# Now the unlock command will prompt for which protector we want to use
>>>>> fscrypt unlock /mnt/disk/dir1
The available protectors are:
0 - custom protector "Super Secret"
1 - raw key protector "Skeleton"
Enter the number of protector to use: 1
Enter key file for protector "Skeleton": secret.key
"/mnt/disk/dir1" is now unlocked and ready for use.

# The protector can also be removed from the policy (if it is not the only one)
>>>>> fscrypt metadata remove-protector-from-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee
WARNING: All files using this policy will NO LONGER be accessible with this protector!!
Stop protecting policy 16382f282d7b29ee with protector 2c75f519b9c9959d? [y/N] y
Protector 2c75f519b9c9959d no longer protecting policy 16382f282d7b29ee.
```

#### Quiet Version
```bash
>>>>> echo "hunter2" | fscrypt metadata add-protector-to-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee --key=secret.key --quiet
>>>>> fscrypt metadata remove-protector-from-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee --quiet --force
```

## Contributing

We would love to accept your contributions to fscrypt. See the `CONTRIBUTING.md`
file for more information about signing the CLA and submitting a pull request.

## Troubleshooting

In general, if you are encountering issues with fscrypt,
[open an issue](https://github.com/google/fscrypt/issues/new), following the
guidelines in `CONTRIBUTING.md`. We will try our best to help.

#### I changed my login passphrase, now all my directories are inaccessible

The PAM module provided by fscrypt (`pam_fscrypt.so`) should automatically
detect changes to a user's login passphrase so that they can still access their
encrypted directories. However, sometimes the login passphrase can become
desynchronized from a user's login protector. This usually happens when the PAM
passphrase is managed by an external system, if the PAM module is not installed,
or if the PAM module is not properly configured.

To fix your login protector, you first should find the appropriate protector ID
by running `fscrypt status "/"`. Then, change the passphrase for this protector
by running:
```
fscrypt metadata change-passphrase --protector=/:ID
```

#### Directories using my login passphrase are not automatically unlocking.

Either the PAM module is not installed correctly, or your login passphrase
changed and things got out of sync. Another reason that these directories might
not unlock is if your session starts without password authentication. The most
common case of this is public-key ssh login.

To trigger a password authentication event, run `su $(whoami) -c exit`.

#### Getting "encryption not enabled" on an ext4 filesystem.

Getting this error on an ext4 system usually means the filesystem has not been
setup for encryption. The only other way to get this error is if filesystem
encryption has been explicitly disabled in the kernel config.

__IMPORTANT:__ Before enabling encryption on an ext4 filesystem __ALL__ of the
following should be true:
  - Your filesystem is formatted as ext4. Other filesystems will have
    different ways of enabling encryption.
  - Your kernel page size (run `getconf PAGE_SIZE`) and your filesystem
    block size (run `tune2fs -l /dev/device | grep 'Block size'`) are the same.
  - You are ok with not being able to mount this filesystem with a v4.0
    kernel or older.
  - Either you are __NOT__ using GRUB to boot directly off this filesystem, or
    you are using GRUB 2.04 or later.  This is necessary because old versions of
    GRUB can't boot from ext4 filesystems that have the encryption feature
    enabled, even if none of the boot files are encrypted themselves.  If, like
    most people, you have a separate `/boot` partition, you are fine.  You are
    also fine if you are using the GRUB Debian package `2.02-2` or later (*not*
    a `2.02_beta*` version), including the version in Ubuntu 18.04 and later,
    since the patch to support encryption was backported.
    
If any of the above is not true, __DO NOT ENABLE FILESYSTEM ENCRYPTION__.

To turn on encryption for your filesystem, run
```
tune2fs -O encrypt /dev/device
```
To turn off encryption for your filesystem, run
```
fsck -fn /dev/device
debugfs -w -R "feature -encrypt" /dev/device
fsck -fn /dev/device
``` 

## Legal

Copyright 2017 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0); see the
`LICENSE` file for more information.

Author: Joe Richey <joerichey@google.com>

This is not an official Google product.
