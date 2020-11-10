# fscrypt [![GitHub version](https://badge.fury.io/go/github.com%2Fgoogle%2Ffscrypt.svg)](https://github.com/google/fscrypt/releases)

[![Build Status](https://travis-ci.org/google/fscrypt.svg?branch=master)](https://travis-ci.org/google/fscrypt)
[![Coverage Status](https://coveralls.io/repos/github/google/fscrypt/badge.svg?branch=master)](https://coveralls.io/github/google/fscrypt?branch=master)
[![GoDoc](https://godoc.org/github.com/google/fscrypt?status.svg)](https://godoc.org/github.com/google/fscrypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/fscrypt)](https://goreportcard.com/report/github.com/google/fscrypt)
[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

`fscrypt` is a high-level tool for the management of [Linux filesystem
encryption](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html).
`fscrypt` manages metadata, key generation, key wrapping, PAM integration, and
provides a uniform interface for creating and modifying encrypted directories.
For a small low-level tool that directly sets policies, see
[`fscryptctl`](https://github.com/google/fscryptctl).

Note that the kernel part of `fscrypt` (which is integrated into filesystems
such as ext4) is also sometimes referred to as "fscrypt".  To avoid confusion,
this documentation instead calls the kernel part "Linux filesystem encryption".

To use `fscrypt`, you must have a filesystem with encryption enabled and a
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
native encryption.  See [Runtime Dependencies](#runtime-dependencies).

## Table of Contents

- [Other encryption solutions](#other-encryption-solutions)
- [Features](#features)
- [Building and Installing](#building-and-installing)
- [Runtime Dependencies](#runtime-dependencies)
- [Configuration file](#configuration-file)
- [Setting up for login protectors](#setting-up-for-login-protectors)
  - [Securing your login passphrase](#securing-your-login-passphrase)
  - [Enabling the PAM module](#enabling-the-pam-module)
    - [Enabling the PAM module on Ubuntu](#enabling-the-pam-module-on-ubuntu)
	- [Enabling the PAM module on Arch Linux](#enabling-the-pam-module-on-arch-linux)
	- [Enabling the PAM module on other Linux distros](#enabling-the-pam-module-on-other-linux-distros)
  - [Allowing `fscrypt` to check your login passphrase](#allowing-fscrypt-to-check-your-login-passphrase)
- [Note about stability](#note-about-stability)
- [Example Usage](#example-usage)
  - [Setting up fscrypt on a directory](#setting-up-fscrypt-on-a-directory)
  - [Locking and unlocking a directory](#locking-and-unlocking-a-directory)
  - [Protecting a directory with your login passphrase](#protecting-a-directory-with-your-login-passphrase)
  - [Changing a custom passphrase](#changing-a-custom-passphrase)
  - [Using a raw key protector](#using-a-raw-key-protector)
  - [Using multiple protectors for a policy](#using-multiple-protectors-for-a-policy)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)
  - [I changed my login passphrase, now all my directories are inaccessible](#i-changed-my-login-passphrase-now-all-my-directories-are-inaccessible)
  - [Directories using my login passphrase are not automatically unlocking.](#directories-using-my-login-passphrase-are-not-automatically-unlocking)
  - [Getting "encryption not enabled" on an ext4 filesystem.](#getting-encryption-not-enabled-on-an-ext4-filesystem)
  - [Getting "Operation not permitted" when moving files into an encrypted directory.](#getting-operation-not-permitted-when-moving-files-into-an-encrypted-directory)
  - [Can't log in with ssh even when user's encrypted home directory is unlocked](#cant-log-in-with-ssh-even-when-users-encrypted-home-directory-is-unlocked)
- [Legal](#legal)

## Other encryption solutions

It is important to distinguish Linux filesystem encryption from two other
encryption solutions: [eCryptfs](https://en.wikipedia.org/wiki/ECryptfs) and
[dm-crypt](https://en.wikipedia.org/wiki/Dm-crypt).

Currently, dm-crypt encrypts an entire block device with a single master key.
dm-crypt can be used with or without `fscrypt`. All filesystem data (including
all filesystem metadata) is encrypted with this single key when using dm-crypt,
while `fscrypt` only encrypts the filenames and file contents in a specified
directory. Note that using both dm-crypt and `fscrypt` simultaneously will give
the protections and benefits of both; however, this may cause a decrease in your
performance, as file contents are encrypted twice.

One example of a reasonable setup could involve using dm-crypt with a TPM or
Secure boot key, while using `fscrypt` for the contents of a home directory.
This would still encrypt the entire drive, but would also tie the encryption of
a user's personal documents to their passphrase.

On the other hand, eCryptfs is another form of filesystem encryption on Linux;
it encrypts a filesystem directory with some key or passphrase. eCryptfs sits on
top of an existing filesystem. This makes eCryptfs an alternative choice if your
filesystem or kernel does not support native filesystem encryption.

Also note that `fscrypt` does not support or setup either eCryptfs or dm-crypt.
For these tools, use
[ecryptfs-utils](https://packages.debian.org/source/jessie/ecryptfs-utils) for
eCryptfs or [cryptsetup](https://linux.die.net/man/8/cryptsetup) for dm-crypt.

## Features

`fscrypt` is intended to improve upon the work in
[e4crypt](http://man7.org/linux/man-pages/man8/e4crypt.8.html) by providing a
more managed environment and handling more functionality in the background.
`fscrypt` has a [design document](https://goo.gl/55cCrI) specifying its full
architecture.  See also the [kernel documentation for Linux filesystem
encryption](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html).

Briefly, `fscrypt` deals with protectors and policies. Protectors represent some
secret or information used to protect the confidentiality of your data. The
three currently supported protector types are:

1. Your login passphrase, through [PAM](http://www.linux-pam.org/Linux-PAM-html).
   The included PAM module (`pam_fscrypt.so`) can automatically unlock login
   protectors when you log in.  __IMPORTANT:__ before using a login protector,
   follow [Setting up for login protectors](#setting-up-for-login-protectors).

2. A custom passphrase.  This passphrase is hashed with
   [Argon2id](https://en.wikipedia.org/wiki/Argon2), by default calibrated to
   use all CPUs and take about 1 second.

3. A raw key file.  See [Using a raw key protector](#using-a-raw-key-protector).

These protectors are mutable, so the information can change without needing to
update any of your encrypted directories.

Policies represent the actual key passed to the kernel. This "policy key" is
immutable and policies are (usually) applied to a single directory. Protectors
then protect policies, so that having one of the protectors for a policy is
enough to get the policy key and access the data. Which protectors protect a
policy can also be changed. This allows a user to change how a directory is
protected without needing to reencrypt the directory's contents.

Concretely, `fscrypt` contains the following functionality:
*   `fscrypt setup` - Creates `/etc/fscrypt.conf` and the `/.fscrypt` directory
    * This is the only functionality which always requires root privileges
*   `fscrypt setup MOUNTPOINT` - Gets a filesystem ready for use with fscrypt
*   `fscrypt encrypt DIRECTORY` - Encrypts an empty directory
*   `fscrypt unlock DIRECTORY` - Unlocks an encrypted directory
*   `fscrypt lock DIRECTORY` - Locks an encrypted directory
*   `fscrypt purge MOUNTPOINT` - Locks all encrypted directories on a filesystem
*   `fscrypt status [PATH]` - Gets detailed info about filesystems or paths
*   `fscrypt metadata` - Manages policies or protectors directly

The following functionality is planned:
*   `fscrypt backup` - Manages backups of the `fscrypt` metadata
*   `fscrypt recovery` - Manages recovery keys for directories
*   `fscrypt cleanup` - Scans filesystem for unused policies/protectors

See the example usage section below or run `fscrypt COMMAND --help` for more
information about each of the commands.

## Building and Installing

`fscrypt` has a minimal set of build dependencies:
*   [Go](https://golang.org/doc/install) 1.11 or higher. Older versions may work
    but they are not tested or supported.
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
Running `make` in `$GOPATH/src/github.com/google/fscrypt` builds the binary
(`fscrypt`) and PAM module (`pam_fscrypt.so`) in the `bin/` directory.

Running `sudo make install` installs `fscrypt` into `/usr/local/bin`,
`pam_fscrypt.so` into `/usr/local/lib/security`, and `pam_fscrypt/config` into
`/usr/local/share/pam-configs`.

For Ubuntu, use `sudo make install PREFIX=/usr` to install into `/usr` instead
of the default of `/usr/local`.  Ordinarily you shouldn't manually install
software into `/usr`, since `/usr` is reserved for Ubuntu's own packages.
However, Ubuntu only recognizes PAM configuration files in `/usr`, not in
`/usr/local`.  This means that the PAM module will only work if you install into
`/usr`.  Note: if you later decide to switch to using the Ubuntu package for
`fscrypt`, you'll have to first manually run `sudo make uninstall PREFIX=/usr`.

It is also possible to use `make install-bin` to only install the `fscrypt`
binary, or `make install-pam` to only install the PAM files.

Alternatively, if you only want to install the `fscrypt` binary to
`$GOPATH/bin`, simply run:
```shell
go get github.com/google/fscrypt/cmd/fscrypt
```

See the `Makefile` for instructions on how to further customize the build.

## Runtime Dependencies

To run, `fscrypt` needs the following libraries:
*   `libpam.so` (almost certainly already on your system)

In addition, `fscrypt` requires kernel support for encryption for your
filesystem, and for some filesystems that a feature flag has been
enabled in the on-disk filesystem superblock:

* For ext4, the kernel must be v4.1 or later, and the kernel configuration must
  have either `CONFIG_FS_ENCRYPTION=y` (for kernels v5.1+) or
  `CONFIG_EXT4_ENCRYPTION=y` or `=m` (for older kernels).  Also, the filesystem
  must have the `encrypt` feature flag enabled; see
  [here](#getting-encryption-not-enabled-on-an-ext4-filesystem) for how to
  enable it.

* For f2fs, the kernel must be v4.2 or later, and the kernel configuration must
  have either `CONFIG_FS_ENCRYPTION=y` (for kernels v5.1+) or
  `CONFIG_F2FS_FS_ENCRYPTION=y` (for older kernels).  Also, the filesystem must
  have the `encrypt` feature flag enabled.  It can be enabled at format time by
  `mkfs.f2fs -O encrypt`, or later by `fsck.f2fs -O encrypt`.

* For UBIFS, the kernel must be v4.10 or later, and the kernel configuration
  must have either `CONFIG_FS_ENCRYPTION=y` (for kernels v5.1+) or
  `CONFIG_UBIFS_FS_ENCRYPTION=y` (for older kernels).

To check whether the needed option is enabled in your kernel, run:
```shell
zgrep -h ENCRYPTION /proc/config.gz /boot/config-$(uname -r) | sort | uniq
```

It is also recommended to use Linux kernel v5.4 or later, since this
allows the use of v2 encryption policies.  v2 policies have several
security and usability improvements over v1 policies.

Be careful when using encryption on removable media, since filesystems with the
`encrypt` feature cannot be mounted on systems with kernel versions older than
the minimums listed above -- even to access unencrypted files!

If you configure `fscrypt` to use non-default features, other kernel
prerequisites may be needed too.  See [Configuration
file](#configuration-file).

## Configuration file

Running `sudo fscrypt setup` will create the configuration file
`/etc/fscrypt.conf` if it doesn't already exist.  It's a JSON file
that looks like the following:

```
{
	"source": "custom_passphrase",
	"hash_costs": {
		"time": "52",
		"memory": "131072",
		"parallelism": "32"
	},
	"options": {
		"padding": "32",
		"contents": "AES_256_XTS",
		"filenames": "AES_256_CTS",
		"policy_version": "2"
	},
	"use_fs_keyring_for_v1_policies": false
}
```

The fields are:

* "source" is the default source for new protectors.  The choices are
  "pam\_passphrase", "custom\_passphrase", and "raw\_key".

* "hash\_costs" describes how difficult the passphrase hashing is.
  By default, `fscrypt setup` calibrates the hashing to use all CPUs
  and take about 1 second.  The `--time` option to `fscrypt setup` can
  be used to customize this time when creating the configuration file.

* "options" are the encryption options to use for new encrypted
  directories:

    * "padding" is the number of bytes by which filenames are padded
      before being encrypted.  The choices are "32", "16", "8", and
      "4".  "32" is recommended.

    * "contents" is the algorithm used to encrypt file contents.  The
      choices are "AES_256_XTS", "AES_128_CBC", and "Adiantum".
      Normally, "AES_256_XTS" is recommended.

    * "filenames" is the algorithm used to encrypt file names.  The
      choices are "AES_256_CTS", "AES_128_CTS", and "Adiantum".
      Normally, "AES_256_CTS" is recommended.

      To use algorithms other than "AES_256_XTS" for contents and
      "AES_256_CTS" for filenames, the needed algorithm(s) may need to
      be enabled in the Linux kernel's cryptography API.  For example,
      to use Adiantum, `CONFIG_CRYPTO_ADIANTUM` must be set.  Also,
      not all combinations of algorithms are allowed; for example,
      "Adiantum" for contents can only be paired with "Adiantum" for
      filenames.  See the [kernel
      documentation](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html#encryption-modes-and-usage)
      for more details about the supported algorithms.

    * "policy\_version" is the version of encryption policy to use.
      The choices are "1" and "2".  If unset, "1" is assumed.
      Directories created with policy version "2" are only usable on
      kernel v5.4 or later, but are preferable to version "1" if you
      don't mind this restriction.

* "use\_fs\_keyring\_for\_v1\_policies" specifies whether to add keys
  for v1 encryption policies to the filesystem keyring, rather than to
  user keyrings.  This can solve [issues with processes being unable
  to access encrypted files](#cant-log-in-with-ssh-even-when-users-encrypted-home-directory-is-unlocked).
  However, it requires kernel v5.4 or later, and it makes unlocking
  and locking encrypted directories require root.

  The purpose of this setting is to allow people to take advantage of
  some of the improvements in Linux v5.4 on encrypted directories that
  are also compatible with older kernels.  If you don't need
  compatibility with older kernels, it's better to not use this
  setting and instead (re-)create your encrypted directories with
  `"policy_version": "2"`.

## Setting up for login protectors

If you want any encrypted directories to be protected by your login passphrase,
you'll need to:

1. Secure your login passphrase (optional, but strongly recommended)
2. Enable the PAM module (`pam_fscrypt.so`)

If you installed `fscrypt` from source rather than from your distro's package
manager, you may also need to allow `fscrypt` to check your login passphrase.

### Securing your login passphrase

Although `fscrypt` uses a strong passphrase hash algorithm, the security of
login protectors is also limited by the strength of your system's passphrase
hashing in `/etc/shadow`.  On most Linux distributions, `/etc/shadow` by default
uses SHA-512 with 5000 rounds, which is much weaker than what `fscrypt` uses.

To mitigate this, you should use a strong login passphrase.

If using a strong login passphrase is annoying because it needs to be entered
frequently to run `sudo`, consider increasing the `sudo` timeout.  That can be
done by adding the following to `/etc/sudoers`:
```
Defaults timestamp_timeout=60
```

You should also increase the number of rounds that your system's passphrase
hashing uses (though this doesn't increase security as much as choosing a strong
passphrase).  To do this, find the line in `/etc/pam.d/passwd` that looks like:
```
password	required	pam_unix.so sha512 shadow nullok
```

Append `rounds=1000000` (or another number of your choice; the goal is to make
the passphrase hashing take about 1 second, similar to `fscrypt`'s default):
```
password	required	pam_unix.so sha512 shadow nullok rounds=1000000
```

Then, change your login passphrase to a new, strong passphrase:
```
passwd
```

If you'd like to keep the same login passphrase (not recommended, as the old
passphrase hash may still be recoverable from disk), then instead run
`sudo passwd $USER` and enter your existing passphrase.  This re-hashes your
existing passphrase with the new `rounds`.

### Enabling the PAM module

To enable the PAM module `pam_fscrypt.so`, follow the directions for your Linux
distro below.  Enabling the PAM module is needed for login passphrase-protected
directories to be automatically unlocked when you log in, and for login
passphrase-protected directories to remain accessible when you change your login
passphrase.

#### Enabling the PAM module on Ubuntu

The official `fscrypt` package for Ubuntu will install a configuration file for
[Ubuntu's PAM configuration
framework](https://wiki.ubuntu.com/PAMConfigFrameworkSpec) to
`/usr/share/pam-configs/fscrypt`.  This file contains reasonable defaults for
the PAM module.  To automatically apply these defaults, run `sudo
pam-auth-update` and follow the on-screen instructions.

This file also gets installed if you build and install `fscrypt` from source,
but only if you use `make install PREFIX=/usr` to install into `/usr` instead of
the default of `/usr/local`.

#### Enabling the PAM module on Arch Linux

On Arch Linux, follow the recommendations at the [Arch Linux
Wiki](https://wiki.archlinux.org/index.php/Fscrypt#Auto-unlocking_directories).

We recommend using the Arch Linux package, either `fscrypt` (official) or
`fscrypt-git` (AUR).  If you instead install `fscrypt` manually using `sudo make
install`, then in addition to the steps on the Wiki you'll also need to [create
`/etc/pam.d/fscrypt`](#allowing-fscrypt-to-check-your-login-passphrase).

#### Enabling the PAM module on other Linux distros

On all other Linux distros, follow the general guidance below to edit
your PAM configuration files.

The `fscrypt` PAM module implements the Auth, Session, and Password
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
passphrase when the last session ends. The `drop_caches` option tells `fscrypt`
to clear the filesystem caches when the last session closes, ensuring all the
locked data is inaccessible; this only needed for v1 encryption policies.  All
the types also support the `debug` option which prints additional debug
information to the syslog.

### Allowing `fscrypt` to check your login passphrase

This step is only needed if you installed `fscrypt` from source code.

Some Linux distros use restrictive settings in `/etc/pam.d/other` that prevent
non-whitelisted programs from checking your login passphrase.  This prevents
`fscrypt` from creating any login passphrase-protected directories, even without
auto-unlocking.  To ensure that `fscrypt` will work properly (if you didn't
install an official `fscrypt` package from your distro, which should have
already handled this), also create a file `/etc/pam.d/fscrypt` containing:
```
auth        required    pam_unix.so
```

## Note about stability

`fscrypt` follows [semantic versioning](http://semver.org). As such, all
versions below `1.0.0` should be considered development versions. This means no
guarantees are make about the stability of APIs or formats of config files. As
the on-disk metadata structures use [Protocol
Buffers](https://github.com/google/protobuf), we don't expect to break backwards
compatibility for metadata, but we give no guarantees.

## Example Usage

All these examples assume there is an ext4 filesystem which supports
encryption mounted at `/mnt/disk`.  See
[here](#getting-encryption-not-enabled-on-an-ext4-filesystem) for how
to enable encryption support on an ext4 filesystem.

### Setting up fscrypt on a directory

```bash
# Check which directories on our system support encryption
>>>>> fscrypt status
filesystems supporting encryption: 1
filesystems with fscrypt metadata: 0

MOUNTPOINT  DEVICE     FILESYSTEM  ENCRYPTION   FSCRYPT
/           /dev/sda1  ext4        not enabled  No
/mnt/disk   /dev/sdb   ext4        supported    No

# Create the global configuration file. Nothing else necessarily needs root.
>>>>> sudo fscrypt setup
Defaulting to policy_version 2 because kernel supports it.
Customizing passphrase hashing difficulty for this system...
Created global config file at "/etc/fscrypt.conf".
Metadata directories created at "/.fscrypt".

# Start using fscrypt with our filesystem
>>>>> fscrypt setup /mnt/disk
Metadata directories created at "/mnt/disk/.fscrypt".

# Initialize encryption on a new empty directory
>>>>> mkdir /mnt/disk/dir1
>>>>> fscrypt encrypt /mnt/disk/dir1
The following protector sources are available:
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
ext4 filesystem "/mnt/disk" has 1 protector and 1 policy

PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"

POLICY                            UNLOCKED  PROTECTORS
16382f282d7b29ee27e6460151d03382  Yes       7626382168311a9d
```

#### Quiet Version
```bash
>>>>> sudo fscrypt setup --quiet --force
>>>>> fscrypt setup /mnt/disk --quiet
>>>>> echo "hunter2" | fscrypt encrypt /mnt/disk/dir1 --quiet --source=custom_passphrase  --name="Super Secret"
```

### Locking and unlocking a directory

```bash
# Write a file to our encrypted directory.
>>>>> echo "Hello World" > /mnt/disk/dir1/secret.txt
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee27e6460151d03382
Options:  padding:32 contents:AES_256_XTS filenames:AES_256_CTS policy_version:2
Unlocked: Yes

Protected with 1 protector:
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"

# Lock the directory.  Note: if using a v1 encryption policy instead
# of v2, you'll need 'sudo fscrypt lock /mnt/disk/dir1 --user=$USER'.
>>>>> fscrypt lock /mnt/disk/dir1
"/mnt/disk/dir1" is now locked.
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee27e6460151d03382
Options:  padding:32 contents:AES_256_XTS filenames:AES_256_CTS policy_version:2
Unlocked: No

Protected with 1 protector:
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

Policy:   16382f282d7b29ee27e6460151d03382
Options:  padding:32 contents:AES_256_XTS filenames:AES_256_CTS policy_version:2
Unlocked: Yes

Protected with 1 protector:
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"
>>>>> cat /mnt/disk/dir1/secret.txt
Hello World
```

#### Quiet Version
```bash
>>>>> fscrypt lock /mnt/disk/dir1 --quiet
>>>>> echo "hunter2" | fscrypt unlock /mnt/disk/dir1 --quiet
```

### Protecting a directory with your login passphrase

First, ensure that you have properly [set up your system for login
protectors](#setting-up-for-login-protectors).

Then, you can protect directories with your login passphrase as follows:

```bash
# Select your login passphrase as the desired source.
>>>>> mkdir /mnt/disk/dir2
>>>>> fscrypt encrypt /mnt/disk/dir2
Should we create a new protector? [y/N] y
The following protector sources are available:
1 - Your login passphrase (pam_passphrase)
2 - A custom passphrase (custom_passphrase)
3 - A raw 256-bit key (raw_key)
Enter the source number for the new protector [2 - custom_passphrase]: 1
Enter login passphrase for joerichey:
"/mnt/disk/dir2" is now encrypted, unlocked, and ready for use.

# Note that the login protector actually sits on the root filesystem
>>>>> fscrypt status /mnt/disk/dir2
"/mnt/disk/dir2" is encrypted with fscrypt.

Policy:   fe1c92009abc1cff4f3257c77e8134e3
Options:  padding:32 contents:AES_256_XTS filenames:AES_256_CTS policy_version:2
Unlocked: Yes

Protected with 1 protector:
PROTECTOR         LINKED   DESCRIPTION
6891f0a901f0065e  Yes (/)  login protector for joerichey
>>>>> fscrypt status /mnt/disk
ext4 filesystem "/mnt/disk" has 2 protectors and 2 policies

PROTECTOR         LINKED   DESCRIPTION
7626382168311a9d  No       custom protector "Super Secret"
6891f0a901f0065e  Yes (/)  login protector for joerichey

POLICY                            UNLOCKED  PROTECTORS
16382f282d7b29ee27e6460151d03382  Yes       7626382168311a9d
fe1c92009abc1cff4f3257c77e8134e3  Yes       6891f0a901f0065e
>>>>> fscrypt status /
ext4 filesystem "/" has 1 protector(s) and 0 policy(ies)

PROTECTOR         LINKED  DESCRIPTION
6891f0a901f0065e  No      login protector for joerichey
```

#### Quiet Version
```bash
>>>>> mkdir /mnt/disk/dir2
>>>>> echo "password" | fscrypt encrypt /mnt/disk/dir2 --source=pam_passphrase --quiet
```

### Changing a custom passphrase
```bash
# First we have to figure out which protector we wish to change.
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee27e6460151d03382
Options:  padding:32 contents:AES_256_XTS filenames:AES_256_CTS policy_version:2
Unlocked: Yes

Protected with 1 protector:
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

`fscrypt` also supports protectors which use raw key files as the user-provided
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
The following protector sources are available:
1 - Your login passphrase (pam_passphrase)
2 - A custom passphrase (custom_passphrase)
3 - A raw 256-bit key (raw_key)
Enter the source number for the new protector [2 - custom_passphrase]: 3
Enter a name for the new protector: Skeleton
Enter key file for protector "Skeleton": secret.key
Protector 2c75f519b9c9959d created on filesystem "/mnt/disk".
>>>>> fscrypt status /mnt/disk
ext4 filesystem "/mnt/disk" has 3 protectors and 2 policies

PROTECTOR         LINKED   DESCRIPTION
7626382168311a9d  No       custom protector "Super Secret"
2c75f519b9c9959d  No       raw key protector "Skeleton"
6891f0a901f0065e  Yes (/)  login protector for joerichey

POLICY                            UNLOCKED  PROTECTORS
16382f282d7b29ee27e6460151d03382  Yes       7626382168311a9d
fe1c92009abc1cff4f3257c77e8134e3  Yes       6891f0a901f0065e

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

`fscrypt` supports the idea of protecting a single directory with multiple
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

POLICY                            UNLOCKED  PROTECTORS
d03fb894584a4318d1780e9a7b0b47eb  No        2c75f519b9c9959d
16382f282d7b29ee27e6460151d03382  No        7626382168311a9d
fe1c92009abc1cff4f3257c77e8134e3  No        6891f0a901f0065e
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee27e6460151d03382
Options:  padding:32 contents:AES_256_XTS filenames:AES_256_CTS policy_version:2
Unlocked: No

Protected with 1 protector:
PROTECTOR         LINKED  DESCRIPTION
7626382168311a9d  No      custom protector "Super Secret"
>>>>> fscrypt metadata add-protector-to-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee27e6460151d03382
WARNING: All files using this policy will be accessible with this protector!!
Protect policy 16382f282d7b29ee27e6460151d03382 with protector 2c75f519b9c9959d? [Y/n]
Enter key file for protector "Skeleton": secret.key
Enter custom passphrase for protector "Super Secret":
Protector 2c75f519b9c9959d now protecting policy 16382f282d7b29ee27e6460151d03382.
>>>>> fscrypt status /mnt/disk/dir1
"/mnt/disk/dir1" is encrypted with fscrypt.

Policy:   16382f282d7b29ee27e6460151d03382
Options:  padding:32 contents:AES_256_XTS filenames:AES_256_CTS policy_version:2
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
>>>>> fscrypt metadata remove-protector-from-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee27e6460151d03382
WARNING: All files using this policy will NO LONGER be accessible with this protector!!
Stop protecting policy 16382f282d7b29ee27e6460151d03382 with protector 2c75f519b9c9959d? [y/N] y
Protector 2c75f519b9c9959d no longer protecting policy 16382f282d7b29ee27e6460151d03382.
```

#### Quiet Version
```bash
>>>>> echo "hunter2" | fscrypt metadata add-protector-to-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee27e6460151d03382 --key=secret.key --quiet
>>>>> fscrypt metadata remove-protector-from-policy --protector=/mnt/disk:2c75f519b9c9959d --policy=/mnt/disk:16382f282d7b29ee27e6460151d03382 --quiet --force
```

## Contributing

We would love to accept your contributions to `fscrypt`. See the
`CONTRIBUTING.md` file for more information about signing the CLA and submitting
a pull request.

## Troubleshooting

In general, if you are encountering issues with `fscrypt`,
[open an issue](https://github.com/google/fscrypt/issues/new), following the
guidelines in `CONTRIBUTING.md`. We will try our best to help.

#### I changed my login passphrase, now all my directories are inaccessible

The PAM module `pam_fscrypt.so` should automatically detect changes to a user's
login passphrase so that they can still access their encrypted directories.
However, sometimes a user's login passphrase can become desynchronized from
their login protector.  This can happen if their login passphrase is managed by
an external system, if the PAM module is not installed, or if the PAM module is
not properly configured.  See [Enabling the PAM
module](#enabling-the-pam-module) for how to configure the PAM module.

To fix a user's login protector, find the corresponding protector ID by running
`fscrypt status "/"`.  Then, change this protector's passphrase by running:
```
fscrypt metadata change-passphrase --protector=/:ID
```

#### Directories using my login passphrase are not automatically unlocking.

First, directories won't unlock if your session starts without password
authentication.  The most common case of this is public-key ssh login.  To
trigger a password authentication event, run `su $USER -c exit`.

If your session did start with password authentication, then either the PAM
module is not correctly installed and configured, or your login passphrase
changed and got out of sync with your login protector.  Ensure you have
correctly [configured the PAM module](#enabling-the-pam-module).  Then, if
necessary, [manually change your login protector's
passphrase](#i-changed-my-login-passphrase-now-all-my-directories-are-inaccessible)
to get it back in sync with your actual login passphrase.

#### Getting "encryption not enabled" on an ext4 filesystem.

This is usually caused by your ext4 filesystem not having the `encrypt` feature
flag enabled.  The `encrypt` feature flag allows the filesystem to contain
encrypted files.  (It doesn't actually encrypt anything by itself.)

Before enabling `encrypt` on your ext4 filesystem, first ensure that all of the
following are true for you:

* You only need to use your filesystem on kernels v4.1 and later.

  (Kernels v4.0 and earlier can't mount ext4 filesystems that have the `encrypt`
  feature flag.)

* Either you only need to use your filesystem on kernels v5.5 and later, or your
  kernel page size (run `getconf PAGE_SIZE`) and filesystem block size (run
  `tune2fs -l /dev/device | grep 'Block size'`) are the same.

  (Both values will almost always be 4096, but they may differ if your
  filesystem is very small, if your system uses the PowerPC CPU architecture, or
  if you overrode the default block size when you created the filesystem.  Only
  kernels v5.5 and later support ext4 encryption in such cases.)

* Either you aren't using GRUB to boot directly off the filesystem in question,
  or you are using GRUB 2.04 or later.

  (Old versions of GRUB can't boot from ext4 filesystems that have `encrypt`
  enabled.  If, like most people, you have a separate `/boot` partition, you are
  fine.  You are also fine if you are using the GRUB Debian package `2.02-2` or
  later [*not* `2.02_beta*`], including the version in Ubuntu 18.04 and later,
  since the patch to support `encrypt` was backported.)

After verifying all of the above, enable `encrypt` by running:
```
tune2fs -O encrypt /dev/device
```

If you need to undo this, first delete all encrypted files and directories on
the filesystem.  Then, run:
```
fsck -fn /dev/device
debugfs -w -R "feature -encrypt" /dev/device
fsck -fn /dev/device
``` 

If you've enabled `encrypt` but you still get the "encryption not enabled"
error, then the problem is that ext4 encryption isn't enabled in your kernel
config.  See [Runtime Dependencies](#runtime-dependencies) for how to enable it.

#### Getting "Operation not permitted" when moving files into an encrypted directory.

This occurs when the kernel version is older than v5.1 and the source files are
on the same filesystem and are either unencrypted or are in a different
encrypted directory hierarchy.

Solution: copy the files instead, e.g. with `cp`.

`mv` works on kernels v5.1 and later, since those kernels return the correct
error code to make `mv` fall back to a copy itself.

__HOWEVER:__ in either case, it is important to realize that the original files
may remain recoverable from free space on the disk after they are deleted.  It's
much better to keep all files encrypted from the very beginning.

As a last resort, the `shred` program may be used to try to overwrite the
original files, e.g.:

```shell
cp file encrypted_dir/
shred -u file
```

However, `shred` isn't guaranteed to be effective on all filesystems and storage
devices.

#### Can't log in with ssh even when user's encrypted home directory is unlocked

This is caused by a limitation in the original design of Linux
filesystem encryption which made it difficult to ensure that all
processes can access unlocked encrypted files.  This issue can also
manifest in other ways such as Docker containers being unable to
access encrypted files, or NetworkManager being unable to access
certificates if they are located in an encrypted directory.

The recommended way to fix this is by creating your encrypted
directories using v2 encryption policies rather than v1.  This
requires Linux v5.4 or later and `fscrypt` v0.2.6 or later.  If these
prerequisites are met, enable v2 policies for new directories by
setting `"policy_version": "2"` in `/etc/fscrypt.conf`.  For example:

```
	"options": {
		"padding": "32",
		"contents": "AES_256_XTS",
		"filenames": "AES_256_CTS",
		"policy_version": "2"
	},
```

This only affects new directories.  If you want to upgrade an existing
encrypted directory to use a v2 policy, you'll need to re-create it by
using `fscrypt encrypt` to encrypt a new empty directory, copying your
files into it, and replacing the original directory with it.

In `fscrypt` v0.2.7 and later, the `fscrypt setup` command
automatically sets `"policy_version": "2"` when creating
`/etc/fscrypt.conf` if kernel support is present.

__IMPORTANT:__ directories that use v2 encryption policies are
unusable on Linux v5.3 and earlier.  If this will be a problem for you
(for example, if your encrypted directories are on removable storage
that needs to work on computers with both old and new kernels), you'll
need to use v1 policies instead.  In this case, you can enable a
fallback option to make `fscrypt` use the filesystem keyring for v1
policies:

```
	"use_fs_keyring_for_v1_policies": true
```

This fallback option only has an effect if the kernel supports using
the filesystem keyring.  This option is also useful if you simply
don't want to re-create your old, v1 directories.  However, this
option makes manually unlocking and locking encrypted directories
start to require root.  (The PAM module will still work.)  E.g.,
you'll need to run `sudo fscrypt unlock`, not `fscrypt unlock`.  Most
people should just use v2 policies instead.

## Legal

Copyright 2017 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0); see the
`LICENSE` file for more information.

Author: Joe Richey <joerichey@google.com>

This is not an official Google product.
