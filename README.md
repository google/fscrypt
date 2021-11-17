# fscrypt [![GitHub version](https://badge.fury.io/go/github.com%2Fgoogle%2Ffscrypt.svg)](https://github.com/google/fscrypt/releases)

[![Build Status](https://github.com/google/fscrypt/workflows/CI/badge.svg)](https://github.com/google/fscrypt/actions?query=workflow%3ACI+branch%3Amaster)
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
native encryption.  See [Runtime dependencies](#runtime-dependencies).

## Table of contents

- [Other encryption solutions](#other-encryption-solutions)
- [Features](#features)
- [Building and installing](#building-and-installing)
- [Runtime dependencies](#runtime-dependencies)
- [Configuration file](#configuration-file)
- [Setting up for login protectors](#setting-up-for-login-protectors)
  - [Securing your login passphrase](#securing-your-login-passphrase)
  - [Enabling the PAM module](#enabling-the-pam-module)
    - [Enabling the PAM module on Debian or Ubuntu](#enabling-the-pam-module-on-debian-or-ubuntu)
	- [Enabling the PAM module on Arch Linux](#enabling-the-pam-module-on-arch-linux)
	- [Enabling the PAM module on other Linux distros](#enabling-the-pam-module-on-other-linux-distros)
  - [Allowing `fscrypt` to check your login passphrase](#allowing-fscrypt-to-check-your-login-passphrase)
- [Backup, restore, and recovery](#backup-restore-and-recovery)
- [Encrypting existing files](#encrypting-existing-files)
- [Example usage](#example-usage)
  - [Setting up fscrypt on a directory](#setting-up-fscrypt-on-a-directory)
  - [Locking and unlocking a directory](#locking-and-unlocking-a-directory)
  - [Protecting a directory with your login passphrase](#protecting-a-directory-with-your-login-passphrase)
  - [Changing a custom passphrase](#changing-a-custom-passphrase)
  - [Using a raw key protector](#using-a-raw-key-protector)
  - [Using multiple protectors for a policy](#using-multiple-protectors-for-a-policy)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)
  - [I changed my login passphrase, now all my directories are inaccessible](#i-changed-my-login-passphrase-now-all-my-directories-are-inaccessible)
  - [Directories using my login passphrase are not automatically unlocking](#directories-using-my-login-passphrase-are-not-automatically-unlocking)
  - [Getting "encryption not enabled" on an ext4 filesystem](#getting-encryption-not-enabled-on-an-ext4-filesystem)
  - [Getting "user keyring not linked into session keyring"](#getting-user-keyring-not-linked-into-session-keyring)
  - [Getting "Operation not permitted" when moving files into an encrypted directory](#getting-operation-not-permitted-when-moving-files-into-an-encrypted-directory)
  - [Getting "Package not installed" when trying to use an encrypted directory](#getting-package-not-installed-when-trying-to-use-an-encrypted-directory)
  - [Some processes can't access unlocked encrypted files](#some-processes-cant-access-unlocked-encrypted-files)
  - [Users can access other users' unlocked encrypted files](#users-can-access-other-users-unlocked-encrypted-files)
  - [Getting "Required key not available" when backing up locked encrypted files](#getting-required-key-not-available-when-backing-up-locked-encrypted-files)
  - [The reported size of encrypted symlinks is wrong](#the-reported-size-of-encrypted-symlinks-is-wrong)
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
   The included PAM module (`pam_fscrypt.so`) can automatically unlock
   directories protected by your login passphrase when you log in, and lock them
   when you log out.  __IMPORTANT:__ before using a login protector, follow
   [Setting up for login protectors](#setting-up-for-login-protectors).

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

See the example usage section below or run `fscrypt COMMAND --help` for more
information about each of the commands.

## Building and installing

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

On Debian (and Debian derivatives such as Ubuntu), use `sudo make install
PREFIX=/usr` to install into `/usr` instead of the default of `/usr/local`.
Ordinarily you shouldn't manually install software into `/usr`, since `/usr` is
reserved for Debian's own packages.  However, Debian's PAM configuration
framework only recognizes configuration files in `/usr`, not in `/usr/local`.
Therefore, the PAM module will only work if you install into `/usr`.  Note: if
you later decide to switch to using the Debian package `libpam-fscrypt`, you'll
have to first manually run `sudo make uninstall PREFIX=/usr`.

It is also possible to use `make install-bin` to only install the `fscrypt`
binary, or `make install-pam` to only install the PAM files.

Alternatively, if you only want to install the `fscrypt` binary to
`$GOPATH/bin`, simply run:
```shell
go get github.com/google/fscrypt/cmd/fscrypt
```

See the `Makefile` for instructions on how to further customize the build.

## Runtime dependencies

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
	"metadata_dir": ""
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

* "use\_fs\_keyring\_for\_v1\_policies" specifies whether to add keys for v1
  encryption policies to the filesystem keyrings, rather than to user keyrings.
  This can solve [issues with processes being unable to access unlocked
  encrypted files](#some-processes-cant-access-unlocked-encrypted-files).
  However, it requires kernel v5.4 or later, and it makes unlocking and locking
  encrypted directories require root.  (The PAM module will still work.)

  The purpose of this setting is to allow people to take advantage of some of
  the improvements in Linux v5.4 on encrypted directories that are also
  compatible with older kernels.  If you don't need compatibility with older
  kernels, it's better to not use this setting and instead (re-)create your
  encrypted directories with `"policy_version": "2"`.

* "metadata_dir" specifies a path to store the fscrypt metadata directory
  (.fscrypt). This is useful if you want to put this outside
  of any filesystem or directory configured for encryption.

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
directories to be automatically unlocked when you log in (and be automatically
locked when you log out), and for login passphrase-protected directories to
remain accessible when you change your login passphrase.

#### Enabling the PAM module on Debian or Ubuntu

The official `libpam-fscrypt` package for Debian (and Debian derivatives such as
Ubuntu) will install a configuration file for [Debian's PAM configuration
framework](https://wiki.ubuntu.com/PAMConfigFrameworkSpec) to
`/usr/share/pam-configs/fscrypt`.  This file contains reasonable defaults for
the PAM module.  To automatically apply these defaults, run
`sudo pam-auth-update` and follow the on-screen instructions.

This file also gets installed if you build and install `fscrypt` from source,
but it is only installed to the correct location if you use `make install
PREFIX=/usr` to install into `/usr` instead of the default of `/usr/local`.

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
unlock directories when logging in as a user, and lock them when logging out.
An easy way to get this working is to add the line:
```
auth        optional    pam_fscrypt.so
```
after `pam_unix.so` in `/etc/pam.d/common-auth` or similar, and to add the
line:
```
session     optional    pam_fscrypt.so
```
after `pam_unix.so` in `/etc/pam.d/common-session` or similar, but before
`pam_systemd.so` or any other module that accesses the user's home directory or
which starts processes that access the user's home directory during their
session.

To make `pam_fscrypt.so` print debugging messages to the system log, add the
`debug` option.  All hook types accept this option.

### Allowing `fscrypt` to check your login passphrase

This step is only needed if you installed `fscrypt` from source code.

Some Linux distros use restrictive settings in `/etc/pam.d/other` that prevent
programs from checking your login passphrase unless a per-program PAM
configuration file grants access.  This prevents `fscrypt` from creating any
login passphrase-protected directories, even without auto-unlocking.  To ensure
that `fscrypt` will work properly (if you didn't install an official `fscrypt`
package from your distro, which should have already handled this), also create a
file `/etc/pam.d/fscrypt` containing:
```
auth        required    pam_unix.so
```

## Backup, restore, and recovery

Encrypted files and directories can't be backed up while they are "locked", i.e.
while they appear in encrypted form.  They can only be backed up while they are
unlocked, in which case they can be backed up like any other files.  Note that
since the encryption is transparent, the files won't be encrypted in the backup
(unless the backup applies its own encryption).

For the same reason (and several others), an encrypted directory can't be
directly "moved" to another filesystem.  However, it is possible to create a new
encrypted directory on the destination filesystem using `fscrypt encrypt`, then
copy the contents of the source directory into it.

For directories protected by a `custom_passphrase` or `raw_key` protector, all
metadata needed to unlock the directory (excluding the actual passphrase or raw
key, of course) is located by default in the `.fscrypt` directory at the root
of the filesystem that contains the encrypted directory.  For example, if you
have an encrypted directory `/home/$USER/private` that is protected by a custom
passphrase, all `fscrypt` metadata needed to unlock the directory with that
custom passphrase will be located by default in `/home/.fscrypt` if you are
using a dedicated `/home` filesystem or in `/.fscrypt` if you aren't.
Alternately, you can specify a different location for fscrypt metadata by
setting the `"metadata_dir"` field in the [Configuration
file](#configuration-file).
If desired, you can back up the `fscrypt` metadata by making a copy of this
directory, although this isn't too important since this metadata is located on
the same filesystem as the encrypted directory(s).

`pam_passphrase` (login passphrase) protectors are a bit different as they are
always stored on the root filesystem, in `/.fscrypt`.  This ties them to the
specific system and ensures that each user has only a single login protector.
Therefore, encrypted directories on a non-root filesystem **can't be unlocked
via a login protector if the operating system is reinstalled or if the disk is
connected to another system** -- even if the new system uses the same login
passphrase for the user.

Because of this, `fscrypt encrypt` will automatically generate a recovery
passphrase when creating a login passphrase-protected directory on a non-root
filesystem.  The recovery passphrase is simply a `custom_passphrase` protector
with a randomly generated high-entropy passphrase.  Initially, the recovery
passphrase is stored in a file in the encrypted directory itself; therefore, to
use it you **must** record it in another secure location.  It is strongly
recommended to do this.  Then, if ever needed, you can use `fscrypt unlock` to
unlock the directory with the recovery passphrase (by choosing the recovery
protector instead of the login protector).

If you really want to disable the generation of a recovery passphrase, use the
`--no-recovery` option.  Only do this if you really know what you are doing and
are prepared for potential data loss.

Alternative approaches to supporting recovery of login passphrase-protected
directories include the following:

* Manually adding your own recovery protector, using
  `fscrypt metadata add-protector-to-policy`.

* Backing up and restoring the `/.fscrypt` directory on the root filesystem.
  Note that after restoring the `/.fscrypt` directory, unlocking the login
  protectors will require the passphrases they had at the time the backup was
  made **even if they were changed later**, so make sure to remember these
  passphrase(s) or record them in a secure location.  Also note that if the UUID
  of the root filesystem changed, you will need to manually fix the UUID in any
  `.fscrypt/protectors/*.link` files on other filesystems.

The auto-generated recovery passphrases should be enough for most users, though.

## Encrypting existing files

`fscrypt` isn't designed to encrypt existing files, as this presents significant
technical challenges and usually is impossible to do securely.  Therefore,
`fscrypt encrypt` only works on empty directories.

Of course, it is still possible to create an encrypted directory, copy files
into it, and delete the original files.  The `mv` command will even work, as it
will fall back to a copy and delete ([except on older
kernels](#getting-operation-not-permitted-when-moving-files-into-an-encrypted-directory)).
However, beware that due to the characteristics of filesystems and storage
devices, this may not properly protect the files, as their original contents may
still be forensically recoverable from disk even after being deleted.  It's
**much** better to encrypt files from the very beginning.

There are only a few cases where copying files into an encrypted directory can
really make sense, such as:

* The source files are located on an in-memory filesystem such as `tmpfs`.

* The confidentiality of the source files isn't important, e.g. they are
  system default files and the user hasn't added any personal files yet.

* The source files are protected by a different `fscrypt` policy, the old and
  new policies are protected by only the same protector(s), and the old policy
  uses similar strength encryption.

If one of the above doesn't apply, then it's probably too late to securely
encrypt your existing files.

As a best-effort attempt, you can use the `shred` program to try to erase the
original files.  Here are the recommended commands for "best-effort" encryption
of an existing directory named "dir":

```bash
mkdir dir.new
fscrypt encrypt dir.new
cp -a -T dir dir.new
find dir -type f -print0 | xargs -0 shred -n1 --remove=unlink
rm -rf dir
mv dir.new dir
```

However, beware that `shred` isn't guaranteed to be effective on all storage
devices and filesystems.  For example, if you're using an SSD, "overwrites" of
data typically go to new flash blocks, so they aren't really overwrites.

Note: for reasons similar to the above, changed or removed `fscrypt` protectors
aren't guaranteed to be forensically unrecoverable from disk either.  Thus, the
use of weak or default passphrases should be avoided, even if changed later.

## Example usage

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

#### Quiet version
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

#### Quiet version
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

#### Quiet version
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

#### Quiet version
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

#### Quiet version
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

#### Quiet version
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

Usually, the PAM module `pam_fscrypt.so` will automatically detect changes to a
user's login passphrase and update the user's `fscrypt` login protector so that
they retain access their login-passphrase protected directories.  However,
sometimes a user's login passphrase can become desynchronized from their
`fscrypt` login protector.  This can happen if `root` assigns the user a new
passphrase without providing the old one, if the user's login passphrase is
managed by an external system such as LDAP, if the PAM module is not installed,
or if the PAM module is not properly configured.  See [Enabling the PAM
module](#enabling-the-pam-module) for how to configure the PAM module.

To fix a user's login protector, find the corresponding protector ID by running
`fscrypt status "/"`.  Then, change this protector's passphrase by running:
```
fscrypt metadata change-passphrase --protector=/:ID
```

#### Directories using my login passphrase are not automatically unlocking

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

#### Getting "encryption not enabled" on an ext4 filesystem

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
config.  See [Runtime dependencies](#runtime-dependencies) for how to enable it.

#### Getting "user keyring not linked into session keyring"

Some older versions of Ubuntu didn't link the user keyring into the session
keyring, which caused problems with `fscrypt`.

To avoid this issue, upgrade to Ubuntu 20.04 or later.

#### Getting "Operation not permitted" when moving files into an encrypted directory

Originally, filesystems didn't return the correct error code when attempting to
rename unencrypted files (or files with a different encryption policy) into an
encrypted directory.  Specifically, they returned `EPERM` instead of `EXDEV`,
which caused `mv` to fail rather than fall back to a copy as expected.

This bug was fixed in version 5.1 of the mainline Linux kernel, as well as in
versions 4.4 and later of the LTS (Long Term Support) branches of the Linux
kernel; specifically v4.19.155, 4.14.204, v4.9.242, and v4.4.242.

If the kernel can't be upgraded, this bug can be worked around by explicitly
copying the files instead, e.g. with `cp`.

__IMPORTANT:__ Encrypting existing files can be insecure.  Before doing so, read
[Encrypting existing files](#encrypting-existing-files).

#### Getting "Package not installed" when trying to use an encrypted directory

Trying to create or open an encrypted file will fail with `ENOPKG` ("Package not
installed") when the kernel doesn't support one or more of the cryptographic
algorithms used by the file or its directory.  Note that `fscrypt encrypt` and
`fscrypt unlock` will still succeed; it's only using the directory afterwards
that will fail.

The kernel will always support the algorithms that `fscrypt` uses by default.
However, if you changed the contents and/or filenames encryption algorithms in
[`/etc/fscrypt.conf`](#configuration-file), then you may run into this issue.
To fix it, enable the needed `CONFIG_CRYPTO_*` options in your Linux kernel
configuration.  See the [kernel
documentation](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html#encryption-modes-and-usage)
for details about which option(s) are required for each encryption mode.

#### Some processes can't access unlocked encrypted files

This issue is caused by a limitation in the original design of Linux filesystem
encryption which made it difficult to ensure that all processes can access
unlocked encrypted files.  This issue can manifest in many ways, such as:

* SSH to a user with an encrypted home directory not working, even when that
  directory is already unlocked

* Docker containers being unable to access encrypted files that were unlocked
  from outside the container

* NetworkManager being unable to access certificates stored in the user's
  already-unlocked encrypted home directory

* Other system services being unable to access already-unlocked encrypted files

* `sudo` sessions being unable to access already-unlocked encrypted files

* A user being unable to access encrypted files that were unlocked by root

If an OS-level error is shown, it is `ENOKEY` ("Required key not available").

To fix this issue, first run `fscrypt status $dir`, where `$dir` is your
encrypted directory.  If the output contains `policy_version:2`, then your issue
is something else, so stop reading now.  If the output contains
`policy_version:1` or doesn't contain any mention of `policy_version`, then
you'll need to upgrade your directory(s) to policy version 2.  To do this:

1. Upgrade to Linux kernel v5.4 or later.

2. Upgrade to `fscrypt` v0.2.7 or later.

3. Run `sudo fscrypt setup --force`.

4. Re-encrypt your encrypted directory(s).  Since files cannot be (re-)encrypted
   in-place, this requires replacing them with new directories.  For example:
   ```
     fscrypt unlock dir  # if not already unlocked
     mkdir dir.new
     fscrypt encrypt dir.new
     cp -a -T dir dir.new
     find dir -type f -print0 | xargs -0 shred -n1 --remove=unlink
     rm -rf dir
     mv dir.new dir
   ```

   You don't need to create a new protector.  I.e., when `fscrypt encrypt` asks
   for a protector, just choose the one you were using before.

5. `fscrypt status` on your directory(s) should now show `policy_version:2`,
   and the issue should be gone.

Note that once your directories are using policy version 2, they will only be
usable with Linux kernel v5.4 and later and `fscrypt` v0.2.6 and later.  So be
careful not to downgrade your software past those versions.

This issue can also be fixed by setting `"use_fs_keyring_for_v1_policies": true`
in `/etc/fscrypt.conf`, as described in [Configuration
file](#configuration-file).  This avoids needing to upgrade directories to
policy version 2.  However, this has some limitations, and the same kernel and
`fscrypt` prerequisites still apply for this option to take effect.  It is
recommended to upgrade your directories to policy version 2 instead.

#### Users can access other users' unlocked encrypted files

This is working as intended.  When an encrypted directory is unlocked (or
locked), it is unlocked (or locked) for all users.  Encryption is not access
control; the Linux kernel already has many access control mechanisms, such as
the standard UNIX file permissions, that can be used to control access to files.

Setting the mode of your encrypted directory to `0700` will prevent users other
than the directory's owner and `root` from accessing it while it is unlocked.
In `fscrypt` v0.2.5 and later, `fscrypt encrypt` sets this mode automatically.

Having the locked/unlocked status of directories be global instead of per-user
may seem unintuitive, but it is actually the only logical way.  The encryption
is done by the filesystem, so in reality the filesystem either has the key or it
doesn't.  And once it has the key, any additional checks of whether particular
users "have" the key would be OS-level access control checks (not cryptography)
that are redundant with existing OS-level access control mechanisms.

Similarly, any attempt of the filesystem encryption feature to prevent `root`
from accessing unlocked encrypted files would be pointless.  On Linux systems,
`root` is usually all-powerful and can always get access to files in ways that
cannot be prevented, e.g. `setuid()` and `ptrace()`.  The only reliable way to
limit what `root` can do is via a mandatory access control system, e.g. SELinux.

The original design of Linux filesystem encryption actually did put the keys
into per-user keyrings.  However, this caused a [massive number of
problems](#some-processes-cant-access-unlocked-encrypted-files), as it's
actually very common that encrypted files need to be accessed by processes
running under different user IDs -- even if it may not be immediately apparent.

#### Getting "Required key not available" when backing up locked encrypted files

Encrypted files can't be backed up while locked; you need to unlock them first.
For details, see [Backup, restore, and recovery](#backup-restore-and-recovery).

#### The reported size of encrypted symlinks is wrong

Originally, filesystems didn't conform to POSIX when reporting the size of
encrypted symlinks, as they gave the size of the ciphertext symlink target
rather than the size of the plaintext target.  This would make the reported size
of symlinks appear to be slightly too large when queried using ``lstat()`` or
similar system calls.  Most programs don't care about this, but in rare cases
programs can depend on the filesystem reporting symlink sizes correctly.

This bug was fixed in version 5.15 of the mainline Linux kernel, as well as in
versions 4.19 and later of the LTS (Long Term Support) branches of the Linux
kernel; specifically v5.10.63, v5.4.145, and v4.19.207.

If the kernel can't be upgraded, the only workaround for this bug is to update
any affected programs to not depend on symlink sizes being reported correctly.

## Legal

Copyright 2017 Google Inc. under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0); see the
`LICENSE` file for more information.

Author: Joe Richey <joerichey@google.com>

This is not an official Google product.
