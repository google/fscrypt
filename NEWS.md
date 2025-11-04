# `fscrypt` release notes

## Version 0.3.6

* Upgraded various dependencies, including `golang.org/x/crypto` where the
  upgrade resolves CVE-2024-45337 and CVE-2025-22869.  (These vulnerabilities
  didn't actually affect `fscrypt`, as it doesn't use the relevant features.)

* `fscrypt` now requires Go 1.23 or later to build.

* Added fallback logic for when sysfs is not mounted.

* Other minor fixes and documentation improvements.

## Version 0.3.5

* Upgraded various dependencies, resolving two security alerts from GitHub.

* `fscrypt` now requires Go 1.18 or later to build.

* `fscrypt` now provides a better error message when it's asked to operate on a
  locked regular file.

* Made some improvements to the documentation.

## Version 0.3.4

* `fscrypt` now requires Go 1.16 or later to build.

* `pam_fscrypt` now supports the option `unlock_only` to disable locking of
  directories on logout.

* Fixed a bug where the number of CPUs used in the passphrase hash would be
  calculated incorrectly on systems with more than 255 CPUs.

* Added support for AES-256-HCTR2 filenames encryption.

* Directories are now synced immediately after an encryption policy is applied,
  reducing the chance of an inconsistency after a sudden crash.

* Added Lustre to the list of allowed filesystems.

* Added a NEWS.md file that contains the release notes, and backfilled it from
  the GitHub release notes.

## Version 0.3.3

This release contains fixes for three security vulnerabilities and related
security hardening:

* Correctly handle malicious mountpoint paths in the `fscrypt` bash completion
  script (CVE-2022-25328, command injection).

* Validate the size, type, and owner (for login protectors) of policy and
  protector files (CVE-2022-25327, denial of service).

* Make the `fscrypt` metadata directories non-world-writable by default
  (CVE-2022-25326, denial of service).

* When running as a non-root user, ignore policy and protector files that aren't
  owned by the user or by root.

* Also require that the metadata directories themselves and the mountpoint root
  directory be owned by the user or by root.

* Make policy and protector files mode `0600` rather than `0644`.

* Make all relevant files owned by the user when `root` encrypts a directory
  with a user's login protector, not just the login protector itself.

* Make `pam_fscrypt` ignore system users completely.

Thanks to Matthias Gerstner (SUSE) for reporting the above vulnerabilities and
suggesting additional hardening.

Note: none of these vulnerabilities or changes are related to the cryptography
used.  The main issue was that it wasn't fully considered how `fscrypt`'s
metadata storage method could lead to denial-of-service attacks if a local user
is malicious.

Although upgrading to v0.3.3 shouldn't break existing users, there may be some
edge cases where users were relying on functionality in ways we didn't
anticipate.  If you encounter any issues, please report them as soon as possible
so that we can find a solution for you.

## Version 0.3.2

* Made linked protectors (e.g., login protectors used on a non-root filesystem)
  more reliable when a filesystem UUID changes.

* Made login protectors be owned by the user when they are created as root, so
  that the user has permission to update them later.

* Made `fscrypt` work when the root directory is on a btrfs filesystem.

* Made `pam_fscrypt` start warning when a user's login protector is getting
  de-synced due to their password being changed by root.

* Support reading the key for raw key protectors from standard input.

* Made `fscrypt metadata remove-protector-from-policy` work even if the
  protector is no longer accessible.

* Made `fscrypt` stop trying to access irrelevant filesystems.

* Improved the documentation.

## Version 0.3.1

* Slightly decreased the amount of memory that `fscrypt` uses for password
  hashing, to avoid out-of-memory situations.

* Made recovery passphrase generation happen without a prompt by default, and
  improved the explanation given.

* Made many improvements to the README file.

* Various other minor fixes

## Version 0.3.0

While this release includes some potentially breaking changes, we don't expect
this to break users in practice.

* Potentially breaking changes to `pam_fscrypt` module:
    * Remove the `drop_caches` and `lock_policies` options.  The `lock_policies`
      behavior is now unconditional, while the correct `drop_caches` setting is
      now auto-detected.  Existing PAM files that specify these options will
      continue to work, but these options will now be ignored.
    * Prioritize over other session modules.  The `pam_fscrypt` session hook is
      now inserted into the correct place in the PAM stack when `pam_fscrypt` is
      configured using Debian's / Ubuntu's PAM configuration framework.

* Non-breaking changes:
    * Add Bash completions for `fscrypt`.
    * Fix an error message.
    * Correctly detect "incompletely locked" v1-encrypted directories on kernel
      versions 5.10 and later.

* Other:
    * Improve Ubuntu installation instructions.
    * Minor README updates
    * CI updates, including switching from Travis CI to GitHub Actions

## Version 0.2.9

This release includes:

* Fix 32-bit build.  This was supposed to be fixed in v0.2.8, but another
  breakage was added in the same release.

* Clarify output of `fscrypt status DIR` on v1-encrypted directories in some
  cases.

* [Developers]
    * Add 32-bit build to presubmit checks.
    * Fix `cli-tests/t_v1_policy` to not be flaky.

## Version 0.2.8

* Build fixes
    * Fix build on 32-bit platforms.
    * Fix build with gcc 10.

* Allow `fscrypt` to work in containers.

* Usability improvements
    * Improve many error messages and suggestions.  For example, if the
      `encrypt` feature flag needs to be enabled on an ext4 filesystem,
      `fscrypt` will now show the `tune2fs` command to run.
    * Document how to securely use login protectors, and link to that
      documentation when creating a new login protector.
    * Try to detect incomplete locking of v1-encrypted directory.
    * Several other small improvements

* [Developers] Added command-line interface tests.

## Version 0.2.7

The main addition in this release is that we now automatically detect support
for V2 policies when running `fscrypt setup` and configure `/etc/fscrypt.conf`
appropriately.  This allows users on newer kernels to automatically start using
V2 policies without manually changing `/etc/fscrypt.conf`.  To use these new
policies, simply run `sudo fscrypt setup` and your `/etc/fscrypt.conf` will be
automatically updated.

We also made changes to make the build of `fscrypt` reproducible:
* Simplify `fscrypt --version` output.
* Use `-trimpath`.

Finally, we added improved documentation and fixed up the Makefile.

## Version 0.2.6

The big feature in this release is support for v2 kernel encryption policies.
With the release of Linux 5.4, the kernel added a [new type of
policy](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html) that
makes `fscrypt` much easier to use.  For directories using these new policies:

* `fscrypt unlock` makes the plaintext version of the directory visible to all
  users (if they have permission).  This makes sharing encrypted folders between
  users (or a user and root) much easier.

* `fscrypt lock` (also new in this release) can be run as a non-root user.

* The policies are no longer tied to the buggy kernel keyring API.
    * This removes the need for users to run `keyctl link` or to reconfigure
      `pam_keyinit`.
    * Some systemd related bugs will no longer be an issue.

* Denial-of-Service attacks possible with the v1 API can no longer be used.

To use this new functionality, make sure you are on Linux 5.4 or later.  Then,
add `"policy_version": "2"` to `"options"` in `/etc/fscrypt.conf`.  After this,
all new directories will encrypted with v2 polices.  See the `README.md` for
more information, including how to use some of the new kernel features with
existing directories.

Many thanks to @ebiggers for the herculean effort to get this code (and the
kernel code) tested and merged.

Other new features in this release:
* The `.fscrypt` directory can now be a symlink.
* When an encrypted directory and a protector reside on different
  filesystems, we now automatically create a recovery password.

Bug fixes in this release:
* Bind mounts are now handled correctly.
* Cleanup polices/protectors on failure.
* Config file is created with the correct mode.
* `fscrypt setup` now properly creates `/.fscrypt`.
* Work around strange Go interaction with process keyrings.
* Misc Optimizations
* Build and CI improvements
* Doc updates

## Version 0.2.5

A special thanks to @ebiggers for most of the changes in this release.

With the release of 1.13 recently, the minimum supported version of Go for
`fscrypt` is now 1.12.

`fscrypt` now uses go modules (and no longer uses `dep`).

New Features:
* [Adiantum](https://github.com/google/adiantum) support
* Display encryption options in `fscrypt status DIR`.

Changes to improve stability of `fscrypt`:
* Ensure `fscrypt` file updates are always atomic.
* Use sane defaults for newly encrypted directories.
* Install PAM modules/configs correctly.

The remaining changes include numerous fixes to the Documentation and CI.

## Version 0.2.4

This release contains multiple bug fixes, including a fix for
[CVE-2018-6558](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6558),
which allowed for privilege escalation.  Please update `fscrypt` as soon as
possible.  Debian and Ubuntu updates should be available soon.

## Version 0.2.3

This small release makes `fscrypt` much easier to build and use.

* `PasswordHash` has completely moved to
  [`x/crypto/argon2`](https://godoc.org/golang.org/x/crypto/argon2), eliminating
  the [`libargon2`](https://github.com/P-H-C/phc-winner-argon2) build and
  runtime dependency.  Now the dependencies to build `fscrypt` are `go`, `make`,
  `gcc`, and some system headers.  That's it!

* `PasswordHash` will only use at most 128MiB.  This allows users to encrypt
  files on removable media and rest assured that it will still work when plugged
  into another system with less memory.

* `fscrypt`'s build and CI systems have been greatly improved.  All dependencies
  are now vendored with `dep` allowing for reproducible builds.  Building,
  testing, and changing `fscrypt` is now much more straightforward.

* Other minor fixes

## Version 0.2.2

This release improves the process of purging keyrings by:
* Fixing a bug where keys would not be cleared on logout if the session
  keyring was misconfigured
* Always syncing the filesystem metadata when purging keys

Minor features include:
* Added cryptographic algorithms from the 4.13 kernel.
* Improved our Travis CI processes.

Features coming in 0.3:
* Major Documentation rewrite
* Commands to automatically handle ext4 feature flags
* UI refactoring

## Version 0.2.1

See the Pull Requests and Closed Issues for more detailed information.

* The PAM module now works without crashing the login process.
* Keys work properly when switching between root and non-root users.
* Finalized how the keys will be provisioned into the kernel keyring.

## Version 0.2.0

This release introduces the PAM Module and associated documentation.

It also includes numerous bug fixes.

## Version 0.1.0

This is the version of `fscrypt` which was first made public on Github.

The redacted commit history from internal development is maintained.
