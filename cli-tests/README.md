# fscrypt command-line interface tests

## Usage

To run the command-line interface (CLI) tests for `fscrypt`, ensure
that your kernel is v5.4 or later and has `CONFIG_FS_ENCRYPTION=y`.
Also ensure that you have the following packages installed:

* e2fsprogs
* expect
* keyutils

Then, run:

```shell
make cli-test
```

You'll need to enter your `sudo` password, as the tests require root.

If you only want to run specific tests, run a command like:

```shell
make && sudo cli-tests/run.sh t_encrypt t_unlock
```

## Updating the expected output

When the output of `fscrypt` has intentionally changed, the test
`.out` files need to be updated.  This can be done automatically by
the following command, but be sure to review the changes:

```shell
make cli-test-update
```

## Writing CLI tests

The fscrypt CLI tests are `bash` scripts named like `t_*.sh`.

The test scripts must be executable and begin by sourcing `common.sh`.
They all run in bash "extra-strict mode" (`-e -u -o pipefail`).  They
run as root and have access to the following environment:

* `$DEV`, `$DEV_ROOT`: ext4 filesystem images with encryption enabled

* `$MNT`, `$MNT_ROOT`: the mountpoints of the above filesystems.
  Initially all filesystems are mounted and are setup for fscrypt.
  Login protectors will be stored on `$MNT_ROOT`.

* `$TMPDIR`: a temporary directory that the test may use

* `$FSCRYPT_CONF`: location of the fscrypt.conf file.  Initially this
  file exists and specifies to use v2 policies with the default
  settings, except password hashing is configured to be extra fast.

* `$TEST_USER`: a non-root user that the test may use.  Their password
  is `TEST_USER_PASS`.

Any output (stdout and stderr) the test prints is compared to the
corresponding `.out` file.  If a difference is detected then the test
is considered to have failed.  The output is first sent through some
standard filters; see `run.sh`.

The test is also failed if it exits with nonzero status.

See `common.sh` for utility functions the tests may use.
