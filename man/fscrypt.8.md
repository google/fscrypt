fscrypt(8) -- manage linux filesystem encryption
================================================

## SYNOPSIS

**fscrypt** _command_ [arguments] [command options] [`--quiet` | `--verbose`]

**fscrypt** [_command_] `--help`

**fscrypt** `--version`

## DESCRIPTION

TODO

## WARNINGS

TODO

## ALTERNATIVE TOOLS

**fscrypt** only manages native filesystem encryption. The encryption tools
below may suit your needs better. 

**fscryptctl**(8) also manages filesystem encryption, but it does so through a
very low-level interface. It applies policy identifiers to directories, and
provisions keys into the kernel keyring. If you want to manage key derivation,
key rotation, metadata, and PAM integration yourself, this is a more lightweight
alternative.

Dm-crypt encrypts an entire block device with a single master key. dm-crypt can
be used with or without **fscrypt**. All filesystem data (including all
filesystem metadata) is encrypted with this single key when using dm-crypt,
while **fscrypt** only encrypts the filenames and file contents in a specified
directory. See **cryptsetup**(8) for more information.

It is possible to use both dm-crypt and **fscrypt** simultaneously, giving the
protections and benefits of both. One example of a reasonable setup could
involve using dm-crypt with a TPM or Secure boot key, while using **fscrypt**
on the contents of a home directory. This would still encrypt the entire drive,
but would also tie the encryption of a user's personal documents to their
passphrase. However, this may cause a decrease in your performance, as file
contents can be encrypted twice.  

eCryptfs is another form of filesystem encryption on Linux; it encrypts a
filesystem directory with some key or passphrase. eCryptfs sits on top of an
existing filesystem. This makes eCryptfs an alternative choice if your
filesystem or kernel does not support native filesystem encryption. See
**ecryptfs**(7) for more information.

## REQUIREMENTS

TODO

## OVERVIEW

TODO: Protectors, Policies, Keyring

## COMMANDS

**fscrypt** has multiple _command_ values, each of which can be used with the
common options (in this page) and command-specific options (found in the
below pages).

* **fscrypt-enable**(8):
    Enable encryption on an ext4 filesystem.
* **fscrypt-setup**(8):
    Create necessary global or per-filesystem files.
* **fscrypt-encrypt**(8):
    Start encrypting an empty directory.
* **fscrypt-unlock**(8):
    Unlock an encrypted directory.
* **fscrypt-purge**(8):
    Remove the keys for an encrypted directory.
* **fscrypt-status**(8):
    Print the status of the system, a filesystem, or a file.
* **fscrypt-metadata**(8):
    Manipulate the policy or protector metadata. **Warning:** this is an
    _expert_ command that can easily cause data loss. Use with care.

## OPTIONS

* `--help`:
    Show the help text for fscrypt, using the man pages if possible.
* `--version`:
    Show the version and copyright information.
* `--verbose`:
    Print additional debug messages to standard output.
* `--quiet`:
    Print nothing to standard output except for errors. Select the default for
    any options that would normally show a prompt.

## RETURN VALUES

On success, all **fscrypt** commands return 0. On failure, commands will return
1 and print the corresponding cause of failure to stderr.

## EXAMPLES

TODO

```bash
# Create the global configuration file. Nothing else needs root.
>>>>> sudo fscrypt setup
Create "/etc/fscrypt.conf"? [Y/n] y
Customizing passphrase hashing difficulty for this system...
Created global config file at "/etc/fscrypt.conf".
```

## BUGS

Any bugs, problems, or design discussion relating to **fscrypt** should be
raised in the
[Github Issue Tracker](https://github.com/google/fscrypt/issues/new).

**IMPORTANT:** Any significant security issues should **NOT** be reported in
the public issue tracker. Practice responsible disclosure by emailing
<joerichey@google.com> and <tyhicks@canonical.com> directly.

## AUTHOR

Joe Richey <joerichey94@gmail.com>

## COPYRIGHT

Copyright 2017 Google Inc. under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

## SEE ALSO

**fscrypt-enable**(8) **fscrypt-setup**(8) **fscrypt-encrypt**(8)
**fscrypt-unlock**(8) **fscrypt-purge**(8) **fscrypt-status**(8)
**fscrypt-metadata**(8) **fscrypt-config**(8) **pam_fscrypt**(8)
**fscryptctl**(8)

[**fscrypt**'s upstream repository](https://github.com/google/fscrypt) contains FAQs, known issues, longer examples, and information about building,
testing, and contributing to **fscrypt**.