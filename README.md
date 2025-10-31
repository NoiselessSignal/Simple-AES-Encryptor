# Simple-AES-Encryptor
Simple AES Encryptor (SAE) is a CLI program for easy file/directory encryption and decryption.

## Help page
```
Simple AES Encryptor (SAE), v. 0.1.0

SAE uses AES-256 for encryption and BLAKE3 for password hashing.

Commands:

    enc : encrypts file/directory
    $ sae enc [TARGET] <OPTIONS>

    dec : decrypts file/directory
    $ sae enc [TARGET] <OPTIONS>

    pwd : cache a password for this user

        Subcommands:

        set : save password hash
        $ sae pwd set <OPTIONS>

        del : remove password hash
        $ sae pwd del <OPTIONS>

        status : check if cache is full or empty
        $ sae pwd status

        verify : compare typed password with the hash
        $ sae pwd verify <OPTIONS>

    help : print this page
    $ sae help

Options:

    -c (--cache)  : use the cached password hash
    -s (--show)   : don't obfuscate password input
    -d (--delete) : remove target after operation
    -q (--quiet)  : hide terminal log
```

## Install

Check out the releases page.

To build SAE yourself, you need the Rust toolchain installed on your Linux system.
```
git clone https://github.com/NoiselessSignal/Simple-AES-Encryptor.git
cd Simple-AES-Encryptor
cargo build -r
```
