Simple AES Encryptor (SAE) is a CLI tool for Linux systems.

SAE uses AES-256 for encryption and BLAKE3 for password hashing.

Commands:
    
    lock: encrypt file/directory
    $ sae lock [PATH] <OPTIONS>

    open: decrypt file/directory
    $ sae open [PATH] <OPTIONS>

    into: specify an output directory
    $ sae lock [PATH] into [OUTPUT] <OPTIONS>
    
    save: access cache for this user
    $ sae save

    help: print this page
    $ sae help

Options:

    -d (--delete) : remove target after operation
    -c (--cache)  : use the cached password hash
