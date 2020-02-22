# kdbx.dart

KeepassX format implementation in pure dart.

Check out [AuthPass Password Manager](https://authpass.app/) for an app
which uses this library.

## Resources

* Code is very much based on https://github.com/keeweb/kdbxweb/
* https://gist.github.com/msmuenchen/9318327

## Usage

TODO

## Features and bugs

* Only supports v3.

# Argon2 support

root directory contains shared libraris (libargon2*) which are built from
https://github.com/authpass/argon2_ffi

# OLD INFO:

# TODO

* For v4 argon2 support would be required. Unfortunately there are no dart 
  implementations, or bindings yet. (as far as I can find).
    * Reference implementation: https://github.com/P-H-C/phc-winner-argon2
    * Rust: https://github.com/bryant/argon2rs/blob/master/src/argon2.rs
    * C#: https://github.com/mheyman/Isopoh.Cryptography.Argon2

