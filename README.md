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

* Supports kdbx v3 with native dart implementation
* Supports kdbx v4 with combination with [argon2 ffi](https://github.com/authpass/argon2_ffi)

# Argon2 support

root directory contains shared libraris (libargon2*) which are built from
https://github.com/authpass/argon2_ffi

* MacOS:
  * argon2_ffi/ios/Classes
  * `cmake . && cmake --build .`
  * `cp libargon2_ffi.dylib kdbx.dart/`
  * Might need to run: `codesign --remove-signature /usr/local/bin/dart`
    https://github.com/dart-lang/sdk/issues/39231#issuecomment-579743656
* Linux:
  * argon2_ffi/ios/Classes
  * `cmake . && cmake --build .`
  * `cp libargon2_ffi.so kdbx.dart/`
* Windows:
  * Install Visual Studio Commnity Edition with C++ Development environment
  * Start "Developer Command Prompt for VS 2019"
  * argon2_ffi/ios/Classes:
    ```
    cmake .
    cmake --build .
    cp Debug\argon2_ffi.dll C:\kdbx.dart\argon2_ffi_plugin.dll
    ```

# OLD INFO:

# TODO

* For v4 argon2 support would be required. Unfortunately there are no dart 
  implementations, or bindings yet. (as far as I can find).
    * Reference implementation: https://github.com/P-H-C/phc-winner-argon2
    * Rust: https://github.com/bryant/argon2rs/blob/master/src/argon2.rs
    * C#: https://github.com/mheyman/Isopoh.Cryptography.Argon2

