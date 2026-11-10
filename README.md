# kdbx.dart

KeepassX format implementation in pure dart.

Check out [AuthPass Password Manager](https://authpass.app/) for an app
which uses this library.

## Resources

* Code is very much based on https://github.com/keeweb/kdbxweb/
* https://gist.github.com/msmuenchen/9318327

## Usage

```dart
import 'package:kdbx/kdbx.dart';

Future<void> main() async {
  final credentials = Credentials(ProtectedValue.fromString('Lorem Ipsum'));
  final kdbx = KdbxFormat().create(credentials, 'Example');

  final entry = KdbxEntry.create(kdbx, kdbx.body.rootGroup);
  kdbx.body.rootGroup.addEntry(entry);
  entry.setString(KdbxKeyCommon.USER_NAME, PlainValue('example user'));
  entry.setString(
    KdbxKeyCommon.PASSWORD,
    ProtectedValue.fromString('password'),
  );

  final bytes = await kdbx.save();
  final reopened = await KdbxFormat().read(bytes, credentials);
  print(reopened.body.rootGroup.entries.single.getString(KdbxKeyCommon.PASSWORD)
      ?.getText());
}
```

`save()` returns the file as bytes and is asynchronous — await it, or the
write may not have happened. See `example/kdbx_example.dart`.

## Behaviour worth knowing

* **Entry history is bounded** by the `HistoryMaxItems` and `HistoryMaxSize`
  the database itself declares. Revisions are dropped oldest-first when a new
  one is taken and at the end of a merge, never on a plain save, so a file
  that is already over its limits keeps the history of every entry nobody
  touches. A negative limit means unlimited; zero keeps nothing; a limit the
  file does not declare at all is treated as unlimited.
* **Unreferenced attachments are dropped** from the binary pool on save, once
  neither an entry nor any of its revisions points at them.
* **A move is not a modification.** Moving an entry between groups, including
  into the recycle bin, updates `LocationChanged`, leaves
  `LastModificationTime` alone and records no history revision.
* **`KdbxGroup.addEntry` and `KdbxDao.move` can throw**
  `KdbxDuplicateUuidException`, which means `move`, `deleteEntry` and
  `deleteGroup` can too. It only happens on a file which already carries two
  live entries with one uuid — the residue of a merge bug fixed after 2.5.0.
  `KdbxFile.duplicateUuidsOnOpen` reports such a file on read, and
  `KdbxDao.mergeDuplicateUuidEntries()` repairs it.

## Features and bugs

* Supports kdbx v3 with native dart implementation
* Supports kdbx v4 with combination with [argon2 ffi](https://github.com/authpass/argon2_ffi)
* Merging two copies of the same database, for sync

# Argon2 support

root directory contains shared libraries (libargon2*) which are built from
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
  * Install Visual Studio Community Edition with C++ Development environment
  * Start "Developer Command Prompt for VS 2019"
  * argon2_ffi/ios/Classes:
    ```
    cmake .
    cmake --build .
    cp Debug\argon2_ffi.dll C:\kdbx.dart\argon2_ffi_plugin.dll
    ```
