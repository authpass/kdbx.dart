## Unreleased

- Fix: merging a file which contained an entry the local copy did not have yet
  added every one of that entry's history revisions to the group as a live
  entry, sharing the new entry's uuid, so the database gained duplicate
  entries which look identical in the entry list. The entry's own history was
  unaffected. With assertions enabled the first revision instead tripped an
  assertion in `KdbxGroup.addEntry`, leaving the file partially merged.
- Databases which were already merged by an affected release build still carry
  those duplicates. Reading one now logs it and records the uuids in
  `KdbxFile.duplicateUuidsOnOpen` (reading still succeeds), merging it reports
  them as merge warnings instead of failing with "object was already market as
  merged", and an incoming deletion removes every copy instead of leaving the
  rest behind. `KdbxDao.mergeDuplicateUuidEntries()` repairs such a file by
  folding the extra copies into the surviving entry's history.
- `KdbxGroup.addEntry` now throws a `StateError` instead of only asserting when
  an entry with that uuid is already in the group, so this can no longer pass
  unnoticed in a release build.

## 2.5.0

- `TransformedKeyCredentials`: open a file from the post-KDF key, skipping
  argon2 entirely. Intended for memory constrained callers such as an iOS
  autofill extension. Export one from `KdbxFile.transformedKeyCredentials`
  after a read or save.
- `KdbxFile.kdfFingerprint` to tell whether a stored transformed key still
  matches a file; a mismatch throws `KdbxTransformedKeyStaleException`.
- Fix: `generateSalts()` did not actually rotate the kdbx4 kdf salt, so every
  save reused the salt the file was created with.

## 2.4.2

- Update dependencies. (archive, pointycastle)

## 2.4.1

- Update dependencies.

## 2.4.0

- Migrate to latest dart version.

## 2.3.0

- Mark objects only as clean when saving was successful.
- Only mark objects as clean if they have not been modified since we started saving.
- Make credentials changeable.
- Add support for CustomData in entries.
- Upgrade dependencies.

## 2.2.0

- If argon2 ffi implementation is not available, fallback to pointycastle (dart-only) 
  implementation.

## 2.1.1

- Throw KdbxInvalidFileStructure for invalid files.

## 2.1.0

- Implement permanently removing entries and groups.
- Fix merging of files with incoming deleted objects.

## 2.0.0+1

- Small Null-safety improvement.
- add debugging to AES decryption.

## 2.0.0

- Null-safety migration

## 1.0.0

- Use kdbx 4.x by default when creating new files.
- Implemented support for custom icons.
- Implemented file merging/synchronization.
- Fixed threading problem on save: only allow one save at a time for each file.
- Support for V2 keyfile https://forum.authpass.app/t/issuues-with-keyfile/84/3

## 0.4.1

- fix bug saving files with history entries which contain attachments.
- fix bug which would create wrong history entries.

## 0.4.0+1

- Fix UsageCount typo (vs. Usagecount) #1

## 0.4.0

- Upgraded xml package dependency to 4.x

## 0.3.1

- Fixed error handling nil UUIDs in recycle bin.
  Also, only create recycle bin on demand (when deleting items).

## 0.3.0+1

- Minor fixes for kdbx 4.x

## 0.3.0

- Initial support for kdbx 4.x

## 0.2.1

- Throw unsupported exception when trying to read kdbx 4.x files.

## 0.2.0

- Fixed writing of packet index for payload.
- Fixed big endian vs. little endian encoding.
- Compatibility fixes with other kdbx apps.

## 0.1.0

- Support for reading and writing kdbx 2.x files
  (with a master password)


## 0.0.1

- Initial version, created by Stagehand
