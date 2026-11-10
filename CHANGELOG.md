## Unreleased

- Fix: merging a file which contained an entry the local copy did not have yet
  added every one of that entry's history revisions to the group as a live
  entry, sharing the new entry's uuid, so the database gained duplicate
  entries which look identical in the entry list. The entry's own history was
  unaffected. With assertions enabled the first revision instead tripped an
  assertion in `KdbxGroup.addEntry`, leaving the file partially merged.
- Databases which were already merged by an affected release build still carry
  those duplicates, and nothing noticed them. Reading one now logs it and
  records the uuids in `KdbxFile.duplicateUuidsOnOpen`; reading still
  succeeds. `KdbxFile.findDuplicateUuidObjects()` answers the same question
  about the current state.
- Merging a file which carries duplicates reports them as merge warnings
  instead of failing with an unhelpful `StateError` part way through, and an
  incoming deleted object now removes every copy of that uuid instead of
  leaving the rest behind forever.
- New `KdbxDao.mergeDuplicateUuidEntries()` repairs such a file: for each
  affected uuid the newest entry which is not in the recycle bin survives, and
  the other copies are folded into its history. It records no deleted object,
  since the uuid lives on, and it has to be run on every replica.
- **Breaking:** `KdbxGroup.addEntry` now throws a `KdbxDuplicateUuidException`
  where it previously only asserted that the uuid is not already in the group,
  so it no longer passes unnoticed in a release build. `KdbxDao.move` checks
  the same condition up front and throws the same exception, which means
  `move`, `deleteEntry` and `deleteGroup` can now throw where they used to
  return - on a file that carries duplicates, they have to, because completing
  the move would drop an entry. Callers moving entries around in a file that
  may carry duplicates need to catch it.

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
