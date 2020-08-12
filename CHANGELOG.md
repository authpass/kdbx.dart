## unreleased 

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
