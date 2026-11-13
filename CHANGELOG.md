## Unreleased

- Fix: a merge applied the other file's deletions unconditionally, and lost
  data four ways (#24). A deletion now wins only when it is newer than the
  object's last change - its data or where it is, so moving an entry, out of
  the recycle bin say, protects it too; a deletion in the same second does
  not win. Same rule in both directions, so both copies agree:
  - an entry edited after another device deleted it is kept;
  - an entry or group created in, or moved into, a group after another
    device deleted that group is kept, and so is the group to hold it. It
    used to go with the group, silently;
  - an object we deleted no longer comes back from a copy that merely still
    has it unchanged, and such a merge is a no-op rather than a change;
  - no file is left holding a uuid both live and deleted.
  `MergeDeletionRefused` reports a deletion the other file made that was not
  applied, and `MergeObjectDeleted.deletionTime` is now the other file's.
- An entry or group a merge removed now throws `KdbxObjectRemovedException`
  when changed, rather than accepting a change that is never saved - a
  screen showing it during the merge is the usual way to get there.
  `KdbxDao.restore` brings it back, so that the next merge keeps it.
- Fix: a deletion record taken over from the other file was stamped with
  the time of the merge rather than the other file's deletion time, and
  `addDeletedObject` ignored the time it was given, so the records of one
  deleted group could disagree with each other (#32).

- Fix: two copies that changed the same entry or group within the same
  second never agreed again. Times are kept to the second, so neither change
  was newer: each copy kept its own, a merge in either direction reported no
  changes, and the other change left no trace. Such a tie is now decided by
  comparing content, the same way on every device, and for an entry the
  losing version is kept as a history revision on both sides.
  `MergeObjectUpdated` and `MergeLocalVersionKept` carry `decidedByContent`
  for these - also on the device whose edit lost when it merges only after
  the other one has saved the decision. Before time or content, a version
  whose history holds the other's current version wins, since it was made
  from it - whatever the clocks of the devices said. Whether a group is
  expanded, and which entry it was scrolled to, is not content: a group
  differing only in that is not a conflict, as before.
- Fix: an edit made in the same second as the version it replaces - edit,
  save, and edit again quickly - got the same time as that version, so a
  device that had synced the first version kept it on merge. An edit is now
  always stamped at least a second after the version it replaces, also when
  the clock has gone backwards. The many changes of one edit before it is
  saved still share one time rather than each moving it a second further.
- Fix: a merge took two history revisions with the same modification time
  for the same revision, so of two from one second only one was ever brought
  over. Revisions are now told apart by time and content. And when the
  history limits had to choose between revisions with the same time, two
  copies chose differently, then traded the revisions back and forth on
  every sync; they now choose the same one.
- Fix: a merge that took over a group without `EnableAutoType` or
  `EnableSearching`, into a copy that had set one, left the element empty,
  and reading that setting then threw `KdbxCorruptedFileException`. An empty
  one now reads as not set.
- `MergeContext.events` reports what a merge did, object by object, so an
  app can tell the user what a sync changed: `MergeObjectAdded`,
  `MergeObjectUpdated` (with `keptUnsavedEdit` when the version replaced was
  an unsaved edit, now kept only as a history revision),
  `MergeLocalVersionKept` (our newer version won over a change from the
  other copy we had never seen, which is kept in history),
  `MergeObjectMoved` and `MergeObjectDeleted` (with the removed object, so a
  screen showing it can close). A merge that changes nothing reports none.
  `MergeEvent` is deliberately not sealed: later releases will add kinds, so
  a `switch` over it needs a default branch. `MergeContext.changes` is
  unchanged.
- An entry a merge copied in from the other file is no longer taken for an
  unsaved edit before the next save. A second merge that replaced it again
  reported it as the user's unsaved work and spared it from the history
  limits; and a local edit to it before the save now keeps the version the
  other device made as a revision, as it already did for a version a merge
  takes over.
- Fix: a merge which took over the other copy's newer version of an entry
  stamped it with the time of the merge instead of the time the change was
  made. Every merge therefore looked like a fresh edit by the merging side:
  two copies merging each other took turns "winning" and never agreed, each
  round adding another revision with identical content until the history
  limit evicted the genuine ones, and a copy that merely relayed an older
  edit beat a newer edit made elsewhere - reverting a password the user had
  just changed, with the newer value left only in history. The entry now
  keeps the times of the version it took over, so the two copies agree on it,
  and merging the same file again changes nothing. Groups were not affected.
  (#22)
- Fix: a merge into an entry with unsaved changes, where the other copy's
  version was newer, overwrote those changes without keeping them as a
  history revision, so the user's edit was gone without a trace. That is the
  situation a merge after a save conflict is in. The overwritten state is now
  always kept as a revision. When it was an unsaved edit, that revision is
  also spared by the history limits until the next save - even a limit of
  zero, and even when the other copy brings in newer revisions that would
  otherwise push it out - so it is written at least once. After that save it
  is ordinary history. (#23)
- A local edit made after such a merge, before the next save, now keeps the
  version the merge brought in as a revision too, the same way it keeps the
  saved state.
- Fix: `MergeContext.totalChanges()` counted every deletion record in the
  file, including ones both copies had agreed on long ago, so in a database
  with any deletion in its past it was never zero, even for a merge that
  changed nothing. It now counts what the merge itself did: its tracked
  changes plus the deletion records it took over, which are also available
  separately as the new `MergeContext.incomingDeletedObjects`. Changes to the
  database's own settings are not counted yet.
- Fix: a merge which took over the other copy's newer version of an entry
  tracked no change when no field differed - when the other copy had only
  removed an attachment, say, or attached content the file already held. The
  entry was changed and marked dirty, but `MergeContext.changes` was empty
  and `totalChanges()` zero. Such a merge now tracks one change for the
  entry.
- As a result of the restamp fix above (#22), merging back a change this copy
  made itself no longer marks its entries dirty. Before, the copy that made a
  change was dirtied by merging it back, so two copies kept writing the same
  content back and forth.

## 2.6.0

- Entry history is now bounded by the `HistoryMaxItems` and `HistoryMaxSize`
  the database itself declares, which nothing had ever read. Oldest-first by
  modification time, when a revision is taken and once at the end of a merge,
  never on save — so a database already over its limits keeps the history of
  every entry nobody touches. A negative limit means unlimited, zero keeps
  nothing, and a limit the file does not declare at all is treated as
  unlimited rather than defaulted.
- The revisions a duplicate-uuid repair folds into the survivor are held back
  from those limits until the file has been saved and read again. They are
  stamped older than the survivor's own revisions, so the limits would reach
  for them first and delete the last copy of that content on the user's next
  unrelated edit.
- Fix: merging a copy which was older than the local one appended a revision
  of that copy's state on every merge, because the check for whether we
  already had that state compared against our own modification time, which
  can never appear in our own history. Repeated syncs against a replica that
  was never written to again piled up identical revisions.
- Unreferenced attachments are now dropped from the binary pool when a file is
  saved, instead of staying in it for good. Nothing used to shrink the pool:
  detaching an attachment deliberately left the bytes for the revisions which
  still held it, and when those revisions went there was no second pass. With
  the history limits above, a revision can now disappear without the user
  deleting anything, which makes those limits the one thing that can orphan an
  attachment by itself - so the two belong together. The pool is rebuilt from
  what the entries and their revisions still point at, which is also what
  renumbers it.
- Fix: a merge discarded the changes to an object which the incoming copy had
  both edited and moved. The move was applied first and bumped the object's
  own modification time, so the comparison which decides whose data is newer
  then found the local copy newer and kept it - the incoming edit was lost
  with no record of it anywhere.
- A move is no longer treated as a modification of the object. Moving an entry
  between groups, which includes sending it to the recycle bin, updates
  `LocationChanged` and leaves `LastModificationTime` alone, and no longer
  records a history revision - so a trashed entry keeps the history someone
  restoring it would want. The revision belonging to the next real change is
  still recorded.
- Fix: a merge copied the incoming copy's `LocationChanged` along with its
  data, so an object that had been moved locally kept its new group but
  recorded the location time of the group it came from. The two copies then
  never agreed on where it belongs, and a third copy with an older move could
  move it back out again.
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
- Fix: an object removed by an incoming deletion during a merge kept pointing
  at the group it was removed from, so code still holding it saw a parent that
  no longer listed it - and `deletePermanently` on such an object recorded a
  second deleted object for that uuid before failing. It is now detached, the
  way `KdbxDao.deletePermanently` detaches, and `KdbxDao.move` says so instead
  of failing on a null parent.
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
- Fix: a `TransformedKeyCredentials` of the wrong length is rejected instead of
  deriving the wrong cipher key and reporting itself as a wrong password - the
  length assertion only fired in debug builds. Refusing to save now says
  'original credentials' rather than 'master password', and `getHash` is
  documented as able to throw.

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
