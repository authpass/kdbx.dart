import 'package:kdbx/src/kdbx_object.dart';

class KdbxException implements Exception {}

class KdbxInvalidKeyException implements KdbxException {}

/// Thrown when a [TransformedKeyCredentials] is used against a file whose KDF
/// parameters have changed since the key was derived — i.e. the file was saved
/// in the meantime and [KdbxHeader.generateSalts] rotated the salt.
///
/// This is not a wrong-credentials error: the user's master password is still
/// correct, the cached derived key simply expired and has to be re-derived from
/// the password.
class KdbxTransformedKeyStaleException implements KdbxException {
  KdbxTransformedKeyStaleException({
    required this.expected,
    required this.actual,
  });

  /// Fingerprint the transformed key was derived for.
  final String expected;

  /// Fingerprint of the file being opened.
  final String actual;

  @override
  String toString() {
    return 'KdbxTransformedKeyStaleException{expected: $expected, '
        'actual: $actual}';
  }
}

class KdbxCorruptedFileException implements KdbxException {
  KdbxCorruptedFileException([this.message]);

  final String? message;

  @override
  String toString() {
    return 'KdbxCorruptedFileException{message: $message}';
  }
}

class KdbxUnsupportedException implements KdbxException {
  KdbxUnsupportedException(this.hint);

  final String hint;

  @override
  String toString() {
    return 'KdbxUnsupportedException{hint: $hint}';
  }
}

/// Thrown when an operation would put two live objects carrying the same uuid
/// into one group - something no kdbx file may contain.
///
/// A file can nevertheless already be in that state. The merge bug fixed after
/// 2.5.0 produced such files, and release builds (with the former assertion
/// compiled out) saved them; it is not the only way a file could have got
/// there, since any writer could have produced one. `KdbxFile` reports it on
/// read through `duplicateUuidsOnOpen`, and `KdbxDao` can repair it with
/// `mergeDuplicateUuidEntries`.
class KdbxDuplicateUuidException implements KdbxException {
  KdbxDuplicateUuidException({required this.uuid, required this.message});

  /// The uuid which is already in use.
  final KdbxUuid uuid;

  final String message;

  @override
  String toString() {
    return 'KdbxDuplicateUuidException{uuid: $uuid, message: $message}';
  }
}

/// Thrown on an attempt to change an entry or group that a merge removed,
/// because the other file had deleted it.
///
/// A merge removes an object only when its deletion is newer than every
/// change to it, so an edit made afterwards would be the first one to come
/// later - and it would be lost, since the object is no longer in the tree
/// and is not saved. A screen that was showing the object when the merge ran
/// is the usual way to get here. Offer to bring it back with
/// `KdbxDao.restore`, which makes the edit possible again.
///
/// Thrown for what changes through the object itself: its fields, an
/// entry's strings and attachments. Not for its `times` or an entry's
/// `customData`, which are nodes of their own, so a change there is still
/// accepted and lost.
class KdbxObjectRemovedException implements KdbxException {
  KdbxObjectRemovedException(this.object);

  /// The object the merge removed.
  final KdbxObject object;

  @override
  String toString() =>
      'KdbxObjectRemovedException{object: $object - removed by a merge, '
      'because the other file deleted it. See KdbxDao.restore.}';
}

class KdbxInvalidFileStructure implements KdbxException {
  KdbxInvalidFileStructure(this.message);

  final String message;

  @override
  String toString() {
    return 'KdbxInvalidFileStructure{$message}';
  }
}
