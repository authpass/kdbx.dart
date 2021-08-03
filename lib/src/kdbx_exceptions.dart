class KdbxException implements Exception {}

class KdbxInvalidKeyException implements KdbxException {}

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

class KdbxInvalidFileStructure implements KdbxException {
  KdbxInvalidFileStructure(this.message);

  final String message;

  @override
  String toString() {
    return 'KdbxInvalidFileStructure{$message}';
  }
}
