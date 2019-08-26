import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/internal/consts.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/api.dart';

final _logger = Logger('kdbx.header');

class Consts {
  static const FileMagic = 0x9AA2D903;

  static const Sig2Kdbx = 0xB54BFB67;
}

enum Compression {
  /// id: 0
  none,

  /// id: 1
  gzip,
}

/// how protected values are encrypted in the xml.
enum ProtectedValueEncryption { plainText, arc4variant, salsa20 }

enum HeaderFields {
  EndOfHeader,
  Comment,
  CipherID,
  CompressionFlags,
  MasterSeed,
  TransformSeed,
  TransformRounds,
  EncryptionIV,
  ProtectedStreamKey,
  StreamStartBytes,
  InnerRandomStreamID, // crsAlgorithm
  KdfParameters,
  PublicCustomData,
}

class HeaderField {
  HeaderField(this.field, this.bytes);

  final HeaderFields field;
  final ByteBuffer bytes;

  String get name => field.toString();
}

class KdbxHeader {
  KdbxHeader({
    @required this.sig1,
    @required this.sig2,
    @required this.versionMinor,
    @required this.versionMajor,
    @required this.fields,
  });

  KdbxHeader.create()
      : this(
          sig1: Consts.FileMagic,
          sig2: Consts.Sig2Kdbx,
          versionMinor: 1,
          versionMajor: 3,
          fields: _defaultFieldValues(),
        );

  static ByteBuffer _intAsUintBytes(int val) =>
      Uint8List.fromList([val]).buffer;

  static List<HeaderFields> _requiredFields(int majorVersion) {
    if (majorVersion < 3) {
      throw KdbxUnsupportedException('Unsupported version: $majorVersion');
    }
    final baseHeaders = [
      HeaderFields.CipherID,
      HeaderFields.CompressionFlags,
      HeaderFields.MasterSeed,
      HeaderFields.EncryptionIV
    ];
    if (majorVersion < 4) {
      return baseHeaders +
          [
            HeaderFields.TransformSeed,
            HeaderFields.TransformRounds,
            HeaderFields.ProtectedStreamKey,
            HeaderFields.StreamStartBytes,
            HeaderFields.InnerRandomStreamID
          ];
    } else {
      // TODO kdbx 4 support
      throw KdbxUnsupportedException('We do not support kdbx 4.x right now');
      return baseHeaders + [HeaderFields.KdfParameters]; // ignore: dead_code
    }
  }

  void _validate() {
    for (HeaderFields required in _requiredFields(versionMajor)) {
      if (fields[required] == null) {
        throw KdbxCorruptedFileException('Missing header $required');
      }
    }
  }

  void _setHeaderField(HeaderFields field, ByteBuffer bytes) {
    fields[field] = HeaderField(field, bytes);
  }

  void generateSalts() {
    // TODO make sure default algorithm is "secure" engouh. Or whether we should
    // use [Random.secure]?
    final random = SecureRandom();
    _setHeaderField(HeaderFields.MasterSeed, random.nextBytes(32).buffer);
    if (versionMajor < 4) {
      _setHeaderField(HeaderFields.TransformSeed, random.nextBytes(32).buffer);
      _setHeaderField(HeaderFields.StreamStartBytes, random.nextBytes(32).buffer);
      _setHeaderField(HeaderFields.ProtectedStreamKey, random.nextBytes(32).buffer);
      _setHeaderField(HeaderFields.EncryptionIV, random.nextBytes(16).buffer);
    } else {
      throw KdbxUnsupportedException('We do not support Kdbx 4.x right now. ($versionMajor.$versionMinor)');
    }
  }

  void write(WriterHelper writer) {
    _validate();
    // write signature
    writer.writeUint32(Consts.FileMagic);
    writer.writeUint32(Consts.Sig2Kdbx);
    // write version
    writer.writeUint16(versionMinor);
    writer.writeUint16(versionMajor);
    for (final field
        in HeaderFields.values.where((f) => f != HeaderFields.EndOfHeader)) {
      _writeField(writer, field);
    }
    _writeField(writer, HeaderFields.EndOfHeader);
  }

  void _writeField(WriterHelper writer, HeaderFields field) {
    final value = fields[field];
    if (value == null) {
      return;
    }
    _writeFieldSize(writer, value.bytes.lengthInBytes);
    writer.writeBytes(value.bytes.asUint8List());
  }

  void _writeFieldSize(WriterHelper writer, int size) {
    if (versionMajor >= 4) {
      writer.writeUint32(size);
    } else {
      writer.writeUint16(size);
    }
  }

  static Map<HeaderFields, HeaderField> _defaultFieldValues() =>
      Map.fromEntries([
        HeaderField(HeaderFields.CipherID,
            CryptoConsts.CIPHER_IDS[Cipher.aes].toBytes()),
        HeaderField(HeaderFields.CompressionFlags, _intAsUintBytes(1)),
        HeaderField(HeaderFields.TransformRounds, _intAsUintBytes(6000)),
        HeaderField(
            HeaderFields.InnerRandomStreamID,
            _intAsUintBytes(ProtectedValueEncryption.values
                .indexOf(ProtectedValueEncryption.salsa20))),
      ].map((f) => MapEntry(f.field, f)));

  static KdbxHeader read(ReaderHelper reader) {
    // reading signature
    final sig1 = reader.readUint32();
    final sig2 = reader.readUint32();
    if (!(sig1 == Consts.FileMagic && sig2 == Consts.Sig2Kdbx)) {
      throw UnsupportedError(
          'Unsupported file structure. ${ByteUtils.toHex(sig1)}, '
          '${ByteUtils.toHex(sig2)}');
    }

    // reading version
    final versionMinor = reader.readUint16();
    final versionMajor = reader.readUint16();

    _logger.finer('Reading version: $versionMajor.$versionMinor');
    final headerFields = Map.fromEntries(readField(reader, versionMajor)
        .map((field) => MapEntry(field.field, field)));
    return KdbxHeader(
      sig1: sig1,
      sig2: sig2,
      versionMinor: versionMinor,
      versionMajor: versionMajor,
      fields: headerFields,
    );
  }

  static Iterable<HeaderField> readField(
      ReaderHelper reader, int versionMajor) sync* {
    while (true) {
      final headerId = reader.readUint8();
      final int bodySize =
          versionMajor >= 4 ? reader.readUint32() : reader.readUint16();
      _logger.finer('Read header ${HeaderFields.values[headerId]}');
      final bodyBytes = bodySize > 0 ? reader.readBytes(bodySize) : null;
      if (headerId > 0) {
        yield HeaderField(HeaderFields.values[headerId], bodyBytes);
      } else {
        break;
      }
    }
  }

  final int sig1;
  final int sig2;
  final int versionMinor;
  final int versionMajor;
  final Map<HeaderFields, HeaderField> fields;

  Compression get compression {
    switch (fields[HeaderFields.CompressionFlags].bytes.asUint32List().single) {
      case 0:
        return Compression.none;
      case 1:
        return Compression.gzip;
      default:
        throw KdbxUnsupportedException('compression');
    }
  }

  ProtectedValueEncryption get innerRandomStreamEncryption =>
      ProtectedValueEncryption.values[
          fields[HeaderFields.InnerRandomStreamID].bytes.asUint32List().single];
}

class KdbxException implements Exception {}

class KdbxInvalidKeyException implements KdbxException {}

class KdbxCorruptedFileException implements KdbxException {
  KdbxCorruptedFileException([this.message]);

  final String message;
}

class KdbxUnsupportedException implements KdbxException {
  KdbxUnsupportedException(this.hint);

  final String hint;
}

class HashedBlockReader {
  static Uint8List readBlocks(ReaderHelper reader) =>
      Uint8List.fromList(readNextBlock(reader).expand((x) => x).toList());

  static Iterable<Uint8List> readNextBlock(ReaderHelper reader) sync* {
    while (true) {
      final blockIndex = reader.readUint32();
      final blockHash = reader.readBytes(32);
      final blockSize = reader.readUint32();
      if (blockSize > 0) {
        final blockData = reader.readBytes(blockSize).asUint8List();
        if (!ByteUtils.eq(crypto.sha256.convert(blockData).bytes as Uint8List,
            blockHash.asUint8List())) {
          throw KdbxCorruptedFileException();
        }
        yield blockData;
      } else {
        break;
      }
    }
  }
}
