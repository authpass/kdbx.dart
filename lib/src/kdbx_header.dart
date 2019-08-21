import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart' as convert;
import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/export.dart';

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
  InnerRandomStreamID,
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
  KdbxHeader({this.sig1, this.sig2, this.versionMinor, this.versionMajor, this.fields});

  static Future<KdbxHeader> read(ReaderHelper reader) async {
    // reading signature
    final sig1 = reader.readUint32();
    final sig2 = reader.readUint32();
    if (!(sig1 == Consts.FileMagic && sig2 == Consts.Sig2Kdbx)) {
      throw UnsupportedError('Unsupported file structure. ${ByteUtils.toHex(sig1)}, ${ByteUtils.toHex(sig2)}');
    }

    // reading version
    final versionMinor = reader.readUint16();
    final versionMajor = reader.readUint16();

    _logger.finer('Reading version: $versionMajor.$versionMinor');
    final headerFields = Map.fromEntries(readField(reader, versionMajor).map((field) => MapEntry(field.field, field)));
    return KdbxHeader(
      sig1: sig1,
      sig2: sig2,
      versionMinor: versionMinor,
      versionMajor: versionMajor,
      fields: headerFields,
    );
  }

  static Iterable<HeaderField> readField(ReaderHelper reader, int versionMajor) sync* {
    while (true) {
      final headerId = reader.readUint8();
      int size = versionMajor >= 4 ? reader.readUint32() : reader.readUint16();
      _logger.finer('Read header ${HeaderFields.values[headerId]}');
      final bodyBytes = size > 0 ? reader.readBytes(size) : null;
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
}

class Credentials {
  Credentials(this._password);

  final ProtectedValue _password;

  Uint8List getHash() {
    final output = convert.AccumulatorSink<crypto.Digest>();
    final input = crypto.sha256.startChunkedConversion(output);
    input.add(_password.hash);
    input.close();
    return output.events.single.bytes as Uint8List;
  }
}

class KdbxException implements Exception {}

class KdbxInvalidKeyException implements KdbxException {}

class KdbxCorruptedFileException implements KdbxException {}

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
        if (!ByteUtils.eq(crypto.sha256.convert(blockData).bytes as Uint8List, blockHash.asUint8List())) {
          throw KdbxCorruptedFileException();
        }
        yield blockData;
      } else {
        break;
      }
    }
  }
}

class ReaderHelper {
  ReaderHelper(this.data);

  final Uint8List data;
  int pos = 0;

  ByteBuffer _nextByteBuffer(int byteCount) => data.sublist(pos, pos += byteCount).buffer;

  int readUint32() => _nextByteBuffer(4).asUint32List().first;

  int readUint16() => _nextByteBuffer(2).asUint16List().first;

  int readUint8() => data[pos++];

  ByteBuffer readBytes(int size) => _nextByteBuffer(size);

  Uint8List readRemaining() => data.sublist(pos);
}

