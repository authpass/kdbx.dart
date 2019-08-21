import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart' as convert;
import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/crypto/protected_value.dart';
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

String _toHex(int val) => '0x${val.toRadixString(16)}';

String _toHexList(Uint8List list) => list.map((val) => _toHex(val)).join(' ');

class KdbxHeader {
  KdbxHeader({this.sig1, this.sig2, this.versionMinor, this.versionMajor, this.fields});

  static Future<KdbxHeader> read(ReaderHelper reader) async {
    // reading signature
    final sig1 = reader.readUint32();
    final sig2 = reader.readUint32();
    if (!(sig1 == Consts.FileMagic && sig2 == Consts.Sig2Kdbx)) {
      throw UnsupportedError('Unsupported file structure. ${_toHex(sig1)}, ${_toHex(sig2)}');
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

class KdbxFormat {
  static Future<void> read(Uint8List input, Credentials credentials) async {
    final reader = ReaderHelper(input);
    final header = await KdbxHeader.read(reader);
    _loadV3(header, reader, credentials);
  }

  static void _loadV3(KdbxHeader header, ReaderHelper reader, Credentials credentials) {
//    _getMasterKeyV3(header, credentials);
    final pwHash = credentials.getHash();
    final seed = header.fields[HeaderFields.TransformSeed].bytes.asUint8List();
    final rounds = header.fields[HeaderFields.TransformRounds].bytes.asUint64List().first;
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    final encryptionIv = header.fields[HeaderFields.EncryptionIV].bytes;
    _logger.finer('Rounds: $rounds');
    final cipher = ECBBlockCipher(AESFastEngine());
    final encryptedPayload = reader.readRemaining();
    cipher.init(true, KeyParameter(seed));

    var transformedKey = pwHash;
    for (int i = 0; i < rounds; i++) {
      transformedKey = AesHelper._processBlocks(cipher, transformedKey);
    }
    transformedKey = crypto.sha256.convert(transformedKey).bytes as Uint8List;
    final masterKey =
        crypto.sha256.convert(Uint8List.fromList(masterSeed.asUint8List() + transformedKey)).bytes as Uint8List;
    final decryptCipher = CBCBlockCipher(AESFastEngine());
    decryptCipher.init(false, ParametersWithIV(KeyParameter(masterKey), encryptionIv.asUint8List()));
//    final decrypted = decryptCipher.process(encryptedPayload);
    final decrypted = AesHelper._processBlocks(decryptCipher, encryptedPayload);

    final streamStart = header.fields[HeaderFields.StreamStartBytes].bytes;

    print('streamStart: ${_toHexList(streamStart.asUint8List())}');
    print('actual     : ${_toHexList(decrypted.sublist(0, streamStart.lengthInBytes))}');

    if (!_eq(streamStart.asUint8List(), decrypted.sublist(0, streamStart.lengthInBytes))) {
      throw KdbxInvalidKeyException();
    }
    final content = decrypted.sublist(streamStart.lengthInBytes);
    final blocks = HashedBlockReader.readBlocks(ReaderHelper(content));

    print('compression: ${header.compression}');
    if (header.compression == Compression.gzip) {
      final xml = GZipCodec().decode(blocks);
      final string = utf8.decode(xml);
      print('xml: $string');
    }

//    final result = utf8.decode(decrypted);
//    final aesEngine = AESFastEngine();
//    aesEngine.init(true, KeyParameter(seed));
//    final key = AesHelper.deriveKey(keyComposite.bytes as Uint8List, salt: seed, iterationCount: rounds, derivedKeyLength: 32);
//    final masterKey = Uint8List.fromList(key + masterSeed.asUint8List());
//    print('key length: ${key.length} + ${masterSeed.lengthInBytes} = ${masterKey.lengthInBytes} (${masterKey.lengthInBytes} bytes)');

//    final result = AesHelper.decrypt(masterKey, reader.readRemaining());
    print('before     : ${_toHexList(encryptedPayload)}');
  }

  static void _getMasterKeyV3(KdbxHeader header, Credentials credentials) {
    final pwHash = credentials.getHash();
    final seed = header.fields[HeaderFields.TransformSeed].bytes.asUint8List();
    final rounds = header.fields[HeaderFields.TransformRounds].bytes.asUint64List().first;
    final masterSeed = header.fields[HeaderFields.MasterSeed].bytes;
    final key = AesHelper.deriveKey(pwHash, salt: seed, iterationCount: rounds);
  }
}

bool _eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    return false;
  }
  for (int i = a.length - 1; i >= 0; i--) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
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
        if (!_eq(crypto.sha256.convert(blockData).bytes as Uint8List, blockHash.asUint8List())) {
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

/// https://gist.github.com/proteye/e54eef1713e1fe9123d1eb04c0a5cf9b
class AesHelper {
  static const CBC_MODE = 'CBC';
  static const CFB_MODE = 'CFB';

  // AES key size
  static const KEY_SIZE = 32; // 32 byte key for AES-256
  static const ITERATION_COUNT = 1000;

  static Uint8List deriveKey(
    Uint8List password, {
    Uint8List salt,
    int iterationCount = ITERATION_COUNT,
    int derivedKeyLength = KEY_SIZE,
  }) {
    Pbkdf2Parameters params = Pbkdf2Parameters(salt, iterationCount, derivedKeyLength);
    KeyDerivator keyDerivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 16));
    keyDerivator.init(params);

    return keyDerivator.process(password);
  }

  static String decrypt(Uint8List derivedKey, Uint8List cipherIvBytes, {String mode = CBC_MODE}) {
//    Uint8List derivedKey = deriveKey(password);
    KeyParameter keyParam = KeyParameter(derivedKey);
    BlockCipher aes = AESFastEngine();

//    Uint8List cipherIvBytes = base64.decode(ciphertext);
    Uint8List iv = Uint8List(aes.blockSize)..setRange(0, aes.blockSize, cipherIvBytes);

    BlockCipher cipher;
    ParametersWithIV params = ParametersWithIV(keyParam, iv);
    switch (mode) {
      case CBC_MODE:
        cipher = CBCBlockCipher(aes);
        break;
      case CFB_MODE:
        cipher = CFBBlockCipher(aes, aes.blockSize);
        break;
      default:
        throw ArgumentError('incorrect value of the "mode" parameter');
        break;
    }
    cipher.init(false, params);

    int cipherLen = cipherIvBytes.length - aes.blockSize;
    Uint8List cipherBytes = new Uint8List(cipherLen)..setRange(0, cipherLen, cipherIvBytes, aes.blockSize);
    Uint8List paddedText = _processBlocks(cipher, cipherBytes);
    Uint8List textBytes = unpad(paddedText);

    return String.fromCharCodes(textBytes);
  }

  static Uint8List unpad(Uint8List src) {
    final pad = PKCS7Padding();
    pad.init(null);

    int padLength = pad.padCount(src);
    int len = src.length - padLength;

    return Uint8List(len)..setRange(0, len, src);
  }

  static Uint8List _processBlocks(BlockCipher cipher, Uint8List inp) {
    var out = Uint8List(inp.lengthInBytes);

    for (var offset = 0; offset < inp.lengthInBytes;) {
      var len = cipher.processBlock(inp, offset, out, offset);
      offset += len;
    }

    return out;
  }
}
