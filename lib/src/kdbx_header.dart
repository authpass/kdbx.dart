import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/crypto/key_encrypter_kdf.dart';
import 'package:kdbx/src/internal/byte_utils.dart';
import 'package:kdbx/src/internal/consts.dart';
import 'package:kdbx/src/kdbx_var_dictionary.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:kdbx/src/utils/scope_functions.dart';

final _logger = Logger('kdbx.header');

class Consts {
  static const FileMagic = 0x9AA2D903;

  static const Sig2Kdbx = 0xB54BFB67;
  static const DefaultKdfSaltLength = 32;
  static const DefaultKdfParallelism = 1;
  static const DefaultKdfIterations = 2;
  static const DefaultKdfMemory = 1024 * 1024;
  static const DefaultKdfVersion = 0x13;
}

enum Compression {
  /// id: 0
  none,

  /// id: 1
  gzip,
}

/// how protected values are encrypted in the xml.
enum ProtectedValueEncryption { plainText, arc4variant, salsa20, chaCha20 }

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

enum InnerHeaderFields {
  EndOfHeader,
  InnerRandomStreamID,
  InnerRandomStreamKey,
  Binary,
}

abstract class HeaderFieldBase<T> {
  T get field;
}

class HeaderField implements HeaderFieldBase<HeaderFields> {
  HeaderField(this.field, this.bytes);

  @override
  final HeaderFields field;
  final Uint8List bytes;

  String get name => field.toString();
}

class InnerHeaderField implements HeaderFieldBase<InnerHeaderFields> {
  InnerHeaderField(this.field, this.bytes);

  @override
  final InnerHeaderFields field;
  final Uint8List bytes;

  String get name => field.toString();
}

class KdbxHeader {
  KdbxHeader({
    @required this.sig1,
    @required this.sig2,
    @required this.versionMinor,
    @required this.versionMajor,
    @required this.fields,
    @required this.endPos,
    Map<InnerHeaderFields, InnerHeaderField> innerFields,
  }) : innerHeader = InnerHeader(fields: innerFields ?? {});

  KdbxHeader.create()
      : this(
          sig1: Consts.FileMagic,
          sig2: Consts.Sig2Kdbx,
          versionMinor: 1,
          versionMajor: 3,
          fields: _defaultFieldValues(),
          endPos: null,
        );

  KdbxHeader.createV4()
      : this(
          sig1: Consts.FileMagic,
          sig2: Consts.Sig2Kdbx,
          versionMinor: 1,
          versionMajor: 4,
          fields: _defaultFieldValuesV4(),
          innerFields: _defaultInnerFieldValuesV4(),
          endPos: null,
        );

  static List<HeaderFields> _requiredFields(int majorVersion) {
    if (majorVersion < 3) {
      throw KdbxUnsupportedException('Unsupported version: $majorVersion');
    }
    final baseHeaders = [
      HeaderFields.CipherID,
      HeaderFields.CompressionFlags,
      HeaderFields.MasterSeed,
      HeaderFields.EncryptionIV,
    ];
    if (majorVersion < 4) {
      return baseHeaders +
          [
            HeaderFields.TransformSeed,
            HeaderFields.TransformRounds,
            HeaderFields.ProtectedStreamKey,
            HeaderFields.StreamStartBytes,
//            HeaderFields.InnerRandomStreamID
          ];
    } else {
      return baseHeaders + [HeaderFields.KdfParameters];
    }
  }

  static VarDictionary _createKdfDefaultParameters() {
    return VarDictionary([
      KdfField.uuid
          .item(KeyEncrypterKdf.kdfUuidForType(KdfType.Argon2).toBytes()),
      KdfField.salt.item(ByteUtils.randomBytes(Consts.DefaultKdfSaltLength)),
      KdfField.parallelism.item(Consts.DefaultKdfParallelism),
      KdfField.iterations.item(Consts.DefaultKdfIterations),
      KdfField.memory.item(Consts.DefaultKdfMemory),
      KdfField.version.item(Consts.DefaultKdfVersion),
    ]);
  }

  void _validate() {
    for (final required in _requiredFields(versionMajor)) {
      if (fields[required] == null) {
        throw KdbxCorruptedFileException('Missing header $required');
      }
    }
  }

  void _validateInner() {
    final requiredFields = [
      InnerHeaderFields.InnerRandomStreamID,
      InnerHeaderFields.InnerRandomStreamKey
    ];
    for (final field in requiredFields) {
      if (innerHeader.fields[field] == null) {
        throw KdbxCorruptedFileException('Missing inner header $field');
      }
    }
  }

  void _setHeaderField(HeaderFields field, Uint8List bytes) {
    fields[field] = HeaderField(field, bytes);
  }

  void _setInnerHeaderField(InnerHeaderFields field, Uint8List bytes) {
    innerHeader.fields[field] = InnerHeaderField(field, bytes);
  }

  void generateSalts() {
    // TODO make sure default algorithm is "secure" engouh. Or whether we should
    //      use like [SecureRandom] from PointyCastle?
    _setHeaderField(HeaderFields.MasterSeed, ByteUtils.randomBytes(32));
    if (versionMajor < 4) {
      _setHeaderField(HeaderFields.TransformSeed, ByteUtils.randomBytes(32));
      _setHeaderField(HeaderFields.StreamStartBytes, ByteUtils.randomBytes(32));
      _setHeaderField(
          HeaderFields.ProtectedStreamKey, ByteUtils.randomBytes(32));
      _setHeaderField(HeaderFields.EncryptionIV, ByteUtils.randomBytes(16));
    } else if (versionMajor < 5) {
      _setInnerHeaderField(
          InnerHeaderFields.InnerRandomStreamKey, ByteUtils.randomBytes(64));
      final kdfParameters = readKdfParameters;
      KdfField.salt.write(
          kdfParameters, ByteUtils.randomBytes(Consts.DefaultKdfSaltLength));
      //         var ivLength = this.dataCipherUuid.toString() === Consts.CipherId.ChaCha20 ? 12 : 16;
      //        this.encryptionIV = Random.getBytes(ivLength);
      final cipherId = base64.encode(fields[HeaderFields.CipherID].bytes);
      final ivLength =
          cipherId == CryptoConsts.CIPHER_IDS[Cipher.chaCha20].uuid ? 12 : 16;
      _setHeaderField(
          HeaderFields.EncryptionIV, ByteUtils.randomBytes(ivLength));
    } else {
      throw KdbxUnsupportedException(
          'We do not support Kdbx 3.x and 4.x right now. ($versionMajor.$versionMinor)');
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
    fields[HeaderFields.EndOfHeader] =
        HeaderField(HeaderFields.EndOfHeader, Uint8List(0));
    _writeField(writer, HeaderFields.EndOfHeader);
  }

  void writeInnerHeader(WriterHelper writer) {
    _validateInner();
    for (final field in InnerHeaderFields.values
        .where((f) => f != InnerHeaderFields.EndOfHeader)) {
      _writeInnerFieldIfExist(writer, field);
    }
    // write attachments
    for (final binary in innerHeader.binaries) {
      _writeInnerField(writer, binary);
    }
    _setInnerHeaderField(InnerHeaderFields.EndOfHeader, Uint8List(0));
    _writeInnerFieldIfExist(writer, InnerHeaderFields.EndOfHeader);
  }

  void _writeInnerFieldIfExist(WriterHelper writer, InnerHeaderFields field) {
    final value = innerHeader.fields[field];
    if (value == null) {
      return;
    }
    _writeInnerField(writer, value);
  }

  void _writeInnerField(WriterHelper writer, InnerHeaderField value) {
    final field = value.field;
    _logger.finer(
        'Writing header $field (${field.index}) (${value.bytes.lengthInBytes})');
    writer.writeUint8(field.index);
    _writeFieldSize(writer, value.bytes.lengthInBytes);
    writer.writeBytes(value.bytes);
  }

  void _writeField(WriterHelper writer, HeaderFields field) {
    final value = fields[field];
    if (value == null) {
      return;
    }
    _logger.finer('Writing header $field (${value.bytes.lengthInBytes})');
    writer.writeUint8(field.index);
    _writeFieldSize(writer, value.bytes.lengthInBytes);
    writer.writeBytes(value.bytes);
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
        HeaderField(
            HeaderFields.CompressionFlags, WriterHelper.singleUint32Bytes(1)),
        HeaderField(
            HeaderFields.TransformRounds, WriterHelper.singleUint64Bytes(6000)),
        HeaderField(
            HeaderFields.InnerRandomStreamID,
            WriterHelper.singleUint32Bytes(ProtectedValueEncryption.values
                .indexOf(ProtectedValueEncryption.salsa20))),
      ].map((f) => MapEntry(f.field, f)));

  static Map<HeaderFields, HeaderField> _defaultFieldValuesV4() =>
      _defaultFieldValues()
        ..remove(HeaderFields.TransformRounds)
        ..remove(HeaderFields.InnerRandomStreamID)
        ..remove(HeaderFields.ProtectedStreamKey)
        ..also((fields) {
          fields[HeaderFields.KdfParameters] = HeaderField(
              HeaderFields.KdfParameters,
              _createKdfDefaultParameters().write());
        });

  static Map<InnerHeaderFields, InnerHeaderField>
      _defaultInnerFieldValuesV4() => Map.fromEntries([
            InnerHeaderField(
                InnerHeaderFields.InnerRandomStreamID,
                WriterHelper.singleUint32Bytes(ProtectedValueEncryption.values
                    .indexOf(ProtectedValueEncryption.chaCha20)))
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
    final headerFields = readAllFields(
        reader,
        versionMajor,
        HeaderFields.values,
        (HeaderFields field, value) => HeaderField(field, value));

    return KdbxHeader(
      sig1: sig1,
      sig2: sig2,
      versionMinor: versionMinor,
      versionMajor: versionMajor,
      fields: headerFields,
      endPos: reader.pos,
    );
  }

  static Map<HeaderFields, HeaderField> readHeaderFields(
          ReaderHelper reader, int versionMajor) =>
      readAllFields(reader, versionMajor, HeaderFields.values,
          (HeaderFields field, value) => HeaderField(field, value));

  static InnerHeader readInnerHeaderFields(
          ReaderHelper reader, int versionMajor) =>
      InnerHeader.fromFields(
        readField(
            reader,
            versionMajor,
            InnerHeaderFields.values,
            (InnerHeaderFields field, value) =>
                InnerHeaderField(field, value)).toList(growable: false),
      );

  static Map<TE, T> readAllFields<T extends HeaderFieldBase<TE>, TE>(
          ReaderHelper reader,
          int versionMajor,
          List<TE> fields,
          T Function(TE field, Uint8List bytes) createField) =>
      Map<TE, T>.fromEntries(
          readField(reader, versionMajor, fields, createField)
              .map((field) => MapEntry(field.field, field)));

  static Iterable<T> readField<T, TE>(
      ReaderHelper reader,
      int versionMajor,
      List<TE> fields,
      T Function(TE field, Uint8List bytes) createField) sync* {
    while (true) {
      final headerId = reader.readUint8();
      final bodySize =
          versionMajor >= 4 ? reader.readUint32() : reader.readUint16();
      final bodyBytes = bodySize > 0 ? reader.readBytes(bodySize) : null;
//      _logger.finer(
//          'Read header ${fields[headerId]}: ${ByteUtils.toHexList(bodyBytes)}');
      if (headerId > 0) {
        final field = fields[headerId];
        _logger.finest('Reading header $field ($headerId) (size: $bodySize)}');
        yield createField(field, bodyBytes);
        /* else {
          if (field == InnerHeaderFields.InnerRandomStreamID) {
            yield HeaderField(HeaderFields.InnerRandomStreamID, bodyBytes);
          } else if (field == InnerHeaderFields.InnerRandomStreamKey) {
            yield HeaderField(HeaderFields.ProtectedStreamKey, bodyBytes);
          }
        }*/
      } else {
        _logger.finest('EndOfHeader ${fields[headerId]}');
        break;
      }
    }
  }

  final int sig1;
  final int sig2;
  final int versionMinor;
  final int versionMajor;
  final Map<HeaderFields, HeaderField> fields;
  final InnerHeader innerHeader;

  /// end position of the header, if we have been reading from a stream.
  final int endPos;

  Compression get compression {
    switch (ReaderHelper.singleUint32(
        fields[HeaderFields.CompressionFlags].bytes)) {
      case 0:
        return Compression.none;
      case 1:
        return Compression.gzip;
      default:
        throw KdbxUnsupportedException('compression');
    }
  }

  ProtectedValueEncryption get innerRandomStreamEncryption =>
      ProtectedValueEncryption
          .values[ReaderHelper.singleUint32(_innerRandomStreamEncryptionBytes)];

  Uint8List get _innerRandomStreamEncryptionBytes => versionMajor >= 4
      ? innerHeader.fields[InnerHeaderFields.InnerRandomStreamID].bytes
      : fields[HeaderFields.InnerRandomStreamID].bytes;

  Uint8List get protectedStreamKey => versionMajor >= 4
      ? innerHeader.fields[InnerHeaderFields.InnerRandomStreamKey].bytes
      : fields[HeaderFields.ProtectedStreamKey].bytes;

  VarDictionary get readKdfParameters => VarDictionary.read(
      ReaderHelper(fields[HeaderFields.KdfParameters].bytes));

  void writeKdfParameters(VarDictionary kdfParameters) =>
      _setHeaderField(HeaderFields.KdfParameters, kdfParameters.write());

  @override
  String toString() {
    return 'KdbxHeader{sig1: $sig1, sig2: $sig2, versionMajor: $versionMajor, versionMinor: $versionMinor}';
  }
}

class KdbxException implements Exception {}

class KdbxInvalidKeyException implements KdbxException {}

class KdbxCorruptedFileException implements KdbxException {
  KdbxCorruptedFileException([this.message]);

  final String message;

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

class HashedBlockReader {
  static const BLOCK_SIZE = 1024 * 1024;
  static const HASH_SIZE = 32;

  static Uint8List readBlocks(ReaderHelper reader) =>
      Uint8List.fromList(readNextBlock(reader).expand((x) => x).toList());

  static Iterable<Uint8List> readNextBlock(ReaderHelper reader) sync* {
    var expectedBlockIndex = 0;
    while (true) {
      // ignore: unused_local_variable
      final blockIndex = reader.readUint32();
      assert(blockIndex == expectedBlockIndex++);
      final blockHash = reader.readBytes(HASH_SIZE);
      final blockSize = reader.readUint32();
      if (blockSize > 0) {
        final blockData = reader.readBytes(blockSize);
        if (!ByteUtils.eq(
            crypto.sha256.convert(blockData).bytes as Uint8List, blockHash)) {
          throw KdbxCorruptedFileException();
        }
        yield blockData;
      } else {
        break;
      }
    }
  }

//  static Uint8List writeBlocks(WriterHelper writer) =>

  static void writeBlocks(ReaderHelper reader, WriterHelper writer) {
    for (var blockIndex = 0;; blockIndex++) {
      final block = reader.readBytesUpTo(BLOCK_SIZE);
      if (block.lengthInBytes == 0) {
        // written all data, write a last empty block.
        writer.writeUint32(blockIndex);
        writer.writeBytes(Uint8List.fromList(
            List.generate(HASH_SIZE, (i) => 0))); // hash 32 ** 0x0
        writer.writeUint32(0); // block size = 0
        return;
      }
      final blockSize = block.lengthInBytes;
      final blockHash = crypto.sha256.convert(block);
      assert(blockHash.bytes.length == HASH_SIZE);
      writer.writeUint32(blockIndex);
      writer.writeBytes(blockHash.bytes as Uint8List);
      writer.writeUint32(blockSize);
      writer.writeBytes(block);
    }
  }
}

class InnerHeader {
  InnerHeader({
    @required this.fields,
    List<InnerHeaderField> binaries,
  })  : binaries = binaries ?? [],
        assert(fields != null);

  factory InnerHeader.fromFields(Iterable<InnerHeaderField> fields) {
    final fieldMap = Map.fromEntries(fields
        .where((f) => f.field != InnerHeaderFields.Binary)
        .map((e) => MapEntry(e.field, e)));
    final binaries =
        fields.where((f) => f.field == InnerHeaderFields.Binary).toList();
    return InnerHeader(fields: fieldMap, binaries: binaries);
  }

  final Map<InnerHeaderFields, InnerHeaderField> fields;
  final List<InnerHeaderField> binaries;

  void updateFrom(InnerHeader other) {
    fields.clear();
    fields.addAll(other.fields);
    binaries.clear();
    binaries.addAll(other.binaries);
  }
}
