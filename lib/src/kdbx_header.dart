import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/crypto/key_encrypter_kdf.dart';
import 'package:kdbx/src/internal/consts.dart';
import 'package:kdbx/src/kdbx_binary.dart';
import 'package:kdbx/src/kdbx_exceptions.dart';
import 'package:kdbx/src/kdbx_var_dictionary.dart';
import 'package:kdbx/src/utils/byte_utils.dart';
import 'package:logging/logging.dart';
import 'package:quiver/check.dart';
import 'package:quiver/core.dart';

final _logger = Logger('kdbx.header');

class Consts {
  static const FileMagic = 0x9AA2D903;

  static const Sig2Kdbx = 0xB54BFB67;
  static const DefaultKdfSaltLength = 32;
  static const DefaultKdfParallelism = 1;
  static const DefaultKdfIterations = 2;
  static const DefaultKdfMemory = 1024 * 1024;
  static const DefaultKdfVersion = 0x13;

  static const DefaultHistoryMaxItems = 20;
  static const DefaultHistoryMaxSize = 10 * 1024 * 1024;
}

enum Compression {
  /// id: 0
  none,

  /// id: 1
  gzip,
}

const _compressionIds = {
  Compression.none: 0,
  Compression.gzip: 1,
};
final _compressionIdsById =
    _compressionIds.map((key, value) => MapEntry(value, key));

extension on Compression {
  int? get id => _compressionIds[this];
}

/// how protected values are encrypted in the xml.
enum ProtectedValueEncryption { plainText, arc4variant, salsa20, chaCha20 }

enum HeaderFields {
  EndOfHeader,
  Comment,

  /// the cipher to use as defined by [Cipher]. in kdbx 3 this is always aes.
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

class KdbxVersion {
  const KdbxVersion._(this.major, this.minor);

  static const V3 = KdbxVersion._(3, 0);
  static const V3_1 = KdbxVersion._(3, 1);
  static const V4 = KdbxVersion._(4, 0);
  static const V4_1 = KdbxVersion._(4, 1);

  final int major;
  final int minor;

  bool operator <(KdbxVersion other) =>
      major < other.major || (major == other.major && minor < other.minor);

  bool operator >(KdbxVersion other) =>
      major > other.major || (major == other.major && minor > other.minor);

  bool operator >=(KdbxVersion other) => this == other || this > other;

  @override
  bool operator ==(Object other) =>
      other is KdbxVersion && major == other.major && minor == other.minor;

  @override
  int get hashCode => hash2(major, minor);

  @override
  String toString() => '$major.$minor';
}

const _headerFieldsByVersion = {
  HeaderFields.TransformSeed: [KdbxVersion.V3],
  HeaderFields.TransformRounds: [KdbxVersion.V3],
  HeaderFields.ProtectedStreamKey: [KdbxVersion.V3],
  HeaderFields.StreamStartBytes: [KdbxVersion.V3],
  HeaderFields.InnerRandomStreamID: [KdbxVersion.V3],
  HeaderFields.KdfParameters: [KdbxVersion.V4],
  HeaderFields.PublicCustomData: [KdbxVersion.V4],
};

bool _isHeaderFieldInVersion(HeaderFields field, KdbxVersion version) {
  final f = _headerFieldsByVersion[field];
  if (f == null || f.isEmpty) {
    return true;
  }
  for (final v in f) {
    if (v.major == version.major) {
      return true;
    }
  }
  return false;
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
    required this.sig1,
    required this.sig2,
    required KdbxVersion version,
    required this.fields,
    required this.endPos,
    Map<InnerHeaderFields, InnerHeaderField>? innerFields,
  })  : _version = version,
        innerHeader = InnerHeader(fields: innerFields ?? {});

  KdbxHeader.createV3()
      : this(
          sig1: Consts.FileMagic,
          sig2: Consts.Sig2Kdbx,
          version: KdbxVersion.V3_1,
          fields: _defaultFieldValues(),
          endPos: null,
        );

  KdbxHeader.createV4()
      : this(
          sig1: Consts.FileMagic,
          sig2: Consts.Sig2Kdbx,
          version: KdbxVersion.V4,
          fields: _defaultFieldValuesV4(),
          innerFields: _defaultInnerFieldValuesV4(),
          endPos: null,
        );

  // TODO: user KdbxVersion
  static List<HeaderFields> _requiredFields(int majorVersion) {
    if (majorVersion < KdbxVersion.V3.major) {
      throw KdbxUnsupportedException('Unsupported version: $majorVersion');
    }
    final baseHeaders = [
      HeaderFields.CipherID,
      HeaderFields.CompressionFlags,
      HeaderFields.MasterSeed,
      HeaderFields.EncryptionIV,
    ];
    if (majorVersion < KdbxVersion.V4.major) {
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
    for (final required in _requiredFields(version.major)) {
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
    fields.remove(HeaderFields.TransformSeed);
    fields.remove(HeaderFields.StreamStartBytes);
    fields.remove(HeaderFields.ProtectedStreamKey);
    fields.remove(HeaderFields.EncryptionIV);
    if (version.major == KdbxVersion.V3.major) {
      _setHeaderField(HeaderFields.TransformSeed, ByteUtils.randomBytes(32));
      _setHeaderField(HeaderFields.StreamStartBytes, ByteUtils.randomBytes(32));
      _setHeaderField(
          HeaderFields.ProtectedStreamKey, ByteUtils.randomBytes(32));
      _setHeaderField(HeaderFields.EncryptionIV, ByteUtils.randomBytes(16));
    } else if (version.major == KdbxVersion.V4.major) {
      _setInnerHeaderField(
          InnerHeaderFields.InnerRandomStreamKey, ByteUtils.randomBytes(64));
      final kdfParameters = readKdfParameters;
      KdfField.salt.write(
          kdfParameters, ByteUtils.randomBytes(Consts.DefaultKdfSaltLength));
      //         var ivLength = this.dataCipherUuid.toString() === Consts.CipherId.ChaCha20 ? 12 : 16;
      //        this.encryptionIV = Random.getBytes(ivLength);
      final cipher = this.cipher;
      final ivLength = cipher == Cipher.chaCha20 ? 12 : 16;
      _setHeaderField(
          HeaderFields.EncryptionIV, ByteUtils.randomBytes(ivLength));
    } else {
      throw KdbxUnsupportedException(
          'We do not support Kdbx 3.x and 4.x right now. ($version)');
    }
  }

  void write(WriterHelper writer) {
    _validate();
    // write signature
    writer.writeUint32(Consts.FileMagic);
    writer.writeUint32(Consts.Sig2Kdbx);
    // write version
    writer.writeUint16(version.minor);
    writer.writeUint16(version.major);
    for (final field
        in HeaderFields.values.where((f) => f != HeaderFields.EndOfHeader)) {
      if (!_isHeaderFieldInVersion(field, version) && fields[field] != null) {
        _logger.warning('Did not expect header field $field in $version');
      }
      _writeField(writer, field);
    }
    fields[HeaderFields.EndOfHeader] =
        HeaderField(HeaderFields.EndOfHeader, Uint8List(0));
    _writeField(writer, HeaderFields.EndOfHeader);
  }

  void writeInnerHeader(WriterHelper writer) {
    assert(version >= KdbxVersion.V4);
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
    if (version >= KdbxVersion.V4) {
      writer.writeUint32(size);
    } else {
      writer.writeUint16(size);
    }
  }

  static Map<HeaderFields, HeaderField> _defaultFieldValues() => _headerFields({
        HeaderFields.CipherID: CryptoConsts.CIPHER_IDS[Cipher.aes]!.toBytes(),
        HeaderFields.CompressionFlags:
            WriterHelper.singleUint32Bytes(Compression.gzip.id!),
        HeaderFields.TransformRounds: WriterHelper.singleUint64Bytes(6000),
        HeaderFields.InnerRandomStreamID: WriterHelper.singleUint32Bytes(
            ProtectedValueEncryption.values
                .indexOf(ProtectedValueEncryption.salsa20)),
      });

  static Map<HeaderFields, HeaderField> _defaultFieldValuesV4() =>
      _headerFields({
        HeaderFields.CipherID: CryptoConsts.CIPHER_IDS[Cipher.aes]!.toBytes(),
        HeaderFields.CompressionFlags:
            WriterHelper.singleUint32Bytes(Compression.gzip.id!),
        HeaderFields.KdfParameters: _createKdfDefaultParameters().write(),
//        HeaderFields.InnerRandomStreamID: WriterHelper.singleUint32Bytes(
//            ProtectedValueEncryption.values
//                .indexOf(ProtectedValueEncryption.chaCha20)),
      });

  static Map<HeaderFields, HeaderField> _headerFields(
          Map<HeaderFields, Uint8List> headerFields) =>
      headerFields.map((key, value) => MapEntry(key, HeaderField(key, value)));

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
      throw KdbxInvalidFileStructure(
          'Unsupported file structure. ${ByteUtils.toHex(sig1)}, '
          '${ByteUtils.toHex(sig2)}');
    }

    // reading version
    final versionMinor = reader.readUint16();
    final versionMajor = reader.readUint16();
    final version = KdbxVersion._(versionMajor, versionMinor);

    _logger.finer('Reading version: $version');
    final headerFields = readAllFields(reader, version, HeaderFields.values,
        (HeaderFields field, value) => HeaderField(field, value));

    return KdbxHeader(
      sig1: sig1,
      sig2: sig2,
      version: version,
      fields: headerFields,
      endPos: reader.pos,
    );
  }

  static Map<HeaderFields, HeaderField> readHeaderFields(
          ReaderHelper reader, KdbxVersion version) =>
      readAllFields(reader, version, HeaderFields.values,
          (HeaderFields field, value) => HeaderField(field, value));

  static InnerHeader readInnerHeaderFields(
          ReaderHelper reader, KdbxVersion version) =>
      InnerHeader.fromFields(
        readField(
            reader,
            version,
            InnerHeaderFields.values,
            (InnerHeaderFields field, value) =>
                InnerHeaderField(field, value)).toList(growable: false),
      );

  static Map<TE, T> readAllFields<T extends HeaderFieldBase<TE>, TE>(
          ReaderHelper reader,
          KdbxVersion version,
          List<TE> fields,
          T Function(TE field, Uint8List bytes) createField) =>
      Map<TE, T>.fromEntries(readField(reader, version, fields, createField)
          .map((field) => MapEntry(field.field, field)));

  static Iterable<T> readField<T, TE>(
      ReaderHelper reader,
      KdbxVersion version,
      List<TE> fields,
      T Function(TE field, Uint8List bytes) createField) sync* {
    while (true) {
      final headerId = reader.readUint8();
      final bodySize =
          version >= KdbxVersion.V4 ? reader.readUint32() : reader.readUint16();
      final bodyBytes =
          bodySize > 0 ? reader.readBytes(bodySize) : Uint8List(0);
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
  KdbxVersion _version;
  KdbxVersion get version => _version;
//  int get versionMinor => _versionMinor;
//  int get versionMajor => _versionMajor;
  final Map<HeaderFields, HeaderField> fields;
  final InnerHeader innerHeader;

  /// end position of the header, if we have been reading from a stream.
  final int? endPos;

  Cipher? get cipher {
    if (version < KdbxVersion.V4) {
      assert(
          CryptoConsts.cipherFromBytes(fields[HeaderFields.CipherID]!.bytes) ==
              Cipher.aes);
      return Cipher.aes;
    }
    try {
      return CryptoConsts.cipherFromBytes(fields[HeaderFields.CipherID]!.bytes);
    } catch (e, stackTrace) {
      _logger.warning(
          'Unable to find cipher. '
          '${fields[HeaderFields.CipherID]?.bytes.encodeBase64()}',
          e,
          stackTrace);
      throw KdbxCorruptedFileException(
        'Invalid cipher. '
        '${fields[HeaderFields.CipherID]?.bytes.encodeBase64()}',
      );
    }
  }

  set cipher(Cipher? cipher) {
    checkArgument(version >= KdbxVersion.V4 || cipher == Cipher.aes,
        message: 'Kdbx 3 only supports aes, tried to set it to $cipher');
    _setHeaderField(
      HeaderFields.CipherID,
      CryptoConsts.CIPHER_IDS[cipher!]!.toBytes(),
    );
  }

  Compression get compression {
    final id =
        ReaderHelper.singleUint32(fields[HeaderFields.CompressionFlags]!.bytes);
    return _compressionIdsById[id] ??
        (() => throw KdbxUnsupportedException('invalid compression $id'))();
  }

  ProtectedValueEncryption get innerRandomStreamEncryption =>
      ProtectedValueEncryption
          .values[ReaderHelper.singleUint32(_innerRandomStreamEncryptionBytes)];

  Uint8List? get _innerRandomStreamEncryptionBytes => version >= KdbxVersion.V4
      ? innerHeader.fields[InnerHeaderFields.InnerRandomStreamID]!.bytes
      : fields[HeaderFields.InnerRandomStreamID]!.bytes;

  Uint8List? get protectedStreamKey => version >= KdbxVersion.V4
      ? innerHeader.fields[InnerHeaderFields.InnerRandomStreamKey]!.bytes
      : fields[HeaderFields.ProtectedStreamKey]!.bytes;

  VarDictionary get readKdfParameters => VarDictionary.read(
      ReaderHelper(fields[HeaderFields.KdfParameters]!.bytes));

  int get v3KdfTransformRounds =>
      ReaderHelper.singleUint64(fields[HeaderFields.TransformRounds]!.bytes);

  void writeKdfParameters(VarDictionary kdfParameters) =>
      _setHeaderField(HeaderFields.KdfParameters, kdfParameters.write());

  void upgrade(int majorVersion) {
    checkArgument(majorVersion == KdbxVersion.V4.major,
        message: 'Can only upgrade to 4');
    _logger.info('Upgrading header to $majorVersion');
    _version = KdbxVersion._(majorVersion, 0);
    if (fields[HeaderFields.KdfParameters] == null) {
      _logger.fine('Creating kdf parameters.');
      writeKdfParameters(_createKdfDefaultParameters());
    }
    fields.remove(HeaderFields.TransformRounds);
    fields.remove(HeaderFields.InnerRandomStreamID);
    _setInnerHeaderField(
        InnerHeaderFields.InnerRandomStreamID,
        WriterHelper.singleUint32Bytes(ProtectedValueEncryption.values
            .indexOf(ProtectedValueEncryption.chaCha20)));
  }

  @override
  String toString() {
    return 'KdbxHeader{sig1: $sig1, sig2: $sig2, version: $version}';
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
    required this.fields,
    List<InnerHeaderField>? binaries,
  }) : binaries = binaries ?? [];

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

  void updateBinaries(Iterable<KdbxBinary> newBinaries) {
    binaries.clear();
    binaries.addAll(newBinaries.map((binary) => binary.writeToInnerHeader()));
  }
}
