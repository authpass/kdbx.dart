import 'dart:typed_data';

import 'package:kdbx/src/utils/byte_utils.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';

final _logger = Logger('kdbx_var_dictionary');

typedef Decoder<T> = T Function(ReaderHelper reader, int length);
typedef Encoder<T> = void Function(WriterHelper writer, T value);

extension on WriterHelper {
  LengthWriter _lengthWriter() => (int length) => writeUint32(length);
}

@immutable
class ValueType<T> {
  const ValueType(this.code, this.decoder, [this.encoder]);
  final int code;
  final Decoder<T> decoder;
  final Encoder<T>? encoder;

  static final typeUInt32 = ValueType<int>(
    0x04,
    (reader, _) => reader.readUint32(),
    (writer, value) => writer.writeUint32(value, writer._lengthWriter()),
  );
  static final typeUInt64 = ValueType<int>(
    0x05,
    (reader, _) => reader.readUint64(),
    (writer, value) => writer.writeUint64(value, writer._lengthWriter()),
  );
  static final typeBool = ValueType<bool>(
    0x08,
    (reader, _) => reader.readUint8() != 0,
    (writer, value) => writer.writeUint8(value ? 1 : 0, writer._lengthWriter()),
  );
  static final typeInt32 = ValueType<int>(
    0x0C,
    (reader, _) => reader.readInt32(),
    (writer, value) => writer.writeInt32(value, writer._lengthWriter()),
  );
  static final typeInt64 = ValueType<int>(
    0x0D,
    (reader, _) => reader.readInt64(),
    (writer, value) => writer.writeInt64(value, writer._lengthWriter()),
  );
  static final typeString = ValueType<String>(
    0x18,
    (reader, length) => reader.readString(length),
    (writer, value) => writer.writeString(value, writer._lengthWriter()),
  );
  static final typeBytes = ValueType<Uint8List>(
    0x42,
    (reader, length) => reader.readBytes(length),
    (writer, value) => writer.writeBytes(value, writer._lengthWriter()),
  );

  static ValueType typeByCode(int code) =>
      values.firstWhere((t) => t.code == code);

  static final values = [
    typeUInt32,
    typeUInt64,
    typeBool,
    typeInt32,
    typeInt64,
    typeString,
    typeBytes,
  ];

  void encode(WriterHelper writer, T value) {
    encoder!(writer, value);
  }
}

class VarDictionaryItem<T> {
  VarDictionaryItem(this._key, this._valueType, this._value);

  final String _key;
  final ValueType<T> _valueType;
  final T _value;

  String toDebugString() {
    return 'VarDictionaryItem{key=$_key, valueType=$_valueType, value=${_value.runtimeType}}';
  }
}

class VarDictionary {
  VarDictionary(List<VarDictionaryItem<dynamic>> items)
      : _items = items,
        _dict = Map.fromEntries(items.map((item) => MapEntry(item._key, item)));

  factory VarDictionary.read(ReaderHelper reader) {
    final items = <VarDictionaryItem>[];
    final versionMinor = reader.readUint8();
    final versionMajor = reader.readUint8();
    _logger.finest('Reading VarDictionary $versionMajor.$versionMinor');
    assert(versionMajor == 1);

    while (true) {
      final item = _readItem(reader);
      if (item == null) {
        break;
      }
      items.add(item);
    }
    return VarDictionary(items);
  }

  static const DEFAULT_VERSION = 0x0100;
  final List<VarDictionaryItem<dynamic>> _items;
  final Map<String, VarDictionaryItem<dynamic>> _dict;

  Uint8List write() {
    final writer = WriterHelper();
    writer.writeUint16(DEFAULT_VERSION);
    for (final item in _items) {
      writer.writeUint8(item._valueType.code);
      ValueType.typeString.encode(writer, item._key);
      item._valueType.encode(writer, item._value);
    }
    writer.writeUint8(0);
    return writer.output.toBytes();
  }

  T? get<T>(ValueType<T> type, String key) => _dict[key]?._value as T?;
  void set<T>(ValueType<T> type, String key, T value) =>
      _dict[key] = VarDictionaryItem<T>(key, type, value);

  static VarDictionaryItem<dynamic>? _readItem(ReaderHelper reader) {
    final type = reader.readUint8();
    if (type == 0) {
      return null;
    }
    final keyLength = reader.readUint32();
    final key = reader.readString(keyLength);
    final valueLength = reader.readInt32();
    final valueType = ValueType.typeByCode(type);
    return VarDictionaryItem<dynamic>(
        key, valueType, valueType.decoder(reader, valueLength));
  }

  String toDebugString() {
    return 'VarDictionary{${_items.map((item) => item.toDebugString())}';
  }
}
