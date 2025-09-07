import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart' show IterableExtension;
import 'package:convert/convert.dart' as convert;
import 'package:crypto/crypto.dart' as crypto;
import 'package:kdbx/src/credentials/credentials.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/utils/byte_utils.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:xml/xml.dart' as xml;

final _logger = Logger('keyfile');

const _nodeVersion = 'Version';
const _nodeKey = 'Key';
const _nodeData = 'Data';
const _nodeMeta = 'Meta';
const _nodeKeyFile = 'KeyFile';
const _nodeHash = 'Hash';

class KeyFileCredentials implements CredentialsPart {
  factory KeyFileCredentials(Uint8List keyFileContents) {
    try {
      final keyFileAsString = utf8.decode(keyFileContents);
      if (_hexValuePattern.hasMatch(keyFileAsString)) {
        return KeyFileCredentials._(
          ProtectedValue.fromBinary(
            convert.hex.decode(keyFileAsString) as Uint8List,
          ),
        );
      }
      final xmlContent = xml.XmlDocument.parse(keyFileAsString);
      final metaVersion = xmlContent
          .findAllElements(_nodeVersion)
          .singleOrNull
          ?.text;
      final key = xmlContent.findAllElements(_nodeKey).single;
      final dataString = key.findElements(_nodeData).single;
      final encoded = dataString.text.replaceAll(RegExp(r'\s'), '');
      Uint8List dataBytes;
      if (metaVersion != null && metaVersion.startsWith('2.')) {
        dataBytes = convert.hex.decode(encoded) as Uint8List;
        assert(
          (() {
            final hash = dataString.getAttribute(_nodeHash);
            if (hash == null) {
              throw const FormatException('Keyfile must contain a hash.');
            }
            final expectedHashBytes = convert.hex.decode(hash);
            final actualHash =
                crypto.sha256.convert(dataBytes).bytes.sublist(0, 4)
                    as Uint8List;
            if (!ByteUtils.eq(expectedHashBytes, actualHash)) {
              throw const FormatException(
                'Corrupted keyfile. Hash does not match',
              );
            }
            return true;
          })(),
        );
      } else {
        dataBytes = base64.decode(encoded);
      }
      _logger.finer('Decoded base64 of keyfile.');
      return KeyFileCredentials._(ProtectedValue.fromBinary(dataBytes));
    } catch (e, stackTrace) {
      _logger.warning(
        'Unable to parse key file as hex or XML, use as is.',
        e,
        stackTrace,
      );
      final bytes = crypto.sha256.convert(keyFileContents).bytes as Uint8List;
      return KeyFileCredentials._(ProtectedValue.fromBinary(bytes));
    }
  }

  /// Creates a new random (32 bytes) keyfile value.
  factory KeyFileCredentials.random() => KeyFileCredentials._(
    ProtectedValue.fromBinary(ByteUtils.randomBytes(32)),
  );

  factory KeyFileCredentials.fromBytes(Uint8List bytes) =>
      KeyFileCredentials._(ProtectedValue.fromBinary(bytes));

  KeyFileCredentials._(this._keyFileValue);

  static final RegExp _hexValuePattern = RegExp(
    r'^[a-f\d]{64}',
    caseSensitive: false,
  );

  final ProtectedValue _keyFileValue;

  @override
  Uint8List getBinary() {
    return _keyFileValue.binaryValue;
    //    return crypto.sha256.convert(_keyFileValue.binaryValue).bytes as Uint8List;
  }

  /// Generates a `.keyx` file as described for Keepass keyfile:
  /// https://keepass.info/help/base/keys.html#keyfiles
  Uint8List toXmlV2() {
    return utf8.encode(toXmlV2String());
  }

  /// Generates a `.keyx` file as described for Keepass keyfile:
  /// https://keepass.info/help/base/keys.html#keyfiles
  @visibleForTesting
  String toXmlV2String() {
    final hash =
        (crypto.sha256.convert(_keyFileValue.binaryValue).bytes as Uint8List)
            .sublist(0, 4);
    final hashHexString = hexFormatLikeKeepass(convert.hex.encode(hash));
    final keyHexString = hexFormatLikeKeepass(
      convert.hex.encode(_keyFileValue.binaryValue),
    );

    final builder = xml.XmlBuilder()
      ..processing('xml', 'version="1.0" encoding="utf-8"');
    builder.element(
      _nodeKeyFile,
      nest: () {
        builder.element(
          _nodeMeta,
          nest: () {
            builder.element(
              _nodeVersion,
              nest: () {
                builder.text('2.0');
              },
            );
          },
        );
        builder.element(
          _nodeKey,
          nest: () {
            builder.element(
              _nodeData,
              nest: () {
                builder.attribute(_nodeHash, hashHexString);
                builder.text(keyHexString);
              },
            );
          },
        );
      },
    );
    return builder.buildDocument().toXmlString(pretty: true);
  }

  /// keypass has all-uppercase letters in pairs of 4 bytes (8 characters).
  @visibleForTesting
  static String hexFormatLikeKeepass(final String hexString) {
    final hex = hexString.toUpperCase();
    const groups = 8;
    final remaining = hex.length % groups;
    return [
      for (var i = 0; i < hex.length ~/ groups; i++)
        hex.substring(i * groups, i * groups + groups),
      if (remaining != 0) hex.substring(hex.length - remaining),
    ].join(' ');
    // range(0, hexString.length / 8).map((i) => hexString.substring(i*_groups, i*_groups + _groups));
    // hexString.toUpperCase().chara
  }
}

class KeyFileComposite implements Credentials {
  KeyFileComposite({required this.password, required this.keyFile});

  PasswordCredentials? password;
  KeyFileCredentials? keyFile;

  @override
  Uint8List getHash() {
    final buffer = [...?password?.getBinary(), ...?keyFile?.getBinary()];
    return crypto.sha256.convert(buffer).bytes as Uint8List;

    //    final output = convert.AccumulatorSink<crypto.Digest>();
    //    final input = crypto.sha256.startChunkedConversion(output);
    ////    input.add(password.getHash());
    //    input.add(buffer);
    //    input.close();
    //    return output.events.single.bytes as Uint8List;
  }
}
