import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart' show IterableExtension;
import 'package:convert/convert.dart' as convert;
import 'package:kdbx/src/credentials/credentials.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:xml/xml.dart' as xml;
import 'package:crypto/crypto.dart' as crypto;

import 'package:logging/logging.dart';

final _logger = Logger('keyfile');

class KeyFileCredentials implements CredentialsPart {
  factory KeyFileCredentials(Uint8List keyFileContents) {
    try {
      final keyFileAsString = utf8.decode(keyFileContents);
      if (_hexValuePattern.hasMatch(keyFileAsString)) {
        return KeyFileCredentials._(ProtectedValue.fromBinary(
            convert.hex.decode(keyFileAsString) as Uint8List));
      }
      final xmlContent = xml.XmlDocument.parse(keyFileAsString);
      final metaVersion =
          xmlContent.findAllElements('Version').singleOrNull?.text;
      final key = xmlContent.findAllElements('Key').single;
      final dataString = key.findElements('Data').single;
      final encoded = dataString.text.replaceAll(RegExp(r'\s'), '');
      Uint8List dataBytes;
      if (metaVersion != null && metaVersion.startsWith('2.')) {
        dataBytes = convert.hex.decode(encoded) as Uint8List;
      } else {
        dataBytes = base64.decode(encoded);
      }
      _logger.finer('Decoded base64 of keyfile.');
      return KeyFileCredentials._(ProtectedValue.fromBinary(dataBytes));
    } catch (e, stackTrace) {
      _logger.warning(
          'Unable to parse key file as hex or XML, use as is.', e, stackTrace);
      final bytes = crypto.sha256.convert(keyFileContents).bytes as Uint8List;
      return KeyFileCredentials._(ProtectedValue.fromBinary(bytes));
    }
  }

  KeyFileCredentials._(this._keyFileValue);

  static final RegExp _hexValuePattern =
      RegExp(r'^[a-f\d]{64}', caseSensitive: false);

  final ProtectedValue _keyFileValue;

  @override
  Uint8List getBinary() {
    return _keyFileValue.binaryValue;
//    return crypto.sha256.convert(_keyFileValue.binaryValue).bytes as Uint8List;
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
