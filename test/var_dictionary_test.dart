import 'package:kdbx/src/crypto/key_encrypter_kdf.dart';
import 'package:kdbx/src/kdbx_var_dictionary.dart';
import 'package:kdbx/src/utils/byte_utils.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:test/test.dart';

final _logger = Logger('var_dictionary_test');

void main() {
  Logger.root.level = Level.ALL;
  PrintAppender().attachToLogger(Logger.root);
  test('write and read var dictionary', () {
    final dict = VarDictionary([
      KdfField.rounds.item(99),
      KdfField.uuid
          .item(KeyEncrypterKdf.kdfUuidForType(KdfType.Argon2).toBytes()),
    ]);
    final serialized = dict.write();
    _logger.fine('Serialized dictionary: ${ByteUtils.toHexList(serialized)}');
    final r = VarDictionary.read(ReaderHelper(serialized));
    expect(KdfField.rounds.read(r), 99);
  });
}
