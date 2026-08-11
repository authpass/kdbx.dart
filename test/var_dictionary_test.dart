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
      KdfField.uuid.item(
        KeyEncrypterKdf.kdfUuidForType(KdfType.Argon2).toBytes(),
      ),
    ]);
    final serialized = dict.write();
    _logger.fine('Serialized dictionary: ${ByteUtils.toHexList(serialized)}');
    final r = VarDictionary.read(ReaderHelper(serialized));
    expect(KdfField.rounds.read(r), 99);
  });

  test('set is visible after a write/read round trip', () {
    final dict = VarDictionary([
      KdfField.rounds.item(99),
      KdfField.uuid.item(
        KeyEncrypterKdf.kdfUuidForType(KdfType.Argon2).toBytes(),
      ),
    ]);
    KdfField.rounds.write(dict, 1234);

    final r = VarDictionary.read(ReaderHelper(dict.write()));
    expect(KdfField.rounds.read(r), 1234);
    expect(KdfField.uuid.read(r), isNotNull);
  });

  test('set adds fields which were not present', () {
    final dict = VarDictionary([KdfField.rounds.item(99)]);
    KdfField.salt.write(dict, ByteUtils.randomBytes(32));

    final r = VarDictionary.read(ReaderHelper(dict.write()));
    expect(KdfField.salt.read(r), hasLength(32));
    expect(KdfField.rounds.read(r), 99);
  });
}
