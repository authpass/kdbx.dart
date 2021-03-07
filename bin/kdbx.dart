import 'dart:async';
import 'dart:io';

import 'package:argon2_ffi_base/argon2_ffi_base.dart';
import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:kdbx/kdbx.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/utils/print_utils.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';
import 'package:prompts/prompts.dart' as prompts;

final _logger = Logger('kdbx');

void main(List<String> arguments) {
  exitCode = 0;
  final runner = KdbxCommandRunner('kdbx', 'Kdbx Utility');
  runner.run(arguments).catchError((dynamic error, StackTrace stackTrace) {
    if (error is! UsageException) {
      return Future<dynamic>.error(error, stackTrace);
    }
    print(error);
    exit(64);
  });

  //  final inputFile = args['input'] as String;
//  if (inputFile == null) {
//    print('Missing Argument --input');
//    print(parser.usage);
//    exitCode = 1;
//    return;
//  }
  _logger.info('done.');
}

class KdbxCommandRunner extends CommandRunner<void> {
  KdbxCommandRunner(String executableName, String description)
      : super(executableName, description) {
    argParser.addFlag('verbose', abbr: 'v');
    addCommand(CatCommand());
    addCommand(DumpXmlCommand());
  }

  @override
  Future<void> runCommand(ArgResults topLevelResults) {
    PrintAppender().attachToLogger(Logger.root);
    Logger.root.level = Level.INFO;
    if (topLevelResults['verbose'] as bool) {
      Logger.root.level = Level.ALL;
    }
    return super.runCommand(topLevelResults);
  }
}

abstract class KdbxFileCommand extends Command<void> {
  KdbxFileCommand() {
    argParser.addOption(
      'input',
      abbr: 'i',
      help: 'Input kdbx file',
      valueHelp: 'foo.kdbx',
    );
    argParser.addOption(
      'keyfile',
      abbr: 'k',
      help: 'Keyfile for decryption',
    );
    argParser.addOption(
      'password',
      abbr: 'p',
      help: 'password',
      valueHelp: 'asdf',
    );
  }

  @override
  FutureOr<void> run() async {
    final inputFile = argResults['input'] as String;
    if (inputFile == null) {
      usageException('Required argument: --input');
    }
    final bytes = await File(inputFile).readAsBytes();
    final password = argResults['password'] as String ??
        prompts.get('Password for $inputFile',
            conceal: true, validate: (str) => str.isNotEmpty);
    final keyFile = argResults['keyfile'] as String;
    final keyFileData =
        keyFile == null ? null : await File(keyFile).readAsBytes();

    Argon2.resolveLibraryForceDynamic = true;
    final file = await KdbxFormat(Argon2FfiFlutter()).read(
      bytes,
      Credentials.composite(ProtectedValue.fromString(password), keyFileData),
    );
    return runWithFile(file);
  }

  Future<void> runWithFile(KdbxFile file);
}

class CatCommand extends KdbxFileCommand {
  CatCommand() {
    argParser.addFlag('decrypt',
        help: 'Force decryption of all protected strings.');
    argParser.addFlag('all-fields',
        help: 'Force decryption of all protected strings.');
  }

  @override
  String get description => 'outputs all entries from file.';

  @override
  String get name => 'cat';

  bool get forceDecrypt => argResults['decrypt'] as bool;

  bool get allFields => argResults['all-fields'] as bool;

  @override
  Future<void> runWithFile(KdbxFile file) async {
    final buf = StringBuffer();
    KdbxPrintUtils(forceDecrypt: forceDecrypt, allFields: allFields)
        .catGroup(buf, file.body.rootGroup);
    print(buf.toString());
  }
}

class DumpXmlCommand extends KdbxFileCommand {
  @override
  String get description => 'Outputs the xml body unencrypted.';

  @override
  String get name => 'dumpXml';

  @override
  List<String> get aliases => ['dump', 'xml'];

  @override
  Future<void> runWithFile(KdbxFile file) async {
    print(file.body.node.toXmlString(pretty: true));
  }
}
