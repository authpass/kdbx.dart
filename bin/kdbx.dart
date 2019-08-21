import 'dart:async';
import 'dart:io';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_header.dart';
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
    return null;
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
  KdbxCommandRunner(String executableName, String description) : super(executableName, description) {
    argParser.addFlag('verbose', abbr: 'v');
    addCommand(CatCommand());
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
  }

  @override
  FutureOr<void> run() async {
    final inputFile = argResults['input'] as String;
    if (inputFile == null) {
      usageException('Required argument: --input');
    }
    final bytes = await File(inputFile).readAsBytes();
    final password = prompts.get('Password for $inputFile', conceal: true, validate: (str) => str.isNotEmpty);
    final file = await KdbxFormat.read(bytes, Credentials(ProtectedValue.fromString(password)));
    return runWithFile(file);
  }

  Future<void> runWithFile(KdbxFile file);
}

class CatCommand extends KdbxFileCommand {
  @override
  String get description => 'outputs all entries from file.';

  @override
  String get name => 'cat';

  @override
  Future<void> runWithFile(KdbxFile file) async {
    _logger.severe('running');
  }
}
