import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/kdbx_format.dart';
import 'package:kdbx/src/kdbx_group.dart';
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
  }

  @override
  FutureOr<void> run() async {
    final inputFile = argResults['input'] as String;
    if (inputFile == null) {
      usageException('Required argument: --input');
    }
    final bytes = await File(inputFile).readAsBytes() as Uint8List;
    final password = prompts.get('Password for $inputFile',
        conceal: true, validate: (str) => str.isNotEmpty);
    final file = await KdbxFormat.read(
        bytes, Credentials(ProtectedValue.fromString(password)));
    return runWithFile(file);
  }

  Future<void> runWithFile(KdbxFile file);
}

class CatCommand extends KdbxFileCommand {
  CatCommand() {
    argParser.addFlag('decrypt',
        help: 'Force decryption of all protected strings.');
  }

  @override
  String get description => 'outputs all entries from file.';

  @override
  String get name => 'cat';

  bool get forceDecrypt => argResults['decrypt'] as bool;

  @override
  Future<void> runWithFile(KdbxFile file) async {
    catGroup(file.body.rootGroup);
  }

  void catGroup(KdbxGroup group, {int depth = 0}) {
    final indent = '  ' * depth;
    print('$indent + ${group.name} (${group.uuid})');
    for (final group in group.groups) {
      catGroup(group, depth: depth + 1);
    }
    for (final entry in group.entries) {
      final value = entry.strings['Password'];
      print(
          '$indent `- ${entry.strings['Title']?.getText()}: ${forceDecrypt ? value?.getText() : value?.toString()}');
    }
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
    print(file.body.xmlDocument.toXmlString(pretty: true));
  }
}
