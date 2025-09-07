import 'package:kdbx/src/crypto/protected_value.dart';
import 'package:kdbx/src/internal/extension_utils.dart';
import 'package:kdbx/src/kdbx_entry.dart';
import 'package:kdbx/src/kdbx_group.dart';

class KdbxPrintUtils {
  KdbxPrintUtils({
    this.forceDecrypt = false,
    this.allFields = false,
  });
  final bool? forceDecrypt;
  final bool? allFields;

  String catGroupToString(KdbxGroup group) =>
      (StringBuffer()..let((that) => catGroup(that, group))).toString();

  void catGroup(StringBuffer buf, KdbxGroup group, {int depth = 0}) {
    final indent = '  ' * depth;
    buf.writeln('$indent + ${group.name.get()} (${group.uuid})');
    for (final group in group.groups) {
      catGroup(buf, group, depth: depth + 1);
    }
    String? valueToSting(StringValue? value) {
      return forceDecrypt! ? value?.getText() : value?.toString();
    }

    for (final entry in group.entries) {
      final value = entry.getString(KdbxKeyCommon.PASSWORD);
      buf.writeln(
        '$indent `- ${entry.debugLabel()}: '
        '${valueToSting(value)}',
      );
      if (allFields!) {
        buf.writeln(
          entry.stringEntries
              .map(
                (field) =>
                    '$indent      ${field.key} = ${valueToSting(field.value)}',
              )
              .join('\n'),
        );
      }
      buf.writeln(
        entry.binaryEntries
            .map(
              (b) => '$indent     `- file: ${b.key} - ${b.value.value.length}',
            )
            .join('\n'),
      );
    }
  }
}
