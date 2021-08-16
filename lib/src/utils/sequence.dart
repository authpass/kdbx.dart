import 'package:clock/clock.dart';

/// Simple class to assign a unique integer for any point in time.
/// This is basically to ensure that even if two events happen at the
/// same millisecond we know which came first.
/// (realistically this will only make a difference in tests).
class TimeSequence {
  TimeSequence._(this._sequenceIndex);
  factory TimeSequence.now() => TimeSequence._(_sequenceCounter++);

  static int _sequenceCounter = 0;

  final int _sequenceIndex;
  final DateTime _date = clock.now();

  bool isAfter(TimeSequence other) {
    return _sequenceIndex > other._sequenceIndex;
  }

  bool isBefore(TimeSequence other) {
    return _sequenceIndex < other._sequenceIndex;
  }

  @override
  String toString() {
    return '{Sequence: $_sequenceIndex time: $_date}';
  }
}
