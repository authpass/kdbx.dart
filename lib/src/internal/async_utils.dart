import 'dart:async';

/// Base class which can be used as a mixin directly, but you have to call `cancelSubscriptions`.
/// If used inside a [State], use [StreamSubscriberMixin].
mixin StreamSubscriberBase {
  final List<StreamSubscription<dynamic>> _subscriptions =
      <StreamSubscription<dynamic>>[];

  /// Listens to a stream and saves it to the list of subscriptions.
  void listen(Stream<dynamic> stream, void Function(dynamic data) onData,
      {Function? onError}) {
    _subscriptions.add(stream.listen(onData, onError: onError));
  }

  void handle(StreamSubscription<dynamic> subscription) {
    _subscriptions.add(subscription);
  }

  /// Cancels all streams that were previously added with listen().
  void cancelSubscriptions() {
    _subscriptions.forEach(_cancelSubscription);
    _subscriptions.clear();
  }

  Future<void> _cancelSubscription(StreamSubscription<dynamic> subscription) =>
      subscription.cancel();
}

class StreamSubscriptions with StreamSubscriberBase {}
