

import 'package:clock/clock.dart';
import 'package:kdbx/src/kdbx_object.dart';
import 'package:kdbx/src/kdbx_xml.dart';
import 'package:xml/xml.dart';

class KdbxTimes extends KdbxNode {
  KdbxTimes.create() : super.create('Times') {
    final now = clock.now().toUtc();
    creationTime.set(now);
    lastModificationTime.set(now);
    lastAccessTime.set(now);
    expiryTime.set(now);
    expires.set(false);
    usageCount.set(0);
    locationChanged.set(now);
  }
  KdbxTimes.read(XmlElement node) : super.read(node);

  DateTimeUtcNode get creationTime => DateTimeUtcNode(this, 'CreationTime');
  DateTimeUtcNode get lastModificationTime => DateTimeUtcNode(this, 'CreationTime');
  DateTimeUtcNode get lastAccessTime => DateTimeUtcNode(this, 'CreationTime');
  DateTimeUtcNode get expiryTime => DateTimeUtcNode(this, 'CreationTime');
  BooleanNode get expires => BooleanNode(this, 'Expires');
  IntNode get usageCount => IntNode(this, 'Usagecount');
  DateTimeUtcNode get locationChanged => DateTimeUtcNode(this, 'LocationChanged');

  void accessedNow() {
    lastAccessTime.set(clock.now());
  }
}
