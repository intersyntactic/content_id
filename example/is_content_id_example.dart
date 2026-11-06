import 'dart:convert';

import 'package:is_content_id/is_content_id.dart';

void main() {
  final id = ObjectId.of(utf8.encode('what went up'));
  print('id: $id');
  print('read back from its hex: ${ObjectId.parse(id.hex) == id}');

  final set = FileSetId.of({
    ListedPath.parse('lib/a.dart')!: id,
    ListedPath.parse('README.md')!: ObjectId.of(utf8.encode('# a\n')),
  });
  print('the set: $set');
}
