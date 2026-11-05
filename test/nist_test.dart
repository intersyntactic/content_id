// The vectors that need files or a shell, so the Dart VM only.
@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:is_content_id/is_content_id.dart';
import 'package:test/test.dart';

/// The messages and digests in a NIST CAVP SHA-256 file, from
/// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
/// (CAVS 11.0). `Len = 0` lists its empty message as `00`.
List<(Uint8List, String)> vectors(String name) {
  final found = <(Uint8List, String)>[];
  var bits = -1;
  var msg = '';
  for (final raw in File('test/vectors/$name').readAsLinesSync()) {
    final line = raw.trim();
    if (line.startsWith('Len = ')) bits = int.parse(line.substring(6));
    if (line.startsWith('Msg = ')) msg = line.substring(6);
    if (line.startsWith('MD = ')) {
      final bytes = bits == 0
          ? Uint8List(0)
          : Uint8List.fromList([
              for (var i = 0; i < msg.length; i += 2)
                int.parse(msg.substring(i, i + 2), radix: 16),
            ]);
      found.add((bytes, line.substring(5)));
    }
  }
  return found;
}

void main() {
  for (final (file, count) in [
    ('SHA256ShortMsg.rsp', 65),
    ('SHA256LongMsg.rsp', 64),
  ]) {
    test('gives every digest in NIST $file', () {
      final all = vectors(file);
      expect(all, hasLength(count));
      for (final (bytes, digest) in all) {
        expect(ObjectId.of(bytes).hex, digest, reason: '${bytes.length} bytes');
      }
    });
  }

  test('agrees with shasum at every length across the block boundaries', () {
    final dir = Directory.systemTemp.createTempSync('sha256');
    addTearDown(() => dir.deleteSync(recursive: true));
    final source = Uint8List.fromList([
      for (var i = 0; i < 130; i++) (i * 167 + 13) & 0xff,
    ]);
    for (var n = 0; n <= 130; n++) {
      File('${dir.path}/m$n').writeAsBytesSync(source.sublist(0, n));
    }
    final r = Process.runSync('bash', [
      '-c',
      'shasum -a 256 m*',
    ], workingDirectory: dir.path);
    expect(r.exitCode, 0, reason: r.stderr as String);
    final theirs = {
      for (final line in (r.stdout as String).trim().split('\n'))
        line.substring(66): line.substring(0, 64),
    };
    for (var n = 0; n <= 130; n++) {
      expect(
        ObjectId.of(source.sublist(0, n)).hex,
        theirs['m$n'],
        reason: '$n bytes',
      );
    }
  });
}
