# is_content_id

Content addresses: names made by hashing bytes with sha256, as types, and the
sha256 they are made with.

```dart
import 'dart:convert';

import 'package:is_content_id/is_content_id.dart';

void main() {
  final id = ObjectId.of(utf8.encode('what went up'));
  print(id); // its sha256, in lower-case hex
  print(ObjectId.parse(id.hex) == id); // true
}
```

## What it has

- **`ObjectId`**: the name of some bytes, their sha256. It is made only by
  `ObjectId.of` (hash these bytes), `ObjectId.parse` (from lower-case hex) or
  `ObjectId.fromDigest` (from the 32 bytes), so a value of the type is always
  well formed.
- **`FileSetId`**: the name of a set of files, each a `ListedPath` and the
  `ObjectId` of its bytes: the sha256 of the listing `shasum -a 256` prints
  for them, in byte order of path. So a person can check it with no Dart,
  from the set's root:

  ```sh
  find . -type f -print0 | LC_ALL=C sort -z |
    xargs -0 shasum -a 256 | shasum -a 256
  ```

  The files are a map from path to id, so a path is in a set once. Which
  files are in it is the caller's to say; this reads none. The empty set has
  no name, since that recipe gives it a different one on macOS and on Linux.
- **`ListedPath`**: a path `find` could print, from the set's root and
  without the `./`, in printable ASCII with no backslash. Made only by
  `ListedPath.parse`, which gives null for anything else.
- **`Sha256Name`**: what every kind of name extends. Two kinds with the same
  bytes are never equal, so an object's id cannot stand in for some other
  hash that happens to share its bytes, as long as no kind overrides `==` or
  `runtimeType`: Dart cannot stop a subclass doing that. It is `base`, so a
  kind cannot `implement` it and skip the check that a name is 32 bytes.
- **`sha256`**: as FIPS 180-4 defines it: one 64-line function, plus its
  round constants.

Classes, not extension types, since a `String` can be cast to an extension
type and skip every check.

## How the sha256 is checked

`dart test -p vm,node` runs it on the Dart VM and as JavaScript. On both, it
gives the FIPS 180-4 examples, passes NIST's Monte Carlo test (100 steps of
1,000 chained hashes), and gives `shasum`'s digest at every length from 0 to
130 bytes. On the VM it also gives every digest in NIST's validation vectors
(65 short and 64 long messages, in `test/vectors`).

A `FileSetId` is checked against the name the recipe above gives a set of
eight files whose paths sort differently in byte order than in a locale's.
That name was made by the shell, the same on macOS and on Linux.

## What it imports

Only `dart:typed_data`: no packages, and no `dart:io`, so it works where
`dart:io` does not.
