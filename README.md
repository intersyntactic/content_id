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
- **`Sha256Name`**: what every kind of name extends. Two kinds with the same
  bytes are never equal, so an object's id cannot stand in for some other
  hash that happens to share its bytes, as long as no kind overrides `==`,
  `hashCode` or `runtimeType`: Dart cannot stop a subclass doing that. It is
  `base`, so a kind cannot `implement` it and skip the check that a name is
  32 bytes.
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

## What it imports

Only `dart:typed_data`: no packages, and no `dart:io`, so it works where
`dart:io` does not.
