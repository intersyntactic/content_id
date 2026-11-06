// Runs anywhere Dart does, the VM and JavaScript alike: `dart test -p vm,node`.
// NIST's vector files need dart:io, so they are in nist_test.dart.
import 'dart:typed_data';

import 'package:is_content_id/is_content_id.dart';
import 'package:test/test.dart';

Uint8List ascii(String s) => Uint8List.fromList(s.codeUnits);

Uint8List fromHex(String h) => Uint8List.fromList([
  for (var i = 0; i < h.length; i += 2)
    int.parse(h.substring(i, i + 2), radix: 16),
]);

String hexOf(Uint8List digest) => ObjectId.fromDigest(digest)!.hex;

/// A second kind of name, to tell kinds apart.
final class OtherName extends Sha256Name {
  OtherName(super.digest);
}

void main() {
  group('sha256', () {
    test('gives the FIPS 180-4 examples', () {
      expect(
        hexOf(sha256(ascii(''))),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
      expect(
        hexOf(sha256(ascii('abc'))),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
      expect(
        hexOf(
          sha256(
            ascii('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
          ),
        ),
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
      );
      expect(
        hexOf(sha256(Uint8List(1000000)..fillRange(0, 1000000, 0x61))),
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
      );
    });

    test('passes the NIST Monte Carlo test: 100 steps of 1,000 hashes', () {
      var seed = fromHex(monteSeed);
      for (final expected in monteDigests) {
        var (a, b, c) = (seed, seed, seed);
        for (var i = 0; i < 1000; i++) {
          (a, b, c) = (b, c, sha256(Uint8List.fromList([...a, ...b, ...c])));
        }
        seed = c;
        expect(hexOf(seed), expected);
      }
    });

    test("gives shasum's digest at every length across block boundaries", () {
      final source = Uint8List.fromList([
        for (var i = 0; i < 130; i++) (i * 167 + 13) & 0xff,
      ]);
      for (var n = 0; n <= 130; n++) {
        expect(
          hexOf(sha256(source.sublist(0, n))),
          shasumDigests[n],
          reason: '$n bytes',
        );
      }
    });
  });

  group('names', () {
    test('ObjectId.of is the sha256 of the bytes', () {
      expect(ObjectId.of(ascii('abc')).bytes, sha256(ascii('abc')));
    });

    test('parse takes only a lower-case hex sha256', () {
      final hex = ObjectId.of(ascii('x')).hex;
      expect(ObjectId.parse(hex)?.hex, hex);
      expect(ObjectId.parse(hex.toUpperCase()), isNull);
      expect(ObjectId.parse(hex.substring(1)), isNull);
      expect(ObjectId.parse('$hex\n'), isNull);
    });

    test('fromDigest takes only 32 bytes', () {
      expect(ObjectId.fromDigest(Uint8List(32)), isNotNull);
      expect(ObjectId.fromDigest(Uint8List(31)), isNull);
      expect(ObjectId.fromDigest(Uint8List(33)), isNull);
    });

    test('a kind of name must be given 32 bytes', () {
      expect(() => OtherName(Uint8List(31)), throwsArgumentError);
    });

    test('the same 32 bytes as two kinds of name are not equal', () {
      final digest = ObjectId.of(ascii('x')).bytes;
      expect(ObjectId.fromDigest(digest), isNot(OtherName(digest)));
      expect(ObjectId.fromDigest(digest), ObjectId.of(ascii('x')));
    });

    test('a name made two ways is the same key in a set', () {
      final id = ObjectId.of(ascii('x'));
      expect(ObjectId.parse(id.hex)!.hashCode, id.hashCode);
      expect({id}.contains(ObjectId.fromDigest(id.bytes)), isTrue);
    });

    test('a name keeps its own copy of the bytes', () {
      final digest = sha256(ascii('x'));
      final id = ObjectId.fromDigest(digest)!;
      digest[0] ^= 1;
      expect(id, ObjectId.of(ascii('x')));
      expect(() => id.bytes[0] = 0, throwsUnsupportedError);
    });
  });

  group('file sets', () {
    test('a set has the name the shell recipe gives it', () {
      // Out of order, so the sort is what puts them in order.
      final files = {
        for (final (path, bytes) in fileSet.reversed)
          ListedPath.parse(path)!: ObjectId.of(ascii(bytes)),
      };
      expect(FileSetId.of(files)?.hex, fileSetName);
    });

    test('the empty set has no name', () {
      expect(FileSetId.of({}), isNull);
    });

    test('a path is one find could print, in printable ASCII', () {
      for (final ok in ['a', 'a/b', 'a b', '[x]~', '...', '.a', '-', ' ']) {
        expect(ListedPath.parse(ok)?.toString(), ok);
      }
      for (final bad in [
        '', '/a', 'a/', 'a//b', '.', './a', 'a/./b', '..', 'a/../b', //
        r'a\b', 'a\nb', 'a\tb', 'a\rb', 'caf\u00e9', '\x7f',
      ]) {
        expect(ListedPath.parse(bad), isNull, reason: bad);
      }
    });

    test('a set and an object with the same bytes are not equal', () {
      final name = FileSetId.of({
        ListedPath.parse('a')!: ObjectId.of(ascii('')),
      })!;
      expect(FileSetId.parse(name.hex), name);
      expect(ObjectId.fromDigest(name.bytes), isNot(name));
    });
  });
}

/// The files in [fileSetName]'s set, each a path and its bytes, in the order
/// `LC_ALL=C sort` puts them: byte order, not a locale's, so upper case
/// comes before lower, and after a common `a` come ` `, `-`, `.`, `/` and
/// `0` in that order, which puts the files in a directory between files
/// beside it.
const fileSet = [
  ('Z.txt', 'last in a locale sort, first in byte order'),
  ('[x]~', 'brackets and tilde'),
  ('a b', 'a space'),
  ('a-b', 'a dash'),
  ('a.b', 'a dot'),
  ('a/b', 'in a directory'),
  ('a/c/d', 'deeper'),
  ('a0', ''),
];

/// What the recipe in [FileSetId]'s comment gives for [fileSet], made by
/// the shell rather than typed, the same on macOS and on Linux (GNU `find`,
/// `sort` and `xargs`, Perl's `shasum`). To make it again:
///
/// ```sh
/// mkdir -p set/a/c && cd set
/// printf 'last in a locale sort, first in byte order' > Z.txt
/// printf 'brackets and tilde' > '[x]~'
/// printf 'a space' > 'a b'
/// printf 'a dash' > a-b
/// printf 'a dot' > a.b
/// printf 'in a directory' > a/b
/// printf 'deeper' > a/c/d
/// : > a0
/// find . -type f -print0 | LC_ALL=C sort -z |
///   xargs -0 shasum -a 256 | shasum -a 256
/// ```
const fileSetName =
    '67a9c3e5fe20a49e76b49321e74845018794e4d6bc959b8fada6dc83ac009995';

/// NIST CAVP SHA-256 Monte Carlo test (SHAVS, `SHA256Monte.rsp`, CAVS 11.1,
/// from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip):
/// its seed and the digest after each of its 100 steps.
const monteSeed =
    '6d1e72ad03ddeb5de891e572e2396f8da015d899ef0e79503152d6010a3fe691';
const monteDigests = [
  'e93c330ae5447738c8aa85d71a6c80f2a58381d05872d26bdd39f1fcd4f2b788',
  '2e78f8c8772ea7c9331d41ed3f9cdf27d8f514a99342ee766ee3b8b0d0b121c0',
  'd6a23dff1b7f2eddc1a212f8a218397523a799b07386a30692fd6fe9d2bf0944',
  'fb0099a964fad5a88cf12952f2991ce256a4ac3049f3d389c3b9e6c00e585db4',
  'f9eba2a4cf6263826beaf6150057849eb975a9513c0b76ecad0f1c19ebbad89b',
  '3ddf05ba8dfec982451a3e9a97695ea9cdb7098c877d0c2cd2c64e58a87754d9',
  '2cc3fe501e3b2e33e60407b0a27025735dd04fd7623bb4fceeebae5cad67ad4b',
  'c534802a459b40c792e1fa68e54ceab69e333fbeeecad65fb124d2f3cc1f1fc1',
  '8986e95d85e64822287c78cb7a714339431332182107109d57827776c6cc930e',
  '72361401c670d07f1151a95e2ee914665c2bdb1228581833c7dc53b89c01c927',
  '124c443bad9d955e084a3961b079c43c59b5e0d666af38f2f37846e85369a618',
  '81914b78674a2a6204eef78ff51369526bf0c2e121cd364eb40a8435479dda14',
  '8eac9d963b44021b70a527ea07420b03f51a998d0d6cb73ad4cb7fc688b4d174',
  '0427263b4dd3ebfcb7871939dbaca5ca94e794f748c02920c9759dfa554ea534',
  '3e9d754f2ec273b0056c2fcad2e891aaf9616fe74005d36cbf5ccba2e037b5b3',
  '986b6594ed96a819e49edb9f65db2ea52168973d7e18ae9e0b8869a8b5dd29a0',
  '117578126a35176a00f8c0cf999442df0890737be1880f06e6a7270959c114c6',
  'fd7f5574788d8ef64b83333ffb62e4cd3311e638db0c514071c19b84e9117afe',
  '19db7ba6e3488a9e935af33ffb912d60c9d3b98a0be1d78e0b374dcb5274a7fb',
  '52519e6319505df7a9aa83778618ec10b78c5771bac50e8d3f59bc815dabfb1f',
  '434d7795fc7510af04b613e120f7f48e6d613ec056ae9fbc7c869b87c1dce63e',
  '020324de7f6763be57bc4a6a0960258ea401ffe40d68f854e82ccfa9e0612ff7',
  'b87c7fd0ec4cd35fab077b64d00917ad06aaccb095bbe4603466644ce6cbce18',
  '01abbd12b2b476b2d540d0c47edcb56263ea658a8080a8f08dbb313942562f00',
  'ce95bb2bf2d5c91402e13ed5271615607f39e0678aae776d18a78351b90b5838',
  'b81af264b0bb485f6656be91478f7b96c324fe262fcc366d9ce3edd44ccb85d0',
  '9e2ad901200ca524c91373f7b5eda9cda142353e763862e350314f793a0b700d',
  'dbfabc7124338d6845f083cb1bbdf7b4060274d8e0e98d08bb7ca3779059b45b',
  'd93c2cd61f5476ea08d85f741720ab2ce5c4e38cd8254758238155fd68ea7723',
  '232d9c3b583e297439c859150738e1b1d530812d63a9a2c1cb8e40cb50a2f27b',
  '8b9c858bd135138d9023a0b5fcf3f12ebbc3b7f721ee0b44be1871187f21f506',
  '05cedbd568ce9adcf5022999b8f3a28995a910c572375186da5febd775d62b79',
  '24282cba8f5dfce7e423a103488a9a924080d549853c699159d27816dbdbe5d9',
  'ba6e3c38128f93f288e781af8a13e7ce5120c2a43a6d1c0d4edc831247350079',
  '706fffec5b69f5ef5465b6a8663c302143af743c6b7cd5fec9f3fa9bf9b2e285',
  '6d32c55c005eea65dacdf0e90f436943d0d0acec3c2355c36e2df1a86d1a11a7',
  'b353f425293db464ad814177ea9689f43054bcdbaf75675e918b78a82ca97a50',
  'c3fa9993130b3c95d9aed30243ba902035933d18adf5e21d2567674769062e81',
  '1e77e07988ebd618740c2f89a7bcf0ae2542279ea8895b39aa70ba8bc37ee00f',
  '063927892a0b095be7d21987ff8157cd4c674c1cd01ab9f0834824e8efbcf938',
  'f43054c280f05371cfbac776d43d6001f71350d898677f035aa8f7e5bd7b3fa3',
  '2427934b28c7a9c2b18a5b7e996351aa567523744f60d54dc35bbb61f56f6fd4',
  '3633976d174279161e13b49e5866c144ce8c1d17ec1901ad56a02c900273fe11',
  '5f9788660d82c80155a7fea91896be3be2eb6a7b2ce963f3804cd09da5ac0c8f',
  '097ef57de6df98c29346e67e7f676569ad402f7a1c88d1cf39ce2d44fd706f72',
  'fedcc810c74706a27fc0b6663ab2f9de0761089682dff1279fcd91312af1b8e3',
  'bd5d61fea8d23089f3f30266b1daa636a352e49476526e71cc0735cbd17054fe',
  '5ead027c03d7a55c17f0c783b6d77670cdb8942772077d09dff9a46ecd527bec',
  '7a06eeea07ca9eb94a98a5e9f00b7efd8de9843b6aa888822c3dccf803637732',
  '44b6a895058ed3f31a5549407af8f788631f8a6eb8c0a5f2e15facc9190b5672',
  'f8a58bff4b54aaebe18fc3f0bb1d24974a125530756dd4a0f15628c35c02ea1c',
  '3bf2ae5408399aba59f42e5bed35a00d038fada16013ffa5da9e8b7207f6012c',
  '31d33c0275986b06f6dccf570d1064c7b36e1574cc4371d4bba2e55321d75397',
  'bda59cbd65e87a57df3f03c89e4d9511de71da05e2eee0560948696b37615f8f',
  'f431cc1817569e92c8ba11ec4741e6dd2e361156575af7b482587ed78e9fb7fe',
  '1b3b3789a32165f725167da6f5ef89d95de5992783961440fce67b66c3351ea6',
  'c9873a09c079ca7f477b5601519ce51896c2a35a28fe05fe8b13e990813c6634',
  'fb16cc865ddcf513be298c7d514033ab3fae7a80b285d2b43e82363342e498f4',
  'ebaebc261b327f8be24026e32099a6b15927c54dbe390b72756f3f6362ea3b3a',
  'ae5a4fdc779d808ba898966c8c14a6c9894107ef3e1d680f6ae37e95cb7e1b67',
  '5a4a67451c197b038c540878b6e7bc6fce3eea9c95795d611359703d6cc7ca02',
  'efb075aa051070a6b2303e026f81a5262a6e64eabb270ec5e13fc6efa3529f6f',
  '8ff3df1a5cd0840bce61520f1e5645ce272a37b884c1750c69a957134c1a20d2',
  '8fbd86567c20dc3ea9948dd5ea6f5204028c4ba258c35052994e7c86de2d7701',
  '670559572a74e9af0513a3f9243bfbfd5805b837705faedc3c480d67a92bc124',
  'ef2ad8656fac9c593d301fcfac77a7815d50b42526d3a44e1573316a25b05904',
  'a3484a7a6cb5c941e15346a3ac4e09e99a5189cc96a87104d196af3c43cf995e',
  '966851a0ef41f8d8ff970f4340a8dae8eec4f1999f5fd4f6cbcfa372fbf85495',
  '8e1559cd4431febfa15662a2ccf2cac82f5401b2657551480bb0e3dd2111032c',
  '5f535e2e7351cb8caf0070166218238a843c17472cea2f5911008be5d7fd6ba2',
  '86ac4ea15f10c264b158058f5c13a36a87ac72f840071bbc45399b36823a5709',
  '5c0d3fe289b2aac7d1bbaf57f4154b8d10875cffc9d8bd2402255ed1615f1d5f',
  'd7d808366d0c8b76ce3e7ab80ea11b4e2f8758f9ff404a3aafbf5b0cc191adcb',
  'e0768536856d1d7399667d6fd2c32f72416eeea1c40a313ee6edc910a5c3b786',
  'd670923731b3e598f5c4db4c7e57fe2275cc6c49b4bf67cb91d520846aec256e',
  '2cb0bdcc305ef3b3d6b7265ab62bee555c524102679da122424713a9a01d69f6',
  '5acdc323fe067a4b915ee521ac8eb81bcff4e205d53e4e7f9a69d436035cc5ad',
  'e634c43558d12c2a8710f2d6f10a86411cfad5a014e6b6cc159733c8ccece283',
  '4a05f4bc3fcaf50e6d0916d7e7024b0ed22e9a3c413ff4bbcc0922d2326dcf6e',
  '17c9d6029e15d3fd84e6809c5ef8a279a040f49ada91601a3ba4572cef7c08bd',
  '1f21e137da2427536758409f3fbf5842589c5f587f0b9d2d10430f840faaaf45',
  'e3d38cff8a8d7fc00693dca5e37b03e7b10dafe4926023e26d937106ddac6a78',
  'cd749eb05c67038fe837910310b3b4cdda190f6235fa970602f865bec1b61a1b',
  'd596ccddea01b4ae29b68b0e8a191007f0c89a1016c380b49786f2d4fac4c43d',
  'cbccb1ff23e33c59dc4c858093c9e215c3759acfe6bc84ff75940b59b25a4e40',
  '7214c134e9a963d6c43969d3ef44ece825dd9cf35bda5fcce92a6b9d0d3fd1b8',
  'aceaf5b775779621319f9ab5d4d370a3359cd6553ed2328cdc9dbab5b68840fa',
  'e8123acb0a2fb62978d3811b31676975542993932108ab14d487ad7875ddef72',
  '660202a436fb05c3d59be699734e77c9750c906c8597ca213d064853ecf8c9f3',
  '4752b0a5ec3f1fb295d5bfa98fa63a0ba38a02a4c1e1f73b0c4d4e88a07e0317',
  '1e24f1467c36b051af3241fcf8c2c868b86dcb8e4669931878018e9914129b42',
  'd1c3efc99d9487e147282d811ab932d4a24362d09ac909f4854e783887068891',
  '7dc455cf6f8b2042b6f0f368c44f18a080e5d3912ce3cdaf7142bd61ae50d02e',
  '4b991c15789084eb1d6c1d7ce8f0928df4d3931c0c22c571f375849b9a6c2b71',
  '8b78f95a007cfb0bd054a1f5d962cd8d927665f79a5ce9e0fc31105e57b8460b',
  'bf305423849cf773fc54206d8ae3c000c3e8b359cba8364581d1f91b0a201032',
  '47006af96cff3843d3ed53bdedb167490d7bfefd93ae3e9ef473cb53aa840fc0',
  'c53cf5026162021fd2345dbad7c53d3a3df47b5bdff8cd34a0ccfee06dbb7328',
  '3326899b575f93cdaff757f8ab7c3996a2fe930450d5002d4575f4e4cc4b4360',
  '6a912ba4188391a78e6f13d88ed2d14e13afce9db6f7dcbf4a48c24f3db02778',
];

/// The sha256 of the first n bytes of `(i * 167 + 13) & 0xff`, for n from 0
/// to 130. They cross the block boundaries: 55 bytes pad to one block, 56 to
/// two, 119 to two and 120 to three. Made by `shasum` rather than typed, and
/// checked against Python's `hashlib`. To make them again:
///
/// ```sh
/// python3 -c 's = bytes((i * 167 + 13) & 0xff for i in range(130)); [open(f"m{n}", "wb").write(s[:n]) for n in range(131)]'
/// for n in $(seq 0 130); do shasum -a 256 m$n | cut -c1-64; done
/// ```
const shasumDigests = [
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  '9d1e0e2d9459d06523ad13e28a4093c2316baafe7aec5b25f30eba2e113599c4',
  'ac4150fe5c10c52db000a2b5c8ec38a06b5f3066bb861429caeea8dd0192a1d9',
  '13c425a746ac9e72be4760dd13b156260d7ad6ea6b8750fbf1c7b0d5a484b852',
  '3ca50c11609595b64693be32e58b46eb35c81dbce77fef6162e9b675e54c7619',
  '0b2efc8144bb0d825a1d8afae908d957ee1cb1a9a933c55a1e121a3d33c33ac8',
  '39ecf6ce33e1f50d1fed7ba6dc6fdb074ab1e0362518cb884a668459e853bbde',
  'c203a078ad61ea701fe3b59157795377099530c374bca00d8515198b64e75dff',
  'f0c621cb705bcc7b4c6b940d4aee13a481804f6ff20640635a33a7dc613f8111',
  'd7d49018f6f0dafcb068f12e57f8dd48a036e83c06553ded4f99e65ade28e6e4',
  '11e88db1776db4313e63084759d44e258f05df254f515284beb2ae54530b1c76',
  'a637bab7c64f733fbe04214b1db659eba54432145e4f50ffe32ce4c61b88c812',
  '41f24dd1b6bba8a99eead9baecb2fbfcb2c1212e206512ee30c4379b1677ba54',
  '632debdecc64eea9a591d4b80f3ba0eeaac4561a134ff2cacc1f21fbff3accce',
  'aab4ab03aec228ce956365e7ebf30ee1c9beb56830c676fd5a50d2743e1946d6',
  '4da00c498b517755271cea35ec91c68544180ae1b4b91be33eaa4719721d71b1',
  'ce141eff2bce3c665db6c8cf602246015a6786ba707d61430d3b1cf43ee9e824',
  '3c8c595a75bc2ec015abec1c214614e773195b21a8fdcc46603588f5d59414dd',
  '38bbd99118257174a3f29328f8fb0834a262533cc6d27a5f11a2de21e581a128',
  'cc0ee2549211b6ee88a76d03cc97bd62afccda188c33569f98b396da070b033a',
  '5593f50c3c902a4dbb934960e027758769dd4991ed68c8c5a0d9ce77334d1704',
  'e447b286f8484f85f19ac5b904b911b9f9c645da6046fc37b79fd27a3df4102a',
  '83a91f7f5a6f097539301377812089cb4d61233adbf92761df3a3ea1f7dbc7ca',
  '0e9ccc7de0cc29a44de4ca37a7be4eae55e1dc03e9d59c1a946cba9519f4d4c2',
  'ee174dce0285a780d55862217b5dbe78a32f155a635b8e306f2888463f2c7122',
  'f38e6cf0e6c93b00b0d2efbee8cc5e012a24b5393c93b28aeb41fe026ef9ef6e',
  '1d7ab78ba63d8348dbadb2cceabbda047a16ee3563df520b385f3fb8ff36a22b',
  '1ab69f9d5f1b275ecdf4dcbd97d665fc91b77b1d65c724b99899b70384e2a635',
  '86447568d1bd278d5f7df52ff0a9539e974e83427b3c35f59b9caea583594074',
  '410e485041e4b9216645fe1bd729c0ddec650f4689879c2ab9c084ddb87f822a',
  'cbf2ac637e659072e0af3d58386345fe1263378ebbd706058b78f7c14b4efc31',
  'e0f1595aeb4ed77b4c5f5c85c81096fa428fca936041d094a0cc2bbada7b9ba9',
  'a0005a1a507e6d6488e4d36992e99f7c693e5c1b68018f8488149346a4a06b23',
  'f456e3e94bd025e42cf609cab6be7081fea007870beb80fe3433c2236ce8a511',
  '89dbffe8618914e059fbec6b2dac81aa9921beac0aa8c61620fe3819171277b1',
  '601456984104fd2b95f368c97a4936fd62ce3638f94116f9013909ab890b11b7',
  'f123e3c628c9e8f2b32cc9a61fcbbedeaed30760f3b13ea02db90fe213f3758b',
  '052bf9f3fbbd7f7def7a3149e946e368288a08951f98df4f50d60d9918b3c277',
  '94060274052bf8abfdc0fe7c27ddf0d5ec940c9e96ed2af9d788e4306caf1917',
  '2108937055f8c731588754324a99f0456a848eb67727637343615c2fcad8ed5f',
  '0c8cd99317c4d88f28731be79805326d5329ecd70ce8cae25ca5496cd890d072',
  '8657f654dacb4974fc9d6177db6c34e9c960f0218594fbda22b7c04664a31786',
  'f08e4c43738ffd5a4a8db2864f2b66f8bd622a6fe6b1b4bcfe492c8d63312dcd',
  '1cb366de1b211835491747c83902fee8b672e3fc38c72c40cba94acf88c0a0ac',
  '6ebba9acc1d3690781c9e6ffd8b7693e7cf72205abe64a5bf45734cbbcf34433',
  '943b0f14ab70d50d5679e23731b42d53c17e9aeb3fae8cda13e01b9052855adb',
  '28edfb4668ab45aa6bc8a2f970fbe675b6f1c3164aa8bd514d486ad85cd91953',
  '1a74f440e56873d224eb8ff11b32b97f8b94448e91c3b2b3f36d21f75ad440c6',
  '3a1f1b38b18f2bccf02f7a11efca31133a35a3ddade893968bc0ba63f7267912',
  '66de5aab0108bf5a809e4c8689d0aeb2a9e37fe4b7acaaa579237d156d4ee4ef',
  '4c55db8015b7e54ff597723794182657d374ab4a0bdd2ea9fced3a37ba54effc',
  '1a6bd48e3c37aff32bbb222c15e5db94a6c12794c61316a529d34b1f6c6c87a2',
  '2afd2a622fe475e29665996b53d8b237b080917b57eabfe6c03c8cb6a5fb2571',
  'b5c404c4e96dcc358bc190e6478ba4b0cb9a218a6852ec59e9337d603789d0e2',
  '5d17705b7f0df5e22eddad8bcefe52e95a9d1006bfae79e828c3c1329d0217ea',
  'b2ca0adc388a66d3a5a7f6541239331d5a867eede554e11262241271faaf36c5',
  '3768eff44f1df02704a832cf708935fbed9bb74d0714fbe75454c266c4e12856',
  'a35b6298adfbc5ec16dc51a8d52145daa2a68f1d66e837d85bed6783d874c5cb',
  'e0f4469743052c88f3077afc03c639fa9a953d8fa6d73afbdd355b9bab908aa8',
  '5f7a47400ea5e41bd7c31682cd717ff82e5024bbb1350553d1f0f22e40b8dc45',
  'f867cac02787eef84fbc9e705a1c5ad99532170fc2006309e3904838f814f33d',
  '66ca6894dac197b079fdf27dd6d53429720254a01a165c914595fb1cd2bec12a',
  '0d3b08f701d8231d3809662ee50118ebd0c6591a6578bf660e02decf7bf93c52',
  'dc06ea9e456da9f9fc2276564018231c36196ff7745bf505fd7f503aec5c67fd',
  'b68fe543b0b5a544e32eb08712e697bfcd3a3cb491563c3b1cba112d378f4bdb',
  '587cdb9ad9be371721f2f84a84eb09f2b698ec19bbe2d7c222179996547a04a6',
  'df8c880195744c9379ddc11b6a7862469de5913621c2f4231ce208a7685ffb22',
  'c24eda61aa3d598e084a47920c97dddae00d5315ac86f7f466a3f7fd9a6a77c0',
  'd4530dae4bbb58fe1a455503b20d1b774de4235a67a5e7367fe7e78bb960c242',
  '66166998f76d81c8eded72e93ffe937b12023eb5fe5b1c984f8da418ecfc3a38',
  '88ca792ead0e03d0e594f96716cdf09eb36a10f7880c93ba878e32142896daf3',
  '7df0a7cab65c44c253f1b47596cf0b255b780d3f309e5d74f7e851eb49e2810e',
  'e66e9c2d98c5b4407b89687d74ad4878f789c753548c3403237f786fc117e583',
  '2afc27ea6df12b6b7f717d257cd65a1a3381e546d9694aaa98abfce2b029cf84',
  '306fbbd71fb0d6c7a5a1bf9f9ed245c88d94b7253797c18f3dfbf744dd6036cf',
  'bdc304eef30db25723fa15e7d600214143d2075b25eef8b7b6863841277141e4',
  'e22a2503dde5a329f6840ab9cd6a1daf8b181b0798368f0a756eac0e4ab50ae6',
  'dc4c20b498847eee6e7735981e4ad9585856d089b8030e9cb87339110990d08a',
  '15bc2000b78806bcfeacafa34c9a617e17f8dd85d5b99917d49a8d02ca9b03c2',
  '5c41256678a6d3d0dbd72b7ab4158b69915bfaf9a330700a352946fd87ef5efc',
  '97a27d9afdd01a62d2991ceb24e5b7e0f7edf6a31b9b34b75cb24cacec43515d',
  '22f7ee5eb0f6305f5266552dd8381bc25694b79d1f8c622127dbf81e9d59ba2d',
  '3c4c6fe194f4062d9c6b3493d4927b022dd43f23541fda8c2d986e59d4680b05',
  '9a942915ca10718333b6b0ad0a4e3c8417498bae7362101e09db15cacd9ef311',
  '1ff21fe7a5d5da9e4843392e6c96ee36f9ddb6c236b7e06e313ebe9e4dd9c2ae',
  '05dac20a2256458df82332da1a275ee80ed2a8128775a57e6fd0ffd143ce67f2',
  '1ac0a62e0c7175af56160d6392380e9c0c75c2b58c7835eaa7d45b7a4b2941f7',
  'cf1220656f4d51ceb0a0502269606461fd7fe17817ee7562c395ba2e1b07e8fb',
  '10c296217362b5fe1604277f178f2c426a56ab0629059c499ffc788df9ef6914',
  '8385a09e2aec27c47c64fdeadb08e4332e3584de26ae68262b828776f41748fa',
  'a90b76932b2f068503c284088ed83654cdef6051393cfa86d89d764e2f2580c7',
  '8ed0c4f28e1ea7c20d9175afc572ef07ec2e579c52032d76e3a13e8d5f5d6cbb',
  '49e43de8ceac8456b21151c126985ef649d652b378eb7adde52bf4bf714f5365',
  'bc86ffb3a9f146650a47c0a21bac10ef5d234a4207151cb06e403c176b91caf4',
  'a4fd5b9bb2b9dc8a264b01c202ff3793542a4a30e47fa0f2d21bd27b0f3d4473',
  '7af12630cc450bb78da210f22014963796e4e8c36d2c310ad48c4026e3cb1a2c',
  'b0335ebe89f2fc1153db3ee9f7f0933069b3e853504d533f0a0ae8a7077c3bda',
  'dc91b1495c1fea4c3456fa0aadd00e023204dd4cc7a4b4bb115f95674b197005',
  '77829eec2e7760fbbb651cdf80715fdf20974b53c5237eaa3f7f9224427a3ac0',
  '5555a14049267647d9680e36e709e46c82b4bc77e842d646cd18243b60987382',
  '2f3e74f3aeb89ea613e396f9abf2a24358df1b06fb85fc84ad02c0ceb4a6dd2a',
  '855deb0088e503888277a3067aaa97c5f4c287d9dc2690a04e0d2a69bf344a87',
  '6cb8ecc77381d5240a8318d686b1be92e2f5d2e70d2aaf725c63b0b87a250005',
  '75f00ac38edbe5294d9166e9c42d74286f9dfc76d693d0d76d908e467af8485c',
  '1a0a7ccea655f86e7c7a5760ef621dd0c6454cc78410a56495afe11cdce96c8b',
  '2245bc2bfb0b81933efd27d3f557790d50451ef66ed8310945b5eb8c3d92d8d4',
  'dcec5cf53285bb043c554c7ea953598d283c910c341fc94eda02c2e1e8e86148',
  'd6802fb9c8cc51c8e0d57251be034de02dc32682fae08bb3c9a89d1feb4d44bd',
  '94112edd6f624adf96103ea6529491e37e2926aeb38547892edd40a2d90e3df2',
  '1424da7dfea68825cc71cf182fc6d2181992f9e3708ad01719b0e27784d2a6ee',
  '785b209cce10bf4785e84ea8533cf065f755ccab39556d24ef7e5d7df67d9495',
  '9905ec11d55cf034f183156b0e03736c10f3374050b17a3c76b50cca3b9be4d0',
  'a11fc5c7ba41fca737a1664f29faebe1dc677f44ae1a4147bad8804d9c981d30',
  '3e37bc2fb8bac1683a55a67eb991deedd8a11dac4826e0cd11ab58a250ad17c6',
  '39995a4b080b621ecc0fa20a68cf53e1ae14558896644264f8a082afb92535a3',
  'c6ef546e12ee56b98c743b3a228c5cb1bfc3f94394e083eecbe94a2a58e5b376',
  '8441248d8a096d5afe5ec1734afc22fe52094b3c3256659c6021bddbe5e584e7',
  'b6cd4e49bf4c95cc921a65b1cbaa1cdc7a82f53ff8dc44630d1d6dc1c3008517',
  'f07f917c111c514e7c082853e2b630918747904429673d18bf35c8d5984c012c',
  'b27b61037be684924f5497ee79c784f09c971d8c8c3136f6270e0fd34775aa1b',
  '00c666e960132985e9c99dc98bf25782df791138d0f1252b69781694ed97d693',
  '59b4904558092282298915cc266fc57bd7fa697c191f4f04b8329dc7d5caf1b5',
  'f2abd38f0e4032ee6a04777e9314d5fbbcfac7a30acc8afc2860e51c31e18493',
  '9cc73b603f9d303472e23daf581ca3e6b5ec71f01e0199bb089f461cdcb01549',
  '72ac56220abce5c4866ec53ae906d5a2dd3dd4a2715c3c59bf71d705d8a77abf',
  '36d435c4eaa9dfa16ee559201735ec017e76ada7d43ef3c789049378444e26d9',
  '690797a85a4ca196af204046919b6f7d5df96b85d28130fb9ee357a24f311f24',
  '805f2702e76ff5d578052c965ded05a689d9293fd86c5584b0db399d33e9745c',
  'cd77acfc16d0964a4c3ef06f0678a5c88d2d610de00f7b997676fea5b4d2ae9e',
  '2c0b373b4a62770395098399a7d08ca18fce440e3b6c35a22e5910eaf515b72c',
  'a8d188692c31c397b7ae11eaa7f0dc6e29d163237d550ed06048ae82a2017f1a',
];
