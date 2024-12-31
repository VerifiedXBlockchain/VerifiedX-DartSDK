// ignore_for_file: constant_identifier_names

import 'package:vfx_dart/src/keypair_service.dart';
import 'package:vfx_dart/src/keypair_utils.dart';
import 'package:vfx_dart/vfx_dart.dart';
import 'package:test/test.dart';

void main() {
  group('Keypair Utils (Private API)', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('Generate Private Key', () {
      final privateKey = KeypairUtils.generateRandomPrivateKey();
      expect(privateKey, isNotNull);
      expect(privateKey.length, equals(64));

      final address = KeypairUtils.addressFromPrivate(privateKey, isTestnet: true);
      expect(address, isNotNull);
      expect(address[0], equals("x"));
    });

    test('Private Key to Address', () {
      final address = KeypairUtils.addressFromPrivate("50fd0400021e7331479b1f8ec99b5dcbe3c50c41cac3afb6cd572e62fbc7bff6", isTestnet: true);
      expect(address, equals("xT5nDBCm9QCWPWtJvSsFu1ZD64ot5MXmx7"));
    });

    test('Generate Mnumonic', () {
      final mnumonic = KeypairUtils.generateMnemonic(words: 24);

      expect(mnumonic, isNotNull);
      final words = mnumonic.split(" ").length;

      expect(words, equals(24));
    });

    test('Mnumonic Recovery', () {
      final words =
          "doctor twelve left dose end thunder unusual shift there kid please alley liquid outdoor abstract pause provide cattle index correct sword mushroom village cave";
      final privateKey = KeypairUtils.privateKeyFromMnemonic(words, 0);
      print(privateKey);
      expect(privateKey, isNotNull);

      final address = KeypairUtils.addressFromPrivate(privateKey, isTestnet: true);
      // expect(address, equals("xPTdEtmwY58pUHx1TVcmcGaAABGUCnvkKT"));
      expect(address, equals("xMFndSBiVzPQSNjQ8bcQFKDZdow8xKQhwK"));
    });
  });

  group('Keypair Service (Public API)', () {
    final kpService = KeypairService(isTestnet: true);

    setUp(() {
      // Additional setup goes here.
    });

    test('Email/Password to Keypair', () {
      final kp = kpService.keypairFromEmailAndPassword("tyler@tylersavery.com", "younotry");
      expect(kp.address, equals("xMjrfrzkrNC2g3KJidbwF21gB7R3m46B9w"));
    });
  });
}
