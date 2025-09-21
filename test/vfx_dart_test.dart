// ignore_for_file: constant_identifier_names

import 'package:vfx_dart/src/keypair_service.dart';
import 'package:vfx_dart/src/bitcoin_keypair_service.dart';
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

      final address =
          KeypairUtils.addressFromPrivate(privateKey, isTestnet: true);
      expect(address, isNotNull);
      expect(address[0], equals("x"));
    });

    test('Private Key to Address', () {
      final address = KeypairUtils.addressFromPrivate(
          "50fd0400021e7331479b1f8ec99b5dcbe3c50c41cac3afb6cd572e62fbc7bff6",
          isTestnet: true);
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

      final address =
          KeypairUtils.addressFromPrivate(privateKey, isTestnet: true);
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
      final kp = kpService.keypairFromEmailAndPassword(
          "tyler@tylersavery.com", "younotry");
      expect(kp.address, equals("xMjrfrzkrNC2g3KJidbwF21gB7R3m46B9w"));
    });
  });

  group('Bitcoin Keypair Utils (Private API)', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('Bitcoin Private Key to Address', () {
      final address = KeypairUtils.bitcoinAddressFromPrivate(
          "50fd0400021e7331479b1f8ec99b5dcbe3c50c41cac3afb6cd572e62fbc7bff6",
          isTestnet: true);
      expect(address, isNotNull);
      expect(
          address,
          startsWith(
              "tb1")); // Bitcoin testnet Bech32 addresses start with 'tb1'
    });

    test('Bitcoin Private Key to Mainnet Address', () {
      final address = KeypairUtils.bitcoinAddressFromPrivate(
          "50fd0400021e7331479b1f8ec99b5dcbe3c50c41cac3afb6cd572e62fbc7bff6",
          isTestnet: false);
      expect(address, isNotNull);
      expect(
          address,
          startsWith(
              "bc1")); // Bitcoin mainnet Bech32 addresses start with 'bc1'
    });

    test('Bitcoin Mnemonic Recovery', () {
      final words =
          "entire taste skull already invest view turtle surge razor key next buffalo venue canoe sheriff winner wash ten subject hamster scrap unit shield garden";
      final privateKey = KeypairUtils.bitcoinPrivateKeyFromMnemonic(words, 0);
      expect(privateKey, isNotNull);
      print(privateKey);
      final address =
          KeypairUtils.bitcoinAddressFromPrivate(privateKey, isTestnet: true);

      print(address);
      expect(address, isNotNull);
      print(address);
      expect(address, startsWith("tb1")); // Bitcoin testnet Bech32 addresses
    });

    test('Bitcoin Specific Private Key to Bech32 Address', () {
      final privateKey = "56635d0d93c446076946c9e0c750dcfcef4db63ea156f01928b667b61a6e8f91";
      final address = KeypairUtils.bitcoinAddressFromPrivate(privateKey, isTestnet: true);
      expect(address, equals("tb1q066af78la3rqmnchc396keujllva6turs52749"));
    });
  });

  group('Bitcoin Keypair Service (Public API)', () {
    final btcService = BitcoinKeypairService(isTestnet: true);

    setUp(() {
      // Additional setup goes here.
    });

    test('Bitcoin Email/Password to Keypair', () {
      final kp = btcService.keypairFromEmailAndPassword(
          "tyler@tylersavery.com", "younotry");
      expect(kp.address, isNotNull);
      expect(kp.address, startsWith("tb1")); // Bitcoin testnet Bech32 addresses
      expect(kp.privateKey, isNotNull);
      expect(kp.publicKey, isNotNull);
    });

    test('Bitcoin Generated Keypair', () {
      final kp = btcService.keypairFromGeneratedPrivateKey();
      expect(kp.address, isNotNull);
      expect(kp.address, startsWith("tb1")); // Bitcoin testnet Bech32 addresses
      expect(kp.privateKey.length, equals(64)); // 32 bytes = 64 hex chars
    });

    test('Bitcoin Mainnet Service', () {
      final btcMainnetService = BitcoinKeypairService(isTestnet: false);
      final kp = btcMainnetService.keypairFromGeneratedPrivateKey();
      expect(kp.address, isNotNull);
      expect(kp.address, startsWith("bc1")); // Bitcoin mainnet Bech32 addresses
    });

    test('Bitcoin Mnemonic Generation and Recovery', () {
      final kp1 = btcService.keypairFromGeneratedMnemonic(words: 12);
      expect(kp1.mnemonic, isNotNull);
      expect(kp1.mnemonic!.split(" ").length, equals(12));

      // Recover from the same mnemonic
      final kp2 = btcService.keypairFromRestoredMnemonic(kp1.mnemonic!);
      expect(kp2.address, equals(kp1.address));
      expect(kp2.privateKey, equals(kp1.privateKey));
    });
  });
}
