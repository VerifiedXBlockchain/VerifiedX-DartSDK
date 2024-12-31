import 'dart:convert';
import 'dart:typed_data';
import 'package:bip32/bip32.dart' as bip32;
import './bip32/bip32.dart' as bip32b;
import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart';
import 'package:base58check/base58.dart' as base58;
import 'package:crypto/crypto.dart' as crypto;
import 'package:bip39/bip39.dart' as bip39;
import 'package:hex/hex.dart';

import './utils.dart' as utils;

class KeypairUtils {
  // ** CONVERTERS **

  static String seedToPrivateKey(String seed, {int index = 0}) {
    // Convert the seed string to a Uint8List
    Uint8List seedBytes = Uint8List.fromList(seed.codeUnits);

    // Create a BIP32 node from the seed
    final rootNode = bip32.BIP32.fromSeed(seedBytes);

    // Derive the child node using the specified derivation path
    final childNode = rootNode.derivePath("m/0'/0'/$index'");

    // Get the private key as a hexadecimal string
    if (childNode.privateKey != null) {
      return hex.encode(childNode.privateKey!);
    }

    return '';
  }

  static String publicFromPrivate(String privateKey) {
    // Define the secp256k1 curve
    final ecDomain = ECDomainParameters('secp256k1');

    // Create the private key parameter
    final privateKeyParam = ECPrivateKey(BigInt.parse(privateKey, radix: 16), ecDomain);

    // Generate the public key
    final publicKey = ecDomain.G * privateKeyParam.d!;

    // Return the public key as a hex string (uncompressed)
    return hex.encode(publicKey!.getEncoded(false));
  }

  static String addressFromPrivate(String privateKey, {bool isTestnet = false}) {
    // Define the secp256k1 curve
    final ecDomain = ECDomainParameters('secp256k1');

    // Generate the key pair from the private key
    final privateKeyBigInt = BigInt.parse(privateKey, radix: 16);
    final publicKeyPoint = ecDomain.G * privateKeyBigInt;
    final publicKeyBytes = publicKeyPoint!.getEncoded(false); // Uncompressed public key

    // Perform SHA256 hash on the public key
    final pubKeySha = utils.sha256(publicKeyBytes);

    // Perform RIPEMD160 hash on the result of SHA256
    final pubKeyShaRipe = utils.ripemd160(pubKeySha);

    // Add network byte to RIPEMD160 hash
    final networkByte = Uint8List.fromList([isTestnet ? 0x89 : 0x3c]);
    final preHashWNetworkData = utils.concatArrays([networkByte, pubKeyShaRipe]);

    // Perform double SHA256 for checksum
    final publicHash = utils.sha256(preHashWNetworkData);
    final publicHashHash = utils.sha256(publicHash);

    // Extract first 4 bytes of the double SHA256 as the checksum
    final checksum = publicHashHash.sublist(0, 4);

    // Concatenate preHash data and checksum
    final addressBytes = utils.concatArrays([preHashWNetworkData, checksum]);

    // Encode the result in Base58
    final base58Address = base58.Base58Encoder("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").convert(addressBytes);

    return base58Address;
  }

  // ** PRIVATE KEY GENERATOR **

  static String generateRandomPrivateKey() {
    // Create a secure random number generator using Pointy Castle
    final secureRandom = SecureRandom('Fortuna')
      ..seed(KeyParameter(Uint8List.fromList(
        SHA256Digest().process(utf8.encode(DateTime.now().toIso8601String())),
      )));

    // Generate 32 bytes (256 bits) of random data
    final keyBytes = secureRandom.nextBytes(32);

    // Convert to hexadecimal string (64 characters)
    return keyBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }

  // ** EMAIL/PASSWORD **

  static String seedFromEmailPassword(String email, String password) {
    email = email.toLowerCase();

    String seed = "$email|$password|";
    seed = "$seed${seed.length}|!@${((password.length * 7) + email.length) * 7}";

    final regChars = RegExp(r'/[a-z]+/g');
    final regUpperChars = RegExp(r'/[A-Z]+/g');
    final regNumbers = RegExp(r'/[0-9]+/g');

    final chars = regChars.hasMatch(password) ? regChars.allMatches(password).length : 1;
    final upperChars = regUpperChars.hasMatch(password) ? regUpperChars.allMatches(password).length : 1;
    final upperNumbers = regNumbers.hasMatch(password) ? regNumbers.allMatches(password).length : 1;

    seed = "$seed${(chars + upperChars + upperNumbers) * password.length}3571";

    seed = "$seed$seed";

    for (int i = 0; i <= 50; i++) {
      seed = crypto.sha256.convert(utf8.encode(seed)).toString();
    }

    return seed;
  }

  // ** MNEMONICS **

  static String generateMnemonic({int words = 12}) {
    if (words != 12 && words != 24) {
      throw ArgumentError("Words must be either 12 or 24");
    }
    int entropyBits = words == 12 ? 128 : 256;
    return bip39.generateMnemonic(strength: entropyBits);
  }

  // Generate a private key from a mnemonic and nonce.
  static String privateKeyFromMnemonic(String mnemonic, int nonce) {
    final isValid = bip39.validateMnemonic(mnemonic);

    if (!isValid) {
      return "";
    }

    final masterPrivateSeed = bip39.mnemonicToSeed(mnemonic);

    final chain = bip32b.Chain.seed(HEX.encode(masterPrivateSeed));
    final key = chain.forPath("m/0'/0'/$nonce'") as bip32b.ExtendedPrivateKey;

    String privateKey = key.privateKeyHex();
    if (privateKey.length > 64 && privateKey.startsWith("00")) {
      privateKey = privateKey.substring(2);
    }

    return privateKey;
  }
}
