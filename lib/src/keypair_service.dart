import 'package:vfx_dart/src/keypair_model.dart';
import 'package:vfx_dart/src/keypair_utils.dart';

class KeypairService {
  // ** KEYPAIR GENERATORS **

  final bool isTestnet;

  const KeypairService({this.isTestnet = false});

  Keypair keypairFromPrivateKey(String privateKey, {String? mnemonic}) {
    final publicKey = KeypairUtils.publicFromPrivate(privateKey);
    final address = KeypairUtils.addressFromPrivate(privateKey, isTestnet: isTestnet);

    return Keypair(
      privateKey: privateKey,
      publicKey: publicKey,
      address: address,
      mnemonic: mnemonic,
    );
  }

  Keypair keypairFromGeneratedPrivateKey(String privateKey) {
    final privateKey = KeypairUtils.generateRandomPrivateKey();
    return keypairFromPrivateKey(privateKey);
  }

  Keypair keypairFromEmailAndPassword(String email, String password) {
    final seed = KeypairUtils.seedFromEmailPassword(email, password);
    final privateKey = KeypairUtils.seedToPrivateKey(seed);
    return keypairFromPrivateKey(privateKey);
  }

  Keypair keypairFromRestoredMnemonic(String mnemonic, {int nonce = 0}) {
    final privateKey = KeypairUtils.privateKeyFromMnemonic(mnemonic, nonce);
    return keypairFromPrivateKey(privateKey, mnemonic: mnemonic);
  }

  Keypair keypairFromGeneratedMnemonic({required int words, int nonce = 0, bool isTestnet = false}) {
    final mnemonic = KeypairUtils.generateMnemonic(words: words);
    final privateKey = KeypairUtils.privateKeyFromMnemonic(mnemonic, nonce);
    return keypairFromPrivateKey(privateKey, mnemonic: mnemonic);
  }
}
