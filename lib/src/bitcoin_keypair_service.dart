import 'package:vfx_dart/src/keypair_model.dart';
import 'package:vfx_dart/src/keypair_utils.dart';

class BitcoinKeypairService {
  final bool isTestnet;

  const BitcoinKeypairService({this.isTestnet = false});

  Keypair keypairFromPrivateKey(String privateKey, {String? mnemonic}) {
    final publicKey = KeypairUtils.publicFromPrivate(privateKey);
    final address =
        KeypairUtils.bitcoinAddressFromPrivate(privateKey, isTestnet: isTestnet);

    return Keypair(
      privateKey: privateKey,
      publicKey: publicKey,
      address: address,
      mnemonic: mnemonic,
    );
  }

  Keypair keypairFromGeneratedPrivateKey() {
    final privateKey = KeypairUtils.generateRandomPrivateKey();
    return keypairFromPrivateKey(privateKey);
  }

  Keypair keypairFromEmailAndPassword(String email, String password) {
    final seed = KeypairUtils.seedFromEmailPassword(email, password);
    final privateKey = KeypairUtils.seedToPrivateKey(seed);
    return keypairFromPrivateKey(privateKey);
  }

  Keypair keypairFromRestoredMnemonic(String mnemonic, {int index = 0}) {
    final privateKey = KeypairUtils.bitcoinPrivateKeyFromMnemonic(mnemonic, index);
    return keypairFromPrivateKey(privateKey, mnemonic: mnemonic);
  }

  Keypair keypairFromGeneratedMnemonic(
      {required int words, int index = 0}) {
    final mnemonic = KeypairUtils.generateMnemonic(words: words);
    final privateKey = KeypairUtils.bitcoinPrivateKeyFromMnemonic(mnemonic, index);
    return keypairFromPrivateKey(privateKey, mnemonic: mnemonic);
  }
}