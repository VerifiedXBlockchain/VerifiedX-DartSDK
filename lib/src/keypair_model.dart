class Keypair {
  final String privateKey;
  final String publicKey;
  final String address;
  final String? mnemonic;

  Keypair({
    required this.privateKey,
    required this.publicKey,
    required this.address,
    this.mnemonic,
  });

  @override
  String toString() {
    return address;
  }
}
