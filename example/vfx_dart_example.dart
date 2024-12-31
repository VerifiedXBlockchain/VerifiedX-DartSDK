import 'package:vfx_dart/vfx_dart.dart';

void main() {
  final keypairService = KeypairService(isTestnet: true);
  final keypair = keypairService.keypairFromEmailAndPassword("dev@verifiedx.io", "tokenized");

  print(keypair);
}
