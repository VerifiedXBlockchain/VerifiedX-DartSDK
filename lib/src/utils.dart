// Convert a Uint8List to a hexadecimal string
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:convert/convert.dart';

String arrayToHex(Uint8List bytes) => hex.encode(bytes);

// Convert a hexadecimal string to a Uint8List
Uint8List hexToBytes(String hexString) => Uint8List.fromList(hex.decode(hexString));

// Convert a BigInt to Uint8List
Uint8List bigIntToBytes(BigInt number) {
  final hexString = number.toRadixString(16).padLeft(64, '0');
  return hexToBytes(hexString);
}

// Perform RIPEMD160 hash
Uint8List ripemd160(Uint8List input) {
  final digest = Digest('RIPEMD-160');
  return digest.process(input);
}

// Perform SHA256 hash
Uint8List sha256(Uint8List input) {
  final digest = Digest('SHA-256');
  return digest.process(input);
}

// Concatenate two Uint8List arrays
Uint8List concatArrays(List<Uint8List> arrays) {
  final length = arrays.fold(0, (sum, item) => sum + item.length);
  final result = Uint8List(length);
  int offset = 0;
  for (final array in arrays) {
    result.setRange(offset, offset + array.length, array);
    offset += array.length;
  }
  return result;
}
