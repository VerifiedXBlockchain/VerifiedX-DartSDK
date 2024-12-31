<!-- 
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/tools/pub/writing-package-pages). 

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/to/develop-packages). 
-->

TODO: VerifiedX (VFX) Dart SDK for generating and managing keypairs.

## Features

- Generate secure random keypair
- Convert private keys to addresses (Mainnet and Testnet supported)
- Generate and recover with mnemonics
- Generate keypair with email & password

## Getting started

```
dart pub get
```

## Usage


```dart
final keypairService = KeypairService(isTestnet: true);
final keypair = keypairService.keypairFromEmailAndPassword("dev@verifiedx.io", "tokenized");

print(keypair);
```

## Additional information

All public and private APIs must have test coverage.
