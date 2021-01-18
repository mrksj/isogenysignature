## Digital Signature Scheme based on Supersingular Isogenies.

This is a fork of
[isogenysignature](https://github.com/yhyoo93/isogenysignature) which
implements the digital signature scheme describes in the paper [*A Post-Quantum Digital Signature Scheme Based on Supersingular Isogenies*](https://eprint.iacr.org/2017/186) by Yoo, Azarderakhsh, Jalali, Jao, and Soukharev.

Following things have been changed:
- Improved memory management
- Ported to [OpenBSD](https://www.openbsd.org)
- Fixed implementation of Unruh's transform
- Enabled the signature scheme to sign messages
- Implemented simple API and option to build a library from the signature
  scheme

This implementation uses an outdated Version of Microsofts [PQCrypto-SIDH](https://github.com/Microsoft/PQCrypto-SIDH)

### BUILDINSTRUCTIONS ON LINUX
To build the signature scheme:
```sh
make ARCH=[x64/x86/ARM] CC=[gcc/clang] ASM=[TRUE/FALSE] GENERIC=[TRUE/FALSE] signature_scheme
```
**Output:** signature_sheme binary

To build the library:
```sh
make ARCH=[x64/x86/ARM] CC=[gcc/clang] ASM=[TRUE/FALSE] GENERIC=[TRUE/FALSE] lib
```
**Output:** `libsisig.so.1.0` which can be used together with the `SISig.h`

**Note:** The implementation has only been tested with the x64 architecture and
the ASM extension (which is only available for x64)

### BUILDINSTRUCTIONS ON OPENBSD
To build the signature scheme:
```sh
make ARCH=x64 ASM=[TRUE/FALSE] GENERIC=[TRUE/FALSE] SET=EXTENDED signature_scheme
```
**Output:** signature_sheme binary

To build the library:
```sh
make ARCH=x64 ASM=[TRUE/FALSE] GENERIC=[TRUE/FALSE] SET=EXTENDED lib
```
**Output:** `libsisig.so.1.0` which can be used together with the `SISig.h`
