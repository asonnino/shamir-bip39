# BIP-39 Shamir Secret Sharing

[![build status](https://img.shields.io/github/actions/workflow/status/asonnino/shamir-bip39/rust.yml?branch=main&logo=github&style=flat-square)](https://github.com/asonnino/shamir-bip39/actions)
[![rustc](https://img.shields.io/badge/rustc-1.69+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

Apply [Shamir’s Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) to [BIP-39 mnemonics](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), in accordance with the specifications outlined in [EIP-3450](https://eips.ethereum.org/EIPS/eip-3450). Each individual share constitutes a valid BIP-39 mnemonic, allowing them to serve as decoy wallets if needed. Similarly, any secret reconstructed using fewer than the required threshold number of shares can also be utilized in the same manner. This implementation makes effective use of the [gf256](https://github.com/geky/gf256) library to perform operations on Galois fields.

> This implementation has not been audited and is only suitable for experimental purposes.

## Basic Usage

The binary offers two primary functions: one for splitting a BIP-39 secret and another for reconstructing it from a threshold number of these shares. By default, this repository utilizes a valid English [BIP-39 dictionary](https://github.com/asonnino/shamir-bip39/blob/main/assets/bip39-en.txt). However, users have the flexibility to specify an external dictionary using the `--dictionary-path` option.

### Splitting

The following command shares a bBBIPIPip-30 mnemonic into 3 shares such that it can be reconstructed from any 2 shares. The feature `double-check` actively asserts that the master secret can reconstructed from any 2 shares, which should always be the case.

```bash
cargo run --features double-check split -t 2 -n 3 --secret "permit universe parent weapon amused modify essay borrow tobacco budget walnut lunch consider gallery ride amazing frog forget treat market chapter velvet useless topple"
```

The command outputs all 3 shares in a similar format as shown in the example below. Note that the output of this command is non-deterministic since the mnemonic is split using a randomly generated polynomial.

```text
Share 1/3
---------------------------------------------------------------------
 1  ice    5  toe     9  slush     13 cross   17 dance    21 echo
 2  rival  6  rough   10 blue      14 eagle   18 puppy    22 various
 3  badge  7  flame   11 scorpion  15 saddle  19 satoshi  23 maple
 4  cup    8  bubble  12 release   16 catch   20 scheme   24 vintage
---------------------------------------------------------------------


Share 2/3
--------------------------------------------------------------------
 1  blouse    5  burger  9  sadness  13 amount  17 mean    21 thumb
 2  envelope  6  hip     10 bus      14 twelve  18 rice    22 vital
 3  shift     7  become  11 own      15 rabbit  19 bitter  23 bread
 4  ghost     8  behind  12 tennis   16 doctor  20 case    24 frog
--------------------------------------------------------------------


Share 3/3
------------------------------------------------------------------------
 1  sleep     5  vital    9  myth     13 battle  17 together  21 load
 2  bronze    6  flip     10 brass    14 valve   18 erase     22 walk
 3  innocent  7  alley    11 prepare  15 region  19 example   23 hollow
 4  property  8  because  12 upset    16 glory   20 hill      24 fiscal
------------------------------------------------------------------------
```

### Reconstruction

The following command reconstructs the master BIP-39 mnemonic from the 3rd and 2nd share:

```bash
cargo run reconstruct --shares "3 sleep bronze innocent property vital flip alley because myth brass prepare upset battle valve region glory together erase example hill load walk hollow fiscal","2 blouse envelope shift ghost burger hip become behind sadness bus own tennis amount twelve rabbit doctor mean rice bitter case thumb vital bread frog"
```

Output:

```text
Master Secret
------------------------------------------------------------------------
 1  permit    5  amused  9  tobacco  13 consider  17 frog    21 chapter
 2  universe  6  modify  10 budget   14 gallery   18 forget  22 velvet
 3  parent    7  essay   11 walnut   15 ride      19 treat   23 useless
 4  weapon    8  borrow  12 lunch    16 amazing   20 market  24 topple
------------------------------------------------------------------------
```

## Related Projects
See also [danielstreit/shamir-bip39](https://github.com/danielstreit/shamir-bip39) for an implementation in TypeScript.

## License

This software is licensed as [Apache 2.0](LICENSE).
