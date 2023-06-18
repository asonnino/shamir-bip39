# BIP-39 Shamir Secret Sharing

[![build status](https://img.shields.io/github/actions/workflow/status/asonnino/shamir-bip39/rust.yml?branch=main&logo=github&style=flat-square)](https://github.com/asonnino/shamir-bip39/actions)
[![rustc](https://img.shields.io/badge/rustc-1.69+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

Apply Shamir’s Secret Sharing to BIP-39 mnemonics following [EIP-3450](https://eips.ethereum.org/EIPS/eip-3450). This implementation is based on the library [gf256](https://github.com/geky/gf256) to compute operations over Galois fields.

Only suitable for experimental usage.
