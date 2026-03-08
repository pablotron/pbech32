# pbech32 Examples

[pbech32][] examples.  Run with `cargo run --example NAME`.

- `decode`: Decode [Bech32][] string from first command-line output,
  convert the decoded data to a string, then print the string to
  standard output.
- `encode`: Read `hrp` and `data` from arguments, create [Bech32m][]
  string, then print the string to standard output.
- `hello-world`: Encode [Bech32][] string, print the string, then parse
  the string and print the structure to standard output.
- `stream`: Read human-readable part (HRP) from first command-line
  argument and data from standard input, then stream [Bech32m][]-encoded
  string to standard output.

[pbech32]: https://github.com/pablotron/pbech32
  "pbech32 Rust library"
[bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  "Bech32 (BIP173)"
[bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  "Bech32m (BIP350)"
