//! Decode [Bech32][] string from first command-line output, convert the
//! decoded data to a string, then print the string to standard output.
//!
//! # Example
//!
//! ```sh
//! $ cargo run -q --example decode fizz1vf6h573ppvvuqe
//! buzz!
//! ```
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"

use pbech32::{Bech32, Err};

/// Strip trailing 0 bytes and convert vector of bytes to string.
fn stringify(v: Vec<u8>) -> String {
  v.iter().filter(|b| **b != 0).map(|b| *b as char).collect::<String>()
}

fn main() -> Result<(), Err> {
  // get/check args
  let args: Vec<String> = std::env::args().collect();
  if args.len() != 2 {
    panic!("Usage: {} [BECH32_STR]", args[0]);
  }

  // decode arg, convert data to string, then print string
  let b: Bech32 = args[1].parse()?; // decode arg
  println!("{}", stringify(b.data)); // convert/print string

  Ok(())
}
