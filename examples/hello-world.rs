//! Encode [Bech32][] string, print the string, then parse the string
//! and print the structure to standard output.
//!
//! # Example
//! 
//! ```sh
//! $ cargo run --example hello-world
//! encoded = hello1wahhymryxruu7j
//! decoded = Bech32 { scheme: Bech32m, hrp: Hrp("hello"), data: [119, 111, 114, 108, 100] }
//! ```
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"
use pbech32::{Bech32, Err, Scheme};

fn main() -> Result<(), Err> {
  // encode bech32 as string
  let s = Bech32 {
    scheme: Scheme::Bech32, // checksum scheme
    hrp: "hello".parse()?, // human-readable part
    data: b"world".to_vec(), // data
  }.to_string();
  
  println!("encoded = {s}"); // print string
  let b: Bech32 = s.parse()?; // parse string
  println!("decoded = {b:?}"); // print struct

  Ok(())
}
