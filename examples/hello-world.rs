//! Encode [Bech32][] string, print the string, then parse the string
//! and print the structure to standard output.
//!
//! # Example
//! 
//! ```sh
//! $ cargo run -q --example hello-world
//! encoded = hello1vehkc6mn27xpct
//! decoded = Bech32 { scheme: Bech32m, hrp: Hrp("hello"), data: [102, 111, 108, 107, 115] }
//! ```
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"
use pbech32::{Bech32, Err, Hrp, Scheme};

fn main() -> Result<(), Err> {
  let scheme = Scheme::Bech32m; // checksum scheme
  let hrp: Hrp = "hello".parse()?; // human-readable part
  let data = b"folks".to_vec(); // data
  let s = Bech32 { scheme, hrp, data }.to_string(); // encode string
  
  println!("encoded = {s}"); // print string
  let b: Bech32 = s.parse()?; // parse string
  println!("decoded = {b:?}"); // print struct

  Ok(()) // return success
}
