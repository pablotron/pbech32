//! Read `hrp` and `data` from arguments, create [Bech32m][]
//! string, then print the string to standard output.
//!
//! # Example
//!
//! ```sh
//! $ cargo run -q --example encode -- foo bar
//! foo1vfshy2dnlu3
//! ```
//!
//! [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "Bech32m (BIP350)"

use pbech32::{Bech32, Hrp, Err, Scheme};

fn main() -> Result<(), Err> {
  // get/check args
  let args: Vec<String> = std::env::args().collect();
  if args.len() != 3 {
    panic!("Usage: {} [hrp] [data]", args[0]);
  }

  // build bech32m, print string
  let scheme = Scheme::Bech32m;
  let hrp: Hrp = args[1].parse()?;
  let data = args[2].as_bytes().to_vec();
  println!("{}", Bech32 { scheme, hrp, data });

  Ok(())
}
