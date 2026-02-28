//! Read human-readable part (HRP) from first command-line argument and
//! data from standard input, then stream [Bech32m][]-encoded string to
//! standard output.
//!
//! # Example
//!
//! ```sh
//! $ echo -n 'world' | cargo run -q --example stream hello; echo
//! hello1wahhymryxruu7j
//! ```
//!
//! [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "Bech32m (BIP350)"

use std::io::Write;
use pbech32::{Encoder, Hrp, Scheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // get/check args
  let args: Vec<String> = std::env::args().collect();
  if args.len() != 2 {
    panic!("Usage: {} [hrp]", args[0]);
  }

  let hrp: Hrp = args[1].parse()?; // parse first arg as hrp
  let (mut stdin, mut stdout) = (std::io::stdin(), std::io::stdout()); // get stdio

  let mut encoder = Encoder::new(&mut stdout, Scheme::Bech32m, hrp)?; // create encoder
  std::io::copy(&mut stdin, &mut encoder)?; // bech32-encode stdin to stdout
  encoder.flush()?; // flush encoder

  Ok(()) // return success
}
