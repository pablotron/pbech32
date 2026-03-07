//! Command-line [Bech32][] encoding/decoding tool.
//!
//! The first argument indicates the mode and must be one of `encode` or
//! `decode`:
//!
//! - `encode`: Read data from standard input, [Bech32m][]-encode it,
//!   then write the encoded data to standard output.
//!
//! - `decode`: Read [Bech32][]-encoded or [Bech32m][]-encoded data from
//!   standard input, verify the checksum, decode the data, then then
//!   write the decoded data to standard output.
//!
//! # Example
//!
//! ```sh
//! # encode string "hello world" as bech32
//! $ echo -n 'hi there' | cargo run -q --bin bech32 encode; echo
//! abc1dp5jqargv4ex2qlre3s
//!
//! # decode bech32-encoded string
//! $ echo -n 'abc1dp5jqargv4ex2qlre3s' | cargo run -q --bin bech32 decode; echo
//! hi there
//! ```
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"
//! [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "Bech32m (BIP350)"

use std::io::{Read, Write};
use pbech32::{Bech32, Encoder, Hrp, Scheme};

/// Default scheme.
const DEFAULT_SCHEME: Scheme = Scheme::Bech32m;

/// Default HRP string.
const DEFAULT_HRP: &str = "abc";

/// Encoder configuration
#[derive(Clone, Debug)]
struct EncodeConfig {
  scheme: Scheme,
  hrp: Hrp,
}

impl EncodeConfig {
  /// Create encoder configuration from environment.
  ///
  /// Reads from the following environment variables:
  ///
  /// - `BECH32_SCHEME`: Encoding scheme name.  One of `bech32` or
  ///   `bech32m`.  Defaults to [`DEFAULT_SCHEME`] if unspecified.
  /// - `BECH32_HRP`: human-readable part (HRP). Defaults to
  ///   [`DEFAULT_HRP`] if unspecified.
  ///
  /// Returns an error if any of following conditions occur:
  ///
  /// - `BECH32_SCHEME` is set and the value is not a valid encoding
  ///   scheme name (e.g. it is not one of `bech32` or `bech32m`).
  /// - `BECH32_HRP` is set and the value is not a valid HRP string.
  pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
    // get scheme
    let scheme = match std::env::var("BECH32_SCHEME") {
      Ok(s) => match s.as_ref() {
        "bech32" => Scheme::Bech32,
        "bech32m" => Scheme::Bech32m,
        _ => return Err("unknown scheme".into()),
      },
      Err(std::env::VarError::NotPresent) => DEFAULT_SCHEME,
      Err(err) => return Err(Box::new(err)),
    };

    // get hrp
    let hrp = match std::env::var("BECH32_HRP") {
      Ok(s) => s.parse::<Hrp>()?,
      Err(std::env::VarError::NotPresent) => DEFAULT_HRP.parse::<Hrp>()?,
      Err(err) => return Err(Box::new(err)),
    };

    // return success
    Ok(Self { scheme, hrp })
  }
}

/// Tool action.
#[derive(Clone, Debug)]
enum Action {
  /// Encode from standard input and write to standard output.
  Encode(EncodeConfig),

  /// Decode from standard input and write to standard output.
  Decode,
}

impl Action {
  /// Run action with given source [reader][`std::io::Read`] and
  /// destination [writer][`std::io::Write`].
  pub fn run<R: Read, W: Write>(&self, mut src: R, mut dst: &mut W) -> Result<(), Box<dyn std::error::Error>> {
    match self {
      Action::Encode(config) => {
        let mut encoder = Encoder::new(&mut dst, config.scheme, config.hrp.clone())?; // create encoder
        std::io::copy(&mut src, &mut encoder)?; // encode from src to encoder
        encoder.flush()?; // flush encoder
      },

      Action::Decode => {
        let mut s = String::new(); // intermediate string buffer
        src.read_to_string(&mut s)?; // read to buffer
        let b: Bech32 = s.parse()?; // parse buffer
        dst.write_all(&b.data)?; // write decoded data to output
      },
    };

    Ok(())
  }
}

impl std::str::FromStr for Action {
  type Err = Box<dyn std::error::Error>;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "e" | "enc" | "encode" => Ok(Action::Encode(EncodeConfig::from_env()?)),
      "d" | "dec" | "decode" => Ok(Action::Decode),
      _ => Err(format!("unknown action: {}", s).into()),
    }
  }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // get/check args
  let args: Vec<String> = std::env::args().collect();
  if args.len() != 2 {
    panic!("Usage: {} [encode|decode]", args[0]);
  }

  // get action from first argument
  let action: Action = args[1].parse()?;

  let (mut stdin, mut stdout) = (std::io::stdin(), std::io::stdout()); // get stdio
  action.run(&mut stdin, &mut stdout)?; // run action
  Ok(()) // return success
}

#[cfg(test)]
mod tests {
  // TODO: add tests
}
