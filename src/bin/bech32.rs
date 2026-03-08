//! Command-line [Bech32][] encoding/decoding tool.
//!
//! # Command-Line Arguments
//!
//! The first command-line argument indicates the action.  It is
//! required and must be one of the following values:
//!
//! - `encode`: Read data from standard input, [Bech32m][]-encode it,
//!   then write the result to standard output.
//! - `decode`: Read [Bech32][]-encoded or [Bech32m][]-encoded data from
//!   standard input, verify the [checksum][], decode the data, then
//!   write the result to standard output.
//! - `help`: Print help.
//!
//! **Note:** `e` and `enc` are aliases for `encode`, and `d` and `dec`
//! are aliases for `decode`.
//!
//! # Environment Variables
//!
//! Encoding reads from the following environment variables:
//!
//! - `BECH32_SCHEME`: Encoding scheme name.  One of `bech32` or
//!   `bech32m`.  Defaults to `bech32m` if unspecified.
//! - `BECH32_HRP`: human-readable part (HRP). Defaults to
//!   `example` if unspecified.
//!
//! # Examples
//!
//! Encode and decode a string:
//!
//! ```sh
//! # encode string
//! $ echo -n hello | cargo run -q --bin bech32 encode; echo
//! example1dpjkcmr0qp8pe8
//!
//! # decode string
//! echo -n example1dpjkcmr0qp8pe8 | cargo run -q --bin bech32 decode; echo
//! hello
//! ```
//!
//! Encode string with a custom human-readable part (HRP):
//!
//! ```sh
//! # encode with hrp set to "yo"
//! $ echo -n hello | BECH32_HRP=yo cargo run -q --bin bech32 encode; echo
//! yo1dpjkcmr03elzfh
//! ```
//!
//! Encode string with using [Bech32][] instead of [Bech32m][]:
//!
//! ```sh
//! # encode with scheme set to "bech32"
//! $ echo -n hello | BECH32_SCHEME=bech32 cargo run -q --bin bech32 encode; echo
//! example1dpjkcmr04ahdu9
//! ```
//!
//! # Notes
//!
//! If you encode a string with a length that is not divisible by 5,
//! then the decoded string may contain trailing `NUL` characters.
//!
//! Example:
//!
//! ```sh
//! $ echo -n hi | cargo run -q --bin bech32 enc | cargo run -q --bin bech32 dec | hd
//! 00000000  68 69 00                                          |hi.|
//! 00000003
//! ```
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"
//! [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "Bech32m (BIP350)"
//! [checksum]: https://en.wikipedia.org/wiki/Checksum
//!   "Checksum (Wikipedia)"

use std::io::{Read, Write};
use pbech32::{Bech32, Encoder, Hrp, Scheme};

/// Default scheme.
const DEFAULT_SCHEME: Scheme = Scheme::Bech32m;

/// Default HRP string.
const DEFAULT_HRP: &str = "example";

/// Encoder configuration
#[derive(Clone, Debug, Eq, PartialEq)]
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
    use std::env::{VarError, var};

    // get scheme
    let scheme = match var("BECH32_SCHEME") {
      Ok(s) if !s.is_empty() => match s.as_ref() {
        "bech32" => Scheme::Bech32,
        "bech32m" => Scheme::Bech32m,
        _ => return Err(format!("unknown scheme: {}", s).into()),
      },
      Ok(_) | Err(VarError::NotPresent) => DEFAULT_SCHEME,
      Err(err) => return Err(Box::new(err)),
    };

    // get hrp
    let hrp = match var("BECH32_HRP") {
      Ok(s) if !s.is_empty() => s.parse::<Hrp>()?,
      Ok(_) | Err(VarError::NotPresent) => DEFAULT_HRP.parse::<Hrp>()?,
      Err(err) => return Err(Box::new(err)),
    };

    // return success
    Ok(Self { scheme, hrp })
  }
}

/// Tool action.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
  /// Encode from standard input and write to standard output.
  Encode(EncodeConfig),

  /// Decode from standard input and write to standard output.
  Decode,

  /// Print usage.
  Help,
}

impl Action {
  /// Usage string
  const HELP: &str = "Usage: bech32 [encode|decode|help]\n";

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

      Action::Help => dst.write_all(Self::HELP.as_ref())?,
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
      "h" | "-h" | "--help" | "help" => Ok(Action::Help),
      _ => Err(format!("unknown action: {}", s).into()),
    }
  }
}

/// Run command.
///
/// **Note:*** This function is separate from [`main()`] to make it
/// testable.
///
/// # Parameters
///
/// - `args`: Command-line arguments.
/// - `stdin`: Input [reader][`std::io::Read`].
/// - `stdout`: Output [writer][`std::io::Wrier`].
fn run<R: Read, W: Write>(args: Vec<String>, mut src: R, mut dst: &mut W) -> Result<(), Box<dyn std::error::Error>> {
  match args.len() {
    2 => args[1].parse::<Action>()?.run(&mut src, &mut dst), // parse/run action
    _ => Err(format!("Usage: {} [encode|decode|help]", args[0]).into()), // usage error
  }
}

/// Command-line entry point.
fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args: Vec<String> = std::env::args().collect(); // get args
  let (mut stdin, mut stdout) = (std::io::stdin(), std::io::stdout()); // get stdio
  run(args, &mut stdin, &mut stdout) // run
}

#[cfg(test)]
mod tests {
  mod encode_config {
    use super::super::*;

    // Set environment variables, invoke function, then restore
    // environment variables to their original values.
    //
    // Used by `tests::encode_config::test_from_env()`.
    //
    // Note: unsafe blocks are necessary because `std::env::set_var()`
    // and `std::env::remove_var()` are unsafe.
    fn with_env<F: FnOnce()>(vals: &[(&str, &str)], f: F) {
      use std::env::{VarError, remove_var, set_var, var};

      // cache old vals
      let old_vals = vals.iter().map(|(key, _)| (key, match var(key) {
        Ok(s) if !s.is_empty() => Some(s),
        Ok(_) | Err(VarError::NotPresent) => None,
        Err(err) => panic!("{err}"),
      }));

      vals.iter().for_each(|(key, val)| unsafe { set_var(key, val) }); // set vars
      f(); // call fn

      // restore old vals
      old_vals.for_each(|(key, val)| match val {
        Some(val) => unsafe { set_var(key, val) },
        None => unsafe { remove_var(key) },
      });
    }

    // this test is ignored by default because it alters environment
    // variables which affect tests running in other threads.  to run
    // this test safely, run tests with threading disabled, like so:
    //
    //   # run tests with threading disabled and include ignored tests
    //   cargo test -j 1 -- --include-ignored
    //
    // same for code coverage w/tarpaulin:
    //
    //   # run tarpaulin with threading disabled and include ignored tests
    //   cargo tarpaulin -j 1 -i
    //
    #[test]
    #[ignore] // ignored because it breaks other tests
    fn test_from_env() {
      let hrp: Hrp = DEFAULT_HRP.parse().unwrap();

      // tests expected to pass
      let pass_tests = vec![(
        "empty",
        vec![],
        EncodeConfig { scheme: Scheme::Bech32m, hrp: hrp.clone() },
      ), (
        "scheme=bech32",
        vec![("BECH32_SCHEME", "bech32")],
        EncodeConfig { scheme: Scheme::Bech32, hrp: hrp.clone() },
      ), (
        "scheme=bech32m",
        vec![("BECH32_SCHEME", "bech32m")],
        EncodeConfig { scheme: Scheme::Bech32m, hrp: hrp.clone() },
      ), (
        "hrp=asdf",
        vec![("BECH32_HRP", "asdf")],
        EncodeConfig { scheme: Scheme::Bech32m, hrp: "asdf".parse().unwrap() },
      ), (
        "scheme=bech32, hrp=fdsa",
        vec![("BECH32_SCHEME", "bech32"), ("BECH32_HRP", "fdsa")],
        EncodeConfig { scheme: Scheme::Bech32, hrp: "fdsa".parse().unwrap() },
      )];

      for (name, env, exp) in pass_tests {
        with_env(&env, || {
          let got = EncodeConfig::from_env().unwrap();
          assert_eq!(got, exp, "{name}");
        });
      }

      // tests expected to fail
      let fail_tests = vec![(
        "scheme=invalid",
        vec![("BECH32_SCHEME", "invalid")],
        "unknown scheme: invalid",
      ), (
        "hrp=foo bar",
        vec![("BECH32_SCHEME", ""), ("BECH32_HRP", "foo bar")],
        "invalid character at position 3",
      )];

      for (name, env, exp) in fail_tests {
        with_env(&env, || {
          match EncodeConfig::from_env() {
            Ok(config) => panic!("got {config:?}, exp err"),
            Err(err) => assert_eq!(err.to_string(), exp, "{name}"),
          };
        });
      }

      // clear all env vars
      for key in vec!["BECH32_SCHEME", "BECH32_HRP"] {
        unsafe { std::env::remove_var(key); }
      }
    }
  }

  mod action {
    use super::super::*;

    #[test]
    fn test_from_str() {
      let hrp: Hrp = DEFAULT_HRP.parse().unwrap();
      let config = EncodeConfig { scheme: DEFAULT_SCHEME, hrp: hrp };
      let tests = vec![
        ("d", Action::Decode),
        ("dec", Action::Decode),
        ("decode", Action::Decode),
        ("e", Action::Encode(config.clone())),
        ("enc", Action::Encode(config.clone())),
        ("encode", Action::Encode(config.clone())),
        ("-h", Action::Help),
        ("--help", Action::Help),
        ("help", Action::Help),
      ];

      for (s, exp) in tests {
        let got: Action = s.parse().unwrap();
        assert_eq!(got, exp, "{s}");
      }
    }

    #[test]
    fn test_from_str_fail() {
      let tests = vec![
        ("asdf", "unknown action: asdf"),
      ];

      for (s, exp) in tests {
        match s.parse::<Action>() {
          Ok(val) => panic!("got {val:?}, exp err"),
          Err(err) => assert_eq!(err.to_string(), exp, "{s}"),
        };
      }
    }

    #[test]
    fn test_run() {
      let hrp: Hrp = DEFAULT_HRP.parse().unwrap();
      let config = EncodeConfig { scheme: DEFAULT_SCHEME, hrp: hrp };

      let tests = vec![
        ("encode asdf", Action::Encode(config.clone()), "asdf", "example1v9ekges6962cn"),
        ("decode asdf", Action::Decode, "example1v9ekges6962cn", "asdf\0"),
        ("help", Action::Help, "", Action::HELP),
      ];

      for (name, action, s, exp) in tests {
        let mut got = vec![]; // output "writer"
        action.run(&mut s.as_bytes(), &mut got).unwrap(); // run action
        let got = str::from_utf8(&got).unwrap(); // convert to string
        assert_eq!(got, exp, "{name}"); // check result
      }
    }
  }

  #[test]
  fn test_run() {
    use super::*;

    // tests expected to pass
    let pass_tests = vec![(
      "encode",
      vec!["bech32".to_string(), "encode".to_string()],
      "asdf",
      "example1v9ekges6962cn",
    ), (
      "decode",
      vec!["bech32".to_string(), "decode".to_string()],
      "example1v9ekges6962cn",
      "asdf\0",
    )];

    for (name, args, s, exp) in pass_tests {
      let mut got = vec![]; // output "writer"
      run(args, &mut s.as_bytes(), &mut got).unwrap(); // run action
      let got = str::from_utf8(&got).unwrap(); // convert to string
      assert_eq!(got, exp, "{name}"); // check result
    }

    // tests expected to fail
    let fail_tests = vec![(
      "missing action",
      vec!["bech32".to_string()],
      "",
      "Usage: bech32 [encode|decode|help]",
    ), (
      "extra args",
      vec!["bech32".to_string(), "foo".to_string(), "bar".to_string()],
      "",
      "Usage: bech32 [encode|decode|help]",
    )];

    for (name, args, s, exp) in fail_tests {
      let mut got = vec![]; // output "writer"
      match run(args, &mut s.as_bytes(), &mut got) {
        Ok(_) => {
          let got = str::from_utf8(&got).unwrap(); // convert to string
          panic!("got success (got = {got}), exp error");
        },
        Err(err) => assert_eq!(err.to_string(), exp, "{name}"),
      }
    }
  }
}
