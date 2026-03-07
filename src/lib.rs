//! [Bech32][] encoding and decoding library.
//!
//! # What is Bech32?
//!
//! [Bech32][] is a fast and user-friendly [base 32][] encoding format
//! that includes a [namespace][] and [checksum][].  [Bech32m][] is an
//! update to [Bech32][] with an improved [checksum][] algorithm.
//!
//! A [Bech32][] string contains a human-readable part (HRP), an encoded
//! data part, and a 6 character [checksum][].  The data part and
//! [checksum][] are [base 32][]-encoded with a user-friendly
//! [alphabet][] that only contains lowercase [ASCII][] alphanumeric
//! characters.
//!
//! Here is an example [Bech32m][] string:
//!
//! ```text
//! hello1vehkc6mn27xpct
//! ```
//!
//! [Bech32][] and [Bech32m][] are specified in [BIP173][] and [BIP350][],
//! respectively.
//!
//! # Library Features
//!
//! - [Bech32 (BIP173)][bip173] and [Bech32m (BIP350)][bip350] support.
//! - Idiomatic encoding and decoding via the [`Display`][`std::fmt::Display`]
//!   and [`FromStr`][`std::str::FromStr`] traits.
//! - Decode arbitrarily long strings.
//! - Streamed, allocation-free [encoding][`Encoder`] to any [writer][].
//! - No external dependencies.
//!
//! # Examples
//!
//! Decode from string:
//!
//! ```
//! # fn main() -> Result<(), pbech32::Err> {
//! use pbech32::Bech32;
//!
//! let s = "a1qypqxpq9mqr2hj"; // bech32m-encoded string
//! let got: Bech32 = s.parse()?; // decode string
//!
//! assert_eq!(got.hrp.to_string(), "a"); // check human-readable part
//! assert_eq!(got.data, vec![1, 2, 3, 4, 5]); // check data
//! # Ok(())
//! # }
//! ```
//!
//! Encode to string:
//!
//! ```
//! # fn main() -> Result<(), pbech32::Err> {
//! use pbech32::{Bech32, Hrp, Scheme};
//!
//! let scheme = Scheme::Bech32m; // checksum scheme
//! let hrp: Hrp = "a".parse()?; // human-readable part
//! let data = vec![1, 2, 3, 4, 5]; // data
//! let got = Bech32 { scheme, hrp, data }.to_string(); // encode as string
//!
//! assert_eq!(got, "a1qypqxpq9mqr2hj"); // check result
//! # Ok(())
//! # }
//! ```
//!
//! Decoding a string verifies the [checksum][] to catch mistakes:
//!
//! ```
//! # fn main() -> Result<(), pbech32::Err> {
//! use pbech32::{Bech32, Err};
//!
//! let s = "a1wypqxpq9mqr2hj"; // string with error ("q" changed to "w")
//! let got = s.parse::<Bech32>(); // try to decode string
//!
//! assert_eq!(got, Err(Err::InvalidChecksum)); // check result
//! # Ok(())
//! # }
//! ```
//!
//! Encode to a [writer][]:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::io::Write;
//! use pbech32::{Encoder, Hrp, Scheme};
//!
//! let mut vec: Vec<u8> = Vec::new(); // output vector
//! let hrp: Hrp = "hello".parse()?; // human readable part
//!
//! let mut encoder = Encoder::new(&mut vec, Scheme::Bech32m, hrp)?; // create encoder
//! encoder.write_all(b"folks")?; // write data
//! encoder.flush()?; // flush encoder (REQUIRED)
//!
//! let got = str::from_utf8(vec.as_ref())?; // convert output vector to string
//! assert_eq!(got, "hello1vehkc6mn27xpct"); // check result
//! # Ok(())
//! # }
//! ```
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"
//! [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "Bech32m (BIP350)"
//! [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "BIP173 (Bech32)"
//! [bip350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "BIP350 (Bech32m)"
//! [ascii]: https://en.wikipedia.org/wiki/ASCII
//!   "ASCII (Wikipedia)"
//! [base 32]: https://en.wikipedia.org/wiki/Base32
//!   "Base 32 (Wikipedia)"
//! [checksum]: https://en.wikipedia.org/wiki/Checksum
//!   "Checksum (Wikipedia)"
//! [namespace]: https://en.wikipedia.org/wiki/Namespace
//!   "Namespace (Wikipedia)"
//! [bch code]: https://en.wikipedia.org/wiki/BCH_code
//!   "BCH code (Wikipedia)"
//! [alphabet]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32
//!   "BIP173: Specification: Bech32"
//! [writer]: `std::io::Write`
//!   "writer"
//! [age encryption]: https://age-encryption.org/
//!   "age encryption"

#![deny(missing_docs)]
#![deny(unsafe_code)]

// ref: https://learnmeabitcoin.com/technical/keys/bech32/
//
// TODO:
// [x] encode/decode data into 5-bit form
// [x] auto-detect scheme
// [x] docs
// [x] document longer string in header docs
// [x] proper hrp char validation (33..127)
// [-] proper data char validation (is_ascii_alphanumeri())
//     n/a, caught by chars::decode()
// [-] test for short data part
//     n/a, but will report MissingSeparator
// [x] use encode/decode wording everywhere
// [x] intro paragraph explaining bech32 and library
// [x] rename to pbech32
// [x] bug: scheme: bech32m, hrp: "hi", data: "folks"
// [x] increase/remove MAX_LEN (4k?)
// [x] streaming/no-alloc api
// [-] impl Drop for Encoder
//     n/a: causes mutable borrow errors in tests
// [-] use AsRef<str> for make() hrp param?
//     n/a: utility method
// [x] add LICENSE.txt
// [ ] add README.md
// [ ] crate docs: document error context fields
// [ ] find possible error positions in string
//     ref: https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp#L458
// [ ] dup tests from age impl:
//     https://github.com/FiloSottile/age/blob/main/internal/bech32/bech32.go

/// String parse error.
///
/// # Examples
///
/// Try to parse an empty string:
///
/// ```
/// # fn main() {
/// use pbech32::{Bech32, Err};
/// let s = ""; // empty string
/// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidLen(0)));
/// # }
/// ```
///
/// Try to parse a string with an invalid character:
///
/// ```
/// # fn main() {
/// use pbech32::{Bech32, Err};
/// let s = "a 1xxxxxx"; // string with invalid bech32 character
/// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidChar(1)));
/// # }
/// ```
///
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Err {
  /// Invalid string length.
  ///
  /// The length of a [Bech32][] string must be in the range `8..`.
  ///
  /// The error field contains the invalid length.
  ///
  /// **Note:** [BIP173][] limits the maximum string length to 90
  /// characters; this library does not have a maximum string length.
  ///
  /// # Example
  ///
  /// Try to parse an empty string:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = ""; // empty string
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidLen(0)));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  /// [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  InvalidLen(usize),

  /// String contains an invalid character at the given position.
  ///
  /// A [Bech32][] string must only contain alphanumeric [ASCII][]
  /// characters.
  ///
  /// The error field indicates the first invalid character position in
  /// the string.
  ///
  /// # Example
  ///
  /// Try to parse a string with an invalid character at position 1:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "a 1xxxxxx"; // string with invalid bech32 character
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidChar(1)));
  /// # }
  /// ```
  ///
  /// [ascii]: https://en.wikipedia.org/wiki/ASCII
  ///   "ASCII (Wikipedia)"
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  InvalidChar(usize),

  /// String contains both uppercase and lowercase characters.
  ///
  /// A [Bech32][] string must not contain both uppercase and lowercase
  /// characters.
  ///
  /// The error fields indicate the first lowercase character position
  /// and in the string the first uppercase character position in the
  /// string, respectively.
  ///
  /// # Example
  ///
  /// Try to parse a string with an lowercase character at position 0
  /// and an uppercase character at position 1:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "Ab1xxxxxx"; // string with mixed-case characters
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::MixedCase(1, 0)));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  MixedCase(usize, usize),

  /// String is missing a separator character.
  ///
  /// A [Bech32][] string must contain a `1` character between the
  /// the human-readable part and the data part.
  ///
  /// # Example
  ///
  /// Try to parse a string which does not have a separator between the
  /// human-readable part and the data part:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "avxxxxxx"; // string without separator
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::MissingSeparator));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  MissingSeparator,

  /// Length of Human-readable part (HRP) of string is invalid.
  ///
  /// The length of the human-readable part of a [Bech32][] string must
  /// be in the range `[1..84]`.
  ///
  /// The error field contains the invalid human-readable part length.
  ///
  /// # Examples
  ///
  /// Try to parse a string with an empty human-readable part:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "1axxxxxx"; // string with empty HRP
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidHrpLen(0)));
  /// # }
  /// ```
  ///
  /// Try to parse a string with a human-readable part that is too long:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = str::repeat("a", 84) + "1xxxxxx"; // string with long HRP
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidHrpLen(84)));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  InvalidHrpLen(usize),

  /// Invalid checksum.
  ///
  /// # Example
  ///
  /// Try to parse a string with an invalid checksum:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "a1xxxxxx"; // string with invalid checksum
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidChecksum));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  InvalidChecksum,
}

impl std::fmt::Display for Err {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    match self {
      Err::InvalidLen(len) => write!(f, "invalid length: {len}"),
      Err::InvalidChar(pos) => write!(f, "invalid character at position {pos}"),
      Err::MixedCase(l, h) => write!(f, "mixed-case characters at positions ({l}, {h})"),
      Err::MissingSeparator => write!(f, "missing separator"),
      Err::InvalidHrpLen(len) => write!(f, "invalid human-readable part length: {len}"),
      Err::InvalidChecksum => write!(f, "invalid checksum"),
    }
  }
}

impl std::error::Error for Err {}

/// [Bech32][] variant.
///
/// [Bech32m][bip350] is identical to [Bech32][bip173] except that it
/// uses a different mask in the final step of the checksum calculation.
///
/// # Examples
///
/// Parse [Bech32][bip173] string:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{Bech32, Scheme};
/// let s = "a1qypqxpq9wunxjs"; // bech32 string (BIP173 checksum)
/// let b: Bech32 = s.parse()?; // parse string
/// assert_eq!(b.scheme, Scheme::Bech32); // check scheme
/// # Ok(())
/// # }
/// ```
///
/// Parse [Bech32m][bip350] string:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{Bech32, Scheme};
/// let s = "a1qypqxpq9mqr2hj"; // bech32m string (BIP350 checksum)
/// let b: Bech32 = s.parse()?; // parse string
/// assert_eq!(b.scheme, Scheme::Bech32m); // check scheme
/// # Ok(())
/// # }
/// ```
///
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
/// [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
/// [bip350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
///   "Bech32m (BIP350)"
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
  /// [Bech32][bip173] variant, as specified in [BIP173][].
  ///
  /// # Example
  ///
  /// Parse [Bech32][bip173] string:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{Bech32, Scheme};
  /// let s = "a1qypqxpq9wunxjs"; // bech32 string (BIP173 checksum)
  /// let b: Bech32 = s.parse()?; // parse string
  /// assert_eq!(b.scheme, Scheme::Bech32); // check scheme
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  Bech32,

  /// [Bech32m][bip350] variant, as specified in [BIP350][].
  ///
  /// # Example
  ///
  /// Parse [Bech32m][bip350] string:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{Bech32, Scheme};
  /// let s = "a1qypqxpq9mqr2hj"; // bech32m string (BIP350 checksum)
  /// let b: Bech32 = s.parse()?; // parse string
  /// assert_eq!(b.scheme, Scheme::Bech32m); // check scheme
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [bip350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  ///   "Bech32m (BIP350)"
  Bech32m,
}

impl Scheme {
  /// Get scheme checksum mask.
  fn checksum_mask(&self) -> u32 {
    match self {
      Scheme::Bech32 => 1,
      Scheme::Bech32m => 0x2bc830a3,
    }
  }
}

/// Character encoding functions.
mod chars {
  /// Encoding lookup table (LUT).
  ///
  /// Used to map 5-bit [`u8`] to character.
  pub(crate) const LUT: [char; 32] = [
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0',
    's', '3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
  ];

  /// Decode character as 5-bit [`u8`] or return [`None`] if the
  /// character is not a valid Bech32 character.
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  pub(crate) fn decode(c: char) -> Option<u8> {
    match c {
      'q' => Some(0),
      'p' => Some(1),
      'z' => Some(2),
      'r' => Some(3),
      'y' => Some(4),
      '9' => Some(5),
      'x' => Some(6),
      '8' => Some(7),
      'g' => Some(8),
      'f' => Some(9),
      '2' => Some(10),
      't' => Some(11),
      'v' => Some(12),
      'd' => Some(13),
      'w' => Some(14),
      '0' => Some(15),
      's' => Some(16),
      '3' => Some(17),
      'j' => Some(18),
      'n' => Some(19),
      '5' => Some(20),
      '4' => Some(21),
      'k' => Some(22),
      'h' => Some(23),
      'c' => Some(24),
      'e' => Some(25),
      '6' => Some(26),
      'm' => Some(27),
      'u' => Some(28),
      'a' => Some(29),
      '7' => Some(30),
      'l' => Some(31),
      _ => None,
    }
  }
}

/// 5-bit/8-bit data conversion functions.
///
/// # Examples
///
/// Encode 8-bit bytes as vector of 5-bit bytes:
///
/// ```
/// # fn main() {
/// let exp = vec![0, 4, 1, 0, 6, 1, 0, 5]; // expected 5-bit result
/// let got = pbech32::bits::convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode 8-bit data
/// assert_eq!(got, exp); // check 5-bit result
/// # }
/// ```
///
/// Decode 5-bit bytes as vector of 8-bit bytes:
///
/// ```
/// # fn main() {
/// let exp = vec![1, 2, 3, 4, 5]; // expected 8-bit result
/// let got = pbech32::bits::convert::<5, 8>(&[0, 4, 1, 0, 6, 1, 0, 5]); // decode 5-bit data
/// assert_eq!(got, exp); // check 8-bit result
/// # }
/// ```
pub mod bits {
  /// Get output capacity (in bytes) needed for bit conversion.
  ///
  /// # Parameters
  ///
  /// - `len`: Input length, in bytes.
  ///
  /// # Generic Parameters
  ///
  /// - `SRC_BITS`: Input bit size (one of `5` or `8`).
  /// - `DST_BITS`: Output bit size (one of `5` or `8`).
  ///
  /// # Returns
  ///
  /// Needed output capacity, in bytes.
  pub(crate) fn capacity<
    const SRC_BITS: usize, // input bit size (5 or 8)
    const DST_BITS: usize, // output bit size (5 or 8)
  >(len: usize) -> usize {
    SRC_BITS * len / DST_BITS + ((len % DST_BITS) != 0) as usize
  }

  /// Convert a slice of five 8-bit bytes into an array of eight 5-bit
  /// bytes.
  ///
  /// Used by [`Encoder::flush_buf()`].
  pub(crate) fn convert_block(b: &[u8]) -> [u8; 8] {
    [
      b[0] >> 3,
      ((b[0] & 7) << 2) | (b[1] >> 6),
      (b[1] >> 1) & 0x1f,
      ((b[1] & 1) << 4) | (b[2] >> 4),
      ((b[2] & 0xf) << 1) | (b[3] >> 7),
      (b[3] >> 2) & 0x1f,
      ((b[3] & 3) << 3) | (b[4] >> 5),
      b[4] & 0x1f,
    ]
  }

  /// Convert between 5-bit and 8-bit data.
  ///
  /// # Generic Parameters
  ///
  /// - `SRC_BITS`: Input bit size (one of `5` or `8`).
  /// - `DST_BITS`: Output bit size (one of `5` or `8`).
  ///
  /// # Examples
  ///
  /// Encode 8-bit data as vector of 5-bit bytes:
  ///
  /// ```
  /// # fn main() {
  /// let exp = vec![0, 4, 1, 0, 6, 1, 0, 5]; // expected 5-bit result
  /// let got = pbech32::bits::convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode 8-bit data
  /// assert_eq!(got, exp); // check 5-bit result
  /// # }
  /// ```
  ///
  /// Decode 5-bit data as vector of 8-bit bytes:
  ///
  /// ```
  /// # fn main() {
  /// let exp = vec![1, 2, 3, 4, 5]; // expected 8-bit result
  /// let got = pbech32::bits::convert::<5, 8>(&[0, 4, 1, 0, 6, 1, 0, 5]); // decode 5-bit data
  /// assert_eq!(got, exp); // check 8-bit result
  /// # }
  /// ```
  pub fn convert<
    const SRC_BITS: usize, // input bit size (5 or 8)
    const DST_BITS: usize, // output bit size (5 or 8)
  >(bytes: &[u8]) -> Vec<u8> {
    let mask: u32 = (1 << (DST_BITS as u32)) - 1; // write mask
    let mut r = Vec::with_capacity(capacity::<SRC_BITS, DST_BITS>(bytes.len()));
    let mut acc: u32 = 0; // accumulator
    let mut acc_len = 0; // accumulator bit count

    for b in bytes {
      acc = (acc << SRC_BITS) | (*b as u32); // accumulate
      acc_len += SRC_BITS; // increase bit count
      while acc_len >= DST_BITS {
        acc_len -= DST_BITS; // reduce bit count
        r.push(((acc >> acc_len) & mask) as u8); // write top bits
        acc &= (1 << acc_len) - 1; // remove top bits
      }
    }

    // flush bits
    if acc_len > 0 {
      acc <<= DST_BITS - acc_len; // pad with zeros
      r.push((acc & mask) as u8); // write remaining bits
    }

    r
  }
}

/// [BCH][] checksum functions.
///
/// **Note:** The data should be 5-bit encoded.  In other words, only
/// the lower 5 bits of each byte contain data.
///
/// # Examples
///
/// Create [Bech32][] checksum:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{bits, checksum, Hrp, Scheme};
///
/// let exp = b"wunxjs"; // expected checksum
/// let hrp: Hrp = "a".parse()?; // parse HRP
/// let data = bits::convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
/// let got = checksum::make(Scheme::Bech32, &hrp, data); // make checksum
/// assert_eq!(&got, exp); // verify checksum
/// # Ok(())
/// # }
/// ```
///
/// Create [Bech32m][] checksum:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{bits, checksum, Hrp, Scheme};
///
/// let exp = b"mqr2hj"; // expected checksum
/// let hrp: Hrp = "a".parse()?; // parse HRP
/// let data = bits::convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
/// let got = checksum::make(Scheme::Bech32m, &hrp, data); // make checksum
/// assert_eq!(&got, exp); // verify checksum
/// # Ok(())
/// # }
/// ```
///
/// [bch]: https://en.wikipedia.org/wiki/BCH_code
///   "BCH code (Wikipedia)"
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
/// [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
///   "Bech32m (BIP350)"
pub mod checksum {
  use super::{chars, Hrp, Scheme};

  /// Generator polynomials.
  ///
  /// Used by [`polymod()`].
  const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  /// Encode checksum as 6-byte array.
  ///
  /// Called by [`make()`].
  pub(crate) fn encode(sum: u32) -> [u8; 6] {
    core::array::from_fn(|i| {
      chars::LUT[((sum as usize) >> (5 * (5 - i))) & 0x1f] as u8
    })
  }

  /// Update checksum `sum` with 5-bit value `val`.
  ///
  /// **Note:** Only absorbs the bottom 5 bits of value.
  pub(crate) fn polymod(mut sum: u32, val: u8) -> u32 {
    // assert_eq!(val & !0x1f, 0); // check upper bits
    let t = sum >> 25; // get bits 25..30
    sum = ((sum & 0x1ffffff) << 5) | ((val & 0x1f) as u32); // absorb bits
    (0..5).map(|i| GEN[i] & !((t >> i) & 1).wrapping_sub(1)).fold(sum, |r, v| r ^ v)
  }

  /// Create checksum for given scheme, human-readable part, and data.
  ///
  /// **Note:** `data` should be 5-bit encoded.  In other words, only
  /// the lower 5 bits of each byte contain data.
  ///
  /// # Examples
  ///
  /// Create [Bech32][] checksum:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{bits, checksum, Scheme};
  ///
  /// let exp = b"wunxjs"; // expected checksum
  /// let hrp = "a".parse()?; // parse hrp
  /// let data = bits::convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
  /// let got = checksum::make(Scheme::Bech32, &hrp, data); // make checksum
  /// assert_eq!(&got, exp); // verify checksum
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Create [Bech32m][] checksum:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{bits, checksum, Scheme};
  ///
  /// let exp = b"mqr2hj"; // expected checksum
  /// let hrp = "a".parse()?; // parse hrp
  /// let data = bits::convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
  /// let got = checksum::make(Scheme::Bech32m, &hrp, data); // make checksum
  /// assert_eq!(&got, exp); // verify checksum
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  /// [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  ///   "Bech32m (BIP350)"
  pub fn make<T: AsRef<[u8]>>(scheme: Scheme, hrp: &Hrp, data: T) -> [u8; 6] {
    let mut sum: u32 = 1;

    sum = hrp.0.bytes().fold(sum, |r, b| polymod(r, b >> 5)); // absorb hrp high bits
    sum = polymod(sum, 0); // absorb 0
    sum = hrp.0.bytes().fold(sum, |r, b| polymod(r, b & 0x1f)); // absorb hrp low bits
    sum = data.as_ref().iter().fold(sum, |r, b| polymod(r, *b)); // absorb data
    sum = (0..6).fold(sum, |r, _| polymod(r, 0)); // absorb 6 zeros

    encode(sum ^ scheme.checksum_mask()) // mask, encode as [u8; 6]
  }
}

/// String constraints.
///
/// Checks for the following:
///
/// - invalid string length
/// - invalid characters
/// - mixed-case characters
///
/// Used by [`RawBech32::new()`] and [`Hrp::from_str()`] to check string
/// validity.
struct Constraints {
  /// Valid length range (low, high).
  ///
  /// **Note:** upper bound is optiona.
  range: (usize, Option<usize>),

  /// Error to return when length is out of range.
  error: Err,
}

impl Constraints {
  /// Check string against constraints.
  ///
  /// Checks for the following:
  ///
  /// - invalid string length
  /// - invalid characters
  /// - mixed-case characters
  ///
  /// Used by [`RawBech32::new()`] and [`Hrp::from_str()`] to check string
  /// validity.
  fn check(&self, s: &str) -> Result<(), Err> {
    let valid_length = match self.range.1 {
      Some(max) => (self.range.0..max).contains(&s.len()),
      None => (self.range.0..).contains(&s.len()),
    };

    // check string length
    if !valid_length {
      // invalid length; populate length field of error and return it
      return Err(match self.error {
        Err::InvalidLen(_) => Err::InvalidLen(s.len()),
        Err::InvalidHrpLen(_) => Err::InvalidHrpLen(s.len()),
        _ => unreachable!(),
      })
    }

    // check for invalid chars (e.g. c != 33..127)
    if let Some((pos, _)) = s.chars().enumerate().find(|(_, c)| !c.is_ascii_graphic()) {
      return Err(Err::InvalidChar(pos));
    }

    // check for mixed case
    let lower = s.chars().enumerate().find(|(_, c)| c.is_ascii_lowercase());
    let upper = s.chars().enumerate().find(|(_, c)| c.is_ascii_uppercase());
    if let Some((lower_pos, _)) = lower && let Some((upper_pos, _)) = upper {
      return Err(Err::MixedCase(lower_pos, upper_pos));
    }

    Ok(())
  }
}

/// Human-readable part (HRP) of [Bech32][] structure.
///
/// A valid HRP string must meet all following conditions:
///
/// - String length must be in the range `1..84`.
/// - Must only contain [ASCII][] characters in the range `33..127`.
/// - Must not contain a mixture of uppercase and lowercase alphabetic
///   characters.
///
/// **Note:** Stored as lowercase.
///
/// # Examples
///
/// Parse string as [`Hrp`]:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::Hrp;
///
/// let s = "testhrp"; // hrp string
/// let hrp: Hrp = s.parse()?; // parse string
/// # Ok(())
/// # }
/// ```
///
/// Convert [`Hrp`] to a string:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::Hrp;
///
/// let s = "foobar"; // hrp string
/// let hrp: Hrp = s.parse()?; // parse string
/// assert_eq!(hrp.to_string(), "foobar"); // check result
/// # Ok(())
/// # }
/// ```
///
/// Convert [`Hrp`] to a [`&str`] with [`Hrp::as_ref()`]:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::Hrp;
///
/// let s = "foobar"; // hrp string
/// let hrp: Hrp = s.parse()?; // parse string
/// assert_eq!(hrp.as_ref(), "foobar"); // check result
/// # Ok(())
/// # }
/// ```
///
/// Strings which contain all uppercase characters are converted to
/// lowercase when parsed as an [`Hrp`]:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::Hrp;
///
/// let hrp: Hrp = "TESTHRP".parse()?; // parse hrp string
/// assert_eq!(hrp.to_string(), "testhrp"); // check result
/// # Ok(())
/// # }
/// ```
///
/// Parsing will fail if the given string is not a valid human-readable
/// part. For example, here is a mixed-case string:
///
/// ```
/// # fn main() {
/// use pbech32::{Err, Hrp};
///
/// let s = "FOObar"; // mixed-case string
/// let got = s.parse::<Hrp>(); // parse string
/// assert_eq!(got, Err(Err::MixedCase(3, 0))); // check result
/// # }
/// ```
///
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
/// [ascii]: https://en.wikipedia.org/wiki/ASCII
///   "ASCII (Wikipedia)"
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hrp(pub String);

impl Hrp {
  /// hrp string constraints
  const CONSTRAINTS: Constraints = Constraints {
    range: (1, Some(84)), // max 83 from BIP173
    error: Err::InvalidHrpLen(0),
  };
}

impl std::str::FromStr for Hrp {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    // check constraints, normalize case
    Self::CONSTRAINTS.check(s)?;
    let s: String = s.chars().map(|c| c.to_ascii_lowercase()).collect();

    Ok(Self(s))
  }
}

impl AsRef<str> for Hrp {
  fn as_ref(&self) -> &str {
    &self.0
  }
}

impl std::fmt::Display for Hrp {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// Parsed [Bech32][] structure with raw 5-bit `data` field.
///
/// Use [`Bech32`] instead to automatically encode and decode / 8-bit
/// data.
///
/// # Examples
///
/// Decode [Bech32m][] string as [`RawBech32`]:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{RawBech32, Scheme};
///
/// let s = "a1qypqxpq9mqr2hj"; // bech32m string
/// let got: RawBech32 = s.parse()?; // parse string
///
/// assert_eq!(got.scheme, Scheme::Bech32m); // check scheme
/// assert_eq!(got.hrp.to_string(), "a"); // check hrp
/// assert_eq!(got.data, vec![0, 4, 1, 0, 6, 1, 0, 5]); // check data
/// # Ok(())
/// # }
/// ```
///
/// Encode [`RawBech32`] as string:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{bits::convert, RawBech32, Scheme};
///
/// let exp = "a1qypqxpq9mqr2hj"; // expected result
///
/// // encode 8-bit bytes as vector of 5-bit bytes
/// let data = convert::<8, 5>(&[1, 2, 3, 4, 5]);
///
/// // populate structure
/// let b = RawBech32 {
///   scheme: Scheme::Bech32m, // checksum scheme
///   hrp: "a".parse()?, // human-readable part
///   data: data, // 5-bit data
/// };
///
/// let got = b.to_string(); // convert to string
/// assert_eq!(got, exp); // check result
/// # Ok(())
/// # }
/// ```
///
/// Use [`RawBech32::new()`] to parse a specific scheme:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{RawBech32, Scheme};
///
/// // expected result
/// let exp = RawBech32 {
///   scheme: Scheme::Bech32m, // checksum scheme
///   hrp: "a".parse()?, // human-readable part
///   data: vec![0, 4, 1, 0, 6, 1, 0, 5], // 5-bit data
/// };
///
/// let s = "a1qypqxpq9mqr2hj"; // bech32m string
/// let got = RawBech32::new(s, Some(Scheme::Bech32m))?; // parse string
/// assert_eq!(got, exp); // check result
/// # Ok(())
/// # }
/// ```
///
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
/// [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
///   "Bech32m (BIP350)"
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawBech32 {
  /// Scheme
  ///
  /// Affects checksum encoding.
  pub scheme: Scheme,

  /// Human-readable part.
  ///
  /// Human-readable prefix containing [ASCII][] characters in the range
  /// `33..127`.
  ///
  /// [ascii]: https://en.wikipedia.org/wiki/ASCII
  ///   "ASCII (Wikipedia)"
  pub hrp: Hrp,

  /// Raw 5-bit data
  ///
  /// **Note:** Use [`bits::convert()`] to decode the 5-bit data
  /// in this field.
  pub data: Vec<u8>,
}

impl RawBech32 {
  /// bech32 string constraints
  const CONSTRAINTS: Constraints = Constraints {
    range: (8, None), // NOTE: BIP173 max is 91.
    error: Err::InvalidLen(0),
  };

  /// Parse string as [`RawBech32`][] with given scheme.
  ///
  /// The difference between this function and [`str::parse()`] is that
  /// this function allows you to limit parsing to a particular scheme.
  ///
  /// Setting the `scheme` parameter to [`None`] enables scheme
  /// auto-detection and is equivalent to calling [`str::parse()`].
  ///
  /// # Example
  ///
  /// Decode string using [`Scheme::Bech32m`]:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{RawBech32, Scheme};
  ///
  /// // expected result
  /// let exp = RawBech32 {
  ///   scheme: Scheme::Bech32m, // checksum scheme
  ///   hrp: "a".parse()?, // human-readable part
  ///   data: vec![0, 4, 1, 0, 6, 1, 0, 5], // 5-bit data
  /// };
  ///
  /// let s = "a1qypqxpq9mqr2hj"; // bech32m string
  /// let got = RawBech32::new(s, Some(Scheme::Bech32m))?; // parse string
  /// assert_eq!(got, exp); // check result
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Decode string using [`Scheme::Bech32`]:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{RawBech32, Scheme};
  ///
  /// // expected result
  /// let exp = RawBech32 {
  ///   scheme: Scheme::Bech32, // checksum scheme
  ///   hrp: "a".parse()?, // human-readable part
  ///   data: vec![0, 4, 1, 0, 6, 1, 0, 5], // 5-bit data
  /// };
  ///
  /// let s = "a1qypqxpq9wunxjs"; // bech32m string
  /// let got = RawBech32::new(s, Some(Scheme::Bech32))?; // parse string
  /// assert_eq!(got, exp); // check result
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Decode string as [`RawBech32`] and auto-detect scheme (equivalent
  /// to calling [`str::parse()`]):
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{RawBech32, Scheme};
  ///
  /// // expected result
  /// let exp = RawBech32 {
  ///   scheme: Scheme::Bech32m, // checksum scheme
  ///   hrp: "a".parse()?, // human-readable part
  ///   data: vec![0, 4, 1, 0, 6, 1, 0, 5], // 5-bit data
  /// };
  ///
  /// let s = "a1qypqxpq9mqr2hj"; // bech32m string
  /// let got = RawBech32::new(s, None)?; // parse string
  /// assert_eq!(got, exp); // check result
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  /// [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  ///   "Bech32m (BIP350)"
  pub fn new(s: &str, scheme: Option<Scheme>) -> Result<Self, Err> {
    // check constraints, normalize case
    Self::CONSTRAINTS.check(s)?;
    let s: String = s.chars().map(|c| c.to_ascii_lowercase()).collect();

    // split into (hrp, data, checksum)
    let cs_pos = s.len() - 6; // checksum start
    let (hrp, enc) = s[..cs_pos].rsplit_once('1').ok_or(Err::MissingSeparator)?;
    let cs_exp = &s.as_bytes()[cs_pos..]; // expected checksum

    // parse hrp
    let hrp: Hrp = hrp.parse()?;

    // decode data
    let mut data: Vec<u8> = Vec::with_capacity(enc.len());
    for (pos, c) in enc.chars().enumerate() {
      data.push(chars::decode(c).ok_or(Err::InvalidChar(pos))?);
    }

    // get ordered list of checksum schemes
    let schemes = match scheme {
      Some(scheme) => vec![scheme],
      None => vec![Scheme::Bech32m, Scheme::Bech32],
    };

    for scheme in schemes {
      // checksum hrp and data, then verify against expected checksum
      if checksum::make(scheme, &hrp, &data) == cs_exp {
        // checksum matches, return success
        return Ok(Self { scheme, data, hrp });
      }
    }

    // checksum does not match, return error
    Err(Err::InvalidChecksum)
  }
}

impl std::str::FromStr for RawBech32 {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::new(s, None)
  }
}

impl std::fmt::Display for RawBech32 {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    // write hrp
    write!(f, "{}1", self.hrp)?;

    // encode/write data
    for b in &self.data {
      write!(f, "{}", chars::LUT[*b as usize])?;
    }

    // write checksum
    // note: unwrap() is safe here because output of make() is always
    // valid UTF-8
    let s = checksum::make(self.scheme, &self.hrp, &self.data);
    write!(f, "{}", str::from_utf8(&s).unwrap())?;

    Ok(())
  }
}

/// Parsed [Bech32][] structure.
///
/// Use [`RawBech32`] and [`bits::convert()`] instead to handle
/// data encoding and decoding manually.
///
/// # Examples
///
/// Decode string as [`Bech32`]:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{Bech32, Scheme};
///
/// let s = "a1qypqxpq9mqr2hj"; // bech32m string
/// let got: Bech32 = s.parse()?; // parse string
///
/// assert_eq!(got.scheme, Scheme::Bech32m); // check scheme
/// assert_eq!(got.hrp.to_string(), "a"); // check hrp
/// assert_eq!(got.data, vec![1, 2, 3, 4, 5]); // check data
/// # Ok(())
/// # }
/// ```
///
/// Encode [`Bech32`] as string:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{Bech32, Scheme};
///
/// let exp = "a1qypqxpq9mqr2hj"; // expected result
///
/// // populate structure
/// let b = Bech32 {
///   scheme: Scheme::Bech32m, // checksum scheme
///   hrp: "a".parse()?, // human-readable part
///   data: vec![1, 2, 3, 4, 5], // 8-bit data
/// };
///
/// let got = b.to_string(); // convert to string
/// assert_eq!(got, exp); // check result
/// # Ok(())
/// # }
/// ```
///
/// Use [`Bech32::new()`] to parse a specific scheme:
///
/// ```
/// # fn main() -> Result<(), pbech32::Err> {
/// use pbech32::{Bech32, Scheme};
///
/// // expected result
/// let exp = Bech32 {
///   scheme: Scheme::Bech32m, // checksum scheme
///   hrp: "a".parse()?, // human-readable part
///   data: vec![1, 2, 3, 4, 5], // 8-bit data
/// };
///
/// let s = "a1qypqxpq9mqr2hj"; // bech32m string
/// let got = Bech32::new(s, Some(Scheme::Bech32m))?; // parse string
/// assert_eq!(got, exp); // check result
/// # Ok(())
/// # }
/// ```
///
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
/// [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
///   "Bech32m (BIP350)"
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bech32 {
  /// Scheme
  ///
  /// Affects checksum encoding.
  pub scheme: Scheme,

  /// Human-readable part
  ///
  /// Human-readable prefix containing [ASCII][] characters in the range
  /// `33..127`.
  ///
  /// [ascii]: https://en.wikipedia.org/wiki/ASCII
  ///   "ASCII (Wikipedia)"
  pub hrp: Hrp,

  /// 8-bit data
  pub data: Vec<u8>,
}

impl Bech32 {
  /// Parse string as [`Bech32`] with given scheme.
  ///
  /// The difference between this function and [`str::parse()`] is that
  /// this function allows you to limit parsing to a particular scheme.
  ///
  /// Setting the `scheme` parameter to [`None`] enables scheme
  /// auto-detection and is equivalent to calling [`str::parse()`].
  ///
  /// # Example
  ///
  /// Decode string using [`Scheme::Bech32m`]:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{Bech32, Scheme};
  ///
  /// // expected result
  /// let exp = Bech32 {
  ///   scheme: Scheme::Bech32m, // checksum scheme
  ///   hrp: "a".parse()?, // human-readable part
  ///   data: vec![1, 2, 3, 4, 5], // 8-bit data
  /// };
  ///
  /// let s = "a1qypqxpq9mqr2hj"; // bech32m string
  /// let got = Bech32::new(s, Some(Scheme::Bech32m))?; // parse string
  /// assert_eq!(got, exp); // check result
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Decode string using [`Scheme::Bech32`]:
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{Bech32, Scheme};
  ///
  /// // expected result
  /// let exp = Bech32 {
  ///   scheme: Scheme::Bech32, // checksum scheme
  ///   hrp: "a".parse()?, // human-readable part
  ///   data: vec![1, 2, 3, 4, 5], // 8-bit data
  /// };
  ///
  /// let s = "a1qypqxpq9wunxjs"; // bech32m string
  /// let got = Bech32::new(s, Some(Scheme::Bech32))?; // parse string
  /// assert_eq!(got, exp); // check result
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Decode string and auto-detect scheme (equivalent to calling
  /// [`str::parse()`]):
  ///
  /// ```
  /// # fn main() -> Result<(), pbech32::Err> {
  /// use pbech32::{Bech32, Scheme};
  ///
  /// // expected result
  /// let exp = Bech32 {
  ///   scheme: Scheme::Bech32m, // checksum scheme
  ///   hrp: "a".parse()?, // human-readable part
  ///   data: vec![1, 2, 3, 4, 5], // 8-bit data
  /// };
  ///
  /// let s = "a1qypqxpq9mqr2hj"; // bech32m string
  /// let got = Bech32::new(s, None)?; // parse string
  /// assert_eq!(got, exp); // check result
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  /// [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  ///   "Bech32m (BIP350)"
  pub fn new(s: &str, scheme: Option<Scheme>) -> Result<Self, Err> {
    let r = RawBech32::new(s, scheme)?;
    let data = bits::convert::<5, 8>(r.data.as_ref());
    Ok(Self { data, scheme: r.scheme, hrp: r.hrp })
  }
}

impl std::str::FromStr for Bech32 {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::new(s, None)
  }
}

impl std::fmt::Display for Bech32 {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    // write hrp
    write!(f, "{}1", self.hrp)?;

    // convert data from 8-bit to 5-bit.
    let data = bits::convert::<8, 5>(self.data.as_ref());

    // encode/write data
    for b in &data {
      write!(f, "{}", chars::LUT[*b as usize])?;
    }

    // write checksum
    // note: unwrap() is safe here beca
    let s = checksum::make(self.scheme, &self.hrp, &data);
    write!(f, "{}", str::from_utf8(&s).unwrap())?;

    Ok(())
  }
}

/// Stream [Bech32][]-encoded data to a [writer][] without allocation.
///
/// Writing to an [`Encoder`] can be done iteratively.
///
/// The destination [writer][] can be anything that implements
/// [`Write`][writer].  Examples: [`Vec<u8>`], [`File`][`std::fs::File`],
/// [`TcpStream`][`std::net::TcpStream`], etc.
///
/// **Note:** You *must* `flush()` the encoder when you have finished
/// writing data or the output will be incomplete.
///
/// # Examples
///
/// Encode to a [`Vec<u8>`]:
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::Write;
/// use pbech32::{Encoder, Hrp, Scheme};
///
/// let mut vec: Vec<u8> = Vec::new(); // output vector
/// let hrp: Hrp = "hello".parse()?; // human readable part
///
/// let mut encoder = Encoder::new(&mut vec, Scheme::Bech32m, hrp)?; // create encoder
/// encoder.write_all(b"folks")?; // write data
/// encoder.flush()?; // flush encoder (REQUIRED)
///
/// let got = str::from_utf8(vec.as_ref())?; // convert output vector to string
/// assert_eq!(got, "hello1vehkc6mn27xpct"); // check result
/// # Ok(())
/// # }
/// ```
///
/// Iteratively encode to a [`Vec<u8>`]:
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::Write;
/// use pbech32::{Encoder, Hrp, Scheme};
///
/// let mut vec: Vec<u8> = Vec::new(); // output vector
/// let hrp: Hrp = "hi".parse()?; // human readable part
///
/// let mut encoder = Encoder::new(&mut vec, Scheme::Bech32m, hrp)?; // create encoder
/// for chunk in vec![b"foo", b"bar", b"baz"] {
///   encoder.write_all(chunk)?; // write chunk
/// }
/// encoder.flush()?; // flush encoder (REQUIRED)
///
/// let got = str::from_utf8(vec.as_ref())?; // convert output vector to string
/// assert_eq!(got, "hi1vehk7cnpwf3xz7skgej7x"); // check result
/// # Ok(())
/// # }
/// ```
///
/// See `examples/stream.rs` for an example of streaming to standard
/// output.
///
/// [writer]: `std::io::Write`
///   "writer"
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
pub struct Encoder<W: std::io::Write> {
  scheme: Scheme, // checksum scheme
  sum: u32, // checksum
  buf: Vec<u8>, // fixed-size internal buffer (5 bytes)
  done: bool, // is encoder done?
  inner: W, // inner writer
}

impl<W: std::io::Write> Encoder<W> {
  /// Create streaming encoder.
  ///
  /// # Parameters
  ///
  /// - `inner`: Wrapped [writer][`std::io::Write`]
  /// - `scheme`: Checksum scheme
  /// - `hrp`: Human-readable part
  ///
  /// # Example
  ///
  /// Encode to a [`Vec<u8>`]:
  ///
  /// ```
  /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
  /// use std::io::Write;
  /// use pbech32::{Encoder, Hrp, Scheme};
  ///
  /// let mut vec: Vec<u8> = Vec::new(); // output vector
  /// let hrp: Hrp = "hello".parse()?; // human readable part
  ///
  /// let mut encoder = Encoder::new(&mut vec, Scheme::Bech32m, hrp)?; // create encoder
  /// encoder.write_all(b"folks")?; // write data
  /// encoder.flush()?; // flush encoder (REQUIRED)
  ///
  /// let got = str::from_utf8(vec.as_ref())?; // convert output vector to string
  /// assert_eq!(got, "hello1vehkc6mn27xpct"); // check result
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// See `examples/stream.rs` for an example of streaming to standard
  /// output.
  pub fn new(mut inner: W, scheme: Scheme, hrp: Hrp) -> std::io::Result<Self> {
    // init checksum and absorb hrp
    let mut sum = hrp.0.bytes().fold(1, |r, b| checksum::polymod(r, b >> 5)); // high bits
    sum = checksum::polymod(sum, 0); // delimiter (one zero)
    sum = hrp.0.bytes().fold(sum, |r, b| checksum::polymod(r, b & 0x1f)); // low bits

    write!(inner, "{hrp}1")?; // write hrp and separator to inner writer
    Ok(Self { inner, scheme, sum, done: false, buf: Vec::<u8>::with_capacity(5) })
  }

  /// Write bytes to inner writer.
  fn inner_write(&mut self, buf: &[u8]) -> std::io::Result<()> {
    if !self.done && let Err(err) = self.inner.write_all(buf) {
      self.done = true; // inner write failed; mark as done
      return Err(err); // return error
    }

    Ok(()) // return success
  }

  /// Flush internal buffer to inner writer.
  fn flush_buf(&mut self) -> std::io::Result<()> {
    assert!(self.buf.len() <= 5);

    // get number of chars to write to inner writer
    // for a full 5 byte buffer this will be 8 bytes.
    let c_len: usize = bits::capacity::<8, 5>(self.buf.len());
    assert!(c_len <= 8, "c_len = {c_len}");

    // if internal buffer is not full then pad it with zeros
    while self.buf.len() < 5 {
      self.buf.push(0);
    }

    // encode internal buffer as block of 8 5-bit bytes, then clear it
    let data = bits::convert_block(self.buf.as_slice()); // encode
    self.buf.clear(); // clear buffer

    // absorb block into checksum, bech32-encode the block as 8 chars,
    // then write `c_len` bech32-encoded chars to the internal writer
    self.sum = (0..c_len).fold(self.sum, |r, i| checksum::polymod(r, data[i])); // absorb
    let c: [u8; 8] = core::array::from_fn(|i| chars::LUT[data[i] as usize] as u8);
    self.inner_write(&c[..c_len])?; // absorb bech32-encoded chars

    Ok(()) // return success
  }
}

impl<W: std::io::Write> std::io::Write for Encoder<W> {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    if self.done {
      return Ok(0); // stop if encoder is done
    }

    for b in buf.iter() {
      self.buf.push(*b); // append to internal buffer

      if self.buf.len() == 5 {
        // internal buffer is full; flush it
        self.flush_buf()?;
      }
    }

    Ok(buf.len()) // return success
  }

  fn flush(&mut self) -> std::io::Result<()> {
    if self.done {
      return Ok(()); // stop if encoder is done
    }

    if !self.buf.is_empty() {
      // flush remaining bytes from internal buffer
      self.flush_buf()?;
    }

    // finalize and write checksum
    self.sum = (0..6).fold(self.sum, |r, _| checksum::polymod(r, 0)); // absorb 6 zeros
    let c = checksum::encode(self.sum ^ self.scheme.checksum_mask()); // encode checksum
    self.inner_write(&c)?; // write encoded checksum

    self.done = true; // mark as done
    Ok(()) // return success
  }
}

// TODO: uncommenting this causes a immutable borrow error in the tests
// impl<W: std::io::Write> Drop for Encoder<W> {
//   use std::io::Write;
//
//   fn drop(&mut self) {
//     match self.flush() {
//       _ => return, // ignores error
//     }
//   }
// }

#[cfg(test)]
mod tests {
  mod err {
    use super::super::Err;

    #[test]
    fn test_display_fmt() {
      let tests = vec![
        (Err::InvalidLen(1234), "invalid length: 1234"),
        (Err::InvalidChar(6789), "invalid character at position 6789"),
        (Err::MixedCase(1, 2), "mixed-case characters at positions (1, 2)"),
        (Err::MissingSeparator, "missing separator"),
        (Err::InvalidHrpLen(3141), "invalid human-readable part length: 3141"),
        (Err::InvalidChecksum, "invalid checksum"),
      ];

      for (err, exp) in tests {
        assert_eq!(err.to_string(), exp, "{exp}");
      }
    }
  }

  mod chars {
    use super::super::chars;

    #[test]
    fn test_decode() {
      let tests = vec![
        ('p', Some(1)),
        ('r', Some(3)),
        ('9', Some(5)),
        ('8', Some(7)),
        ('f', Some(9)),
        ('1', None),
      ];

      for (c, exp) in tests {
        assert_eq!(chars::decode(c), exp, "{c}");
      }
    }
  }

  mod bits {
    use super::super::bits;

    #[test]
    fn test_convert_85() {
      let tests = vec![(
        vec![1u8, 2, 3, 4, 5],
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
        ],
      ), (
        vec![1u8, 2, 3, 4, 5, 6],
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00,
        ],
      ), (
        vec![1u8, 2, 3, 4, 5, 6, 7],
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
        ],
      ), (
        vec![1u8, 2, 3, 4, 5, 6, 7, 8],
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
          0b1000_0,
        ],
      ), (
        vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9],
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
          0b1000_0, 0b00010, 0b01_000,
        ],
      ), (
        vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
          0b1000_0, 0b00010, 0b01_000, 0b01010,
        ],
      )];

      for (src, exp) in tests {
        let got = bits::convert::<8, 5>(src.as_ref());
        assert_eq!(got, exp);
      }
    }

    #[test]
    fn test_convert_58() {
      let tests = vec![(
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
        ],
        vec![1u8, 2, 3, 4, 5],
      ), (
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00,
        ],
        vec![1u8, 2, 3, 4, 5, 6, 0],
      ), (
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
        ],
        vec![1u8, 2, 3, 4, 5, 6, 7, 0],
      ), (
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
          0b1000_0,
        ],
        vec![1u8, 2, 3, 4, 5, 6, 7, 8, 0],
      ), (
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
          0b1000_0, 0b00010, 0b01_000,
        ],
        vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 0],
      ), (
        vec![
          0b00000u8, 0b001_00, 0b00001, 0b0_0000,
          0b0011_0, 0b00001, 0b00_000, 0b00101,
          0b00000, 0b110_00, 0b00011, 0b1_0000,
          0b1000_0, 0b00010, 0b01_000, 0b01010,
        ],
        vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10],
      )];

      for (src, exp) in tests {
        let got = bits::convert::<5, 8>(src.as_ref());
        assert_eq!(got, exp);
      }
    }
  }

  mod constraints {
    use super::super::*;

    #[test]
    fn test_pass() {
      let tests = vec![(
        Constraints { range: (1, Some(5)), error: Err::InvalidLen(0) },
        "a",
      ), (
        Constraints { range: (1, Some(5)), error: Err::InvalidLen(0) },
        "A",
      )];

      for (c, s) in tests {
        c.check(s).unwrap();
      }
    }

    #[test]
    fn test_fail() {
      let tests = vec![(
        "empty",
        Constraints { range: (1, Some(5)), error: Err::InvalidLen(0) },
        "",
        Err::InvalidLen(0),
      ), (
        "long",
        Constraints { range: (1, Some(5)), error: Err::InvalidLen(0) },
        "aaaaa",
        Err::InvalidLen(5),
      ), (
        "long, custom error",
        Constraints { range: (1, Some(5)), error: Err::InvalidHrpLen(0) },
        "aaaaa",
        Err::InvalidHrpLen(5),
      ), (
        "mixed case",
        Constraints { range: (1, Some(5)), error: Err::InvalidLen(0) },
        "Aa",
        Err::MixedCase(1, 0),
      ), (
        "invalid char",
        Constraints { range: (1, Some(5)), error: Err::InvalidLen(0) },
        "a a",
        Err::InvalidChar(1),
      )];

      for (name, c, s, exp) in tests {
        assert_eq!(c.check(s), Err(exp), "{name}");
      }
    }
  }

  mod hrp {
    use super::super::*;

    #[test]
    fn test_from_str_pass() {
      // check all valid hrp chars
      let valid_chars: String = (33..127).map(char::from).filter(|c| !c.is_ascii_uppercase()).collect();

      let tests = vec![
        ("a", "a"),
        ("asdf", "asdf"),
        ("ASDF", "asdf"),
        (&valid_chars, &valid_chars),
      ];

      for (s, exp) in tests {
        let got: Hrp = s.parse().unwrap();
        assert_eq!(got.as_ref(), exp);
      }
    }

    #[test]
    fn test_from_str_fail() {
      let long_str = str::repeat("x", 85);
      let tests = vec![
        ("", Err::InvalidHrpLen(0)),
        (&long_str, Err::InvalidHrpLen(long_str.len())),
        ("a b", Err::InvalidChar(1)),
        ("Ab", Err::MixedCase(1, 0)),
      ];

      for (s, exp) in tests {
        assert_eq!(s.parse::<Hrp>(), Err(exp));
      }
    }
  }

  mod checksum {
    use super::super::*;

    #[test]
    fn test_make() {
      let long_data: Vec<u8> = (0..82).map(|_| 0).collect();
      let tests = vec![
        (Scheme::Bech32, "a", vec![], b"2uel5l"),
        (Scheme::Bech32m, "A", vec![], b"lqfn3a"),
        (Scheme::Bech32m, "a", vec![], b"lqfn3a"),
        (Scheme::Bech32, "1", long_data, b"c8247j"),
      ];

      for (scheme, hrp, data, exp) in tests {
        let hrp = hrp.parse().unwrap();
        let got = checksum::make(scheme, &hrp, data);
        assert_eq!(&got, exp);
      }
    }
  }

  mod rawbech32 {
    use super::super::*;

    #[test]
    fn test_to_str() {
      let hrp_a: Hrp = "a".parse().unwrap();
      let hrp_1: Hrp = "1".parse().unwrap();

      let tests = vec![(
        RawBech32 { scheme: Scheme::Bech32, hrp: hrp_a.clone(), data: vec![] },
        "a12uel5l",
      ), (
        RawBech32 { scheme: Scheme::Bech32m, hrp: hrp_a.clone(), data: vec![] },
        "a1lqfn3a",
      ), (
        RawBech32 {
          scheme: Scheme::Bech32,
          hrp: hrp_1,
          data: vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
          ],
        },
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
      ), (
        RawBech32 {
          scheme: Scheme::Bech32,
          hrp: "bc".parse().unwrap(),
          data: vec![
            0b00000, 0b01000, 0b01000, 0b01101, 0b00111, 0b11001,
            0b00110, 0b10001, 0b00000, 0b00001, 0b11111, 0b11100,
            0b10010, 0b10100, 0b01110, 0b01001, 0b10111, 0b01011,
            0b00010, 0b11001, 0b00000, 0b11010, 0b01100, 0b00001,
            0b00111, 0b11110, 0b11100, 0b11110, 0b11100, 0b00110,
            0b10000, 0b00001, 0b00110,
          ],
        },
        "bc1qggd8ex3qpluj5wfhtzeq6vp87u7uxspxljx8se",
      )];

      for (val, exp) in tests {
        let got = val.to_string();
        assert_eq!(got, exp, "{exp}");
      }
    }

    #[test]
    fn test_from_str() {
      let hrp_a: Hrp = "a".parse().unwrap();
      let hrp_1: Hrp = "1".parse().unwrap();

      let tests = vec![(
        "a12uel5l",
        RawBech32 { scheme: Scheme::Bech32, hrp: hrp_a.clone(), data: vec![] },
      ), (
        "A12UEL5L",
        RawBech32 { scheme: Scheme::Bech32, hrp: hrp_a.clone(), data: vec![] },
      ), (
        "a1lqfn3a",
        RawBech32 { scheme: Scheme::Bech32m, hrp: hrp_a.clone(), data: vec![] },
      ), (
        "A1LQFN3A",
        RawBech32 { scheme: Scheme::Bech32m, hrp: hrp_a.clone(), data: vec![] },
      ), (
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        RawBech32 {
          scheme: Scheme::Bech32,
          hrp: hrp_1.clone(),
          data: vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
          ],
        },
      ), (
        "bc1qggd8ex3qpluj5wfhtzeq6vp87u7uxspxljx8se",
        RawBech32 {
          scheme: Scheme::Bech32,
          hrp: "bc".parse().unwrap(),
          data: vec![
            0b00000, 0b01000, 0b01000, 0b01101, 0b00111, 0b11001,
            0b00110, 0b10001, 0b00000, 0b00001, 0b11111, 0b11100,
            0b10010, 0b10100, 0b01110, 0b01001, 0b10111, 0b01011,
            0b00010, 0b11001, 0b00000, 0b11010, 0b01100, 0b00001,
            0b00111, 0b11110, 0b11100, 0b11110, 0b11100, 0b00110,
            0b10000, 0b00001, 0b00110,
          ]
        },
      )];

      for (s, exp) in tests {
        let got: RawBech32 = s.parse().expect(s);
        assert_eq!(got, exp, "{s}: {got} != {exp}");
      }
    }
  }

  mod bech32 {
    use super::super::*;

    #[test]
    fn test_to_str() {
      let hrp: Hrp = "a".parse().unwrap();
      let tests = vec![(
        Bech32 { scheme: Scheme::Bech32, hrp: hrp.clone(), data: vec![] },
        "a12uel5l",
      ), (
        Bech32 { scheme: Scheme::Bech32m, hrp: hrp.clone(), data: vec![] },
        "a1lqfn3a",
      ), (
        Bech32 { scheme: Scheme::Bech32, hrp: hrp.clone(), data: vec![1, 2, 3, 4, 5] },
        "a1qypqxpq9wunxjs",
      ), (
        Bech32 { scheme: Scheme::Bech32m, hrp: hrp.clone(), data: vec![1, 2, 3, 4, 5] },
        "a1qypqxpq9mqr2hj",
      )];

      for (val, exp) in tests {
        let got = val.to_string();
        assert_eq!(got, exp, "{exp}");
      }
    }

    #[test]
    fn test_from_str() {
      let hrp: Hrp = "a".parse().unwrap();
      let tests = vec![(
        "a12uel5l",
        Bech32 { scheme: Scheme::Bech32, hrp: hrp.clone(), data: vec![] },
      ), (
        "A12UEL5L",
        Bech32 { scheme: Scheme::Bech32, hrp: hrp.clone(), data: vec![] },
      ), (
        "a1lqfn3a",
        Bech32 { scheme: Scheme::Bech32m, hrp: hrp.clone(), data: vec![] },
      ), (
        "A1LQFN3A",
        Bech32 { scheme: Scheme::Bech32m, hrp: hrp.clone(), data: vec![] },
      ), (
        "a1qypqxpq9wunxjs",
        Bech32 { scheme: Scheme::Bech32, hrp: hrp.clone(), data: vec![1, 2, 3, 4, 5] },
      ), (
        "a1qypqxpq9mqr2hj",
        Bech32 { scheme: Scheme::Bech32m, hrp: hrp.clone(), data: vec![1, 2, 3, 4, 5] },
      ), (
        "hello1vehkc6mn27xpct",
        Bech32 { scheme: Scheme::Bech32m, hrp: "hello".parse::<Hrp>().unwrap(), data: b"folks".to_vec() },
      )];

      for (s, exp) in tests {
        let got: Bech32 = s.parse().expect(s);
        assert_eq!(got, exp, "{s}: {got} != {exp}");
      }
    }
  }

  mod encoder {
    use super::super::*;
    use std::io::Write;

    #[test]
    fn test_write_and_flush() {
      let tests = vec![(
        Scheme::Bech32m,
        "a",
        b"".to_vec(),
        "a1lqfn3a",
      ), (
        Scheme::Bech32m,
        "a",
        b"a".to_vec(),
        "a1vyv2rgae",
      ), (
        Scheme::Bech32m,
        "a",
        b"ab".to_vec(),
        "a1v93qw2fnlx",
      ), (
        Scheme::Bech32m,
        "a",
        b"abc".to_vec(),
        "a1v93xx3s7l23",
      ), (
        Scheme::Bech32m,
        "a",
        b"abcd".to_vec(),
        "a1v93xxeq4gxvyc",
      ), (
        Scheme::Bech32m,
        "a",
        b"abcde".to_vec(),
        "a1v93xxer9zche3p",
      ), (
        Scheme::Bech32m,
        "a",
        b"abcdef".to_vec(),
        "a1v93xxer9vczn72zl",
      ), (
        Scheme::Bech32m,
        "ab",
        b"cdef".to_vec(),
        "ab1vdjx2es7ryzmh",
      ), (
        Scheme::Bech32m,
        "hello",
        b"folks".to_vec(),
        "hello1vehkc6mn27xpct",
      ), (
        Scheme::Bech32m,
        "blum",
        b"flub".to_vec(),
        "blum1vek82cskf3qwx",
      ), (
        Scheme::Bech32m,
        "foo",
        b"bar".to_vec(),
        "foo1vfshy2dnlu3",
      )];

      for (scheme, hrp, data, exp) in tests {
        let hrp: Hrp = hrp.parse().unwrap();
        let mut got: Vec<u8> = Vec::new();
        let mut e = Encoder::new(&mut got, scheme, hrp).unwrap();
        e.write_all(data.as_slice()).unwrap();
        e.flush().unwrap(); // flush encoder
        assert_eq!(str::from_utf8(&got).unwrap(), exp);
      }
    }
  }
}
