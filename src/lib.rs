//! [Bech32][] encoding and decoding library.
//!
//! [Bech32][] is a [checksummed][checksum] [base 32][] encoding format
//! that is fast and user-friendly.  [Bech32m][] is an update to
//! [Bech32][] which improves the [checksum][] algorithm.  [Bech32][]
//! and [Bech32m][] are specified in [BIP173][] and [BIP350][],
//! respectively.
//!
//! A [Bech32][] string contains a human-readable part (HRP), a
//! [base 32][]-encoded data part, and a 6 character [BCH][] checksum.
//!
//! Here is an example [Bech32m][] string:
//!
//! ```text
//! hello1wahhymryxruu7j
//! ```
//!
//! # Library Features
//!
//! - [Bech32 (BIP173)][bip173] and [Bech32m (BIP350)][bip350] support.
//! - Idiomatic string encoding and decoding with [`std::fmt::Display`]
//!   and [`std::str::FromStr`].
//! - Decodes strings up to 512 characters long (see [note][MAX_LEN]).
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
//! let s = "a1qypqxpq9mqr2hj"; // bech32m string
//! let got: Bech32 = s.parse()?; // parse string
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
//! use pbech32::{Bech32, Scheme};
//!
//! // populate structure
//! let b = Bech32 {
//!   scheme: Scheme::Bech32m, // checksum scheme
//!   hrp: "a".parse()?, // human-readable part
//!   data: vec![1, 2, 3, 4, 5], // data
//! };
//!
//! let got = b.to_string(); // encode as string
//! assert_eq!(got, "a1qypqxpq9mqr2hj"); // check result
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
//! [bch]: https://en.wikipedia.org/wiki/BCH_code
//!   "BCH code (Wikipedia)"

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
// [ ] bug: scheme: bech32m, hrp: "hi", data: "folks"
// [ ] use AsRef<str> for make() hrp param?
// [ ] dup tests from age impl:
//     https://github.com/FiloSottile/age/blob/main/internal/bech32/bech32.go

/// Maximum string decode length, in bytes.
///
/// **Note:** This limit differs from [BIP173][] which limits the
/// maximum string length to 90 bytes.
///
/// [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "BIP173 (Bech32)"
pub const MAX_LEN: usize = 512;

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
/// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidLen));
/// # }
/// ```
///
/// Try to parse a string with an invalid character:
///
/// ```
/// # fn main() {
/// use pbech32::{Bech32, Err};
/// let s = "a 1xxxxxx"; // string with invalid bech32 character
/// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidChar));
/// # }
/// ```
///
/// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
///   "Bech32 (BIP173)"
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Err {
  /// Invalid string length.
  ///
  /// The length of a [Bech32][] string must be in the range `8..MAX_LEN`.
  ///
  /// **Note:** This library will parse strings up to [`MAX_LEN`]
  /// characters long.  This differs from [BIP173][] which limits
  /// the maximum string length to 90 characters,
  ///
  /// # Examples
  ///
  /// Try to parse an empty string:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = ""; // empty string
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidLen));
  /// # }
  /// ```
  ///
  /// Try to parse a string that is too long:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err, MAX_LEN};
  /// let s = str::repeat("x", MAX_LEN); // long string
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidLen));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  /// [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  InvalidLen,

  /// String contains an invalid character.
  ///
  /// A [Bech32][] string must only contain alphanumeric [ASCII][] characters.
  ///
  /// # Example
  ///
  /// Try to parse a string with an invalid character:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "a 1xxxxxx"; // string with invalid bech32 character
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidChar));
  /// # }
  /// ```
  ///
  /// [ascii]: https://en.wikipedia.org/wiki/ASCII
  ///   "ASCII (Wikipedia)"
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  InvalidChar,

  /// String contains mixed uppercase and lowercase characters.
  ///
  /// A [Bech32][] string must not contain both uppercase and lowercase
  /// characters.
  ///
  /// # Example
  ///
  /// Try to parse a string with both uppercase and lowercase
  /// characters:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "Ab1xxxxxx"; // string with mixed-case characters
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::MixedCase));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  MixedCase,

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
  /// # Examples
  ///
  /// Try to parse a string with an empty human-readable part:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = "1axxxxxx"; // string with empty HRP
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidHrpLen));
  /// # }
  /// ```
  ///
  /// Try to parse a string with a human-readable part that is too long:
  ///
  /// ```
  /// # fn main() {
  /// use pbech32::{Bech32, Err};
  /// let s = str::repeat("a", 84) + "1xxxxxx"; // string with long HRP
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidHrpLen));
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  InvalidHrpLen,

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
      'n' => Some(29),
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

/// 5-bit to 8-bit data conversion functions.
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
pub mod bits {
  /// Get capacity needed for bit conversion.
  fn capacity<
    const SRC_BITS: usize, // input bit size (5 or 8)
    const DST_BITS: usize, // output bit size (5 or 8)
  >(len: usize) -> usize {
    SRC_BITS * len / DST_BITS + match (SRC_BITS, DST_BITS, len % DST_BITS) {
      (8, 5, 0) => 0,
      (8, 5, 1) => 1,
      (8, 5, 2) => 2,
      (8, 5, 3) => 2,
      (8, 5, 4) => 3,

      (5, 8, 0) => 0,
      (5, 8, 1) => 1,
      (5, 8, 2) => 2,
      (5, 8, 3) => 2,
      (5, 8, 4) => 3,
      (5, 8, 5) => 4,
      (5, 8, 6) => 4,
      (5, 8, 7) => 5,

      _ => unreachable!(),
    }
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
  fn encode(sum: u32) -> [u8; 6] {
    core::array::from_fn(|i| {
      chars::LUT[((sum as usize) >> (5 * (5 - i))) & 0x1f] as u8
    })
  }

  /// Update checksum `sum` with 5-bit value `val`.
  ///
  /// **Note:** Only absorbs the bottom 5 bits of value.
  fn polymod(mut sum: u32, val: u8) -> u32 {
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
  range: (usize, usize),

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
    // check string length
    if !(self.range.0..self.range.1).contains(&s.len()) {
      return Err(self.error);
    }

    // check for invalid chars (e.g. c != 33..127)
    if !s.chars().all(|c| c.is_ascii_graphic()) {
      return Err(Err::InvalidChar);
    }

    // check for mixed case
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
      return Err(Err::MixedCase);
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
/// assert_eq!(got, Err(Err::MixedCase)); // check result
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
    range: (1, 84), // max 83 from BIP173
    error: Err::InvalidHrpLen,
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
    range: (8, MAX_LEN), // NOTE: BIP173 max is 91.
    error: Err::InvalidLen,
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
    for c in enc.chars() {
      data.push(chars::decode(c).ok_or(Err::InvalidChar)?);
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

#[cfg(test)]
mod tests {
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
        Constraints { range: (1, 5), error: Err::InvalidLen },
        "a",
      ), (
        Constraints { range: (1, 5), error: Err::InvalidLen },
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
        Constraints { range: (1, 5), error: Err::InvalidLen },
        "",
        Err::InvalidLen,
      ), (
        "long",
        Constraints { range: (1, 5), error: Err::InvalidLen },
        "aaaaa",
        Err::InvalidLen,
      ), (
        "long, custom error",
        Constraints { range: (1, 5), error: Err::InvalidHrpLen },
        "aaaaa",
        Err::InvalidHrpLen,
      ), (
        "mixed case",
        Constraints { range: (1, 5), error: Err::InvalidLen },
        "Aa",
        Err::MixedCase,
      ), (
        "invalid char",
        Constraints { range: (1, 5), error: Err::InvalidLen },
        "a a",
        Err::InvalidChar,
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
        ("", Err::InvalidHrpLen),
        (&long_str, Err::InvalidHrpLen),
        ("a b", Err::InvalidChar),
        ("Ab", Err::MixedCase),
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
      )];

      for (s, exp) in tests {
        let got: Bech32 = s.parse().expect(s);
        assert_eq!(got, exp, "{s}: {got} != {exp}");
      }
    }
  }
}
