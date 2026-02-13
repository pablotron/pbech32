//! [Bech32][] parsing and encoding library.
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"
//! [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "Bech32 (BIP173)"
//! [bip350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "Bech32m (BIP350)"
//! [ascii]: https://en.wikipedia.org/wiki/ASCII
//!   "ASCII (Wikipedia)"

#![deny(missing_docs)]
#![deny(unsafe_code)]

// ref: https://learnmeabitcoin.com/technical/keys/bech32/
//
// TODO:
// [x] encode/decode data into 5-bit form
// [x] auto-detect scheme
// [ ] docs
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
/// use bech32::{Bech32, Err};
/// let s = ""; // empty string
/// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidLen));
/// # }
/// ```
///
/// Try to parse a string with an invalid character:
///
/// ```
/// # fn main() {
/// use bech32::{Bech32, Err};
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
  /// The length of a [Bech32][] string must be in the range `8..256`.
  ///
  /// **Note:** This library will parse strings up to 256 characters in
  /// length; the  maximum length of a [Bech32][] string according to
  /// [BIP173][] is 90 characters,
  ///
  /// # Examples
  ///
  /// Try to parse an empty string:
  ///
  /// ```
  /// # fn main() {
  /// use bech32::{Bech32, Err};
  /// let s = ""; // empty string
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidLen));
  /// # }
  /// ```
  ///
  /// Try to parse a string that is too long:
  ///
  /// ```
  /// # fn main() {
  /// use bech32::{Bech32, Err};
  /// let s = str::repeat("x", 256); // long string
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
  /// use bech32::{Bech32, Err};
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
  /// use bech32::{Bech32, Err};
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
  /// use bech32::{Bech32, Err};
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
  /// use bech32::{Bech32, Err};
  /// let s = "1axxxxxx"; // string with empty HRP
  /// assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidHrpLen));
  /// # }
  /// ```
  ///
  /// Try to parse a string with a human-readable part that is too long:
  ///
  /// ```
  /// # fn main() {
  /// use bech32::{Bech32, Err};
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
  /// use bech32::{Bech32, Err};
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
/// TODO
///
/// # Examples
///
/// Parse [Bech32][bip173] string:
///
/// ```
/// # fn main() -> Result<(), bech32::Err> {
/// use bech32::{Bech32, Scheme};
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
/// # fn main() -> Result<(), bech32::Err> {
/// use bech32::{Bech32, Scheme};
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
  /// # fn main() -> Result<(), bech32::Err> {
  /// use bech32::{Bech32, Scheme};
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
  /// # fn main() -> Result<(), bech32::Err> {
  /// use bech32::{Bech32, Scheme};
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
/// use bech32::bits::convert;
///
/// let exp = vec![0, 4, 1, 0, 6, 1, 0, 5]; // expected 5-bit result
/// let got = convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode 8-bit data
/// assert_eq!(got, exp); // check 5-bit result
/// # }
/// ```
///
/// Decode 5-bit data as vector of 8-bit bytes:
///
/// ```
/// # fn main() {
/// use bech32::bits::convert;
///
/// let exp = vec![1, 2, 3, 4, 5]; // expected 8-bit result
/// let got = convert::<5, 8>(&[0, 4, 1, 0, 6, 1, 0, 5]); // decode 5-bit data
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
  /// # Examples
  ///
  /// Encode 8-bit data as vector of 5-bit bytes:
  ///
  /// ```
  /// # fn main() {
  /// use bech32::bits::convert;
  ///
  /// let exp = vec![0, 4, 1, 0, 6, 1, 0, 5]; // expected 5-bit result
  /// let got = convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode 8-bit data
  /// assert_eq!(got, exp); // check 5-bit result
  /// # }
  /// ```
  ///
  /// Decode 5-bit data as vector of 8-bit bytes:
  ///
  /// ```
  /// # fn main() {
  /// use bech32::bits::convert;
  ///
  /// let exp = vec![1, 2, 3, 4, 5]; // expected 8-bit result
  /// let got = convert::<5, 8>(&[0, 4, 1, 0, 6, 1, 0, 5]); // decode 5-bit data
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
/// Notes:
///
/// 1. The human-readable part must be lowercase.
/// 2. The data should be 5-bit encoded.  In other words, only the
///    lower 5 bits of each byte contain data.
///
/// # Examples
///
/// Create [Bech32][] checksum:
///
/// ```
/// # fn main() -> Result<(), bech32::Err> {
/// use bech32::{bits::convert, checksum::make, Scheme};
///
/// let exp = b"wunxjs"; // expected checksum
/// let data = convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
/// let got = make(Scheme::Bech32, "a", data); // make checksum
/// assert_eq!(&got, exp); // verify checksum
/// # Ok(())
/// # }
/// ```
///
/// Create [Bech32m][] checksum:
///
/// ```
/// # fn main() -> Result<(), bech32::Err> {
/// use bech32::{bits::convert, checksum::make, Scheme};
///
/// let exp = b"mqr2hj"; // expected checksum
/// let data = convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
/// let got = make(Scheme::Bech32m, "a", data); // make checksum
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
  use super::{chars, Scheme};

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
  /// Notes:
  ///
  /// 1. The human-readable part must be lowercase.
  /// 2. The data should be 5-bit encoded.  In other words, only the
  ///    lower 5 bits of each byte contain data.
  ///
  /// # Examples
  ///
  /// Create [Bech32][] checksum:
  ///
  /// ```
  /// # fn main() -> Result<(), bech32::Err> {
  /// use bech32::{bits::convert, checksum::make, Scheme};
  ///
  /// let exp = b"wunxjs"; // expected checksum
  /// let data = convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
  /// let got = make(Scheme::Bech32, "a", data); // make checksum
  /// assert_eq!(&got, exp); // verify checksum
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// Create [Bech32m][] checksum:
  ///
  /// ```
  /// # fn main() -> Result<(), bech32::Err> {
  /// use bech32::{bits::convert, checksum::make, Scheme};
  ///
  /// let exp = b"mqr2hj"; // expected checksum
  /// let data = convert::<8, 5>(&[1, 2, 3, 4, 5]); // encode data
  /// let got = make(Scheme::Bech32m, "a", data); // make checksum
  /// assert_eq!(&got, exp); // verify checksum
  /// # Ok(())
  /// # }
  /// ```
  ///
  /// [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ///   "Bech32 (BIP173)"
  /// [bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  ///   "Bech32m (BIP350)"
  pub fn make<T: AsRef<[u8]>>(scheme: Scheme, hrp: &str, data: T) -> [u8; 6] {
    let mut sum: u32 = 1;

    sum = hrp.bytes().fold(sum, |r, b| polymod(r, b >> 5)); // absorb hrp high bits
    sum = polymod(sum, 0); // absorb 0
    sum = hrp.bytes().fold(sum, |r, b| polymod(r, b & 0x1f)); // absorb hrp low bits
    sum = data.as_ref().iter().fold(sum, |r, b| polymod(r, *b)); // absorb data
    sum = (0..6).fold(sum, |r, _| polymod(r, 0)); // absorb 6 zeros

    encode(sum ^ scheme.checksum_mask()) // mask, encode as [u8; 6]
  }
}

/// Parsed [Bech32][] structure with 5-bit `data` field.
///
/// Use [`Bech32`] structure instead to automatically encode and decode
/// 8-bit data.
///
/// # Examples
///
/// Parse [Bech32m][] string:
///
/// ```
/// # fn main() -> Result<(), bech32::Err> {
/// use bech32::{RawBech32, Scheme};
///
/// // expected result
/// let exp = RawBech32 {
///   scheme: Scheme::Bech32m,
///   hrp: "a".to_string(),
///   data: vec![0, 4, 1, 0, 6, 1, 0, 5],
/// };
///
/// let s = "a1qypqxpq9mqr2hj"; // bech32m string
/// let got: RawBech32 = s.parse()?; // parse string
/// assert_eq!(got, exp); // check result
/// # Ok(())
/// # }
/// ```
///
/// Convert [`RawBech32`] to string:
///
/// ```
/// # fn main() -> Result<(), bech32::Err> {
/// use bech32::{RawBech32, Scheme};
///
/// // expected result
/// let exp = "a1qypqxpq9mqr2hj";
///
/// // populate structure
/// let b = RawBech32 {
///   scheme: Scheme::Bech32m,
///   hrp: "a".to_string(),
///   data: vec![0, 4, 1, 0, 6, 1, 0, 5],
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
/// # fn main() -> Result<(), bech32::Err> {
/// use bech32::{RawBech32, Scheme};
///
/// // expected result
/// let exp = RawBech32 {
///   scheme: Scheme::Bech32m,
///   hrp: "a".to_string(),
///   data: vec![0, 4, 1, 0, 6, 1, 0, 5],
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
  /// Checksum scheme
  pub scheme: Scheme,

  /// Human-readable part
  pub hrp: String,

  /// Raw 5-bit data
  ///
  /// **Note:** Use [`bits::convert()`] to decode the 5-bit data
  /// in this field.
  pub data: Vec<u8>,
}

impl RawBech32 {
  /// Parse string as bech32 string using given scheme.
  pub fn new(s: &str, scheme: Option<Scheme>) -> Result<Self, Err> {
    // check that string length is in the range 8..256
    //
    // NOTE: BIP173 limits the maximum length to 90 characters rather
    // than 256 characters.
    if s.len() < 8 || s.len() > 255 {
      return Err(Err::InvalidLen);
    }

    // check for invalid chars
    if !s.chars().all(|c| c.is_ascii_alphanumeric()) {
      return Err(Err::InvalidChar);
    }

    // check for mixed case
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
      return Err(Err::MixedCase);
    }

    // normalize case and split into (hrp, data)
    let s: String = s.chars().map(|c| c.to_ascii_lowercase()).collect();
    let (hrp, enc) = s[..(s.len()-6)].rsplit_once('1').ok_or(Err::MissingSeparator)?;

    // check hrp length
    if hrp.len() < 1 || hrp.len() > 83 {
      return Err(Err::InvalidHrpLen);
    }

    // decode data
    let mut data: Vec<u8> = Vec::with_capacity(enc.len());
    for c in enc.chars() {
      data.push(chars::decode(c).ok_or(Err::InvalidChar)?);
    }

    // get expected checksum from end of string
    let exp_csum = &s.as_bytes()[(s.len() - 6)..];

    // get list of schemes to try
    let schemes = match scheme {
      Some(scheme) => vec![scheme],
      None => vec![Scheme::Bech32m, Scheme::Bech32],
    };

    for scheme in schemes {
      // calculate checksum of hrp and data, then verify that it matches
      // the expected checksum
      if checksum::make(scheme, hrp, &data) == exp_csum {
        // checksum matches, return success
        return Ok(Self { scheme, data, hrp: hrp.to_string() });
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

/// Parsed Bech32 data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bech32 {
  /// Bech32 scheme
  pub scheme: Scheme,

  /// Human-readable part.
  pub hrp: String, // TODO: &'a str

  /// Packed data.
  pub data: Vec<u8>,
}

impl Bech32 {
  /// Parse string as bech32 string with given scheme.
  /// specification.
  pub fn new(s: &str, scheme: Option<Scheme>) -> Result<Self, Err> {
    let r = RawBech32::new(s, scheme)?;
    let data = bits::convert::<5, 8>(r.data.as_ref());
    Ok(Self { data, scheme: r.scheme, hrp: r.hrp.to_string() })
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

  mod rawbech32 {
    use super::super::*;

    #[test]
    fn test_to_str() {
      let tests = vec![(
        RawBech32 { scheme: Scheme::Bech32, hrp: "a".to_string(), data: vec![] },
        "a12uel5l",
      ), (
        RawBech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![] },
        "a1lqfn3a",
      ), (
        RawBech32 {
          scheme: Scheme::Bech32,
          hrp: "bc".to_string(),
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
      let tests = vec![(
        "a12uel5l",
        RawBech32 {
          scheme: Scheme::Bech32,
          hrp: "a".to_string(),
          data: vec![],
        },
      ), (
        "A12UEL5L",
        RawBech32 { scheme: Scheme::Bech32, hrp: "a".to_string(), data: vec![] },
      ), (
        "a1lqfn3a",
        RawBech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![] },
      ), (
        "A1LQFN3A",
        RawBech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![] },
      ), (
        "bc1qggd8ex3qpluj5wfhtzeq6vp87u7uxspxljx8se",
        RawBech32 {
          scheme: Scheme::Bech32,
          hrp: "bc".to_string(),
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
      let tests = vec![(
        Bech32 { scheme: Scheme::Bech32, hrp: "a".to_string(), data: vec![] },
        "a12uel5l",
      ), (
        Bech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![] },
        "a1lqfn3a",
      ), (
        Bech32 { scheme: Scheme::Bech32, hrp: "a".to_string(), data: vec![1, 2, 3, 4, 5] },
        "a1qypqxpq9wunxjs",
      ), (
        Bech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![1, 2, 3, 4, 5] },
        "a1qypqxpq9mqr2hj",
      )];

      for (val, exp) in tests {
        let got = val.to_string();
        assert_eq!(got, exp, "{exp}");
      }
    }

    #[test]
    fn test_from_str() {
      let tests = vec![(
        "a12uel5l",
        Bech32 { scheme: Scheme::Bech32, hrp: "a".to_string(), data: vec![] },
      ), (
        "A12UEL5L",
        Bech32 { scheme: Scheme::Bech32, hrp: "a".to_string(), data: vec![] },
      ), (
        "a1lqfn3a",
        Bech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![] },
      ), (
        "A1LQFN3A",
        Bech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![] },
      ), (
        "a1qypqxpq9wunxjs",
        Bech32 { scheme: Scheme::Bech32, hrp: "a".to_string(), data: vec![1, 2, 3, 4, 5] },
      ), (
        "a1qypqxpq9mqr2hj",
        Bech32 { scheme: Scheme::Bech32m, hrp: "a".to_string(), data: vec![1, 2, 3, 4, 5] },
      )];

      for (s, exp) in tests {
        let got: Bech32 = s.parse().expect(s);
        assert_eq!(got, exp, "{s}: {got} != {exp}");
      }
    }
  }
}
