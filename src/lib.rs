//! [Bech32][] parsing and encoding library.
//!
//! [bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "BIP-173: Bech32"
//! [bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//!   "BIP-173: Bech32"
//! [bip350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//!   "BIP-350: Bech32m"

// ref: https://learnmeabitcoin.com/technical/keys/bech32/
//
// TODO:
// [x] encode/decode data into 5-bit form
// [ ] docs
// [ ] dup tests from age impl:
//     https://github.com/FiloSottile/age/blob/main/internal/bech32/bech32.go

/// Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Err {
  Len,
  InvalidChar,
  MixedCase,
  MissingSeparator,
  InvalidHrpLen,
  TruncatedData,
  InvalidChecksumLength,
  InvalidChecksum,
}

/// Bec32 specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Spec {
  /// Bech32 spec (BIP-173).
  Bech32,

  /// Bech32m spec (BIP-350).
  Bech32m,
}

impl Spec {
  /// Get checksum mask for specification.
  fn checksum_mask(&self) -> u32 {
    match self {
      Spec::Bech32 => 1,
      Spec::Bech32m => 0x2bc830a3,
    }
  }
}

/// Encoding lookup table (LUT).
const LUT: [char; 32] = [
  'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0',
  's', '3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

/// Decode character as 5-bit [`u8`].  Returns [`None`] if the input
/// is not a valid bech32 character.
fn decode_char(c: char) -> Option<u8> {
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

/// Checksum functions.
pub mod checksum {
  use super::Spec;
  const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  /// Encode checksum as byte array.
  fn encode(sum: u32) -> [u8; 6] {
    core::array::from_fn(|i| {
      super::LUT[((sum as usize) >> (5 * (5 - i))) & 0x1f] as u8
    })
  }

  /// Update checksum `sum` with 5-bit value `val`.
  fn polymod(mut sum: u32, val: u8) -> u32 {
    let t = sum >> 25; // get bits 25..30
    sum = ((sum & 0x1ffffff) << 5) | ((val & 0x1f) as u32);
    (0..5).map(|i| GEN[i] & !((t >> i) & 1).wrapping_sub(1)).fold(sum, |r, v| r ^ v)
  }

  /// Create checksum from case-normalized human-readable part and
  /// unpacked (e.g. 5 bits per octet) data.
  pub fn make(spec: Spec, hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut sum: u32 = 1;

    sum = hrp.bytes().fold(sum, |r, b| polymod(r, b >> 5)); // absorb hrp high bits
    sum = polymod(sum, 0); // absorb 0
    sum = hrp.bytes().fold(sum, |r, b| polymod(r, b & 0x1f)); // absorb hrp low bits
    sum = data.iter().fold(sum, |r, b| polymod(r, *b)); // absorb data
    sum = (0..6).fold(sum, |r, _| polymod(r, 0)); // absorb 6 zeros

    encode(sum ^ spec.checksum_mask()) // finalize, encode as [u8; 6]
  }
}

/// Data encoding/decoding functions.
pub mod bits {
  /// Get capacity needed for conversion.
  fn capacity<const SRC_BITS: usize, const DST_BITS: usize>(len: usize) -> usize {
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

  /// Encode packed data as 5-bit bytes.
  pub fn convert<const SRC_BITS: usize, const DST_BITS: usize>(bytes: &[u8]) -> Vec<u8> {
    let mask: u32 = (1 << (DST_BITS as u32)) - 1;
    let mut r = Vec::with_capacity(capacity::<SRC_BITS, DST_BITS>(bytes.len()));
    let mut acc: u32 = 0;
    let mut acc_len = 0;

    for b in bytes {
      acc = (acc << SRC_BITS) | (*b as u32);
      acc_len += SRC_BITS;
      while acc_len >= DST_BITS {
        acc_len -= DST_BITS;
        r.push(((acc >> acc_len) & mask) as u8);
        acc &= (1 << acc_len) - 1;
      }
    }

    // flush bits
    if acc_len > 0 {
      acc <<= DST_BITS - acc_len;
      r.push((acc & mask) as u8);
    }

    r
  }
}

/// Raw bech32 data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawBech32 {
  /// Bech32 specification.
  pub spec: Spec,

  /// Human-readable part.
  pub hrp: String, // TODO: &'a str

  /// Packed data.
  pub data: Vec<u8>,
}

impl RawBech32 {
  /// Parse string as bech32 string with format from given
  /// specification.
  pub fn new(spec: Spec, s: &str) -> Result<Self, Err> {
    // check that string length is in the range 8..91
    if s.len() < 8 || s.len() > 90 {
      return Err(Err::Len);
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
      data.push(decode_char(c).ok_or(Err::InvalidChar)?);
    }

    // calculate checksum of hrp and data, then verify that it matches
    // the checksum at the end of the input string
    let got_csum = checksum::make(spec, hrp, &data);
    let exp_csum = &s.as_bytes()[(s.len() - 6)..];
    if got_csum != exp_csum {
      return Err(Err::InvalidChecksum);
    }

    Ok(Self { spec, data, hrp: hrp.to_string() })
  }
}

impl std::str::FromStr for RawBech32 {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::new(Spec::Bech32, s)
  }
}

impl std::fmt::Display for RawBech32 {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    // write hrp
    write!(f, "{}1", self.hrp)?;

    // encode/write data
    for b in &self.data {
      write!(f, "{}", LUT[*b as usize])?;
    }

    // write checksum
    // note: unwrap() is safe here beca
    let s = checksum::make(self.spec, &self.hrp, &self.data);
    write!(f, "{}", str::from_utf8(&s).unwrap())?;

    Ok(())
  }
}

/// Bech32 data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bech32 {
  /// Bech32 specification.
  pub spec: Spec,

  /// Human-readable part.
  pub hrp: String, // TODO: &'a str

  /// Packed data.
  pub data: Vec<u8>,
}

impl Bech32 {
  /// Parse string as bech32 string with format from given
  /// specification.
  pub fn new(spec: Spec, s: &str) -> Result<Self, Err> {
    let r = RawBech32::new(spec, s)?;
    let data = bits::convert::<5, 8>(r.data.as_ref());
    Ok(Self { data, spec: r.spec, hrp: r.hrp.to_string() })
  }
}

impl std::str::FromStr for Bech32 {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::new(Spec::Bech32, s)
  }
}

impl std::fmt::Display for Bech32 {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    // write hrp
    write!(f, "{}1", self.hrp)?;

    // encode/write data
    for b in bits::convert::<8, 5>(&self.data.as_ref()) {
      write!(f, "{}", LUT[b as usize])?;
    }

    // write checksum
    // note: unwrap() is safe here beca
    let s = checksum::make(self.spec, &self.hrp, &self.data);
    write!(f, "{}", str::from_utf8(&s).unwrap())?;

    Ok(())
  }
}

#[cfg(test)]
mod tests {
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
        RawBech32 { spec: Spec::Bech32, hrp: "a".to_string(), data: vec![] },
        "a12uel5l",
      ), (
        RawBech32 {
          spec: Spec::Bech32,
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
        assert_eq!(got, exp);
      }
    }

    #[test]
    fn test_from_str() {
      let tests = vec![(
        "a12uel5l",
        RawBech32 {
          spec: Spec::Bech32,
          hrp: "a".to_string(),
          data: vec![],
        },
      ), (
        "A12UEL5L",
        RawBech32 { spec: Spec::Bech32, hrp: "a".to_string(), data: vec![] },
      ), (
        "bc1qggd8ex3qpluj5wfhtzeq6vp87u7uxspxljx8se",
        RawBech32 {
          spec: Spec::Bech32,
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
}
