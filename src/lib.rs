pub fn add(left: u64, right: u64) -> u64 {
  left + right
}

#[derive(Debug)]
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

/// Checksum calculator
#[derive(Debug)]
struct Checksummer(u32);

impl Default for Checksummer {
  fn default() -> Self {
    Self(1)
  }
}

impl Checksummer {
  const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  
  pub fn write(&mut self, bytes: &Vec<u8>) {
    for b in bytes {
      let t = self.0 >> 25;
      self.0 = ((self.0 & 0x1ffffff) << 5) ^ (*b as u32);
      self.0 ^= (0..5)
        .map(|i| Self::GEN[i] & !((t >> i) & 1).wrapping_sub(1))
        .fold(0, |r, v| r ^ v);
    }
  }

  /// Get final checksum
  pub fn sum(&self) -> u32 {
    self.0 ^ 1
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bech32 {
  /// Human-readable part.
  pub spec: Spec,
  pub hrp: String, // TODO: &'a str
  pub data: Vec<u8>,
}

impl Bech32 {
  /// Return the amount of space needed to decode the given
  /// bech32-encoded data.
  fn decode_len(len: usize) -> usize {
    5 * len / 8 + match len % 8 {
      0 => 0,
      1 => 1,
      2 => 2,
      3 => 2,
      4 => 3,
      5 => 4,
      6 => 4,
      7 => 5,
      _ => unreachable!(),
    }
  }

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

  /// Decode slice as a vector of ['u8'].
  fn decode_data(s: &str) -> Result<Vec<u8>, Err> {
    // get decode length
    let len = Self::decode_len(s.len());

    let mut data: Vec<u8> = Vec::with_capacity(len);

    let mut acc: u32 = 0;
    let mut acc_len = 0;
    for c in s.chars().map(|c| c.to_ascii_lowercase()) {
      let t = Self::decode_char(c).ok_or(Err::InvalidChar)?;
      acc |= (t as u32) << acc_len;
      acc += 5;
      while acc_len > 7 {
        data.push((acc & 0xff) as u8);
        acc >>= 8;
        acc_len -= 8;
      }
    }

    // flush remaining bits
    while acc_len > 0 {
      data.push((acc & 0xff) as u8);
      acc >>= 8;
      acc_len -= acc_len.min(8);
    }

    Ok(data)
  }

  /// Decode checksum slice ['u32'].
  fn decode_checksum(s: &str) -> Result<u32, Err> {
    if s.len() != 6 {
      return Err(Err::InvalidChecksumLength);
    }

    let mut acc: u32 = 0;
    for c in s.chars().map(|c| c.to_ascii_lowercase()) {
      let t = Self::decode_char(c).ok_or(Err::InvalidChar)?;
      acc <<= 5;
      acc |= t as u32;
    }

    Ok(acc)
  }

  /// Calculate checksum for given human-readable part and data.
  fn checksum(_spec: &Spec, hrp: &str, data: &Vec<u8>) -> u32 {
    let mut cs: Checksummer = Default::default();

    cs.write(&hrp.bytes().map(|b| b >> 5).collect()); // hrp high bits
    cs.write(&vec!(0u8)); // delimiter
    cs.write(&hrp.bytes().map(|b| b & 0x1f).collect()); // hrp low bits
    cs.write(&data); // data
    cs.write(&vec!(0u8, 0, 0, 0, 0, 0)); // tail

    cs.sum()
  }
}

impl std::str::FromStr for Bech32 {
  type Err = Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    // check string length
    if s.len() < 8 {
      return Err(Err::Len);
    }

    // check for invalid chars
    if s.chars().find(|c| ((*c as u32) < 33) || ((*c as u32)) > 127).is_some() {
      return Err(Err::InvalidChar);
    }

    // check for mixed case
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
      return Err(Err::MixedCase);
    }

    // split into hrp and encoded data
    let (hrp, enc) = s[..(s.len()-6)].rsplit_once('1').ok_or(Err::MissingSeparator)?;

    // check hrp length
    if hrp.len() < 1 || hrp.len() > 83 {
      return Err(Err::InvalidHrpLen);
    }

    let spec = Spec::Bech32;

    // decode data
    let data = Self::decode_data(&enc)?;

    // verify checksum
    let exp_csum = Self::checksum(&spec, &hrp, &data);
    let got_csum = Self::decode_checksum(&s[(s.len() - 6)..])?;
    if got_csum != exp_csum {
      return Err(Err::InvalidChecksum);
    }

    Ok(Bech32 {
      spec: spec,
      hrp: hrp.to_string(),
      data: data,
    })
  }
}

const ENCODE_LUT: [char; 32] = [
  'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0',
  's', '3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l', 
];

impl std::fmt::Display for Bech32 {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    // write hrp
    write!(f, "{}1", self.hrp)?;

    // encode/write data
    let mut acc: u32 = 0;
    let mut acc_len = 0;
    for b in &self.data {
      acc |= (*b as u32) << acc_len;
      acc_len += 8;
      while acc_len > 4 {
        write!(f, "{}", ENCODE_LUT[(acc & 0x1f) as usize])?;
        acc >>= 5;
        acc_len -= 5;
      }
    }

    // flush data bits
    while acc_len > 0 {
      write!(f, "{}", ENCODE_LUT[(acc & 0x1f) as usize])?;
      acc >>= 5;
      acc_len -= acc_len.min(5);
    }

    // write checksum
    let sum = Self::checksum(&self.spec, &self.hrp, &self.data);
    for i in 0..6 {
      write!(f, "{}", ENCODE_LUT[(sum as usize >> (5 * (5 - i))) & 0x1f])?;
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  mod bech32 {
    use super::super::*;

    #[test]
    fn test_to_str() {
      let tests = vec![(
        Bech32 { spec: Spec::Bech32, hrp: "a".to_string(), data: vec![] },
        "a12uel5l",
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
        Bech32 { spec: Spec::Bech32, hrp: "a".to_string(), data: vec![] },
      ), (
        "A12UEL5L",
        Bech32 { spec: Spec::Bech32, hrp: "a".to_string(), data: vec![] },
      )];

      for (s, exp) in tests {
        let got: Bech32 = s.parse().expect(s);
        assert_eq!(got, exp);
      }
    }
  }
}
