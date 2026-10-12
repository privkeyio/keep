// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Fixed-length byte strings carried as lowercase hex, parsed strictly:
//! exactly the right length, lowercase only.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! hex_bytes {
    ($name:ident, $len:expr) => {
        #[doc = concat!(stringify!($len), " bytes, carried as lowercase hex.")]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// Parse lowercase hex of exactly the right length.
            pub fn parse(s: &str) -> crate::Result<Self> {
                if !is_lower_hex(s, $len) {
                    return Err(crate::malformed(concat!(
                        "expected ",
                        stringify!($len),
                        " bytes of lowercase hex"
                    )));
                }
                let mut out = [0u8; $len];
                hex::decode_to_slice(s, &mut out).map_err(|_| crate::malformed("hex"))?;
                Ok(Self(out))
            }

            /// The lowercase hex form.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
                Self::parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_bytes!(Hex16, 16);
hex_bytes!(Hex32, 32);
hex_bytes!(Hex33, 33);
hex_bytes!(Hex64, 64);

/// Whether `s` is lowercase hex of exactly `len` bytes.
pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len * 2 && lower_hex_chars(s)
}

fn lower_hex_chars(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A decimal number written as plain digits with no leading zero.
pub(crate) fn parse_decimal(s: &str) -> Option<u64> {
    let digits = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

pub(crate) fn strictly_ascending<T: Ord>(list: &[T]) -> bool {
    list.windows(2).all(|w| w[0] < w[1])
}

/// A byte string of any length, carried as lowercase hex.
pub(crate) mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        if s.len() % 2 != 0 || !super::lower_hex_chars(&s) {
            return Err(serde::de::Error::custom("expected lowercase hex"));
        }
        hex::decode(s.as_ref()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_strict() {
        assert!(Hex16::parse(&"ab".repeat(16)).is_ok());
        assert!(Hex16::parse(&"AB".repeat(16)).is_err());
        assert!(Hex16::parse(&"ab".repeat(15)).is_err());
        assert!(Hex16::parse(&"ab".repeat(17)).is_err());
        assert!(Hex16::parse(&format!("{}zz", "ab".repeat(15))).is_err());
        assert!(serde_json::from_str::<Hex32>(&format!("\"{}\"", "0".repeat(64))).is_ok());
        assert!(serde_json::from_str::<Hex32>("1").is_err());
    }

    #[test]
    fn byte_strings_are_lowercase_hex_only() {
        #[derive(serde::Deserialize)]
        struct B(#[serde(with = "hex_vec")] Vec<u8>);
        assert_eq!(
            serde_json::from_str::<B>("\"0aff\"").unwrap().0,
            [0x0a, 0xff]
        );
        assert!(serde_json::from_str::<B>("\"0AFF\"").is_err());
        assert!(serde_json::from_str::<B>("\"0af\"").is_err());
    }

    #[test]
    fn decimals_are_plain_digits() {
        assert_eq!(parse_decimal("0"), Some(0));
        assert_eq!(parse_decimal("120"), Some(120));
        for bad in ["", "01", "+1", "-1", "1.0", " 1", "18446744073709551616"] {
            assert_eq!(parse_decimal(bad), None, "{bad}");
        }
    }
}
