//! Merkle nibble types.

use std::{cmp::min, hash::Hash};

use bytes::Buf;
use rlp::{Rlp, RlpStream};

use crate::Result;

/// Represents a nibble. A 16-variant value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Nibble {
    N0 = 0,
    N1,
    N2,
    N3,
    N4,
    N5,
    N6,
    N7,
    N8,
    N9,
    N10,
    N11,
    N12,
    N13,
    N14,
    N15,
}

impl From<usize> for Nibble {
    fn from(val: usize) -> Nibble {
        match val {
            0 => Nibble::N0,
            1 => Nibble::N1,
            2 => Nibble::N2,
            3 => Nibble::N3,
            4 => Nibble::N4,
            5 => Nibble::N5,
            6 => Nibble::N6,
            7 => Nibble::N7,
            8 => Nibble::N8,
            9 => Nibble::N9,
            10 => Nibble::N10,
            11 => Nibble::N11,
            12 => Nibble::N12,
            13 => Nibble::N13,
            14 => Nibble::N14,
            15 => Nibble::N15,
            _ => panic!(),
        }
    }
}

impl From<Nibble> for usize {
    fn from(nibble: Nibble) -> usize {
        nibble as usize
    }
}

impl From<u8> for Nibble {
    fn from(val: u8) -> Nibble {
        match val {
            0 => Nibble::N0,
            1 => Nibble::N1,
            2 => Nibble::N2,
            3 => Nibble::N3,
            4 => Nibble::N4,
            5 => Nibble::N5,
            6 => Nibble::N6,
            7 => Nibble::N7,
            8 => Nibble::N8,
            9 => Nibble::N9,
            10 => Nibble::N10,
            11 => Nibble::N11,
            12 => Nibble::N12,
            13 => Nibble::N13,
            14 => Nibble::N14,
            15 => Nibble::N15,
            _ => panic!(),
        }
    }
}

impl From<Nibble> for u8 {
    fn from(nibble: Nibble) -> u8 {
        nibble as u8
    }
}

/// A nibble type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NibbleType {
    Leaf,
    Extension,
}

/// A nibble vector.
pub type NibbleVec = Vec<Nibble>;
/// A nibble slice.
pub type NibbleSlice<'a> = &'a [Nibble];

/// Given a key, return the corresponding nibble.
pub fn from_key(key: &[u8]) -> NibbleVec {
    let mut vec = NibbleVec::new();

    for i in 0..(key.len() * 2) {
        if i & 1 == 0 {
            // even
            vec.push(((key[i / 2] & 0xf0) >> 4).into());
        } else {
            vec.push((key[i / 2] & 0x0f).into());
        }
    }

    vec
}

/// Given a nibble, return the corresponding key.
pub fn into_key(nibble: NibbleSlice) -> Vec<u8> {
    let mut ret = Vec::new();

    for i in 0..nibble.len() {
        let value: u8 = nibble[i].into();
        if i & 1 == 0 {
            // even
            ret.push(value << 4);
        } else {
            ret[i / 2] |= value;
        }
    }

    ret
}

// Check if this rlp list consume all buffer, with given number of items.
pub(crate) fn is_list_consume_rlp(mut buf: &[u8], num: usize) -> bool {
    let buf = &mut buf;
    for _i in 0..num {
        let Ok(h) = fastrlp::Header::decode(buf) else {
            return false
        };
        if h.payload_length > buf.len() {
            return false;
        }
        buf.advance(h.payload_length);
    }
    buf.is_empty()
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NibblePair(pub NibbleVec, pub NibbleType);

impl NibblePair {
    // 1 byte prefix + ceil(len_in_nible / 2)
    // exampe:
    // 1 nibble  = 1 + 0
    // 2 nibbles = 1 + 1
    // 3 nibbles = 1 + 1
    // ...
    fn payload_length(&self) -> usize {
        1 + self.0.len() / 2
    }
    // If we have zero or one nible, it's byte representation would be less < EMPTY_STRING_CODE(0x80), and be serialized as single byte without length prefix
    fn skip_rlp_header(&self) -> bool {
        self.payload_length() == 1
    }
}

impl<'de> fastrlp::Decodable<'de> for NibblePair {
    fn decode(buf: &mut &'de [u8]) -> Result<NibblePair, fastrlp::DecodeError> {
        let h = fastrlp::Header::decode(buf)?;
        if h.list {
            return Err(fastrlp::DecodeError::UnexpectedList);
        }

        let data = &buf[..h.payload_length];
        buf.advance(h.payload_length);

        let start_odd = data[0] & 0b00010000 == 0b00010000;
        let is_leaf = data[0] & 0b00100000 == 0b00100000;

        let start_index = if start_odd { 1 } else { 2 };

        let len = data.len() * 2;

        let mut vec = NibbleVec::with_capacity(len);

        for i in start_index..len {
            if i & 1 == 0 {
                // even
                vec.push(((data[i / 2] & 0xf0) >> 4).into());
            } else {
                vec.push((data[i / 2] & 0x0f).into());
            }
        }

        Ok(NibblePair(
            vec,
            if is_leaf {
                NibbleType::Leaf
            } else {
                NibbleType::Extension
            },
        ))
    }
}

impl fastrlp::Encodable for NibblePair {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let payload_length = self.payload_length();
        if !self.skip_rlp_header() {
            fastrlp::Header {
                payload_length: payload_length,
                list: false,
            }
            .encode(out);
        }
        let typ = match self.1 {
            NibbleType::Leaf => 0b00100000,
            NibbleType::Extension => 0b00000000,
        };
        if self.0.len() % 2 == 0 {
            // even
            out.put_u8(0b00000000 | typ);

            let mut last_u8 = 0;
            for (i, val) in self.0.iter().enumerate() {
                let v: u8 = (*val).into();
                if i % 2 == 0 {
                    last_u8 = v << 4;
                } else {
                    last_u8 |= v;
                    out.put_u8(last_u8);
                }
            }
        } else {
            let mut last_u8 = 0b00010000 | typ;

            for (i, val) in self.0.iter().enumerate() {
                let v: u8 = (*val).into();
                if i % 2 == 0 {
                    last_u8 |= v;
                    out.put_u8(last_u8)
                } else {
                    last_u8 = v << 4;
                }
            }
        }
    }
    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        if !self.skip_rlp_header() {
            return fastrlp::Header {
                payload_length,
                list: false,
            }
            .length()
                + payload_length;
        };
        payload_length
    }
}

// /// Decode a nibble from RLP.
// pub fn decode(rlp: &Rlp) -> Result<(NibbleVec, NibbleType)> {
//     let mut vec = NibbleVec::new();

//     let data = rlp.data()?;
//     let start_odd = data[0] & 0b00010000 == 0b00010000;
//     let start_index = if start_odd { 1 } else { 2 };
//     let is_leaf = data[0] & 0b00100000 == 0b00100000;

//     let len = data.len() * 2;

//     for i in start_index..len {
//         if i & 1 == 0 {
//             // even
//             vec.push(((data[i / 2] & 0xf0) >> 4).into());
//         } else {
//             vec.push((data[i / 2] & 0x0f).into());
//         }
//     }

//     Ok((
//         vec,
//         if is_leaf {
//             NibbleType::Leaf
//         } else {
//             NibbleType::Extension
//         },
//     ))
// }

impl rlp::Encodable for NibblePair {
    fn rlp_append(&self, s: &mut RlpStream) {
        let mut ret: Vec<u8> = Vec::new();

        if self.0.len() & 1 == 0 {
            // even
            ret.push(0b00000000);

            for (i, val) in self.0.iter().enumerate() {
                if i & 1 == 0 {
                    let v: u8 = (*val).into();
                    ret.push(v << 4);
                } else {
                    let end = ret.len() - 1;
                    let v: u8 = (*val).into();
                    ret[end] |= v;
                }
            }
        } else {
            ret.push(0b00010000);

            for (i, val) in self.0.iter().enumerate() {
                if i & 1 == 0 {
                    let end = ret.len() - 1;
                    let v: u8 = (*val).into();
                    ret[end] |= v;
                } else {
                    let v: u8 = (*val).into();
                    ret.push(v << 4);
                }
            }
        }

        ret[0] |= match self.1 {
            NibbleType::Leaf => 0b00100000,
            NibbleType::Extension => 0b00000000,
        };

        s.append(&ret);
    }
}
/// Encode a nibble into the given RLP stream.
pub fn encode(vec: NibbleSlice, typ: NibbleType, s: &mut RlpStream) {
    let mut ret: Vec<u8> = Vec::new();

    if vec.len() & 1 == 0 {
        // even
        ret.push(0b00000000);

        for (i, val) in vec.iter().enumerate() {
            if i & 1 == 0 {
                let v: u8 = (*val).into();
                ret.push(v << 4);
            } else {
                let end = ret.len() - 1;
                let v: u8 = (*val).into();
                ret[end] |= v;
            }
        }
    } else {
        ret.push(0b00010000);

        for (i, val) in vec.iter().enumerate() {
            if i & 1 == 0 {
                let end = ret.len() - 1;
                let v: u8 = (*val).into();
                ret[end] |= v;
            } else {
                let v: u8 = (*val).into();
                ret.push(v << 4);
            }
        }
    }

    ret[0] |= match typ {
        NibbleType::Leaf => 0b00100000,
        NibbleType::Extension => 0b00000000,
    };

    s.append(&ret);
}

/// Common prefix for two nibbles.
pub fn common<'a, 'b>(a: NibbleSlice<'a>, b: NibbleSlice<'b>) -> NibbleSlice<'a> {
    let mut common_len = 0;

    for i in 0..min(a.len(), b.len()) {
        if a[i] == b[i] {
            common_len += 1;
        } else {
            break;
        }
    }

    &a[0..common_len]
}

/// Common prefix for two nibbles. Return the sub nibbles.
pub fn common_with_sub<'a, 'b>(
    a: NibbleSlice<'a>,
    b: NibbleSlice<'b>,
) -> (NibbleSlice<'a>, NibbleVec, NibbleVec) {
    let common = common(a, b);
    let asub = a[common.len()..].into();
    let bsub = b[common.len()..].into();

    (common, asub, bsub)
}

/// Common prefix for all provided nibbles.
pub fn common_all<'a, T: Iterator<Item = NibbleSlice<'a>>>(mut iter: T) -> NibbleSlice<'a> {
    let first = match iter.next() {
        Some(val) => val,
        None => return &[],
    };
    let second = match iter.next() {
        Some(val) => val,
        None => return first,
    };

    let mut common_cur = common(first, second);
    for key in iter {
        common_cur = common(common_cur, key);
    }

    common_cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_into_key() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 244, 233, 188];

        assert_eq!(key, into_key(&from_key(&key)));
    }
}
