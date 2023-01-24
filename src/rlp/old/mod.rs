pub mod decode;
pub mod encode;

pub use decode::{Decodable, DecoderError};
pub use encode::Encodable;

use crate::merkle::nibble::{NibbleType, NibbleVec};

pub use encode::encode;

pub use decode::decode;
