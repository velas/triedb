use std::fmt;

use serde::de::{Deserialize, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserializer, Serialize, Serializer};

pub struct EntriesHex {
    pub data: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl EntriesHex {
    pub fn new(data: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Self {
        let res = Self { data };
        log::info!("{}", serde_json::to_string_pretty(&res).unwrap());
        res
    }
}

impl Serialize for EntriesHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.data.len()))?;
        for (key, value) in &self.data {
            let tuple: (String, Option<String>) = (
                hexutil::to_hex(key),
                value.as_ref().map(|value| hexutil::to_hex(value)),
            );
            seq.serialize_element(&tuple)?;
        }
        seq.end()
    }
}
struct TestInputHexVisitor;

impl<'de> Visitor<'de> for TestInputHexVisitor {
    type Value = EntriesHex;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct TestInputHex")
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut out: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![];
        let mut element: Option<(String, Option<String>)> = seq.next_element()?;
        while let Some((key, value)) = element {
            let key_vec: Vec<u8> = hexutil::read_hex(&key).map_err(|err| {
                serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(&format!("{:?}", err)),
                    &self,
                )
            })?;
            let value_vec: Option<Vec<u8>> = match value {
                Some(value) => Some(hexutil::read_hex(&value).map_err(|err| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(&format!("{:?}", err)),
                        &self,
                    )
                })?),
                None => None,
            };
            out.push((key_vec, value_vec));
            element = seq.next_element()?;
        }
        Ok(EntriesHex::new(out))
    }
}

impl<'de> Deserialize<'de> for EntriesHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Instantiate our Visitor and ask the Deserializer to drive
        // it over the input data, resulting in an instance of MyMap.
        deserializer.deserialize_seq(TestInputHexVisitor)
    }
}