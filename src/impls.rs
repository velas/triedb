
#[cfg(test)]
pub mod test_types {
    use std::convert::TryFrom;

    use quickcheck::{Arbitrary, Gen};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    pub struct K(usize);

    impl K {
        pub fn to_bytes(self) -> [u8; 8] {
            self.0.to_be_bytes()
        }

        #[allow(dead_code)]
        pub fn from_bytes(bytes: &[u8]) -> Self {
            Self(usize::from_be_bytes(
                <[u8; std::mem::size_of::<usize>()]>::try_from(bytes).unwrap(),
            ))
        }
    }

    impl Arbitrary for K {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(usize::arbitrary(g))
        }
    }

    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
    pub struct Data(Vec<usize>);

    const AVG_DATA_SIZE: usize = 16;

    impl Arbitrary for Data {
        fn arbitrary(_: &mut Gen) -> Self {
            Self(Vec::arbitrary(&mut Gen::new(AVG_DATA_SIZE)))
        }
    }
}
