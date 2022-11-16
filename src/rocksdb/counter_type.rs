use rocksdb_lib::MergeOperands;

pub fn serialize_counter(counter: i64) -> [u8; 8] {
    counter.to_le_bytes()
}

pub fn deserialize_counter(counter: &[u8]) -> i64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(counter);
    i64::from_le_bytes(bytes)
}
pub fn merge_counter(
    key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let mut val = existing_val.map(deserialize_counter).unwrap_or_default();
    assert_eq!(key.len(), 32);
    for op in operands.iter() {
        let diff = deserialize_counter(op);
        // this assertion is incorrect because rocks can merge multiple values into one.
        // assert!(diff == -1 || diff == 1);
        val += diff;
    }
    Some(serialize_counter(val).to_vec())
}
