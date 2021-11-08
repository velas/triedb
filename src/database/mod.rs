use crate::ValueChange;

use super::{Change, H256};
/// An immutable database handle.
pub trait Database {
    /// Get a raw value from the database.
    fn get(&self, key: H256) -> &[u8];
}

pub trait DatabaseMut: Database {
    fn set(&mut self, key: H256, value: ValueType);
    fn apply_change(&mut self, change: Change) {
        for change in change.change_list {
            match change {
                ValueChange::Add { key, rlp, .. } => self.set(key, ValueType::Added(rlp)),
                ValueChange::Remove { key, .. } => self.set(key, ValueType::Removed),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValueType {
    Removed,
    Added(Vec<u8>),
}
