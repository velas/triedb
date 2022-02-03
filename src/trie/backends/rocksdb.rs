#![allow(unused)] // FIXME: delete this line

use std::borrow::Cow;

use primitive_types::H256;

use crate::database::{Database, DatabaseMut};

pub struct RocksBackend;

impl Database for RocksBackend {
    fn get(&self, key: H256) -> &[u8] {
        todo!()
    }
}

impl DatabaseMut for RocksBackend {
    fn gc_insert_node<F>(&self, key: H256, value: &[u8], child_extractor: F)
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        todo!()
    }

    fn gc_try_cleanup_node<F>(&self, key: H256, child_extractor: F) -> Vec<H256>
    where
        F: FnMut(&[u8]) -> Vec<H256>,
    {
        todo!()
    }

    fn gc_pin_root(&self, root: H256) {
        todo!()
    }

    fn gc_unpin_root(&self, root: H256) -> bool {
        todo!()
    }

    fn gc_count(&self, key: H256) -> usize {
        todo!()
    }

    fn node_exist(&self, key: H256) -> bool {
        todo!()
    }
}
