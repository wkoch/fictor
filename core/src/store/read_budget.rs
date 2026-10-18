//! Kernel read results are counted in their escaped JSON representation before
//! retaining another item. This bounds accumulation, not just the final frame.
use super::StoreError;
use serde::Serialize;
use std::io::{self, Write};

pub(super) struct ReadBudget {
    remaining: usize,
}
impl ReadBudget {
    pub(super) fn new(limit: usize, fixed_bytes: usize) -> Result<Self, StoreError> {
        Ok(Self {
            remaining: limit.checked_sub(fixed_bytes).ok_or(StoreError::TooLarge)?,
        })
    }
    pub(super) fn item(&mut self, value: &impl Serialize, comma: bool) -> Result<(), StoreError> {
        if comma {
            self.write_all(b",").map_err(|_| StoreError::TooLarge)?;
        }
        self.value(value)
    }
    pub(super) fn value(&mut self, value: &impl Serialize) -> Result<(), StoreError> {
        serde_json::to_writer(self, value).map_err(|error| {
            if error.is_io() {
                StoreError::TooLarge
            } else {
                StoreError::Json(error)
            }
        })
    }
}
impl Write for ReadBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("read response limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
