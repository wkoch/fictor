//! Trusted in-memory publication after the durable promotion transaction.
use crate::{admin::MutationReason, store::PromotionIntent};
use std::{future::Future, pin::Pin};

pub type PromotionPublicationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), MutationReason>> + Send + 'a>>;

/// The coordinator holds the installer's gate throughout every callback.
/// Publication failures retain admission blocks; no callback starts a process
/// or substitutes for the lock/journal validation performed by the coordinator.
pub trait PromotionPublication: Send + Sync {
    fn block_before_lock(&self, ext_id: &str) -> Result<(), MutationReason>;
    fn publish_after_commit<'a>(
        &'a self,
        intent: &'a PromotionIntent,
    ) -> PromotionPublicationFuture<'a>;
    fn reconcile<'a>(&'a self, intent: &'a PromotionIntent) -> PromotionPublicationFuture<'a>;
}
