//! One writer snapshot for the trusted administrative installation flow.
use super::{PromotionIntent, Proposal, ProposalNonce, ProposalState, Store, StoreError};
use rusqlite::OptionalExtension;

// Deliberately no Debug/Serialize: the nonce and raw journal snapshots belong
// only to the trusted service, whose response selects the contracted fields.
pub(crate) struct InstallationSnapshot {
    pub proposal: Proposal,
    pub nonce: Option<ProposalNonce>,
    pub promotion: Option<PromotionIntent>,
}

impl Store {
    pub(crate) async fn installation_snapshot(
        &self,
        id: String,
    ) -> Result<InstallationSnapshot, StoreError> {
        self.with_writer(move |writer| {
            let tx = writer.db.transaction()?;
            super::read_promotion_intents(&tx)?;
            let proposal = super::proposals::get(&tx, &id)?;
            if proposal.tainted || proposal.source != serde_json::json!({"kind":"local"}) {
                return Err(StoreError::Invalid("invalid local installation state"));
            }
            let nonce = if proposal.state == ProposalState::Checked {
                let value: String = tx.query_row("SELECT nonce FROM proposals WHERE id=?1", [&id], |row| row.get(0))?;
                Some(ProposalNonce::from_admin(value)?)
            } else { None };
            let operation: Option<String> = tx.query_row(
                "SELECT operation_id FROM promotion_intents WHERE proposal_id=?1 ORDER BY created_at DESC,operation_id DESC LIMIT 1",
                [&id], |row| row.get(0),
            ).optional()?;
            let promotion = operation.map(|operation| super::promotion::load(&tx, &operation)).transpose()?;
            tx.commit()?;
            Ok(InstallationSnapshot { proposal, nonce, promotion })
        }).await
    }
}
