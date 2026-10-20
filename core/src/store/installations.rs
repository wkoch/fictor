//! One writer snapshot for the trusted administrative installation flow.
use super::{PromotionIntent, Proposal, ProposalNonce, ProposalState, Store, StoreError};

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
            let promotion = super::promotion::latest_promotion(&tx, &writer.blobs, &id)?;
            let proposal = super::proposals::get(&tx, &id)?;
            if proposal.tainted || proposal.source != serde_json::json!({"kind":"local"}) {
                return Err(StoreError::Invalid("invalid local installation state"));
            }
            let nonce = if proposal.state == ProposalState::Checked {
                let value: String =
                    tx.query_row("SELECT nonce FROM proposals WHERE id=?1", [&id], |row| {
                        row.get(0)
                    })?;
                Some(ProposalNonce::from_admin(value)?)
            } else {
                None
            };
            tx.commit()?;
            Ok(InstallationSnapshot {
                proposal,
                nonce,
                promotion,
            })
        })
        .await
    }
}
