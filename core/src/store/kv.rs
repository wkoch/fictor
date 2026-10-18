use super::{Store, StoreError, now_ms, read_budget::ReadBudget};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;

const MAX_VALUE_BYTES: usize = 1024 * 1024;

impl Store {
    /// Namespace must come from the authenticated instance identity in the Kernel Protocol.
    pub async fn kv_set(
        &self,
        namespace: String,
        key: String,
        value: Value,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(&value)?;
        if json.len() > MAX_VALUE_BYTES {
            return Err(StoreError::TooLarge);
        }
        self.write(move |db| {
            db.execute("INSERT INTO kv (ns,key,value,updated_at) VALUES (?1,?2,?3,?4) ON CONFLICT(ns,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", params![namespace,key,json,now_ms()?])?;
            Ok(())
        }).await
    }

    pub async fn kv_get(
        &self,
        namespace: String,
        key: String,
    ) -> Result<Option<Value>, StoreError> {
        self.read(move |db| {
            let json: Option<String> = db
                .query_row(
                    "SELECT value FROM kv WHERE ns=?1 AND key=?2",
                    params![namespace, key],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(json.map(|json| serde_json::from_str(&json)).transpose()?)
        })
        .await
    }

    pub async fn kv_delete(&self, namespace: String, key: String) -> Result<(), StoreError> {
        self.write(move |db| {
            db.execute(
                "DELETE FROM kv WHERE ns=?1 AND key=?2",
                params![namespace, key],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn kv_list(
        &self,
        namespace: String,
        prefix: String,
        limit: usize,
    ) -> Result<Vec<(String, Value)>, StoreError> {
        self.read(move |db| list(db, namespace, prefix, limit, None))
            .await
    }

    /// Kernel-only variant: includes the `{items:[{key,value}]}` result wrapper.
    pub(crate) async fn kv_list_bounded(
        &self,
        namespace: String,
        prefix: String,
        limit: usize,
        response_limit: usize,
    ) -> Result<Vec<(String, Value)>, StoreError> {
        self.read(move |db| {
            let budget = ReadBudget::new(response_limit, b"{\"items\":[]}".len())?;
            list(db, namespace, prefix, limit, Some(budget))
        })
        .await
    }
}

fn list(
    db: &Connection,
    namespace: String,
    prefix: String,
    limit: usize,
    mut budget: Option<ReadBudget>,
) -> Result<Vec<(String, Value)>, StoreError> {
    // Prefix is literal, including SQL LIKE metacharacters and Unicode.
    let mut statement = db.prepare("SELECT key,value FROM kv WHERE ns=?1 AND substr(key,1,length(?2))=?2 ORDER BY key LIMIT ?3")?;
    let mut rows = statement.query(params![namespace, prefix, limit.clamp(1, 10000) as i64])?;
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        let key: String = row.get(0)?;
        let value: String = row.get(1)?;
        let value: Value = serde_json::from_str(&value)?;
        if let Some(budget) = budget.as_mut() {
            #[derive(Serialize)]
            struct Item<'a> {
                key: &'a str,
                value: &'a Value,
            }
            budget.item(
                &Item {
                    key: &key,
                    value: &value,
                },
                !entries.is_empty(),
            )?;
        }
        entries.push((key, value));
    }
    Ok(entries)
}
