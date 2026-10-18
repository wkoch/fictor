use super::{Store, StoreError, now_ms};
use rusqlite::{OptionalExtension, params};
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
        self.read(move |db| {
            // Prefix is literal, including SQL LIKE metacharacters and Unicode.
            let mut statement = db.prepare("SELECT key,value FROM kv WHERE ns=?1 AND substr(key,1,length(?2))=?2 ORDER BY key LIMIT ?3")?;
            let entries = statement.query_map(params![namespace,prefix,limit.clamp(1,10000) as i64], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?;
            entries.map(|row| { let (key,value)=row?; Ok((key,serde_json::from_str(&value)?)) }).collect()
        }).await
    }
}
