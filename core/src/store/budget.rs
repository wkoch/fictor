//! Durable admission counters, serialized with every other SQLite write (ADR-017).
use super::{Store, StoreError, now_ms};
use rusqlite::OptionalExtension;

#[derive(Debug, PartialEq, Eq)]
pub struct BudgetExceeded {
    pub scope: &'static str,
    pub limit: u64,
}

/// Civil date in the system timezone at admission. localtime_r has caller-owned
/// storage; unlike localtime it can safely run on concurrent proxy requests.
pub fn local_day() -> Result<String, StoreError> {
    let seconds = now_ms()? / 1000;
    let seconds: libc::time_t = seconds;
    let mut calendar = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: both pointers remain valid for the call, and success initializes tm.
    if unsafe { libc::localtime_r(&seconds, calendar.as_mut_ptr()) }.is_null() {
        return Err(StoreError::Clock);
    }
    // SAFETY: localtime_r succeeded above.
    let calendar = unsafe { calendar.assume_init() };
    Ok(format!(
        "{:04}-{:02}-{:02}",
        calendar.tm_year + 1900,
        calendar.tm_mon + 1,
        calendar.tm_mday
    ))
}

impl Store {
    pub async fn reserve_model_budget(
        &self,
        session: Option<String>,
        day_limit: u64,
        session_limit: u64,
    ) -> Result<Result<(), BudgetExceeded>, StoreError> {
        self.write(move |db| {
            // The writer queue may cross midnight; date belongs to admission here.
            let day = local_day()?;
            let tx = db.transaction()?;
            let now = now_ms()?;
            let mut keys = vec![("day", day, day_limit)];
            if let Some(session) = session {
                let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE id=?1 AND archived=0 AND kind!='system')", [&session], |r| r.get(0))?;
                if !exists { return Err(StoreError::NotFound); }
                keys.push(("session", session, session_limit));
            }
            for (scope, key, limit) in &keys {
                let count: Option<i64> = tx.query_row("SELECT count FROM budget_usage WHERE scope=?1 AND key=?2", (scope, key), |r| r.get(0)).optional()?;
                if count.unwrap_or(0) as u64 >= *limit || count == Some(i64::MAX) {
                    return Ok(Err(BudgetExceeded { scope, limit: *limit }));
                }
            }
            for (scope, key, _) in keys {
                tx.execute("INSERT INTO budget_usage(scope,key,count,updated_at) VALUES (?1,?2,1,?3) ON CONFLICT(scope,key) DO UPDATE SET count=count+1, updated_at=excluded.updated_at", (scope,key,now))?;
            }
            tx.commit()?;
            Ok(Ok(()))
        }).await
    }
}
