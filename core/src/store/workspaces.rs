//! Durable workspace U accounting. Only trusted core policy may call the setter:
//! it must already have admitted a non-read tool whose effective fs.write
//! contains `${workspace}`. Extensions never supply this eligibility decision.
//!
//! Human clearing is intentionally absent until its effect on overlapping
//! workspaces is specified. No workspace operation propagates P.
use super::{Event, Sensitivity, Store, StoreError, Trust, events, now_ms, sessions};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use std::path::{Component, Path, PathBuf};

impl Store {
    /// Read the mark shared by this canonical directory and overlapping trees.
    /// Symbolic-link paths are canonicalized before comparing whole components.
    pub async fn workspace_untrusted(&self, workspace: PathBuf) -> Result<bool, StoreError> {
        let owner = self.owner().clone();
        self.read(move |db| {
            owner
                .verify()
                .map_err(|_| StoreError::Invalid("workspace owner changed"))?;
            let workspace = canonical_workspace(&workspace, owner.home())?;
            marked(db, &workspace, owner.home())
        })
        .await
    }

    /// Commit workspace U and its audit before the caller executes the tool.
    /// The caller supplies policy eligibility, never an extension or tool result.
    /// A durable `tool.call` in this session is mandatory provenance. Repeated
    /// writes to an already-marked exact root keep its original provenance and
    /// do not produce another flag transition. Overlap alone does not suppress
    /// a new exact mark: that root must retain its own durable contamination.
    pub async fn flag_workspace_for_tool(
        &self,
        session_id: String,
        source_event_id: String,
    ) -> Result<bool, StoreError> {
        let owner = self.owner().clone();
        self.with_writer(move |writer| {
            owner.verify().map_err(|_| StoreError::Invalid("workspace owner changed"))?;
            let event_id = writer.next_id()?;
            let timestamp = now_ms()?;
            let tx = writer.db.transaction()?;
            let session = sessions::get(&tx, &session_id)?;
            if session.archived { return Err(StoreError::Invalid("sessão arquivada")); }
            let source = events::get(&tx, &source_event_id)?;
            if source.session_id != session_id || source.kind != "tool.call" || source.actor != "core" {
                return Err(StoreError::Invalid("invalid workspace source event"));
            }
            let stored = session.workspace.as_deref().ok_or(StoreError::Invalid("sessão sem workspace"))?;
            let workspace = canonical_workspace(Path::new(stored), owner.home())?;
            if workspace.as_os_str() != Path::new(stored).as_os_str() {
                return Err(StoreError::Invalid("workspace changed"));
            }
            // Confirm all persisted roots are well-formed before accounting for
            // another one; a damaged row must never silently lose its mark.
            let _ = marked(&tx, &workspace, owner.home())?;
            if !session.flags.untrusted { return Ok(false); }
            if !source.flags.untrusted {
                return Err(StoreError::Invalid("workspace source predates contamination"));
            }
            let workspace = workspace.to_str().ok_or(StoreError::Invalid("workspace deve ser UTF-8"))?;
            let previous: Option<i64> = tx.query_row("SELECT flags FROM workspace_flags WHERE workspace=?1", [workspace], |row| row.get(0)).optional()?;
            if previous == Some(1) { return Ok(false); }
            tx.execute("INSERT INTO workspace_flags(workspace,flags,session_id,source_event_id,updated_at) VALUES(?1,1,?2,?3,?4) ON CONFLICT(workspace) DO UPDATE SET flags=1,session_id=excluded.session_id,source_event_id=excluded.source_event_id,updated_at=excluded.updated_at",
                params![workspace,session_id,source_event_id,timestamp])?;
            let system = sessions::get(&tx, "sys")?;
            let event = Event {
                id: event_id, parent_id: system.head_id, session_id: "sys".into(),
                kind: "workspace.flagged".into(), actor: "core".into(),
                payload: json!({"workspace":workspace,"flag":"U","session_id":session_id,"source_event_id":source_event_id}),
                blob_refs: vec![], trust: Trust::Trusted, sensitivity: Sensitivity::Public,
                source: "core".into(), flags: system.flags, text: None, created_at: timestamp,
            };
            events::insert(&tx, &event)?;
            tx.execute("UPDATE sessions SET head_id=?1,updated_at=?2 WHERE id='sys'", params![event.id,timestamp])?;
            tx.commit()?;
            Ok(true)
        }).await
    }
}

fn canonical_workspace(workspace: &Path, home: &Path) -> Result<PathBuf, StoreError> {
    if !workspace.is_absolute() {
        return Err(StoreError::Invalid("workspace deve ser absoluto"));
    }
    let canonical = workspace.canonicalize()?;
    if !canonical.is_dir()
        || canonical.parent().is_none()
        || canonical.starts_with(home)
        || home.starts_with(&canonical)
    {
        return Err(StoreError::Invalid("invalid workspace directory"));
    }
    canonical
        .to_str()
        .ok_or(StoreError::Invalid("workspace deve ser UTF-8"))?;
    Ok(canonical)
}

fn marked(db: &Connection, workspace: &Path, home: &Path) -> Result<bool, StoreError> {
    let mut query = db.prepare("SELECT workspace,flags FROM workspace_flags")?;
    let mut rows = query.query([])?;
    let mut untrusted = false;
    while let Some(row) = rows.next()? {
        let text: String = row.get(0)?;
        let path = Path::new(&text);
        let bits: i64 = row.get(1)?;
        let normalized = path.components().collect::<PathBuf>();
        if !matches!(bits, 0 | 1)
            || !path.is_absolute()
            || path.parent().is_none()
            || text.contains('\0')
            || normalized.as_os_str() != path.as_os_str()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            || path.starts_with(home)
            || home.starts_with(path)
        {
            return Err(StoreError::Invalid("invalid workspace flag snapshot"));
        }
        untrusted |= bits == 1 && (workspace.starts_with(path) || path.starts_with(workspace));
    }
    Ok(untrusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Mode,
        store::{AppendEvent, Flags, NewSession, Provenance},
    };
    use std::{fs, os::unix::fs::symlink};

    struct Fixture {
        root: tempfile::TempDir,
        home: PathBuf,
        workspace: PathBuf,
        store: Store,
    }
    impl Fixture {
        async fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("home");
            crate::home::prepare(&home).unwrap();
            let workspace = root.path().join("a");
            fs::create_dir(&workspace).unwrap();
            let store = Store::open(&home).await.unwrap();
            Self {
                root,
                home,
                workspace,
                store,
            }
        }
        async fn session(&self, workspace: &Path) -> String {
            self.store
                .create_session(NewSession {
                    title: "Workspace fixture".into(),
                    workspace: workspace.into(),
                    workspace_trust: Trust::Trusted,
                    harness: "fixture".into(),
                    mode: Mode::Default,
                    model: Some("fixture".into()),
                })
                .await
                .unwrap()
                .id
        }
        async fn call(&self, session_id: &str, untrusted: bool, private: bool) -> Event {
            if untrusted || private {
                self.store
                    .append(AppendEvent {
                        session_id: session_id.into(),
                        parent_id: None,
                        kind: "fixture.input".into(),
                        actor: "core".into(),
                        payload: json!({}),
                        blob_refs: vec![],
                        provenance: Provenance {
                            trust: if untrusted {
                                Trust::Untrusted
                            } else {
                                Trust::Trusted
                            },
                            sensitivity: if private {
                                Sensitivity::Private
                            } else {
                                Sensitivity::Public
                            },
                            source: "fixture".into(),
                        },
                    })
                    .await
                    .unwrap();
            }
            self.store.append(AppendEvent { session_id: session_id.into(), parent_id: None, kind: "tool.call".into(), actor: "core".into(), payload: json!({"call_id":"fixture","name":"fixture__write","arguments":{},"origin":"harness"}), blob_refs: vec![], provenance: Provenance::core() }).await.unwrap()
        }
        async fn flags(&self) -> Vec<(String, i64, String, String)> {
            self.store.read(|db| {
                let mut query = db.prepare("SELECT workspace,flags,session_id,source_event_id FROM workspace_flags ORDER BY workspace")?;
                query.query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?.collect::<Result<Vec<_>,_>>().map_err(Into::into)
            }).await.unwrap()
        }
        async fn audits(&self) -> Vec<Event> {
            self.store
                .event_path("sys".into(), None, None)
                .await
                .unwrap()
                .events
                .into_iter()
                .filter(|event| event.kind == "workspace.flagged")
                .collect()
        }
    }

    #[tokio::test]
    async fn workspace_u_is_durable_and_shared_by_overlapping_roots_and_canonical_aliases() {
        let fixture = Fixture::new().await;
        let child = fixture.workspace.join("child");
        fs::create_dir(&child).unwrap();
        let sibling = fixture.root.path().join("ab");
        fs::create_dir(&sibling).unwrap();
        let alias = fixture.root.path().join("alias");
        symlink(&fixture.workspace, &alias).unwrap();
        let session = fixture.session(&child).await;
        let call = fixture.call(&session, true, true).await;
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(session.clone(), call.id.clone())
                .await
                .unwrap()
        );
        for path in [&child, &fixture.workspace, &alias] {
            assert!(
                fixture
                    .store
                    .workspace_untrusted(path.clone())
                    .await
                    .unwrap()
            );
        }
        assert!(!fixture.store.workspace_untrusted(sibling).await.unwrap());
        let rows = fixture.flags().await;
        assert_eq!(
            rows,
            vec![(
                child.to_str().unwrap().into(),
                1,
                session.clone(),
                call.id.clone()
            )]
        );
        let audit = fixture.audits().await.remove(0);
        assert_eq!(
            audit.payload,
            json!({"workspace":child,"flag":"U","session_id":session,"source_event_id":call.id})
        );
        assert_eq!(audit.actor, "core");
        assert_eq!(audit.session_id, "sys");
        assert_eq!(audit.flags, Flags::default());
        assert_eq!(audit.trust, Trust::Trusted);
        assert_eq!(audit.sensitivity, Sensitivity::Public);
        let Fixture {
            root,
            home,
            workspace,
            store,
        } = fixture;
        store.shutdown().await.unwrap();
        let reopened = Store::open(&home).await.unwrap();
        assert!(reopened.workspace_untrusted(workspace).await.unwrap());
        reopened.shutdown().await.unwrap();
        drop(root);
    }

    #[tokio::test]
    async fn trusted_or_private_only_calls_never_set_workspace_u() {
        let fixture = Fixture::new().await;
        for private in [false, true] {
            let session = fixture.session(&fixture.workspace).await;
            let call = fixture.call(&session, false, private).await;
            assert!(
                !fixture
                    .store
                    .flag_workspace_for_tool(session, call.id)
                    .await
                    .unwrap()
            );
        }
        assert!(fixture.flags().await.is_empty());
        assert!(fixture.audits().await.is_empty());
    }

    #[tokio::test]
    async fn workspace_marks_require_the_same_sessions_real_tainted_tool_call() {
        let fixture = Fixture::new().await;
        let first = fixture.session(&fixture.workspace).await;
        let second = fixture.session(&fixture.workspace).await;
        let old_clean_call = fixture.call(&first, false, false).await;
        let call = fixture.call(&first, true, false).await;
        fixture.call(&second, true, false).await;
        for (session, source) in [
            (second, call.id.clone()),
            (first.clone(), old_clean_call.id),
            (first.clone(), "missing".into()),
        ] {
            assert!(
                fixture
                    .store
                    .flag_workspace_for_tool(session, source)
                    .await
                    .is_err()
            );
        }
        let non_call = fixture
            .store
            .append(AppendEvent {
                session_id: first.clone(),
                parent_id: None,
                kind: "fixture.event".into(),
                actor: "core".into(),
                payload: json!({}),
                blob_refs: vec![],
                provenance: Provenance::core(),
            })
            .await
            .unwrap();
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(first.clone(), non_call.id)
                .await
                .is_err()
        );
        let wrong_actor = fixture
            .store
            .append(AppendEvent {
                session_id: first.clone(),
                parent_id: None,
                kind: "tool.call".into(),
                actor: "ext:fixture".into(),
                payload: json!({}),
                blob_refs: vec![],
                provenance: Provenance::core(),
            })
            .await
            .unwrap();
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(first, wrong_actor.id)
                .await
                .is_err()
        );
        assert!(fixture.flags().await.is_empty());
        assert!(fixture.audits().await.is_empty());
    }

    #[tokio::test]
    async fn exact_mark_deduplicates_but_an_overlapping_root_keeps_its_own_provenance() {
        let fixture = Fixture::new().await;
        let child = fixture.workspace.join("child");
        fs::create_dir(&child).unwrap();
        let parent_session = fixture.session(&fixture.workspace).await;
        let child_session = fixture.session(&child).await;
        let first = fixture.call(&parent_session, true, false).await;
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(parent_session.clone(), first.id.clone())
                .await
                .unwrap()
        );
        assert!(
            fixture
                .store
                .workspace_untrusted(child.clone())
                .await
                .unwrap()
        );
        let original = fixture.flags().await;
        let second = fixture.call(&parent_session, false, false).await;
        for source in [first.id, second.id] {
            assert!(
                !fixture
                    .store
                    .flag_workspace_for_tool(parent_session.clone(), source)
                    .await
                    .unwrap()
            );
        }
        assert_eq!(fixture.flags().await, original);
        assert_eq!(fixture.audits().await.len(), 1);
        let child_call = fixture.call(&child_session, true, false).await;
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(child_session, child_call.id)
                .await
                .unwrap()
        );
        assert_eq!(fixture.flags().await.len(), 2);
        assert_eq!(fixture.audits().await.len(), 2);
    }

    #[tokio::test]
    async fn a_failed_workspace_audit_rolls_back_the_mark_and_the_system_head() {
        let fixture = Fixture::new().await;
        let session = fixture.session(&fixture.workspace).await;
        let call = fixture.call(&session, true, false).await;
        let before = fixture.store.session("sys".into()).await.unwrap().head_id;
        fixture.store.write(|db| { db.execute_batch("CREATE TRIGGER refuse_workspace_audit BEFORE INSERT ON events WHEN NEW.kind='workspace.flagged' BEGIN SELECT RAISE(ABORT,'fixture'); END;")?; Ok(()) }).await.unwrap();
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(session.clone(), call.id.clone())
                .await
                .is_err()
        );
        assert!(fixture.flags().await.is_empty());
        assert_eq!(
            fixture.store.session("sys".into()).await.unwrap().head_id,
            before
        );
        fixture
            .store
            .write(|db| {
                db.execute_batch("DROP TRIGGER refuse_workspace_audit")?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(session, call.id)
                .await
                .unwrap()
        );
        assert_eq!(fixture.audits().await.len(), 1);
    }

    #[tokio::test]
    async fn a_retargeted_workspace_or_malformed_persisted_root_fails_closed() {
        let fixture = Fixture::new().await;
        let session = fixture.session(&fixture.workspace).await;
        let call = fixture.call(&session, true, false).await;
        let moved = fixture.root.path().join("moved");
        fs::rename(&fixture.workspace, &moved).unwrap();
        symlink(&moved, &fixture.workspace).unwrap();
        assert!(
            fixture
                .store
                .flag_workspace_for_tool(session, call.id)
                .await
                .is_err()
        );
        fixture.store.write(|db| { db.execute("INSERT INTO workspace_flags(workspace,flags,updated_at) VALUES('/tmp/../unsafe',1,0)", [])?; Ok(()) }).await.unwrap();
        assert!(fixture.store.workspace_untrusted(moved).await.is_err());
        assert!(fixture.audits().await.is_empty());
    }
}
