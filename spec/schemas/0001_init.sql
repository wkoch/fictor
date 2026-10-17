-- Fictor: migração inicial. Aplicar em transação e definir PRAGMA user_version = 1.
-- Pragmas de conexão (journal_mode=WAL, foreign_keys=ON, busy_timeout, synchronous=NORMAL)
-- são definidos pelo core ao abrir cada conexão.

CREATE TABLE sessions (
  id                TEXT PRIMARY KEY,                    -- ULID; 'sys' é reservado
  kind              TEXT NOT NULL DEFAULT 'normal'
                    CHECK (kind IN ('normal', 'delegated', 'eval', 'system')),
  title             TEXT NOT NULL DEFAULT '',
  workspace         TEXT,                                -- caminho absoluto canônico; NULL em 'sys'
  workspace_trust   TEXT NOT NULL DEFAULT 'trusted'
                    CHECK (workspace_trust IN ('trusted', 'untrusted')),
  harness           TEXT,                                -- ext_id com role=harness
  mode              TEXT NOT NULL DEFAULT 'default'
                    CHECK (mode IN ('plan', 'default', 'auto')),
  model             TEXT,                                -- opaco para o core
  ext_overrides     TEXT NOT NULL DEFAULT '{}',          -- JSON {ext_id: chave do lock}; usado por evals
  parent_session_id TEXT REFERENCES sessions(id),
  fork_event_id     TEXT,                                -- evento do pai onde a sessão ramificou
  head_id           TEXT,                                -- último evento desta sessão
  archived          INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL,                    -- unix ms
  updated_at        INTEGER NOT NULL
);

CREATE INDEX sessions_parent ON sessions(parent_session_id);
CREATE INDEX sessions_updated ON sessions(archived, updated_at);

CREATE TABLE events (
  seq         INTEGER PRIMARY KEY,                       -- rowid; content_rowid do FTS
  id          TEXT NOT NULL UNIQUE,                      -- ULID
  parent_id   TEXT REFERENCES events(id),
  session_id  TEXT NOT NULL REFERENCES sessions(id),
  kind        TEXT NOT NULL,
  actor       TEXT NOT NULL,                             -- 'user' | 'core' | 'ext:<id>' | 'ext:<id>@ui'
  payload     TEXT NOT NULL,                             -- JSON; {"$blob": "sha256:..."} se > 64 KiB
  blob_refs   TEXT NOT NULL DEFAULT '[]',                -- JSON array de 'sha256:<hex>'
  trust       TEXT NOT NULL CHECK (trust IN ('trusted', 'untrusted')),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public', 'private')),
  source      TEXT NOT NULL DEFAULT '',
  flags       INTEGER NOT NULL DEFAULT 0,                -- cumulativo: bit 0 = U, bit 1 = P
  text        TEXT,                                      -- texto pesquisável (opcional)
  created_at  INTEGER NOT NULL
);

CREATE INDEX events_session ON events(session_id, seq);
CREATE INDEX events_parent ON events(parent_id);
CREATE INDEX events_kind ON events(kind, seq);

CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN
  SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN
  SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE VIRTUAL TABLE events_fts USING fts5(
  text,
  content = 'events',
  content_rowid = 'seq',
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER events_fts_insert AFTER INSERT ON events
WHEN new.text IS NOT NULL
BEGIN
  INSERT INTO events_fts(rowid, text) VALUES (new.seq, new.text);
END;

CREATE TABLE kv (
  ns         TEXT NOT NULL,                              -- ext_id ou 'core'
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,                              -- JSON, até 1 MiB
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (ns, key)
) WITHOUT ROWID;

CREATE TABLE approvals (
  id         TEXT PRIMARY KEY,
  session_id TEXT REFERENCES sessions(id),
  kind       TEXT NOT NULL CHECK (kind IN ('tool', 'custom')),
  request    TEXT NOT NULL,                              -- JSON exibido ao usuário
  nonce      TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'pending'
             CHECK (status IN ('pending', 'allowed', 'denied', 'cancelled')),
  scope      TEXT CHECK (scope IN ('once', 'session', 'always')),
  message    TEXT,                                       -- texto do usuário ao negar
  created_at INTEGER NOT NULL,
  decided_at INTEGER
);

CREATE INDEX approvals_pending ON approvals(status, created_at);

CREATE TABLE grants (
  id          TEXT PRIMARY KEY,
  session_id  TEXT REFERENCES sessions(id),              -- NULL = permanente
  tool        TEXT NOT NULL,                             -- nome exposto exato
  approval_id TEXT REFERENCES approvals(id),
  created_at  INTEGER NOT NULL
);

CREATE INDEX grants_lookup ON grants(tool, session_id);

CREATE TABLE proposals (
  id          TEXT PRIMARY KEY,
  ext_id      TEXT NOT NULL,
  version     TEXT NOT NULL,
  hash        TEXT,                                      -- preenchido após o passo de hash
  source      TEXT NOT NULL,                             -- JSON {kind, ...}
  state       TEXT NOT NULL
              CHECK (state IN ('received', 'checking', 'checked', 'approved', 'rejected', 'promoted', 'failed')),
  update_of   TEXT,                                      -- chave do lock ativa no momento
  tainted     INTEGER NOT NULL DEFAULT 0,                -- veio de sessão com U
  manifest    TEXT,                                      -- JSON normalizado
  checks      TEXT,                                      -- JSON com resultados
  packages    TEXT,                                      -- JSON com pacotes resolvidos
  audit_blob  TEXT,                                      -- relatório do auditor (Fase 3)
  nonce       TEXT NOT NULL,
  decided_by  TEXT,                                      -- 'user' | 'auto:dev-profile'
  note        TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE INDEX proposals_state ON proposals(state, created_at);

CREATE TABLE timers (
  ext_id  TEXT NOT NULL,
  id      TEXT NOT NULL,
  cron    TEXT,
  at_ms   INTEGER,
  payload TEXT,                                          -- JSON
  next_at INTEGER NOT NULL,
  PRIMARY KEY (ext_id, id),
  CHECK ((cron IS NULL) <> (at_ms IS NULL))
) WITHOUT ROWID;

CREATE INDEX timers_due ON timers(next_at);

CREATE TABLE web_sessions (
  id         TEXT PRIMARY KEY,                           -- valor do cookie (hash, não o valor bruto)
  csrf       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
