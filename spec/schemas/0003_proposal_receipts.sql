-- Fictor: migração 0003. Aplicar em transação e definir PRAGMA user_version = 3.
-- ADR-035: a tentativa existe antes da identidade validada do manifest.
-- Manter foreign_keys=ON. Nenhuma tabela da Fase 0 referencia proposals.
-- O runner faz o backup antes da transação; 0001/0002 e events não mudam.

CREATE TABLE proposals_v3 (
  id          TEXT PRIMARY KEY,
  ext_id      TEXT,                                      -- NULL enquanto não identificada
  version     TEXT,                                      -- NULL junto com ext_id
  hash        TEXT,
  source      TEXT NOT NULL,
  state       TEXT NOT NULL
              CHECK (state IN ('received', 'checking', 'checked', 'approved', 'rejected', 'promoted', 'failed')),
  update_of   TEXT,
  tainted     INTEGER NOT NULL DEFAULT 0,
  manifest    TEXT,
  checks      TEXT,
  packages    TEXT,
  audit_blob  TEXT,
  nonce       TEXT NOT NULL,
  decided_by  TEXT,
  note        TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  CHECK ((ext_id IS NULL) = (version IS NULL)),
  CHECK (ext_id IS NOT NULL OR state IN ('received', 'failed'))
);

INSERT INTO proposals_v3 (
  id, ext_id, version, hash, source, state, update_of, tainted,
  manifest, checks, packages, audit_blob, nonce, decided_by, note,
  created_at, updated_at
)
SELECT
  id, ext_id, version, hash, source, state, update_of, tainted,
  manifest, checks, packages, audit_blob, nonce, decided_by, note,
  created_at, updated_at
FROM proposals;

DROP TABLE proposals;
ALTER TABLE proposals_v3 RENAME TO proposals;
CREATE INDEX proposals_state ON proposals(state, created_at);
