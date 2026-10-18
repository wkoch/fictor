-- Fictor: migração 0002. Aplicar em transação e definir PRAGMA user_version = 2.
-- Orçamento do model proxy (02-core.md#orçamento) e flags entre sessões
-- (05-security.md#fluxo-entre-sessões). ADR-014 e ADR-017.

CREATE TABLE budget_usage (
  scope      TEXT NOT NULL CHECK (scope IN ('day', 'session')),
  key        TEXT NOT NULL,                     -- 'YYYY-MM-DD' (data local) ou session_id
  count      INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
  updated_at INTEGER NOT NULL,                  -- unix ms
  PRIMARY KEY (scope, key)
) WITHOUT ROWID;

CREATE TABLE workspace_flags (
  workspace       TEXT PRIMARY KEY,             -- caminho canônico
  flags           INTEGER NOT NULL CHECK (flags IN (0, 1)),   -- bit 0 = U; P não é propagado
  session_id      TEXT REFERENCES sessions(id), -- sessão que acendeu a flag
  source_event_id TEXT,                         -- tool.call que acendeu a flag
  updated_at      INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE ext_flags (                        -- marca d'água de extensões globais (Fase 1)
  ext_id     TEXT PRIMARY KEY,
  flags      INTEGER NOT NULL CHECK (flags BETWEEN 0 AND 3),  -- bit 0 = U, bit 1 = P
  updated_at INTEGER NOT NULL
) WITHOUT ROWID;
