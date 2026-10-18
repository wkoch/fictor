-- Fictor: migração 0004. Aplicar em transação e definir PRAGMA user_version = 4.
-- ADR-036/037. Snapshots UTF-8 exatos; hashes calculados/validados pelo writer.
ALTER TABLE proposals ADD COLUMN review_base_hash TEXT;
ALTER TABLE proposals ADD COLUMN overrides TEXT NOT NULL
  DEFAULT '{"permissions":{},"tools":{}}';

CREATE TABLE promotion_intents (
  operation_id TEXT PRIMARY KEY NOT NULL,
  proposal_id TEXT NOT NULL REFERENCES proposals(id),
  before_lock TEXT,
  before_hash TEXT,
  after_lock TEXT NOT NULL,
  after_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('prepared','committed','aborted')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK ((before_lock IS NULL) = (before_hash IS NULL))
);
CREATE UNIQUE INDEX promotion_one_pending ON promotion_intents((1))
  WHERE state = 'prepared';
CREATE INDEX promotion_by_proposal ON promotion_intents(proposal_id, created_at);
