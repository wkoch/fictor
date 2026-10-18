-- Fictor: migração 0005. Aplicar em transação e definir PRAGMA user_version = 5.
-- Novo estado derivado e mutável do supervisor; events continua append-only.
CREATE TABLE extension_crash_recovery (
  id              INTEGER PRIMARY KEY,
  ext_id          TEXT NOT NULL,
  bundle_key      TEXT NOT NULL,
  session_id      TEXT REFERENCES sessions(id),
  boot_id         TEXT NOT NULL CHECK (length(boot_id) = 36),
  crashes         TEXT NOT NULL DEFAULT '[]'
                  CHECK (json_valid(crashes) AND json_type(crashes) = 'array'
                         AND json_array_length(crashes) <= 6),
  retry_at_ms     INTEGER NOT NULL DEFAULT 0 CHECK (retry_at_ms >= 0),
  blocked         INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
  updated_at      INTEGER NOT NULL,
  CHECK (session_id IS NULL OR session_id <> 'sys'),
  CHECK ((blocked = 0 AND json_array_length(crashes) <= 5)
      OR (blocked = 1 AND json_array_length(crashes) = 6 AND retry_at_ms = 0))
);

CREATE UNIQUE INDEX extension_crash_global
  ON extension_crash_recovery(ext_id, bundle_key)
  WHERE session_id IS NULL;
CREATE UNIQUE INDEX extension_crash_session
  ON extension_crash_recovery(ext_id, bundle_key, session_id)
  WHERE session_id IS NOT NULL;
