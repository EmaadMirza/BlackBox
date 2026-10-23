-- L1a ledger schema. Run as the migration owner, never as ledger_app.
BEGIN;

CREATE SCHEMA IF NOT EXISTS blackbox;
REVOKE ALL ON SCHEMA blackbox FROM PUBLIC;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ledger_owner') THEN
        CREATE ROLE ledger_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ledger_app') THEN
        CREATE ROLE ledger_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS blackbox.schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS blackbox.entries (
    log_id TEXT NOT NULL,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    sealed_entry JSONB NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    prev_hash TEXT NOT NULL,
    epoch_id BIGINT NOT NULL CHECK (epoch_id >= 0),
    type TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (log_id, seq)
);
CREATE TABLE IF NOT EXISTS blackbox.checkpoints (
    checkpoint_hash TEXT PRIMARY KEY,
    log_id TEXT NOT NULL,
    tree_size BIGINT NOT NULL CHECK (tree_size >= 0),
    checkpoint JSONB NOT NULL,
    canonical_bytes BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS blackbox.cosignatures (
    checkpoint_hash TEXT NOT NULL REFERENCES blackbox.checkpoints(checkpoint_hash),
    witness_id TEXT NOT NULL,
    cosignature JSONB NOT NULL,
    PRIMARY KEY (checkpoint_hash, witness_id)
);
CREATE TABLE IF NOT EXISTS blackbox.conflicts (
    conflict_id BIGSERIAL PRIMARY KEY,
    log_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    existing_hash TEXT NOT NULL,
    rejected_hash TEXT NOT NULL,
    evidence JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION blackbox.reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'BlackBox storage is append-only: % is forbidden', TG_OP
        USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION blackbox.enforce_entry_contiguity() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    previous_seq BIGINT;
    previous_hash TEXT;
BEGIN
    SELECT e.seq, e.entry_hash INTO previous_seq, previous_hash
    FROM blackbox.entries e WHERE e.log_id = NEW.log_id
    ORDER BY e.seq DESC LIMIT 1 FOR UPDATE;
    IF previous_seq IS NULL THEN
        IF NEW.seq <> 0 THEN
            RAISE EXCEPTION 'entry sequence must begin at zero' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.seq <> previous_seq + 1 OR NEW.prev_hash <> previous_hash THEN
            RAISE EXCEPTION 'entry sequence or predecessor is not contiguous'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS entries_no_mutation ON blackbox.entries;
CREATE TRIGGER entries_no_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.entries
FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
DROP TRIGGER IF EXISTS checkpoints_no_mutation ON blackbox.checkpoints;
CREATE TRIGGER checkpoints_no_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
DROP TRIGGER IF EXISTS entries_contiguous ON blackbox.entries;
CREATE TRIGGER entries_contiguous
BEFORE INSERT ON blackbox.entries
FOR EACH ROW EXECUTE FUNCTION blackbox.enforce_entry_contiguity();

REVOKE ALL ON ALL TABLES IN SCHEMA blackbox FROM PUBLIC;
GRANT USAGE ON SCHEMA blackbox TO ledger_app;
GRANT SELECT, INSERT ON blackbox.entries, blackbox.conflicts TO ledger_app;
GRANT SELECT ON blackbox.schema_version, blackbox.checkpoints, blackbox.cosignatures TO ledger_app;
GRANT USAGE, SELECT ON SEQUENCE blackbox.conflicts_conflict_id_seq TO ledger_app;

INSERT INTO blackbox.schema_version(version) VALUES (1) ON CONFLICT (version) DO NOTHING;
COMMIT;
