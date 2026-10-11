-- TODO(spec §10.1): validate migration and caller authorization in Stage 2.
-- Storage scaffold only. Run with a migration owner, NEVER the service role.
BEGIN;
CREATE SCHEMA blackbox;
REVOKE ALL ON SCHEMA blackbox FROM PUBLIC;

-- NOLOGIN group roles: provision login identities out of band; no embedded passwords.
CREATE ROLE blackbox_append NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE blackbox_read NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT USAGE ON SCHEMA blackbox TO blackbox_append, blackbox_read;

CREATE TABLE blackbox.entries (
    log_id TEXT NOT NULL,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    epoch_id BIGINT NOT NULL CHECK (epoch_id >= 0),
    entry_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    sealed_entry JSONB NOT NULL,
    canonical_bytes BYTEA NOT NULL,
    PRIMARY KEY (log_id, seq)
);
CREATE TABLE blackbox.checkpoints (
    checkpoint_hash TEXT PRIMARY KEY,
    log_id TEXT NOT NULL,
    tree_size BIGINT NOT NULL CHECK (tree_size >= 0),
    checkpoint JSONB NOT NULL,
    canonical_bytes BYTEA NOT NULL
);
CREATE TABLE blackbox.cosignatures (
    checkpoint_hash TEXT NOT NULL REFERENCES blackbox.checkpoints(checkpoint_hash),
    witness_id TEXT NOT NULL,
    cosignature JSONB NOT NULL,
    PRIMARY KEY (checkpoint_hash, witness_id)
);
CREATE TABLE blackbox.payload_refs (
    reference TEXT PRIMARY KEY,
    commitment TEXT NOT NULL,
    log_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    FOREIGN KEY (log_id, seq) REFERENCES blackbox.entries(log_id, seq)
);
CREATE TABLE blackbox.approvals (
    receipt_id TEXT PRIMARY KEY,
    log_id TEXT NOT NULL,
    intent_seq BIGINT NOT NULL,
    receipt JSONB NOT NULL,
    FOREIGN KEY (log_id, intent_seq) REFERENCES blackbox.entries(log_id, seq)
);
CREATE TABLE blackbox.findings (
    finding_id TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    detection_time TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL
);
CREATE TABLE blackbox.alarms (
    alarm_id TEXT PRIMARY KEY,
    alarm_type TEXT NOT NULL,
    source TEXT NOT NULL,
    detection_time TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL
);
-- Frontier snapshots are append-only, keyed by covered tree size.
CREATE TABLE blackbox.merkle_frontiers (
    log_id TEXT NOT NULL,
    tree_size BIGINT NOT NULL CHECK (tree_size >= 0),
    frontier JSONB NOT NULL,
    PRIMARY KEY (log_id, tree_size)
);
CREATE FUNCTION blackbox.reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'BlackBox storage is append-only: % is forbidden', TG_OP;
    RETURN NULL;
END;
$$;
CREATE TRIGGER entries_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.entries
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
CREATE TRIGGER checkpoints_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
CREATE TRIGGER cosignatures_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.cosignatures
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
CREATE TRIGGER payload_refs_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.payload_refs
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
CREATE TRIGGER approvals_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.approvals
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
CREATE TRIGGER findings_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.findings
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
CREATE TRIGGER alarms_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.alarms
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
CREATE TRIGGER frontier_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.merkle_frontiers
    FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
REVOKE ALL ON ALL TABLES IN SCHEMA blackbox FROM PUBLIC;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA blackbox TO blackbox_append;
GRANT SELECT ON ALL TABLES IN SCHEMA blackbox TO blackbox_read;
REVOKE ALL ON FUNCTION blackbox.reject_mutation() FROM PUBLIC;
-- No writer owns tables or has UPDATE, DELETE, TRUNCATE, DDL or superuser rights.
-- JSONB is for indexing; signature verification MUST use/rebuild canonical bytes.
-- Gateway/signer caller identity is an API concern, not enforced by these grants.
COMMIT;
