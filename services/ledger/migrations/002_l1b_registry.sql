BEGIN;
CREATE TABLE IF NOT EXISTS blackbox.pinned_roots (
    log_id TEXT PRIMARY KEY,
    root_public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blackbox.intermediates (
    intermediate_id TEXT PRIMARY KEY,
    log_id TEXT NOT NULL,
    certificate JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS blackbox.epochs (
    epoch_certificate_id TEXT PRIMARY KEY,
    log_id TEXT NOT NULL,
    epoch_id BIGINT NOT NULL,
    certificate JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS blackbox.merkle_frontiers (
    log_id TEXT NOT NULL,
    tree_size BIGINT NOT NULL CHECK (tree_size >= 0),
    frontier JSONB NOT NULL,
    root_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (log_id, tree_size)
);
INSERT INTO blackbox.schema_version(version) VALUES (2) ON CONFLICT (version) DO NOTHING;
REVOKE ALL ON blackbox.pinned_roots, blackbox.intermediates, blackbox.epochs FROM PUBLIC;
GRANT SELECT ON blackbox.pinned_roots, blackbox.intermediates, blackbox.epochs TO ledger_app;
GRANT INSERT ON blackbox.pinned_roots, blackbox.intermediates, blackbox.epochs TO ledger_app;
GRANT SELECT, INSERT ON blackbox.merkle_frontiers TO ledger_app;
DROP TRIGGER IF EXISTS merkle_frontiers_no_mutation ON blackbox.merkle_frontiers;
CREATE TRIGGER merkle_frontiers_no_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.merkle_frontiers
FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();
COMMIT;
