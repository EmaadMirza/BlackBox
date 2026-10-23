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
INSERT INTO blackbox.schema_version(version) VALUES (2) ON CONFLICT (version) DO NOTHING;
REVOKE ALL ON blackbox.pinned_roots, blackbox.intermediates, blackbox.epochs FROM PUBLIC;
GRANT SELECT ON blackbox.pinned_roots, blackbox.intermediates, blackbox.epochs TO ledger_app;
GRANT INSERT ON blackbox.pinned_roots, blackbox.intermediates, blackbox.epochs TO ledger_app;
COMMIT;
