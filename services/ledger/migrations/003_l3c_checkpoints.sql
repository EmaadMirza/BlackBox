BEGIN;

CREATE TABLE IF NOT EXISTS blackbox.alarms (
    alarm_id BIGSERIAL PRIMARY KEY,
    log_id TEXT NOT NULL,
    code TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'high', 'critical')),
    message TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS alarms_no_mutation ON blackbox.alarms;
CREATE TRIGGER alarms_no_mutation
BEFORE UPDATE OR DELETE OR TRUNCATE ON blackbox.alarms
FOR EACH STATEMENT EXECUTE FUNCTION blackbox.reject_mutation();

CREATE UNIQUE INDEX IF NOT EXISTS checkpoints_log_tree_size
    ON blackbox.checkpoints (log_id, tree_size);

INSERT INTO blackbox.schema_version(version) VALUES (3) ON CONFLICT (version) DO NOTHING;

GRANT INSERT ON blackbox.checkpoints TO ledger_app;
GRANT SELECT, INSERT ON blackbox.alarms TO ledger_app;
GRANT USAGE, SELECT ON SEQUENCE blackbox.alarms_alarm_id_seq TO ledger_app;

COMMIT;
