BEGIN;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=24) THEN
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS claim_token TEXT;
ALTER TABLE exploration_nodes ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ;
ALTER TABLE llm_profiles DROP CONSTRAINT IF EXISTS llm_profiles_format_check;
ALTER TABLE llm_profiles ADD CONSTRAINT llm_profiles_format_check CHECK(format IN ('openai','anthropic','openai-responses','ollama'));
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS decided_by TEXT NOT NULL DEFAULT '';
ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS decided_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
CREATE TABLE IF NOT EXISTS managed_target_approvals(
 account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,scope TEXT NOT NULL,executor_id BIGINT NOT NULL REFERENCES ssh_targets(id) ON DELETE CASCADE,destination TEXT NOT NULL,addresses JSONB NOT NULL,addresses_hash TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(account_id,scope,executor_id,destination,addresses_hash)
);
ALTER TABLE managed_target_approvals ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_managed_target_approvals ON managed_target_approvals USING(account_id=current_setting('app.account_id',true)::bigint) WITH CHECK(account_id=current_setting('app.account_id',true)::bigint);
IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN GRANT SELECT,INSERT ON managed_target_approvals TO vulnetic_app; END IF;
CREATE TABLE IF NOT EXISTS finding_evidence_reviews(
 id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,evidence_version BIGINT NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX finding_evidence_reviews_latest ON finding_evidence_reviews(account_id,finding_id,id DESC);
ALTER TABLE finding_evidence_reviews ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_finding_evidence_reviews ON finding_evidence_reviews USING(account_id=current_setting('app.account_id',true)::bigint) WITH CHECK(account_id=current_setting('app.account_id',true)::bigint AND EXISTS(SELECT 1 FROM findings f WHERE f.id=finding_id AND f.account_id=finding_evidence_reviews.account_id));
IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN GRANT SELECT,INSERT ON finding_evidence_reviews TO vulnetic_app;GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO vulnetic_app;END IF;
INSERT INTO beta_migrations(version) VALUES(24);
END IF;END $$;

COMMIT;
