-- Additive beta migrations. Existing IDs and histories are preserved.
CREATE TABLE IF NOT EXISTS beta_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
DO $$ BEGIN
IF NOT EXISTS (SELECT 1 FROM beta_migrations WHERE version=1) THEN
    ALTER TABLE accounts ADD COLUMN IF NOT EXISTS blocked BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE scheduled_task_actions ADD COLUMN IF NOT EXISTS account_id BIGINT REFERENCES accounts(id);
    UPDATE scheduled_task_actions a SET account_id=t.account_id FROM tasks t WHERE a.task_id=t.id::text;
    -- Unattributable historical global pauses are retained but cannot fire.
    UPDATE scheduled_task_actions SET cancelled=true WHERE account_id IS NULL AND fired_at IS NULL;
    CREATE INDEX IF NOT EXISTS scheduled_task_actions_account ON scheduled_task_actions(account_id);
    ALTER TABLE scheduled_task_actions ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant_scheduled_actions ON scheduled_task_actions
      USING (account_id=current_setting('app.account_id',true)::bigint)
      WITH CHECK (account_id=current_setting('app.account_id',true)::bigint);
    INSERT INTO beta_migrations(version) VALUES(1);
END IF;
END $$;

DO $$
DECLARE tab TEXT;
BEGIN
IF NOT EXISTS (SELECT 1 FROM beta_migrations WHERE version=5) THEN
    FOREACH tab IN ARRAY ARRAY['agents','tools','agent_triggers','task_categories','task_templates','intercept_rules','asset_intercept_rules'] LOOP
      EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS account_id BIGINT NOT NULL DEFAULT 1 REFERENCES accounts(id) ON DELETE CASCADE',tab);
      EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
      EXECUTE format('CREATE POLICY tenant_catalog ON %I USING (account_id=current_setting(''app.account_id'',true)::bigint) WITH CHECK (account_id=current_setting(''app.account_id'',true)::bigint)',tab);
    END LOOP;
    ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_key_key;
    CREATE UNIQUE INDEX agents_account_key ON agents(account_id,key);
    ALTER TABLE tools DROP CONSTRAINT IF EXISTS tools_pkey;
    ALTER TABLE tools ADD PRIMARY KEY(account_id,key);
    ALTER TABLE task_categories DROP CONSTRAINT IF EXISTS task_categories_nkey_key;
    CREATE UNIQUE INDEX task_categories_account_name ON task_categories(account_id,nkey);
    ALTER TABLE task_templates DROP CONSTRAINT IF EXISTS task_templates_nkey_key;
    CREATE UNIQUE INDEX task_templates_account_name ON task_templates(account_id,nkey);
    ALTER TABLE agent_prompts ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant_agent_prompts ON agent_prompts
      USING (EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint))
      WITH CHECK (EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint));
    ALTER TABLE agent_prompt_vars ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant_agent_vars ON agent_prompt_vars
      USING (EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint))
      WITH CHECK (EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint));
    ALTER TABLE agent_skill_visibility ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant_agent_skills ON agent_skill_visibility
      USING (EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint))
      WITH CHECK (EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint));
    INSERT INTO beta_migrations(version) VALUES(5);
END IF;
END $$;

CREATE TABLE IF NOT EXISTS account_settings (
 account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 key TEXT NOT NULL,value TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(account_id,key)
);
DO $$ BEGIN
IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=7) THEN
 ALTER TABLE conversations ADD COLUMN ssh_target_id BIGINT REFERENCES ssh_targets(id) ON DELETE SET NULL;
 DROP POLICY IF EXISTS tenant_isolation_agent_visibility ON agent_visibility;
 CREATE POLICY tenant_isolation_agent_visibility ON agent_visibility
 USING(EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint)
 AND resource_kind='mcp' AND EXISTS(SELECT 1 FROM mcp_servers m WHERE m.id=resource_id AND m.account_id=current_setting('app.account_id',true)::bigint))
 WITH CHECK(EXISTS(SELECT 1 FROM agents a WHERE a.id=agent_id AND a.account_id=current_setting('app.account_id',true)::bigint)
 AND resource_kind='mcp' AND EXISTS(SELECT 1 FROM mcp_servers m WHERE m.id=resource_id AND m.account_id=current_setting('app.account_id',true)::bigint));
 INSERT INTO beta_migrations(version) VALUES(7);
END IF; END $$;
ALTER TABLE account_settings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_settings ON account_settings;
CREATE POLICY tenant_settings ON account_settings
 USING(account_id=current_setting('app.account_id',true)::bigint)
 WITH CHECK(account_id=current_setting('app.account_id',true)::bigint);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT SELECT,INSERT,UPDATE,DELETE ON account_settings TO vulnetic_app;
 END IF;
END $$;

DO $$ BEGIN
IF NOT EXISTS (SELECT 1 FROM beta_migrations WHERE version=4) THEN
    DROP INDEX IF EXISTS uq_llm_one_default;
    CREATE UNIQUE INDEX uq_llm_one_default ON llm_profiles(account_id) WHERE is_default;
    INSERT INTO beta_migrations(version) VALUES(4);
END IF;
END $$;

DO $$ BEGIN
IF NOT EXISTS (SELECT 1 FROM beta_migrations WHERE version=2) THEN
    ALTER TABLE intercept_pending ADD COLUMN IF NOT EXISTS account_id BIGINT REFERENCES accounts(id);
    UPDATE intercept_pending p SET account_id=t.account_id FROM tasks t WHERE p.task_id=t.id::text;
    UPDATE intercept_pending p SET account_id=c.account_id FROM conversations c
      WHERE p.conversation_id=c.id AND (p.account_id IS NULL OR p.account_id=c.account_id);
    -- Conflicting parents are deliberately quarantined, not assigned by guesswork.
    UPDATE intercept_pending p SET account_id=NULL FROM tasks t, conversations c
      WHERE p.task_id=t.id::text AND p.conversation_id=c.id AND t.account_id<>c.account_id;
    ALTER TABLE intercept_pending ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant_intercept_pending ON intercept_pending
      USING (account_id=current_setting('app.account_id',true)::bigint)
      WITH CHECK (account_id=current_setting('app.account_id',true)::bigint);
    CREATE INDEX IF NOT EXISTS intercept_pending_account ON intercept_pending(account_id);
    INSERT INTO beta_migrations(version) VALUES(2);
END IF;
END $$;

CREATE OR REPLACE FUNCTION intercept_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE task_owner BIGINT; conversation_owner BIGINT;
BEGIN
    IF NEW.task_id IS NOT NULL THEN SELECT account_id INTO task_owner FROM tasks WHERE id::text=NEW.task_id; END IF;
    IF NEW.conversation_id IS NOT NULL THEN SELECT account_id INTO conversation_owner FROM conversations WHERE id=NEW.conversation_id; END IF;
    IF task_owner IS NOT NULL AND conversation_owner IS NOT NULL AND task_owner<>conversation_owner THEN
      RAISE EXCEPTION 'approval parents belong to different accounts';
    END IF;
    NEW.account_id := COALESCE(task_owner,conversation_owner);
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS intercept_owner_insert ON intercept_pending;
CREATE TRIGGER intercept_owner_insert BEFORE INSERT ON intercept_pending FOR EACH ROW EXECUTE FUNCTION intercept_owner();

DO $$ BEGIN
IF NOT EXISTS (SELECT 1 FROM beta_migrations WHERE version=3) THEN
    ALTER TABLE ssh_targets ADD COLUMN IF NOT EXISTS host_key TEXT NOT NULL DEFAULT '';
    INSERT INTO beta_migrations(version) VALUES(3);
END IF;
END $$;

DO $$ DECLARE tab TEXT; BEGIN
IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=8) THEN
 FOREACH tab IN ARRAY ARRAY['llm_records','llm_usage','skill_usage','tool_usage'] LOOP
  EXECUTE format('ALTER TABLE %I ADD COLUMN account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE',tab);
  EXECUTE format('UPDATE %I l SET account_id=t.account_id FROM tasks t WHERE l.task_id::text=t.id::text',tab);
  IF tab<>'llm_usage' THEN
   EXECUTE format('UPDATE %I l SET account_id=c.account_id FROM conversations c WHERE l.session_id=''conv-''||c.id::text AND (l.account_id IS NULL OR l.account_id=c.account_id)',tab);
   EXECUTE format('UPDATE %I l SET account_id=NULL FROM conversations c,tasks t WHERE l.session_id=''conv-''||c.id::text AND l.task_id::text=t.id::text AND t.account_id<>c.account_id',tab);
  END IF;
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_ledger ON %I USING(account_id=current_setting(''app.account_id'',true)::bigint) WITH CHECK(account_id=current_setting(''app.account_id'',true)::bigint)',tab);
  EXECUTE format('CREATE INDEX ON %I(account_id)',tab);
 END LOOP;
 INSERT INTO beta_migrations(version) VALUES(8);
END IF; END $$;
CREATE TABLE IF NOT EXISTS account_audit(
 id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 user_id BIGINT,action TEXT NOT NULL,resource TEXT NOT NULL,status INT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS account_audit_owner ON account_audit(account_id,id DESC);
ALTER TABLE account_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_audit ON account_audit;
CREATE POLICY tenant_audit ON account_audit USING(account_id=current_setting('app.account_id',true)::bigint) WITH CHECK(account_id=current_setting('app.account_id',true)::bigint);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT SELECT,INSERT ON account_audit TO vulnetic_app;
 GRANT USAGE,SELECT ON SEQUENCE account_audit_id_seq TO vulnetic_app;
 GRANT SELECT,INSERT,UPDATE,DELETE ON llm_records,llm_usage,skill_usage,tool_usage TO vulnetic_app;
 GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO vulnetic_app;
END IF;END $$;

CREATE TABLE IF NOT EXISTS execution_proofs(
 id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,conversation_id BIGINT REFERENCES conversations(id) ON DELETE SET NULL,
 run_id TEXT NOT NULL,tool TEXT NOT NULL,payload TEXT NOT NULL,digest TEXT NOT NULL,truncated BOOLEAN NOT NULL DEFAULT false,created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS execution_proofs_owner ON execution_proofs(account_id,task_id,id DESC);
CREATE TABLE IF NOT EXISTS finding_verifications(
 id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,user_id BIGINT NOT NULL,
 steps TEXT NOT NULL,evidence_version BIGINT NOT NULL,source_evidence TEXT NOT NULL,source_summary TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_verifications_finding ON finding_verifications(finding_id);
CREATE TABLE IF NOT EXISTS finding_verification_proofs(
 verification_id BIGINT NOT NULL REFERENCES finding_verifications(id) ON DELETE CASCADE,
 proof_id BIGINT NOT NULL REFERENCES execution_proofs(id),PRIMARY KEY(verification_id,proof_id)
);
ALTER TABLE execution_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_verification_proofs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_proofs ON execution_proofs;
CREATE POLICY tenant_proofs ON execution_proofs USING(account_id=current_setting('app.account_id',true)::bigint) WITH CHECK(account_id=current_setting('app.account_id',true)::bigint);
DROP POLICY IF EXISTS tenant_verifications ON finding_verifications;
CREATE POLICY tenant_verifications ON finding_verifications USING(account_id=current_setting('app.account_id',true)::bigint) WITH CHECK(account_id=current_setting('app.account_id',true)::bigint);
DROP POLICY IF EXISTS tenant_verification_proofs ON finding_verification_proofs;
CREATE POLICY tenant_verification_proofs ON finding_verification_proofs USING(EXISTS(SELECT 1 FROM finding_verifications v WHERE v.id=verification_id)) WITH CHECK(EXISTS(SELECT 1 FROM finding_verifications v JOIN execution_proofs p ON p.id=proof_id WHERE v.id=verification_id AND v.account_id=p.account_id));
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT SELECT ON execution_proofs TO vulnetic_app;
 GRANT SELECT,INSERT ON finding_verifications,finding_verification_proofs TO vulnetic_app;
 GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO vulnetic_app;
END IF;END $$;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=9) THEN
 ALTER TABLE ssh_targets ADD COLUMN preflight JSONB NOT NULL DEFAULT '{}'::jsonb;
 UPDATE ssh_targets SET status='pending',verified_at=NULL WHERE status='verified';
 INSERT INTO beta_migrations(version) VALUES(9);
END IF;END $$;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=10) THEN
 ALTER TABLE tasks ADD COLUMN user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
 ALTER TABLE conversations ADD COLUMN user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
 ALTER TABLE execution_proofs ADD COLUMN user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
 INSERT INTO beta_migrations(version) VALUES(10);
END IF;END $$;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=11) THEN
 ALTER TABLE accounts ADD COLUMN session_version BIGINT NOT NULL DEFAULT 0;
 UPDATE accounts SET session_version=1 WHERE blocked;
 INSERT INTO beta_migrations(version) VALUES(11);
END IF;END $$;
CREATE OR REPLACE FUNCTION revoke_blocked_account_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.blocked AND NOT OLD.blocked THEN NEW.session_version := OLD.session_version+1; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS revoke_blocked_account_sessions ON accounts;
CREATE TRIGGER revoke_blocked_account_sessions BEFORE UPDATE OF blocked ON accounts
 FOR EACH ROW EXECUTE FUNCTION revoke_blocked_account_sessions();

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=12) THEN
 ALTER TABLE exploration_nodes DROP CONSTRAINT ck_node_state;
 ALTER TABLE exploration_nodes ADD CONSTRAINT ck_node_state CHECK (
  (kind='begin' AND state IN ('open')) OR
  (kind='intent' AND state IN ('open','running','paused','done','blocked','exhausted','stopped','deleted')) OR
  (kind='goal' AND state IN ('open','met','abandoned')) OR
  (kind='fact' AND state IN ('confirmed','dismissed','origin')) OR
  (kind='finding' AND state IN ('confirmed','dismissed','candidate','verified')) OR
  (kind='hint' AND state IN ('active','consumed')) OR
  (kind='digest' AND state IN ('active','superseded'))
 );
 CREATE TABLE finding_retest_reviews(
  retest_id BIGINT PRIMARY KEY REFERENCES finding_retests(id) ON DELETE CASCADE,
  account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL,steps TEXT NOT NULL,proof_ids JSONB NOT NULL,
  reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now()
 );
 INSERT INTO beta_migrations(version) VALUES(12);
END IF;END $$;
CREATE OR REPLACE FUNCTION invalidate_finding_node_verification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.evidence IS DISTINCT FROM OLD.evidence OR NEW.summary IS DISTINCT FROM OLD.summary OR NEW.evidence_version IS DISTINCT FROM OLD.evidence_version THEN
  UPDATE exploration_nodes SET state='candidate' WHERE id=NEW.node_id AND kind='finding' AND state='verified';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS invalidate_finding_node_verification ON findings;
CREATE TRIGGER invalidate_finding_node_verification AFTER UPDATE OF evidence,summary,evidence_version ON findings
 FOR EACH ROW EXECUTE FUNCTION invalidate_finding_node_verification();

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=13) THEN
 UPDATE intercept_pending SET decision_source='model'
 WHERE rule_id IS NULL AND reason ILIKE '[model]%' AND decision_source IN ('','unknown');
 INSERT INTO beta_migrations(version) VALUES(13);
END IF;END $$;
ALTER TABLE finding_retest_reviews ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_retest_reviews ON finding_retest_reviews;
CREATE POLICY tenant_retest_reviews ON finding_retest_reviews
 USING(account_id=current_setting('app.account_id',true)::bigint)
 WITH CHECK(account_id=current_setting('app.account_id',true)::bigint AND EXISTS(
  SELECT 1 FROM finding_retests r JOIN findings f ON f.id=r.finding_id JOIN users u ON u.id=finding_retest_reviews.user_id
  WHERE r.id=retest_id AND f.account_id=finding_retest_reviews.account_id AND u.account_id=f.account_id
  AND r.status='completed' AND r.verdict IN ('fixed','reproduced')
  AND jsonb_typeof(proof_ids)='array' AND jsonb_array_length(proof_ids) BETWEEN 1 AND 20
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(proof_ids) ids(id) WHERE NOT EXISTS(
   SELECT 1 FROM execution_proofs p WHERE p.id=ids.id::bigint AND p.account_id=f.account_id AND p.conversation_id=r.conversation_id
  ))
 ));
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT SELECT,INSERT ON finding_retest_reviews TO vulnetic_app;
END IF;END $$;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=14) THEN
 ALTER TABLE ssh_targets ADD COLUMN transport TEXT NOT NULL DEFAULT 'ssh' CHECK(transport IN ('ssh','agent'));
 ALTER TABLE ssh_targets ADD COLUMN agent_expires_at TIMESTAMPTZ;
 CREATE UNIQUE INDEX ssh_targets_id_account ON ssh_targets(id,account_id);
 CREATE TABLE execution_agents(
  target_id BIGINT PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  join_hash BYTEA UNIQUE,
  join_expires_at TIMESTAMPTZ NOT NULL,
  lifetime_seconds INTEGER NOT NULL CHECK(lifetime_seconds BETWEEN 300 AND 86400),
  account_version BIGINT NOT NULL,
  runtime_hash BYTEA UNIQUE,
  enrolled_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  FOREIGN KEY(target_id,account_id) REFERENCES ssh_targets(id,account_id) ON DELETE CASCADE
 );
 INSERT INTO beta_migrations(version) VALUES(14);
END IF;END $$;
ALTER TABLE execution_agents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_execution_agents ON execution_agents;
CREATE POLICY tenant_execution_agents ON execution_agents
 USING(account_id=current_setting('app.account_id',true)::bigint)
 WITH CHECK(account_id=current_setting('app.account_id',true)::bigint);
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT SELECT,INSERT,UPDATE,DELETE ON execution_agents TO vulnetic_app;
END IF;END $$;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=15) THEN
 ALTER TABLE execution_agents DROP CONSTRAINT execution_agents_lifetime_seconds_check;
 ALTER TABLE execution_agents ADD CONSTRAINT execution_agents_lifetime_seconds_check CHECK(lifetime_seconds BETWEEN 300 AND 604800);
 INSERT INTO beta_migrations(version) VALUES(15);
END IF;END $$;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=16) THEN
 CREATE TABLE executor_origins(ip INET PRIMARY KEY,blocked_until TIMESTAMPTZ NOT NULL,last_seen TIMESTAMPTZ NOT NULL DEFAULT now());
 CREATE INDEX executor_origins_expiry ON executor_origins(blocked_until);
 REVOKE ALL ON executor_origins FROM PUBLIC;
 INSERT INTO beta_migrations(version) VALUES(16);
END IF;END $$;

-- No function accepts SQL, a table name, or executable content from the application.
CREATE OR REPLACE FUNCTION public.vulnetic_runtime_owner(kind TEXT,resource BIGINT) RETURNS BIGINT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT account_id FROM (
  SELECT account_id FROM public.tasks WHERE kind='task' AND id=resource
  UNION ALL SELECT account_id FROM public.findings WHERE kind='finding' AND id=resource
  UNION ALL SELECT account_id FROM public.conversations WHERE kind='conversation' AND id=resource
  UNION ALL SELECT account_id FROM public.llm_profiles WHERE kind='profile' AND id=resource
  UNION ALL SELECT t.account_id FROM public.tasks t WHERE kind='exploration' AND exploration_id=resource
  UNION ALL SELECT account_id FROM public.notification_channels WHERE kind='notification' AND id=resource
  UNION ALL SELECT f.account_id FROM public.finding_retests r JOIN public.findings f ON f.id=r.finding_id WHERE kind='retest' AND r.id=resource
  UNION ALL SELECT account_id FROM public.users WHERE kind='user' AND id=resource
 ) owned LIMIT 1
$$;
CREATE OR REPLACE FUNCTION public.vulnetic_login(email_value TEXT) RETURNS SETOF public.users
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT * FROM public.users WHERE email=email_value LIMIT 1
$$;
CREATE OR REPLACE FUNCTION public.vulnetic_agent_identity(token_hash BYTEA) RETURNS TABLE(account_id BIGINT,target_id BIGINT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT e.account_id,e.target_id FROM public.execution_agents e JOIN public.accounts a ON a.id=e.account_id JOIN public.ssh_targets t ON t.id=e.target_id
 WHERE octet_length(token_hash)=32 AND e.runtime_hash=token_hash AND e.revoked_at IS NULL AND NOT a.blocked AND e.account_version=a.session_version AND t.agent_expires_at>now()
$$;
CREATE OR REPLACE FUNCTION public.vulnetic_agent_enrollment(token_hash BYTEA) RETURNS TABLE(account_id BIGINT,target_id BIGINT,lifetime_seconds INTEGER)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT e.account_id,e.target_id,e.lifetime_seconds FROM public.execution_agents e JOIN public.accounts a ON a.id=e.account_id
 WHERE octet_length(token_hash)=32 AND e.join_hash=token_hash AND e.join_expires_at>now() AND e.enrolled_at IS NULL AND e.revoked_at IS NULL AND NOT a.blocked AND e.account_version=a.session_version FOR UPDATE OF e
$$;
REVOKE ALL ON FUNCTION public.vulnetic_runtime_owner(TEXT,BIGINT),public.vulnetic_login(TEXT),public.vulnetic_agent_identity(BYTEA),public.vulnetic_agent_enrollment(BYTEA) FROM PUBLIC;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT EXECUTE ON FUNCTION public.vulnetic_runtime_owner(TEXT,BIGINT),public.vulnetic_login(TEXT),public.vulnetic_agent_identity(BYTEA),public.vulnetic_agent_enrollment(BYTEA) TO vulnetic_app;
 GRANT SELECT,INSERT,UPDATE ON executor_origins TO vulnetic_app;
 REVOKE CREATE ON SCHEMA public FROM PUBLIC,vulnetic_app;
END IF;END $$;
INSERT INTO beta_migrations(version) VALUES(17) ON CONFLICT DO NOTHING;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=18) THEN
 ALTER TABLE explorations ADD COLUMN account_id BIGINT REFERENCES accounts(id);
 UPDATE explorations e SET account_id=t.account_id FROM tasks t WHERE t.exploration_id=e.id;
 CREATE INDEX explorations_account ON explorations(account_id);
 INSERT INTO beta_migrations(version) VALUES(18);
END IF;END $$;
DROP POLICY IF EXISTS tenant_isolation_explorations ON explorations;
CREATE POLICY tenant_isolation_explorations ON explorations
 USING(account_id=current_setting('app.account_id',true)::bigint)
 WITH CHECK(account_id=current_setting('app.account_id',true)::bigint);
DO $$ DECLARE tab TEXT; BEGIN
 FOREACH tab IN ARRAY ARRAY['exploration_nodes','exploration_edges'] LOOP
 EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_%I ON %I',tab,tab);
 EXECUTE format('CREATE POLICY tenant_isolation_%I ON %I USING(EXISTS(SELECT 1 FROM public.explorations e WHERE e.id=exploration_id)) WITH CHECK(EXISTS(SELECT 1 FROM public.explorations e WHERE e.id=exploration_id))',tab,tab);
 END LOOP;
END $$;

DROP POLICY IF EXISTS tenant_isolation_exploration_anchors ON exploration_anchors;
CREATE POLICY tenant_isolation_exploration_anchors ON exploration_anchors
 USING(EXISTS(SELECT 1 FROM exploration_nodes n WHERE n.id=node_id) AND EXISTS(SELECT 1 FROM assets a WHERE a.id=asset_id))
 WITH CHECK(EXISTS(SELECT 1 FROM exploration_nodes n WHERE n.id=node_id) AND EXISTS(SELECT 1 FROM assets a WHERE a.id=asset_id));
CREATE OR REPLACE FUNCTION public.vulnetic_pilot_account_count() RETURNS BIGINT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$SELECT count(DISTINCT account_id) FROM public.users$$;
REVOKE ALL ON FUNCTION public.vulnetic_pilot_account_count() FROM PUBLIC;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN GRANT EXECUTE ON FUNCTION public.vulnetic_pilot_account_count() TO vulnetic_app;END IF;END $$;

-- CVE verifier history and exact attribution are separate from customer-editable tools.
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=19) THEN
 ALTER TABLE asset_cve_candidates ADD COLUMN details JSONB NOT NULL DEFAULT '{}';
 CREATE TABLE cve_authorizations (
  id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES accounts(id),user_id BIGINT NOT NULL REFERENCES users(id),
  task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
  executor_id BIGINT NOT NULL,recipe_id TEXT NOT NULL,recipe_digest TEXT NOT NULL,target_url TEXT NOT NULL,payload TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,remaining_runs INTEGER NOT NULL CHECK(remaining_runs BETWEEN 0 AND 3),created_at TIMESTAMPTZ NOT NULL DEFAULT now()
 );
 CREATE TABLE cve_check_runs (
  id BIGSERIAL PRIMARY KEY,account_id BIGINT NOT NULL REFERENCES accounts(id),user_id BIGINT NOT NULL REFERENCES users(id),
  authorization_id BIGINT REFERENCES cve_authorizations(id) ON DELETE SET NULL,task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
  asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,executor_id BIGINT NOT NULL,recipe_id TEXT NOT NULL,recipe_digest TEXT NOT NULL,
  target_url TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('running','completed')),outcome TEXT NOT NULL DEFAULT 'inconclusive',
  payload TEXT NOT NULL DEFAULT '',proof_id BIGINT REFERENCES execution_proofs(id),started_at TIMESTAMPTZ NOT NULL DEFAULT now(),finished_at TIMESTAMPTZ
 );
 CREATE UNIQUE INDEX cve_one_running_check_per_executor ON cve_check_runs(account_id,executor_id) WHERE status='running';
 CREATE INDEX cve_checks_by_task ON cve_check_runs(account_id,task_id,id);
 ALTER TABLE execution_proofs ADD COLUMN asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL;
 ALTER TABLE execution_proofs ADD COLUMN executor_id BIGINT;
 ALTER TABLE execution_proofs ADD COLUMN verification_run_id BIGINT REFERENCES cve_check_runs(id);
 ALTER TABLE execution_proofs ADD COLUMN full_artifact_id TEXT NOT NULL DEFAULT '';
 ALTER TABLE execution_proofs ADD COLUMN preview_digest TEXT NOT NULL DEFAULT '';
 ALTER TABLE execution_proofs ADD COLUMN failed BOOLEAN NOT NULL DEFAULT false;
 ALTER TABLE execution_proofs ADD COLUMN capture_incomplete BOOLEAN NOT NULL DEFAULT false;
 ALTER TABLE execution_proofs ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
 ALTER TABLE finding_verifications ADD COLUMN check_run_id BIGINT REFERENCES cve_check_runs(id);
 INSERT INTO beta_migrations(version) VALUES(19);
END IF;END $$;
ALTER TABLE cve_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_check_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_cve_authorizations ON cve_authorizations;
CREATE POLICY tenant_cve_authorizations ON cve_authorizations USING(account_id=current_setting('app.account_id',true)::bigint)
 WITH CHECK(account_id=current_setting('app.account_id',true)::bigint AND EXISTS(SELECT 1 FROM tasks t WHERE t.id=task_id AND t.account_id=cve_authorizations.account_id) AND EXISTS(SELECT 1 FROM assets a WHERE a.id=asset_id AND a.account_id=cve_authorizations.account_id) AND EXISTS(SELECT 1 FROM users u WHERE u.id=user_id AND u.account_id=cve_authorizations.account_id));
DROP POLICY IF EXISTS tenant_cve_check_runs ON cve_check_runs;
CREATE POLICY tenant_cve_check_runs ON cve_check_runs USING(account_id=current_setting('app.account_id',true)::bigint)
 WITH CHECK(account_id=current_setting('app.account_id',true)::bigint AND EXISTS(SELECT 1 FROM users u WHERE u.id=user_id AND u.account_id=cve_check_runs.account_id));
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT SELECT,INSERT,UPDATE ON cve_authorizations,cve_check_runs TO vulnetic_app;
 GRANT USAGE,SELECT ON SEQUENCE cve_authorizations_id_seq,cve_check_runs_id_seq TO vulnetic_app;
END IF;END $$;

DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=20) THEN
 ALTER TABLE llm_usage ADD COLUMN call_id TEXT;
 CREATE UNIQUE INDEX llm_usage_call_id ON llm_usage(account_id,call_id) WHERE call_id IS NOT NULL;
 INSERT INTO beta_migrations(version) VALUES(20);
END IF;END $$;


-- Additive execution metadata; historic ledger attribution remains unknown.
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM beta_migrations WHERE version=21) THEN
 ALTER TABLE conversations ADD COLUMN source_task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL;
 CREATE TABLE execution_runs (
  id TEXT PRIMARY KEY, account_id BIGINT NOT NULL REFERENCES accounts(id),
  task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
  conversation_id BIGINT REFERENCES conversations(id) ON DELETE SET NULL,
  payload JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
 );
 CREATE INDEX execution_runs_task ON execution_runs(account_id,task_id,updated_at DESC);
 CREATE INDEX execution_runs_conversation ON execution_runs(account_id,conversation_id,updated_at DESC);
 ALTER TABLE llm_usage ADD COLUMN conversation_id BIGINT;
 ALTER TABLE llm_usage ADD COLUMN run_id TEXT;
 CREATE INDEX llm_usage_conversation ON llm_usage(account_id,conversation_id);
 CREATE INDEX llm_usage_run ON llm_usage(account_id,run_id);
 -- Remove only the invalid empty requirement from built-in legacy schemas.
 UPDATE tools SET schema=jsonb_set(schema::jsonb,'{required}',COALESCE((SELECT jsonb_agg(v) FROM jsonb_array_elements(schema::jsonb->'required') v WHERE v<>'""'::jsonb),'[]'::jsonb))
 WHERE system AND kind='builtin' AND jsonb_typeof(schema::jsonb->'required')='array' AND schema::jsonb->'required' @> '[""]'::jsonb AND NOT COALESCE(schema::jsonb->'properties','{}'::jsonb) ? '';
 INSERT INTO beta_migrations(version) VALUES(21);
END IF;END $$;
ALTER TABLE execution_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_execution_runs ON execution_runs;
CREATE POLICY tenant_execution_runs ON execution_runs
 USING(account_id=current_setting('app.account_id',true)::bigint)
 WITH CHECK(account_id=current_setting('app.account_id',true)::bigint
 AND (task_id IS NULL OR EXISTS(SELECT 1 FROM tasks t WHERE t.id=task_id AND t.account_id=execution_runs.account_id))
 AND (conversation_id IS NULL OR EXISTS(SELECT 1 FROM conversations c WHERE c.id=conversation_id AND c.account_id=execution_runs.account_id)));
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='vulnetic_app') THEN
 GRANT SELECT,INSERT,UPDATE ON execution_runs TO vulnetic_app;
END IF;END $$;
