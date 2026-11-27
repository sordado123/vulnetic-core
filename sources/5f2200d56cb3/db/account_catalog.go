package db

func (d *DB) SeedCustomAgent(key, name, description, prompt string) error {
	var id int64
	if err := d.QueryRow(`INSERT INTO agents(account_id,key,name,description,role,builtin,enabled,max_turns,run_seconds) VALUES($1,$2,$3,$4,'assistant',false,true,0,0)
 ON CONFLICT(account_id,key) DO UPDATE SET key=EXCLUDED.key RETURNING id`, d.catalogAccount(), key, name, description).Scan(&id); err != nil {
		return err
	}
	var promptID int64
	if err := d.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,1,$2,'built-in default','system')
 ON CONFLICT(agent_id,version) DO UPDATE SET agent_id=EXCLUDED.agent_id RETURNING id`, id, prompt).Scan(&promptID); err != nil {
		return err
	}
	_, err := d.Exec(`UPDATE agents SET current_prompt_id=COALESCE(current_prompt_id,$2) WHERE id=$1 AND account_id=$3`, id, promptID, d.catalogAccount())
	return err
}

// SeedAccountAgents uses code-owned metadata and prompt bodies, never another customer's edits.
// The caller supplies its signup transaction so account and defaults commit together.
func (d *DB) SeedAccountAgents(prompts map[string]string) error {
	for _, a := range builtinAgents {
		var id int64
		err := d.QueryRow(`INSERT INTO agents(account_id,key,name,description,role,builtin,enabled,interactive_shell,run_seconds,max_turns)
VALUES($1,$2,$3,$4,$5,true,true,false,0,0) ON CONFLICT(account_id,key) DO UPDATE SET key=EXCLUDED.key RETURNING id`, d.catalogAccount(), a.key, a.name, a.desc, a.role).Scan(&id)
		if err != nil {
			return err
		}
		for _, v := range a.vars {
			if _, err = d.Exec(`INSERT INTO agent_prompt_vars(agent_id,var_name,description,example,source) VALUES($1,$2,$3,$4,$5) ON CONFLICT(agent_id,var_name) DO NOTHING`, id, v.name, v.desc, v.example, v.source); err != nil {
				return err
			}
		}
		if prompt := prompts[a.key]; prompt != "" {
			var promptID int64
			if err = d.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by) VALUES($1,1,$2,'built-in default','system') ON CONFLICT(agent_id,version) DO UPDATE SET agent_id=EXCLUDED.agent_id RETURNING id`, id, prompt).Scan(&promptID); err != nil {
				return err
			}
			if _, err = d.Exec(`UPDATE agents SET current_prompt_id=COALESCE(current_prompt_id,$2) WHERE id=$1 AND account_id=$3`, id, promptID, d.catalogAccount()); err != nil {
				return err
			}
		}
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return err
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return err
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return err
	}
	return d.seedDefaultAssetInterceptRules()
}

func (d *DB) EnsureAccountCatalogs(seed func(*DB) error) error {
	rows, err := d.Query(`SELECT id FROM accounts a WHERE a.id<>1 AND NOT EXISTS(SELECT 1 FROM account_settings s WHERE s.account_id=a.id AND s.key='catalog_seed_v1' AND s.value='true') ORDER BY id`)
	if err != nil {
		return err
	}
	var accounts []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		accounts = append(accounts, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range accounts {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`SELECT id FROM accounts WHERE id=$1 FOR UPDATE`, id); err != nil {
			tx.Rollback()
			return err
		}
		var exists bool
		if err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM account_settings WHERE account_id=$1 AND key='catalog_seed_v1' AND value='true')`, id).Scan(&exists); err != nil {
			tx.Rollback()
			return err
		}
		if !exists {
			scoped := d.ForAccount(id)
			scoped.Querier = tx
			if err = seed(scoped); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
