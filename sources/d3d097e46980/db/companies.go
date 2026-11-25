package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"unicode/utf8"
)

// =====================================================================
// Company entity layer
// =====================================================================

// Company is a row in the companies table.
type Company struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	NKey      string  `json:"nkey"`
	Logo      *string `json:"logo,omitempty"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

// CompanyWithScope extends Company with its scope rules and asset count.
type CompanyWithScope struct {
	Company
	Scope      []ScopeRule `json:"scope"`
	AssetCount int         `json:"asset_count"`
}

// ScopeRule is one company_scope row.
type ScopeRule struct {
	ID        int64  `json:"id"`
	CompanyID int64  `json:"company_id"`
	Kind      string `json:"kind"`
	Domain    string `json:"domain,omitempty"`
	Net       string `json:"net,omitempty"`
	Value     string `json:"value,omitempty"`
	Raw       string `json:"raw"`
	Reason    string `json:"reason,omitempty"`
}

// CompanyStore operates on the companies + company_scope tables.
type CompanyStore struct{ db *DB }

var (
	ErrCompanyNameConflict = errors.New("company name already exists")
	ErrCompanyNotFound     = errors.New("company not found")
)

const (
	// Company scope is not capped by rule count: scopes entered one IP / domain at
	// a time easily run into the thousands, and a cap would just force users to
	// split them across multiple companies. The request body size
	// (server-side maxCompanyMutationBodyBytes) remains the backstop.
	//
	// Raw and normalized textual scope payloads are bounded by Unicode rune
	// count so multi-byte input is treated consistently by the API and DB layer.
	MaxCompanyScopeRawRunes   = 1024
	MaxCompanyScopeValueRunes = 1024
)

// CompanyScopeValidationError identifies a client-correctable scope error.
// Storage and transaction failures are returned as ordinary errors instead.
type CompanyScopeValidationError struct{ Message string }

func (e *CompanyScopeValidationError) Error() string { return e.Message }

// ValidateCompanyScopeInputBounds applies request-wide limits before parsing.
// Store methods call it again so non-HTTP callers cannot bypass the limits.
// Only the length of a single rule is constrained; the number of rules is not.
func ValidateCompanyScopeInputBounds(inputs []ScopeInput) error {
	for i, input := range inputs {
		if utf8.RuneCountInString(input.Value) > MaxCompanyScopeRawRunes {
			return &CompanyScopeValidationError{Message: fmt.Sprintf(
				"company scope rule #%d raw value is too long: at most %d characters", i+1, MaxCompanyScopeRawRunes,
			)}
		}
	}
	return nil
}

// Scope writes rebuild derived asset ownership globally, so serialize them to
// ensure the committed attribution always reflects the latest committed rules.
// This key is reserved for company mutations; 7337741001 is the schema lock and
// 7337741002 is the cross-package test-suite lock.
const companyScopeMutationLock int64 = 7337741003

// Companies returns the company store.
func (d *DB) Companies() *CompanyStore { return &CompanyStore{db: d} }

// AccountIDForTask resolves the account that owns taskID — see DB.AccountIDForTask.
// Exposed on CompanyStore too since agent tool handlers often hold a
// *CompanyStore without an *AssetStore alongside it (the two are independently
// optional on ToolSet).
func (s *CompanyStore) AccountIDForTask(taskID int64) (int64, error) {
	return s.db.AccountIDForTask(taskID)
}

// companyNKey normalises a company name: lowercase + trim + collapse whitespace.
func companyNKey(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(name)), " ")
}

// UpsertCompany creates or updates a company by name within accountID. Returns
// the id and whether a new row was created.
func (s *CompanyStore) UpsertCompany(accountID int64, name, logo string) (id int64, created bool, err error) {
	nkey := companyNKey(name)
	var logoVal any
	if logo != "" {
		logoVal = logo
	}
	err = s.db.QueryRow(`
INSERT INTO companies(account_id, name, nkey, logo)
VALUES ($1, $2, $3, $4)
ON CONFLICT (account_id, nkey) DO UPDATE SET
    name = EXCLUDED.name,
    logo = COALESCE(EXCLUDED.logo, companies.logo),
    updated_at = now()
RETURNING id, (xmax = 0)`, accountID, name, nkey, logoVal).Scan(&id, &created)
	return
}

// CreateCompanyWithScope creates a company without updating an existing row.
// The company, its valid initial scope rules, and derived asset attribution are
// committed atomically. Invalid inputs retain the legacy partial-validation
// contract and are reported without preventing valid rules from being stored.
func (s *CompanyStore) CreateCompanyWithScope(accountID int64, name, logo string, inputs []ScopeInput, reason string) (
	id int64, added, skipped, invalid int, validationErrors []string, err error,
) {
	if err := ValidateCompanyScopeInputBounds(inputs); err != nil {
		return 0, 0, 0, 0, nil, err
	}
	rules, invalid, validationErrors := parseScopeInputs(inputs)
	if err := validateParsedScopeBounds(rules); err != nil {
		return 0, 0, 0, invalid, validationErrors, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, 0, invalid, validationErrors, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := lockCompanyScopeMutation(tx); err != nil {
		return 0, 0, 0, invalid, validationErrors, err
	}

	nkey := companyNKey(name)
	var logoVal any
	if logo != "" {
		logoVal = logo
	}
	if err := tx.QueryRow(`
INSERT INTO companies(account_id, name, nkey, logo)
VALUES ($1, $2, $3, $4)
ON CONFLICT (account_id, nkey) DO NOTHING
RETURNING id`, accountID, name, nkey, logoVal).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, 0, invalid, validationErrors, ErrCompanyNameConflict
		}
		return 0, 0, 0, invalid, validationErrors, err
	}

	added, skipped, needsAttribution, err := insertScopeRulesTx(tx, id, rules, reason)
	if err != nil {
		return 0, 0, 0, invalid, validationErrors, err
	}
	if needsAttribution {
		warning, err := recomputeAttributionTx(tx, accountID)
		if err != nil {
			return 0, 0, 0, invalid, validationErrors, err
		}
		logAttributionWarning(warning)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, 0, invalid, validationErrors, err
	}
	return id, added, skipped, invalid, validationErrors, nil
}

// GetCompany returns one company by id, scoped to accountID (nil if not
// found or owned by a different account).
func (s *CompanyStore) GetCompany(accountID, id int64) (*Company, error) {
	c := &Company{}
	err := s.db.QueryRow(`
SELECT id, name, nkey, logo, created_at::text, updated_at::text
FROM companies WHERE id = $1 AND account_id = $2`, id, accountID).Scan(
		&c.ID, &c.Name, &c.NKey, &c.Logo, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

// GetCompanyByName returns one company by normalized name within accountID
// (nil if not found).
func (s *CompanyStore) GetCompanyByName(accountID int64, name string) (*Company, error) {
	nkey := companyNKey(name)
	c := &Company{}
	err := s.db.QueryRow(`
SELECT id, name, nkey, logo, created_at::text, updated_at::text
FROM companies WHERE nkey = $1 AND account_id = $2`, nkey, accountID).Scan(
		&c.ID, &c.Name, &c.NKey, &c.Logo, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

// UpsertByName creates the company if it doesn't exist within accountID,
// then returns its id.
func (s *CompanyStore) UpsertByName(accountID int64, name string) (int64, error) {
	id, _, err := s.UpsertCompany(accountID, name, "")
	return id, err
}

// DeleteCompany deletes a company (scoped to accountID) and re-evaluates
// automatic ownership against the remaining companies in the same account and
// transaction. Explicitly-owned assets are detached by the FK and may then
// fall back to a remaining scope match.
func (s *CompanyStore) DeleteCompany(accountID, id int64) error {
	_, err := s.DeleteCompanyWithAssets(accountID, id, false)
	return err
}

// DeleteCompanyWithAssets deletes a company scoped to accountID, and
// optionally all of its assets, in one transaction, then re-evaluates
// ownership against the remaining companies in that same account.
func (s *CompanyStore) DeleteCompanyWithAssets(accountID, id int64, deleteAssets bool) (assetsDeleted int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := lockCompanyScopeMutation(tx); err != nil {
		return 0, err
	}
	if deleteAssets {
		res, err := tx.Exec(`DELETE FROM assets WHERE company_id = $1 AND account_id = $2`, id, accountID)
		if err != nil {
			return 0, err
		}
		assetsDeleted, err = res.RowsAffected()
		if err != nil {
			return 0, err
		}
	}
	res, err := tx.Exec(`DELETE FROM companies WHERE id = $1 AND account_id = $2`, id, accountID)
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if deleted == 0 {
		return 0, ErrCompanyNotFound
	}
	// This path has no per-request warning channel, so the log is the only place
	// the operator can learn about unparseable ip rows here.
	warning, err := recomputeAttributionTx(tx, accountID)
	if err != nil {
		return 0, err
	}
	logAttributionWarning(warning)
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return assetsDeleted, nil
}

// ListCompanies returns all companies within accountID, with scope and asset count.
func (s *CompanyStore) ListCompanies(accountID int64) ([]*CompanyWithScope, error) {
	rows, err := s.db.Query(`
SELECT c.id, c.name, c.nkey, c.logo, c.created_at::text, c.updated_at::text,
       COUNT(DISTINCT a.id) AS asset_count
FROM companies c
LEFT JOIN assets a ON a.company_id = c.id
WHERE c.account_id = $1
GROUP BY c.id
ORDER BY c.name`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*CompanyWithScope
	for rows.Next() {
		cws := &CompanyWithScope{}
		if err := rows.Scan(&cws.ID, &cws.Name, &cws.NKey, &cws.Logo,
			&cws.CreatedAt, &cws.UpdatedAt, &cws.AssetCount); err != nil {
			return nil, err
		}
		out = append(out, cws)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// fetch scope rules for each company
	for _, cws := range out {
		cws.Scope, err = s.GetScope(accountID, cws.ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetScope returns all scope rules for a company owned by accountID (empty,
// no error, if the company belongs to a different account — same "not found"
// shape as a company that simply has no rules yet).
func (s *CompanyStore) GetScope(accountID, companyID int64) ([]ScopeRule, error) {
	rows, err := s.db.Query(`
SELECT cs.id, cs.company_id, cs.kind,
       COALESCE(cs.domain,''), COALESCE(cs.net::text,''), COALESCE(cs.value,''), cs.raw, COALESCE(cs.reason,'')
FROM company_scope cs
JOIN companies c ON c.id = cs.company_id
WHERE cs.company_id = $1 AND c.account_id = $2
ORDER BY cs.id`, companyID, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ScopeRule, 0)
	for rows.Next() {
		var r ScopeRule
		if err := rows.Scan(&r.ID, &r.CompanyID, &r.Kind, &r.Domain, &r.Net, &r.Value, &r.Raw, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddScope parses and inserts scope lines for a company, then reattributes assets.
// Returns counts of added, skipped, and invalid lines.
func (s *CompanyStore) AddScope(accountID, companyID int64, lines []string, reason string) (added, skipped, invalid int, errors []string) {
	inputs := make([]ScopeInput, 0, len(lines))
	for _, line := range lines {
		inputs = append(inputs, ScopeInput{Value: line})
	}
	return s.AddScopeInputs(accountID, companyID, inputs, reason)
}

// AddScopeInputs inserts structured scope rules. Empty kinds use the automatic
// CIDR/IP/ICP/domain/keyword classification used by AddScope.
func (s *CompanyStore) AddScopeInputs(accountID, companyID int64, inputs []ScopeInput, reason string) (added, skipped, invalid int, errors []string) {
	added, skipped, invalid, validationErrors, err := s.AddScopeInputsChecked(accountID, companyID, inputs, reason)
	if err != nil {
		validationErrors = append(validationErrors, err.Error())
	}
	return added, skipped, invalid, validationErrors
}

// AddScopeInputsChecked inserts structured scope rules while keeping input
// validation separate from storage and transaction errors.
func (s *CompanyStore) AddScopeInputsChecked(accountID, companyID int64, inputs []ScopeInput, reason string) (
	added, skipped, invalid int, validationErrors []string, err error,
) {
	if err := ValidateCompanyScopeInputBounds(inputs); err != nil {
		return 0, 0, 0, nil, err
	}
	rules, invalid, errors := parseScopeInputs(inputs)
	if err := validateParsedScopeBounds(rules); err != nil {
		return 0, 0, invalid, errors, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, invalid, errors, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := lockCompanyScopeMutation(tx); err != nil {
		return 0, 0, invalid, errors, err
	}
	if err := ensureCompanyExistsTx(tx, accountID, companyID); err != nil {
		return 0, 0, invalid, errors, err
	}
	if len(rules) == 0 {
		if err := tx.Commit(); err != nil {
			return 0, 0, invalid, errors, err
		}
		return 0, 0, invalid, errors, nil
	}
	added, skipped, needsAttribution, err := insertScopeRulesTx(tx, companyID, rules, reason)
	if err != nil {
		return 0, 0, invalid, errors, err
	}
	if needsAttribution {
		warning, err := recomputeAttributionTx(tx, accountID)
		if err != nil {
			return 0, 0, invalid, errors, fmt.Errorf("failed to recompute company attribution: %w", err)
		}
		logAttributionWarning(warning)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, invalid, errors, err
	}
	return added, skipped, invalid, errors, nil
}

func parseScopeInputs(inputs []ScopeInput) (rules []ParsedScope, invalid int, validationErrors []string) {
	rules = make([]ParsedScope, 0, len(inputs))
	for _, input := range inputs {
		rule, err := ParseScopeInput(input)
		if err != nil {
			invalid++
			validationErrors = append(validationErrors, fmt.Sprintf("%s: %v", input.Value, err))
			continue
		}
		rules = append(rules, rule)
	}
	return rules, invalid, validationErrors
}

func validateParsedScopeBounds(rules []ParsedScope) error {
	for i, rule := range rules {
		if utf8.RuneCountInString(rule.Raw) > MaxCompanyScopeRawRunes {
			return &CompanyScopeValidationError{Message: fmt.Sprintf(
				"company scope rule #%d raw value is too long: at most %d characters", i+1, MaxCompanyScopeRawRunes,
			)}
		}
		if utf8.RuneCountInString(rule.Value) > MaxCompanyScopeValueRunes {
			return &CompanyScopeValidationError{Message: fmt.Sprintf(
				"company scope rule #%d normalized value is too long: at most %d characters", i+1, MaxCompanyScopeValueRunes,
			)}
		}
	}
	return nil
}

func ensureCompanyExistsTx(tx *sql.Tx, accountID, companyID int64) error {
	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM companies WHERE id = $1 AND account_id = $2)`, companyID, accountID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrCompanyNotFound
	}
	return nil
}

func lockCompanyScopeMutation(tx *sql.Tx) error {
	_, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, companyScopeMutationLock)
	return err
}

func insertScopeRulesTx(tx *sql.Tx, companyID int64, rules []ParsedScope, reason string) (
	added, skipped int, needsAttribution bool, err error,
) {
	for _, rule := range rules {
		inserted, insertErr := insertScopeRuleTx(tx, companyID, rule, reason)
		if insertErr != nil {
			return 0, 0, false, insertErr
		}
		if !inserted {
			skipped++
			continue
		}
		added++
		needsAttribution = needsAttribution || rule.Kind != "keyword"
	}
	return added, skipped, needsAttribution, nil
}

// insertScopeRuleTx inserts a scope rule. inserted=false means a duplicate was
// ignored by ON CONFLICT, not an error.
func insertScopeRuleTx(tx *sql.Tx, companyID int64, rule ParsedScope, reason string) (inserted bool, err error) {
	var res interface{ RowsAffected() (int64, error) }
	switch rule.Kind {
	case "domain":
		res, err = tx.Exec(`
INSERT INTO company_scope(company_id, kind, domain, raw, reason)
VALUES ($1, 'domain', $2, $3, $4)
ON CONFLICT ON CONSTRAINT uq_sv2_domain DO NOTHING`,
			companyID, rule.Domain, rule.Raw, reason)
	case "ip", "cidr":
		res, err = tx.Exec(`
INSERT INTO company_scope(company_id, kind, net, raw, reason)
VALUES ($1, $2, $3::cidr, $4, $5)
ON CONFLICT ON CONSTRAINT uq_sv2_net DO NOTHING`,
			companyID, rule.Kind, rule.Net, rule.Raw, reason)
	case "icp", "keyword":
		res, err = tx.Exec(`
INSERT INTO company_scope(company_id, kind, value, raw, reason)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (company_id, kind, value) WHERE kind IN ('icp','keyword') DO NOTHING`,
			companyID, rule.Kind, rule.Value, rule.Raw, reason)
	default:
		return false, fmt.Errorf("unsupported company scope kind %q", rule.Kind)
	}
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecomputeAttribution rebuilds only scope-derived ownership. Explicit company
// links are immutable under scope edits. Precedence is domain, IP/CIDR, then
// normalized exact ICP; keyword rules never attribute assets.
func (s *CompanyStore) RecomputeAttribution(accountID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := lockCompanyScopeMutation(tx); err != nil {
		return err
	}
	warning, err := recomputeAttributionTx(tx, accountID)
	if err != nil {
		return err
	}
	logAttributionWarning(warning)
	return tx.Commit()
}

// recomputeAttributionTx rebuilds scope-derived ownership for ONE account.
// Every statement filters assets by a.account_id = $1 and constrains the
// candidate company_scope rows to companies owned by that same account
// (company_scope has no account_id column of its own, so it is joined
// through companies) — without both halves, a scope rule in one account
// could attribute an asset belonging to a different account whenever their
// domain/IP/ICP patterns happen to coincide, which is exactly the leak this
// function exists to prevent now that it runs across more than one tenant.
//
// It returns a warning for assets whose ip column cannot be parsed: try_inet
// skips them instead of aborting the statement, so without this they would
// silently never receive a network-based company. Callers surface the
// warning and it is always logged.
func recomputeAttributionTx(tx *sql.Tx, accountID int64) (string, error) {
	// Only derived rows are cleared, and only within this account. Historical
	// rows migrated without provenance are marked explicit by schema.sql,
	// which is the non-destructive default.
	if _, err := tx.Exec(`
UPDATE assets
SET company_id = NULL, company_source = 'scope'
WHERE company_source = 'scope' AND account_id = $1`, accountID); err != nil {
		return "", err
	}

	// Domain-based attribution (root_domain exact match).
	if _, err := tx.Exec(`
WITH matched AS (
    SELECT DISTINCT ON (a.id) a.id AS asset_id, cs.company_id
    FROM assets a
    JOIN company_scope cs ON cs.kind = 'domain' AND a.root_domain = cs.domain
    JOIN companies comp ON comp.id = cs.company_id AND comp.account_id = $1
    WHERE a.company_id IS NULL
      AND a.account_id = $1
      AND a.type IN ('root_domain','subdomain','service','endpoint')
      AND a.root_domain IS NOT NULL
    ORDER BY a.id, length(cs.domain) DESC, cs.company_id
)
UPDATE assets a
SET company_id = matched.company_id, company_source = 'scope'
FROM matched
WHERE a.id = matched.asset_id`, accountID); err != nil {
		return "", err
	}

	// IP/CIDR attribution for still-unowned assets.
	if _, err := tx.Exec(`
WITH matched AS (
    SELECT DISTINCT ON (a.id) a.id AS asset_id, cs.company_id
    FROM assets a
    JOIN company_scope cs ON cs.kind IN ('ip','cidr') AND cs.net >>= try_inet(a.ip)
    JOIN companies comp ON comp.id = cs.company_id AND comp.account_id = $1
    WHERE a.company_id IS NULL
      AND a.account_id = $1
      AND a.type IN ('ip','subdomain','service','endpoint')
      AND a.ip IS NOT NULL
    ORDER BY a.id, masklen(cs.net) DESC, cs.company_id
)
UPDATE assets a
SET company_id = matched.company_id, company_source = 'scope'
FROM matched
WHERE a.id = matched.asset_id`, accountID); err != nil {
		return "", err
	}

	// Exact normalized ICP attribution after domain/network precedence.
	if _, err := tx.Exec(`
WITH matched AS (
    SELECT DISTINCT ON (a.id) a.id AS asset_id, cs.company_id
    FROM assets a
    JOIN company_scope cs ON cs.kind = 'icp'
      AND (
        lower(regexp_replace(COALESCE(a.icp,''), '[[:space:]]+', '', 'g')) = cs.value
        OR lower(regexp_replace(COALESCE(a.app_icp,''), '[[:space:]]+', '', 'g')) = cs.value
      )
    JOIN companies comp ON comp.id = cs.company_id AND comp.account_id = $1
	WHERE a.company_id IS NULL
      AND a.account_id = $1
      AND (COALESCE(a.icp,'') <> '' OR COALESCE(a.app_icp,'') <> '')
    ORDER BY a.id, cs.company_id
)
UPDATE assets a
SET company_id = matched.company_id, company_source = 'scope'
FROM matched
WHERE a.id = matched.asset_id`, accountID); err != nil {
		return "", err
	}
	return malformedIPAssetWarning(tx, accountID)
}

// malformedIPAssetsSampled bounds how many offending ids one warning names, so a
// large batch of bad rows stays readable in a toast and in the log.
const malformedIPAssetsSampled = 5

// logAttributionWarning records a recompute warning in the server log. Every
// recompute path calls it, so the warning is reported even for triggers with no
// per-request response (company deletion, scopesentry sync, agent asset writes).
func logAttributionWarning(warning string) {
	if warning != "" {
		log.Printf("[assets] %s", warning)
	}
}

// malformedIPAssetQueryer is satisfied by both *sql.Tx and *DB so the warning
// can be produced inside a recompute transaction or read standalone by the API.
type malformedIPAssetQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// MalformedIPAssetWarning reports assets with an unparseable ip outside of any
// mutation, letting the API attach the warning to a scope response without
// widening the mutation signatures — an unrelated data problem is not one of
// this request's validation errors.
func (s *CompanyStore) MalformedIPAssetWarning(accountID int64) (string, error) {
	return malformedIPAssetWarning(s.db, accountID)
}

// malformedIPAssetWarning describes assets, within accountID, whose ip column
// is not a valid address. They are invisible to network attribution, so the
// operator has to be told which rows to fix — silently skipping them would
// look like scope rules that simply do not work.
func malformedIPAssetWarning(q malformedIPAssetQueryer, accountID int64) (string, error) {
	rows, err := q.Query(`
SELECT id, ip, count(*) OVER () AS total
FROM assets
WHERE ip IS NOT NULL AND ip <> '' AND try_inet(ip) IS NULL
  AND type IN ('ip','subdomain','service','endpoint')
  AND account_id = $2
ORDER BY id
LIMIT $1`, malformedIPAssetsSampled, accountID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var total int
	samples := make([]string, 0, malformedIPAssetsSampled)
	for rows.Next() {
		var id int64
		var ip string
		if err := rows.Scan(&id, &ip, &total); err != nil {
			return "", err
		}
		samples = append(samples, fmt.Sprintf("#%d %s", id, ip))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if total == 0 {
		return "", nil
	}
	warning := fmt.Sprintf(
		"%d assets have an ip field that is not a valid IP; skipped for IP/CIDR scope matching (these assets will not be attributed to a company by subnet rules): %s",
		total, strings.Join(samples, ", "),
	)
	if total > len(samples) {
		warning += fmt.Sprintf(" and %d more", total)
	}
	return warning, nil
}

// UpdateScope replaces all scope rules for a company and reattributes.
func (s *CompanyStore) UpdateScope(accountID, companyID int64, lines []string, reason string) (added, invalid int, errs []string) {
	inputs := make([]ScopeInput, 0, len(lines))
	for _, line := range lines {
		inputs = append(inputs, ScopeInput{Value: line})
	}
	return s.UpdateScopeInputs(accountID, companyID, inputs, reason)
}

// UpdateScopeInputs replaces all rules with a structured set.
func (s *CompanyStore) UpdateScopeInputs(accountID, companyID int64, inputs []ScopeInput, reason string) (added, invalid int, errs []string) {
	added, invalid, validationErrors, err := s.UpdateScopeInputsChecked(accountID, companyID, inputs, reason)
	if err != nil {
		validationErrors = append(validationErrors, err.Error())
	}
	return added, invalid, validationErrors
}

// UpdateScopeInputsChecked replaces all rules while separating validation
// feedback from storage and transaction failures.
func (s *CompanyStore) UpdateScopeInputsChecked(accountID, companyID int64, inputs []ScopeInput, reason string) (
	added, invalid int, validationErrors []string, err error,
) {
	if err := ValidateCompanyScopeInputBounds(inputs); err != nil {
		return 0, 0, nil, err
	}
	rules, invalid, errs := parseScopeInputs(inputs)
	if invalid > 0 {
		return 0, invalid, errs, &CompanyScopeValidationError{Message: fmt.Sprintf(
			"company scope contains %d invalid rules; the existing scope was not overwritten", invalid,
		)}
	}
	if err := validateParsedScopeBounds(rules); err != nil {
		return 0, invalid, errs, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, invalid, errs, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := lockCompanyScopeMutation(tx); err != nil {
		return 0, invalid, errs, err
	}
	if err := ensureCompanyExistsTx(tx, accountID, companyID); err != nil {
		return 0, invalid, errs, err
	}
	if _, err := tx.Exec(`DELETE FROM company_scope WHERE company_id = $1`, companyID); err != nil {
		return 0, invalid, errs, err
	}
	added, _, _, err = insertScopeRulesTx(tx, companyID, rules, reason)
	if err != nil {
		return 0, invalid, errs, err
	}
	// Rebuild even for an empty replacement because removing the old rules may
	// detach scope-derived assets or expose a lower-precedence company match.
	warning, err := recomputeAttributionTx(tx, accountID)
	if err != nil {
		return 0, invalid, errs, fmt.Errorf("failed to recompute company attribution: %w", err)
	}
	logAttributionWarning(warning)
	if err := tx.Commit(); err != nil {
		return 0, invalid, errs, err
	}
	return added, invalid, errs, nil
}

// ResolveCompany returns the company_id for a given root_domain and/or ip
// within accountID, or nil if no scope rule matches. Mirrors the attribution
// logic used at asset insert time.
func (s *CompanyStore) ResolveCompany(accountID int64, rootDomain, ipStr string) (*int64, error) {
	return s.ResolveCompanyWithICP(accountID, rootDomain, ipStr, "")
}

// ResolveCompanyWithICP mirrors RecomputeAttribution for insert-time
// ownership, scoped to accountID. ICP is consulted only after domain and
// IP/CIDR fail to match.
func (s *CompanyStore) ResolveCompanyWithICP(accountID int64, rootDomain, ipStr, icp string) (*int64, error) {
	return resolveCompanyWithICP(s.db, accountID, rootDomain, ipStr, icp)
}

type companyScopeQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

// resolveCompanyWithICP mirrors recomputeAttributionTx's precedence
// (domain, then IP/CIDR, then ICP) for one asset at insert time, filtering
// every candidate company_scope row to companies owned by accountID — the
// same cross-account leak recomputeAttributionTx guards against applies here:
// without it, a brand-new asset could be auto-attributed to another
// account's company on a coincidental domain/IP/ICP match.
func resolveCompanyWithICP(q companyScopeQueryer, accountID int64, rootDomain, ipStr, icp string) (*int64, error) {
	if rootDomain != "" {
		var cid int64
		err := q.QueryRow(`
SELECT cs.company_id FROM company_scope cs
JOIN companies c ON c.id = cs.company_id
WHERE cs.kind = 'domain'
  AND cs.domain = $1
  AND c.account_id = $2
ORDER BY length(cs.domain) DESC, cs.company_id
LIMIT 1`, rootDomain, accountID).Scan(&cid)
		if err == nil {
			return &cid, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	if ipStr != "" {
		if net.ParseIP(ipStr) != nil {
			var cid int64
			err := q.QueryRow(`
SELECT cs.company_id FROM company_scope cs
JOIN companies c ON c.id = cs.company_id
WHERE cs.kind IN ('ip','cidr')
  AND cs.net >>= $1::inet
  AND c.account_id = $2
ORDER BY masklen(cs.net) DESC, cs.company_id
LIMIT 1`, ipStr, accountID).Scan(&cid)
			if err == nil {
				return &cid, nil
			}
			if err != sql.ErrNoRows {
				return nil, err
			}
		}
	}
	if normalized := NormalizeICP(icp); normalized != "" {
		var cid int64
		err := q.QueryRow(`
SELECT cs.company_id FROM company_scope cs
JOIN companies c ON c.id = cs.company_id
WHERE cs.kind = 'icp' AND cs.value = $1
  AND c.account_id = $2
ORDER BY cs.company_id
LIMIT 1`, normalized, accountID).Scan(&cid)
		if err == nil {
			return &cid, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	return nil, nil
}
