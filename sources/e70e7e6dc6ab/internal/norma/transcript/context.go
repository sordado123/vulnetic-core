// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package transcript

import "context"

type ctxKey int

const sessionIDKey ctxKey = 0

// WithSessionID carries the active session id on the context so subagents can
// write their sidechain under the parent session's directory.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

// SessionIDFrom returns the session id carried on ctx, or "" if none.
func SessionIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(sessionIDKey).(string)
	return v
}
