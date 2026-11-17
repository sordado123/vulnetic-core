// Vulnetic SDK incorporation: import paths adapted and release-specific local changes.
// Original notices remain applicable; see THIRD_PARTY_NOTICES.md and SOURCE-SNAPSHOT.json.
package tool

import (
	"context"
	"encoding/json"
)

type resultRecorderKey struct{}
type resultMetadataKey struct{}

func WithResultMetadata(ctx context.Context, fn func(string) string) context.Context {
	return context.WithValue(ctx, resultMetadataKey{}, fn)
}
func ResultMetadataFrom(ctx context.Context, id string) string {
	fn, _ := ctx.Value(resultMetadataKey{}).(func(string) string)
	if fn == nil {
		return ""
	}
	return fn(id)
}

// ResultRecorder receives host-side results before their reduction for the model.
type ResultRecorder func(id, name string, input json.RawMessage, output string, failed bool)

func WithResultRecorder(ctx context.Context, record ResultRecorder) context.Context {
	return context.WithValue(ctx, resultRecorderKey{}, record)
}

func ResultRecorderFrom(ctx context.Context) ResultRecorder {
	record, _ := ctx.Value(resultRecorderKey{}).(ResultRecorder)
	return record
}
