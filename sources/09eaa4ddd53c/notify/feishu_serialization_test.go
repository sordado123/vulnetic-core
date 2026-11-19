package notify

import (
	"strings"
	"testing"
)

func TestFeishuMeasuresSerializedBatch(t *testing.T) {
	items := make([]Item, 500)
	for i := range items {
		items[i] = Item{Name: strings.Repeat("<\"", 100), Severity: "high", Summary: strings.Repeat("<", 200)}
	}
	card, kept := feishuCard(Message{Items: items, Batch: true, Limits: &Limits{SummaryRunes: 0, AssetsShown: 0}})
	if kept <= 0 || kept >= len(items) {
		t.Fatal("batch did not split", kept)
	}
	if feishuEnvelopeBytes+feishuJSONSize(card) > feishuMaxCardBytes {
		t.Fatal("serialized card exceeds cap")
	}
}
