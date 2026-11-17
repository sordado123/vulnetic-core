package admission

import (
	"context"
	"errors"
	"testing"
)

func TestAdmissionAccountAndProcessBounds(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	p := New(1, 2)
	a, err := p.Try(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Try(1); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	b, err := p.Try(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Try(3); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	a()
	a()
	c, err := p.Try(3)
	if err != nil {
		t.Fatal(err)
	}
	b()
	c()
	if p.active != 0 {
		t.Fatal("release leaked capacity")
	}
	if _, err = p.Try(0); err == nil {
		t.Fatal("missing owner allowed")
	}
}
func TestAdmissionCancelledWait(t *testing.T) {
	t.Setenv("VULNETIC_SAAS_MODE", "true")
	p := New(1, 1)
	release, _ := p.Try(1)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Wait(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
