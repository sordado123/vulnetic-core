package artifactquota

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestSharedAccountQuotaPreservesExistingData(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("existing", []byte("123456"), 0600); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for _, name := range []string{"skill", "transcript"} {
		group.Add(1)
		go func() {
			defer group.Done()
			err := write(root, name, 4, false, 10, func() error { return root.WriteFile(name, []byte("data"), 0600) })
			if err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			} else if !errors.Is(err, ErrExceeded) {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d writes, expected exactly one", accepted)
	}
	if data, err := root.ReadFile("existing"); err != nil || string(data) != "123456" {
		t.Fatal("existing data changed", err)
	}
	if err := write(root, "existing", 2, false, 10, func() error { return root.WriteFile("existing", []byte("ok"), 0600) }); err != nil {
		t.Fatal("shrinking an existing file must remain possible", err)
	}
	called := false
	if err := write(root, "existing", 5, true, 10, func() error { called = true; return nil }); !errors.Is(err, ErrExceeded) || called {
		t.Fatal("append exceeded shared quota", err)
	}
}

func TestSlowAccountDoesNotBlockOtherAccounts(t *testing.T) {
	first, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_ = write(first, "file", 1, false, 10, func() error { close(started); <-release; return nil })
	}()
	defer func() { close(release); <-finished }()
	<-started
	other := make(chan error, 1)
	go func() { other <- write(second, "file", 1, false, 10, func() error { return nil }) }()
	select {
	case err := <-other:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("one account blocked another account's artifact writes")
	}
}

func TestQuotaReconcilesAfterUncertainWrite(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = write(root, "partial", 4, false, 10, func() error {
		if err := root.WriteFile("partial", []byte("1234"), 0600); err != nil {
			return err
		}
		return errors.New("synthetic failure")
	})
	if err == nil {
		t.Fatal("write failure hidden")
	}
	called := false
	err = write(root, "next", 7, false, 10, func() error { called = true; return nil })
	if !errors.Is(err, ErrExceeded) || called {
		t.Fatal("partial file was not counted", err)
	}
}

func TestDatabaseAllowanceReconcilesFailedWrite(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("existing", []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	err = WithAllowance(root, func(available int64) error {
		if available != Limit-3 {
			t.Fatalf("wrong allowance: %d", available)
		}
		if err := root.WriteFile("index", []byte("pages"), 0600); err != nil {
			return err
		}
		return errors.New("synthetic failed database operation")
	})
	if err == nil {
		t.Fatal("producer failure hidden")
	}
	if total, err := Bytes(root); err != nil || total != 8 {
		t.Fatalf("failed producer bytes not reconciled: %d %v", total, err)
	}
}
