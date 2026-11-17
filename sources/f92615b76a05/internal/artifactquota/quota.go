package artifactquota

import (
	"errors"
	"io/fs"
	"os"
	"sync"
)

const Limit int64 = 1 << 30

var ErrExceeded = errors.New("account artifact quota of 1 GiB exceeded; existing data was preserved")

// All producers for one account share admission; other accounts continue independently.
var writes sync.Map

type accountUsage struct {
	sync.Mutex
	total int64
	known bool
}

func usage(root *os.Root) *accountUsage {
	value, _ := writes.LoadOrStore(root.Name(), &accountUsage{})
	return value.(*accountUsage)
}

// Invalidate is for a producer that changed the tree outside Write/Remove.
func Invalidate(root *os.Root) {
	state := usage(root)
	state.Lock()
	state.known = false
	state.Unlock()
}

// Remove shares write admission and can release space even when the quota is full.
func Remove(root *os.Root, path string) error    { return remove(root, path, false) }
func RemoveAll(root *os.Root, path string) error { return remove(root, path, true) }
func remove(root *os.Root, path string, all bool) error {
	state := usage(root)
	state.Lock()
	defer state.Unlock()
	state.known = false
	if all {
		return root.RemoveAll(path)
	}
	return root.Remove(path)
}

func Bytes(root *os.Root) (int64, error) {
	state := usage(root)
	state.Lock()
	defer state.Unlock()
	total, err := scanBytes(root)
	if err == nil {
		state.total = total
		state.known = true
	} else {
		state.known = false
	}
	return total, err
}
func scanBytes(root *os.Root) (int64, error) {
	var total int64
	err := fs.WalkDir(root.FS(), ".", func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err == nil {
			total += info.Size()
		}
		return err
	})
	return total, err
}

// Write reserves incremental bytes under account admission; startup and uncertain writes reconcile the tree.
// size is the replacement size, or the additional bytes for an append.
func Check(root *os.Root, path string, size int64) error {
	return write(root, path, size, false, Limit, nil)
}
func Write(root *os.Root, path string, size int64, appendOnly bool, commit func() error) error {
	return write(root, path, size, appendOnly, Limit, commit)
}

func write(root *os.Root, path string, size int64, appendOnly bool, limit int64, commit func() error) error {
	state := usage(root)
	state.Lock()
	defer state.Unlock()
	if size < 0 {
		return ErrExceeded
	}
	if !state.known {
		total, err := scanBytes(root)
		if err != nil {
			return err
		}
		state.total = total
		state.known = true
	}
	total := state.total
	if !appendOnly {
		info, err := root.Lstat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && info.Mode().IsRegular() {
			total -= info.Size()
		}
		if err == nil && info.IsDir() {
			child, err := root.OpenRoot(path)
			if err != nil {
				return err
			}
			old, err := scanBytes(child)
			child.Close()
			if err != nil {
				return err
			}
			total -= old
		}
	}
	if total < 0 {
		state.known = false
		return errors.New("artifact quota changed; retry after reconciliation")
	}
	if total > limit || size > limit-total {
		return ErrExceeded
	}
	if commit == nil {
		return nil
	}
	if err := commit(); err != nil {
		state.known = false
		return err
	}
	state.total = total + size
	return nil
}
