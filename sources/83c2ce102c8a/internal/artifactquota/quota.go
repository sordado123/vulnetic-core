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

// Remove shares write admission and can release space even when the quota is full.
func Remove(root *os.Root, path string) error {
	value, _ := writes.LoadOrStore(root.Name(), &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	return root.Remove(path)
}

func Bytes(root *os.Root) (int64, error) {
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

// Write checks the complete account tree and holds admission until commit.
// size is the replacement size, or the additional bytes for an append.
func Write(root *os.Root, path string, size int64, appendOnly bool, commit func() error) error {
	return write(root, path, size, appendOnly, Limit, commit)
}

func write(root *os.Root, path string, size int64, appendOnly bool, limit int64, commit func() error) error {
	value, _ := writes.LoadOrStore(root.Name(), &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	if size < 0 {
		return ErrExceeded
	}
	total, err := Bytes(root)
	if err != nil {
		return err
	}
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
			old, err := Bytes(child)
			child.Close()
			if err != nil {
				return err
			}
			total -= old
		}
	}
	if total > limit || size > limit-total {
		return ErrExceeded
	}
	return commit()
}
