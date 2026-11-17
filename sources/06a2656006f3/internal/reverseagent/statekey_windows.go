package reverseagent

import (
	"context"
	"errors"
	"os"
	"unsafe"

	"github.com/sordado123/vulnetic/internal/winsecure"
	"golang.org/x/sys/windows"
)

func clientPlatform() string                           { return "windows" }
func privateStateFile(path string, _ os.FileInfo) bool { return winsecure.Private(path) == nil }

func cryptClientState(ctx context.Context, encrypt bool, data []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !encrypt {
		if len(data) < 5 || string(data[:4]) != "VSCW" {
			return nil, errors.New("invalid encrypted reconnect state")
		}
		data = data[4:]
	}
	if len(data) == 0 {
		return nil, errors.New("empty state")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	result := append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...)
	if encrypt {
		result = append([]byte("VSCW"), result...)
	}
	return result, nil
}
