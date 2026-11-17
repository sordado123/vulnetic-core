package notify

import (
	"context"
	"fmt"
	"net"

	"github.com/sordado123/vulnetic/config"
)

type DialContext func(context.Context, string, string) (net.Conn, error)
type remoteDialKey struct{}

func WithRemoteDial(ctx context.Context, dial DialContext) context.Context {
	return context.WithValue(ctx, remoteDialKey{}, dial)
}
func remoteDial(ctx context.Context) (DialContext, error) {
	dial, _ := ctx.Value(remoteDialKey{}).(DialContext)
	if config.SaaSMode() && dial == nil {
		return nil, fmt.Errorf("notification delivery requires a verified VPS")
	}
	return dial, nil
}
