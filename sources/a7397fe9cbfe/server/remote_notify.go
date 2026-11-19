package server

import (
	"context"
	"fmt"

	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/notify"
)

func (s *Server) notificationContext(ctx context.Context, accountID int64, cfg map[string]any) (context.Context, func(), error) {
	if !config.SaaSMode() {
		return ctx, func() {}, nil
	}
	value, _ := cfg["ssh_target_id"].(float64)
	if value <= 0 || value != float64(int64(value)) {
		return nil, nil, fmt.Errorf("select a verified VPS for this notification channel")
	}
	ex, closeExecutor, err := s.remoteExecutor(accountID, int64(value), fmt.Sprintf(".vulnetic/accounts/%d/notifications", accountID))
	if err != nil {
		return nil, nil, err
	}
	return notify.WithRemoteDial(ctx, ex.DialContext), closeExecutor, nil
}
