package agentgateway

import "errors"

var (
	ErrGatewayUnavailable = errors.New("gateway_unavailable: executor control channel is unavailable")
	ErrExecutorOffline    = errors.New("executor_offline: the authorized executor has not reconnected")
	ErrExecutorClosed     = errors.New("executor_closed: this execution connection was closed")
	ErrExecutorExpired    = errors.New("executor_expired: the original access deadline has passed")
	ErrExecutorRevoked    = errors.New("executor_revoked: executor authorization is no longer valid")
)
