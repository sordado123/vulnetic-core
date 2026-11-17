// Package admission bounds interactive and background work using the same account identity.
package admission

import (
	"context"
	"errors"
	"github.com/sordado123/vulnetic/config"
	"sync"
	"time"
)

var ErrBusy = errors.New("capacity_busy: execution capacity is in use; retry after current work completes")

type Pool struct {
	mu                sync.Mutex
	active            int
	accounts          map[int64]int
	perAccount, total int
}

func New(perAccount, total int) *Pool {
	return &Pool{accounts: map[int64]int{}, perAccount: perAccount, total: total}
}

var Models = New(3, 15)
var Commands = New(4, 20)
var Connections = New(16, 80)
var Conversations = New(2, 10)

func (p *Pool) Try(account int64) (func(), error) {
	if !config.SaaSMode() {
		return func() {}, nil
	}
	if account <= 0 {
		return nil, errors.New("execution account is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active >= p.total || p.accounts[account] >= p.perAccount {
		return nil, ErrBusy
	}
	p.active++
	p.accounts[account]++
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.active--
			p.accounts[account]--
			if p.accounts[account] == 0 {
				delete(p.accounts, account)
			}
		})
	}, nil
}

// Wait only holds the caller's existing run; cancellation never starts a delayed call.
func (p *Pool) Wait(ctx context.Context, account int64) (func(), error) {
	for {
		release, err := p.Try(account)
		if err == nil {
			return release, nil
		}
		if !errors.Is(err, ErrBusy) {
			return nil, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
