package main

import (
	"context"
	"github.com/sordado123/vulnetic/internal/agentgateway"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	token, err := os.ReadFile(os.Getenv("VULNETIC_GATEWAY_TOKEN_FILE"))
	if err != nil {
		log.Fatal("gateway token file unavailable")
	}
	g, err := agentgateway.New(strings.TrimSpace(string(token)))
	if err != nil {
		log.Fatal(err)
	}
	for _, item := range strings.Split(os.Getenv("VULNETIC_GATEWAY_TRUSTED_PROXIES"), ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		prefix, e := netip.ParsePrefix(strings.TrimSpace(item))
		if e != nil {
			log.Fatal("invalid trusted proxy prefix")
		}
		g.TrustedProxies = append(g.TrustedProxies, prefix)
	}
	g.LegacyHost = os.Getenv("VULNETIC_LEGACY_AGENT_HOST")
	if g.LegacyHost != "" {
		g.LegacyUntil, err = time.Parse(time.RFC3339, os.Getenv("VULNETIC_LEGACY_AGENT_UNTIL"))
		if err != nil || g.LegacyUntil.After(time.Now().Add(7*24*time.Hour)) {
			log.Fatal("legacy agent deadline must be fixed and within seven days")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	public := &http.Server{Addr: ":8788", Handler: g.PublicHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	private := &http.Server{Addr: ":8789", Handler: g.PrivateHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		if err := public.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Print("gateway public listener stopped")
			stop()
		}
	}()
	go func() {
		if err := private.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Print("gateway control listener stopped")
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = public.Shutdown(shutdown)
	_ = private.Shutdown(shutdown)
}
