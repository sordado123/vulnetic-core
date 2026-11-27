package reverseagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type ExecutorConfig struct {
	HostKey   ssh.Signer
	ClientKey ssh.PublicKey
	Username  string
	Directory string
	slots     chan struct{}
}

func Serve(ctx context.Context, connection net.Conn, cfg ExecutorConfig) error {
	if cfg.HostKey == nil || cfg.ClientKey == nil || cfg.Username == "" {
		return errors.New("executor identity is required")
	}
	cfg.slots = make(chan struct{}, 32)
	return serve(ctx, connection, cfg, true)
}

func serve(parent context.Context, connection net.Conn, cfg ExecutorConfig, outer bool) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != cfg.Username || !bytes.Equal(key.Marshal(), cfg.ClientKey.Marshal()) {
			return nil, errors.New("executor authentication failed")
		}
		return nil, nil
	}}
	config.AddHostKey(cfg.HostKey)
	if runtime.GOOS == "windows" {
		config.ServerVersion = "SSH-2.0-Vulnetic-Windows"
	}
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return err
	}
	_ = connection.SetDeadline(time.Time{})
	defer server.Close()
	go func() {
		for request := range requests {
			if request.WantReply {
				_ = request.Reply(request.Type == "keepalive@vulnetic", nil)
			}
		}
	}()
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	slots := make(chan struct{}, 32)
	if !outer {
		slots = cfg.slots
	}
	for incoming := range channels {
		select {
		case slots <- struct{}{}:
		default:
			_ = incoming.Reject(ssh.ResourceShortage, "executor channel limit reached")
			continue
		}
		kind := incoming.ChannelType()
		if (outer && kind != "vulnetic-executor") || (!outer && kind != "session" && kind != "direct-tcpip") {
			<-slots
			_ = incoming.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		workers.Add(1)
		go func(incoming ssh.NewChannel) {
			defer workers.Done()
			defer func() { <-slots }()
			if outer {
				channel, requests, err := incoming.Accept()
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				_ = serve(ctx, &ChannelConn{Channel: channel}, cfg, false)
			} else if incoming.ChannelType() == "session" {
				serveSession(ctx, incoming, cfg.Directory)
			} else {
				serveTCP(ctx, incoming)
			}
		}(incoming)
	}
	return server.Wait()
}

func serveTCP(ctx context.Context, incoming ssh.NewChannel) {
	var address struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}
	if ssh.Unmarshal(incoming.ExtraData(), &address) != nil || address.Port == 0 || address.Port > 65535 {
		_ = incoming.Reject(ssh.Prohibited, "invalid destination")
		return
	}
	connection, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(address.Host, fmt.Sprint(address.Port)))
	if err != nil {
		_ = incoming.Reject(ssh.ConnectionFailed, "remote connection failed")
		return
	}
	defer connection.Close()
	channel, requests, err := incoming.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	stop := context.AfterFunc(ctx, func() { _ = connection.Close(); _ = channel.Close() })
	defer stop()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(connection, channel); _ = connection.Close(); close(done) }()
	_, _ = io.Copy(channel, connection)
	_ = channel.Close()
	_ = connection.Close()
	<-done
}

func serveSession(ctx context.Context, incoming ssh.NewChannel, directory string) {
	channel, requests, err := incoming.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	stop := context.AfterFunc(ctx, func() { _ = channel.Close() })
	defer stop()
	for request := range requests {
		if request.Type != "exec" {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			continue
		}
		var payload struct{ Command string }
		if ssh.Unmarshal(request.Payload, &payload) != nil || len(payload.Command) > 1<<20 {
			_ = request.Reply(false, nil)
			return
		}
		if serveNative(ctx, payload.Command, directory, channel, request) {
			return
		}
		command, err := shellCommand(payload.Command, directory)
		if err != nil {
			_ = request.Reply(false, nil)
			return
		}
		if prepareProcess(command) != nil {
			_ = request.Reply(false, nil)
			return
		}
		defer killProcess(command)
		stdin, err := command.StdinPipe()
		if err != nil {
			_ = request.Reply(false, nil)
			return
		}
		command.Stdout = channel
		command.Stderr = channel.Stderr()
		if err = command.Start(); err != nil {
			_ = stdin.Close()
			_ = request.Reply(false, nil)
			return
		}
		if err = startedProcess(command); err != nil {
			killProcess(command)
			_ = command.Wait()
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		go func() { _, _ = io.Copy(stdin, channel); _ = stdin.Close() }()
		kill := context.AfterFunc(ctx, func() { killProcess(command) })
		done := make(chan struct{})
		go func() {
			defer close(done)
			for request := range requests {
				var signal struct{ Name string }
				ok := request.Type == "signal" && ssh.Unmarshal(request.Payload, &signal) == nil && (signal.Name == "KILL" || signal.Name == "TERM" || signal.Name == "INT")
				if ok {
					killProcess(command)
				}
				if request.WantReply {
					_ = request.Reply(ok, nil)
				}
			}
			killProcess(command)
		}()
		err = command.Wait()
		kill()
		killProcess(command)
		status := uint32(0)
		if err != nil {
			status = 1
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() >= 0 {
				status = uint32(exit.ExitCode())
			}
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		_ = channel.Close()
		<-done
		return
	}
}
