package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/sordado123/vulnetic/internal/reverseagent"
)

var installationName = regexp.MustCompile(`^vulnetic-agent\.[A-Za-z0-9]{8}$`)

func validateInstallation(executable, enrollmentFile, cgroup string) error {
	directory := filepath.Dir(executable)
	if filepath.Base(executable) != "agent" || !installationName.MatchString(filepath.Base(directory)) || filepath.Clean(enrollmentFile) != filepath.Join(directory, "state", "enrollment") {
		return errors.New("use the Vulnetic installation command")
	}
	for _, path := range []string{directory, executable, enrollmentFile} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid private installation path")
		}
	}
	info, err := os.Stat(enrollmentFile)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return errors.New("enrollment input must be a private file")
	}
	unit := strings.ReplaceAll(filepath.Base(directory), ".", "-") + ".service"
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && strings.Contains("/"+strings.Trim(parts[2], "/")+"/", "/"+unit+"/") {
			return nil
		}
	}
	return errors.New("systemd lifetime and process-group supervision are required; use the generated installation command")
}

func requireUnprivilegedUser(uid int) error {
	if uid <= 0 {
		return errors.New("the executor must run as its dedicated non-root user; reinstall with the generated command")
	}
	return nil
}

func requirePrivateGroups(primary int, groups []int) error {
	if primary <= 0 {
		return errors.New("the executor requires its dedicated private group")
	}
	for _, group := range groups {
		if group != primary {
			return errors.New("the executor must not belong to supplementary groups such as sudo or docker")
		}
	}
	return nil
}

func runLinux() error {
	server := flag.String("server", "", "Vulnetic HTTPS URL")
	enrollmentFile := flag.String("enrollment-file", "", "private one-use enrollment input")
	directory := flag.String("directory", "", "remote task workspace base")
	flag.Parse()
	_ = os.Unsetenv("VULNETIC_ENROLL_TOKEN")
	_ = os.Unsetenv("VULNETIC_SERVER_URL")
	if runtime.GOOS != "linux" {
		return errors.New("the temporary executor requires Linux")
	}
	if err := requireUnprivilegedUser(os.Geteuid()); err != nil {
		return err
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	if err = requirePrivateGroups(os.Getegid(), groups); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cgroups, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return errors.New("process supervision is unavailable")
	}
	if err = validateInstallation(executable, *enrollmentFile, string(cgroups)); err != nil {
		return err
	}
	enrollment, err := os.Open(*enrollmentFile)
	if err != nil {
		return errors.New("could not open the private enrollment input")
	}
	input, err := io.ReadAll(io.LimitReader(enrollment, 256))
	_ = enrollment.Close()
	if err != nil {
		return errors.New("could not read the enrollment input")
	}
	identity, err := user.Current()
	if err != nil {
		return errors.New("could not identify the executor user")
	}
	if *directory == "" {
		*directory, err = os.UserHomeDir()
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "Temporary Vulnetic executor starting; authorization expires automatically.")
	err = reverseagent.Run(ctx, reverseagent.ClientConfig{ServerURL: *server, EnrollmentToken: strings.TrimSpace(string(input)), Username: identity.Username, Directory: *directory, StateFile: filepath.Join(filepath.Dir(*enrollmentFile), "state.enc"), EnrollmentFile: *enrollmentFile})
	if errors.Is(err, reverseagent.ErrLeaseEnded) || errors.Is(err, context.DeadlineExceeded) {
		_ = os.WriteFile(filepath.Join(filepath.Dir(*enrollmentFile), "expired"), nil, 0600)
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
