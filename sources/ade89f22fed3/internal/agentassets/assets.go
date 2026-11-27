package agentassets

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sordado123/vulnetic/config"
	"github.com/sordado123/vulnetic/internal/reverseagent"
)

func openAgentBinary(w http.ResponseWriter, r *http.Request) *os.File {
	arch := r.PathValue("arch")
	filename := "linux-" + arch
	if arch == "windows-amd64" {
		filename = "windows-amd64.exe"
	} else if arch != "amd64" && arch != "arm64" {
		writeErr(w, 404, "unsupported executor architecture")
		return nil
	}
	directory := os.Getenv("VULNETIC_AGENT_BINARY_DIR")
	if directory == "" {
		directory = filepath.Join(config.BaseDir(), "agents")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		writeErr(w, 503, "executor binaries are not installed")
		return nil
	}
	defer root.Close()
	file, err := root.Open(filename)
	if err != nil {
		writeErr(w, 503, "executor binary is unavailable")
		return nil
	}
	return file
}

func Binary(w http.ResponseWriter, r *http.Request) {
	file := openAgentBinary(w, r)
	if file == nil {
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		writeErr(w, 503, "executor binary is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "vulnetic-agent", info.ModTime(), file)
}

func Checksum(w http.ResponseWriter, r *http.Request) {
	file := openAgentBinary(w, r)
	if file == nil {
		return
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		writeErr(w, 503, "executor checksum unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "%x  agent\n", hash.Sum(nil))
}

func Installer(w http.ResponseWriter, r *http.Request) {
	base, err := platformURL()
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = io.WriteString(w, strings.ReplaceAll(InstallScript, "__PLATFORM_URL__", quote(base)))
}

const InstallScript = `#!/bin/sh
set -eu
umask 077
platform=__PLATFORM_URL__
: "${VULNETIC_ENROLL_TOKEN:?Generate a new installation command in Vulnetic}"
: "${VULNETIC_LEASE_SECONDS:?Choose an executor lifetime in Vulnetic}"
case "$VULNETIC_LEASE_SECONDS" in ''|*[!0-9]*) echo 'Invalid executor lifetime' >&2; exit 1;; esac
test "$VULNETIC_LEASE_SECONDS" -ge 300 && test "$VULNETIC_LEASE_SECONDS" -le 604800 || exit 1
test "$(uname -s)" = Linux || { echo 'The executor requires Linux' >&2; exit 1; }
test "$(id -u)" = 0 || { echo 'Run this installer as root (sudo -i). The installed agent runs without root or sudo.' >&2; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported CPU architecture' >&2; exit 1;; esac
for tool in curl sha256sum systemctl systemd-creds bash python3 useradd usermod getent; do command -v "$tool" >/dev/null || { echo "Install required tool: $tool (systemd 250+ required)" >&2; exit 1; }; done
base=/var/lib/vulnetic-executors
workspace=/var/lib/vulnetic-workspace
units=/etc/systemd/system
account=vulnetic-agent
target=multi-user.target
for path in "$base" "$workspace" "$units"; do test ! -L "$path" || { echo 'Unsafe installation directory' >&2; exit 1; }; done
mkdir -p "$base"
test "$(stat -c %u "$base")" = 0 || { echo 'Installation directory must be owned by root; administrator review required' >&2; exit 1; }
chmod 711 "$base"
if getent passwd "$account" >/dev/null; then
 test -f "$base/service-user.uid" && test "$(cat "$base/service-user.uid")" = "$(id -u "$account")" || { echo 'Existing vulnetic-agent account is not managed by this installer; ask your administrator' >&2; exit 1; }
else
 getent group "$account" >/dev/null && { echo 'Existing unmanaged vulnetic-agent group' >&2; exit 1; }
 useradd --system --user-group --home-dir "$workspace" --no-create-home --shell /usr/sbin/nologin "$account"
 printf '%s\n' "$(id -u "$account")" > "$base/service-user.uid"
fi
test "$(id -u "$account")" != 0 && test "$(id -gn "$account")" = "$account" && test "$(id -G "$account")" = "$(id -g "$account")" || { echo 'The dedicated agent user must have no supplementary groups (including sudo or docker)' >&2; exit 1; }
case "$(getent shadow "$account" | cut -d: -f2)" in '!'*|'*'*) ;; *) echo 'The dedicated user password must remain locked' >&2; exit 1;; esac
python3 - "$account" "$workspace" "$base/service-user.uid" <<'USER'
import os,pwd,stat,subprocess,sys
account,home,marker=sys.argv[1:]
record=pwd.getpwnam(account)
info=os.stat(marker,follow_symlinks=False)
if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
 raise SystemExit('Unsafe managed-user marker; administrator review required')
with open(marker) as file:
 if file.read().strip()!=str(record.pw_uid): raise SystemExit('Managed-user identity mismatch; administrator review required')
if record.pw_dir!=home:
 raise SystemExit('Dedicated user home must be '+home+'; found '+record.pw_dir+'. No files were moved; administrator review required')
if record.pw_shell in ('/bin/bash','/usr/bin/bash'):
 shell=next((path for path in ('/usr/sbin/nologin','/sbin/nologin') if os.access(path,os.X_OK)),None)
 if shell is None: raise SystemExit('Install nologin before reinstalling the executor')
 subprocess.run(['usermod','--shell',shell,account],check=True)
 print('Restored nologin for the managed service user; workspace files and existing executor deadlines are unchanged')
elif record.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin'):
 raise SystemExit('Unexpected dedicated user shell: '+record.pw_shell+'; administrator review required')
USER
if test ! -d "$workspace"; then mkdir -m 700 "$workspace"; chown "$account:$account" "$workspace"; fi
test "$(stat -c %u "$workspace")" = "$(id -u "$account")" || { echo 'Workspace ownership needs administrator review; no existing files were changed' >&2; exit 1; }
# Managed workspace preparation: repair only known directories, then drop privileges before creating any.
python3 - "$account" "$workspace" <<'WORKSPACE'
` + prepareWorkspacePython + `
WORKSPACE

directory=$(mktemp -d "$base/vulnetic-agent.XXXXXXXX")
unit=$(basename "$directory" | tr . -)
started=0
cleanup() {
 if test "$started" = 0; then
  systemctl disable --now "$unit.service" >/dev/null 2>&1 || true
  rm -f -- "$units/$unit.service" "$directory/agent" "$directory/checksum" "$directory/cleanup.sh" "$directory/state-key.cred" "$directory/deadline" "$directory/state/enrollment"
  rmdir -- "$directory/state" "$directory" 2>/dev/null || true
 fi
}
trap cleanup EXIT HUP INT TERM
mkdir -m 700 "$directory/state"
chown "$account:$account" "$directory/state"
python3 -c 'import os,sys;sys.stdout.buffer.write(os.urandom(32))' | systemd-creds encrypt --with-key=host --name=vulnetic-state-key - "$directory/state-key.cred" >/dev/null 2>&1 || { echo 'Encrypted systemd credentials unavailable; systemd 250+ is required. No plaintext key was saved.' >&2; exit 1; }
systemd-creds decrypt --name=vulnetic-state-key "$directory/state-key.cred" - >/dev/null 2>&1 || exit 1
curl --fail --silent --show-error "$platform/agent/binary/$arch" -o "$directory/agent"
curl --fail --silent --show-error "$platform/agent/checksum/$arch" -o "$directory/checksum"
(cd "$directory" && sha256sum --check checksum)
chmod 555 "$directory/agent"
printf '%s\n' "$VULNETIC_ENROLL_TOKEN" > "$directory/state/enrollment"
chown "$account:$account" "$directory/state/enrollment"
printf '%s\n' "$(( $(date +%s) + VULNETIC_LEASE_SECONDS ))" > "$directory/deadline"
chmod 444 "$directory/deadline"
unset VULNETIC_ENROLL_TOKEN VULNETIC_SERVER_URL
cat > "$directory/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -eu
directory=$(dirname "$0")
case "$directory" in /var/lib/vulnetic-executors/vulnetic-agent.????????) ;; *) exit 1;; esac
state="$directory/state"
if test "${1:-}" = remove; then
 test "$(id -u)" = 0 || { echo 'Run removal as root; the running agent has no administrative rights' >&2; exit 1; }
 unit=$(basename "$directory" | tr . -)
 systemctl disable --now "$unit.service" >/dev/null 2>&1 || true
 rm -f -- "/etc/systemd/system/$unit.service" "$directory/agent" "$directory/checksum" "$directory/cleanup.sh" "$directory/state-key.cred" "$directory/deadline"
 rm -f -- "$state/enrollment" "$state/state.enc" "$state/expired" "$state"/.state-*
 rmdir -- "$state" "$directory" 2>/dev/null || true
 systemctl daemon-reload >/dev/null 2>&1 || true
 exit 0
fi
if test ! -f "$state/expired" && test "$(date +%s)" -lt "$(cat "$directory/deadline")"; then exit 0; fi
rm -f -- "$state/enrollment" "$state/state.enc" "$state/expired" "$state"/.state-*
CLEANUP
chmod 555 "$directory/cleanup.sh"
chmod 755 "$directory"
python3 - "$units/$unit.service" "$directory" "$platform" "$workspace" "$VULNETIC_LEASE_SECONDS" "$target" <<'UNIT'
import sys
name,directory,platform,home,lifetime,target=sys.argv[1:]
def quote(value): return '"'+value.replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('\n','\\n').replace('\r','\\r')+'"'
args=[directory+'/agent','--server',platform,'--enrollment-file',directory+'/state/enrollment','--directory',home]
with open(name,'x') as file:
 file.write('[Unit]\nDescription=Vulnetic temporary unprivileged executor\nWants=network-online.target\nAfter=network-online.target\nConditionPathExists='+directory+'/state/enrollment\n\n[Service]\nType=simple\nUser=vulnetic-agent\nGroup=vulnetic-agent\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nUMask=0077\nReadWritePaths='+quote(directory+'/state')+' '+quote(home)+'\nLoadCredentialEncrypted=vulnetic-state-key:'+directory+'/state-key.cred\nExecStart='+ ' '.join(map(quote,args))+'\nStandardInput=null\nExecStopPost=/bin/sh '+quote(directory+'/cleanup.sh')+'\nRestart=on-failure\nRestartSec=5\nRuntimeMaxSec='+lifetime+'\nTimeoutStopSec=5\nKillMode=control-group\nSendSIGKILL=yes\nEnvironment=PATH=/usr/bin:/bin:/usr/sbin:/sbin\nEnvironment=HOME='+quote(home)+'\n\n[Install]\nWantedBy='+target+'\n')
UNIT
systemctl daemon-reload
systemctl enable --now "$unit.service"
started=1
printf 'Vulnetic executor runs as vulnetic-agent without root or sudo. Verify the connection in Vulnetic. Reconnect preserves the original deadline.\n'
printf 'Expiry clears private connection state; root-owned service files stay inactive. Workspace: %s\n' "$workspace"
printf 'To remove all installation files, as root: sh %s/cleanup.sh remove\n' "$directory"
`

func writeErr(w http.ResponseWriter, status int, message string) { http.Error(w, message, status) }
func quote(value string) string                                  { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func platformURL() (string, error) {
	base := strings.TrimSpace(os.Getenv("VULNETIC_AGENT_PUBLIC_URL"))
	if base == "" {
		base = strings.TrimSpace(os.Getenv("VULNETIC_PUBLIC_URL"))
	}
	u, err := reverseagent.ValidateServerURL(base)
	if err != nil {
		return "", fmt.Errorf("operator must configure the HTTPS enrollment URL")
	}
	return u.String(), nil
}
