# syntax=docker/dockerfile:1
#
# Runtime image (no compilation inside the image): install common tools only and ship
# a **pre-built Linux single binary**. The binary is cross-compiled by the CI binaries
# job (pure Go, no QEMU) and placed at dist/<TARGETARCH>/vulnetic in the build context.
# This way multi-arch builds only need to emulate the apt layer for arm64 instead of
# emulating the Next/Go compilation, which is much faster.
#
# To build the image manually, prepare the binary yourself first:
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/vulnetic ./cmd/vulnetic
#   docker build -t vulnetic:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add/remove as needed).
# Node 20.x comes from NodeSource: bookworm's apt nodejs is 18, but Playwright requires >=20.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
      php-cli \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Web-recon toolbox (drost-community take 1, #100): pinned release binaries installed
# into /usr/local/bin so hunt workers can run them directly through their Bash tool.
# Versions pinned per tool; upgrade deliberately. sqlmap is a python checkout (no
# release binaries) symlinked into PATH.
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
ARG SUBFINDER_VERSION=v2.17.0
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.3.0
ARG DALFOX_VERSION=v3.2.4
ARG GITLEAKS_VERSION=v8.21.2
ARG ACTIONLINT_VERSION=v1.7.7
RUN set -eux; \
    base="https://github.com"; \
    pd_fetch() { repo="$1"; ver="$2"; name="$3"; nov="${ver#v}"; \
      curl -fsSL "$base/$repo/releases/download/$ver/${name}_${nov}_linux_${TARGETARCH}.zip" -o /tmp/t.zip \
      && unzip -o -q /tmp/t.zip -d /tmp/td \
      && find /tmp/td -type f -name "$name" -exec install -m 0755 {} /usr/local/bin/ \; \
      && rm -rf /tmp/t.zip /tmp/td; }; \
    case "$TARGETARCH" in amd64) FFUF_ARCH=amd64; DALFOX_ARCH=x86_64; GITLEAKS_ARCH=x64;; arm64) FFUF_ARCH=arm64; DALFOX_ARCH=aarch64; GITLEAKS_ARCH=arm64;; esac; \
    pd_fetch projectdiscovery/nuclei "$NUCLEI_VERSION" nuclei; \
    pd_fetch projectdiscovery/httpx "$HTTPX_VERSION" httpx; \
    pd_fetch projectdiscovery/subfinder "$SUBFINDER_VERSION" subfinder; \
    pd_fetch projectdiscovery/katana "$KATANA_VERSION" katana; \
    tar_fetch() { url="$1"; name="$2"; \
      curl -fsSL "$url" -o /tmp/t.tgz \
      && mkdir -p /tmp/td && tar -xzf /tmp/t.tgz -C /tmp/td \
      && find /tmp/td -type f -name "$name" -exec install -m 0755 {} /usr/local/bin/ \; \
      && rm -rf /tmp/t.tgz /tmp/td; }; \
    tar_fetch "$base/ffuf/ffuf/releases/download/$FFUF_VERSION/ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz" ffuf; \
    tar_fetch "$base/hahwul/dalfox/releases/download/$DALFOX_VERSION/dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz" dalfox; \
    # secrets-scan skill (Peça 13): gitleaks, Go single binary, same tar_fetch as ffuf/dalfox.
    tar_fetch "$base/gitleaks/gitleaks/releases/download/$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION#v}_linux_${GITLEAKS_ARCH}.tar.gz" gitleaks; \
    # cicd-supply-chain skill (Peça 14): actionlint, Go single binary, robust GitHub Actions YAML parsing.
    tar_fetch "$base/rhysd/actionlint/releases/download/$ACTIONLINT_VERSION/actionlint_${ACTIONLINT_VERSION#v}_linux_${TARGETARCH}.tar.gz" actionlint; \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap; \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    # jwt-attacks skill (Peça 8): ticarpi/jwt_tool, pure Python checkout, same pattern as sqlmap above.
    git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool; \
    pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt; \
    chmod +x /opt/jwt_tool/jwt_tool.py; \
    ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool; \
    # race-conditions skill (Peça 10): httpx+h2 for scripts/race.py's single-packet-style burst.
    pip install --no-cache-dir httpx h2; \
    # deser-ssti-chains skill (Peça 11): phpggc, pure PHP gadget-chain generator (php-cli installed above).
    # ysoserial/ysoserial.net (Java/.NET) are deliberately NOT baked in here — they need a
    # JRE/.NET runtime and are heavy for how rarely they are used; fetch the specific release
    # jar on demand, under the skill's own authorization gate, only when a program approves
    # deserialization RCE testing.
    git clone --depth 1 https://github.com/ambionics/phpggc /opt/phpggc; \
    ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc; \
    # cve-verify skill (Peça 6 fallback): searchsploit (exploit-database/exploitdb), a CLI
    # search over a local CSV mirror — never downloads or executes anything at runtime.
    git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /opt/exploitdb; \
    ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit; \
    nuclei -version >/dev/null; httpx -version; subfinder -version; katana -version; \
    ffuf -V >/dev/null; dalfox --version >/dev/null 2>&1 || true; sqlmap --version >/dev/null; \
    gitleaks version >/dev/null; actionlint -version >/dev/null; jwt_tool -h >/dev/null 2>&1 || true; \
    phpggc -l >/dev/null 2>&1 || true; searchsploit -h >/dev/null 2>&1 || true; \
    # cve-verify skill (Peça 2): nuclei ships with NO templates by default — without this,
    # the skill silently finds nothing (or tries a runtime download that fails under an
    # egress allowlist). -silent keeps build logs quiet; this is not pinned to a templates
    # release tag, a deliberate v1 trade-off documented in the CVE-lookup plan.
    nuclei -update-templates -silent

# bbot recursive recon orchestrator (#117): blacklanternsecurity/bbot, AGPL-3.0
# (same license as Vulnetic; standalone CLI dependency, not linked code). Pinned
# version, own venv to isolate from the image python. Module dependencies are
# preinstalled (--install-all-deps) so scans never need pip at runtime, which
# would fail under a program's egress allowlist.
ARG BBOT_VERSION=3.0.2
RUN set -eux; \
    python -m venv /opt/bbot; \
    /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}"; \
    ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot; \
    bbot -y --install-all-deps; \
    bbot --version >/dev/null; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness >/dev/null 2>&1 || true; \
    bbot --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert,gowitness --no-color >/tmp/bbot-dry.log 2>&1 || true; \
    ! grep -qE "Installing|ERRR|CRITICAL" /tmp/bbot-dry.log || { cat /tmp/bbot-dry.log; exit 1; }


# Preinstall Playwright MCP and CLI (globally) so no npx network download is needed at runtime.
# @playwright/mcp: browser MCP runs directly via `npx @playwright/mcp` (installed globally, no -y/@latest needed).
# @playwright/cli: provides playwright-cli, verified with --help right after install.
# Then install playwright (browser management) and preinstall chromium plus its system
# dependencies via --with-deps, so MCP/CLI work on first start inside the container
# without downloading browsers over the network.
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# pre-built binary for the matching architecture (dist/amd64/vulnetic or dist/arm64/vulnetic)
COPY dist/${TARGETARCH}/vulnetic /app/vulnetic
# Daemon startup script: decides whether to relaunch the process based on its exit code;
# the in-page one-click update relies on it to swap the binary. It also forwards SIGTERM
# to vulnetic — docker stop only signals PID 1; without forwarding, vulnetic never receives it,
# cannot shut down gracefully, and is hard-killed by SIGKILL after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/vulnetic /app/start.sh
COPY skills/ /app/skills/
# persistence point for data/ (SQLite + jwt.key)
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
