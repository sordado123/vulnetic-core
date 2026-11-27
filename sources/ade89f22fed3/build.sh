#!/usr/bin/env bash
# Vulnetic cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   VULNETIC_TARGET_OS=linux             One target OS in single-target mode.
#   VULNETIC_TARGET_ARCH=amd64           One target arch in single-target mode.
#   VULNETIC_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   VULNETIC_BUILD_VERSION=v0.3.3        Version embedded in the binary and archive name.
#   VULNETIC_OUTPUT=/path/to/vulnetic       Explicit binary path in single-target mode.
#   VULNETIC_OUTPUT_DIR=dist             Directory for default binary paths.
#   VULNETIC_PACKAGE=1                   Create a zip archive for each target.
#   VULNETIC_PACKAGE_DIR=dist            Directory for release archives.
#   VULNETIC_COMPRESS=off                UPX mode: off, auto, or required.
#   VULNETIC_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   VULNETIC_SKIP_FRONTEND=1             Reuse server/webui/dist (for CI artifact builds).
#   VULNETIC_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   VULNETIC_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./build.sh                         Build for the current OS and architecture
  ./build.sh --target linux/amd64   Build one specific target
  ./build.sh --release               Build and package all supported targets

Options:
  --release              Build the amd64/arm64 targets for Linux, macOS, and Windows, and generate zips
  --target OS/ARCH       Set a single target, e.g. windows/amd64
  --upx                  Force UPX compression of the binary (may affect compatibility on some Linux environments)
  --no-compress          No UPX; use only Go linker trimming and zip compression
  --help                 Show this help

The multi-target list can be overridden via VULNETIC_TARGETS, e.g.:
  VULNETIC_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
VULNETIC_RELEASE="${VULNETIC_RELEASE:-0}"
VULNETIC_COMPRESS="${VULNETIC_COMPRESS:-off}"
VULNETIC_PACKAGE="${VULNETIC_PACKAGE:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      VULNETIC_RELEASE=1
      VULNETIC_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target requires an OS/ARCH argument"
      target_arg="$2"
      case "$target_arg" in
        */*)
          VULNETIC_TARGET_OS="${target_arg%%/*}"
          VULNETIC_TARGET_ARCH="${target_arg##*/}"
          VULNETIC_TARGETS="$target_arg"
          ;;
        *) die "target must be OS/ARCH, e.g. linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      VULNETIC_COMPRESS=0
      shift
      ;;
    --upx)
      VULNETIC_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "unknown argument: $1 (use --help for usage)" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "Go not detected (the project requires Go 1.26 or newer)"

VULNETIC_GOSUMDB="${VULNETIC_GOSUMDB:-sum.golang.org}"
if [ -z "${VULNETIC_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    VULNETIC_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    VULNETIC_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed as v0.3.3; keep the binary version consistent.
VULNETIC_BUILD_VERSION="${VULNETIC_BUILD_VERSION#v}"
VULNETIC_OUTPUT_DIR="${VULNETIC_OUTPUT_DIR:-dist}"
VULNETIC_PACKAGE_DIR="${VULNETIC_PACKAGE_DIR:-$VULNETIC_OUTPUT_DIR}"
VULNETIC_UPX_ARGS="${VULNETIC_UPX_ARGS:---best --lzma}"

if [ "${VULNETIC_RELEASE}" = "1" ]; then
  VULNETIC_TARGETS="${VULNETIC_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  VULNETIC_TARGET_OS="${VULNETIC_TARGET_OS:-$(GOSUMDB="$VULNETIC_GOSUMDB" go env GOOS)}"
  VULNETIC_TARGET_ARCH="${VULNETIC_TARGET_ARCH:-$(GOSUMDB="$VULNETIC_GOSUMDB" go env GOARCH)}"
  VULNETIC_TARGETS="${VULNETIC_TARGETS:-${VULNETIC_TARGET_OS}/${VULNETIC_TARGET_ARCH}}"
fi

if [ "${VULNETIC_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d server/webui/dist ] || die "VULNETIC_SKIP_FRONTEND=1 but server/webui/dist does not exist"
else
  command -v npm >/dev/null 2>&1 || die "npm not detected (building the frontend static assets requires Node.js/npm)"
  command -v rsync >/dev/null 2>&1 || die "rsync not detected"
  info "Building frontend static assets"
  if [ "${VULNETIC_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "Syncing frontend assets to server/webui/dist"
  mkdir -p server/webui/dist
  rsync -a --delete web/out/ server/webui/dist/
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$VULNETIC_COMPRESS" in
    0|off|false|none)
      info "Skipping UPX: $binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "VULNETIC_COMPRESS must be off, auto, or required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$VULNETIC_COMPRESS" = "required" ]; then
      die "VULNETIC_COMPRESS=required but upx was not detected"
    fi
    warn "upx not detected; keeping the linker-compressed result: $binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$VULNETIC_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$VULNETIC_COMPRESS" = "required" ]; then
      die "UPX compression failed: $binary"
    fi
    warn "UPX does not support this target format; keeping the uncompressed binary: $binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX compression done: $binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="vulnetic-${VULNETIC_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${VULNETIC_PACKAGE_DIR}/${package_name}"
  archive="${VULNETIC_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "packaging requires zip"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  # The guardian start script is the official entry point: the page's one-click
  # update relies on it to relaunch the process after it exits; running the vulnetic
  # binary directly means it never comes back up after an update. Ship only the one
  # matching the target OS.
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$VULNETIC_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  ok "Release archive: $archive"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "invalid target: $target (must be OS/ARCH)" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "unsupported OS: $goos (supported: linux, darwin, windows)" ;;
  esac

  binary_name="vulnetic"
  [ "$goos" = "windows" ] && binary_name="vulnetic.exe"
  if [ -n "${VULNETIC_OUTPUT:-}" ] && [ "$VULNETIC_RELEASE" != "1" ]; then
    output="$VULNETIC_OUTPUT"
  else
    output="${VULNETIC_OUTPUT_DIR}/vulnetic-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "Compiling ${goos}/${goarch}, version ${VULNETIC_BUILD_VERSION}"
  GOSUMDB="$VULNETIC_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${VULNETIC_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/vulnetic

  compress_binary "$output" "$goos"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  if [ "$VULNETIC_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  ok "Build complete: $output"
}

write_checksums() {
  [ "$VULNETIC_PACKAGE" = "1" ] || return 0
  checksum_file="$VULNETIC_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$VULNETIC_PACKAGE_DIR" && for archive in *.zip; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$VULNETIC_PACKAGE_DIR" && for archive in *.zip; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    warn "Neither sha256sum nor shasum detected; skipping SHA256SUMS"
    return 0
  fi
  ok "Checksum file: $checksum_file"
}

mkdir -p "$VULNETIC_OUTPUT_DIR"
if [ "$VULNETIC_PACKAGE" = "1" ]; then mkdir -p "$VULNETIC_PACKAGE_DIR"; fi

old_ifs="$IFS"
IFS=','
read -r -a targets <<< "$VULNETIC_TARGETS"
IFS="$old_ifs"
[ "${#targets[@]}" -gt 0 ] || die "VULNETIC_TARGETS must not be empty"
for target in "${targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  build_target "$target"
done

if [ "$VULNETIC_PACKAGE" = "1" ]; then
  write_checksums
  info "Release packages generated in: $VULNETIC_PACKAGE_DIR"
fi
