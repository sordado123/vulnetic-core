#!/bin/sh
# Document dependencies on the customer's Linux VPS (automatic setup on Debian/Ubuntu).
# Does not touch the agent service, enrollment tokens, identities or lease files.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this dependency installer as the VPS administrator; the agent must remain non-root.' >&2
  exit 1
fi
document_tools_ready() {
  for document_tool in pdfinfo pdftotext pdftoppm tesseract; do
    command -v "$document_tool" >/dev/null 2>&1 || return 1
  done
  document_languages=$(tesseract --list-langs 2>/dev/null) || return 1
  printf '%s\n' "$document_languages" | grep -qx eng && printf '%s\n' "$document_languages" | grep -qx por
}
if ! document_tools_ready; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo 'Automatic setup requires Debian/Ubuntu. Install Poppler utilities and Tesseract with English/Portuguese data using your distribution package manager, then rerun this command. No agent authorization was changed.' >&2
    exit 1
  fi
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends poppler-utils tesseract-ocr tesseract-ocr-eng tesseract-ocr-por
fi
document_tools_ready || { echo 'Document dependencies are incomplete; no agent authorization was changed.' >&2; exit 1; }
echo 'Document tools installed. No agent restart or re-enrollment is needed; its existing expiration is unchanged.'
