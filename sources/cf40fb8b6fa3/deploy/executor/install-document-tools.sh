#!/bin/sh
# Optional one-time dependency setup on the customer's Debian/Ubuntu VPS.
# Does not touch the agent service, enrollment tokens, identities or lease files.
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run this dependency installer as the VPS administrator; the agent must remain non-root.' >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo 'This setup supports Debian/Ubuntu. Install Poppler utilities and Tesseract with English/Portuguese language data using your distribution package manager.' >&2
  exit 1
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends poppler-utils tesseract-ocr tesseract-ocr-eng tesseract-ocr-por
echo 'Document tools installed. No agent restart or re-enrollment is needed; its existing expiration is unchanged.'
