#!/usr/bin/env bash
# D2-01: install pinned Syft, Grype, OSV-Scanner into tools/bin (gitignored), verify sha256, pre-download Grype DB.
# Supports Windows (Git Bash) and Linux amd64. No sudo, no package manager.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/tool_versions.env"
BIN="$ROOT/tools/bin"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$BIN"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) OS=windows; EXE=.exe ;;
  Linux)                OS=linux;   EXE= ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; esac

sha_of() { sha256sum "$1" | cut -d' ' -f1; }
fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
verify() { # file expected_sha
  [ "$(sha_of "$1")" = "$2" ] || { echo "CHECKSUM MISMATCH for $1" >&2; exit 1; }
}
unpack() { # archive dest-binary-name
  if [ "$OS" = windows ]; then
    powershell.exe -NoProfile -Command "Expand-Archive -Force -LiteralPath '$(cygpath -w "$1")' -DestinationPath '$(cygpath -w "$TMP/x")'"
  else
    mkdir -p "$TMP/x"; tar -xzf "$1" -C "$TMP/x"
  fi
  cp "$TMP/x/$2$EXE" "$BIN/$2$EXE"; rm -rf "$TMP/x"
}
install_anchore() { # name version
  local n=$1 v=$2 ext; [ "$OS" = windows ] && ext=zip || ext=tar.gz
  local base="https://github.com/anchore/$n/releases/download/v$v" f="${n}_${v}_${OS}_${ARCH}.$ext"
  fetch "$base/$f" "$TMP/$f"; fetch "$base/${n}_${v}_checksums.txt" "$TMP/sums"
  verify "$TMP/$f" "$(grep " $f\$" "$TMP/sums" | cut -d' ' -f1)"
  unpack "$TMP/$f" "$n"
}

install_anchore syft  "$SYFT_VERSION"
install_anchore grype "$GRYPE_VERSION"

# OSV-Scanner ships a bare binary + a SHA256SUMS file
OSV_BASE="https://github.com/google/osv-scanner/releases/download/v$OSV_SCANNER_VERSION"
OSV_F="osv-scanner_${OS}_${ARCH}$EXE"
fetch "$OSV_BASE/$OSV_F" "$TMP/$OSV_F"; fetch "$OSV_BASE/osv-scanner_SHA256SUMS" "$TMP/osvsums"
verify "$TMP/$OSV_F" "$(grep " $OSV_F\$" "$TMP/osvsums" | cut -d' ' -f1)"
cp "$TMP/$OSV_F" "$BIN/osv-scanner$EXE"; chmod +x "$BIN"/* 2>/dev/null || true

export PATH="$BIN:$PATH"
echo "Pre-downloading Grype vulnerability DB..."
GRYPE_DB_AUTO_UPDATE=true grype db update

echo "---- installed versions ----"
syft version | grep -E '^Version'
grype version | grep -E '^Version'
osv-scanner --version | head -1
