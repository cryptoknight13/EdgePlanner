#!/usr/bin/env bash
# Phase 8c: download one GGUF model listed under llm.models in config/settings.yaml and check its sha256.
#
#   bash scripts/fetch_model.sh qwen3-0.6b
set -euo pipefail

KEY=${1:?usage: fetch_model.sh <model key from config/settings.yaml llm.models>}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
read -r FILE URL SHA < <("$ROOT/.venv/bin/python" - "$ROOT" "$KEY" <<'PY'
import sys, yaml
root, key = sys.argv[1], sys.argv[2]
m = yaml.safe_load(open(f"{root}/config/settings.yaml"))["llm"]["models"].get(key)
if not m:
    sys.exit(f"unknown model {key!r}")
print(m["file"], m["url"], m["sha256"])
PY
)
DEST="$ROOT/$FILE"
mkdir -p "$(dirname "$DEST")"
if [ -f "$DEST" ] && echo "$SHA  $DEST" | sha256sum -c --status; then
  echo "skip  $KEY (already downloaded, sha256 ok)"
  exit 0
fi
echo "fetch $KEY"
curl -L --fail --retry 3 -sS -o "$DEST.part" "$URL"
echo "$SHA  $DEST.part" | sha256sum -c --quiet
mv "$DEST.part" "$DEST"
echo "ok    $DEST"
