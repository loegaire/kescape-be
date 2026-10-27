#!/bin/sh
set -u

OUT="${SBOM_OUT:-/tmp/sboms}"
mkdir -p "$OUT"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\010\013\014\016-\037'
}

registry_of() {
  case "$1" in
    */*)
      first=${1%%/*}
      case "$first" in
        *.*|*:*|localhost) printf '%s' "$first" ;;
        *) printf 'docker.io' ;;
      esac
      ;;
    *) printf 'docker.io' ;;
  esac
}

n=0
for img in ${SBOM_IMAGES:-}; do
  n=$((n + 1))
  reg=$(registry_of "$img")
  ts=$(date +%s)

  echo "PROGRESS {\"ts\":$ts,\"stage\":\"pull\",\"image\":\"$(json_escape "$img")\",\"registry\":\"$(json_escape "$reg")\"}"
  echo "PROGRESS {\"ts\":$ts,\"stage\":\"syft\",\"image\":\"$(json_escape "$img")\",\"registry\":\"$(json_escape "$reg")\"}"

  file="$OUT/$n.json"
  timeout "${SYFT_TIMEOUT:-600}" syft "$img" -q -o "spdx-json=$file" 2>"$OUT/$n.err"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    bytes=$(wc -c < "$file" | tr -d ' ')
    echo "PROGRESS {\"ts\":$ts,\"stage\":\"sbom\",\"image\":\"$(json_escape "$img")\",\"registry\":\"$(json_escape "$reg")\",\"bytes\":$bytes}"
    b64=$(gzip -c "$file" | base64 | tr -d '\n')
    echo "SBOM $(json_escape "$img") $b64"
  else
    if [ "$rc" -eq 124 ]; then
      msg="timed out after ${SYFT_TIMEOUT:-600}s"
    else
      msg=$(tr '\n' ' ' < "$OUT/$n.err" | cut -c1-300)
      [ -z "$msg" ] && msg="syft exited with code $rc"
    fi
    echo "PROGRESS {\"ts\":$ts,\"stage\":\"error\",\"image\":\"$(json_escape "$img")\",\"registry\":\"$(json_escape "$reg")\",\"message\":\"$(json_escape "$msg")\"}"
  fi
done

echo "PROGRESS {\"ts\":$(date +%s),\"stage\":\"done\"}"
