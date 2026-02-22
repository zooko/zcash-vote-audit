#!/usr/bin/env bash
set -euo pipefail

BASE="https://zecvote.zone/election"
DATA="data"

IDS=(
  d7281580b01f8d1d056b52965397a63895ac491538d49ae9a9bbb4458271f701
  8f01a2ca0af8e088637dfde26524180bcb48e5ed5f7fb6410cfe2a385b269706
  b4e3b9a1008483ea68d8fb2abb4f8e6987e870d20fca410f3edae8ca8362d00e
  626452804795e079e8a43cb42183a38c55ad45d59bfe30c90478d8c660452308
  e3ac5600cf85c4e2dd82e53cf9f05975052a9779325c0e43305b6ab7cb592101
  1d075a9b9e0b53072efebff331722d99a74bc7f21b6d26f0600d47d377a67e2b
  340534dc1a42a2faef9fe57ecff609526d8433e5e9a9f6feac6d09fe1f0d5d2d
  89a963d3ea444af7af7460b5c9f6c1aff5b4dc6cbd9b4356f9ef24591fcef626
  a816627d9b7c36116c150d2e80cbda64c616556733cbdeeaf6572db849405335
  b94cacd2a847e2996048b9371a4b4eb989decd8cfa0d3ebb06d0bb6527eb7c3f
  7fa15c2d77bb5b1ad3bec984d95bd5a61954494d6cba2cc2c71a3d85aec0963e
)

NAMES=(
  "Q01 ZSAs"
  "Q02 NSM"
  "Q03 Burn Fees"
  "Q04 Memo Bundles"
  "Q05 Explicit Fees"
  "Q06 Sprout"
  "Q07 Tachyon"
  "Q08 STARK"
  "Q09 Dynamic Fees"
  "Q10 Consensus Accounts"
  "Q11 Quantum Recovery"
)

fetch() {
  local url="$1" out="$2"
  # Skip if already downloaded and non-empty
  [ -f "$out" ] && [ -s "$out" ] && return 0
  for attempt in 1 2 3 4 5 6 7 8; do
    if curl -sS --fail --max-time 60 -o "$out.tmp" "$url" 2>/dev/null; then
      if [ -s "$out.tmp" ]; then
        mv "$out.tmp" "$out"
        return 0
      fi
    fi
    rm -f "$out.tmp"
    echo "    retry $attempt for $(basename "$out")..."
    sleep $((attempt * 3))
  done
  echo "    FAILED: $url"
  return 1
}

for idx in "${!IDS[@]}"; do
  id="${IDS[$idx]}"
  name="${NAMES[$idx]}"
  dir="$DATA/$id"
  mkdir -p "$dir"

  echo ""
  echo "=== $name ==="

  echo "  election.json"
  fetch "$BASE/$id" "$dir/election.json"
  sleep 1

  echo "  num_ballots"
  fetch "$BASE/$id/num_ballots" "$dir/num_ballots.txt"
  sleep 1

  n=$(tr -d '[:space:]' < "$dir/num_ballots.txt")
  echo "  $n ballots"

  fails=0
  for i in $(seq 1 "$n"); do
    printf "\r  ballot %d/%s  " "$i" "$n"
    if ! fetch "$BASE/$id/ballot/height/$i" "$dir/ballot_$i.json"; then
      fails=$((fails + 1))
    fi
    sleep 0.5
  done
  echo ""
  if [ "$fails" -gt 0 ]; then
    echo "  ⚠ $fails failures — rerun script to retry"
  else
    echo "  ✓ all $n ballots"
  fi
done

echo ""
echo "Done. Data in ./$DATA/"
echo "Rerun this script to retry any failures (existing files are skipped)."
