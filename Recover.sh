#!/usr/bin/env bash
# recover.sh — recover a contract as it was deployed at an incident.
#
#   ./recover.sh <slug> <chain> <address> <incident_block>
#
#   slug            short name for the hack, e.g. butter-bridge
#   chain           ethereum | bsc | polygon | arbitrum | base
#   address         the contract hit in the exploit (proxy or plain)
#   incident_block  block number of the exploit transaction
#
# Produces hacks/<slug>/ with pre-incident source, current source,
# a diff, and a notes.md pre-filled for the claim form.

set -euo pipefail

SLUG="${1:?slug required}"
CHAIN="${2:?chain required}"
ADDR="${3:?address required}"
BLOCK="${4:?incident block required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$ROOT/hacks/$SLUG"
PREV=$((BLOCK - 1))

# EIP-1967 slots
SLOT_IMPL=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
SLOT_BEACON=0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
SLOT_ADMIN=0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103

case "$CHAIN" in
  ethereum) RPC="${ETH_RPC_URL:?set ETH_RPC_URL}";      KEY="${ETHERSCAN_API_KEY:?}" ;;
  bsc)      RPC="${BSC_RPC_URL:?set BSC_RPC_URL}";      KEY="${ETHERSCAN_API_KEY:?}" ;;
  polygon)  RPC="${POLYGON_RPC_URL:?set POLYGON_RPC_URL}"; KEY="${ETHERSCAN_API_KEY:?}" ;;
  arbitrum) RPC="${ARB_RPC_URL:?set ARB_RPC_URL}";      KEY="${ETHERSCAN_API_KEY:?}" ;;
  base)     RPC="${BASE_RPC_URL:?set BASE_RPC_URL}";    KEY="${ETHERSCAN_API_KEY:?}" ;;
  *) echo "unknown chain: $CHAIN" >&2; exit 1 ;;
esac

mkdir -p "$DIR"
echo "==> $SLUG on $CHAIN, incident block $BLOCK"

slot_addr() { # read a storage slot at a block, return address or empty
  local word
  word=$(cast storage "$ADDR" "$1" --block "$2" --rpc-url "$RPC" 2>/dev/null || echo "")
  [[ -z "$word" ]] && return 0
  [[ "$word" =~ ^0x0{64}$ ]] && return 0
  echo "0x${word: -40}"
}

IMPL_PRE=$(slot_addr "$SLOT_IMPL" "$PREV")
IMPL_NOW=$(slot_addr "$SLOT_IMPL" latest)
BEACON=$(slot_addr "$SLOT_BEACON" "$PREV")
ADMIN=$(slot_addr "$SLOT_ADMIN" "$PREV")

if [[ -n "$IMPL_PRE" ]]; then
  PROXY_KIND="EIP-1967 transparent/UUPS"
elif [[ -n "$BEACON" ]]; then
  PROXY_KIND="EIP-1967 beacon (resolve implementation() on $BEACON)"
  IMPL_PRE=$(cast call "$BEACON" 'implementation()(address)' --block "$PREV" --rpc-url "$RPC" 2>/dev/null || echo "")
  IMPL_NOW=$(cast call "$BEACON" 'implementation()(address)' --rpc-url "$RPC" 2>/dev/null || echo "")
else
  PROXY_KIND="not EIP-1967 — treating as plain contract (verify manually)"
  IMPL_PRE="$ADDR"
  IMPL_NOW="$ADDR"
fi

echo "    proxy kind : $PROXY_KIND"
echo "    impl @ N-1 : ${IMPL_PRE:-<none>}"
echo "    impl @ now : ${IMPL_NOW:-<none>}"
[[ -n "$ADMIN" ]] && echo "    admin      : $ADMIN"

if [[ -z "$IMPL_PRE" ]]; then
  echo "!!  could not resolve implementation. Check Etherscan 'Read as Proxy'," >&2
  echo "    or dump slots 0-5 with: cast storage $ADDR <i> --block $PREV" >&2
  exit 1
fi

echo "==> upgrade history"
cast logs --address "$ADDR" 'Upgraded(address)' --rpc-url "$RPC" \
  | tee "$DIR/upgrades.log" | grep -E 'blockNumber|topics' || echo "    (none found)"

echo "==> pulling source"
cast etherscan-source -d "$DIR/src-pre" "$IMPL_PRE" --etherscan-api-key "$KEY" --chain "$CHAIN" \
  || echo "!!  unverified — copy manually from the explorer into $DIR/src-pre"

if [[ "$IMPL_NOW" != "$IMPL_PRE" && -n "$IMPL_NOW" ]]; then
  cast etherscan-source -d "$DIR/src-current" "$IMPL_NOW" --etherscan-api-key "$KEY" --chain "$CHAIN" || true
  diff -ru "$DIR/src-pre" "$DIR/src-current" > "$DIR/patch.diff" 2>/dev/null || true
  echo "    wrote patch.diff — this is the fix, and your write-up material"
else
  echo "    implementation unchanged since incident — confirm it really wasn't patched"
fi

echo "==> smell test"
grep -rn --include=*.sol -E 'encodePacked|delegatecall|\.call\{|balanceOf\[|getReserves|sync\(\)|_mint\(' \
  "$DIR/src-pre" 2>/dev/null | head -40 || echo "    (no obvious hits)"

cat > "$DIR/notes.md" <<EOF
# $SLUG

## Recovery (rule 02 — goes in the claim)
- chain: $CHAIN
- contract hit: $ADDR
- proxy kind: $PROXY_KIND
- incident block: $BLOCK
- implementation live at incident: $IMPL_PRE
- implementation today: $IMPL_NOW
- recovered by: reading the EIP-1967 implementation slot at block $PREV

## Claim form fields
- Protocol / project:
- Amount lost (digits only):
- Root cause:
- Smart contract bug? Yes
- Scan ID:
- Tier: Lite
- Finding title (verbatim):
- Why this finding is the bug:

## Vulnerable code
- file:line —
- pattern —

## Sources
- postmortem / analysis:
- loss figure source:
EOF

mkdir -p "$DIR/scan"
echo "==> done. Trim the vulnerable file into $DIR/scan/ and upload only that."