# Recovery process — butter-bridge (MAP Protocol OmniService / MOSV3)

This documents, step by step, how the `butter-bridge` hack was recovered and prepared for
scanning, from repo setup through to the point of uploading to CertiK's AI Auditor. It follows the
5-step process in [HackDetails.md](HackDetails.md).

---

## 1. Repository setup

Started from a single file, `Recover.sh` (a script for pulling a contract's pre-incident source —
see its own header comment for usage). Before doing anything with it:

- Read the full file to confirm it had no hardcoded secrets — RPC URLs and the Etherscan API key
  are read from environment variables, nothing embedded.
- Confirmed visibility (public) and repo name (`certiK_1BChallenge`) with the repo owner.

```bash
git init
git branch -m main
git add Recover.sh
git commit -m "Add recover.sh for pulling pre-incident contract source"
gh repo create certiK_1BChallenge --public --source=. --remote=origin --push
```

Repo: https://github.com/sivajialla/certiK_1BChallenge

Two more files appeared shortly after (`HackDetails.md`, `Readme.md`) — read both to check for
sensitive content before staging, then committed and pushed them too.

---

## 2. Getting `Recover.sh` actually working

First real run:

```bash
export ETH_RPC_URL='<alchemy mainnet url>'
export ETHERSCAN_API_KEY='<etherscan key>'
./Recover.sh butter-bridge ethereum 0x0000317bec33af037b5fab2028f52d14658f6a56 25137572
```

This correctly resolved the EIP-1967 proxy's implementation history via `cast storage`:

- implementation live at incident (block 25137571): `0x92feada957bbeb17868f9f59aed548e50191283d`
- implementation today (patched): `0x12bfb3b58ad02a0df40ee7186d26266c52d0109c`

But two things in the script were broken, plus one RPC-plan limitation surfaced:

### Bug 1 — `cast etherscan-source` no longer exists
The installed `cast` (v1.7.1) renamed this subcommand to `cast source` (same flags: `-d`,
`--etherscan-api-key`, `--chain`). Fixed both call sites in `Recover.sh`.

### Bug 2 — chain slug mismatch
`cast source --chain` wants network names (`mainnet`, `bsc`, `polygon`, ...), but the script was
passing its own slug (`ethereum`) straight through. Added a `CAST_CHAIN` mapping in the chain
`case` statement:

```bash
ethereum) ... CAST_CHAIN=mainnet;  CHAIN_ID=1 ;;
bsc)      ... CAST_CHAIN=bsc;      CHAIN_ID=56 ;;
polygon)  ... CAST_CHAIN=polygon;  CHAIN_ID=137 ;;
arbitrum) ... CAST_CHAIN=arbitrum; CHAIN_ID=42161 ;;
base)     ... CAST_CHAIN=base;     CHAIN_ID=8453 ;;
```

### Limitation — `eth_getLogs` range cap on free-tier RPCs
`cast logs` with no `--from-block`/`--to-block` defaults to `earliest → latest` (the whole chain).
Alchemy's free tier caps unbounded `eth_getLogs` at 10 blocks, so the "upgrade history" step
always failed. Verified this wasn't a broken endpoint — `eth_blockNumber` and a bounded 5-block
`eth_getLogs` both worked fine directly against the same RPC URL.

Since bounding the query would still miss real upgrade events outside the window, switched the
upgrade-history fetch to **Etherscan's log API**, which has no such range cap and uses the same
`ETHERSCAN_API_KEY` already required:

```bash
TOPIC_UPGRADED=$(cast keccak "Upgraded(address)")
curl -s "https://api.etherscan.io/v2/api?chainid=$CHAIN_ID&module=logs&action=getLogs&address=$ADDR&topic0=$TOPIC_UPGRADED&fromBlock=0&toBlock=latest&apikey=$KEY" \
  | jq -r '.result[]? | [.blockNumber, .transactionHash, ("0x" + .topics[1][-40:])] | @tsv' \
  | while IFS=$'\t' read -r blk tx impl; do
      printf 'block %-10d impl %s  tx %s\n' "$((blk))" "$impl" "$tx"
    done | tee "$DIR/upgrades.log"
```

After all three fixes, a clean rerun produced the full upgrade timeline, confirming the patched
implementation (`0x12bfb3b5...`) was deployed at block `25141484` — about 3,912 blocks (~13 hours)
**after** the incident block `25137572`.

All three fixes were committed to `Recover.sh` and pushed.

---

## 3. Recording the official challenge rules

The challenge's 5 official steps were pasted in and saved verbatim into `HackDetails.md` as the
canonical reference (find & recover → enrol on Hunt/AI Auditor → scan only the suspect file →
pick the right finding → submit the claim).

---

## 4. Recovering the actual pre-incident source

The live-at-incident implementation, `0x92FeaDa957bbeb17868F9F59Aed548e50191283D`, turned out to
be **unverified** — both on Etherscan (`cast source` failed with "Contract source code not
verified") and on Sourcify (`match: null` from the v2 API). Scanning today's (patched) code would
prove nothing per rule 01, so the real vulnerable source had to be found another way.

### 4.1 Confirming which hack this is

A post-mortem was provided describing a hash-collision bug: `retryMessageIn` authenticated
retried cross-chain messages with `keccak256(abi.encodePacked(...))` over four consecutive
dynamic-`bytes` fields (`initiator`, `from`, `to`, `swapData`). Since `abi.encodePacked` has no
length prefixes, different splits of the same bytes across those four fields can serialize to the
identical byte string — and therefore the identical hash.

This matched the already-pulled *current* (patched) source in `hacks/butter-bridge/src-current/`,
whose imports pointed at `@mapprotocol/protocol` — i.e. this was the MAP Protocol / Butter Bridge
(OmniService / MOSV3) contract. A web search confirmed the public incident: MAP Protocol's Butter
Bridge V3.1 was exploited on 2026-05-20 for ~1 quadrillion MAPO minted (~4.8M× real supply),
~$180K realized loss.

### 4.2 Failed verification lookups

```bash
# Sourcify — no match
curl -s "https://sourcify.dev/server/v2/contract/1/0x92FeaDa957bbeb17868F9F59Aed548e50191283D"
# → {"match":null,"creationMatch":null,"runtimeMatch":null,...}
```

### 4.3 Finding the canonical source repo

Searched GitHub for the MAP Protocol / Butter Bridge contracts. Several `mapprotocol` org repos
were older codebases (V1/V2 bridge, different contract names). The actual match was
`butternetwork/butter-mos-contracts`, path `evmv3/contracts/abstract/BridgeAbstract.sol` — same
file names, same structure as the pulled current source (`Bridge.sol`, `BridgeAbstract.sol`,
`IMOSV3.sol`, etc.).

(A third-party incident-reproduction repo, `sanbir/evm-hack-registry`, was also found and read for
cross-checking the attacker's transaction trace — but its author didn't have the real vulnerable
bytecode either and only guessed at the root cause ("skipped the check... or never required a
prior store"). It was not used as the source of the vulnerable code.)

### 4.4 Finding the exact fix commit

```bash
gh api "repos/butternetwork/butter-mos-contracts/commits?path=evmv3/contracts/abstract/BridgeAbstract.sol&per_page=100"
```

The most recent commit touching that file was:

```
834cd8bfa8  2026-05-21T04:12:50Z  fix(mos v3): audit fix and fix store message hash bug;
122aa023b7  2026-04-22T07:10:34Z  (previous commit — no changes to this file for a month before the fix)
```

`834cd8bfa8` landed ~12 hours after the incident (2026-05-20 16:13:47 UTC) — matching the on-chain
patch deployment timing found in step 2. Pulling the diff confirmed it matches the post-mortem
exactly:

```diff
- orderList[_inEvent.orderId] = uint256(
-     keccak256(abi.encodePacked(
-         _inEvent.messageType, _inEvent.fromChain, _inEvent.toChain,
-         _inEvent.token, _inEvent.amount, _inEvent.gasLimit,
-         _initiator, _inEvent.from, _inEvent.to, _inEvent.swapData
-     ))
- );
+ orderList[_inEvent.orderId] = uint256(_getStoreMessageHash(_initiator, _inEvent));
  ...
- bytes32 retryHash = keccak256(abi.encodePacked(
-     inEvent.messageType, inEvent.fromChain, inEvent.toChain, _token, _amount,
-     inEvent.gasLimit, initiator, _fromAddress, inEvent.to, inEvent.swapData
- ));
+ bytes32 retryHash = _getStoreMessageHash(initiator, inEvent);
  ...
+ function _getStoreMessageHash(...) internal pure returns (bytes32 hash) {
+     hash = keccak256(abi.encode(
+         inEvent.messageType, inEvent.fromChain, inEvent.toChain, inEvent.token,
+         inEvent.amount, inEvent.gasLimit, _initiator, inEvent.from, inEvent.to,
+         keccak256(inEvent.swapData)          // <- dynamic bytes pre-hashed, not packed raw
+     ));
+ }
```

The fix switches `abi.encodePacked` → `abi.encode` and pre-hashes `swapData` separately — exactly
the shape of fix that only makes sense against a packing/collision bug, not a missing-check bug.
This gave high confidence the fix commit's **parent** is the real pre-incident source.

### 4.5 Pulling the pre-incident source

```bash
PARENT=3a4b0f1571e9e47841af59aba7cf5099e467e984   # parent of the fix commit
REPO=butternetwork/butter-mos-contracts

for f in contracts/Bridge.sol contracts/abstract/BridgeAbstract.sol \
         contracts/interface/IMOSV3.sol contracts/interface/IButterBridgeV3.sol \
         contracts/interface/ISwapOutLimit.sol contracts/interface/IFeeService.sol \
         contracts/interface/IMapoExecutor.sol contracts/interface/IMintableToken.sol \
         contracts/interface/IButterReceiver.sol contracts/lib/EvmDecoder.sol \
         contracts/lib/Helper.sol contracts/lib/Types.sol; do
  gh api "repos/$REPO/contents/evmv3/${f}?ref=$PARENT" --jq '.content' \
    | base64 -d > "hacks/butter-bridge/src-pre/${f}"
done
```

### 4.6 Verifying

```bash
grep -n "keccak256(abi.encodePacked\|retryHash\|retry_verify_fail" \
  hacks/butter-bridge/src-pre/contracts/abstract/BridgeAbstract.sol
```

Confirmed the exact vulnerable code is present, verbatim, at lines 425-446 (`_storeMessageData`)
and 467-504 (`_getStoredMessage`) — the ten-field `abi.encodePacked` with the last four
(`initiator`, `from`/`_fromAddress`, `to`, `swapData`) all dynamic `bytes` packed consecutively.

```bash
diff -ru hacks/butter-bridge/src-pre/contracts hacks/butter-bridge/src-current/Bridge/contracts \
  > hacks/butter-bridge/patch.diff
```

This confirmed **`BridgeAbstract.sol` was the only file the fix touched** — i.e. it's the single
suspect file for step 3 of the challenge (scan only the file you suspect).

### 4.7 Building the scan candidate and notes

```bash
mkdir -p hacks/butter-bridge/scan
cp hacks/butter-bridge/src-pre/contracts/abstract/BridgeAbstract.sol hacks/butter-bridge/scan/
```

`hacks/butter-bridge/notes.md` was then written up with:
- the full recovery method (how the pre-incident source was found, since it wasn't verified
  anywhere)
- root cause and attack walkthrough (precomputed `CREATE` address → "NotContract" retry commitment
  planted → exploit contract deployed at that address → `retryMessageIn` called with re-split
  fields that collide to the same hash → forged message reaches `mapoExecute` → mints 1e33 wei of
  MAPO)
- vulnerable file:line references
- a draft of every claim-form field except **Scan ID** and **Finding title**, which can only come
  from an actual AI Auditor run

### 4.8 Independent cross-check

A Blockaid (`@blockaid_`) X/Twitter post was provided, giving the exploit tx hash, attacker EOA
(`0x4059...`), exploit contract (`0x2475...`), MAPO token address, and a precise loss breakdown
(52.21 ETH / ~$180K drained from the Uniswap V4 ETH/MAPO pool after the attacker dumped 1B MAPO;
~999.999B MAPO still held by the attacker as ongoing dilution risk). This matched the block number,
addresses, and loss figure already in `notes.md`, and was added as a corroborating attribution
section citing an independent source.

Everything above was committed to `hacks/butter-bridge/` and pushed to
https://github.com/sivajialla/certiK_1BChallenge as work progressed.

---

## 5. Scanning in CertiK's AI Auditor (rules 02-05)

This part requires the account holder's own login — it can't be driven from the command line.

1. **Enrol / sign in.** If not already on Hunt, request access there first. AI Auditor credits
   ($100) land automatically on the same email the Hunt application was approved under — sign in
   to AI Auditor with that exact address.
2. **Upload only the suspect file.** Use `hacks/butter-bridge/scan/BridgeAbstract.sol` (581 lines)
   — not the whole repo, not the full `src-pre/` tree. A larger bundle burns credits and buries
   the real finding among noise.
3. **Start on Lite tier.** Only escalate to Max if Lite misses the bug.
4. **Read the findings and pick the one that names the actual exploited code path** — i.e. one
   that points at `_getStoredMessage`'s `retryHash` check (`BridgeAbstract.sol:481-495`) or the
   matching commitment-hash construction in `_storeMessageData` (`:425-446`). AI Auditor may phrase
   it as a hash collision, ambiguous/ill-defined ABI packing, weak message authentication, or
   similar — the key is that it points at that exact function, not somewhere else in the file.
5. **Record the result.** Take the finding's exact title and the scan ID, and fill them into the
   `Scan ID` / `Finding title (verbatim)` fields in `hacks/butter-bridge/notes.md`. That, plus the
   one-or-two-sentence "why this finding is the bug" already drafted there, is the claim.
6. **Submit the claim** on the claim form using those fields.
