# butter-bridge (MAP Protocol OmniService / MOSV3)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum
- contract hit (proxy): 0x0000317bec33af037b5fab2028f52d14658f6a56 (OmniServiceProxy)
- proxy kind: EIP-1967 transparent/UUPS
- incident block: 25137572 (tx at 25137571 per post-mortem — 2026-05-20 16:13:47 UTC)
- implementation live at incident: 0x92feada957bbeb17868f9f59aed548e50191283d — **unverified on
  Etherscan and Sourcify**, so recovered from source, not the explorer
- implementation today (patched): 0x12bfb3b58ad02a0df40ee7186d26266c52d0109c, deployed block
  25141484 (~13h after the incident)
- recovered by:
  1. read the EIP-1967 implementation slot at block 25137571 to get the live impl address
  2. impl unverified -> found the canonical source repo (`butternetwork/butter-mos-contracts`,
     path `evmv3/`) and located the fix commit `834cd8bfa8` ("fix(mos v3): audit fix and fix
     store message hash bug"), dated 2026-05-21T04:12:50Z — ~12h after the incident, consistent
     with the on-chain patch timing
  3. pulled `evmv3/contracts/abstract/BridgeAbstract.sol` (+ direct first-party imports) at the
     fix commit's **parent** (`3a4b0f1571e9e47841af59aba7cf5099e467e984`) as the pre-incident,
     vulnerable source — this is the exact commit the fix diff was written against
  4. confirmed: `diff -ru src-pre src-current` shows **only `BridgeAbstract.sol` changed** in the
     fix — matches expectation, single suspect file

## Claim form fields
- Protocol / project: MAP Protocol — Butter Bridge / OmniService (MOSV3)
- Amount lost (digits only): 180000
- Root cause: `_storeMessageData` / `_getStoredMessage` in `BridgeAbstract.sol` computed the
  retry-commitment hash with `keccak256(abi.encodePacked(...))` over ten fields, the last four of
  which (`initiator`, `from`/`_fromAddress`, `to`, `swapData`) are all dynamic `bytes` packed back
  to back with no length prefixes. Different splits of the same underlying bytes across those four
  fields serialize to the identical packed byte string, and therefore the identical keccak256 —
  so an attacker-chosen retry payload with rearranged field boundaries collides with a
  previously-stored commitment hash it was never actually authorized to satisfy.
- Smart contract bug? Yes
- Scan ID: <fill in after running AI Auditor Lite on scan/BridgeAbstract.sol>
- Tier: Lite
- Finding title (verbatim): <fill in from AI Auditor's finding list>
- Why this finding is the bug: The finding must name the hash-collision / weak-message-binding
  pattern in `_getStoredMessage`'s `retryHash` check (BridgeAbstract.sol:481-495) or the matching
  commit-hash construction in `_storeMessageData` (BridgeAbstract.sol:431-446) — this is the exact
  code path `retryMessageIn` calls, and the fix commit changed nothing else.

## Attack walkthrough
1. Attacker originates a real, oracle-multisig-signed MAP-relay-chain message addressed to a
   precomputed `CREATE`-derived address with no code yet.
2. `_transferIn` sees `!Helper._isContract(to)` and stores a "NotContract" retry commitment via
   `_storeMessageData` — `orderList[orderId] = keccak256(abi.encodePacked(messageType, fromChain,
   toChain, token, amount, gasLimit, initiator, from, to, swapData))`.
3. Attacker deploys the exploit contract at that exact precomputed address.
4. Attacker calls `retryMessageIn` with the four dynamic-bytes fields (`initiator`, `from`, `to`,
   `swapData`) re-split at different byte boundaries than the original message, but packing to the
   **identical** byte string (and hash) as the planted commitment.
5. `_getStoredMessage`'s `retryHash == orderList[orderId]` check passes on the forged split.
   `_transferIn` proceeds to call `IMapoExecutor(to).mapoExecute(...)` on the attacker's contract /
   the MAPO token with attacker-controlled `swapData`, decoding an `INTERCHAIN_TRANSFER` that mints
   1e33 wei (1e15 MAPO, ~4.8M× real supply) directly to the attacker.
- Not a key compromise, not a light-client bug, not a MAPO-token bug — a pure Solidity
  `abi.encodePacked`-with-multiple-dynamic-fields footgun in the bridge's own retry-authentication.

## Vulnerable code
- file:line — `hacks/butter-bridge/scan/BridgeAbstract.sol:481-495` (`_getStoredMessage`, the
  check `retryMessageIn` relies on) and `:425-446` (`_storeMessageData`, where the same
  collision-prone hash is first written to `orderList`)
- pattern — `keccak256(abi.encodePacked(...))` spanning multiple consecutive dynamic-length
  `bytes` parameters — classic ABI-packing hash-collision / signature-malleability footgun

## Sources
- postmortem / analysis: MAP Protocol official post-mortem —
  https://x.com/MapProtocol/status/2059587998409490510 ; third-party writeup/PoC (used to
  cross-check attacker tx trace, not as the source of the vulnerable code) —
  https://github.com/sanbir/evm-hack-registry/tree/main/2026-05-MAPProtocol_exp
- fix commit (ground truth for the vulnerable code):
  https://github.com/butternetwork/butter-mos-contracts/commit/834cd8bfa8
- loss figure source: https://www.cryptotimes.io/2026/05/21/map-bridge-exploit-1-quadrillion-mapo-minted-in-cross-chain-attack/
  ; https://cointelegraph.com/news/map-protocol-loses-96-of-its-value-after-quadrillion-token-mint-exploit
