# new-market-trading (SquidRouterModule — forged Axelar express-execute confused deputy)

## Recovery (rule 01 — goes in the claim)
- chain: Base (same bug hit Ethereum and Arbitrum too, per contemporaneous reporting — 88 Safes
  across 3 chains, ~15 minutes; Base picked as the recovery/scan chain since our tooling is
  EVM-mainnet/Base-first and the exploit tx is directly confirmed there)
- contract hit: `SquidRouterModule` at `0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca` — a custom
  Gnosis Safe module built by New Market Trading (NMT), **not** built or operated by Squid itself
  (Squid/Squid Labs publicly distanced themselves from this incident — the module merely integrates
  with Squid's Axelar-based bridge). Not a proxy.
- exploit tx: `0xf4f73ba0ac93a642df558840ac5d1be3cc6dc07e3862c53d93ad4841eeba2443`, block
  **27872020** on Base, status success (confirmed via `cast receipt`)
- implementation live at incident vs. today: **identical**. `SquidRouterModule` isn't upgradeable;
  NMT's response was to disable/remove the module from affected Safes, not patch this address in
  place. The still-live verified source genuinely is the exploited code.
- recovered by: `cast source --chain base 0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca` — verified
  directly, `ContractName: SquidRouterModule`, no proxy indirection or reconstruction needed
- note: NMT's V1 platform was audited by Burra Security (Oct 2025) and did **not** include this
  module; `SquidRouterModule` was added afterward in V2, so this specific code was never covered by
  that audit

## Claim form fields
- Protocol / project: New Market Trading (NMT) — SquidRouterModule (Gnosis Safe module)
- Amount lost (digits only): 3980000
- Root cause: `SquidRouterModule._executeWithToken` (scan/SquidRouterModule.sol:142-157), the
  callback Axelar's express-relay mechanism invokes, has exactly one authorization check:
  `require(srcAddress == squidRouter, ...)` — a comparison against a caller-supplied **string**
  form of the source address (line 151-152). This does not verify that a real, funded cross-chain
  bridge transfer actually occurred; Axelar's `expressExecuteWithToken` entry point is designed to
  let *any* express-relay executor call in with attacker-chosen `payload`/`amount`/`tokenSymbol`
  data ahead of the real underlying transfer settling. `_processPayload` (lines 159-175) then
  `abi.decode`s a `delegate` address directly out of that attacker-controlled `payload` (line 164)
  and passes it into `_handleActions` → `_handleAction` → `_checkPermission(safe, delegate, ...)`
  (BaseModule.sol) with **no check that the caller is actually that delegate** — `_checkPermission`
  only verifies the *claimed* delegate's real, legitimate permissions on the *real* victim Safe. An
  attacker who names a real, already-permissioned relayer/bot address as `delegate` in their forged
  payload passes every check, because every check is validating an identity the attacker merely
  cited, not one they had to prove. This is the classic "confused deputy" pattern — the module acts
  on the victim Safe's behalf believing it's following a legitimate, permissioned delegate's
  instructions, when it's actually following the attacker's forged claim about who that delegate is.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name `_executeWithToken`'s string-form
  `sourceAddress` check as insufficient proof of a genuine bridged transfer, and/or
  `_processPayload`'s trust in an attacker-supplied `delegate` address that `_checkPermission`
  then validates using that claimed identity's real permissions rather than verifying the caller's
  actual identity. This is the exact "forged express payload" / confused-deputy mechanism
  documented by DarkNavy and Common Prefix's independent technical writeups, and matches the real
  attack: three fake `expressExecuteWithToken` calls with zero bridged amount, each impersonating a
  permissioned delegate to approve tokens, authorize Permit2, then force a full-balance swap.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker identifies that `SquidRouterModule` inherits Axelar's `expressExecuteWithToken` —
   designed for legitimate express-relay executors to front-run a real bridge settlement — and that
   this entry point is reachable by anyone, with `_executeWithToken`'s only gate being a
   caller-supplied string comparison against Squid's own router address.
2. Attacker calls `expressExecuteWithToken` (or the underlying `_executeWithToken`) directly with
   `sourceAddress` set to Squid's real router address (satisfying the one check present), an
   `amount` of effectively zero real bridged value, and a forged `payload` encoding: `module` =
   this same module address (satisfying `_processPayload`'s `module == address(this)` check),
   `safe` = the victim's real Gnosis Safe, and `delegate` = a real, already-permissioned
   relayer/automation address for that Safe (not the attacker's own address).
3. `_processPayload` transfers the (near-zero) "bridged" token to the victim Safe, then calls
   `_handleActions(safe, delegate, params)` with the attacker's chosen `params` — a sequence of
   three actions: approve a token, authorize Permit2, and execute a full-balance swap through a
   Uniswap V3 pool the attacker controls.
4. Each action's `_checkPermission(safe, delegate, ...)` call passes, because `delegate` genuinely
   does hold that permission on that Safe — the check has no way to know the actual caller isn't
   that delegate, since delegate identity was never authenticated, only cited.
5. The victim Safe's tokens are approved, Permit2-authorized, and swapped in full through the
   attacker's pool in a single sequence, extracting the Safe's entire balance.
6. Repeated across 88 Safes on Ethereum, Base, and Arbitrum within ~15 minutes. Attacker later
   removed liquidity from the pools, consolidated proceeds cross-chain via Relay, swapped
   everything to DAI, and swept it to a single wallet.
- Not a key compromise, not phishing, not off-chain — a missing authentication check in a public
  cross-chain callback entry point, reachable by anyone, that let attacker-supplied payload data
  substitute for genuine bridge-relay proof and real delegate identity.

## Vulnerable code
- file:line — `hacks/new-market-trading/scan/SquidRouterModule.sol:142-157` (`_executeWithToken`,
  the insufficient string-form source-address check) and `:159-175` (`_processPayload`, where an
  attacker-controlled `delegate` address is trusted and forwarded into permission-checked action
  execution with no verification the caller actually is that delegate)
- pattern — confused deputy: a privileged module trusts an identity (`delegate`) supplied in
  attacker-controlled input data, then performs a real authorization check against that *claimed*
  identity rather than verifying the *caller's* actual identity — the permission check is correct
  in isolation, but checks the wrong party

## Sources
- technical writeups: DarkNavy — https://www.darknavy.org/web3/exploits/new-market-trading-squid-router-module-forged-express-payload/ ;
  Common Prefix — https://www.commonprefix.com/blog/squidroutermodule-exploit-investigation ;
  QuillAudits — https://www.quillaudits.com/blog/hack-analysis/new-market-trading-exploit ;
  Rekt News — https://rekt.news/newmarkettrading-rekt
- news coverage (Squid/Squid Labs distancing themselves, confirming third-party module):
  https://www.tradingview.com/news/cointelegraph:6c8298b42094b:0-squid-and-safe-labs-say-third-party-module-behind-3-2m-exploit/ ;
  https://coinpedia.org/news/3m-drained-from-86-gnosis-safes-in-squidroutermodule-exploit/
- on-chain: exploit tx
  `0xf4f73ba0ac93a642df558840ac5d1be3cc6dc07e3862c53d93ad4841eeba2443`, block 27872020 (Base),
  confirmed success via `cast receipt`
- ground-truth source: Basescan, verified `SquidRouterModule` at
  `0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca` — no reconstruction needed, not upgradeable, code
  unchanged since deployment
