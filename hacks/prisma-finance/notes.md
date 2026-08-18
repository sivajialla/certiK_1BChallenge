# prisma-finance (Prisma Finance — MigrateTroveZap flashloan hijack)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum
- contract hit: `MigrateTroveZap` — **not a proxy**, deployed twice for two debt tokens: mkUSD at
  `0xcc7218100da61441905e0c327749972e3cbee9ee`, ULTRA at
  `0xC3eAf094e2586965244aB6534f6Dc69c6C16b5D5`. Both verified, both contain the identical bug
  (same source, deployed for two different debt-token/trove-manager pairs)
- exploit tx (primary, mkUSD): `0x00c503b595946bccaea3d58025b5f9b3726177bbdc9674e634244135282116c7`,
  block **19532297**, status success (confirmed via `cast receipt`)
- attacker EOA: `0x7E39E3B3ff7ADef2613d5Cc49558EAB74B9a4202` — responsible for ~$11.6M of the
  ~$12.3M total loss (two other addresses accounted for the remainder)
- note: the exploit tx's direct `to` address, `0xD996073019c74B2fB94eAD236e32032405bC027c`, is the
  attacker's own **unverified** wrapper/helper contract — it calls into the real, verified
  `MigrateTroveZap` internally. Same pattern seen in euler-v1: don't mistake the attacker's helper
  contract for the actual vulnerable protocol contract.
- implementation live at incident vs. today: **identical**. `MigrateTroveZap` isn't upgradeable;
  Prisma's response was to have users stop calling it (front-end/UI removed the migration flow),
  not to patch this address in place — confirmed by reading the deployed source directly, which
  still contains the exact bug described in every independent writeup
- recovered by: `cast source --chain mainnet 0xcc7218100da61441905e0c327749972e3cbee9ee` — verified
  directly, `ContractName: MigrateTroveZap`, no proxy indirection or fix-commit archaeology needed

## Claim form fields
- Protocol / project: Prisma Finance — `MigrateTroveZap` (mkUSD version)
- Amount lost (digits only): 11600000
- Root cause: `MigrateTroveZap.onFlashLoan` (scan/MigrateTroveZap.sol:62-83) is the ERC-3156
  flashloan callback. Its only access check is `require(msg.sender == address(debtToken), ...)`
  (line 69) — it verifies the caller is the debt token contract, but **never verifies who
  initiated the flashloan** (i.e. that it was this same `MigrateTroveZap` contract, via its own
  legitimate `migrateTrove` function). `debtToken.flashLoan(...)` (an ERC-3156 standard function,
  scan/IDebtToken.sol) can be called by **any external address**, specifying `MigrateTroveZap` as
  the receiver and attacker-chosen arbitrary `data`. `onFlashLoan` blindly `abi.decode`s that data
  into `account`, `troveManagerFrom`, `troveManagerTo`, and `coll` (lines 70-78) and immediately
  calls `borrowerOps.closeTrove(troveManagerFrom, account)` then
  `borrowerOps.openTrove(troveManagerTo, account, ..., coll, toMint, ...)` (lines 80-81) using those
  attacker-supplied values — closing a victim's real trove and reopening it with attacker-chosen
  collateral/debt figures, entirely bypassing `migrateTrove()`'s legitimate ownership and
  debt-existence checks (lines 92-97).
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name `onFlashLoan`'s missing check that the
  flashloan was actually initiated by `MigrateTroveZap` itself (via `migrateTrove`), rather than by
  an arbitrary caller invoking `debtToken.flashLoan()` directly with `MigrateTroveZap` as the
  receiver and forged `data`. This is the exact mechanism every independent writeup (Olympix,
  ImmuneBytes, ZAN, SharkTeam, CertiK, CUBE3) converges on, and matches the real attack's structure:
  a small legitimate trove opened first, then `flashLoan` called directly to trigger `onFlashLoan`
  with forged parameters that hijack a much larger trove's collateral.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker opens a small, legitimate Trove (e.g. 1 wstETH collateral, 2,000 mkUSD debt) via the
   normal `BorrowerOperations` flow — just to have a valid account/trove pair to reference.
2. Attacker calls `debtToken.flashLoan(receiver=MigrateTroveZap, token=debtToken, amount, data)`
   **directly** — bypassing `MigrateTroveZap.migrateTrove()` entirely, which is the only function
   meant to trigger this flashloan. `data` is `abi.encode`d to claim `account` = attacker's own
   address, but `coll` (collateral amount) set to a large, attacker-chosen value far exceeding what
   the attacker's real trove holds.
3. `debtToken` calls back into `MigrateTroveZap.onFlashLoan`. The only check,
   `msg.sender == address(debtToken)`, passes trivially (the debt token contract genuinely is the
   caller — it just doesn't matter who told it to call `flashLoan` in the first place).
4. `onFlashLoan` decodes the attacker's forged `data` and calls `borrowerOps.closeTrove(...)` then
   `borrowerOps.openTrove(...)`, reopening the attacker's trove with the large, spoofed collateral
   figure — collateral that was actually sitting in the `MigrateTroveZap` contract's own balance
   from unrelated legitimate migrations by other users, not from the attacker.
5. Attacker closes/withdraws the newly-inflated trove, extracting far more collateral than they
   ever deposited. Repeated across mkUSD and ULTRA zap versions and multiple attacker addresses,
   netting ~$12.3M total (~$11.6M to the primary attacker).
- Not a key compromise, not phishing, not off-chain — a missing "who actually initiated this
  flashloan" check in a public ERC-3156 callback, reachable by anyone willing to pay the flashloan
  fee.

## Vulnerable code
- file:line — `hacks/prisma-finance/scan/MigrateTroveZap.sol:62-83` (`onFlashLoan`, the missing
  initiator-validation check before trusting `data`) and `:86-118` (`migrateTrove`, the legitimate
  entry point whose ownership/debt-existence checks the direct-`flashLoan`-call path bypasses
  entirely)
- pattern — ERC-3156 flashloan callback (`onFlashLoan`) that checks only `msg.sender == token`
  (i.e. "did the token contract call me back") without checking that the flashloan was actually
  initiated by the contract's own trusted entry point — any address can call the token's public
  `flashLoan()` function naming this contract as receiver and supply arbitrary forged callback data

## Sources
- primary technical writeup: Olympix — https://olympixai.medium.com/decoding-the-prisma-finance-exploit-0aacecd5e876
  (also: https://medium.com/devsecops-ai/prismas-11-6m-exploit-wasn-t-a-flaw-in-logic-it-was-a-flaw-in-trust-51e2f3e48457)
- additional writeups: ImmuneBytes — https://immunebytes.com/blog/prisma-finance-exploit-march-28-2024-detailed-analysis/ ;
  ZAN — https://medium.com/@zan.top/attack-analysis-on-prisma-finance-cf3111b5eb0d ;
  SharkTeam — https://medium.com/@sharkteam/sharkteam-analysis-of-the-attack-on-prisma-finance-f999af6fba5e ;
  CertiK — https://www.certik.com/resources/blog/prisma-finance-incident-analysis ;
  official post-mortem — https://hackmd.io/@PrismaRisk/PostMortem0328
- on-chain: exploit tx
  `0x00c503b595946bccaea3d58025b5f9b3726177bbdc9674e634244135282116c7`, block 19532297, confirmed
  success via `cast receipt`
- ground-truth source: Etherscan, verified `MigrateTroveZap` at
  `0xcc7218100da61441905e0c327749972e3cbee9ee` (mkUSD) and
  `0xC3eAf094e2586965244aB6534f6Dc69c6C16b5D5` (ULTRA) — no reconstruction needed, both directly
  verified, not upgradeable, code unchanged since deployment
