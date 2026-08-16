# euler-v1 (Euler Finance — donateToReserves self-liquidation exploit)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum
- contract hit: Euler's custom module-dispatcher architecture, not a standard EIP-1967 proxy.
  - main dispatcher (Etherscan-flagged proxy, `ContractName: Euler`): `0x27182842E098f60e3D576794A5bFFb0777E025d3`
  - eDAI eToken thin proxy (calls dispatch through the main contract): `0xe025E3ca2bE02316033184551D4d3Aa22024D9DC`
  - Liquidation module thin proxy: `0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34`
  - Every eToken/module has its own lightweight forwarding proxy, all ultimately delegatecalling
    into shared module implementation contracts (`EToken.sol`, `Liquidation.sol`) selected
    internally by the main dispatcher — recovered the actual module *source*, not any one proxy's
    on-chain bytecode, since that's where the bug lives
- exploit tx (primary DAI attack): `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`,
  block **16817996**, status success (confirmed via `cast receipt`)
- attacker EOA: `0x5F259D0b76665c337c6104145894F4D1D2758B8c`; attacker contract:
  `0xeBC29199C817Dc47BA12E3F86102564D640CBf99`
- recovered by: `cast run` (Foundry trace-replay) on the exploit tx to identify the exact call
  sequence and confirm which contracts/functions were actually hit —
  `eDAI.donateToReserves(0, 1e26)` followed immediately by `Liquidation.checkLiquidation(...)` /
  `Liquidation.liquidate(...)` on the same attacker-controlled sub-account — then pulled the module
  source directly from Euler's own archived (post-shutdown) GitHub repo,
  `euler-legacy-xyz/euler-contracts` (formerly `euler-xyz/euler-contracts`), `contracts/modules/EToken.sol`
  and `contracts/modules/Liquidation.sol` plus their shared base classes
- **no fix-commit archaeology needed and no reconstruction risk**: Euler Finance never resumed V1
  operation after the hack (funds were eventually returned via negotiation with the attacker; the
  team later launched an unrelated V2 architecture). The repo was archived, not patched — the code
  pulled here is exactly what was live and exploited, not a guess from a parent commit.
- confirmed present verbatim: `EToken.sol:359-386` (`donateToReserves`) transfers `amount` from the
  caller's tracked balance straight into `reserveBalance` and never calls `checkLiquidity`/any
  solvency check on the donating account — grepped directly, present exactly as described in every
  third-party post-mortem

## Claim form fields
- Protocol / project: Euler Finance (Euler V1 — EToken / Liquidation modules)
- Amount lost (digits only): 50000000 (capped at the $50M/hack scoring limit; real total loss was
  ~$197M across all affected assets, per contemporaneous reporting — see sources)
- Root cause: `EToken.donateToReserves` (scan/EToken.sol:359-386) lets any account move funds from
  its own tracked `balance` into the pool's `reserveBalance` with **no solvency/health check**
  (no call to `checkLiquidity` or any liquidity-computation helper anywhere in the function) — only
  a plain balance-sufficiency check (`origBalance >= amount`). This lets an attacker who has
  recursively over-borrowed against a large flash-loaned deposit deliberately donate away a chunk
  of their own collateral to intentionally push their own account's health score below 1, without
  the protocol ever validating that the resulting state is still solvent. `Liquidation.liquidate`
  (scan/Liquidation.sol:198+) then treats this deliberately-manufactured bad debt as a legitimate
  liquidation opportunity and pays out the attacker's second account (acting as "liquidator") a
  large discount/yield — funded by the pool's own real depositor funds, not the attacker's capital.
- Smart contract bug? Yes
- Scan ID: `8e2d050f-483b-5bcd-8db5-81375e68ab57` (Lite)
- Tier: Lite
- Finding title (verbatim): [Discussion] Unchecked donateToReserves permits intentional
  undercollateralization and reserve-funded liquidation losses
- Why this finding is the bug: The finding names `donateToReserves`'s missing `checkLiquidity`
  call as the mechanism letting a borrower donate away collateral while still carrying debt, and
  its PoC reproduces the real attack sequence step-for-step: self-borrow to build a leveraged
  position, `donateToReserves` most of the eToken balance with no solvency check, then liquidate
  the now-underwater account from a separate attacker-controlled address to collect the payout.
  This is exactly the `donateToReserves` → `checkLiquidation`/`liquidate` sequence observed in the
  real exploit transaction's trace.
- Severity note: AI Auditor rated this finding **Discussion**, not Critical/High — it explicitly
  hedges that it couldn't fully confirm the "reserve-funded liquidation loss" consequence from the
  scanned files alone (liquidation payout mechanics weren't fully traceable within scope). Per the
  same precedent as butter-bridge's Info-severity catch, rule 04 only requires the finding to name
  the bug actually exploited, not hit a severity threshold — the root-cause mechanism named here is
  exactly correct.

## AI Auditor scan log

### Lite — 2026-08-16 — CAUGHT (first try)
- Task ID: `8e2d050f-483b-5bcd-8db5-81375e68ab57`
- 5 findings returned:
  1. **[Discussion] Unchecked donateToReserves permits intentional undercollateralization and
     reserve-funded liquidation losses** (EToken.sol:379-385) — **this is the exploited bug.**
     Names the missing `checkLiquidity(account)` call in `donateToReserves` exactly, and its PoC
     (self-borrow → donate → liquidate from a second address) matches the real attack's structure.
  2. [Major] Withdrawals fail to account for sender-side transfer fees (`withdraw`/`pushTokens`,
     EToken.sol:190-195) — real but unrelated fee-on-transfer accounting bug, not what was
     exploited.
  3. [Info] Reserve fee is lost when reserve accounting caps are exceeded (`increaseReserves`,
     BaseLogic.sol:535-538) — real but unrelated silent-cap-skip bug.
  4. [Discussion/Info] Average-liquidity decay can be slowed by zero-value transfers
     (`getUpdatedAverageLiquidity`, BaseLogic.sol:600-611) — real but unrelated, and the tool
     itself notes no reachable code path establishes the prerequisite state in the scanned files.
  5. [Major] First-depositor exchange rate inflation enables zero-share deposits (`deposit`,
     BaseLogic.sol:197-202) — a real, classic ERC4626-style share-inflation bug, but unrelated to
     the donation/self-liquidation mechanism actually exploited.
- Conclusion: **Lite caught it on the first try.** Finding 1 is the claim.

## Attack walkthrough
1. Attacker flash-loans 30M DAI (via a chain of Aave → another lender's flash loan facility, per
   the trace) into an exploit contract.
2. Attacker deploys two sub-accounts/contracts and recursively deposits/borrows DAI through Euler
   to build up a large leveraged position — collateral in one account, debt tracked appropriately —
   using the flash-loaned capital as the base.
3. Attacker calls `eDAI.donateToReserves(0, 1e26)` (100M eDAI) on the leveraged account. This
   function unconditionally moves that amount from the account's tracked balance into the pool's
   `reserveBalance`, with no check that the account remains solvent afterward — its collateral
   value now sits below its liability value.
4. Attacker (from a second, "liquidator" account/contract) calls
   `Liquidation.checkLiquidation(...)` against the now-undercollateralized first account.
   `computeLiqOpp` sees `healthScore < 1e18` and computes a real, sizeable discount/yield —
   because the deliberately-donated shortfall looks identical on-chain to organic bad debt from a
   market move.
5. The "liquidator" account calls `Liquidation.liquidate(...)`, which pays out the discounted
   yield. Because `Liquidation.liquidate`'s only post-condition check is `checkLiquidity` on the
   *liquidator* (line ~280) — not any validation that the violator's shortfall was legitimate — the
   attacker collects real pool funds (from other depositors' real DAI) in exchange for "repaying" a
   debt that was never actually at organic risk.
6. Attacker repeats this donate→self-liquidate cycle across many assets/sub-accounts within ~15
   minutes on 2023-03-13, extracting ~$197M in total before repaying the flash loans and keeping
   the difference.
- Not a key compromise, not phishing, not off-chain — a missing solvency check in a single public
  function (`donateToReserves`), reachable by anyone, that lets an account manufacture a fake
  liquidation opportunity the protocol's own liquidation logic then pays out as if it were real.

## Vulnerable code
- file:line — `hacks/euler-v1/scan/EToken.sol:359-386` (`donateToReserves`, missing solvency check
  before moving balance into `reserveBalance`) — this is the single function every independent
  post-mortem (BlockSec, SlowMist, Coinbase, Omniscia, Cyfrin) converges on as the root cause
- pattern — state-mutating public function that moves value/collateral without re-validating the
  caller's account health afterward, combined with a downstream liquidation mechanism that trusts
  the resulting (attacker-manufactured) health score at face value

## Sources
- technical deep-dive: BlockSec — https://blocksec.com/blog/euler-finance-incident-the-largest-hack-of-2023
- additional writeups: SlowMist — https://slowmist.medium.com/slowmist-an-analysis-of-the-attack-on-euler-finance-5143abc0d5ad ;
  Coinbase — https://www.coinbase.com/blog/euler-compromise-investigation-part-1-the-exploit ;
  Omniscia (Euler's own post-mortem writeup) — https://medium.com/@omniscia.io/euler-finance-incident-post-mortem-1ce077c28454 ;
  Cyfrin — https://www.cyfrin.io/blog/how-did-the-euler-finance-hack-happen-hack-analysis ;
  CertiK — https://www.certik.com/resources/blog/euler-finance-incident-analysis
- on-chain: exploit tx
  `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`, block 16817996, confirmed
  success via `cast receipt`; call sequence confirmed via `cast run` trace-replay
- ground-truth source: `euler-legacy-xyz/euler-contracts` (GitHub, archived, formerly
  `euler-xyz/euler-contracts`), `contracts/modules/EToken.sol` and `contracts/modules/Liquidation.sol` —
  the live, never-patched code (protocol never resumed V1 after the hack)
