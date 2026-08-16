# kyberswap-elastic (KyberSwap Elastic — concentrated-liquidity DEX)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum (multi-chain incident — same `Pool.sol`/`SwapMath.sol` bug hit Arbitrum, Optimism,
  BSC, Avalanche, Polygon, Fantom, Base, Scroll, Linea, Polygon zkEVM, BitTorrent, Cronos too;
  Ethereum picked as the recovery/scan chain since our tooling is EVM-mainnet-first)
- contract hit: `Pool` — **not a proxy**. Each KyberSwap Elastic pool is deployed directly (no
  EIP-1967/beacon indirection); `Proxy: 0` on Etherscan. Example exploited pool on Ethereum:
  `0xcbec1e9407f1910c86f261eaeac27d85c0479e8c` (an ETHx pool)
- exploit tx (Ethereum, one of many): `0x485e08dc2b6a4b3aeadcb89c3d18a37666dc7d9424961a2091d6b3696792f0f3`,
  block **18630392**, status success (confirmed via `cast receipt`)
- attacker EOA ("KyberSwap Exploiter 1"): `0x50275e0b7261559ce1644014d4b78d4aa63be836` (from address
  on the exploit tx, matches Etherscan's own label)
- implementation live at incident vs. today: **identical**. Since `Pool` isn't upgradeable, the
  code at this address has never changed — KyberSwap's fix was to deploy brand-new pool contracts
  with a corrected `SwapMath` library, not to patch this address in place. The still-live source at
  `0xcbec1e94...` genuinely **is** the exploited code, verbatim, no reconstruction needed.
- recovered by: pulling verified source directly via `cast source --chain mainnet
  0xcbec1e9407f1910c86f261eaeac27d85c0479e8c` — `ContractName: Pool`, fully verified, no proxy
  indirection to resolve first
- note: an initial guess at the "pool" address (`0xaf2acf3d4ab78e4c702256d214a3189a874cdc13`, taken
  from a log emitter in the exploit tx receipt) turned out to be the **attacker's own PoC/exploit
  helper contract** (bytecode contains `forge-std`'s `failed()` selector and debug-string events
  like `"STARTING Pool..."`), not a real KyberSwap contract — caught by checking the bytecode before
  trusting the address, corrected to the real target pool named in third-party writeups.

## Claim form fields
- Protocol / project: KyberSwap Elastic
- Amount lost (digits only): 48000000 (capped at the $50M/hack scoring limit; real total loss per
  KyberSwap's own post-mortem was ~$56.2M in affected assets, ~$55.2M actually extracted, across all
  chains combined — DeFiLlama's hacks.csv separately lists $48M for this incident)
- Root cause: `SwapMath.estimateIncrementalLiquidity` (scan/SwapMath.sol:169-216), specifically the
  `!isToken0` branch (185-193): the code comment says "we round up deltaL, to round down nextSqrtP,"
  but the implementation calls `FullMath.mulDivFloor` (rounds down) instead of a round-up variant.
  This mis-rounds `deltaL`, which `SwapMath.calcFinalPrice` (scan/SwapMath.sol:253+) then uses to
  compute `nextSqrtP` — the error lets `nextSqrtP` overshoot the intended tick boundary
  (`targetSqrtP`) without the swap loop recognizing a tick crossing. `Pool._updateLiquidityAndCrossTick`
  (scan/PoolTicksState.sol:78+, called from `Pool.swap`, scan/Pool.sol:457) never fires to update the
  active liquidity for the new tick, so subsequent swap steps compute against stale liquidity/price
  state — the discrepancy an attacker can chain across repeated precise swaps to drain a pool.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name the rounding-direction mismatch in
  `estimateIncrementalLiquidity`'s `mulDivFloor` call (line 189) — the exact function whose deltaL
  output feeds `calcFinalPrice`'s `nextSqrtP`, letting price overshoot a tick boundary that
  `_updateLiquidityAndCrossTick` never gets triggered to account for. This is the single-line
  root cause identified by BlockSec's independent technical writeup and matches the precise
  precision-loss mechanism the attacker's crafted swap sequence exploited.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker flash-borrows a large amount of a token (e.g. ETHx) from an external source (Uniswap V3)
   to fund a large, precisely-sized swap into a KyberSwap Elastic pool.
2. The swap is engineered so that, mid-swap-step, `SwapMath.computeSwapStep` calls
   `estimateIncrementalLiquidity` in the `!isToken0` branch, where the intended round-up of `deltaL`
   is instead rounded down via `mulDivFloor` (line 189).
3. The under-rounded `deltaL` feeds into `calcFinalPrice`, producing a `nextSqrtP` that has crossed
   past the actual tick boundary (`targetSqrtP`) — but the swap step's caller (`Pool.swap`,
   `Pool.sol:397-457`) doesn't see this as "tick crossed," so `_updateLiquidityAndCrossTick`
   (`PoolTicksState.sol:78`) is never invoked to roll the active liquidity over to the new tick.
4. The pool's internal liquidity/price state is now inconsistent with reality — liquidity for the
   old tick is still being used to price swaps against a price that has already moved past it.
5. The attacker repeats/chains precisely-sized swaps across this state mismatch, extracting far more
   output than the pool's actual liquidity should allow, draining the pool's reserves.
6. Same core bug (single shared `SwapMath` library, deployed identically per-chain since pools
   aren't upgradeable) was replayed by the attacker across ~13 chains within a short window on
   2023-11-22/23, netting ~$55.2M extracted / ~$56.2M affected total.
- Not a key compromise, not phishing, not off-chain — a single incorrect rounding-direction choice
  (`mulDivFloor` where the code's own comment says round up) in a pure-math internal library
  function, reachable from any public swap call with an attacker-chosen amount/direction.

## Vulnerable code
- file:line — `hacks/kyberswap-elastic/scan/SwapMath.sol:185-193` (`estimateIncrementalLiquidity`,
  `!isToken0` branch, the `mulDivFloor` that should round up) and `:253+` (`calcFinalPrice`, where
  the mis-rounded `deltaL` produces an overshot `nextSqrtP`)
- pattern — asymmetric/incorrect rounding direction in a fee/liquidity-delta calculation that
  controls whether a price-boundary (tick) crossing is correctly detected downstream; classic
  "precision loss becomes exploitable state desync" bug in concentrated-liquidity AMM math

## Sources
- official post-mortem: https://blog.kyberswap.com/post-mortem-kyberswap-elastic-exploit/
- technical deep-dive (root cause, exact function/line): BlockSec —
  https://blocksec.com/blog/yet-another-tragedy-of-precision-loss-an-in-depth-analysis-of-the-kyber-swap-incident-1
  (mirror: https://blocksecteam.medium.com/yet-another-tragedy-of-precision-loss-an-in-depth-analysis-of-the-kyberswap-incident-b0556022a570)
- additional writeups: SlowMist — https://slowmist.medium.com/a-deep-dive-into-the-kyberswap-hack-3e13f3305d3a ;
  Halborn — https://www.halborn.com/blog/post/explained-the-kyberswap-hack-november-2023 ;
  SolidityScan — https://blog.solidityscan.com/kyberswap-hack-analysis-25e25f2e4a7b/
- on-chain: exploit tx (Ethereum)
  `0x485e08dc2b6a4b3aeadcb89c3d18a37666dc7d9424961a2091d6b3696792f0f3`, block 18630392, confirmed
  success via `cast receipt`
- ground-truth source: Etherscan, verified `Pool` contract at
  `0xcbec1e9407f1910c86f261eaeac27d85c0479e8c` (no reconstruction — this address's live code is the
  exact code that was exploited, since Pool contracts are not upgradeable)
