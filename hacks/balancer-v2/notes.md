# balancer-v2 (Balancer V2 — Composable Stable Pools rounding exploit)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum (multi-chain incident — same `ComposableStablePool`/`BasePool`/`StableMath` bug
  was deployed identically across Ethereum, Base, Polygon, Arbitrum, and others; Ethereum picked
  as the recovery/scan chain)
- contract hit: `ComposableStablePool` — **not a proxy**. Balancer V2 pools are immutable once
  deployed (`Proxy: 0` on Etherscan); the Vault (`0xBA12222222228d8Ba445958a75a0704d566BF2C8`)
  routes swaps into per-pool logic contracts, but each pool's own math/scaling code never changes.
  Example exploited pool on Ethereum: `0xdacf5fa19b1f720111609043ac67a9818262850c` (osETH/wETH-BPT)
- exploit contract deployment tx: `0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742`,
  block 23717397 — confirmed via `cast receipt` (`contractAddress: 0x54B53503c0e2173Df29f8da735fBd45Ee8aBa30d`)
- main attack/withdrawal tx: `0xd155207261712c35fa3d472ed1e51bfcd816e616dd4f517fa5959836f5b48569`,
  block **23717404**, `to: 0x54B53503c0e2173Df29f8da735fBd45Ee8aBa30d` (the just-deployed exploit
  contract), status success (both confirmed via `cast receipt`)
- attacker deployer EOA: `0x506D1f9EFe24f0d47853aDca907EB8d89AE03207`; funds-recipient address:
  `0xAa760D53541d8390074c61DEFeaba314675b8e3f` ("Balancer Exploiter 2" per Etherscan's own label)
- implementation live at incident vs. today: **identical**. Since `ComposableStablePool` isn't
  upgradeable, the deployed code has never changed — Balancer's response was to pause/drain-protect
  remaining pools and design a new architecture (V3) rather than patch this address. The still-live
  verified source at `0xdacf5fa1...` genuinely **is** the exploited code, verbatim.
- recovered by: pulling verified source directly via `cast source --chain mainnet
  0xdacf5fa19b1f720111609043ac67a9818262850c` — `ContractName: ComposableStablePool`, fully
  verified, full first-party dependency closure (52 files) resolved automatically, no proxy
  indirection or fix-commit archaeology needed
- **trimmed for scan, aggressively (credit-conscious pass)**: cut down to the minimal set of
  complete files that actually define and exercise the buggy code path — **7 files, 2,056 lines**
  (down from the full 52-file/8,891-line closure, and a first trim to 37/7,919 before this pass):
  `BaseGeneralPool.sol` (has `_swapGivenOut`, the exact vulnerable call site), `BasePool.sol`
  (defines `_upscale`/`_downscaleUp`/`_downscaleDown`, the asymmetric rounding helpers, and is
  `BaseGeneralPool`'s base class), `StableMath.sol` (the invariant `D` math the rounding error
  corrupts), `FixedPoint.sol` (defines `mulDown`/`divUp`/`divDown`), `Math.sol` and
  `BalancerErrors.sol` (direct dependencies of `FixedPoint`'s `_require` calls), `IGeneralPool.sol`
  (small interface `BaseGeneralPool` implements).
  - dropped this pass, beyond the first trim: `ComposableStablePool.sol` and its own
    storage/rate/protocol-fee/amplification siblings (~2,300 lines), `IVault.sol` (772 lines),
    `ERC20.sol`/`BalancerPoolToken.sol`/`WordCodec.sol`/`InputHelpers.sol` and several small
    interfaces — none of these are read by `_swapGivenOut`, `_upscale`/`_downscale`, or
    `StableMath`'s invariant computation directly; left as dangling imports (same pattern already
    proven safe for `@openzeppelin/...` refs in kyberswap-elastic/euler-v1 and for the
    permit/pause/governance files dropped in the first trim pass here)
  - **known tradeoff, accepted deliberately for this pass**: this bundle no longer includes a
    concrete deployed pool contract (`ComposableStablePool.sol`) using this swap path — only the
    abstract base classes that define and implement the bug. Per the bonzo-finance lesson, a
    scan scoped this tightly risks the validator being unable to confirm real-world reachability
    (i.e. "is this actually deployed and callable, not just theoretical library code") the same
    way it initially rejected a structurally-correct finding there. Chosen anyway this round to
    conserve AI Auditor credits; if this scan's finding gets marked invalid/unclear on
    reachability grounds, the fix is the same one that worked for bonzo — re-add
    `ComposableStablePool.sol` (+ its direct siblings) and rescan.
- confirmed present verbatim: `BaseGeneralPool._swapGivenOut` (scan/BaseGeneralPool.sol:68-85)
  upscales the requested output amount via `_upscale` (scan/BasePool.sol:680-686), which
  unconditionally calls `FixedPoint.mulDown` — the function's own doc comment (lines 681-684)
  explicitly acknowledges "Upscale rounding wouldn't necessarily always go in the same direction...
  This is the only place where we round in the same direction for all amounts, as the impact of
  this rounding is expected to be minimal" — a self-acknowledged simplification that this incident
  proved exploitable when compounded across many repeated swaps

## Claim form fields
- Protocol / project: Balancer V2 (Composable Stable Pools)
- Amount lost (digits only): 50000000 (capped at the $50M/hack scoring limit; real total loss was
  ~$128M across all affected chains combined, per contemporaneous reporting — see sources)
- Root cause: `BaseGeneralPool._swapGivenOut` (scan/BaseGeneralPool.sol:68-85) upscales both pool
  balances and the requested output amount via `_upscale` (scan/BasePool.sol:680-686), which always
  rounds down (`FixedPoint.mulDown`) — unlike `_downscale`, which offers both `divUp` and `divDown`
  variants depending on which direction is safe for the pool. This one-directional rounding was a
  deliberate, documented simplification (see the function's own comment) assumed to have minimal
  impact per-swap. The attacker exploited this by issuing dozens of carefully-sized micro-swaps
  inside `batchSwap()` calls against Composable Stable Pools, each one shaving a small, favorable
  rounding error off the pool's `StableMath` invariant `D` (scan/StableMath.sol) without ever
  triggering a revert or sanity check. Compounded over ~65 micro-swaps, this quietly deflated the
  invariant (and thus the BPT exchange rate) far below its true value, which the attacker then
  monetized by redeeming BPT at the artificially depressed rate for a large profit.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name the rounding-direction asymmetry between
  `_upscale` (always rounds down via `mulDown`, no round-up variant) and `_downscale`
  (offers both `divUp`/`divDown`) as used in `_swapGivenOut` — the exact mechanism that let
  repeated small swaps compound a rounding error against the pool's `StableMath` invariant `D`
  without tripping any safety check. This is the precise, independently-confirmed root cause
  (BlockSec, Check Point Research, Trail of Bits, Certora) of the real attack.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker deploys an exploit contract (`0x54B53503c0e2173Df29f8da735fBd45Ee8aBa30d`) at block
   23717397, built around an auxiliary local replica of Balancer's `StableMath` to simulate swap
   outcomes off-chain and find rounding "cliffs" — input sizes where the `mulDown`/`divUp`
   asymmetry in `_swapGivenOut` produces the largest exploitable rounding error per swap.
2. Attacker calls the deployed exploit contract (block 23717404), which issues a sequence of ~65
   carefully-sized `EXACT_OUT` micro-swaps against Composable Stable Pools (e.g. osETH/wETH-BPT,
   wstETH-WETH-BPT) — each individually tiny and unremarkable, routed through Balancer's Vault
   `batchSwap()` entry point.
3. Each `_swapGivenOut` call upscales the requested output via `_upscale`'s unconditional
   round-down, understating the true output slightly; the corresponding required input, while
   itself correctly rounded up via `_downscaleUp`, is computed against the already-slightly-wrong
   upscaled balances/output — accumulating a small, one-directional bias in the pool's tracked
   `StableMath` invariant `D` with every swap.
4. Because each individual step stays within normal-looking bounds (no single swap looks anomalous
   or trips a revert), the invariant `D` — and therefore the BPT price, which is derived as
   `D / totalSupply` — drifts down invisibly over the sequence of swaps.
5. Attacker redeems/arbitrages BPT positions at the now-artificially-depressed exchange rate in
   separate follow-up transactions, extracting real pool value in exchange for BPT that should have
   been worth far less than face value under the true (non-manipulated) invariant.
6. Same core bug replayed across ~9 chains (Ethereum, Base, Polygon, Arbitrum, and others) within a
   short window on 2025-11-03, netting ~$128M total.
- Not a key compromise, not phishing, not off-chain — a rounding-direction inconsistency in a pure
  fixed-point-math scaling helper, reachable from any public swap call via repeated, precisely-sized
  inputs.

## Vulnerable code
- file:line — `hacks/balancer-v2/scan/BaseGeneralPool.sol:68-85` (`_swapGivenOut`, where the
  asymmetric rounding is applied) and `hacks/balancer-v2/scan/BasePool.sol:680-686` (`_upscale`,
  the unconditional-round-down helper, with its own comment acknowledging the simplification)
- pattern — asymmetric/one-directional rounding in a fixed-point scaling helper shared across all
  swap paths, exploitable by compounding many small, precisely-sized operations to drift a
  protocol-tracked invariant away from its true value without tripping any single-transaction
  sanity check — the same general bug *class* as kyberswap-elastic's rounding-direction mismatch,
  but here compounded across repeated swaps rather than a single mis-detected tick crossing

## Sources
- technical deep-dive (root cause, exact function): BlockSec —
  https://blocksec.com/blog/in-depth-analysis-the-balancer-v2-exploit
- additional writeups: Check Point Research (exact tx/address data) —
  https://research.checkpoint.com/2025/how-an-attacker-drained-128m-from-balancer-through-rounding-error-exploitation/ ;
  Trail of Bits — https://blog.trailofbits.com/2025/11/07/balancer-hack-analysis-and-guidance-for-the-defi-ecosystem/ ;
  Certora — https://www.certora.com/blog/breaking-down-the-balancer-hack ;
  SlowMist — https://slowmist.medium.com/when-small-flaws-collapse-a-giant-inside-balancers-100m-hack-85b9e92a9ae3 ;
  OpenZeppelin — https://www.openzeppelin.com/news/understanding-the-balancer-v2-exploit
- on-chain: exploit contract deployment
  `0x6ed07db1a9fe5c0794d44cd36081d6a6df103fab868cdd75d581e3bd23bc9742` (block 23717397) and
  main attack tx `0xd155207261712c35fa3d472ed1e51bfcd816e616dd4f517fa5959836f5b48569`
  (block 23717404) — both confirmed success via `cast receipt`
- ground-truth source: Etherscan, verified `ComposableStablePool` contract at
  `0xdacf5fa19b1f720111609043ac67a9818262850c` (no reconstruction — this address's live code is
  the exact code that was exploited, since Balancer V2 pools are not upgradeable)
