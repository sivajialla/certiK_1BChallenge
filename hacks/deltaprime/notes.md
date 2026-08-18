# deltaprime (DeltaPrime — swapDebtParaSwap missing value-parity check)

## Recovery (rule 01 — goes in the claim)
- chain: Arbitrum (DeltaPrime "Blue" deployment; the same Nov 11 2024 incident also hit "Red" on
  Avalanche via an analogous facet — this claim focuses on the Arbitrum leg, which the recovered
  exploit tx and facet source both confirm directly)
- contract hit: DeltaPrime uses an EIP-2535 Diamond pattern — each user's "SmartLoan" is a Diamond
  proxy instance (e.g. `0xf81b4381b70ef520ae635afd4b0e8aeb994131fb`) that delegatecalls into shared,
  immutable **facet** contracts based on function selector, routed via `SmartLoanDiamondBeacon`
  (`0x62Cf82FB0484aF382714cD09296260edc1DC0c6c`). The bug lives in the shared
  `AssetsOperationsFacet`/`AssetsOperationsArbitrumFacet` logic, not in any individual user's loan.
- **pre-incident vulnerable facet** (recovered, not the current one): `AssetsOperationsArbitrumFacet`
  at `0xCA60C5D2ee1F9C79C92A9D5831DC22cCc291b5f5` — confirmed via on-chain `DiamondCut` event
  archaeology (see below) to be the facet actually mapped to the `swapDebtParaSwap` selector
  (`0x8913e62c`) at incident time
- exploit tx: `0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f`, block
  **273278742** on Arbitrum, status success (confirmed via `cast receipt`)
- attacker EOA: `0xb87881637b5c8e6885C51aB7D895e53FA7d7c567`; attacker helper contract:
  `0x0B2Bcf06F740C322BC7276b6b90dE08812cE9bfE`
- recovered by (since DeltaPrime's official GitHub repo, `DeltaPrimeLabs/deltaprime-contracts`, is
  a single-commit "Initial public release" snapshot from a year after the incident — no usable git
  history):
  1. computed the selector for the current (patched) `swapDebtParaSwap` signature and confirmed via
     Etherscan's `DiamondCut` event logs (topic0
     `0x8faa70878671ccd212d20771b795c50af8fd3ff6cf27f4bde57e5d4de0aeb673` on the
     `SmartLoanDiamondBeacon`) that this exact selector was **removed** ~9 days after the incident
     (block 276542324, consistent with an emergency post-incident fix)
  2. queried all `DiamondCut` events on the Diamond from genesis through the incident block, decoded
     each with `cast decode-event`, and found the most recent pre-incident `REPLACE` action touching
     this selector: block **229807814**, facet `0xCA60C5D2ee1F9C79C92A9D5831DC22cCc291b5f5` — no
     later replacement exists before the incident, confirming this facet was live throughout
  3. this facet address is independently verified on Arbiscan as `AssetsOperationsArbitrumFacet`,
     source pulled directly via `cast source` — ground truth, not reconstructed
  4. confirmed the pulled `swapDebtParaSwap` lacks the USD-value-parity check present in the
     current (patched) version at the same address-family — see diff described in "Root cause"

## Claim form fields
- Protocol / project: DeltaPrime (Blue deployment, Arbitrum)
- Amount lost (digits only): 4750000 (Arbitrum "Blue" + Avalanche "Red" combined per contemporaneous
  reporting; this claim's recovered code/tx is the Arbitrum leg)
- Root cause: `AssetsOperationsFacet.swapDebtParaSwap` (scan/AssetsOperationsFacet.sol:269-297)
  clamps `_repayAmount` to at most the account's actual borrowed balance and its actual post-swap
  token balance (`Math.min(...)`, lines 272 and 292) — but **never validates that `_repayAmount`'s
  USD value is anywhere close to `_borrowAmount`'s USD value**. The function borrows `_borrowAmount`
  of `_toAsset` first (line 278, `toAssetPool.borrow(_borrowAmount)`), then executes an
  attacker-controlled ParaSwap call (`selector`+`data`, line 288) that is supposed to swap the
  newly-borrowed asset back into `_fromAsset` to fund the repayment — but nothing stops the
  attacker's calldata from routing that borrowed value to their own contract instead of actually
  swapping it back. `_repayAmount` then gets silently clamped down (via `Math.min`) to whatever
  tiny/near-zero `_fromAsset` balance is actually left, so the loan records a repayment for a
  fraction of the real USD value of the debt just taken on — the account walks away owing far less
  than the value of what it borrowed. The fix (visible in the current on-chain code) added an
  explicit `require(maxDiff <= 500, ...)` check enforcing repay-value and borrow-value stay within
  5% of each other.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name `swapDebtParaSwap`'s missing check that the
  repaid value (`_repayAmount`) is commensurate with the newly-borrowed value (`_borrowAmount`) —
  the function borrows first, lets an attacker-controlled external call determine what (if
  anything) comes back, and only clamps the repayment to whatever residual balance exists rather
  than requiring the two amounts to be economically equivalent. This is the exact mechanism named
  in every independent writeup (SolidityScan, Verichains, QuillAudits, Halborn, CertiK, Three
  Sigma) and matches the confirmed pre-incident facet source recovered above.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker flash-loans ~59.958 WETH, deposits it as collateral into a freshly-created SmartLoan
   (a Diamond instance they own — `onlyOwner`/`onlyOwnerOrInsolvent` checks on facet functions only
   gate "is this the loan owner," which the attacker legitimately is for their own loan).
2. Attacker calls `swapDebtParaSwap(_fromAsset=WBTC, _toAsset=..., _repayAmount=<attacker-chosen>,
   _borrowAmount=1.18 WBTC, selector, data)` — or the reverse framing per the writeups: borrows a
   valuable asset (WBTC) against a much smaller value actually returned.
3. `toAssetPool.borrow(_borrowAmount)` mints/lends the attacker 1.18 WBTC worth of value into the
   SmartLoan's control.
4. The subsequent `PARA_ROUTER.call(abi.encodePacked(selector, data))` — fully attacker-controlled
   calldata — routes the borrowed WBTC to the attacker's own helper contract instead of performing
   a genuine swap back into the repay asset.
5. `_repayAmount = Math.min(fromToken.balanceOf(address(this)), _repayAmount)` (line 292) silently
   shrinks the recorded repayment to whatever negligible balance is left in the loan — no revert, no
   check that this bears any relation to the value just borrowed.
6. `_processRepay(...)` records the loan as repaid for the (tiny) clamped amount. The loan's
   `remainsSolvent` modifier doesn't catch this because the loan's collateral (the original 59.9
   WETH) still nominally covers its now-understated recorded debt.
7. Attacker withdraws, keeping the diverted WBTC while the loan shows a small, "repaid" position.
   A parallel `claimReward`-based vector on `TraderJoeV2ArbitrumFacet` (an unvalidated `pair`
   parameter passed to a rewarder-claim path) was also used per the writeups, though this file
   focuses primarily on the well-confirmed `swapDebtParaSwap` mechanism — see note below.
- Not a key compromise, not phishing, not off-chain — a missing value-parity check between a
  freshly-incurred debt and its claimed repayment, reachable by any account through its own,
  legitimately-owned loan instance.

## Vulnerable code
- file:line — `hacks/deltaprime/scan/AssetsOperationsFacet.sol:269-297` (`swapDebtParaSwap`,
  specifically the absence of any USD-value-parity check between `_repayAmount` and
  `_borrowAmount` before/after the attacker-controlled `PARA_ROUTER.call`)
- pattern — borrow-then-arbitrary-external-call-then-clamp-repayment: the function borrows real
  value first, lets attacker-supplied calldata execute an uncontrolled external call, then silently
  reduces the recorded repayment obligation to match whatever's left, instead of requiring the
  swap's output to be verified against the amount borrowed
- secondary/less-confirmed vector — `claimReward` on `TraderJoeV2ArbitrumFacet` accepting an
  unvalidated `pair`/`ids` parameter per third-party writeups (SolidityScan, QuillAudits); the
  exact pre-incident code for this second function wasn't independently reconstructed with the same
  confidence as `swapDebtParaSwap` above, since the current on-chain `claimReward(ILBPair,uint256[])`
  (TraderJoeV2Facet.sol) doesn't obviously match the "excessive reward payout" description on its
  own — flagging this honestly rather than asserting a location we haven't verified as precisely

## Sources
- technical writeups: SolidityScan — https://blog.solidityscan.com/deltaprime-hack-analysis-44edb9b22567 ;
  Verichains — https://blog.verichains.io/p/deltaprime-exploit-analysis ;
  QuillAudits — https://quillaudits.medium.com/decoding-deltaprimedefis-4-75-million-exploit-838c46e4daf8 ;
  Halborn — https://www.halborn.com/blog/post/explained-the-deltaprime-hack-november-2024 ;
  CertiK — https://www.certik.com/blog/deltaprime-incident-analysis ;
  Three Sigma — https://threesigma.xyz/blog/exploit/deltaprime-defi-exploit-avalanche-arbitrum-hack
- official post-mortem: https://medium.com/@DeltaPrimeDefi/deltaprime-post-mortem-reimbursement-plan-07-12-2024-2d654912715b
- on-chain: exploit tx
  `0x6a2f989b5493b52ffc078d0a59a3bf9727d134b403aa6e0bf309fd513a728f7f`, block 273278742 (Arbitrum),
  confirmed success via `cast receipt`; pre-incident facet address confirmed via `DiamondCut` event
  archaeology (block 229807814 REPLACE, no later replacement before the incident)
- ground-truth source: Arbiscan, verified `AssetsOperationsArbitrumFacet` at
  `0xCA60C5D2ee1F9C79C92A9D5831DC22cCc291b5f5` — the actual pre-incident facet, confirmed live at
  incident time via on-chain event history, not a reconstruction
