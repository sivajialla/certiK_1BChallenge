# meter-bridge (Meter Passport Bridge — WETH handler deposit-validation bypass)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum (Meter's Passport bridge is a ChainBridge fork spanning multiple chains;
  Ethereum was the leg actually hit by this exploit tx)
- contract hit: `Bridge` (dispatcher) — `0xa2A22B46B8df38cd7C55E6bf32Ea5a32637Cf2b1` — dispatches to
  a per-resourceID `ERC20Handler` — `0xde4fC7C3C5E7bE3F16506FcC790a8D93f8Ca0b40` (the WETH handler,
  found by querying `_resourceIDToHandlerAddress` for the WETH resourceID used in the exploit tx).
  Neither is a proxy.
- exploit tx (first of several): `0x2d3987963b77159cfe4f820532d729b0364c7f05511f23547765c75b110b629c`,
  block **14146530**, status success (confirmed via `cast receipt`); a second, larger deposit at
  block 14146589 followed the same pattern
- attacker EOA: `0x8d3d13cac607B7297Ff61A5E1E71072758AF4D01` ("Meter Passport Bridge Exploiter"
  per Etherscan's own label) — subsequently drained WETH via direct transfers (blocks 14146842,
  14146923) and laundered through Tornado Cash
- implementation live at incident vs. today: both contracts are **not upgradeable**; live source is
  the exact exploited code (Meter's fix was operational — pausing/reconfiguring the bridge — not an
  in-place contract patch)
- recovered by:
  1. found the exploiter EOA from third-party writeups, pulled its Etherscan tx list directly via
     the Etherscan V2 API, and spotted the exact `deposit(uint8,bytes32,bytes)` calls matching the
     reported attack pattern (calling the *generic* `deposit`, not `depositETH`)
  2. decoded the exploit tx's calldata with `cast decode-calldata` to recover the `resourceID`
     (which embeds the WETH token address, a common ChainBridge convention) and the forged `amount`
  3. queried `Bridge._resourceIDToHandlerAddress(resourceID)` directly on-chain via `cast call` at
     the pre-incident block to find the exact `ERC20Handler` instance responsible for WETH
  4. both `Bridge` and `ERC20Handler` are verified on Etherscan (2022-era single-file flattened
     bundles) — pulled directly, no reconstruction needed

## Claim form fields
- Protocol / project: Meter (Meter Passport Bridge)
- Amount lost (digits only): 4400000 (Meter's own direct bridge loss; a further ~$3.3M was lost
  separately by Hundred Finance, a third-party lending protocol that had listed the fraudulently
  minted destination-chain tokens as collateral — that is a downstream consequence on a *different*
  protocol's contracts, not part of this claim, per rule 01/04's one-incident-one-hack framing)
- Root cause: two contracts, one shared assumption. `Bridge.depositETH` (scan/Bridge.sol:505-532)
  is the intended entry point for wrapped-native deposits: it validates
  `amount == msg.value - fee` (an assembly-decoded `amount` from calldata checked against actual
  ETH sent), wraps the ETH into WETH, and **transfers that real WETH to the handler** before calling
  `handler.deposit(...)`. `Bridge.deposit` (scan/Bridge.sol:480-503) is the *generic* entry point
  used for ordinary ERC20 tokens — it does no such pre-transfer, relying entirely on the handler's
  own `deposit` function to pull/verify funds (normally via `transferFrom`). But nothing in `Bridge`
  restricts which `resourceID` can be passed to the generic `deposit` — the WETH resourceID works
  there too. `ERC20Handler.deposit` (scan/ERC20Handler.sol:474-501) contains an explicit skip:
  `if (tokenAddress != _wtokenAddress) { ...lock or burn... }` — for the WETH resourceID this
  condition is false, so **no lock, no burn, no transferFrom, nothing** happens; the code comment
  literally says "ether case, the weth already in handler, do nothing" (line 503), an assumption
  that's only true when reached via `depositETH`. Calling `Bridge.deposit` directly with the WETH
  resourceID reaches this same skip-branch with zero funds ever transferred, and the handler records
  a `DepositRecord` with an attacker-chosen `amount` anyway — which the bridge relayers then honor,
  minting real value on the destination chain against nothing.
- Smart contract bug? Yes
- Scan ID: `c7fd103e-eb8a-5a6f-8525-ea6b54f86cb2` (Max)
- Tier: Max
- Finding title (verbatim): Plain WETH Deposits Mint Unbacked Cross-Chain Claims and Drain
  Destination Reserves
- Why this finding is the bug: The finding names the exact mechanism — `Bridge.deposit` is
  permissionless and accepts any resourceID (including WETH's) with no value pre-transfer, while
  `ERC20Handler.deposit`'s `if (tokenAddress != _wtokenAddress)` guard skips locking/burning for
  WETH, assuming (only true via `depositETH`) that WETH was already transferred. Its "unbacked
  payout" attack-path PoC — pay only the flat fee, encode an arbitrary WETH amount, let the
  destination-side proposal pay it out via `IWETH.withdraw`/`safeTransferETH` from the shared
  reserve — matches the real, on-chain-confirmed attack exactly.

## AI Auditor scan log

### Max — 2026-08-18 — CAUGHT
- Task ID: `c7fd103e-eb8a-5a6f-8525-ea6b54f86cb2`
- 24 findings returned across `Bridge.sol` (1-7) and `ERC20Handler.sol` (8-24):
  - **Finding 3 [Major] Plain WETH Deposits Mint Unbacked Cross-Chain Claims and Drain Destination
    Reserves** (Bridge.sol:480-492 / ERC20Handler.sol:474-521) — **this is the exploited bug.**
    Names `Bridge.deposit`'s missing value pre-transfer and `ERC20Handler.deposit`'s WETH skip
    branch exactly; PoC matches the real attack step-for-step.
  - Finding 6 [Critical] Non-Canonical Calldata Offsets Enable Unbacked WETH Deposit Records — a
    related but different, more exotic mechanism (manipulating ABI dynamic-bytes offsets so
    `depositETH`'s value check and the handler's decoded amount diverge) rather than simply calling
    `deposit()` directly, which is what actually happened.
  - Findings 1, 2, 5, 7 — governance/quorum risks around `adminSetResource`, relayer threshold
    changes, and `cancelProposal` — real design questions, unrelated to the exploited path.
  - Findings 8-21 — a large cluster of fee-on-transfer/rebasing-token accounting findings
    (`lockERC20`/`releaseERC20` not measuring balance deltas) — a genuine, distinct bug class, not
    what was exploited (Meter's WETH isn't fee-on-transfer).
  - Findings 22, 24 — `fundERC20`'s missing access control (permissionless allowance drain) — real
    but different from the exploited deposit-path bug; Finding 22 does connect it *to* the WETH
    skip-branch as one possible funding source, but the actual historical attack didn't need
    `fundERC20` at all (the handler already held real WETH from legitimate `depositETH` users).
  - Finding 23 — destination-chain WETH reserve availability/liquidity-management gap — real
    operational risk, not the exploited bug.
- Conclusion: Max caught it. Finding 3 is the claim.

## Attack walkthrough
1. Attacker identifies that `Bridge.deposit(destinationChainID, resourceID, data)` — the generic,
   ERC20-oriented deposit function — has no restriction on which `resourceID` it accepts, including
   the WETH resourceID that's meant to only ever be reached via the dedicated `depositETH` path.
2. Attacker calls `Bridge.deposit()` directly, passing the WETH `resourceID` and a `data` payload
   whose embedded `amount` field is a large, arbitrary value (287.96 WETH-equivalent in one of the
   observed transactions) — while sending only the tiny bridge `fee` as `msg.value` (this function
   only checks `msg.value == fee`, unlike `depositETH`'s `amount == msg.value - fee` check).
3. `Bridge.deposit()` forwards the call to `ERC20Handler.deposit(...)` with the attacker's
   resourceID, depositNonce, and forged `amount`.
4. `ERC20Handler.deposit()` checks `if (tokenAddress != _wtokenAddress)` — false for the WETH
   resourceID — so the lock/burn/transfer branch is skipped entirely. No real WETH is pulled from
   the attacker. The handler nonetheless records a `DepositRecord` with the forged `amount` as if a
   real deposit had occurred.
5. Off-chain bridge relayers, watching for `Deposit` events and reading `_depositRecords`, see a
   seemingly-legitimate deposit and mint the corresponding wrapped assets on the destination chain
   (Moonriver/BSC) — value that was never actually locked on Ethereum.
6. Attacker repeats across multiple transactions and drains real WETH reserves held by the handler
   (from *other* users' legitimate `depositETH` deposits) by later withdrawing/bridging back,
   netting ~$4.4M; downstream, Hundred Finance separately lost ~$3.3M after accepting the
   fraudulently-minted tokens as collateral.
- Not a key compromise, not phishing, not off-chain — a missing input/state validation in a public
  bridge deposit function, reachable by anyone, that let a shared trust assumption between two
  functions be violated by simply calling the "wrong" (but entirely public) entry point.

## Vulnerable code
- file:line — `hacks/meter-bridge/scan/Bridge.sol:480-503` (`deposit`, the generic entry point with
  no value pre-transfer or resourceID restriction) and
  `hacks/meter-bridge/scan/ERC20Handler.sol:474-501` (`deposit`, specifically the
  `if (tokenAddress != _wtokenAddress)` skip at line 503 that assumes funds were already
  transferred — an assumption only `depositETH` actually guarantees)
- pattern — cross-function trust assumption: one code path (`depositETH`) validates and pre-funds a
  precondition that a second, differently-reachable code path (`deposit` → handler) blindly
  assumes was already satisfied, with no shared enforcement mechanism between them

## Sources
- technical writeups: Halborn — https://www.halborn.com/blog/post/explained-the-meter-io-hack-february-2022 ;
  ChainSafe — https://blog.chainsafe.io/breaking-down-the-meter-hack/ ;
  Ken Alabs — https://medium.com/@alabs.ken/analysis-of-the-meter-bridge-exploit-2b51ffe89b6c
- news coverage: Cointelegraph — https://cointelegraph.com/news/latest-defi-bridge-exploit-results-in-4-4m-losses-for-meter
- on-chain: exploit tx
  `0x2d3987963b77159cfe4f820532d729b0364c7f05511f23547765c75b110b629c`, block 14146530, confirmed
  success via `cast receipt`; handler address confirmed via `cast call` on
  `Bridge._resourceIDToHandlerAddress`
- ground-truth source: Etherscan, verified `Bridge` at `0xa2A22B46B8df38cd7C55E6bf32Ea5a32637Cf2b1`
  and `ERC20Handler` at `0xde4fC7C3C5E7bE3F16506FcC790a8D93f8Ca0b40` — no reconstruction needed,
  neither upgradeable, code unchanged since deployment
