# bonzo-finance (Bonzo Lend — Supra oracle verifier, on Hedera)

## Recovery (rule 01 — goes in the claim)
- chain: Hedera mainnet (EVM chainId 295 — not covered by `Recover.sh`'s existing chain list or
  Etherscan V2; used the Hedera mirror node + Sourcify directly instead, see below)
- contract hit: Supra's `SupraSValueFeedVerifier` — proxy `0.0.4323006` /
  `0x2fa6dbfe4291136cf272e1a3294362b6651e8517` (EIP-1967 UUPS)
- also involved (not buggy themselves, but part of the call path):
  - Supra pull-oracle: proxy `0.0.4323024` / `0x41ab2059baa4b73e9a3f55d30dff27179e0ea181`,
    implementation `0xef8a81a6f1861c214bcc2464a765e65334b424c9` (verified, `src/SupraOraclePull_V2.sol`
    — pulled into `context/pull-oracle/` for reference on how `requireHashVerified_V2` is called)
  - Bonzo LendingPool: `0.0.7308459` / `0x236897c518996163e7b313ad21d1c9fcc7ba1afc` — correctly
    trusted the (forged) feed; not itself buggy
- incident tx (forged oracle update): `0xd50c55e24eb8483ec55bf74e84fc9853d0f0fe36f64abdb812a2d9afa2a10a60`
- incident block: 97504678 (2026-07-11), confirmed via `eth_getTransactionReceipt` on Hedera's
  Hashio EVM RPC (status success)
- implementation live at incident: `0x63e0a27bc77ca817c89f5231d568c4e58100fbf0`
- implementation today (patched): `0x02ebd8829b944c48e6bff15fdec04f7d51b70526`
- recovered by:
  1. resolved the verifier proxy's EIP-1967 implementation slot at block 97504677 (pre-incident)
     and latest, via `cast storage` against Hedera's public Hashio RPC (`mainnet.hashio.io/api`) —
     archive queries work fine on this endpoint, unlike Monad's public RPC
  2. Sourcify (not Etherscan — Hedera isn't on Etherscan V2) had **both** implementations verified:
     pre-incident (`0x63e0a27b...`, verified 2026-03-31, i.e. verified independently of and prior
     to the incident) and patched (`0x02ebd882...`, verified 2026-07-13, ~2 days after) — full
     ground-truth source for both, no fix-commit archaeology or reconstruction needed
  3. `diff -ru src-pre src-current` isolates the entire fix to one file,
     `src/SupraSValueFeedVerifier.sol`, confirming it's the single suspect file
- note: a third-party writeup (sanbir/evm-hack-registry,
  `2026-07-BonzoLend_exp/BonzoLend_exp.md`) had already investigated this incident and got the
  addresses and mechanism exactly right, but had marked its own vulnerable-code copy as a
  "RECONSTRUCTED teaching model" since they couldn't get Hedera into a Foundry fork. We didn't
  need it — Sourcify had the real, verified pre-incident source directly.

## Claim form fields
- Protocol / project: Bonzo Lend (Hedera) — via Supra's `SupraSValueFeedVerifier` oracle contract
- Amount lost (digits only): 9050000
- Root cause: `SupraSValueFeedVerifier.requireHashVerified_V2` (scan/SupraSValueFeedVerifier.sol,
  around line 315) passed the caller-supplied BLS `signature` and the stored
  `committee_public_key[committee_id]` straight into `BLS.verifySingle` → a BN254 pairing
  precompile call, with no check that either was non-zero first. The pairing product of two
  identity (all-zero) points is mathematically `1`, so the precompile returns `true` for a
  genuinely-empty signature checked against an unregistered (all-zero, default-value) committee
  public key — the verifier accepted this as a valid signature instead of rejecting it outright.
- Smart contract bug? Yes
- Scan ID: <pending — Lite missed, see scan log below; run Max next>
- Tier: Max (Lite already run and missed, see below)
- Finding title (verbatim): <fill in once a finding names requireHashVerified_V2's missing
  zero-point check>
- Why this finding is the bug: The finding must name the missing check in
  `requireHashVerified_V2` before it trusts `BLS.verifySingle`'s result — specifically, that
  neither the supplied `signature` nor the stored `committee_public_key[committee_id]` is
  validated as non-zero/non-identity before the pairing check. This is the exact one-function
  code path the attacker's forged oracle-update transaction went through, and it's the only
  function the real fix commit touched.

## AI Auditor scan log

### Lite — 2026-08-15 — MISSED
- Task ID: `a7874b28-0ab5-5f48-b0ba-19ef207e61e4`
- 2 findings returned, neither touching `requireHashVerified_V2` (~line 315-330, where the fix
  added the zero-signature/zero-pubkey checks):
  1. [Major] `initialize()` never calls `__Ownable_init()`, so `owner()` stays the zero address
     forever, permanently locking all `onlyOwner` functions (line 186) — real bug, but the attack
     never called any owner-restricted function
  2. [Medium] `requireVoteVerified`'s `verifiedVotes[smrVoteHash]` cache isn't invalidated when
     `updatePublicKey` rotates the committee key, so a vote signed by a revoked key stays valid
     (205-212) — real bug, but this is the SMR/vote-consensus path (`requireHashVerified_V1`), not
     the price-update path (`requireHashVerified_V2`) the attacker actually used
- Conclusion: Lite did not surface the exploited vulnerability. Per rule 03, escalate to Max.

### Max — 2026-08-15 — MISSED (full miss, both tiers)
- Task ID: `43fc336e-3090-5334-a4f4-c12e5e4ab1ef`
- 8 findings returned, none touching `requireHashVerified_V2` (line 315+) or its missing
  zero-signature/zero-pubkey check — every finding is about the V1/vote-consensus path
  (`requireVoteVerified`, `requireHashVerified_V1`, `publicKey`), `processCluster`'s round/replay
  bookkeeping, or the broken `Ownable` init — none of it the price-update path the attacker used:
  1. [Discussion] `requireVoteVerified` hardcoded to V1, inconsistent with multi-committee design
     (205-212)
  2. [Discussion] `updatePublicKey` key rotation can freeze the round gate (262-271)
  3. [Discussion] vote hash has no chain-id/contract binding, replayable across deployments
     sharing `domain`+`publicKey` (91-99) — closest any finding gets to V2 is a passing remark
     that "V1's `bytes.concat(bytes32)` and V2's `abi.encode(bytes32)` are byte-identical," which
     is about message-encoding equivalence, not the missing zero-point check
  4. [Discussion] equal-round cluster overwrite, last-writer-wins (265-267)
  5. [Major] same broken `Ownable2Step_init()` as Lite finding 1 (186)
  6. [Discussion] unvalidated feed-storage address can brick updates (188)
  7. [Minor] write-nothing cluster can block co-committed updates via the transaction-wide replay
     guard (243-253)
  8. [Medium] `verifiedVotes` cache not invalidated on key rotation — same bug as Lite finding 2,
     re-surfaced with a fuller PoC (line 126 cited, but describes the same `requireVoteVerified`
     function at 205-212)
- Conclusion: **both Lite and Max missed the exploited vulnerability.** The real bug — no check
  that `_signature` or `committee_public_key[committee_id]` is non-zero before trusting
  `BLS.verifySingle`'s pairing result — never appears in either report, despite ground-truth
  verified source (not a reconstruction) and a real, confirmed $9.05M loss.

### Ultra — 2026-08-15 — MISSED (full miss, all three tiers)
- Task ID: `ba918112-d3e0-5994-bd2c-8894495ab6e2`
- 14 findings returned — the most thorough of the three scans, going deep on `requireVoteVerified`
  / `requireHashVerified_V1` (cache-not-invalidated-on-rotation, cross-deployment replay, no
  epoch-binding — findings 3, 4, 5, 8, 11), `processCluster`'s replay/round bookkeeping
  (whole-transaction replay guard blocking siblings, equal-round overwrites, future-timestamp
  check using the wrong field, non-price payloads accepted — findings 2, 6, 7, 9, 10, 12, 13, 14),
  and the same `Ownable` init bug as Lite/Max (finding 1). **Not one of the 14 findings mentions
  `requireHashVerified_V2` or references anywhere near line 315.** Every finding is real, and some
  (14, Medium) are thoughtfully argued — but none of them is the bug that was actually exploited.
- Conclusion: **complete miss across all three tiers — Lite, Max, and Ultra.** This is the
  strongest miss case recovered so far: ground-truth verified source (not reconstructed), a
  confirmed $9.05M real-world loss, an exact one-function root cause that's fully present and
  reachable in the scanned file, and three independent scan tiers — including the most thorough
  one available — all converge on a large, plausible-sounding set of *other* bugs while missing
  the actual one. Strong candidate to report as a miss per rule 05 ("misses are funded") rather
  than (or in addition to) pursuing further scanning — there's no fourth tier to escalate to.

## Attack walkthrough
1. Attacker (`0x9A4966152F6e10b33Cb7a37975e8619816d6a494`) deposits 250 SAUCE (a few dollars) as
   collateral into Bonzo's LendingPool — legitimate, small, just to have a borrowable position.
2. Attacker calls Supra's pull-oracle update path with a forged price update for pair 425
   (SAUCE/WHBAR): `committee_id = 2` (a committee ID whose public key was **never registered** —
   `committee_public_key[2]` reads as the Solidity default, `[0,0,0,0]`), `signature = [0, 0]`
   (the BLS identity/zero point), and a price field of `10**30`.
3. The pull-oracle forwards this to `SupraSValueFeedVerifier.requireHashVerified_V2`, which calls
   `BLS.verifySingle(signature=[0,0], pubkey=[0,0,0,0], hashToPoint(message))` → a BN254 pairing
   precompile call. The pairing equation holds trivially for identity inputs, so the precompile
   returns `true`. No check ever rejected the zero signature or zero pubkey before this point.
4. The verifier reports the forged update as verified. The pull-oracle writes SAUCE's price as
   `10**30` (~12 orders of magnitude above its real value) into on-chain storage.
5. ~8 seconds later, the attacker borrows 6.63M USDC and 34.5M WHBAR from Bonzo's LendingPool
   against their 250 SAUCE collateral, which the manipulated feed now values in the tens of
   millions of dollars.
6. Stolen funds bridged via Stargate to Arbitrum/Base/Ethereum, then to Tornado Cash. A separate
   whitehat ("Wallet B") independently exploited the same bug for ~$1M and claims to be returning
   it.
- Not a key compromise, not phishing, not off-chain — a missing input-validation check in an
  on-chain BLS signature verifier, reachable by anyone who can call the pull-oracle's public
  update function with attacker-chosen parameters.

## Vulnerable code
- file:line — `hacks/bonzo-finance/scan/SupraSValueFeedVerifier.sol` — `requireHashVerified_V2`
  (~line 315), specifically the absence of a zero-signature / zero-pubkey guard before the
  `BLS.verifySingle` pairing check
- pattern — missing validation that cryptographic verification inputs (signature, public key) are
  non-identity/non-zero before trusting a pairing-precompile result; the pairing equation is
  trivially satisfied by identity elements on both sides

## Sources
- Bonzo's own incident report: https://bonzo.finance/blog/bonzo-lend-incident-report-oracle-provider-exploit
- news coverage: https://finance.biggo.com/news/65f1e655-6ee6-4201-b7da-a385c2a561ab ;
  https://cryptobriefing.com/bonzo-lend-9m-oracle-exploit-hedera/
- on-chain: exploit tx
  `0xd50c55e24eb8483ec55bf74e84fc9853d0f0fe36f64abdb812a2d9afa2a10a60` (Hedera, block 97504678,
  confirmed success via `eth_getTransactionReceipt`)
- ground-truth source: Sourcify, chain 295 —
  pre-incident `0x63e0a27bc77ca817c89f5231d568c4e58100fbf0` (verified 2026-03-31, before the
  incident), patched `0x02ebd8829b944c48e6bff15fdec04f7d51b70526` (verified 2026-07-13, after)
- cross-reference (mechanism/addresses, not used as source of vulnerable code):
  https://github.com/sanbir/evm-hack-registry/tree/main/2026-07-BonzoLend_exp
