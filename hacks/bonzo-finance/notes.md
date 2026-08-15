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
- Scan ID: <pending>
- Tier: Lite
- Finding title (verbatim): <fill in once a finding names requireHashVerified_V2's missing
  zero-point check>
- Why this finding is the bug: The finding must name the missing check in
  `requireHashVerified_V2` before it trusts `BLS.verifySingle`'s result — specifically, that
  neither the supplied `signature` nor the stored `committee_public_key[committee_id]` is
  validated as non-zero/non-identity before the pairing check. This is the exact one-function
  code path the attacker's forged oracle-update transaction went through, and it's the only
  function the real fix commit touched.

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
