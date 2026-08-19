# mango-markets (Mango Markets V3 — unrealized-PnL-as-collateral oracle manipulation)

## Recovery (rule 01 — goes in the claim)
- chain: Solana (first non-EVM recovery in this repo — AI Auditor supports non-Solidity languages,
  confirmed before starting this recovery)
- contract hit: Mango Markets V3 on-chain program, `mv3ekLzLbnVPNxjSKvqBpU3ZeZXPQdEC3bp5MDEBG68`
  (Solana mainnet). Not upgradeable in the EVM-proxy sense, but Solana programs *can* be upgraded
  in place by their upgrade authority — irrelevant here since Mango V3 was never patched after the
  incident (see below).
- incident date: October 11, 2022. Attacker: Avraham Eisenberg — later criminally convicted of
  fraud and market manipulation for this exact incident (SEC also brought a parallel enforcement
  action), making the root cause and attribution about as well-documented as any hack gets.
- implementation live at incident vs. today: **unchanged for the exploited files**. Confirmed via
  GitHub commit history on `blockworks-foundation/mango-v3` (the official, still-public repo): the
  last commit touching `program/src/state.rs` before the incident was `43963f0f8a`
  (2022-09-08), and **no commit ever touched this file again** afterward — Mango's response was to
  negotiate a fund return with the attacker and eventually deprecate V3 entirely in favor of a new
  V4 architecture, not patch this program in place. The pre-incident commit is therefore also the
  permanent, final state of this code.
- recovered by: GitHub commit-history archaeology (same method used for butter-bridge) — since
  Solana doesn't have an Etherscan-style "verified source" explorer service in the same way, the
  official GitHub repo (still public, unarchived) is the ground-truth source. Queried commit
  history for `program/src/state.rs` bounded to Sept-Nov 2022, confirmed the file was last touched
  well before the incident and never touched after, then pulled `state.rs`, `oracle.rs`,
  `error.rs`, and the relevant sections of `processor.rs` directly from commit `43963f0f8a`.

## Claim form fields
- Protocol / project: Mango Markets V3
- Amount lost (digits only): 50000000 (capped at the $50M/hack scoring limit; real total loss was
  ~$116M per the SEC's own charging documents, ~$110M per contemporaneous reporting)
- Root cause: `PerpAccount::get_val` (scan/state.rs, in the `impl PerpAccount` block) computes an
  account's perpetual-futures position value by multiplying its raw base position directly by
  `price` — an oracle price passed in with **no manipulation-resistance safeguard**. That `price`
  itself comes from `read_oracle` (scan/processor_extract.rs), which reads Pyth's aggregate price
  (`price_account.agg.price`) directly and applies exactly one filter: rejecting prices where
  Pyth's own reported confidence interval is too wide (`conf > PYTH_CONF_FILTER`) — a data-quality
  check, not a manipulation-resistance one. There is no price-impact cap, no TWAP smoothing, no
  check on position size relative to the underlying market's actual liquidity/depth, and no limit
  on how much of an account's collateral value can come from a single, thinly-traded asset's
  unrealized PnL. `get_val`'s output feeds `get_quote_position` and ultimately
  `HealthCache`/`MangoAccount::get_health` (scan/state.rs), which determines borrowing power used
  directly by `withdraw`/`withdraw2` (scan/processor_extract.rs) to release real assets from the
  protocol's treasury. An attacker who can move a thinly-traded market's price via real (if
  economically self-referential) trades can therefore inflate their own account's computed health
  by an arbitrary amount and borrow real assets against it.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name the missing manipulation-resistance safeguard
  in the oracle-price-to-collateral-value pipeline — specifically, that `get_val`/`get_health`
  trust a spot oracle price with no bound on how much borrowing power a single, thin-liquidity
  market's price can generate, and that `read_oracle`'s only filter is a Pyth confidence-interval
  check rather than a manipulation/liquidity-aware safeguard. This is the exact mechanism
  documented by CoinTelegraph, Solidus Labs' order-book analysis, and the SEC's own charging
  documents, and matches the real attack: real trades on real (thin) markets pushed MNGO's price
  >1000%, generating >$100M in computed unrealized PnL used as withdrawable collateral.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker (Avraham Eisenberg) funds two separate Mango accounts with ~$5M USDC each.
2. Account A opens a large short position in MNGO-PERP; Account B opens the exact opposite (long)
   position of the same size, using leverage — Mango's own matching engine pairs these against each
   other, so no external counterparty is needed for the position itself.
3. Attacker then buys real MNGO spot tokens across the (thin-liquidity) external markets that feed
   into Pyth's price aggregate for MNGO, spending a few million dollars of real capital to push the
   *aggregate reported price* of MNGO up over 1,000% in a short window.
4. Mango's oracle (`read_oracle`) picks up this inflated price. Because Pyth's confidence interval
   stays narrow (the manipulated price genuinely was the consistent price across the — thin —
   aggregated sources at that moment), the one existing filter doesn't reject it.
5. Account B's long MNGO-PERP position, now valued at the inflated price via `get_val`, shows over
   $100M in unrealized profit. `get_health` computes Account B's borrowing power directly from this
   figure — there's no separate check on whether that "profit" reflects value the protocol actually
   has, or whether it's concentrated entirely in one thinly-traded, self-referential position.
6. Attacker calls `withdraw`/`withdraw2` from Account B, draining real assets (BTC, SOL, USDC, and
   others) from Mango's shared treasury — funds legitimately deposited by other users — up to the
   fabricated borrowing limit.
7. Total: ~$116M extracted (per SEC charging documents), later partially returned after negotiation
   (attacker kept ~$47M as a "bug bounty," in his own framing — Mango's governance token holders
   voted to accept this in lieu of pursuing recovery through other means at the time; Eisenberg was
   subsequently criminally convicted).
- Not a key compromise, not phishing, not off-chain — a missing safeguard in the on-chain
  collateral-valuation logic that let a self-referential, oracle-derived unrealized-profit figure
  on a thinly-traded asset be treated as fully legitimate, withdrawable collateral.

## Vulnerable code
- file:line — `hacks/mango-markets/scan/state.rs` (`PerpAccount::get_val`, `get_quote_position`,
  and `HealthCache`/`MangoAccount::get_health` — the chain that turns an oracle price into
  borrowing power with no manipulation-resistance check) and
  `hacks/mango-markets/scan/processor_extract.rs` (`read_oracle`, whose only safeguard is a Pyth
  confidence-interval filter, and `withdraw`/`withdraw2`, which release real assets based on the
  resulting computed health)
- pattern — missing manipulation-resistance / liquidity-awareness check before trusting an oracle
  price (or a value derived from it) as collateral — the same general bug class as
  bonzo-finance's missing BLS zero-point check and kyberswap-elastic's rounding bug: a value that
  should have been validated against a wider safety margin before being trusted for a
  high-stakes decision (minting, borrowing, or in this case, withdrawing real treasury assets)

## Sources
- technical/legal documentation: SEC press release (charging documents) —
  https://www.sec.gov/newsroom/press-releases/2023-13 ; CoinDesk (conviction coverage) —
  https://www.coindesk.com/policy/2024/04/18/mango-markets-exploiter-avi-eisenberg-found-guilty-of-fraud-and-manipulation ;
  Solidus Labs order-book analysis — https://www.soliduslabs.com/post/mango-hack ;
  Cointelegraph — https://cointelegraph.com/news/how-low-liquidity-led-to-mango-markets-losing-over-116-million
- on-chain: program ID `mv3ekLzLbnVPNxjSKvqBpU3ZeZXPQdEC3bp5MDEBG68` (Solana mainnet); incident
  date October 11, 2022
- ground-truth source: GitHub, `blockworks-foundation/mango-v3` (official, still-public repo),
  commit `43963f0f8a` (2022-09-08) — the last commit touching `program/src/state.rs` before the
  incident, and confirmed (via commit-history query bounded through Nov 2022 and beyond) never
  patched afterward
