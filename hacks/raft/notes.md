# raft (Raft Protocol — ERC20Indexable storedIndex manipulation)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum
- contract hit: `InterestRatePositionManager` at `0x9AB6b21cDF116f611110b048987E58894786C244`.
  Not a proxy. Inherits `PositionManager`/`ERC20RMinter`, which in turn manages
  `ERC20Indexable`-family collateral/debt tokens (the "rcbETH"-style indexable wrapper the
  writeups refer to) — the actual vulnerable logic (`setIndex`/`mint`/`balanceOf`) lives in the
  `ERC20Indexable` base contract, present in this same deployed bytecode.
- exploit tx: `0xfeedbf51b4e2338e38171f6e19501327294ab1907ab44cfd2d7e7336c975ace7`, block
  **18543486**, status success (confirmed via `cast receipt`)
- attacker EOA: `0xc1f2b71A502B551a65Eee9C96318aFdD5fd439fA`
- implementation live at incident vs. today: **identical**. Not upgradeable; Raft's response was
  operational (pausing, later shutting the protocol down entirely) rather than patching this
  address. Live verified source genuinely is the exploited code.
- recovered by: `cast source --chain mainnet 0x9AB6b21cDF116f611110b048987E58894786C244` —
  verified directly, `ContractName: InterestRatePositionManager`, full flattened single-file
  bundle (4,304 lines covering the whole protocol: `ERC20Indexable`, `RToken`, `PositionManager`,
  `InterestRateDebtToken`, `InterestRatePositionManager`, plus vendored OZ-style base classes), no
  reconstruction needed

## Claim form fields
- Protocol / project: Raft Protocol (`InterestRatePositionManager` / `ERC20Indexable`)
- Amount lost (digits only): 3300000 (realized/net loss figure most consistently reported; the
  attacker minted ~6.7M unbacked R total but destroyed most of the drained collateral by mistake,
  sending 1,570 of 1,577 stolen ETH to a burn address — net economic damage to the protocol/R
  peg is reported at $3.3M by most contemporaneous sources)
- Root cause: `ERC20Indexable.setIndex` (scan/InterestRatePositionManager.sol, `setIndex`)
  computes `newIndex = backingAmount.divUp(supply)`, where `supply` is the token's *internal*
  share-count (`ERC20.totalSupply()`, pre-index) and `backingAmount` is the real collateral amount
  passed in by the position manager. If `supply` is extremely small (e.g. a freshly-created
  position holding on the order of 1 wei of internal shares) while `backingAmount` is made large
  (funded via a flash loan), `storedIndex` becomes astronomically inflated. Both `balanceOf`
  (`ERC20.balanceOf(account).mulDown(currentIndex())`) and `totalSupply()` are defined as internal
  shares multiplied by this index — so a position holding a negligible number of internal shares
  can be made to report an enormous nominal collateral balance. Combined with `mint`'s
  `amount.divUp(storedIndex)` rounding (which mints new shares in proportion to the *current*,
  attacker-inflated index), the attacker could mint and later liquidate positions to extract R
  stablecoin far in excess of any real collateral actually backing it.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name `ERC20Indexable.setIndex`'s
  `backingAmount.divUp(supply)` calculation as exploitable when `supply` (internal share count) is
  made disproportionately small relative to `backingAmount` — letting `storedIndex` (and therefore
  every share-holder's `balanceOf`) be inflated by orders of magnitude through a single
  flash-loan-funded transaction. This is the exact "precision calculation flaw" / "storedIndex
  manipulation" mechanism named across every independent writeup (ImmuneBytes, MetaTrust, Olympix,
  Sentinel Protocol).

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker flash-loans 6,000 cbETH from Aave.
2. Attacker sets up a position/scenario where the relevant `ERC20Indexable` collateral token's
   internal share supply is minimal (on the order of 1 wei) — achieved by pre-creating a position
   and manipulating it into a state with negligible recorded internal shares.
3. Attacker transfers a large amount of real cbETH (~6,001 cbETH total, per the flash-loaned
   funds) into the position manager, triggering `setIndex(backingAmount)` with a huge
   `backingAmount` against the tiny `supply` — `storedIndex` is recalculated as
   `backingAmount.divUp(supply)`, inflating it to thousands of times its intended value.
2. With `storedIndex` now massively inflated, `balanceOf`/`totalSupply` for the manipulated token
   report grossly overstated collateral value for a trivial number of internal shares.
5. Attacker mints R stablecoin against this artificially inflated collateral valuation and/or
   liquidates the pre-created position, extracting far more R than any real collateral backs —
   ~6.7M R minted/extracted in total.
6. Attacker sells/moves the extracted R, causing R to depeg ~50% from its intended $1 peg.
7. In an unrelated operational mistake, the attacker then sent the bulk of the drained ETH
   (1,570 of 1,577 ETH) to a burn address, destroying most of what was stolen — leaving net
   realized damage around $3.3M despite the much larger nominal amount minted.
- Not a key compromise, not phishing, not off-chain — a rounding/index-recalculation bug in a
  public collateral-accounting function, reachable by anyone who can fund a position and trigger
  an index update while the token's internal share supply is small.

## Vulnerable code
- file:line — `hacks/raft/scan/InterestRatePositionManager.sol`, `ERC20Indexable.setIndex`
  (`newIndex = backingAmount.divUp(supply)`) and the paired `balanceOf`/`totalSupply` functions
  that multiply internal shares by this attacker-influenceable index
- pattern — index/share-ratio recalculation using `newValue.divUp(currentSupply)` with no floor on
  `currentSupply` or bound on how much a single funding operation can move the index — classic
  "inflate the exchange rate via a near-zero-supply edge case" vault/index-token vulnerability,
  in the same general family as ERC4626 first-depositor inflation attacks

## Sources
- technical writeups: ImmuneBytes — https://immunebytes.com/blog/raft-protocol-exploit-nov-10-2023-detailed-analysis/ ;
  MetaTrust — https://metatrust.io/blogs/post/when-hacking-goes-haywire-rafts-1570-eth-loss-takes-a-cosmic-detour-to-the-black-hole ;
  Olympix — https://olympixai.medium.com/ledger-heco-kronos-raft-exploits-in-the-supply-chain-keys-and-math-959210847a21 ;
  Sentinel Protocol — https://medium.com/sentinel-protocol/the-raft-protocol-exploit-a-hackers-miscalculation-leads-to-major-loss-d76c64e6e16b
- news coverage: CoinDesk — https://www.coindesk.com/tech/2023/11/10/defi-platform-raft-suffers-33m-exploit-but-hacker-likely-takes-a-loss-on-the-attack ;
  web3isgoinggreat — https://www.web3isgoinggreat.com/?id=raft-hack
- on-chain: exploit tx
  `0xfeedbf51b4e2338e38171f6e19501327294ab1907ab44cfd2d7e7336c975ace7`, block 18543486, confirmed
  success via `cast receipt`
- ground-truth source: Etherscan, verified `InterestRatePositionManager` at
  `0x9AB6b21cDF116f611110b048987E58894786C244` — no reconstruction needed, not upgradeable, code
  unchanged since deployment
