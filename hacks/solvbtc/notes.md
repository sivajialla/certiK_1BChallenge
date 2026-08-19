# solvbtc (Solv Protocol — BitcoinReserveOffering double-mint reentrancy)

## Recovery (rule 01 — goes in the claim)
- chain: Ethereum
- contract hit: `BitcoinReserveOffering` (BRO vault) — proxy (`BeaconProxy`) at
  `0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869`, implementation at
  `0x15f7c1ac69f0c102e4f390e45306bd917f21cfcf`
- exploit tx: `0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d`, block
  **24592074**, status success (confirmed via `cast receipt`)
- attacker EOA: `0xA407fE273DB74184898CB56D2cb685615e1C0D6e`
- implementation live at incident vs. today: **identical** — confirmed the implementation address
  resolves the same way currently; Solv's response was operational (covering affected users,
  requesting fund return with a bounty) rather than an in-place patch of this exact deployment
- recovered by: `cast source --chain mainnet 0x15f7c1ac69f0c102e4f390e45306bd917f21cfcf` — verified
  directly, `ContractName: BitcoinReserveOffering`, no reconstruction needed. Genuinely small
  contract (204 lines) — no fix-commit archaeology or large-bundle trimming required.

## Claim form fields
- Protocol / project: Solv Protocol — BitcoinReserveOffering (BRO vault)
- Amount lost (digits only): 2700000
- Root cause: `mint()` (scan/BitcoinReserveOffering.sol:139-156) is guarded by `nonReentrant`, but
  when a user deposits their *entire* SFT balance (`amount_ == sftBalance`), it calls
  `ERC3525TransferHelper.doSafeTransferIn(...)`, which performs `safeTransferFrom` on the
  underlying ERC-3525 token. Because `BitcoinReserveOffering` itself is the transfer recipient,
  this triggers a callback into its own `onERC721Received` (scan/BitcoinReserveOffering.sol:111-134)
  — a function with **no `nonReentrant` guard of its own**. Inside that callback,
  `_mint(from_, value)` (line ~131) credits the depositor with BRO tokens for the SFT's value.
  Execution then returns to the still-in-progress outer `mint()` call, which — unaware the deposit
  was already credited inside the callback — reaches its own `_mint(msg.sender, value)` at the end
  (line ~155) and mints the *same* value a second time. `mint()`'s own `nonReentrant` modifier only
  prevents re-entering `mint()` itself; it does nothing to stop the *self-triggered* callback path
  through `onERC721Received`, which is a completely separate, unprotected entry point that reaches
  the same `_mint` logic.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name the missing `nonReentrant` guard on
  `onERC721Received` (and/or `onERC3525Received`) combined with `mint()`'s full-balance deposit
  path (`doSafeTransferIn`) triggering that callback on the contract itself — the exact mechanism
  by which a single `mint()` call credits the depositor twice for the same SFT value: once inside
  the transfer callback, once in the outer function's continuation. This matches every independent
  writeup (Olympix, DarkNavy, Verichains, Halborn, QuillAudits) and the real attack, which looped
  this 22 times to inflate 135 BRO into ~567.8M BRO.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker acquires or holds a small amount (135.36 BRO-equivalent) of the underlying ERC-3525
   SFT representing Bitcoin-backed reserve value.
2. Attacker calls `mint(sftId_, amount_)` with `amount_` equal to the SFT's full balance — the
   condition that routes through `doSafeTransferIn` rather than a partial `doTransferIn`.
3. `doSafeTransferIn` calls `safeTransferFrom` on the ERC-3525 token, transferring the SFT to
   `BitcoinReserveOffering`. Because the recipient is a contract, this triggers
   `onERC721Received` as a callback — landing back inside `BitcoinReserveOffering` itself, mid-way
   through the original `mint()` call.
4. `onERC721Received` runs its own logic and calls `_mint(from_, value)`, crediting the attacker
   with BRO tokens for the deposit — the first mint.
5. The callback returns, the SFT transfer completes, and control resumes in the outer `mint()`
   function, which proceeds to its own `_mint(msg.sender, value)` call — the second mint, for the
   identical value, since `mint()` has no way to know the callback already credited it.
6. Attacker repeats this cycle 22 times (each cycle compounding on the inflated balance), turning
   ~135.36 BRO into ~567,758,681 BRO.
7. Attacker redeems/burns the inflated BRO for ~38.05 real SolvBTC, swaps it through Uniswap V3 to
   ~37.99 WBTC, then to ~1,211 ETH (~$2.7M).
- Not a key compromise, not phishing, not off-chain — a reentrancy gap between a `nonReentrant`-guarded
  entry point and an *unguarded* self-triggered callback that reaches the same minting logic,
  reachable by anyone who can call the vault's public deposit function.

## Vulnerable code
- file:line — `hacks/solvbtc/scan/BitcoinReserveOffering.sol:111-134` (`onERC721Received`, missing
  `nonReentrant`) and `:139-156` (`mint`, whose full-balance deposit path triggers that unprotected
  callback on itself via `doSafeTransferIn` → `safeTransferFrom`)
- pattern — reentrancy via a self-directed ERC-721/ERC-3525 transfer callback: guarding the public
  entry point (`mint`) with `nonReentrant` doesn't protect against a *different*, unguarded function
  (`onERC721Received`) that the entry point's own external call triggers on the same contract,
  reaching the same state-mutating logic (`_mint`) through a second path

## Sources
- technical writeups: Olympix — https://olympixai.medium.com/the-2-7m-solv-protocol-exploit-a-reentrancy-bug-that-should-never-have-shipped-and-how-olympix-617e4703a531 ;
  DarkNavy — https://www.darknavy.org/web3/exploits/solv-bro-double-mint/ ;
  Verichains — https://blog.verichains.io/p/solv-protocol-hack-analysis ;
  Halborn — https://www.halborn.com/blog/post/explained-the-solv-hack-march-2026 ;
  QuillAudits — https://www.quillaudits.com/blog/hack-analysis/solv-protocol-exploit
- news coverage: crypto.news — https://crypto.news/solv-protocol-exploit-drains-2-7m-in-solvbtc-10-bounty-offered/
- on-chain: exploit tx
  `0x44e637c7d85190d376a52d89ca75f2d208089bb02b7c4708ad2aaae3a97a958d`, block 24592074, confirmed
  success via `cast receipt`
- ground-truth source: Etherscan, verified `BitcoinReserveOffering` implementation at
  `0x15f7c1ac69f0c102e4f390e45306bd917f21cfcf` (proxy at
  `0x014e6f6ba7a9f4c9a51a0aa3189b5c0a21006869`) — no reconstruction needed
