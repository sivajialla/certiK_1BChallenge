# drips-network (Drips Network — legacy DaiDripsHub)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum
- contract hit (proxy): 0x73043143e0a6418cc45d82d4505b096b802fd365 (ManagedDripsHubProxy /
  "DaiDripsHub", a legacy Drips Network deployment)
- proxy kind: EIP-1967 transparent/UUPS
- incident tx: 0xc38a6e2259a85ced94238a0b0a49697992f2a6b8140c28f3fd2343d3d8434130
- incident block: 25529927 (2026-07-14)
- implementation live at incident: 0x8d321e80487356c846f34456d31ce761776ef697
- implementation today: 0x8d321e80487356c846f34456d31ce761776ef697 — **unchanged**. This
  implementation was deployed at block 13799866 and was never upgraded again (no upgrade after
  the incident either) — confirmed via the proxy's full `Upgraded(address)` history (one entry
  total). Today's code genuinely is the exploited code; nothing to reconstruct from a fix commit
  this time.
- recovered by: reading the EIP-1967 implementation slot at block 25529926; source pulled
  automatically since the implementation is verified on Etherscan (flattened single-file bundle,
  `scan/Contract.sol`, containing the full inheritance chain: `Context` → `Ownable`,
  `ERC1967Upgrade`/`Proxy`/`ERC1967Proxy`/`UUPSUpgradeable` (OZ boilerplate), `DripsHub` (abstract
  base with the bug) → `ManagedDripsHub` → `ERC20DripsHub` (public `give()` entry points +
  `_transfer` override) → `DaiDripsHub` (thin DAI-specific subclass)

## Claim form fields
- Protocol / project: Drips Network — legacy DaiDripsHub deployment
- Amount lost (digits only): 24883
- Root cause: `DripsHub._give()` (scan/Contract.sol:1376-1388) calls
  `_transfer(userOrAccount.user, -int128(amt))` where `amt` is `uint128`, with no check that
  `amt <= type(uint128).max / 2` (i.e. fits in `int128`'s positive range). `int128(amt)` is a raw
  bit-pattern reinterpretation, not a range-checked cast — Solidity 0.8's overflow checks don't
  cover this explicit conversion. Passing `amt = 2**128 - B` makes `int128(amt) == -B`, so
  `-int128(amt) == B` (positive). `ERC20DripsHub._transfer` (scan/Contract.sol:2130-2145) branches
  on the sign of its `int128 amt` argument: positive means "withdraw `amt` from the reserve and
  pay the caller," negative means "pull `amt` from the caller into the hub." The crafted input
  flips `give()` from its intended "caller pays" direction into "reserve pays caller."
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: Lite
- Finding title (verbatim): <fill in once a finding names _give / _transfer's signed-conversion>
- Why this finding is the bug: The finding must name the unchecked `int128(amt)` conversion in
  `_give` (line ~1387) or the sign-branching in `_transfer` (line ~2130) — this exact pair is the
  entire vulnerable code path `give(address,uint128)` reaches, and it's the only mechanism by
  which a `give()` call can withdraw from the reserve instead of depositing into it.

## Attack walkthrough
1. Reserve (`0xf9bbb2df44cfe46e501cf91c99b2f8fef9d9d44a`) holds `B` DAI backing the hub.
2. Attacker contract (`0x00c64B5a926ba1fceC30EfaD88C344c619F54F12`) calls
   `give(receiver, amt)` with `amt = 2**128 - B` — a huge `uint128` value, not a small/negative
   one (there's no negative `uint128`; the trick is entirely in the later signed reinterpretation).
3. `_give` computes `int128(amt)`. Since `amt > type(int128).max`, the top bit of the 128-bit
   pattern is set, so the signed reinterpretation is negative: `int128(amt) == -B`.
4. `_give` calls `_transfer(user, -int128(amt))` = `_transfer(user, B)` — a **positive** argument.
5. `_transfer`'s `amt > 0` branch runs: withdraws `B` DAI from the reserve and transfers it
   straight to `user` (the attacker), instead of the intended `amt < 0` branch that would have
   pulled DAI *from* the attacker.
6. `_storage().receiverStates[receiver].collectable += amt` also runs first, incrementing
   `receiver`'s collectable balance by the raw huge `amt` value — a secondary accounting
   corruption, not itself the fund-drain mechanism.
7. Funds flow: reserve → hub → attack contract → attacker EOA
   (`0x84dA7a5e2315Eb798f04B75554AeB15047269CCE`), draining 24,882.995421947667857715 DAI.
- Not a key compromise, not phishing, not off-chain — a pure unchecked signed/unsigned
  reinterpretation bug reachable from a single public function with attacker-controlled input.

## Vulnerable code
- file:line — `hacks/drips-network/scan/Contract.sol:1376-1388` (`DripsHub._give`, the unchecked
  `-int128(amt)` conversion) and `:2130-2145` (`ERC20DripsHub._transfer`, the sign-branch that
  turns the flipped sign into an actual reserve withdrawal)
- pattern — unchecked `uint128` → `int128` conversion used to control fund-transfer direction,
  with no upper-bound validation on the unsigned input before the cast

## Sources
- postmortem / technical writeup: Verichains — "Drips Network: When Giving Became Receiving" —
  https://blog.verichains.io/p/drips-network-when-giving-became
- news coverage / loss figure: https://cryptonews.net/news/security/33204202/
- on-chain: exploit tx
  https://etherscan.io/tx/0xc38a6e2259a85ced94238a0b0a49697992f2a6b8140c28f3fd2343d3d8434130
  (block 25529927, confirmed via `eth_getTransactionReceipt` — status success)
