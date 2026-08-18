# sushiswap (SushiSwap RouteProcessor2 — forged pool callback)

## Recovery (rule 01 — goes in the claim)
- chain: ethereum (same bug deployed identically across ~14 chains — Arbitrum, Avalanche, BSC,
  Polygon, Optimism, Fantom, Gnosis, Moonbeam, Moonriver, Boba, Fuse, Arbitrum Nova, Polygon zkEVM;
  Ethereum picked as the recovery/scan chain)
- contract hit: `RouteProcessor2` at `0x044b75f554b886A065b9567891e45c79542d7357`. Not a proxy —
  RouteProcessor2 was deployed only 4 days before the exploit; SushiSwap's response was to have
  users revoke approvals and deploy a new, fixed `RouteProcessor3`, not patch this address.
- exploit tx (example): `0xb8f57cf82b7057d9d03f1500e3f0ce46980388c3b13ff317f1c617d932313386`,
  block **17007838**, status success (confirmed via `cast receipt`)
- implementation live at incident vs. today: **identical**, confirmed live and unchanged
- recovered by: `cast source --chain mainnet 0x044b75f554b886A065b9567891e45c79542d7357` —
  verified directly, `ContractName: RouteProcessor2`, no reconstruction needed

## Claim form fields
- Protocol / project: SushiSwap — RouteProcessor2
- Amount lost (digits only): 3300000
- Root cause: `swapUniV3` (scan/RouteProcessor2.sol:310-324) reads an attacker-controlled `pool`
  address straight out of the route data (`stream.readAddress()`, line 311) with **no check that
  it's a real Uniswap V3 pool deployed by the canonical factory** — the contract's own doc comment
  on `uniswapV3SwapCallback` (line 328) explicitly says "The caller of this method must be checked
  to be a UniswapV3Pool deployed by the canonical UniswapV3Factory," but the actual check at line
  340, `require(msg.sender == lastCalledPool, ...)`, only verifies the caller matches whatever
  `lastCalledPool` was set to two lines earlier (line 315, `lastCalledPool = pool` — the same
  attacker-supplied address). An attacker supplies their own malicious contract as `pool`;
  RouteProcessor2 calls `IUniswapV3Pool(pool).swap(...)` on it, the attacker's contract calls back
  into `uniswapV3SwapCallback` immediately, and the identity check passes trivially since
  `msg.sender` genuinely is the value RouteProcessor2 itself just wrote. The callback then executes
  `IERC20(tokenIn).safeTransferFrom(from, msg.sender, amount)` (line 347), where `from` is also
  attacker-controlled from the route data — pulling tokens from any user who has an outstanding
  ERC20 approval to RouteProcessor2, straight to the attacker's fake pool contract.
- Smart contract bug? Yes
- Scan ID: <pending>
- Tier: <pending — start Lite>
- Finding title (verbatim): <pending>
- Why this finding is the bug: The finding must name `swapUniV3`/`uniswapV3SwapCallback`'s missing
  validation that `pool` is a genuine, factory-deployed Uniswap V3 pool — the check only verifies
  `msg.sender == lastCalledPool`, a value the attacker's own malicious contract caused
  RouteProcessor2 to set on itself, letting the attacker's `uniswapV3SwapCallback` invocation pass
  and pull approved tokens from any RouteProcessor2 user via `safeTransferFrom`. This is the exact
  mechanism named across every independent writeup (SharkTeam, CertiK, Hacken, SolidityScan,
  Sushi's own post-mortem) and matches the contract's own doc-comment warning that was never
  actually implemented in code.

## AI Auditor scan log
(not yet run)

## Attack walkthrough
1. Attacker identifies that any user who has approved `RouteProcessor2` to spend their tokens
   (a completely normal, expected interaction for using the router) is exposed, because
   `swapUniV3` accepts an arbitrary `pool` address from caller-supplied route data.
2. Attacker deploys a malicious contract that mimics `IUniswapV3Pool.swap`'s interface, then calls
   `processRoute` with a route whose `pool` parameter points to this malicious contract instead of
   a real Uniswap V3 pool.
3. `swapUniV3` sets `lastCalledPool = pool` (the malicious contract's address) and calls
   `IUniswapV3Pool(pool).swap(...)` on it.
4. The attacker's fake "pool" contract, inside its own `swap` implementation, immediately calls
   back into `RouteProcessor2.uniswapV3SwapCallback`.
5. The callback's only check, `msg.sender == lastCalledPool`, passes — `msg.sender` genuinely is
   the attacker's contract, which is genuinely what `lastCalledPool` was just set to.
6. The callback decodes `(tokenIn, from)` from attacker-controlled `data`, and since
   `from != address(this)`, calls `IERC20(tokenIn).safeTransferFrom(from, msg.sender, amount)` —
   pulling `amount` of `tokenIn` from any victim address (`from`) that has an outstanding approval
   to RouteProcessor2, straight to the attacker's fake pool.
7. Repeated across many victim addresses and tokens/chains, netting ~$3.3M before HYDN's security
   team and Sushi's own "revoke all chains" emergency response limited further losses (HYDN
   separately whitehat-rescued >$600K).
- Not a key compromise, not phishing, not off-chain — a missing check that a caller-supplied pool
  address is a real, factory-deployed pool before trusting its callback, reachable by anyone who
  can call the router's public swap-routing entry point.

## Vulnerable code
- file:line — `hacks/sushiswap/scan/RouteProcessor2.sol:310-324` (`swapUniV3`, where an
  unvalidated attacker-supplied `pool` address is trusted) and `:335-348`
  (`uniswapV3SwapCallback`, where the only authentication is `msg.sender == lastCalledPool` — a
  value the attacker's own fake pool caused the contract to set on itself)
- pattern — missing caller/counterparty validation in a swap callback: the contract's own
  documentation states the correct check ("must be a UniswapV3Pool deployed by the canonical
  UniswapV3Factory") but the implementation substitutes a same-transaction self-consistency check
  (`msg.sender == lastCalledPool`) that an attacker fully controls both sides of

## Sources
- technical writeups: SharkTeam — https://medium.com/@sharkteam/permission-verification-vulnerability-analysis-of-the-sushiswap-attack-525c050f64c4 ;
  CertiK — https://www.certik.com/blog/post-mortem-sushiswap ;
  Hacken — https://hacken.io/discover/sushi-hack-explained/ ;
  SolidityScan — https://blog.solidityscan.com/sushiswap-hack-analysis-improper-router-approve-parameters-68bfd266c33b/ ;
  Sushi's own post-mortem — https://www.sushi.com/blog/routeprocessor2-post-mortem
- on-chain: exploit tx
  `0xb8f57cf82b7057d9d03f1500e3f0ce46980388c3b13ff317f1c617d932313386`, block 17007838, confirmed
  success via `cast receipt`
- ground-truth source: Etherscan, verified `RouteProcessor2` at
  `0x044b75f554b886A065b9567891e45c79542d7357` — no reconstruction needed, not upgradeable, code
  unchanged since deployment
