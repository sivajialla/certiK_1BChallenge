# Recovery playbook — CertiK $1B AI Auditor Challenge

A repeatable process for taking any historical hack from "I have an address and a block number"
to "a single trimmed file ready for AI Auditor," per the 5 official rules in
[HackDetails.md](HackDetails.md). Read this before starting a new hack; use
`hacks/<slug>/notes.md` to record the specifics of each one.

---

## 0. One-time environment setup

```bash
# foundry's cast must be installed
which cast || curl -L https://foundry.paradigm.xyz | bash && foundryup

export ETH_RPC_URL=...       # mainnet
export BSC_RPC_URL=...
export POLYGON_RPC_URL=...
export ARB_RPC_URL=...
export BASE_RPC_URL=...
export ETHERSCAN_API_KEY=... # used for source pulls AND upgrade-history log queries
chmod +x Recover.sh
```

`Recover.sh` already has these fixes baked in — no need to rediscover them per hack:
- uses `cast source` (not the removed `cast etherscan-source`)
- maps chain slugs (`ethereum`) to what `cast --chain` actually expects (`mainnet`)
- fetches upgrade history via Etherscan's log API instead of raw `eth_getLogs`, so it isn't
  bounded by RPC free-tier block-range caps (e.g. Alchemy's 10-block limit on unbounded queries)

---

## 1. Pick a hack and gather the basic facts (rule 01)

- protocol/hack slug, chain, the contract actually hit (proxy or plain), incident block number
- reference-material databases are a starting point, not a required list — anything with a real,
  contract-level root cause is fair game
- **the root cause must be a bug in the contract code** — not keys, phishing, rugs, or off-chain
  infra. Confirm this before investing time in recovery.

---

## 2. Run `Recover.sh`

```bash
./Recover.sh <slug> <chain> <address> <incident_block>
```

This automatically:
1. resolves the EIP-1967 implementation live at `incident_block - 1` and today, via
   `cast storage` on the standard proxy/beacon/admin slots
2. pulls the full `Upgraded(address)` event history for the proxy (Etherscan log API — unbounded)
3. attempts to pull verified source for both the pre-incident and current implementations
   (`cast source`, into `hacks/<slug>/src-pre/` and `hacks/<slug>/src-current/`)
4. diffs them into `patch.diff` if both pulled successfully
5. runs a grep-based smell test over `src-pre` for common bug patterns
   (`encodePacked`, `delegatecall`, raw `.call{`, `_mint(`, etc.)
6. scaffolds `hacks/<slug>/notes.md` with the claim-form fields blank

**Read the console output carefully.** The two implementation addresses it prints are the whole
ballgame — if `impl @ N-1 == impl @ now`, today's code likely *is* what was exploited (rare, but
check upgrades.log to be sure nothing patched shortly after). If they differ, only `impl @ N-1` is
a legitimate scan target.

---

## 3. If the pre-incident implementation is unverified — this is common, budget time for it

`cast source` will print `Error: Contract source code not verified: 0x...` and leave `src-pre/`
empty. Do not treat this as a dead end — most protocols with real vulnerable code end up
unverified precisely because they patched and redeployed immediately, and never bothered
re-verifying the old one. Work through this checklist in order:

**3.1 — Check Sourcify directly** (sometimes verified there when Etherscan isn't)
```bash
curl -s "https://sourcify.dev/server/v2/contract/<chainid>/<address>"
# {"match": null, ...}  → not there either, move on
```

**3.2 — Identify the protocol's real GitHub org/repo**
- Look at the import paths in whatever source *did* pull successfully — usually the current
  (patched) implementation pulls fine, since teams re-verify after a fix. An import like
  `@someorg/protocol/contracts/...` names the npm scope, which is usually also the GitHub org.
- Search GitHub directly:
  ```bash
  gh repo list <org> --limit 50
  gh api "search/code?q=<DistinctiveInterfaceOrContractName>+in:file+language:solidity"
  gh api "search/repositories?q=org:<org>+bridge"   # or whatever the domain is
  ```
- **Watch for decoys** — protocols often have multiple repos across versions (V1/V2/V3) with
  similar names. Confirm the file/directory structure and contract names actually match what you
  pulled for the current implementation before trusting a repo.

**3.3 — Find the fix commit**
```bash
gh api "repos/<org>/<repo>/commits?path=<path/to/file.sol>&per_page=100" \
  | jq -r '.[] | "\(.sha[0:10])  \(.commit.author.date)  \(.commit.message | split("\n")[0])"'
```
Look for a commit shortly after the incident timestamp (cross-check against `upgrades.log`'s
patch-deployment block/time) with a message hinting at a fix ("fix", "audit", "patch",
"security", "hash bug", etc.). The commit immediately before it is your candidate pre-incident
version — confirm nothing else touches that file in between.

**3.4 — Confirm the fix commit actually matches the reported root cause**
```bash
gh api repos/<org>/<repo>/commits/<fix_sha> -H "Accept: application/vnd.github.v3.diff"
```
Read the diff. If you have a post-mortem or write-up, the diff should plausibly explain it — e.g.
a fix that changes `abi.encodePacked` → `abi.encode` only makes sense against a hash-collision
bug, not a missing-authorization bug. If the diff doesn't line up with the reported root cause,
keep looking — you may have the wrong commit, wrong file, or wrong repo.

**3.5 — Pull the pre-incident source from the fix commit's parent**
```bash
PARENT=$(gh api repos/<org>/<repo>/commits/<fix_sha> --jq '.parents[0].sha')
gh api "repos/<org>/<repo>/contents/<path>?ref=$PARENT" --jq '.content' | base64 -d > hacks/<slug>/src-pre/<path>
```
Pull the vulnerable file plus its direct first-party imports (interfaces, libs) — skip
third-party boilerplate (OpenZeppelin, etc.) unless the bug actually involves it.

**3.6 — No public repo, or no matching commit exists**
Fall back to decompiling the on-chain bytecode (lower confidence — note this explicitly in
`notes.md`), or manually reconstructing from whatever partial source/ABI is available. Don't
silently substitute the patched version and call it done — rule 01 is explicit that scanning
today's code "proves nothing."

---

## 4. Verify the recovery before trusting it

```bash
# mind directory nesting — cast source's -d output nests under the contract name
# (e.g. src-current/<ContractName>/contracts/...), src-pre from GitHub usually won't
diff -ru hacks/<slug>/src-pre/contracts hacks/<slug>/src-current/<ContractName>/contracts > hacks/<slug>/patch.diff
```

- A diff that isolates to a small, plausible set of files is a strong signal you have the right
  commit. A diff that touches everything (renamed paths, reformatted files, wrong compiler
  version) is a signal you have the wrong one.
- Re-run the smell test against the confirmed `src-pre`.
- Grep for the specific pattern named in any post-mortem/write-up and confirm it's present
  *verbatim*, at the code path actually reachable from the exploit transaction — not just present
  somewhere in the file.

---

## 5. Build the scan candidate (rule 03)

```bash
mkdir -p hacks/<slug>/scan
cp hacks/<slug>/src-pre/<path/to/the/file/that/actually/changed>.sol hacks/<slug>/scan/
```

Only the file(s) that diverged in the fix, per the diff in step 4 — not the whole `src-pre` tree,
not unrelated files. A large bundle burns AI Auditor credits and buries the real finding among
noise. Add supporting first-party files only if the suspect file is unreadable without them
(e.g. a thin proxy wrapper around an abstract base — trim to the base, not the wrapper).

---

## 6. Fill in `notes.md`

`Recover.sh` scaffolds the file; fill in as you go:
- **Protocol / project, root cause, attack walkthrough** — written in your own words, precise
  enough that "why this finding is the bug" (rule 04) is a one-line lookup later
- **Vulnerable code** — exact `file:line` in `scan/`, and the specific pattern
- **Sources** — official post-mortem if one exists, the fix commit URL (this is your ground truth
  for the vulnerable code, cite it explicitly), and loss-figure sources
- Cross-check against independent on-chain-monitoring accounts (Blockaid and similar) when
  available — they're a fast way to confirm addresses, tx hashes, and realized-loss figures
  without waiting on a formal write-up
- Leave **Scan ID** and **Finding title** blank until step 7

---

## 7. Scan in AI Auditor (rules 02–05)

This part is account-gated — it has to happen in your own browser session, not from the CLI.

1. **Enrol / sign in.** If not already on Hunt, request access there first. The $100 in AI Auditor
   credits lands automatically on the same email your Hunt application was approved under — sign
   in to AI Auditor with that exact address.
2. **Upload only `hacks/<slug>/scan/*`.** Not the whole repo, not the full `src-pre/` tree.
3. **Start on Lite tier.** Escalate to Max only if Lite misses the bug.
4. **Pick the finding that names the actual exploited code path** — the one pointing at the
   specific function/lines recorded in `notes.md`'s "Vulnerable code" section, not just any
   finding in the file.
5. **Record the finding's exact title and the scan ID** into `notes.md`.
6. **Submit the claim form**: finding name, scan ID, and the one-or-two-sentence "why this finding
   is the bug" already drafted in `notes.md`.

---

## Repo layout reference

```
Recover.sh              # the recovery script (fixed, see section 0)
Readme.md                # quick pipeline reference
HackDetails.md            # the 5 official challenge rules, verbatim
PROCESS.md                # this file
hacks/
  <slug>/
    src-pre/              # vulnerable implementation — the one you scan
    src-current/           # today's (patched) implementation, for diffing/reference
    patch.diff             # src-pre vs src-current — should isolate to the real fix
    upgrades.log            # full Upgraded(address) history for the proxy
    scan/                    # the single trimmed file(s) actually uploaded to AI Auditor
    notes.md                  # claim-form draft + recovery method + sources
```
