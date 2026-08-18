# CertiK Hunt workspace

One folder per hack. Same pipeline every time.

    hunt-workspace/
      recover.sh          # recovers the implementation live at an incident
      candidates.md       # pipeline of hacks to work, with loss figures
      hacks/
        butter-bridge/
          src-pre/        # the vulnerable implementation  <-- scan from here
          src-current/    # today's patched version
          patch.diff      # the fix, for the write-up
          upgrades.log
          scan/           # the single trimmed file you upload
          notes.md        # claim-form fields, filled in as you go

## Setup

    export ETH_RPC_URL=...
    export BSC_RPC_URL=...
    export ETHERSCAN_API_KEY=...
    chmod +x recover.sh

## Per hack

1. Find the exploit tx and its block. From a known exploiter address:

       cast logs --from-block <lo> --to-block <hi> \
         'Transfer(address,address,uint256)' <from_topic> <to_topic>

2. Confirm which contract executed the vulnerable path:

       cast run <tx> --trace-printer | less

3. Recover the code as deployed:

       ./recover.sh butter-bridge ethereum 0x0000317b...58f6a56 25137572

4. Read `patch.diff`. If the fix touches the function you suspect, you have
   the right version. Confirm the vulnerable pattern is present in `src-pre`.

5. Trim to one file plus its imports into `scan/`. Upload only that.
   AI Auditor, Lite tier. Record the scan ID immediately.

6. Fill in `notes.md`, then transfer it to the claim form.

## Scan status

| Protocol | Chain | Amount lost (claim) | Tiers run | Result | Claim status |
|---|---|---:|---|---|---|
| [butter-bridge](hacks/butter-bridge/notes.md) | Ethereum | $180,000 | Lite, Max | Lite missed, **Max caught** | Ready to submit |
| [drips-network](hacks/drips-network/notes.md) | Ethereum | $24,883 | Lite | **Lite caught** (first try) | Ready to submit |
| [kyberswap-elastic](hacks/kyberswap-elastic/notes.md) | Ethereum | $48,000,000 (capped; recorded $187,500 by AI Auditor) | Lite | **Lite caught** (first try) | Ready to submit |
| [euler-v1](hacks/euler-v1/notes.md) | Ethereum | $50,000,000 (capped) | Lite | **Lite caught** (first try) | Ready to submit |
| [bonzo-finance](hacks/bonzo-finance/notes.md) | Hedera | $9,050,000 | Lite, Max, Ultra | All 3 missed — team confirmed correct internally but marked `verified_as_invalid` (scan scope lacked reachability into the calling contract) | Rescan pending, wider scope now in `scan/` |
| [balancer-v2](hacks/balancer-v2/notes.md) | Ethereum | $50,000,000 (capped) | Lite, Max | Both missed on a trimmed 7-file bundle (closest hit was a different, related bug) | Rescan pending, `scan/` restored to 19 files for reachability |

Notes:
- "Tiers run" only counts tiers actually escalated to (per rule 03: escalate only when a lower tier misses).
- AI Auditor's own recorded claim amount can differ substantially from the submitted "Amount lost" figure (see kyberswap-elastic) — the driving formula isn't documented anywhere we've found; worth checking the platform's own claim record before assuming the submitted number is what scores.
- "Capped" means the real-world loss exceeded the $50M/hack scoring cap (rule 04), so the submitted figure is the cap itself, not the actual loss.

## Rules that bite

- Scan the pre-incident implementation, never today's.
- Root cause must be a contract bug — not keys, phishing, rugs, or off-chain.
- One incident = one hack, however many chains it touched.
- Five claims a day process automatically; spread bigger batches across days.
- Lite scores the same as Max. Escalate only when Lite misses.
- Something exploitable *today* → report privately, do not claim or post.