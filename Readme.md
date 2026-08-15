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

## Rules that bite

- Scan the pre-incident implementation, never today's.
- Root cause must be a contract bug — not keys, phishing, rugs, or off-chain.
- One incident = one hack, however many chains it touched.
- Five claims a day process automatically; spread bigger batches across days.
- Lite scores the same as Max. Escalate only when Lite misses.
- Something exploitable *today* → report privately, do not claim or post.