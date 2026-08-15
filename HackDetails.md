# CertiK $1B AI Auditor Challenge — Official Rules

5 steps, in this order.

## 01 — Find and recover

Find a historical hack, and recover the contract as it was deployed. The root
cause has to have been a bug in the contract code, and the code you scan has
to be the implementation that was live at the incident — most protocols
upgraded straight afterwards, so today's version is usually the patched one
and scanning it proves nothing. The databases under Reference material are a
place to start, not the list you have to pick from.

## 02 — Enrol on Hunt / AI Auditor

Request access on the Hunt page if you are not on Hunt yet, then enrol. Your
$100 in AI Auditor credits is added to the account on the same email you use
there when your application is approved — nothing to claim, and no button to
find. Sign in to AI Auditor with that same address if you never have, because
that is the account they land on.

## 03 — Scan only the suspect file

Scan only the file you suspect. Not the whole repository — a large bundle
burns credits you will need later and buries the finding among noise. Start
on Lite and escalate to Max only if Lite misses.

## 04 — Pick the right finding

Read the findings and pick the one that names the bug actually exploited, in
that code path. That finding, its scan id, and a sentence on why it is the
bug are your claim.

## 05 — Submit the claim

Submit the claim on the claim form — the finding by name, its scan id, and
one or two sentences on why that finding is the bug the attacker used. Ask in
the challenge Discord if you get stuck or run low on credits: misses are
funded.
