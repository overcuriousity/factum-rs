# Handoff: full-review fixes (branch review-fixes)

Stopped 2026-11-01 because the machine was shutting down. Base: b1e7379 (2.7.1). Nothing is merged to main.

## State
- Tasks 1-9: complete and reviewed. Task 10: rounds 1-3 complete and reviewed.
- Task 10 round 4 (fresh implementer) was still running at shutdown. Requirements: task-10-round-4-findings.md here.
  Its uncommitted work was committed as-is in the last commit ("WIP: Task 10 round 4 ...") and is UNVERIFIED: may not
  build or pass. Check it against the findings, finish it, add its "Fix round 4" report, then run a scoped re-review
  (re-review-instructions.md). Round 5 is the last; after that adjudicate per the SDD skill.
- Tasks 11-14: not started. They are in docs/superpowers/plans/2026-10-29-full-review-fixes.md, with carry-overs.
  Task 11 item 10 and Task 13 item 16 are carry-overs that earlier tasks rely on (`factum --version` hashes; Close as
  Damaged in the GUI for directory faults).
- Afterwards: run the full test suite once (never run yet on this branch), final whole-branch review on the most capable
  model, then list every `Ruling:` line in progress.md for the user. Don't merge without asking.

## How to resume
Follow superpowers:subagent-driven-development. One implementer at a time, one review per task, ledger in
progress.md. Fix minors in the loop too: the user asked for every finding to be fixed. Binding user decisions are in
global-constraints.md. The live ledger is .superpowers/sdd/2026-10-29-full-review-fixes/ (git-ignored); the copy here is
for anyone without that folder. Targeted tests only until the end. Run memory bombs only under `ulimit -v`.
Don't build a Rust target in /tmp (16 GB tmpfs).

## To raise with the user at the end
- Expired primary key valid only through certification stays FAIL `key_untrusted` (as in 2.7.1).
- Metadata budget clamp(128 × compressed members read, 4 GiB, 16 GiB).
- A directory fault blocks add and signing; Close as Damaged is the way out.
- `x509_expired` WARN stays on old X.509 containers permanently.
- Optional, not built: signed hash of verify_container.py; a Verify line saying a picked file is not in this log.
- install.ps1 changes never run; Windows code never compiled or run here (CI has windows-latest).
- Real TLDs as IOCs make README.md, setup.py, run.sh show up as domains.
