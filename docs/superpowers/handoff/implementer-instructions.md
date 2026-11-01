# Implementer instructions (all tasks)

Read first, in this order: global-constraints.md in this folder (constraints and the user's binding decisions), then your task brief (your requirements, with exact values to use verbatim).

- Work only in /home/user01/Projekte/factum/factum-rs-review-fixes (branch review-fixes). Never touch /home/user01/Projekte/factum/factum-rs (the main checkout). Never push.
- Scratch files go only in /tmp/claude-1000/-home-user01-Projekte-factum-factum-rs/00a27775-c80c-406d-9847-54e49a7fe7cc/scratchpad/<your task>/.
- Tests that start the binary must isolate HOME and the config dir; never write to the real ~/.config.
- Targeted tests only (`cargo test --test <file> <name>`, `cargo test --lib <path>`). Do NOT run the full suite; the controller does that once at the end. Keep `cargo build`, `cargo clippy --all-targets` and `cargo fmt --check` clean.
- If something is unclear, reply NEEDS_CONTEXT with questions rather than guessing. If it is too hard or needs an architectural choice, reply BLOCKED with specifics.
- Do only what the brief asks. The user objects to unrequested features: anything you add beyond the brief goes in a labelled "my own calls" list in the report so the user can veto it.
- Line numbers in the brief are hints from b1e7379; earlier tasks moved code. Before fixing a finding, confirm it still exists; if not, say so in the report.
- You do not dispatch subagents: no helpers, no reviewers. Review is the controller's job after you report.
- Implement, write regression tests, verify, commit per logical group (message footer in the constraints file), then self-review your own diff (completeness, quality, YAGNI, existing patterns, tests that verify real behaviour) and fix what you find.

Write the full report to the report path in your dispatch: what you did per item, tests and results (commands + relevant output), files changed, self-review findings, concerns, your own calls.

Then reply with ONLY (under 15 lines): Status (DONE | DONE_WITH_CONCERNS | BLOCKED | NEEDS_CONTEXT), commits (short SHA + subject), one-line test summary, concerns, report path.

If review findings come back you will be resumed: fix them, re-run the covering tests, append a fix report (what changed, tests, command, output), commit, and reply with the same short contract.
