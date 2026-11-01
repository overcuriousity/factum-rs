# SDD ledger — plan: docs/superpowers/plans/2026-10-29-full-review-fixes.md

Worktree: /home/user01/Projekte/factum/factum-rs-review-fixes (branch review-fixes, base b1e7379, plan commit d884f13)
No separate spec: the plan's "User decisions" section is binding; rulings are provisional against it.

## Pre-flight scan

| Tasks | Shared file/interface | Produces → consumes | Finding |
|---|---|---|---|
| T1 / T11 | byte-capped file-name helper | T1 creates, T11 uses | ordered T1 before T11, ok |
| T1 / T14 | seal folder writer in user config | T1 creates, T14 dialog validation uses | ordered, ok |
| T1 / T2 / T11 | src/export/verify.py | T1 splitlines, T2 gpg strictness, T11 hash/duplicates | sequential, disjoint parts, ok |
| T1 / T2 | verifier.rs, late_signing.rs | T1 seal-dir source, T2 tolerant rows/cache | disjoint, ok |
| T2 / T8 | EXPKEYSIG handling | GPG (signer) vs gpgsm (x509) | both valid+time check; consistent semantics, ok |
| T2 / T13 | verification cache vs UI-thread verify | T13 still moves verify off the UI thread | ok |
| T3 / T14 | gui/dialogs.rs | T3 suggestion_list only, T14 rest | ok |
| T7 / T8 / T9 | container/volume.rs | T7 open/truncate path, T8 source/link/path fields, T9 close/recheck | sequential, ok |
| T7 / T10 | duplicate names / CD count | Rust check T7, Python mirror T10 | ok |
| T8 / T9 | containers.rs Add Again (raw paths) | T8 item 8 records raw form, T9 item 5 indexes add_again_plan | ok, T8 first |
| T9 / T10 | replacedBy semantics | T9 log cross-check; T10 Python WARN | ok |
| T9 / T13 | container guard/lock behaviour | T9 core locks, T13 GUI guard | ok |
| T13 / T14 | gui/mod.rs | T13 core, T14 dialog result handling only | ok |
| each task | self-consistency | tests named per item, files listed cover items | T1 item 6 helper location left to implementer; T13 item 6 carries a controller ruling |

Ruling: Quit confirmation (T13.6) gets one confirm dialog — user chose "no confirm dialog" only for dialogs with typed text; losing a running acquisition is worse than one prompt — cost if wrong: remove one dialog.
Ruling: Full suite runs once at the end, not per task (user memory "targeted tests during implementation") — overrides the implementer template's "full suite before committing" — cost if wrong: a cross-task regression found late.

## Progress
Task 1: dispatched (BASE d884f13, implementer opus)
Task 1: implementer DONE_WITH_CONCERNS (575dc4e..baa31e0); review dispatched (opus)
Task 1: review — Needs fixes (1 Critical: migration marker in attacker-controlled DB; 6 minor). Fix round 1 sent to implementer (FIX_BASE baa31e0).
Ruling: Minor findings are fixed in the loop rather than deferred — user asked to fix everything — cost if wrong: longer fix rounds.
Ruling: Seal-folder change recorded in the application log (WARN) + GUI notice, not the signed case log — a new signed event type would FAIL unsigned cases — cost if wrong: add a case-log event later.
Ruling: Export reports also state the checked seal folder (report-only line, not in case.json) — decision 1 says "every verify report" — cost if wrong: one line to remove.
Task 1: session restarted 2026-10-30; fix round 1 was interrupted with uncommitted work, implementer resumed on it (FIX_BASE baa31e0).
Task 1: fix round 1 implementer DONE_WITH_CONCERNS (baa31e0..4a5ed20); re-review dispatched
Task 1: fix round 1/5 (7 addressed, 1 new Important open — first start with FACTUM_DB skips the real DB's folder; commits baa31e0..4a5ed20). Fix round 2 sent (FIX_BASE 4a5ed20).
Ruling: A WARN finding (`seal_dir_unused`) replaces "skip the marker when FACTUM_DB is set" — it covers every path to the loss and a tampered DB can only plant a hint, never a redirect — cost if wrong: one spurious WARN on databases with an old setting.
Ruling: `${` single-quote branch reverted — python-dotenv expands in every quoting form, so it bought nothing — cost if wrong: a path with `${...}` reads differently in factum-notes (only fixable there, with interpolate=False).
Ruling: set_seal_folder deletes `seal_dir` from the open DB — otherwise the WARN never clears; the old GUI overwrote the same value — cost if wrong: remove one line and its assertion.
Task 1: fix round 2 implementer DONE (4a5ed20..7f6b690); re-review dispatched
Task 1: fix round 2/5 (2 addressed, 0 open; commits 4a5ed20..7f6b690)
Task 1: complete (commits d884f13..7f6b690, review clean)
Task 1: minor (deferred): seal_dir_unused WARN can't be cleared for CLI-only users, with a real FACTUM_SEAL_DIR variable, or for databases not open when the folder is chosen.
Task 1: minor (deferred): seal-folder change record goes to stderr only; GUI from a launcher keeps none.
Task 2: implementer DONE_WITH_CONCERNS (7f6b690..bab1137); review dispatched (opus)
Task 10: carry-over from Task 2: verify_container.py must match the new EXPKEYSIG and primary-fingerprint behaviour.
Task 2: review — Needs fixes (2 Important: expired remembered key writes unsigned notes; subkey trust; 7 minor). Fix round 1 sent (FIX_BASE bab1137). Minor verify_container + cli lookup moved into plan Tasks 10 and 5.
Ruling: An expired primary key valid only through certification stays FAIL key_untrusted; the scratch-trustdb recovery isn't adopted — unchanged from 2.7.1, and it needs faked-system-time and a second trustdb — cost if wrong: second-examiner checks of expired keys keep failing until the user asks for it. RAISE WITH USER AT END.
Task 2: fix round 1 implementer DONE_WITH_CONCERNS (bab1137..0241e4c); re-review dispatched
Task 2: fix round 1/5 (6 addressed, 0 open; commits bab1137..0241e4c)
Task 2: complete (commits 7f6b690..0241e4c, review clean)
Task 2: my-own-calls to surface: list_keys also returns the active key when it can't sign (labels reachable without UI).
Task 3: dispatched (BASE 6068d0f, implementer sonnet)
Task 3: implementer DONE (6068d0f..08caa34); review dispatched
Task 3: review — Needs fixes (1 Important: reopen can create a duplicate open number; 3 minor). Fix round 1 sent (FIX_BASE 08caa34).
Ruling: Reopen is refused while another open case holds the number — decision 8 says no two open cases share a number, and this overrides my earlier "reopening isn't in scope" note — cost if wrong: an examiner must archive or renumber the other case first.
Task 3: fix round 1 implementer DONE (08caa34..87f8226); re-review dispatched
Task 3: fix round 1/5 (4 addressed, 0 open; commits 08caa34..87f8226)
Task 3: complete (commits 6068d0f..87f8226, review clean)
Task 4: dispatched (BASE 87f8226, implementer sonnet)
Task 4: implementer DONE_WITH_CONCERNS (87f8226..162dd94); review dispatched
Ruling: IOC exclusion list: restore `bin` and `pkg` (not delegated TLDs; my plan text was wrong) and remove `cab` (a real gTLD) — decision 6 says exclude non-TLDs only; judged from memory because the machine has no root-zone list — cost if wrong: one suffix misclassified, one-word change. Sent with Task 4's fix round.
Task 4: review — Approved; 3 small fixes sent as round 1 (FIX_BASE 162dd94).
Task 4: fix round 1 implementer DONE (162dd94..eea4ed3); re-review dispatched
Task 4: fix round 1/5 (3 addressed, 0 open; commits 162dd94..eea4ed3)
Task 4: complete (commits 87f8226..eea4ed3, review clean)
Task 5: dispatched (BASE eea4ed3, implementer sonnet)
Task 5: implementer DONE (8a2d6a9); review dispatched
Task 5: review — Needs fixes (1 Important: second verify after export; 5 minor). Fix round 1 sent (FIX_BASE 8a2d6a9).
Ruling: Commit footer stays "Claude Opus 5.5" on every commit, including those written by Sonnet implementers — that is the attribution line the session gave the controller — cost if wrong: footer text differs from the model that wrote a commit.
Task 5: fix round 1 implementer DONE (8a2d6a9..27ceb8a); re-review dispatched
Task 5: fix round 1/5 (6 addressed, 0 open; commits 8a2d6a9..27ceb8a)
Task 5: complete (commits eea4ed3..27ceb8a, review clean)
Task 6: dispatched (BASE 27ceb8a, implementer sonnet)
Task 6: implementer DONE_WITH_CONCERNS (27ceb8a..28d8b58); review dispatched
Task 6: review — Needs fixes (1 Important: EXPKEYSIG fatal in installers; 4 minor). Fix round 1 sent (FIX_BASE 28d8b58).
Task 6: fix round 1 implementer DONE_WITH_CONCERNS (28d8b58..00b5973); re-review dispatched
Task 6: fix round 1/5 (5 addressed, 0 open; commits 28d8b58..00b5973)
Task 6: complete (commits 27ceb8a..00b5973, review clean)
Task 6: not run: every install.ps1 change (no PowerShell here). Needs a Windows try before release. TELL USER.
Task 7: dispatched (BASE 00b5973, implementer opus)
Task 7: implementer DONE_WITH_CONCERNS (00b5973..a87413f); review dispatched (opus)
Task 10: carry-over from Task 7: a complete state that cannot be read is Fail trailing_data in Rust; Python must match (plan said WARN).
Task 7: review — Needs fixes (1 Critical: opening cuts complete members, even a logged state; 2 Important: empty stored member disables refusal, CRC field suppresses verdicts; 3 minor). Fix round 1 sent (FIX_BASE a87413f).
Task 10: carry-over from Task 7: Python gives one "cannot be read" line per file on a bad CRC; match the separate CRC finding from the Rust fix.
Task 7: fix round 1 implementer DONE_WITH_CONCERNS (a87413f..22fdaa0); bevy name rule requested before re-review.
Ruling: A zero-size stored member named as a bevy counts as interrupted — a crash while acquiring a large incompressible file must recover without a manual cut — cost if wrong: one name rule to remove.
Ruling: A copy truncated inside the directory with `known` at or below end1 is still cut — it is what a crash while writing the directory leaves, and those members were never logged — cost if wrong: an unlogged tail of a truncated copy is removed on open.
Task 10: carry-over from Task 7: junk tails are Fail in Rust; Python must match, not WARN.
Task 7: fix round 1 complete from implementer (a87413f..b86bc37); re-review dispatched (opus)
Task 7: fix round 1/5 (6 addressed, 1 Important open — CRC mismatch error text; commits a87413f..b86bc37). Fix round 2 sent (FIX_BASE b86bc37).
Ruling: A container with a proven directory fault (metadata or content CRC mismatch) is not appended to or signed; Close as Damaged is the way out — it writes nothing and lets the case be archived — cost if wrong: an examiner with a one-bit CRC fault can't sign that container. Added to plan Task 9 items 11-12.
Task 7: fix round 2 implementer DONE_WITH_CONCERNS (b86bc37..5989e68); read-error text requested before re-review
Task 7: fix round 2 implementer complete (b86bc37..2e40780); re-review dispatched. Note bd2f58b is a plan-only commit inside the range.
Task 7: minor (deferred): uuid_of's File::open failure still says "is not a factum container" — Locate on an unreadable file.
Task 7: fix round 2/5 (7 addressed, 0 open; commits b86bc37..2e40780)
Task 7: complete (commits 00b5973..2e40780, review clean)
Task 8: dispatched (BASE 2e40780, implementer opus)
Task 8: implementer DONE_WITH_CONCERNS (2e40780..a472cb5); review dispatched (opus)
Task 8: not run: Windows code in sources and mounts never compiled here. TELL USER.
Task 10: carry-over from Task 8: decode/refuse IRI escapes; expired certs (openssl cms -verify fails on them); compare CMS signer with first .cer certificate.
Task 8: review — Needs fixes (3 Important: visible mount dropped, expired intermediate passes, no WARN for expired cert; 7 minor). Fix round 1 sent (FIX_BASE a472cb5).
Ruling: An expired X.509 certificate gets a WARN `x509_expired`, like GPG's `key_expired` — old containers then verify with a warning for good, as GPG ones do — cost if wrong: a permanent ⚠ on old X.509 containers.
Ruling: A false "changed" on file systems that renumber inodes stays a loud failure — it's the safe direction and acceptance logic adds risk — cost if wrong: files on vfat/CIFS can be refused and must be re-added.
Task 8: fix round 1 implementer DONE (a472cb5..4bcf7b2); re-review dispatched
Task 8: fix round 1/5 (10 addressed, 0 open; commits a472cb5..4bcf7b2)
Task 8: complete (commits 2e40780..4bcf7b2, review clean)
Task 9: dispatched (BASE 4bcf7b2, implementer opus)
Task 9: implementer DONE_WITH_CONCERNS (4bcf7b2..951979d); review dispatched (opus)
Task 13: carry-over from Task 9: wire Recheck.directory_faults into Dialog::Damaged, pass as close_container_damaged's third argument (GUI passes &[] today); Close and Archive stops there.
Task 10: carry-over from Task 9: verify_container.py must FAIL history/0/.
Task 9: review — Needs fixes (6 Important: signing inside the write transaction; Close Without File regression; late signing can lose an addition; hostile history numbers; signed "no file found damaged" when none were checked; dead sector at the head stays retryable; 1 minor). Fix round 1 sent (FIX_BASE 951979d).
Task 9: fix round 1 implementer DONE (951979d..af900cd); re-review dispatched (opus)
Task 10: carry-over from Task 9: verify_container.py:511 enumerates range(1, max(closes)); walk neighbouring keys like Rust.
Task 9: fix round 1/5 (7 addressed, 3 new minor open; commits 951979d..af900cd). Fix round 2 sent (FIX_BASE af900cd).
Task 9: fix round 2 implementer DONE (af900cd..a1b7238); re-review dispatched
Task 9: fix round 2/5 (4 addressed, 0 open; commits af900cd..a1b7238)
Task 9: complete (commits 4bcf7b2..a1b7238, review clean)
Task 9: minor (deferred): close refusal says "a fault of its directory" for an open failure; could read "or of reading it".
Task 10: dispatched (BASE 5a335c7, implementer sonnet)
Task 10: session restarted; worktree clean at 5a335c7, no partial work survived; implementer resumed (opus — the dispatch line above says sonnet, that was wrong).
Task 10: implementer DONE_WITH_CONCERNS (5a335c7..7847d5e); review dispatched (opus)
Task 10: review — Needs fixes (2 Critical: method field hides content swap with exit 0; version.txt tamper skips everything in Rust including the log; 8 Important incl. Rust hang on a stray `>`, traceback, hangs, memory; 2 minor). Fix round 1 sent (FIX_BASE 7847d5e), with Rust files in scope.
Ruling: A container's format is decided by its layout, never by the unsigned version.txt or tool= line — both are one-bit tampers — cost if wrong: a foreign tool's container that happens to carry factum-named members gets Fail instead of Warn.
Task 10: fix round 1 implementer DONE_WITH_CONCERNS (7847d5e..1d6ca31); re-review dispatched (opus)
Task 10: fix round 1/5 (9 addressed; 3 open + 3 new: clean Ok on swapped evidence at the logged path, budget false FAIL, budget text; commits 7847d5e..1d6ca31). Fix round 2 sent (FIX_BASE 1d6ca31).
Ruling: Metadata budget scales with stored metadata: max(4 GiB, 64 × compressed metadata size) in both verifiers — a fixed 4 GiB fails a legitimate 200k-file container closed twice — cost if wrong: a crafted file can use up to 64× its stored metadata in memory.
Ruling: verify_container.py gets user decision 2's treatment (prints its own hash), no new signed metadata — the user objects to unrequested features — cost if wrong: a replaced script in a container is caught only by a reader who compares the hash. Mention the signed-hash option to the user.
Task 10: minor (deferred): an added unknown member at the root of a signed container gets no finding in either verifier.
Task 10: fix round 2 implementer DONE_WITH_CONCERNS (1d6ca31..9e0676c); re-review dispatched (opus)
Task 10: fix round 2/5 (9 addressed, 1 open + 2 new: log_mismatch beside too_large, uncharged parse text, budget without a ceiling; commits 1d6ca31..9e0676c). Fix round 3 sent (FIX_BASE 9e0676c).
Ruling: Metadata budget is clamp(128 × compressed exact members read, 4 GiB, 16 GiB) — replaces the 64× formula; 128 stops the false too_large on near-identical files, and the 16 GiB ceiling bounds a crafted file — cost if wrong: a verifying machine needs up to about 16 GiB plus a margin, and a container over the ceiling reports too_large. One constant per verifier. RAISE WITH USER AT END.
Ruling: The script prints a distinct `Result: NOT SIGNED` line for an unsigned file, exit 0 unchanged — README claimed neither verifier calls an unsigned file good — cost if wrong: one line of output changes.
Option for the user, not built: a line in the Verify window saying a picked file is no container of this log, naming its uuid.
Task 10: fix round 3 implementer DONE_WITH_CONCERNS (9e0676c..4639903); re-review dispatched (opus)
Task 10: fix round 3/5 (8 addressed, finding 2 open in both verifiers, 4 new minor; commits 9e0676c..4639903). Round 4 goes to a fresh implementer (FIX_BASE 4639903).
Ruling: Round 4 uses a fresh Opus implementer rather than a higher tier — the open item is one well-scoped fix with reproducers, and the old implementer's context is over 660k tokens — cost if wrong: a stalled fix goes to round 5 on a higher tier.
