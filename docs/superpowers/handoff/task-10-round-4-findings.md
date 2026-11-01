# Task 10 fix round 4: open findings

Round 3 left one finding open, in both verifiers, plus four minors. Everything else in Task 10 is confirmed done.
Reproducers (read them first, run them only under `ulimit -v`, never uncapped):
- /tmp/claude-1000/-home-user01-Projekte-factum-factum-rs/00a27775-c80c-406d-9847-54e49a7fe7cc/scratchpad/rr12/tools/subj.py
- /tmp/claude-1000/-home-user01-Projekte-factum-factum-rs/00a27775-c80c-406d-9847-54e49a7fe7cc/scratchpad/rr12/tools/pyprefix.py
- Runner: /tmp/claude-1000/-home-user01-Projekte-factum-factum-rs/00a27775-c80c-406d-9847-54e49a7fe7cc/scratchpad/rr12/run.sh

Binding controller ruling, do not change it: budget = clamp(128 × compressed size of the exact members read, 4 GiB,
16 GiB), in both verifiers, counting only the root and factum/history/<n>/information.turtle and .hashes.

## IMPORTANT: text held by a parse must be charged as it is held

Rust: charged only after the statement ends (src/container/turtle.rs `parse_within`, the `parser.statement()?` loop).
`Graph::add` (turtle.rs:97) copies subject and predicate into every triple, and one statement can hold every triple.
A 35 KB file `<16 MiB subject> <b> <c> , <c> , ...` (2M objects) would need about 32 TiB; it aborted with exit 134
under an 8 GiB cap. A long `@prefix` with `p:c , p:c , ...` also aborted. With no cap it grows until the OOM killer,
and the GUI verifies in-process. The `parse_within` doc comment says this is refused. `text_counts_for_what_it_holds`
passes only because its 64 MiB fits in memory.

Python: expansion is not charged (src/container/verify_container.py `expand`, `prefixes[prefix] + local`).
`take_memory` charges only `len(line)`, and each short line then holds full-prefix copies. A 2 KB file (1 MiB prefix,
1,500 lines of `    p:x p:y ;`) held 3.1 GiB, charged about 1.3 MiB, no `too_large`. A 56 KB file (2M lines) hit
the 8 GiB cap, and its `too_large` came from MemoryError at the cap, with about 450 MiB of 4 GiB charged.

Required: charge per triple inside `statement()` in Rust and per triple after `expand` in Python, so the budget stops
a parse before the memory is used, whatever the shape of the statement. Add tests that would fail without the check by
counting charged bytes or stopping within the budget, not by fitting in memory. Keep the existing cases working:
legitimate 200,000 files × 3 closes + open at about 11:1 must not give `too_large` (Rust 6.41 GiB, Python 5.22 GiB at
round 3); the `\xff` and `a` bombs and the 1 GiB pad stay `too_large`.

## MINOR

1. Spec "ceiling" paragraph in docs/superpowers/specs/2026-10-26-evidence-containers-design.md: "up to that ceiling,
   not beyond it" is false (5.2-5.3 GiB measured at a 4.0 GiB limit). State the measured overshoot honestly.
2. src/container/verify_container.py `READ_METADATA`: `[1-9][0-9]{0,9}` also matches 4294967296 to 9999999999, which
   Python doesn't read and Rust doesn't count, so a pad at factum/history/5000000000/information.turtle buys budget in
   Python. Count only numbers that are read (u32 range), matching Rust.
3. src/container/turtle.rs `tokenize`: `xxx.` pushes a Name and a Dot in one iteration and only `last()` is charged.
   Iterate `tokens[counted..]`.
4. src/container/verify.rs test `a_stop_at_the_limit_keeps_a_stripped_file_...` asserts only `!stopped_on_budget()`,
   which passes with no `too_large` at all. Pin the `too_large` too.
5. Code comments in zip64.rs and verify_container.py say 11.5:1, the spec says 11:1; measured is about 10.8:1 whole
   file. Make them consistent.
6. README sentence on unsigned files: a closed state without a signature is Fail `unsigned` in both, so "factum warns"
   holds for `not_signed` only. Word it accurately.
