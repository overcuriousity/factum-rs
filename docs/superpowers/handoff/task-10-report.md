# Task 10 report: Python container verifier parity

Status: DONE_WITH_CONCERNS (one deliberate verdict disagreement needs a user decision, see Concerns 1).
Base 5a335c7. The session restarted once before any edit; nothing was lost. Worktree stayed on `review-fixes`.

## What was done, per item

All findings were confirmed still present before fixing. `zipfile` and the `Prefix` wrapper are gone: the script now
has its own ZIP reader, a port of zip64.rs, because zipfile cannot make the distinctions the brief asks for.
verify_container.py grew from 579 to about 1240 lines; the port is most of that.

1. Root signatures of a closed current state compared with `factum/history/n/` (`check_root_signatures`), FAIL `history`.
2. and 8. `read_end_records`, `read_archive`, `find_last_end`, `search_back`, `walk_tail` (walk_states), `member_step`,
   `state_end`, `search_tail` ported. Interrupted addition: WARN `trailing_data`. A complete state that cannot be read, or
   junk past the newest end: FAIL `trailing_data`. Nothing past the end: no finding. Task 7's end-of-directory checks
   (directory ends where the records begin, entries behind the count, member behind the directory, ZIP64 locator position,
   local header against directory) all ported.
3. and 8. `read()` reports unreadable members as a FAIL with the code Rust uses for that member. CRC: `member_blocks` reads
   raw data through the local header, then zlib, so hashes finish and "CRC-32 differs" is a finding beside them; metadata
   checks continue. A CRC on a file whose damage is explained by a replacement is suppressed, as in Rust. In-memory reads
   are capped at 1 GiB, as MAX_IN_MEMORY.
4. `file_images` built once per check; no membership test without a replacement.
5. Duplicate names: FAIL `duplicate_member`. Count-versus-size mismatch: FAIL `trailing_data`.
6. Every `replacedBy` is a WARN `replaced_copy` listing the pair, with the comment that only factum checks it against the
   case log.
7. `signature_problem`, `old_gpg`, `expired_key_trusted` and the trust rule copied from verify.py; `--batch --pinentry-mode
   error`; VALIDSIG field 9 (primary fingerprint).
9. `iri_value` decodes `\u`/`\U` and refuses U+0000 to U+0020 and `<>"{}|^` backtick backslash, raw or decoded, including
   surrogates and over-range values; applied to subjects, objects, datatypes and @prefix. Literals gained `\U` and refuse
   unknown escapes. X.509: chain checked with `-attime <signingTime>` (so every certificate must have been valid at
   signing); a second check at the current time gives WARN `x509_expired`; CMS signer compared with the first `.cer`
   certificate, FAIL `x509_mismatch`; `.sig` without `.cer` is WARN `x509_no_certificate`, checked with the signature's
   own certificates. New Turtle properties pass through the parser and into the metadata comparison; tested with a
   non-Unicode path.
10. `history/0` is a FAIL `history`. Gaps are one finding each, walked between neighbouring keys, so no memory grows with a
    huge number. Tested with u32::MAX.

Beyond the listed items, needed for verdicts to agree (the brief's parity requirement): number parsing as Rust does it
(`decimal`: `int()` would accept spaces, underscores and non-ASCII digits, and raises on over 4300 digits); first hash wins
rather than last; IRI and literal objects told apart in `first`, `has_type`, `replacedBy`; the ZIP comment, not
container.description, gives the volume (as Rust's `get_arn`); container.description is read so its CRC counts; UTF-8 read
lossily; ImageStream reading ported chunk by chunk, with Rust's plausibility limits; `sorted(..., key=repr)`, as sorting
triples with a None and a str datatype could raise TypeError on a crafted file.

## Finding codes

Each finding line ends with ` [code]`, so existing "line starts with a check mark" readers still work.
Same as Rust: not_aff4, trailing_data, duplicate_member, history, unsupported, not_checked, turtle_hash, stream_hash,
replaced_copy, not_signed, unsigned, signature_invalid, key_unknown, key_untrusted, key_expired, x509_invalid,
x509_untrusted, x509_expired, x509_mismatch, x509_no_certificate.

Rust codes with no Python equivalent:
- `signature_mismatch`: compares a signature's signed text with an expected payload; a detached signature over the Turtle
  can only be good or bad, and verify_file does not produce it either (`covers_payload` equals `valid`).
- `signed_later`: comes from the case log (`late`).
- `log_mismatch` and `file_missing`: comparisons with the case log; Python has no log.

`x509_untrusted` exists in Python only with `--ca`: without it there is no trust list, so it stays the existing WARN
(`not_checked`, "root not checked"), where Rust would FAIL on a root gpgsm does not trust. That is a matter of what each
machine trusts, not of the file; the parity tests pass `--ca`.

## Tests and results

    cargo test --offline --test containers           124 passed, 0 failed
    cargo test --offline --test sample_container     3 passed
    cargo test --offline --test containers both_verifiers   5 passed
    cargo fmt --check, cargo clippy --offline --all-targets  clean
    python3 -I src/container/verify_container.py samples/container/sample.aff4l --ca samples/container/root.pem --use-carried-key
        Result: OK - 0 failure(s), 0 warning(s)
    python3 -I src/container/verify_container.py samples/container/sample.aff4l
        Result: FAIL - 2 failure(s), 2 warning(s)

The no-flags run FAILs on `key_unknown`, as it did before this task: the TEST ONLY key is not in the keyring here. CI runs
it with `--ca` and `--use-carried-key`, and that is the form that stays OK. The Rust sample test still passes.

New tests in tests/containers.rs (`mod script`), all running `python3 -I` with this build's script against `verify_file`
(no log), each asserting the same level, the expected level, and the finding code on both sides:
- `both_verifiers_agree_on_tampered_containers`, 41 cases on a real gpg-signed container: every one the brief lists
  (hidden member behind a lowered count, duplicate name, trailing bytes, CRC flip on content and on information.turtle,
  root signature swapped against history, history/0, huge history number, forged replacedBy), plus raised count, cut end
  records and cut directory, interrupted addition, CRC of each metadata member, differing local headers, flipped bytes,
  unknown compression method, dropped storage type, swapped key, two signatures, missing signature, removed close, edited
  history, edited metadata, escaped and illegal IRIs, information.hdt, not a ZIP.
- `both_verifiers_agree_on_replacements`, `both_verifiers_agree_on_x509_signatures`,
  `both_verifiers_agree_on_certificates_that_expired`, `both_verifiers_say_so_when_the_key_is_unknown_or_has_expired`.
- `the_script_fails_what_factum_only_warns_is_unsupported` pins the disagreement in Concerns 1.
- `script_reads_the_raw_form_of_paths_that_are_not_unicode`; tests/sample_container.rs
  `this_build_of_the_script_passes_the_sample` (CI's sample step runs the older script the sample carries, so nothing ran
  this build's script on the sample).

`script_warns_about_a_long_interrupted_tail` asserted the old behaviour (junk past the end is a WARN), which the brief
reverses. Replaced by `script_warns_about_an_interrupted_addition` and `script_fails_bytes_no_addition_leaves`.

Mutation checks, each reverted afterwards; the parity tests failed for all: no root comparison, tail always a warning,
chain not checked at the signing time, CRC ignored, history/0 not refused. Helper checks in a scratch script: inflating
with output zlib still holds after its input ends, the size limit, IRI, literal and number parsing. `ast.parse` accepts
the script as Python 3.5 syntax. It was only run on Python 3.14 here; no older interpreter is installed.

Excluded from the parity test because Rust judges them only with the case log: replacedBy against the log
(`a_replacement_the_log_does_not_record_fails`, `a_replacement_is_compared_with_the_log_both_ways`), an older copy
(`live_file_replaced_by_an_older_copy_fails`, `older_copy_verifies_as_earlier_state`), a file missing from the container
(`file_missing_from_container_is_log_mismatch`), certificates against the log
(`x509_certificate_other_than_the_logged_one_fails`, `x509_certificate_of_a_late_signature_is_compared_with_the_log_too`),
folders against the log, tampered `source_raw`, signed-later status.

## Files changed

src/container/verify_container.py, tests/containers.rs, tests/sample_container.rs, CHANGELOG.md, README.md,
docs/superpowers/specs/2026-10-26-evidence-containers-design.md.

## Self-review findings, fixed before commit

- `member_blocks` could lose output zlib still held once input ran out, giving a false CRC failure; split into
  `stored_blocks` and `inflated_blocks`, which keep calling zlib.
- `signing_time` took the last signingTime in the file, which could come from the unsigned attributes; it now reads only
  the signed attributes. It uses `openssl asn1parse` because gpgsm writes BER of indefinite length (seen on the sample).
- Parity table noise reduced; my first expected value for cut end records was wrong (Rust FAILs on purpose, Task 7), and
  the cut-directory case was added beside it. My first "no root comparison" mutation was a syntax error, so it proved
  nothing; redone properly.

## Concerns

1. **One verdict disagreement, kept on purpose; the user should decide.** The brief says the verifiers must agree on every
   tampered container tried. With `version.txt` removed, or another major/minor, Rust gives WARN `unsupported`, "nothing was
   checked", and Python gives FAIL. Aligning would make a stripped container exit 0 with `Result: OK` and nothing checked,
   a regression from today's exit 1. Python keeps FAIL (code `unsupported`) because spec 4.6 limits it to what factum wrote;
   the test pins it and README and spec say so. Same reasoning for `tool=` in version.txt: Rust relaxes `unsigned`,
   `not_signed` and "no stored content" for another tool, and that line is unsigned, so editing it would relax Python too.
   Python ignores `tool=`, so a forged `tool=other` can be FAIL in Python and lower in Rust; from reading the code, not run, and not in the parity test.
   To align instead: change that FAIL to a WARN and return 0.
2. Rust weakness found, same in both, not fixed (out of scope): setting an unknown compression method on a ZipSegment in
   its local header and the directory gives only WARN `not_checked` for that file, though its content is then unverified.
   A bevy gives FAIL. The parity table pins this as Warn. factum wrote the container and its method is known, so this
   could be a FAIL in both.
3. Also the same in both, not fixed: a `factum/history/<n>/` number above u32 is not read as a close at all, so such a
   member is ignored with no finding. Pinned as Ok in the parity table.
4. Foreign constructs Rust reads and Python does not, unchanged: `aff4l:imports`, Maps, `dataStream` in metadata,
   non-layout Turtle. Spec 4.6 says Python need not read them, and factum never writes them. On such a file Python
   fails or misses what it does not read, so verdicts can differ. `blockMapHash` WARN not ported either, for the same
   reason. From reading the code, not run: an `imports` triple added to an open state is FAIL in Rust if the store is bad, and ignored by Python.
5. X.509 expiry detection depends on openssl's error text containing "expired"; any other failure at the current time after
   a pass at signing time is a FAIL `x509_invalid`, which errs safe. `-attime` and `asn1parse` were only run on OpenSSL 3.5.
6. Python's gpg rule differs from Rust's in one case by design of Task 2: with `--use-carried-key`, trust is not required.

## My own calls (for veto)

- Finding codes printed as a ` [code]` suffix; the brief named the codes but not the form.
- `old_gpg`: gpg older than 2.1 gives WARN `not_checked` rather than a FAIL on every signature, since `--pinentry-mode` is
  now always passed. verify.py instead stops; a container's other checks are still worth running.
- WARN `not_checked` for `information.hdt` and for a `.1` part file, ported so verdicts agree.
- A `.cer` with nothing readable is checked with the signature's own certificates, then FAILs `x509_mismatch`, as Rust.
- With `--ca`, a signature good against the carried root but not yours is FAIL `x509_untrusted` (one more openssl run).
- `--use-carried-key` is the only case that reads the history `.pubkey.asc`, as Rust does not read it for older closes.
- New test `this_build_of_the_script_passes_the_sample`, and the pinned-disagreement test.
- README and spec sentences on what the script does and where it differs.

## Fix round 1

Base 7847d5e. Scope widened by the controller to verify.rs, turtle.rs, containers.rs and zip64.rs. All 12 items addressed.
Status: DONE_WITH_CONCERNS (see the concerns below; none blocks).

### Per item

1. **Content swap gets no Fail.** Python: an unknown compression method is FAIL `stream_hash` always. Rust: FAIL
   `stream_hash` when the format is factum's, Warn only for other tools. Pinned row flipped. New test with the log:
   `a_signed_file_in_a_format_nobody_reads_fails_with_the_log_too`.
2. **version.txt split.** A factum layout with no or another version.txt is FAIL `unsupported`, and the check goes on, so
   an evidence byte flipped as well is still found. `container.description` is read before the version decision. Warn
   only for a file with no factum layout. Python keeps its FAIL and returns there. Test:
   `a_signed_container_without_version_txt_is_still_checked` (asserts `unsupported`, `stream_hash`, `report.log`).
3. **Forged `tool=`.** `factum_layout` decides the format: `factum/README.txt`, `verify_container.py`, `SIGNATURE_MEMBERS`
   or anything under `factum/history/`. The `tool=` line is not read any more. Rows and tests with and without the log.
4. **Stray `>`.** Tokenizer returns an error where it did not advance. Tests in turtle.rs. The tokenizer also walks bytes
   now instead of a `Vec<char>`, which would have cost 4 GiB per GiB of Turtle (needed for item 7).
5. **Crafted signature.** `signing_time` builds a `datetime`, which also refuses day 32, hour 25 and second 99, which
   `calendar.timegm` alone would have accepted; `ValueError`/`OverflowError` give None and so FAIL `x509_invalid`. Checked
   directly with six stamps, and months 13 and 00 are in the parity test.
6. **Hangs.** Both: `search_back` passes the record's offset; `read_end_records` no longer scans. Beyond the finding: a
   search still read a whole directory for each record that claimed all the bytes before it, and the comment (up to 64 KiB)
   for each candidate. The directory is now read as far as it holds up, the comment last, and a count above `size / 46` is
   refused first. Test `a_search_does_not_slow_with_the_records_it_tries` covers both shapes. `pem_certificates` is a line
   walk with the same BEGIN-restarts rule as Rust's `pem_blocks`.
7. **Memory.** `MAX_TOTAL_IN_MEMORY` = 4 GiB per run in both. Member reads are limited to what is left; `parse_within`
   (Rust, 128 bytes a token) and `take_memory` (Python, 384 bytes a content line plus the str size) charge the parsed form.
   Python walks lines with a regular expression, so blank lines pass in C. `MemoryError` is a FAIL at each read and parse
   and in `main`. Bevies are not charged: one is held at a time, capped by `MAX_IN_MEMORY`.
8. **History outside a close.** FAIL `history`, one finding with the count and the first name. The second rule is in:
   **proved**, not assumed. In v2.6.0, v2.7.0 and v2.7.1 `commit()` is the only writer of a new `information.turtle`, and
   both its callers pass `SIGNATURE_MEMBERS` as omit. Every state in the sample agrees: three open states have no root
   signature, the two closed ones have all four. A late signature goes to the root only while the state is that close.
9. **Undeclared splits.** `resolve_imports` ported to Python in full, not only the missing store. `expand` refuses whitespace
   in a prefixed name. `#` comments stay a Python FAIL. README and spec state every remaining difference.
10. **Parity table.** 58 rows now. Method and over-u32 rows corrected; rows added for `tool=` and `imports`. The pinned
    disagreement is replaced: a signed container without version.txt now agrees (FAIL in both), and
    `the_script_fails_what_is_not_factums_where_factum_does_not` pins what stays different on truly foreign files.
    `replaced_copy || code == "stream_hash"` replaced by one expected message per case.
11. **container.description removed.** FAIL `history` on a factum layout; Python always. The ZIP comment gives the uuid
    then, so the log still runs (`without_container_description_the_file_fails_and_the_log_is_still_compared`).
12. **Repeated chunks.** Possible, in both: a bevy whose chunks overlap is damage (`chunks_follow_each_other`). Bevy offsets
    are strictly sequential in `store_image_stream`, so nothing factum wrote is affected. Logical size is then bounded by
    the stored bytes at zlib's ratio (about 1000:1): that remains, and is real content to hash.

### Found by my own fuzz, beyond the list

- **Python passed metadata Rust rejects** (13 of 16,000 mutants, `rust=Fail python=Warn`): a statement ending ` ;` with no
  following predicate. `parse_turtle` was line based and never tracked whether a statement had ended. Fixed in 3930c29,
  two rows added. That contradicted a sentence I had just written in the spec, which I then reworded to "is not meant to".
- Rust's `\u` escapes accepted a leading `+` (`from_str_radix`); now hex digits only, as Python.

### Tests

    cargo fmt --check, cargo clippy --offline --all-targets    clean
    cargo test --offline --test containers                     130 passed
    cargo test --offline --test sample_container               3 passed
    cargo test --offline --test export container               4 passed
    cargo test --offline --test container_x509                 11 passed
    cargo test --offline --test container_zip                  5 passed
    cargo test --offline --lib container                       178 passed, 1 ignored
    cargo test --offline --test containers both_verifiers      5 passed
    sample with --ca and --use-carried-key                     Result: OK, 0 failure(s), 0 warning(s)
    sample without flags                                       Result: FAIL, key_unknown, as before this task

Differential fuzz (harness in the scratch folder: fuzz_parity.rs, runfuzz.sh, copied to tests/ only for a run; 16 kinds of
mutation on two real gpg-signed containers, one closed, one open after a close):

| run | code | mutants | agree | declared | disagree | crashes/panics | slow |
|---|---|---|---|---|---|---|---|
| seed 2 | before 3930c29 | 16,000 | 15,833 | not separated (154) | 13 real | 0 | 0 |
| seed 3 | final | 24,000 | 23,774 | 226 | **0** | 0 | 0 |

The 226 are all "valid Turtle outside factum's layout" (comments, single quotes, trailing spaces, object lists): Rust Warn,
Python FAIL, the only failure in each. `rust=Fail python=Warn`: 0. All 3,801 Ok/Ok mutants have unchanged root metadata
(checked by the harness), so none is a shared pass of edited metadata.

Not covered by the fuzz: X.509 (only in the parity table), `--use-carried-key`, and files with no factum layout (0 mutants
lost all of it; pinned by test instead).

Measured on crafted files under `ulimit -v` 9 GiB, release build. All FAIL, none aborted:

| file | size | Python | Rust |
|---|---|---|---|
| three 1 GiB newline turtles | 3 MiB | 6.6 s, 4.2 GiB (was 12.6 GiB) | 5.2 s, 3.2 GiB (aborted before) |
| 1 GiB of short triples | 2 MiB | 2.3 s, 2.1 GiB | 3.2 s, 2.0 GiB |
| one astral character, 2 GiB | 2 MiB | 1.4 s, 1.1 GiB | 1.2 s, 1.1 GiB |
| eight 100 MiB of short triples | | 20 s, 2.1 GiB | 12 s, 2.3 GiB |
| 256 KiB of end records | | 1.2 s (was 74 s) | 0.5 s (47 s in debug) |
| 1 MiB of end records | | 7.6 s (was over 100 s) | 2.9 s |

Python's "dense" and end-record figures are the first, unloaded measurement. `pem_certificates` on 2.2 MiB: 0.02 s.

Mutation checks on the new rules, each reverted, each caught by the row that should catch it: no open-state signature rule,
no check outside closes, Python method a warning again, open last statement, Rust method a warning again.

### Concerns

1. **Budget of 4 GiB can fail a legitimate giant container.** Charges come to about 7 times the Turtle, so about 600 MiB of
   Turtle across all states (my estimate, some 400,000 file versions) is the limit, for example 100,000 files over 4 states.
   It is one constant in each verifier, and the verdict names the reason. The user may prefer another value; a higher one
   raises what a crafted file can cost.
2. Near that limit the verifiers can disagree, as they charge differently (declared in the README).
3. **Shared gap, not fixed:** some members are read by neither verifier. A flipped bit in the root
   `information.turtle.hashes` of a closed state passes both (57 fuzz mutants), as does the history `.pubkey.asc` of a close
   that is not current (52), and `verify_container.py` and `factum/README.txt`. The first is one more name in the root
   comparison, if wanted.
4. **Possible hole, not in the list, not fixed:** a `container.description` naming another uuid, with its CRC fixed, makes
   `find_container_by_uuid` miss, so the log comparison is skipped. Comparing it with the ZIP comment on a factum layout would
   be a few lines in each verifier. From reading the code, not run.
5. A file stripped of its whole layout, version.txt and all, is Warn in Rust when its uuid is not in this log. That follows
   the ruling, and a file whose uuid is in the log now fails (see my own calls).
6. Python stops at `unsupported`, so it reports fewer findings there than Rust, which goes on. Same verdict.
7. Rust's `hash_map` still hashes up to 1 PiB of zeros for a Map, cancellable in the GUI. Not reachable in Python, which does
   not read Maps; on a factum layout an unsigned open state could name one.
8. Only run on Python 3.14 and OpenSSL 3.5; Python 3.5 syntax checked with `ast.parse` only. Windows not run.

### My own calls (for veto)

- `containers.rs`: a file whose uuid is in the log but whose metadata could not be compared is a FAIL `log_mismatch`. Without
  it, a legacy-looking file carrying a logged uuid would stay a Warn, which is what item 2 set out to end.
- The uuid falls back to the ZIP comment in Rust and Python.
- 4 GiB; token and line costs of 128 and 384 bytes.
- `ContainerReport::finding` is `pub(crate)`.
- `read_archive` reads the directory in 64 KiB steps and refuses a count above `size / 46`, beyond what item 6 named.
- `member_bytes_up_to` is public.
- Rust refuses `\u+041`, which it took before.
- Messages for `unsupported` on a factum layout say it was checked all the same.

## Fix round 2

Base 1d6ca31. All 10 items addressed. Status: DONE_WITH_CONCERNS (see below; none blocks).

### Per item

1. **Route to a clean Ok.** (a) New `verify_expected_container(path, expected, ...)`; `verify_container_file` is that with
   `None`. `ContainerAction::Verify(id)` passes the id through `start_container_verification` and `workers::verify_container`.
   `containers_at` also finds logged containers by canonical path. If either expects something and the file names another
   container, or none, it is FAIL `log_mismatch`, and the log comparison does not run. A file at no logged place with nothing
   expected stays valid. (b) On a factum layout, `container.description` differing from the ZIP comment, or a state whose
   Turtle has no `ZipVolume` subject of that name, is FAIL `history` in both. (c) `not_signed` warns in every format; the
   pinned row and six foreign-file tests moved. All three of the reviewer's runs are tests:
   `at_its_logged_place_a_file_cannot_name_itself_out_of_the_log`,
   `a_forged_file_at_a_logged_place_fails_and_nowhere_passes_as_good`, `a_file_asked_for_as_a_container_has_to_be_it`,
   and in the GUI `verify_of_a_container_expects_that_container`.
2. **Search.** One search spends at most `max(16 MiB, file length)`: 1 KiB per record tried, one per directory byte read.
   Same constants in both. `find_last_end` treats the rest as no state. `search_tail` treats running out as an error, so
   a tail that outruns it is FAIL `trailing_data`, not the Warn of an interrupted addition, as a state might lie further back.
3. **Signature size.** `.sig`, `.cer` and `.asc` are read up to 4 MiB in both (`MAX_SIGNATURE_MEMBER`). A public key is not
   capped so: it can be large with its certifications, and it is only compared.
4. **Names.** `expand` and the prefix name refuse `;,<>"'()[]#` and whitespace, and a trailing dot. Beyond the finding: an
   `@prefix` inside an open statement is refused too (Rust refuses it). `both_verifiers_fail_a_type_a_name_cannot_hold`.
5. **Budget.** `max(4 GiB, 64 x compressed size of the metadata members)` in both. "Metadata members" means names starting
   `information.turtle` in any folder, capped at the file's length, as a directory can claim any size. Both now charge one
   formula: bytes of members held, plus 300 bytes per parsed line (triples, subjects and prefixes in Rust, which is the same
   count as content lines in factum's layout). Before, Rust charged tokens and also the text, which it does not copy. The
   300 is measured. Rust keeps a separate transient guard on tokens. `report.graph` is moved, not cloned.
6. **Exhaustion.** New code `too_large`: one finding that names the limit and says it does not mean alteration; the check
   stops there, so no later rule can read anything into what was not read. FAIL on a factum layout, Warn on a foreign file.
   A member above 1 GiB counts as this too. Signature members are outside the budget, being capped and let go at once. The
   open-state rule no longer fires when a close could not be read, also for reasons other than the budget.
7. **Unprotected files.** The script prints its SHA-256 first and says to compare it. README.txt and `readme_text` say neither
   is signed, to run a trusted copy or compare with `factum --version` or the release notes, and that GitHub is only where
   there is a network. No new signed metadata.
8. **Root hashes.** A closed state's root `information.turtle.hashes` goes through `check_turtle_hashes` in both; a missing one
   is a FAIL as well.
9. **Secondary store.** Bad Turtle is FAIL `turtle_hash` on a factum layout, Warn on foreign files; Python FAILs always.
10. **Test.** `a_search_stops_at_its_limit_however_many_records_claim_a_directory` asserts that the limit ended the search, by
    counter, with the unbounded work computed. No clock. `a_state_behind_records_that_are_none_is_found` guards the other side.

### Tests

    cargo fmt --check, cargo clippy --offline --all-targets    clean
    cargo test --offline --test containers                     138 passed
    cargo test --offline --test sample_container               3 passed
    cargo test --offline --test export container               4 passed
    cargo test --offline --test container_x509                 11 passed
    cargo test --offline --test container_zip                  5 passed
    cargo test --offline --lib container                       185 passed, 1 ignored
    cargo test --offline --lib gui::tests::verify              3 passed
    parity table                                               68 rows
    sample with --ca and --use-carried-key                     Result: OK, 0 failure(s), 0 warning(s)
    sample without flags                                       Result: FAIL, key_unknown, as before this task

Differential fuzz, seed 4, code of 99849f1 and d8c3093 (what followed is tests and a wrapped message): 24,000 mutants,
**23,834 agree, 166 declared, 0 disagree, 0 crashes or panics, 0 slow**. Rust Fail with Python not Fail: 0. New mutations:
delimiters in names, an unfinished statement, `@prefix` inside a statement, escapes in IRIs, another uuid as a member. The 166
are all valid Turtle outside factum's layout. All 3,443 Ok/Ok mutants have unchanged root metadata. The 57 flips in the root
hashes file that passed both last round are gone; the 57 flips of this kind left are in the history `.pubkey.asc` of a close
that is not current, which no verdict reads. Same gaps as before: no X.509, no `--use-carried-key`, no mutant without any
layout marker (those are pinned by tests).

Large containers, reviewer's `big.py` (1,212 bytes of Turtle per file). Release build, verdict is the expected `unsigned`, as
big.py writes no signatures. Both verifiers agree on each.

| files x closes | deflate | budget | Python charged | Python peak | Rust peak |
|---|---|---|---|---|---|
| 200,000 x 2 | level 1 | 4.00 GiB (floor) | 2.69 GiB | 3.1 GiB, 57 s | 3.9 GiB, 15 s (4.3 GiB before the move) |
| 500,000 x 2 | level 6 | 7.60 GiB (scaled) | 6.72 GiB | 7.2 GiB, 135 s | 9.9 GiB, 40 s |

Before this round Rust failed the first of these as `too_large` (4.6 GB charged). Compression sets the budget: big.py derives its
three hashes from one value, giving 12.9:1 at level 1 and 14.3:1 at level 6. Independent hashes, as real files have, give 9.2:1
at level 1, and factum writes at `Compression::fast`, which is level 1. So real metadata gets about 7 times its text per stored
copy and is charged about 5.5 per state, which scales with any number of closes.

Crafted files, under the same limit, all FAIL:

| file | Python | Rust |
|---|---|---|
| `quad.py` 40,000 x 1,000 | 1.4 s (was 60 s) | 0.08 s |
| `quad.py` 40,000 x 200,000 | 1.5 s | 0.08 s |
| 4 MiB DER of `05 00` (`asn.py`, was 32 MiB, 3.3 GiB) | 430 MiB, 6 s | |
| three 1 GiB newline turtles | 7.9 s, 4.2 GiB | 12.6 s, 3.2 GiB |
| 1 MiB of end records | 0.5 s | 0.1 s |

Mutation checks, each reverted: 10 rules. The first pass was nine: eight caught (log expectation off, logged place ignored,
description against comment in both, `not_signed` for factum only, whitespace-only names, Python root hashes, a store a
Warn). **One survived:** with Rust's `ZipVolume` check off all 137 tests passed, as my row replaced the volume everywhere and
other rules caught it first. `both_verifiers_fail_metadata_of_another_volume` isolates it; that mutation and the same one in
Python, run afterwards, both fail it.

### Self-review findings, fixed before commit

- My first zip64 test asserted `limit - search <= limit`, which cannot fail for a `u64`. Rewritten to assert the limit ended it.
- My first cut of that test removed the module's helper functions; restored from git.
- The first `check_states` extraction needed `too_many_arguments`; replaced by one `supported` branch.
- `report.graph` cloned the whole newest graph at the end: the peak of the check. Now moved.
- `not_checked` in my spec sentence was too broad last round; `information.hdt` and multi-part files still warn. Reworded.

### Concerns

1. **The budget is an estimate:** real peak was up to 1.3 times the limit in Rust (9.9 GiB at 7.6 GiB) and about 1 in Python.
   An examiner's machine needs that much for a container that size. 300 bytes is Python's measured figure; Rust's graph costs
   about 450 at its peak, tokens included, and I kept one figure so that the two verdicts agree.
2. Near the limit they can still differ: Rust's token guard stops at 96 bytes a token, about 375 a line, while the charge is
   300. Declared in the README.
3. Above the 4 GiB floor, metadata compressing better than about 12:1 with three or more closes could get a false `too_large`:
   predicted from the formula for big.py-like data, not run. Independent hashes do not reach that ratio.
4. **One member is still capped at 1 GiB**, about 880,000 files in one state. That is `too_large` now, not "larger than".
   `Volume::open` refuses the same size, so factum could not have gone on writing such a container either.
5. A real state behind more end-record lookalikes than the search limit is FAIL `not_aff4`, not a fallback to that state. It
   takes more than one per KiB of file, so only crafted files, and it stays a FAIL.
6. A file stripped of its whole layout, at no logged place, with no uuid in this log, is Warn: that is the ruling, and nothing
   can tell it from a foreign file. With a uuid in the log, or at a logged place, it fails.
7. Python stops at `unsupported`, so it lists fewer findings there than Rust. Same verdict.
8. The history `.pubkey.asc` of a close that is not current stays unread. It decides nothing unless `--use-carried-key` is used.
9. The script's message names `factum --version`, whose hash line arrives with Task 11. `verify.py` does not print its hash yet.
10. Only run on Python 3.14 and OpenSSL 3.5; Python 3.5 syntax checked with `ast.parse`. Windows not run.

### My own calls (for veto)

- `too_large` is a Warn on a foreign file, following the ruling's "Warn only for foreign files".
- A member above 1 GiB stops the check as `too_large`, rather than a per-member FAIL.
- The 4 MiB cap also covers `.asc`, not only `.sig` and `.cer`; a public key stays at 1 GiB.
- A missing root `information.turtle.hashes` on a closed state is a FAIL.
- `search_tail` running out is an error rather than "no state".
- `@prefix` inside a statement, a trailing dot and delimiters in a prefix name are refused, beyond the listed characters.
- The search limit charges records as well as directory bytes.
- `ContainerReport::finding` stays `pub(crate)`; `TOO_MUCH` in turtle.rs is public.
- The test seam `BUDGET` in verify.rs, like `FAIL_READ`.

## Fix round 3

Base ab86383. All 9 items addressed. Status: DONE_WITH_CONCERNS (see below; none blocks).

### Corrections to what I reported before

- Round 2 said Rust "does not copy" valid text, and I dropped its charge. That was wrong for what mattered: invalid UTF-8 is
  copied at up to 3 times, and tokens and triples own their strings. It was a regression: 16.8 GiB against 5.6 GiB at 1d6ca31.
- Round 2's "9.2:1" was zlib, not factum's writer. Measured with factum's flate2 at `Compression::fast`, on 50,000 files of
  `gen.py`: near-identical 10.4:1, coarse timestamps 4.3:1, typical 3.4:1. (zlib level 1 on the same: 15.1, 6.3, 5.0.)
  The statement built on it, that real containers scale with any number of closes, still holds, better for most real
  metadata; near-identical files needed the 128.
- The spec's "gains an attacker almost nothing" was false, and "alike in both verifiers" overstated. Both are reworded.

### Per item

1. **Budget stop and the log.** `verify_expected_container` no longer adds `log_mismatch` when the check stopped on the budget.
   That holds only for a Fail `too_large`: on a file with no layout it is a Warn, and skipping there would let a stripped file
   with a logged uuid off with a Warn, so that branch stays a Fail. Test through `verify_expected_container` itself:
   `a_stop_at_the_limit_is_no_finding_of_the_log`.
2. **Text charged as held.** Rust: 3 times the length for bytes that are not UTF-8, before the copy is made; tokens count their
   text; each triple counts its subject, predicate, value and datatype, as it holds a copy of each. A flat line cost could not
   do that, as one long subject repeats in every triple. Python: each line charges `LINE_COST` plus its text at the str's
   width, as the refund of the decoded text only covers that. `MAX_LINE` = 1 MiB refuses a longer line, FAIL `turtle_hash`.
   With text counted, `LINE_COST` is 200 in both, down from 300.
3. **Budget formula.** `clamp(128 x compressed size, 4 GiB, 16 GiB)` in both, constants `METADATA_BUDGET_PER_STORED_BYTE`,
   `MIN_METADATA_BUDGET`, `MAX_METADATA_BUDGET`. Counted: exactly root and `factum/history/<n>/` `information.turtle` and
   `.hashes`, `<n>` canonical and from 1. Test lists seven names that buy nothing, the floor, the ceiling and a lying directory.
4. **NOT SIGNED.** Exit stays 0. The result reads `Result: NOT SIGNED` when the state checked is unsigned, which also covers an
   open state on top of signed closes, not only "nothing signed at all": that state is no more signed. README made true.
5. **End of a search.** `search_gave_up` in both: the message says the search stopped at its limit and that this does not say
   what the file is. Code stays `not_aff4`. Through the log the finding says "nothing could be read of it".
6. **Limit printed** to one decimal, in both.
7. **Spec** says how the two count and where they differ.
8. **Ratios** corrected above, and in the code comments and spec ("about 11:1" / "about 11.5:1" as you gave it; I measured 10.4).
9. **Clone on the log path: gone, by a borrow.** Moving it broke `gui::tests::verify_container_opens_report_window`, as the GUI
   titles its window from `report.graph`, so `as_ref()` it is. No clone, no behaviour change.

### Tests and numbers

    cargo fmt --check, cargo clippy --offline --all-targets    clean
    cargo test --offline --test containers                     142 passed
    cargo test --offline --test sample_container               3 passed
    cargo test --offline --test export container               4 passed
    cargo test --offline --test container_x509                 11 passed
    cargo test --offline --test container_zip                  5 passed
    cargo test --offline --lib container                       191 passed, 1 ignored
    cargo test --offline --lib gui::tests::verify              3 passed
    parity tests (`both_verifiers`)                            7 passed; table 68 rows
    sample with --ca and --use-carried-key                     Result: OK, 0 failure(s), 0 warning(s)
    sample without flags                                       Result: FAIL, key_unknown, as before this task

Differential fuzz, seed 5, on aa04ee5 (what followed is tests only): 24,000 mutants, **23,870 agree, 130 declared, 0 disagree, 0
crashes or panics, 0 slow**. Rust Fail with Python not Fail: 0. One Ok/Ok mutant was flagged as changed metadata; I looked at it.
Both verifiers and Python's `zipfile` inflate that member to exactly the bytes of the newest close with a good CRC: the flip was
in deflate padding, and the harness had compared through the `zip` crate. Not a finding. Gaps as before: no X.509, no
`--use-carried-key`, no mutant without any layout marker. `split.py` was not run: it needs a Rust binary with a budget override.

Memory, under an 18 GB `ulimit -v`, release build, all FAIL `too_large` or stopping there, none aborted. Machine loaded, so
times are rough.

| case | limit | Python peak | Rust peak | before |
|---|---|---|---|---|
| 1 GiB pad, closes of triples (`bomb.py`) | 4.0 GiB | 4.2 GiB, 6 s | 3.8 GiB, 6 s | 64.4 GiB budget, Rust aborted |
| three closes of 1 GiB `\xff` literals, 2.8 MiB | 4.0 GiB | 5.3 GiB, 12 s | 3.1 GiB, 2 s | Rust 16.8 GiB, aborted at 18 |
| three closes of 1 GiB `a` literals | 4.0 GiB | 5.3 GiB, 7 s | 5.2 GiB, 11 s | Python 15.6 GiB |
| three closes of `semis`, 6 MiB | 4.0 GiB | 5.3 GiB, 8 s | 3.7 GiB, 8 s | |

The 78 MiB case: `gen.py` near-identical files, 200,000 x 3 closes, root as a true open state, and rewritten through factum's own
`Appender`, as `zipfile` compresses better and gave 54 MB. That made 73.9 MiB (77.4 MB).

| budget | Python charged | Python peak | Rust peak | verdict, both |
|---|---|---|---|---|
| 9.2 GiB (at 64 it would be 4.6 GiB, the false `too_large`) | 4.2 GiB | 5.2 GiB, 133 s | 6.4 GiB, 51 s | `unsigned` x 3, `not_signed`; no `too_large` |

Mutation checks, each reverted: 8 rules. In the first pass of five, three were caught (log finding on a budget stop, triple text
uncharged, budget counting any name) and two survived: `token text uncharged` and `lossy copy uncharged`, as the later text
charge caught the same input. Isolating tests added (a direct `tokenize` check, and invalid bytes in a comment, where nothing
reaches a token). Both are caught now, as are the three Python rules run after them: line text uncharged, no line cap, OK on
unsigned.

### Self-review findings, fixed before commit

- `take()` on the log path broke the GUI (see 9).
- An edit dropped the indentation inside `if end is None:`, which broke the script; caught by the script tests at once.
- `search_gave_up` runs the search a second time rather than threading a flag through: only on a file that already failed.

### Concerns

1. A crafted file can now take a verifier to about 1.3 times the limit it was given, so up to about 21 GiB at the ceiling of
   16 GiB, if its directory really stores that much: this takes a file of 128 MiB of metadata or more. The ceiling is your
   ruling; the 1.3 is Rust's measured overshoot from round 2, not re-measured at the ceiling.
2. Above the ceiling a genuine container fails `too_large`. At 16 GiB and about 7 times the text per state charged, that is about
   2.3 GiB of Turtle over all states, some 2 million file versions at 1,050 bytes each. Estimated, not run.
3. Near the limit the verifiers can differ, as the spec now says.
4. Python keeps the decoded text's charge when a text fails to parse, so a file with unparsable states reaches `too_large`
   sooner. It is a FAIL either way.
5. A line over 1 MiB fails in Python and reads in Rust: declared. factum writes no such line, as far as I can find.
6. The history `.pubkey.asc` of a close that is not current stays unread; it decides nothing without `--use-carried-key`.
7. Only run on Python 3.14 and OpenSSL 3.5; Python 3.5 syntax checked with `ast.parse`. Windows not run.

### My own calls (for veto)

- `NOT SIGNED` for any unsigned state checked, not only when nothing at all is signed.
- `log_mismatch` stays on a `too_large` that is only a Warn.
- `MAX_LINE` = 1 MiB. `LINE_COST` = 200 in both.
- A 3-times charge for all of a member that is not valid UTF-8, not only for its invalid bytes: such a member is never genuine.
- The wording "nothing could be read of it" in the log finding.
