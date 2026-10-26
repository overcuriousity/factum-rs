# Contributing

## Development

```bash
cargo test                                   # everything; gpg and python3 tests run when they are installed
cargo test --no-default-features             # without the GUI
cargo clippy --all-targets && cargo fmt      # CI fails on warnings and unformatted code
FACTUM_SCREENSHOTS=/tmp/shots cargo test --lib gui::   # renders GUI screenshots (needs a GPU or Mesa lavapipe)
FACTUM_DB=/tmp/demo.db cargo run --example demo_db && FACTUM_DB=/tmp/demo.db cargo run -- --gui
```

Layout: `src/` holds the services (one `impl Factum` block per former Python manager: `cases.rs`, `notes.rs`,
`seals.rs`, `verifier.rs`, ...), `src/export/` the reports and bundles, `src/gui/` the egui interface, `tests/` the
integration tests (ports of the factum-notes test suite).

## Compatibility rules

factum must stay compatible with factum-notes and with bundles already handed out:

- Never change `canonical.rs`, `merkle.rs`, `leaf_data`, `entry_signed_payload` or `seal_payload` output. The tests
  pin them byte for byte.
- `src/export/verify.py` is the verifier shipped in every bundle. Change it only together with factum-notes.
- A schema change needs a new `SCHEMA_VERSION`, and databases of the old version must be refused, not migrated
  silently.

## Releases

1. Add the changes under `## [Unreleased]` in `CHANGELOG.md`.
2. `scripts/release.sh X.Y.Z` (sets the version, dates the changelog, runs the tests, commits and tags).
3. `git push origin HEAD vX.Y.Z`. The release workflow builds all platforms, checksums, attestations and the
   vendored source archive, and publishes the GitHub release.

From the GitHub web interface instead: merge a pull request that sets the version in `Cargo.toml` and `Cargo.lock` and
has a `## [X.Y.Z]` section in `CHANGELOG.md`, then Actions → Release → Run workflow on `main` with the tag left
empty. The run tags `main` as `vX.Y.Z` and publishes. A tag of that name without a release (e.g. one pushed on the
wrong commit) is moved; a released version is refused.

To sign `SHA256SUMS`, add the repository secrets `RELEASE_GPG_KEY` (armored secret key) and
`RELEASE_GPG_PASSPHRASE`.
