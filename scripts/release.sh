#!/usr/bin/env bash
# Prepares a release: sets the version in Cargo.toml/Cargo.lock, dates the CHANGELOG section, commits and tags.
# Pushing the tag starts the release workflow, which builds and publishes the binaries.
#
#   scripts/release.sh 2.0.1          then: git push origin main v2.0.1
#
# CHANGELOG.md must have a section "## [Unreleased]" with the changes; it becomes "## [2.0.1] - <today>".
set -euo pipefail

version=${1:?usage: scripts/release.sh <version, e.g. 2.0.1>}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "not a semantic version: $version" >&2; exit 1; }
cd "$(dirname "$0")/.."
[[ -z $(git status --porcelain) ]] || { echo "the working tree is not clean" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/v$version" >/dev/null && { echo "tag v$version exists already" >&2; exit 1; }
grep -q '^## \[Unreleased\]' CHANGELOG.md || { echo "CHANGELOG.md has no '## [Unreleased]' section" >&2; exit 1; }

sed -i.bak "0,/^version = \".*\"/s//version = \"$version\"/" Cargo.toml && rm Cargo.toml.bak
sed -i.bak "s/^## \[Unreleased\]/## [Unreleased]\n\n## [$version] - $(date -u +%Y-%m-%d)/" CHANGELOG.md && rm CHANGELOG.md.bak
cargo update --workspace --quiet
cargo test --locked --quiet
git commit --quiet -am "Release $version"
git tag -a "v$version" -m "factum $version"
echo "Tagged v$version. Publish with: git push origin HEAD v$version"
