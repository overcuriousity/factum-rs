# Installing factum on air-gapped machines

There are two ways: install a **release binary** (recommended), or **build from source** with all dependencies
included. Both need one transfer from a machine with internet access (USB stick, data diode, CD).

## 1. Release binary

### On the connected machine

Download what you need from the [release page](https://github.com/overcuriousity/factum-rs/releases/latest):

- the archive for the target platform (see the table in the README), e.g. `factum-x86_64-unknown-linux-gnu.tar.gz`
- `SHA256SUMS` (and `SHA256SUMS.asc` if the release has it)
- `install.sh` (Linux/macOS) or `install.ps1` (Windows)

Or let the script collect and verify everything — all platforms, or only some:

```bash
scripts/airgap-download.sh --version v2.1.4 --target x86_64-unknown-linux-gnu --target x86_64-pc-windows-msvc
# -> factum-v2.1.4-airgap/ and factum-v2.1.4-airgap.tar
```

Optionally check the build provenance before transfer (needs the GitHub CLI):

```bash
gh attestation verify factum-x86_64-unknown-linux-gnu.tar.gz --repo overcuriousity/factum-rs
```

### On the air-gapped machine

Put the files in one folder. The installer checks the archive against `SHA256SUMS` next to it and refuses a mismatch.

**Linux / macOS**

```bash
sh install.sh --archive ./factum-x86_64-unknown-linux-gnu.tar.gz
# system-wide:  sudo sh install.sh --archive ./factum-x86_64-unknown-linux-gnu.tar.gz
# no GUI:       sh install.sh --archive ./factum-cli-x86_64-unknown-linux-musl.tar.gz
```

**Windows** (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Archive .\factum-x86_64-pc-windows-msvc.zip
```

**By hand**, without the installer:

```bash
sha256sum -c --ignore-missing SHA256SUMS      # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
tar -xzf factum-x86_64-unknown-linux-gnu.tar.gz
install -m 755 factum-*/factum /usr/local/bin/factum
```

On Windows: `Get-FileHash -Algorithm SHA256 .\factum-x86_64-pc-windows-msvc.zip` and compare with `SHA256SUMS`,
then extract the ZIP and put `factum.exe` anywhere (it needs no installation).

If the release has a signed `SHA256SUMS.asc`, import the release key once (from a trusted source) and check it:
`gpg --verify SHA256SUMS.asc SHA256SUMS`.

## 2. Build from source offline

`factum-<version>-vendored-source.tar.gz` contains the source and every dependency (`vendor/`), with cargo
configured to use them. You need a Rust toolchain (1.95 or newer) on the build machine — e.g. the offline installer
from <https://forge.rust-lang.org/infra/other-installation-methods.html#standalone-installers>, or your
distribution's `rust`/`cargo` packages from a local mirror — and a C compiler (gcc/clang, or MSVC Build Tools on
Windows) for the bundled SQLite.

```bash
tar -xzf factum-2.1.4-vendored-source.tar.gz
cd factum-2.1.4-vendored-source
cargo build --release --offline --locked                         # GUI + CLI
cargo build --release --offline --locked --no-default-features   # command line only
sh install.sh --help                                             # or copy target/release/factum yourself
```

To vendor a specific commit yourself on a connected machine:

```bash
git clone https://github.com/overcuriousity/factum-rs && cd factum-rs
mkdir -p .cargo && cargo vendor --locked vendor > .cargo/config.toml
cd .. && tar -czf factum-vendored.tar.gz factum-rs
```

## 3. GPG without internet

factum uses the system's `gpg`. Install it from your distribution's offline media or a local mirror
(`gnupg2` on RHEL/Alma/Rocky, `gnupg` on Debian/Ubuntu); on Windows the Gpg4win installer works offline. Keys:

```bash
gpg --import analyst-public-and-secret.asc      # or create one: gpg --quick-gen-key "Name <mail>" ed25519 sign 2y
gpg --edit-key <fingerprint> trust              # 5 = ultimate for your own key, so verification counts it as trusted
factum --list-gpg && factum --set-active gpg <key-id>
```

To verify bundles from colleagues offline, import their public keys and set the trust you have checked; or run
`python3 verify.py bundle.zip --use-bundled-keys` and compare the printed fingerprints with a trusted list.

### X.509 for evidence containers

Containers can be signed with an X.509 certificate as well, through `gpgsm`, which ships with GnuPG (Gpg4win on
Windows). Import the certificate with its private key and mark the root trusted after checking its fingerprint:

```bash
gpgsm --import examiner.p12
echo "<root fingerprint, colon-separated> S relax" >> ~/.gnupg/trustlist.txt
```

factum signs only with a root that is already in the trust list; it never marks one trusted itself. Revocation is
not checked (no CRL or OCSP offline); the verification says so. Recipients check the X.509 signature with
`python3 verify_container.py <container>.aff4l --ca ROOT.pem`, which needs `openssl`.

## 4. Companion

The optional analytical companion needs only an OpenAI- or Anthropic-compatible endpoint reachable on the lab network,
for example a local inference server. No model files ship with factum, and nothing else leaves the machine. For
`https://` endpoints TLS uses the system trust store, so install the lab's CA there. Without a configured endpoint
the companion does nothing.

The companion follows the proxy variables `ALL_PROXY`, `HTTPS_PROXY` and `HTTP_PROXY` (also in lower case): when one
is set, case content goes to that proxy on its way to the endpoint, unless `NO_PROXY` names the endpoint's host
(for example `NO_PROXY=10.0.0.5,inference.lab`). The settings dialog says so while such a variable is set. Unset them,
or list the endpoint in `NO_PROXY`, when the content must not pass through the proxy.

## 5. Updating

Repeat step 1 with the new release. Databases are kept; factum only refuses databases of an older, incompatible
schema and never modifies them.
