#!/usr/bin/env bash
# Writes samples/container/: a signed sample container, the throwaway GPG public key and the throwaway X.509 root
# that signed it. Every key is made here for this purpose only (TEST ONLY) and the private keys are deleted.
# Needs gpg, gpgsm and openssl. Run again when the container format changes.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/samples/container"
# short path: gpg-agent's socket path is limited to ~107 characters
work=$(mktemp -d /tmp/fs-XXXXXX)
export GNUPGHOME="$work/gnupg"
cleanup() {
    gpgconf --kill gpg-agent 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
mkdir -m 700 "$GNUPGHOME"
printf 'allow-loopback-pinentry\nno-allow-mark-trusted\n' > "$GNUPGHOME/gpg-agent.conf"

gpg --batch --passphrase '' --quick-gen-key 'factum sample (TEST ONLY) <sample@factum.invalid>' ed25519 sign never

cd "$work"
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
    -subj '/CN=factum sample root (TEST ONLY)' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj '/CN=factum sample examiner (TEST ONLY)/O=factum'
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n' > ext
openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key -CAcreateserial -out leaf.pem -days 3650 -extfile ext
openssl pkcs12 -export -inkey leaf.key -in leaf.pem -certfile root.pem -out leaf.p12 -passout pass:
gpgsm --batch --pinentry-mode loopback --passphrase '' --import leaf.p12
# fpr records: field 10 the certificate's fingerprint, field 13 its issuer's
fprs=$(gpgsm --batch --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10 ":" $13 }')
root_fpr=$(echo "$fprs" | awk -F: '$1 == $2 { print $1 }')
leaf_fpr=$(echo "$fprs" | awk -F: '$1 != $2 { print $1 }')
echo "$root_fpr" | sed 's/../&:/g; s/:$//' | sed 's/$/ S relax/' > "$GNUPGHOME/trustlist.txt"
gpgconf --kill gpg-agent

mkdir -p src/docs
printf 'hello\n' > src/hello.txt
printf '# Sample\n\nA file in a folder, to show that paths are kept.\n' > src/docs/readme.md
printf 'added after the container was reopened\n' > src/later.txt

mkdir -p "$out"
rm -f "$out/sample.aff4l"
(cd "$root" && cargo run --quiet --example sample_container -- "$out/sample.aff4l" "$GNUPGHOME" "$leaf_fpr" "$work/src")
gpg --batch --armor --export > "$out/gpg-public.asc"
cp root.pem "$out/root.pem"
gpg_fpr=$(gpg --batch --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')
echo "samples/container: sample.aff4l, gpg-public.asc, root.pem"
echo "GPG fingerprint $gpg_fpr: put it into samples/container/README.md"
