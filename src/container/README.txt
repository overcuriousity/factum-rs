EVIDENCE CONTAINER (AFF4-L v1.0), written by factum

This file is an AFF4-L logical evidence container: a ZIP64 file holding preserved files together with their
original path, timestamps, size and MD5, SHA-1 and SHA-256 hashes. It opens with any ZIP tool; AFF4-L tools read
the metadata in information.turtle.

What makes it trustworthy
- information.turtle lists every file with its hashes. information.turtle.hashes holds the SHA-256 and SHA-512
  of information.turtle.
- information.turtle.asc is a GPG signature over information.turtle; information.turtle.pubkey.asc is the
  signer's public key. information.turtle.factum.sig / .cer are an X.509 (CMS) signature and its certificate
  chain, when the examiner signed with a certificate too.
- The container can be extended after it was closed. Each closed state stays inside it, signed, under
  factum/history/<n>/, and the content it refers to never moves or changes. A copy handed over earlier verifies
  against the same files.

Verifying without factum (Python 3, no other packages)
  unzip -j <container>.aff4l verify_container.py      (or extract it with any ZIP tool)
  python3 verify_container.py <container>.aff4l
  python3 verify_container.py <container>.aff4l --ca ROOT.pem   (checks the X.509 chain against your root)

GPG signatures are checked with the system's gpg when it is installed, against your keyring: import the
examiner's public key first (gpg --import). Or add --use-carried-key: the script then uses the key the container
carries (information.turtle.pubkey.asc) in a temporary keyring and prints its fingerprint; compare it with one you
received separately.
The script prints one line per check (✓ passed, ⚠ warning, ✗ failed) and exits with 0 only if nothing failed.
