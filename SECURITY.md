# Security

factum is a forensic tool: a weakness in how it hashes, signs or verifies case logs matters even if it needs local
access to exploit.

Please report vulnerabilities privately through GitHub's [private vulnerability reporting](https://github.com/overcuriousity/factum-rs/security/advisories/new)
rather than in a public issue. Include the factum version, the platform and how to reproduce the problem.

In scope, for example: a modification of a case log, seal or bundle that `factum --verify` or `verify.py` does not
report; a signature shown as valid that is not; reports or the GUI interpreting note text as markup or code.
