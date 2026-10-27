#!/usr/bin/env python3
"""Verify a factum case bundle without factum.

    python3 verify.py CASE_BUNDLE.zip [--use-bundled-keys]
    python3 verify.py EXTRACTED_FOLDER [--use-bundled-keys]

On Windows, use "py" instead of "python3".

Needs Python 3.8 or newer and gpg on the PATH; uses only the Python standard library.
Exit code 0: no failures (warnings are possible). Exit code 1: at least one failure.
The format is specified in README.md next to this file.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

TRUSTED = ("TRUST_FULLY", "TRUST_ULTIMATE")
FAILS = []
WARNINGS = []


def fail(message):
    FAILS.append(message)
    print("  FAIL  " + message)


def warn(message):
    WARNINGS.append(message)
    print("  WARN  " + message)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleAccumulator(object):
    """RFC 9162 tree hash of a growing list of leaves."""

    def __init__(self):
        self.size = 0
        self.subtrees = []  # (leaf count, hash) of perfect subtrees, largest first

    def add(self, leaf):
        size, value = 1, leaf
        while self.subtrees and self.subtrees[-1][0] == size:
            value = node_hash(self.subtrees.pop()[1], value)
            size *= 2
        self.subtrees.append((size, value))
        self.size += 1

    def root(self):
        if not self.subtrees:
            return hashlib.sha256(b"").digest()
        value = self.subtrees[-1][1]
        for _, left in reversed(self.subtrees[:-1]):
            value = node_hash(left, value)
        return value


def leaf_data(case_id, entry):
    return canonical_json({
        "case_id": case_id, "corrects_id": entry["corrects_id"], "created_utc": entry["created_utc"],
        "evidence_id": entry["evidence_id"], "format": entry["format"], "kind": entry["kind"],
        "leaf_index": entry["leaf_index"], "payload": entry["payload"], "text": entry["text"],
    })


def entry_payload(leaf_hex, tree_size, root_hex):
    return canonical_json({"format": 1, "leaf_hash": leaf_hex, "root_hash": root_hex, "tree_size": tree_size})


def seal_payload(case, head):
    return canonical_json({
        "case_file": head["case_file"], "case_id": case["id"], "created_utc": head["created_utc"], "format": 1,
        "reason": head["reason"], "root_hash": head["root_hash"], "tree_size": head["tree_size"],
    })


def load_bundle(path):
    files = {}
    if os.path.isdir(path):
        for folder, _, names in os.walk(path):
            for name in names:
                full = os.path.join(folder, name)
                with open(full, "rb") as handle:
                    files[os.path.relpath(full, path).replace(os.sep, "/")] = handle.read()
    else:
        with zipfile.ZipFile(path) as bundle:
            for name in bundle.namelist():
                if not name.endswith("/"):
                    files[name] = bundle.read(name)
    return files


class Gpg(object):
    def __init__(self, home, bundled_keys):
        self.home = home
        self.bundled_keys = bundled_keys
        self.workdir = tempfile.mkdtemp(prefix="fv-")
        self.signers = {}

    def run(self, args):
        command = ["gpg", "--batch", "--status-fd", "2"]
        if self.home:
            command += ["--homedir", self.home]
        result = subprocess.run(command + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = {}
        for line in result.stderr.decode("utf-8", "replace").splitlines():
            if line.startswith("[GNUPG:] "):
                parts = line[9:].split(" ")
                status[parts[0]] = parts[1:]
        return result.stdout, status

    def write(self, name, content):
        path = os.path.join(self.workdir, name)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def check(self, what, signature, expected_text=None, data=None):
        """Verify a clearsigned block against expected_text, or a detached signature over data."""
        signature_path = self.write("signature.asc", signature)
        if data is None:
            output, status = self.run(["--decrypt", signature_path])
        else:
            output, status = self.run(["--verify", signature_path, self.write("data", data)])
        if "GOODSIG" not in status or "VALIDSIG" not in status:
            reason = "signing key not in keyring" if "NO_PUBKEY" in status else "bad signature"
            fail("%s: signature invalid (%s)." % (what, reason))
            return False
        if expected_text is not None and output.decode("utf-8").strip() != expected_text:
            fail("%s: the signature was made over different data." % what)
            return False
        fingerprint = status["VALIDSIG"][0]
        self.signers[fingerprint] = " ".join(status["GOODSIG"][1:])
        trusted = any(key in TRUSTED for key in status)
        if not trusted and not self.bundled_keys:
            fail("%s: signing key %s is not trusted." % (what, fingerprint))
            return False
        return True

    def cleanup(self):
        shutil.rmtree(self.workdir, ignore_errors=True)


def check_manifest(files):
    manifest = files.get("MANIFEST.sha256")
    if manifest is None:
        fail("MANIFEST.sha256 is missing.")
        return
    listed = {}
    for line in manifest.decode("utf-8").splitlines():
        digest, _, name = line.partition("  ")
        listed[name] = digest
    for name, digest in sorted(listed.items()):
        if name not in files:
            fail("%s is listed in the manifest but missing." % name)
        elif hashlib.sha256(files[name]).hexdigest() != digest:
            fail("%s was modified after export." % name)
    for name in sorted(files):
        if name not in listed and name not in ("MANIFEST.sha256", "MANIFEST.sha256.asc"):
            fail("%s is not listed in the manifest." % name)


def check_signed(gpg, files, what, item, expected):
    """An entry or seal is signed at creation (signature_file) or later (late_signature_file)."""
    name = item.get("signature_file") or item.get("late_signature_file")
    if not name:
        fail("%s is not signed." % what)
        return
    if name not in files:
        fail("%s: signature file %s is missing." % (what, name))
        return
    if gpg.check(what, files[name], expected_text=expected) and not item.get("signature_file"):
        warn("%s was signed later on %s." % (what, item.get("late_signed_utc")))


def check_log(data, files, gpg):
    case = data["case"]
    entries = sorted(data["entries"], key=lambda entry: entry["leaf_index"])
    by_id = dict((entry["id"], entry) for entry in entries)
    accumulator = MerkleAccumulator()
    roots = {0: accumulator.root().hex()}
    for position, entry in enumerate(entries):
        what = "Entry #%d (leaf %d)" % (entry["id"], entry["leaf_index"])
        if entry["leaf_index"] != position:
            fail("%s: expected leaf index %d — entries are missing or out of order." % (what, position))
        leaf = leaf_hash(leaf_data(case["id"], entry).encode("utf-8"))
        if leaf.hex() != entry["leaf_hash"]:
            fail("%s: content does not match its leaf hash (modified)." % what)
        accumulator.add(leaf)
        root = accumulator.root().hex()
        roots[accumulator.size] = root
        if entry["tree_size"] != accumulator.size or entry["root_hash"] != root:
            fail("%s: stored tree head does not match the recomputed tree." % what)
        check_signed(gpg, files, what, entry, entry_payload(leaf.hex(), accumulator.size, root))
        if entry["corrects_id"] is not None:
            target = by_id.get(entry["corrects_id"])
            if (entry["kind"] != "note" or target is None or target["kind"] != "note"
                    or target["leaf_index"] >= entry["leaf_index"]):
                fail("%s: corrects #%s, which is not an earlier note of this case." % (what, entry["corrects_id"]))
    newest = None
    for head in data["tree_heads"]:
        what = "Seal #%d (size %d, %s)" % (head["id"], head["tree_size"], head["reason"])
        if head["tree_size"] > accumulator.size:
            fail("%s: covers %d entries but the log has only %d — entries were removed."
                 % (what, head["tree_size"], accumulator.size))
        elif roots.get(head["tree_size"]) != head["root_hash"]:
            fail("%s: root hash does not match the log." % what)
        else:
            newest = max(newest or 0, head["tree_size"])
        check_signed(gpg, files, what, head, seal_payload(case, head))
    if newest is None:
        warn("No valid seal covers this log.")
    elif newest < accumulator.size:
        warn("%d entries were added after the newest seal." % (accumulator.size - newest))
    return accumulator


def check_metadata(data):
    entries = sorted(data["entries"], key=lambda entry: entry["leaf_index"])
    events = [entry["payload"] for entry in entries if entry["kind"] == "system" and isinstance(entry["payload"], dict)]

    def last(*names):
        found = [payload for payload in events if payload.get("event") in names]
        return found[-1] if found else None

    case = data["case"]
    current = last("case_created", "case_edited")
    if current is None:
        fail("The log has no 'case created' entry.")
    else:
        for key in ("case_file", "case_name", "description"):
            if case[key] != current.get(key):
                fail("Case field '%s' differs from the log." % key)
    created = last("case_created")
    if created is not None and created.get("created_utc") != case["created_utc"]:
        fail("The case creation time differs from the log.")
    state = last("case_archived", "case_reopened")
    expected = state.get("archived_utc") if state and state["event"] == "case_archived" else None
    if case["archived_utc"] != expected:
        fail("The archive state differs from the log.")
    created_events = dict((p.get("evidence_id"), p) for p in events if p.get("event") == "evidence_created")
    deleted_events = dict((p.get("evidence_id"), p) for p in events if p.get("event") == "evidence_deleted")
    # the description: the newest edit, else the creation; a payload before schema 4 has none
    details = dict((p.get("evidence_id"), p.get("details", ""))
                   for p in events if p.get("event") in ("evidence_created", "evidence_edited"))
    rows = dict((row["id"], row) for row in data["evidence"])
    for evidence_id, row in sorted(rows.items()):
        event = created_events.get(evidence_id)
        if event is None:
            fail("Evidence #%d has no 'evidence created' entry." % evidence_id)
            continue
        for key in ("description", "evidence_hash", "created_utc"):
            if row[key] != event.get(key):
                fail("Evidence #%d field '%s' differs from the log." % (evidence_id, key))
        if row.get("details", "") != details.get(evidence_id):
            fail("Evidence #%d field 'details' differs from the log." % evidence_id)
        if row["deleted_utc"] != deleted_events.get(evidence_id, {}).get("deleted_utc"):
            fail("Evidence #%d deletion state differs from the log." % evidence_id)
    for evidence_id in sorted(set(created_events) - set(rows)):
        fail("Evidence #%d is in the log but missing from case.json." % evidence_id)
    for entry in entries:
        if entry["evidence_id"] is not None and entry["evidence_id"] not in created_events:
            fail("Entry #%d refers to evidence #%s, which was not created in this case."
                 % (entry["id"], entry["evidence_id"]))


def tolerant_output():
    # redirected output on Windows uses the ANSI code page; a signer name like "Łukasz" must not abort verification
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def main(argv=None):
    tolerant_output()
    parser = argparse.ArgumentParser(description="Verify a factum case bundle.")
    parser.add_argument("bundle", help="the bundle ZIP or a folder it was extracted to")
    parser.add_argument("--use-bundled-keys", action="store_true",
                        help="verify against public-keys.asc from the bundle, in a temporary keyring")
    args = parser.parse_args(argv)
    if shutil.which("gpg") is None:
        print("gpg is not installed or not on the PATH.")
        return 1
    files = load_bundle(args.bundle)
    home = None
    if args.use_bundled_keys:
        home = tempfile.mkdtemp(prefix="fk-")
        subprocess.run(["gpg", "--batch", "--homedir", home, "--import"], input=files.get("public-keys.asc", b""),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    gpg = Gpg(home, args.use_bundled_keys)
    accumulator = None
    try:
        print("Manifest")
        check_manifest(files)
        if "MANIFEST.sha256.asc" in files and "MANIFEST.sha256" in files:
            gpg.check("Manifest", files["MANIFEST.sha256.asc"], data=files["MANIFEST.sha256"])
        else:
            fail("The manifest is not signed.")
        if "case.json" not in files:
            fail("case.json is missing.")
        else:
            data = json.loads(files["case.json"].decode("utf-8"))
            print("Case log")
            accumulator = check_log(data, files, gpg)
            print("Case and evidence details")
            check_metadata(data)
    finally:
        gpg.cleanup()
        if home:
            subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            shutil.rmtree(home, ignore_errors=True)
    print("")
    if gpg.signers:
        if args.use_bundled_keys:
            print("Signer fingerprints, taken from the bundle's own keys. Compare them with a trusted source:")
        else:
            print("Signers:")
        for fingerprint, user in sorted(gpg.signers.items()):
            print("  %s  %s" % (fingerprint, user))
    size = accumulator.size if accumulator else 0
    root = accumulator.root().hex() if accumulator else "-"
    print("Result: %s — %d failure(s), %d warning(s), %d entries, root %s"
          % ("FAIL" if FAILS else "OK", len(FAILS), len(WARNINGS), size, root))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
