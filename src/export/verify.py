#!/usr/bin/env python3
"""Verify a factum case bundle without factum.

    python3 -I verify.py CASE_BUNDLE.zip [--use-bundled-keys]
    python3 -I verify.py EXTRACTED_FOLDER [--use-bundled-keys]

On Windows, use "py" instead of "python3".

Needs Python 3.8 or newer and gpg 2.1 or newer on the PATH; uses only the Python standard library. A gpg in the current
folder or in the bundle's is refused.
Exit code 0: no failures (warnings are possible). Exit code 1: at least one failure.
The format is specified in README.md next to this file.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib

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


# what zipfile raises on bytes that are not as written: RuntimeError for a method or encryption it does not read
ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError, RuntimeError)


def load_bundle(path):
    """The files by name, and every name as it stands in the bundle, repeated ones and folders too. What cannot be read
    is a failure and is left out, so the rest is still checked."""
    files = {}
    listed = []
    if os.path.isdir(path):
        for folder, _, names in os.walk(path):
            for name in names:
                full = os.path.join(folder, name)
                name = os.path.relpath(full, path).replace(os.sep, "/")
                listed.append(name)
                try:
                    with open(full, "rb") as handle:
                        files[name] = handle.read()
                except OSError as e:
                    fail("%s cannot be read (%s)." % (name, e))
    else:
        try:
            with zipfile.ZipFile(path) as bundle:
                for info in bundle.infolist():
                    # orig_filename: filename has lost what follows a NUL, and on Windows its backslashes
                    listed.append(info.orig_filename)
                    if not info.filename.endswith("/"):
                        try:
                            files[info.filename] = bundle.read(info)
                        except ZIP_ERRORS as e:
                            fail("%s cannot be read from the bundle (%s)." % (info.filename, e))
        except ZIP_ERRORS as e:
            fail("The bundle cannot be read as a ZIP (%s)." % e)
    return files, listed


def check_names(listed):
    """Names that make ZIP tools, an extraction and this script see different files."""
    exact = set()
    folded = {}
    for name in listed:
        if re.match(r"/|[A-Za-z]:", name) or ".." in name.split("/") or "\\" in name or "\0" in name:
            fail("%r is not a safe name for a file in a bundle." % name)
        if name in exact:
            fail("%r is in the bundle more than once: ZIP tools may read a different copy than this check." % name)
        exact.add(name)
        first = folded.setdefault(name.casefold(), name)
        if first != name:
            fail("%r and %r differ only in case." % (first, name))


def signature_problem(status, exit_code):
    """Why gpg's status lines are not exactly one good signature; None when they are."""
    keys = [key for key, _ in status]
    if "NO_PUBKEY" in keys:
        return "signing key not in keyring"
    if "REVKEYSIG" in keys:
        return "signing key was revoked"
    if "EXPSIG" in keys:
        return "signature expired"
    if "BADSIG" in keys or "ERRSIG" in keys or "FAILURE" in keys or exit_code != 0:
        return "bad signature"
    good = sum(1 for key in keys if key in ("GOODSIG", "EXPKEYSIG"))
    if good > 1 or keys.count("VALIDSIG") > 1:
        return "more than one signature"
    if good != 1 or keys.count("VALIDSIG") != 1:
        return "bad signature"
    if "EXPKEYSIG" in keys:
        # gpg also says KEYEXPIRED of other subkeys; the last one before EXPKEYSIG is the signing key's
        expiries = [values[0] for key, values in status[:keys.index("EXPKEYSIG")] if key == "KEYEXPIRED"]
        made = dict(status)["VALIDSIG"][2]
        if expiries and expiries[-1].isdigit() and made.isdigit() and int(made) > int(expiries[-1]):
            return "signature made after the signing key expired"
    return None


def own_hash():
    """The SHA-256 of this file: it comes with the bundle it checks, so nothing vouches for it but a copy to compare
    with. factum --version and the release notes give the hash."""
    try:
        with open(os.path.abspath(__file__), "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except (NameError, OSError):
        return "unknown"


def same_folder(one, other):
    return os.path.normcase(os.path.realpath(one)) == os.path.normcase(os.path.realpath(other))


def inside_folder(path, folder):
    path, folder = (os.path.normcase(os.path.realpath(item)) for item in (path, folder))
    return path == folder or path.startswith(os.path.join(folder, ""))


def find_gpg(bundle):
    """gpg as an absolute path, or None with the reason. Windows looks in the current folder before the PATH, for a bare
    name and in shutil.which, and what lies beside a bundle comes from whoever made it: a gpg there is not run."""
    found = shutil.which("gpg")
    if found is None:
        return None, "gpg is not installed or not on the PATH."
    found = os.path.abspath(found)
    folder = os.path.dirname(found)
    if os.path.isdir(bundle):
        beside_bundle = inside_folder(folder, bundle)
    else:
        beside_bundle = same_folder(folder, os.path.dirname(os.path.abspath(bundle)))
    if beside_bundle or same_folder(folder, os.getcwd()):
        return None, "Refusing %s: a gpg in the current folder or the bundle's is not run. Nothing was checked." % found
    return found, None


class Gpg(object):
    def __init__(self, program, home, bundled_keys):
        self.program = program
        self.home = home
        self.bundled_keys = bundled_keys
        self.workdir = tempfile.mkdtemp(prefix="fv-")
        self.signers = {}

    def run(self, args):
        # what is checked comes from the bundle: gpg must never ask for anything
        command = [self.program, "--batch", "--pinentry-mode", "error", "--status-fd", "2"]
        if self.home:
            command += ["--homedir", self.home]
        result = subprocess.run(command + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = []
        for line in result.stderr.decode("utf-8", "replace").splitlines():
            if line.startswith("[GNUPG:] "):
                parts = line[9:].split(" ")
                status.append((parts[0], parts[1:]))
        return result.stdout, status, result.returncode

    def write(self, name, content):
        path = os.path.join(self.workdir, name)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def expired_key_trusted(self, fingerprint):
        """gpg gives no trust level for a signature by an expired key, but the key listing still says what it can: the
        validity of a live primary key whose signing subkey expired, and owner trust, of which only "u" makes a key
        valid. An expired primary key that was valid through certification cannot be told apart."""
        output, _, _ = self.run(["--list-keys", "--with-colons", "--fixed-list-mode", fingerprint])
        for line in output.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                return fields[1] in ("u", "f") or (len(fields) > 8 and fields[8] == "u")
        return False

    def check(self, what, signature, expected_text=None, data=None):
        """Verify a clearsigned block against expected_text, or a detached signature over data."""
        signature_path = self.write("signature.asc", signature)
        if data is None:
            output, status, exit_code = self.run(["--decrypt", signature_path])
        else:
            output, status, exit_code = self.run(["--verify", signature_path, self.write("data", data)])
        reason = signature_problem(status, exit_code)
        if reason:
            fail("%s: signature invalid (%s)." % (what, reason))
            return False
        if expected_text is not None:
            try:
                same = output.decode("utf-8").strip() == expected_text
            except ValueError:
                same = False
            if not same:
                fail("%s: the signature was made over different data." % what)
                return False
        values = dict(status)
        validsig = values["VALIDSIG"]
        # the primary key, as factum reports it; field 0 may be a subkey
        fingerprint = validsig[9] if len(validsig) > 9 and validsig[9] else validsig[0]
        self.signers[fingerprint] = " ".join(values.get("GOODSIG", values.get("EXPKEYSIG"))[1:])
        expired = "EXPKEYSIG" in values
        trust = [key for key, _ in status if key.startswith("TRUST_")]
        trusted = bool(trust) and all(key in TRUSTED for key in trust)
        if not trusted and not self.bundled_keys:
            if not expired:
                fail("%s: signing key %s is not trusted." % (what, fingerprint))
                return False
            if not self.expired_key_trusted(fingerprint):
                fail("%s: signing key %s has expired and is not trusted as far as gpg can tell." % (what, fingerprint))
                return False
        if expired:
            warn("%s: signing key %s has expired since." % (what, fingerprint))
        return True

    def cleanup(self):
        shutil.rmtree(self.workdir, ignore_errors=True)


def old_gpg(program):
    """The version of gpg when it is older than 2.1, which has no --pinentry-mode; None otherwise."""
    result = subprocess.run([program, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    match = re.search(r"(\d+)\.(\d+)\S*", lines[0]) if lines else None
    if match and (int(match.group(1)), int(match.group(2))) < (2, 1):
        return match.group(0)
    return None


def check_manifest(files):
    manifest = files.get("MANIFEST.sha256")
    if manifest is None:
        fail("MANIFEST.sha256 is missing.")
        return
    try:
        text = manifest.decode("utf-8")
    except ValueError:
        fail("MANIFEST.sha256 is not UTF-8 text.")
        text = manifest.decode("utf-8", "replace")
    listed = {}
    for line in text.splitlines():
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


def is_id(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_id_or_none(value):
    return value is None or is_id(value)


def is_name_or_none(value):
    return value is None or isinstance(value, str)


def any_value(_):
    return True


# what the checks need of each row of case.json to go on; any_value is only compared or hashed, whatever it is
CASE_FIELDS = {"id": any_value, "case_file": any_value, "case_name": any_value, "description": any_value,
               "created_utc": any_value, "archived_utc": any_value}
ENTRY_FIELDS = {"id": is_id, "leaf_index": is_id, "corrects_id": is_id_or_none, "evidence_id": is_id_or_none,
                "created_utc": any_value, "format": any_value, "kind": any_value, "payload": any_value,
                "text": any_value, "leaf_hash": any_value, "tree_size": any_value, "root_hash": any_value}
HEAD_FIELDS = {"id": is_id, "tree_size": is_id, "case_file": any_value, "created_utc": any_value, "reason": any_value,
               "root_hash": any_value}
EVIDENCE_FIELDS = {"id": is_id, "description": any_value, "evidence_hash": any_value, "created_utc": any_value,
                   "deleted_utc": any_value}
SIGNED_FIELDS = ("signature_file", "late_signature_file")
EVIDENCE_EVENTS = ("evidence_created", "evidence_edited", "evidence_deleted")


def row_problem(what, row, fields):
    if not isinstance(row, dict):
        return "%s is not an object" % what
    for key, valid in sorted(fields.items()):
        if key not in row:
            return "%s has no %s" % (what, key)
        if not valid(row[key]):
            return "%s has a %s of the wrong type" % (what, key)
    if not all(is_name_or_none(row.get(key)) for key in SIGNED_FIELDS):
        return "%s has a signature file name of the wrong type" % what
    return None


def shape_problem(data):
    """What keeps case.json from being read: it comes with the bundle, so any valid JSON can stand there."""
    if not isinstance(data, dict):
        return "it is not an object"
    for key in ("entries", "tree_heads", "evidence"):
        if not isinstance(data.get(key), list):
            return "%s is not a list" % key
    rows = [("case", data.get("case"), CASE_FIELDS)]
    rows += [("entry %d" % n, row, ENTRY_FIELDS) for n, row in enumerate(data["entries"])]
    rows += [("seal %d" % n, row, HEAD_FIELDS) for n, row in enumerate(data["tree_heads"])]
    rows += [("evidence %d" % n, row, EVIDENCE_FIELDS) for n, row in enumerate(data["evidence"])]
    for what, row, fields in rows:
        problem = row_problem(what, row, fields)
        if problem:
            return problem
    for n, entry in enumerate(data["entries"]):
        payload = entry["payload"]
        if (entry["kind"] == "system" and isinstance(payload, dict) and payload.get("event") in EVIDENCE_EVENTS
                and not is_id(payload.get("evidence_id"))):
            return "entry %d has an evidence id of the wrong type" % n
    return None


def read_case(content):
    """case.json as data, or None and what keeps it from being read."""
    try:
        data = json.loads(content.decode("utf-8"))
        canonical_json(data)  # as deep as the checks will go
    except (ValueError, RecursionError) as e:
        return None, "it is not JSON (%s)" % e
    return data, shape_problem(data)


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
        # surrogatepass: JSON can spell a surrogate, which factum never writes, and a hash that differs says what it is
        leaf = leaf_hash(leaf_data(case["id"], entry).encode("utf-8", "surrogatepass"))
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
    try:
        return check_bundle(argv)
    except Exception as e:  # nothing the checks expect: it must not read as a pass, or as anything but unfinished
        fail("The check did not finish (%s: %s)." % (type(e).__name__, e))
        print("Result: FAIL — the check did not finish, %d failure(s)" % len(FAILS))
        return 1


def check_bundle(argv):
    parser = argparse.ArgumentParser(description="Verify a factum case bundle.")
    parser.add_argument("bundle", help="the bundle ZIP or a folder it was extracted to")
    parser.add_argument("--use-bundled-keys", action="store_true",
                        help="verify against public-keys.asc from the bundle, in a temporary keyring")
    args = parser.parse_args(argv)
    print("verify.py SHA-256 %s" % own_hash())
    print("Compare it with factum --version or the release notes: this script comes with the bundle it checks.")
    program, problem = find_gpg(args.bundle)
    if problem:
        print(problem)
        return 1
    version = old_gpg(program)
    if version:
        print("verify.py needs gpg 2.1 or newer, this is gpg %s. Nothing was checked." % version)
        return 1
    files, listed = load_bundle(args.bundle)
    home = None
    if args.use_bundled_keys:
        home = tempfile.mkdtemp(prefix="fk-")
        subprocess.run([program, "--batch", "--homedir", home, "--import"], input=files.get("public-keys.asc", b""),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    gpg = Gpg(program, home, args.use_bundled_keys)
    accumulator = None
    try:
        print("File names")
        check_names(listed)
        print("Manifest")
        check_manifest(files)
        if "MANIFEST.sha256.asc" in files and "MANIFEST.sha256" in files:
            gpg.check("Manifest", files["MANIFEST.sha256.asc"], data=files["MANIFEST.sha256"])
        else:
            fail("The manifest is not signed.")
        if "case.json" not in files:
            fail("case.json is missing.")
        else:
            data, problem = read_case(files["case.json"])
            if problem:
                fail("case.json cannot be read: %s." % problem)
            else:
                print("Case log")
                accumulator = check_log(data, files, gpg)
                print("Case and evidence details")
                check_metadata(data)
    finally:
        gpg.cleanup()
        if home:
            # beside gpg, for the reason gpg is found the way it is
            gpgconf = os.path.join(os.path.dirname(program), "gpgconf")
            try:
                subprocess.run([gpgconf, "--homedir", home, "--kill", "gpg-agent"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                pass
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
