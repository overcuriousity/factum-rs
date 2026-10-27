#!/usr/bin/env python3
"""Verify an evidence container (AFF4-L v1.0) written by factum, without factum.

    python3 verify_container.py <container>.aff4l [--ca ROOT.pem] [--use-carried-key]

Checks every stored file against its MD5, SHA-1 and SHA-256, information.turtle against
information.turtle.hashes, the GPG signature (with the system's gpg) and the X.509 signature (with openssl) of
the current state and of every closed state kept under factum/history/<n>/. Python 3 standard library only.
Every line starts with a check mark: passed, warning or failed. Exit code 0 only if nothing failed.
"""

import argparse
import base64
import collections
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

AFF4 = "http://aff4.org/Schema#"
AFF4L = ("https://aff4.org/Schema/2022/#", "http://aff4.org/Schema/2022/#")
FACTUM = "https://github.com/overcuriousity/factum-rs/schema/2026#"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
ZLIB = "https://www.ietf.org/rfc/rfc1950.txt"
STORED = (AFF4 + "compression/stored", AFF4 + "NullCompressor")
TRUSTED = ("TRUST_FULLY", "TRUST_ULTIMATE")
TURTLE = "information.turtle"
SIGNATURES = ("information.turtle.asc", "information.turtle.pubkey.asc",
              "information.turtle.factum.sig", "information.turtle.factum.cer")
FAILS = []
WARNINGS = []


def tolerant_output():
    """Windows consoles may not print the check marks; never fail on that."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def ok(message):
    print("✓ " + message)


def warn(message):
    WARNINGS.append(message)
    print("⚠ " + message)


def fail(message):
    FAILS.append(message)
    print("✗ " + message)


# --- factum's Turtle layout: @prefix lines, then "<subject>" and one "    predicate object ;" line per triple

PREFIX = re.compile(r"^@prefix (\S*): <([^>]*)> \.$")
LITERAL = re.compile(r'^"((?:[^"\\]|\\.)*)"(?:\^\^(\S+))?$')


def unescape(text):
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            n = text[i + 1]
            if n == "u":
                out.append(chr(int(text[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append({"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_turtle(text):
    """Returns {subject: [(predicate, value, is_iri, datatype)]} for factum's layout."""
    prefixes, graph, subject = {}, {}, None

    def expand(name):
        if name.startswith("<") and name.endswith(">"):
            return name[1:-1]
        prefix, _, local = name.partition(":")
        if prefix not in prefixes:
            raise ValueError("unknown prefix " + prefix)
        return prefixes[prefix] + local

    # only \n ends a line: str.splitlines() would also split at U+2028, U+0085, ...
    for line in text.split("\n"):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        match = PREFIX.match(line)
        if match:
            prefixes[match.group(1)] = match.group(2)
        elif line.startswith("<") and line.endswith(">"):
            subject = line[1:-1]
            graph.setdefault(subject, [])
        elif line.startswith("    ") and subject is not None and line[-2:] in (" ;", " ."):
            predicate, _, obj = line[4:-2].partition(" ")
            predicate = RDF_TYPE if predicate == "a" else expand(predicate)
            literal = LITERAL.match(obj)
            if literal:
                datatype = expand(literal.group(2)) if literal.group(2) else None
                graph[subject].append((predicate, unescape(literal.group(1)), False, datatype))
            else:
                graph[subject].append((predicate, expand(obj), True, None))
        else:
            raise ValueError("not factum's Turtle layout: " + line[:60])
    return graph


def local(iri):
    for namespace in (AFF4,) + AFF4L:
        if iri.startswith(namespace):
            return iri[len(namespace):]
    return None


def values(graph, subject, name):
    return [t for t in graph.get(subject, []) if local(t[0]) == name]


def first(graph, subject, name):
    found = values(graph, subject, name)
    return found[0][1] if found else None


def has_type(graph, subject, name):
    return any(t[0] == RDF_TYPE and local(t[1]) == name for t in graph.get(subject, []))


def first_factum(graph, subject, name):
    for predicate, value, _, _ in graph.get(subject, []):
        if predicate == FACTUM + name:
            return value
    return None


def file_images(graph):
    return [s for s in graph if has_type(graph, s, "FileImage")]


def hashes_of(graph, subject):
    out = {}
    for _, value, _, datatype in values(graph, subject, "hash"):
        if datatype:
            out[datatype.rsplit("#", 1)[-1]] = value.lower()
    return out


def display(graph, arn):
    return first(graph, arn, "originalPathName") or first(graph, arn, "fileName") or arn


# --- content

def image_stream(archive, graph, arn):
    if first(graph, arn, "size") is None:
        raise ValueError("it has no aff4:size")
    size = int(first(graph, arn, "size"))
    chunk_size = int(first(graph, arn, "chunkSize") or 32768)
    per_bevy = int(first(graph, arn, "chunksInSegment") or 2048)
    compression = first(graph, arn, "compressionMethod") or ZLIB
    if compression != ZLIB and compression not in STORED:
        raise NotImplementedError("compression " + compression)
    remaining, bevy = size, 0
    while remaining > 0:
        data = archive.read("%s/%08d" % (arn, bevy))
        index = archive.read("%s/%08d.index" % (arn, bevy))
        for i in range(min(per_bevy, len(index) // 12)):
            offset, length = struct.unpack_from("<QI", index, i * 12)
            chunk = data[offset:offset + length]
            if compression == ZLIB and length != chunk_size:
                chunk = zlib.decompress(chunk)
            chunk = chunk[:min(remaining, chunk_size)]
            yield chunk
            remaining -= len(chunk)
            if remaining <= 0:
                return
        bevy += 1


def zip_segment(archive, arn):
    with archive.open(arn) as member:
        while True:
            block = member.read(1 << 20)
            if not block:
                return
            yield block


def check_files(archive, graph):
    checked = 0
    for arn in file_images(graph):
        name = display(graph, arn)
        if has_type(graph, arn, "ZipSegment"):
            blocks = zip_segment(archive, arn)
        elif has_type(graph, arn, "ImageStream"):
            blocks = image_stream(archive, graph, arn)
        elif first_factum(graph, arn, "metadataOnly") == "true" or first_factum(graph, arn, "symlinkTarget"):
            continue  # metadata only, or a link: nothing stored
        else:
            fail("%s: no stored content, though it is neither metadata only nor a link." % name)
            continue
        digests = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
        size = 0
        try:
            for block in blocks:
                size += len(block)
                for digest in digests.values():
                    digest.update(block)
        except NotImplementedError as e:
            warn("%s: not checked (%s)." % (name, e))
            continue
        except (KeyError, zlib.error, zipfile.BadZipFile, ValueError) as e:
            fail("%s: its content cannot be read (%s)." % (name, e))
            continue
        expected = hashes_of(graph, arn)
        compared = [a for a in digests if a in expected]
        bad = [a for a in compared if digests[a].hexdigest() != expected[a]]
        listed = first(graph, arn, "size")
        if bad:
            fail("%s: the content does not match its %s." % (name, ", ".join(bad)))
        elif listed is not None and int(listed) != size:
            fail("%s: %d bytes stored, %s listed." % (name, size, listed))
        elif not compared:
            warn("%s: no hash to check it against." % name)
        else:
            checked += 1
    return checked


# --- an interrupted addition: bytes after the last complete state

class Prefix(io.RawIOBase):
    """The first `length` bytes of a file, as a file: the container as it was before an interrupted addition."""

    def __init__(self, handle, length):
        self.handle, self.length, self.position = handle, length, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        base = {0: 0, 1: self.position, 2: self.length}[whence]
        self.position = max(0, min(self.length, base + offset))
        return self.position

    def readinto(self, buffer):
        count = min(len(buffer), self.length - self.position)
        self.handle.seek(self.position)
        data = self.handle.read(count)
        buffer[:len(data)] = data
        self.position += len(data)
        return len(data)


def open_container(path):
    """The ZIP of the last complete state; and how many bytes follow it (an interrupted addition)."""
    try:
        return zipfile.ZipFile(path), 0
    except zipfile.BadZipFile:
        pass
    handle = open(path, "rb")
    size = os.path.getsize(path)
    end = size
    block = 1 << 20
    while end > 0:
        start = max(0, end - block)
        handle.seek(start)
        data = handle.read(end - start + 3)
        at = data.rfind(b"PK\x05\x06")
        while at >= 0:
            candidate = start + at
            comment = struct.unpack_from("<H", data, at + 20)[0] if at + 22 <= len(data) else None
            if comment is not None and candidate + 22 + comment <= size:
                try:
                    view = Prefix(handle, candidate + 22 + comment)
                    archive = zipfile.ZipFile(io.BufferedReader(view))
                    return archive, size - (candidate + 22 + comment)
                except zipfile.BadZipFile:
                    pass
            at = data.rfind(b"PK\x05\x06", 0, at)
        end = start
    raise zipfile.BadZipFile("no complete ZIP directory")


# --- signatures

class Gpg(object):
    def __init__(self, carried_key):
        self.available = shutil.which("gpg") is not None
        self.home = tempfile.mkdtemp(prefix="fc-") if carried_key else None
        self.carried_key = carried_key
        self.signers = {}

    def run(self, args, data=None):
        command = ["gpg", "--batch", "--status-fd", "2"]
        if self.home:
            command += ["--homedir", self.home]
        result = subprocess.run(command + args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = {}
        for line in result.stderr.decode("utf-8", "replace").splitlines():
            if line.startswith("[GNUPG:] "):
                parts = line[9:].split(" ")
                status[parts[0]] = parts[1:]
        return status

    def check(self, label, signature, key, data, workdir):
        if not self.available:
            warn("%s: GPG signature not checked (gpg is not installed)." % label)
            return
        if self.home and key:
            self.run(["--import"], key)
        path = os.path.join(workdir, "signature.asc")
        with open(path, "wb") as handle:
            handle.write(signature)
        status = self.run(["--verify", path, "-"], data)
        if "GOODSIG" not in status or "VALIDSIG" not in status:
            reason = "signing key not in the keyring (import information.turtle.pubkey.asc after checking its " \
                     "fingerprint, or use --use-carried-key)" if "NO_PUBKEY" in status else "bad signature"
            fail("%s: GPG signature invalid (%s)." % (label, reason))
            return
        fingerprint = status["VALIDSIG"][0]
        self.signers[fingerprint] = " ".join(status["GOODSIG"][1:])
        if not any(key in TRUSTED for key in status) and not self.carried_key:
            fail("%s: GPG signing key %s is not trusted." % (label, fingerprint))
            return
        ok("%s: GPG signature good (%s)." % (label, fingerprint))

    def cleanup(self):
        if self.home:
            subprocess.run(["gpgconf", "--homedir", self.home, "--kill", "gpg-agent"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            shutil.rmtree(self.home, ignore_errors=True)


def pem_certificates(text):
    return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", text, re.S)


def armored_der(text):
    """The DER of a PEM block of any label (gpgsm writes CMS as BEGIN SIGNED MESSAGE)."""
    lines = [l.strip() for l in text.splitlines()]
    body = []
    inside = False
    for line in lines:
        if line.startswith("-----BEGIN "):
            inside = True
        elif line.startswith("-----END "):
            break
        elif inside and line and ":" not in line:
            body.append(line)
    return base64.b64decode("".join(body))


def check_x509(label, signature, chain, data, ca, workdir):
    if shutil.which("openssl") is None:
        warn("%s: X.509 signature not checked (openssl is not installed)." % label)
        return
    certificates = pem_certificates(chain.decode("utf-8", "replace"))
    if not certificates:
        fail("%s: the X.509 certificate chain is missing." % label)
        return
    paths = {}
    for name, content in (("sig.der", armored_der(signature.decode("utf-8", "replace"))), ("data", data),
                          ("chain.pem", "".join(certificates).encode()),
                          ("root.pem", certificates[-1].encode())):
        paths[name] = os.path.join(workdir, name)
        with open(paths[name], "wb") as handle:
            handle.write(content)
    trusted_root = ca or paths["root.pem"]
    result = subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", paths["sig.der"],
                             "-content", paths["data"], "-CAfile", trusted_root, "-certfile", paths["chain.pem"],
                             "-purpose", "any", "-out", os.devnull],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        fail("%s: X.509 signature invalid (%s)." % (label, result.stderr.decode("utf-8", "replace").strip()[:200]))
        return
    if ca:
        ok("%s: X.509 signature good, chain ends at your root %s." % (label, os.path.basename(ca)))
    else:
        ok("%s: X.509 signature good against the chain it carries." % label)
        warn("%s: root not checked against a trusted certificate (pass --ca ROOT.pem)." % label)


# --- states

def read(archive, name):
    try:
        return archive.read(name)
    except KeyError:
        return None


def check_hashes(label, turtle, hashes):
    if hashes is None:
        fail("%s: information.turtle.hashes is missing." % label)
        return
    try:
        graph = parse_turtle(hashes.decode("utf-8"))
    except ValueError as e:
        fail("%s: information.turtle.hashes cannot be read (%s)." % (label, e))
        return
    found = {}
    for triples in graph.values():
        for _, value, _, datatype in triples:
            if datatype:
                found[datatype.rsplit("#", 1)[-1]] = value.lower()
    actual = {"SHA256": hashlib.sha256(turtle).hexdigest(), "SHA512": hashlib.sha512(turtle).hexdigest()}
    compared = [a for a in actual if a in found]
    if not compared:
        fail("%s: information.turtle.hashes has no SHA-256 or SHA-512." % label)
    elif any(found[a] != actual[a] for a in compared):
        fail("%s: information.turtle does not match information.turtle.hashes." % label)
    else:
        ok("%s: information.turtle matches its %s." % (label, " and ".join(compared)))


def main(argv=None):
    tolerant_output()
    parser = argparse.ArgumentParser(description="Verify an evidence container written by factum.")
    parser.add_argument("container", help="the .aff4l file")
    parser.add_argument("--ca", help="the root certificate (PEM) the X.509 chain must end at")
    parser.add_argument("--use-carried-key", action="store_true",
                        help="verify GPG signatures against the public key the container carries, in a temporary "
                             "keyring; compare the printed fingerprint with one you received separately")
    args = parser.parse_args(argv)
    try:
        archive, tail = open_container(args.container)
    except (OSError, zipfile.BadZipFile) as e:
        fail("%s is not a readable container (%s)." % (args.container, e))
        return 1
    if tail:
        warn("%d bytes after the last complete state (an interrupted addition); the last complete state was checked."
             % tail)
    counts = collections.Counter(archive.namelist())
    for name in sorted(n for n, count in counts.items() if count > 1):
        fail("listed more than once: %s (ZIP tools may read a different copy than this check)." % name)
    version = (read(archive, "version.txt") or b"").decode("utf-8", "replace")
    if "major=2" not in version or "minor=1" not in version:
        fail("Not an AFF4-L v1.0 container (version.txt: %r)." % version.strip())
        return 1
    current = read(archive, TURTLE)
    if current is None:
        fail("information.turtle is missing.")
        return 1
    states = []  # (label, prefix of its members, turtle, closed)
    closes = set()
    for name in archive.namelist():
        match = re.match(r"^factum/history/(\d+)/information\.turtle$", name)
        if match:
            closes.add(int(match.group(1)))
    for missing in sorted(set(range(1, max(closes, default=0))) - closes):
        fail("closed state %d is missing from the container (a removed close)." % missing)
    for n in sorted(closes):
        states.append(("close %d" % n, "factum/history/%d/" % n, read(archive, "factum/history/%d/%s" % (n, TURTLE)),
                       True))
    if not states or states[-1][2] != current:
        states.append(("current (open)", "", current, False))
    else:
        label, prefix, turtle, closed = states[-1]
        states[-1] = (label + " (current)", prefix, turtle, closed)
    gpg = Gpg(args.use_carried_key)
    workdir = tempfile.mkdtemp(prefix="fc-")
    newest = None
    try:
        graphs = []
        for label, prefix, turtle, closed in states:
            print(label.capitalize())
            check_hashes(label, turtle, read(archive, prefix + "information.turtle.hashes"))
            signed = False
            signature = read(archive, prefix + SIGNATURES[0])
            if signature is not None:
                signed = True
                gpg.check(label, signature, read(archive, prefix + SIGNATURES[1]), turtle, workdir)
            x509 = read(archive, prefix + SIGNATURES[2])
            if x509 is not None:
                signed = True
                check_x509(label, x509, read(archive, prefix + SIGNATURES[3]) or b"", turtle, args.ca, workdir)
            if closed and not signed:
                fail("%s: not signed." % label)
            try:
                graphs.append((label, parse_turtle(turtle.decode("utf-8"))))
            except (ValueError, UnicodeDecodeError) as e:
                fail("%s: information.turtle cannot be read (%s)." % (label, e))
        if graphs:
            newest = graphs[-1][1]
            print("Files")
            for label, graph in graphs[:-1]:
                for arn in file_images(graph):
                    if arn not in newest:
                        fail("%s (%s) is no longer listed." % (display(graph, arn), label))
                    elif sorted(graph[arn]) != sorted(newest[arn]):
                        fail("%s: its metadata in %s differs from the newest state." % (display(graph, arn), label))
            checked = check_files(archive, newest)
            ok("%d file(s) checked against their hashes." % checked)
            if not states[-1][3]:
                closed = len(file_images(graphs[-2][1])) if len(graphs) > 1 else None
                listed = len(file_images(newest))
                if closed is None:
                    warn("The container was never closed: none of its %d file(s) is signed." % listed)
                else:
                    warn("%d file(s) added after the last close are not signed yet." % (listed - closed))
    finally:
        gpg.cleanup()
        shutil.rmtree(workdir, ignore_errors=True)
    print("")
    if gpg.signers:
        if args.use_carried_key:
            print("GPG signer fingerprints, taken from the container's own key. Compare them with a trusted source:")
        else:
            print("GPG signers:")
        for fingerprint, user in sorted(gpg.signers.items()):
            print("  %s  %s" % (fingerprint, user))
    print("Result: %s — %d failure(s), %d warning(s)" % ("FAIL" if FAILS else "OK", len(FAILS), len(WARNINGS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
