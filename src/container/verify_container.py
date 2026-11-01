#!/usr/bin/env python3
"""Verify an evidence container (AFF4-L v1.0) written by factum, without factum.

    python3 -I verify_container.py <container>.aff4l [--ca ROOT.pem] [--use-carried-key]

Checks every stored file against its MD5, SHA-1 and SHA-256, information.turtle against
information.turtle.hashes, the GPG signature (with the system's gpg) and the X.509 signature (with openssl) of
the current state and of every closed state kept under factum/history/<n>/. Python 3 standard library only.
Every line starts with a check mark: passed, warning or failed, and a finding ends with factum's code for it in square
brackets. Exit code 0 only if nothing failed.
"""

import argparse
import base64
import calendar
import collections
import datetime
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

AFF4 = "http://aff4.org/Schema#"
AFF4L = ("https://aff4.org/Schema/2022/#", "http://aff4.org/Schema/2022/#")
FACTUM = "https://github.com/overcuriousity/factum-rs/schema/2026#"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
ZLIB = "https://www.ietf.org/rfc/rfc1950.txt"
STORED = (AFF4 + "compression/stored", AFF4 + "NullCompressor")
TRUSTED = ("TRUST_FULLY", "TRUST_ULTIMATE")
TURTLE = "information.turtle"
HASHES = "information.turtle.hashes"
SIGNATURES = ("information.turtle.asc", "information.turtle.pubkey.asc",
              "information.turtle.factum.sig", "information.turtle.factum.cer")
MAX_CHUNK_SIZE = 64 << 20
MAX_CHUNKS_PER_SEGMENT = 1 << 20
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
MAX_IN_MEMORY = 1 << 30  # of one member
# of a container's metadata, all its states and their graphs together: this much for each byte the file stores of the
# members it reads, as near-identical files compress to about 11:1 with factum's writer ...
METADATA_BUDGET_PER_STORED_BYTE = 128
# ... and never less than this, as what is small always fits ...
MIN_METADATA_BUDGET = 4 << 30
# ... nor more than this, which caps a crafted file whichever way it is built
MAX_METADATA_BUDGET = 16 << 30
# of a signature or a certificate chain: no reason to be more, and openssl makes many times that of it when it prints it
MAX_SIGNATURE_MEMBER = 4 << 20
# what a parsed line holds in memory, its text apart (a triple, a subject, a prefix), as measured on large containers;
# factum charges the same. Its text is charged as it is held, expanded, not as the line writes it
LINE_COST = 200
# factum writes no line near this, and the regular expressions below take many times a line's length to match it
MAX_LINE = 1 << 20
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


def warn(code, message):
    WARNINGS.append(message)
    print("⚠ %s [%s]" % (message, code))


def fail(code, message):
    FAILS.append(message)
    print("✗ %s [%s]" % (message, code))


class Memory(object):
    left = limit = MIN_METADATA_BUDGET


class TooLarge(Exception):
    """The metadata does not fit: the check stops there, which says nothing about the container."""


def take_memory(count):
    if count > Memory.left:
        raise TooLarge()
    Memory.left -= count


def holds(*texts):
    """What these strs hold in memory; None is no text."""
    return sum(sys.getsizeof(text) for text in texts if text is not None)


def decimal(text, limit):
    """A number as factum reads one: digits only, None when there are others or it is above `limit`."""
    match = re.fullmatch(r"\+?0*([0-9]+)", text)
    if not match or len(match.group(1)) > 20:
        return None
    value = int(match.group(1))
    return value if value <= limit else None


# --- factum's Turtle layout: @prefix lines, then "<subject>" and one "    predicate object ;" line per triple

# what ends a name in Turtle, so it is none of a name's: in factum, a list or a comment would start here
NAME_ENDS = r"""\s;,<>"'()\[\]#"""
PREFIX = re.compile(r"^@prefix ([^" + NAME_ENDS + r"]*): <([^>]*)> \.$")
LITERAL = re.compile(r'^"((?:[^"\\]|\\.)*)"(?:\^\^(\S+))?$')
ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "r": "\r", "f": "\f", '"': '"', "'": "'", "\\": "\\"}
NOT_IN_IRI = '<>"{}|^`\\'
LINE = re.compile(r"[^\n]+")
# only \n ends a line: str.splitlines() would also split at U+2028, U+0085, ... Walked, not split: a list of the lines
# can be many times the size of the text, and whitespace is passed without a step here for each line of it
CONTENT_LINE = re.compile(r"^[^\S\n]*\S[^\n]*", re.M)


def uchar(text, at, escaped):
    """The character of a \\u or \\U escape whose digits start at `at`, and where they end."""
    end = at + (4 if escaped == "u" else 8)
    digits = text[at:end]
    code = int(digits, 16) if re.fullmatch(r"[0-9a-fA-F]+", digits) and len(digits) == end - at else None
    if code is None or code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
        raise ValueError("bad \\u escape")
    return chr(code), end


def unescape(text):
    out, i = [], 0
    while i < len(text):
        c = text[i]
        i += 1
        if c == "\\":
            n = text[i:i + 1]
            i += 1
            if n in ("u", "U"):
                c, i = uchar(text, i, n)
            elif n in ESCAPES:
                c = ESCAPES[n]
            else:
                raise ValueError("unknown escape \\" + n)
        out.append(c)
    return "".join(out)


def iri_value(text):
    """What is between < and >: \\u and \\U decoded, and what the grammar does not allow refused, written or escaped.
    Otherwise a forged <aff4://x\\u0041> would be another ARN here than in factum."""
    out, i = [], 0
    while i < len(text):
        c = text[i]
        i += 1
        if c == "\\":
            escaped = text[i:i + 1]
            if escaped not in ("u", "U"):
                raise ValueError("an IRI allows only \\u and \\U escapes")
            c, i = uchar(text, i + 1, escaped)
        if c <= " " or c in NOT_IN_IRI:
            raise ValueError("%r is not allowed in an IRI" % c)
        out.append(c)
    return "".join(out)


def parse_turtle(text):
    """Returns {subject: [(predicate, value, is_iri, datatype)]} for factum's layout."""
    prefixes, graph, subject = {}, {}, None

    def expand(name):
        if name.startswith("<") and name.endswith(">"):
            return iri_value(name[1:-1])
        if re.search("[" + NAME_ENDS + "]", name) or name.endswith("."):
            raise ValueError("not factum's Turtle layout: " + name[:60])
        prefix, _, local = name.partition(":")
        if prefix not in prefixes:
            raise ValueError("unknown prefix " + prefix)
        return prefixes[prefix] + local

    for content in CONTENT_LINE.finditer(text):
        line = content.group().rstrip("\r")
        if len(line) > MAX_LINE:
            raise ValueError("not factum's Turtle layout: a line of %d characters" % len(line))
        take_memory(LINE_COST)
        match = PREFIX.match(line)
        if match and subject is None:
            namespace = iri_value(match.group(2))
            take_memory(holds(match.group(1), namespace))
            prefixes[match.group(1)] = namespace
        elif line.startswith("<") and line.endswith(">") and subject is None:
            subject = iri_value(line[1:-1])
            take_memory(holds(subject))
            graph.setdefault(subject, [])
        elif line.startswith("    ") and subject is not None and line[-2:] in (" ;", " ."):
            predicate, _, obj = line[4:-2].partition(" ")
            predicate = RDF_TYPE if predicate == "a" else expand(predicate)
            literal = LITERAL.match(obj)
            if literal:
                datatype = expand(literal.group(2)) if literal.group(2) else None
                triple = (predicate, unescape(literal.group(1)), False, datatype)
            else:
                triple = (predicate, expand(obj), True, None)
            # the graph keeps the expanded text, however short the line was
            take_memory(holds(triple[0], triple[1], triple[3]))
            graph[subject].append(triple)
            if line.endswith(" ."):
                subject = None
        else:
            raise ValueError("not factum's Turtle layout: " + line[:60])
    if subject is not None:
        raise ValueError("not factum's Turtle layout: the last statement does not end")
    return graph


def parse_metadata(data):
    """The graph of a member's bytes; what they make in memory comes out of the budget. Unreadable bytes are not refused
    here, as in factum: the hashes and signatures say what they are worth."""
    text = data.decode("utf-8", "replace")
    size = sys.getsizeof(text)
    take_memory(size)  # only while it is parsed; what the graph keeps of it is charged as it keeps it
    graph = parse_turtle(text)
    Memory.left += size
    return graph


def local(iri):
    for namespace in (AFF4,) + AFF4L:
        if iri.startswith(namespace):
            return iri[len(namespace):]
    return None


def values(graph, subject, name):
    return [t for t in graph.get(subject, []) if local(t[0]) == name]


def first(graph, subject, name):
    """The first literal; an IRI says nothing here, as in factum."""
    for _, value, is_iri, _ in values(graph, subject, name):
        if not is_iri:
            return value
    return None


def number(graph, subject, name):
    value = first(graph, subject, name)
    return None if value is None else decimal(value, U64_MAX)


def has_type(graph, subject, name):
    return any(t[0] == RDF_TYPE and t[2] and local(t[1]) == name for t in graph.get(subject, []))


def first_factum(graph, subject, name):
    for predicate, value, is_iri, _ in graph.get(subject, []):
        if predicate == FACTUM + name and not is_iri:
            return value
    return None


def factum_iris(graph, subject, name):
    return [t[1] for t in graph.get(subject, []) if t[0] == FACTUM + name and t[2]]


def file_images(graph):
    return [s for s in graph if has_type(graph, s, "FileImage")]


def algorithm_of(datatype):
    return re.split("[#/]", datatype)[-1]


def hash_value(graph, subject, algorithm):
    for _, value, _, datatype in values(graph, subject, "hash"):
        if datatype and algorithm_of(datatype) == algorithm:
            return value.lower()
    return None


def content_identity(graph, arn):
    """What a file and its replacement must share: the hashes and the size."""
    found = {}
    for _, value, _, datatype in values(graph, arn, "hash"):
        for algorithm in ("MD5", "SHA1", "SHA256"):
            if datatype and datatype.endswith("#" + algorithm):
                found.setdefault(algorithm, value)
    return found.get("MD5", ""), found.get("SHA1", ""), found.get("SHA256", ""), number(graph, arn, "size") or 0


def display(graph, arn):
    return first(graph, arn, "originalPathName") or first(graph, arn, "fileName") or arn


# --- the ZIP, read here as in factum: zipfile takes trailing bytes for a comment, entries behind the count for
# nothing, and gives no content when a CRC-32 differs

LOCAL_SIG = b"PK\x03\x04"
CENTRAL_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
EOCD64_SIG = b"PK\x06\x06"
LOCATOR_SIG = b"PK\x06\x07"
HISTORY = b"factum/history/"
# the members the check reads as a state's metadata: the root's, or those of a close
READ_METADATA = re.compile(rb"(?:factum/history/([1-9][0-9]{0,9})/)?information\.turtle(?:\.hashes)?")
EOCD_LEN = 22
LOCATOR_LEN = 20
EOCD64_LEN = 56
# encrypted, sizes in a data descriptor, UTF-8 name: the flags that change how a member is read
FLAGS_COMPARED = 1 | (1 << 3) | (1 << 11)
BUFFER = 1 << 20
CENTRAL_LEN = 46
DIRECTORY_BLOCK = 1 << 16
MIN_SEARCH_LIMIT = 16 << 20  # what one search for an end record may spend, at least: see Search
SEARCH_TRY = 1 << 10  # what it costs to try a record, whatever it turns out to be; directory bytes read count one each

Entry = collections.namedtuple("Entry", "name flags method crc compressed size offset")


class Invalid(Exception):
    """Bytes that are not what they should be; a failing disk is an OSError."""


class Archive(object):
    """A central directory: the members of one state of the file."""

    def __init__(self, handle, entries, comment):
        self.handle, self.entries, self.comment = handle, entries, comment
        self.index = dict((entry.name, entry) for entry in entries)  # of several, the last

    def get(self, name):
        return self.index.get(name.encode("utf-8"))

    def has(self, name):
        return self.get(name) is not None

    def volume(self):
        """The volume ARN the ZIP comment gives (AFF4 Standard v1.0, 5.4)."""
        return self.comment.decode("utf-8", "replace").strip()

    def duplicates(self):
        counts = collections.Counter(entry.name for entry in self.entries)
        return sorted(name.decode("utf-8", "replace") for name, count in counts.items() if count > 1)


def read_at(handle, offset, length):
    handle.seek(offset)
    data = handle.read(length)
    if len(data) != length:
        raise Invalid("the file ends early")
    return data


def u16_at(data, at):
    return struct.unpack_from("<H", data, at)[0]


def u32_at(data, at):
    return struct.unpack_from("<I", data, at)[0]


def u64_at(data, at):
    return struct.unpack_from("<Q", data, at)[0]


def find_end_record(handle, end):
    """Where the end-of-central-directory record that ends exactly at `end` starts."""
    if end < EOCD_LEN:
        raise Invalid("not a ZIP file")
    # the record is followed by a comment of up to 65535 bytes
    window = min(EOCD_LEN + 0xFFFF, end)
    tail = read_at(handle, end - window, window)
    at = tail.rfind(EOCD_SIG)
    while at >= 0 and not (at + EOCD_LEN <= len(tail) and at + EOCD_LEN + u16_at(tail, at + 20) == len(tail)):
        at = tail.rfind(EOCD_SIG, 0, at + 3)
    if at < 0:
        raise Invalid("no end-of-central-directory record")
    return end - window + at


def read_end_records(handle, eocd, end):
    """What the records say whose end-of-central-directory record starts at `eocd` and ends at `end`, as far as they
    agree with where they are in the file: (entry count, directory size, directory offset)."""
    record = read_at(handle, eocd, EOCD_LEN)
    if record[:4] != EOCD_SIG or u16_at(record, 20) != end - eocd - EOCD_LEN:
        raise Invalid("no end-of-central-directory record")
    count, cd_size, cd_offset = u16_at(record, 10), u32_at(record, 12), u32_at(record, 16)
    # where the central directory has to end: at the ZIP64 record, or at the classic one
    cd_end = eocd
    if eocd >= LOCATOR_LEN:
        locator = read_at(handle, eocd - LOCATOR_LEN, LOCATOR_LEN)
        if locator[:4] == LOCATOR_SIG:
            record_offset = u64_at(locator, 8)
            if record_offset + EOCD64_LEN > eocd - LOCATOR_LEN:
                raise Invalid("bad ZIP64 locator")
            record = read_at(handle, record_offset, EOCD64_LEN)
            if record[:4] != EOCD64_SIG:
                raise Invalid("bad ZIP64 end-of-central-directory record")
            # right before the locator: a ZIP nested in a member points at offsets of its own
            if u64_at(record, 4) + record_offset + 12 != eocd - LOCATOR_LEN:
                raise Invalid("bad ZIP64 locator")
            count, cd_size, cd_offset = u64_at(record, 32), u64_at(record, 40), u64_at(record, 48)
            cd_end = record_offset
    if cd_offset + cd_size != cd_end:
        raise Invalid("the central directory does not end where the end records begin")
    if cd_size > 1 << 32:
        raise Invalid("central directory too large")
    if count > cd_size // CENTRAL_LEN:
        raise Invalid("the central directory holds less than its entry count")
    return count, cd_size, cd_offset


def zip64_values(extra, size, compressed, offset):
    """The 0xFFFFFFFF fields, replaced with the values of the ZIP64 extra field."""
    at = 0
    fields = [size, compressed, offset]
    while at + 4 <= len(extra):
        kind, length = u16_at(extra, at), u16_at(extra, at + 2)
        body = extra[at + 4:at + 4 + length]
        if kind == 1:
            used = 0
            for index, value in enumerate(fields):
                if value == 0xFFFFFFFF and used + 8 <= len(body):
                    fields[index] = u64_at(body, used)
                    used += 8
        at += 4 + length
    return fields


class Search(object):
    """What one search of a file of `length` bytes may spend. Each record costs little, but a crafted file can hold many
    that each claim the same long directory; a complete state is never that far from the end. Linear in the file, so
    what a real container costs is not touched, and whatever a file holds a search ends."""

    def __init__(self, length):
        self.left = max(MIN_SEARCH_LIMIT, length)


def read_archive(handle, end):
    """The central directory whose end-of-central-directory record ends exactly at `end`."""
    return read_archive_at(handle, find_end_record(handle, end), end)


def read_archive_at(handle, eocd, end, search=None):
    """read_archive for a record whose start is known. The directory is read as far as it holds up, and only then the
    comment: a search may try thousands of records, and each of them may claim all that lies before it. Directory bytes
    come out of `search`."""
    count, cd_size, cd_offset = read_end_records(handle, eocd, end)
    directory = bytearray()

    def read_directory(needed):
        while len(directory) < needed and len(directory) < cd_size:
            held = len(directory)
            block = min(cd_size - held, DIRECTORY_BLOCK)
            if search is not None:
                if block > search.left:
                    raise Invalid("the search for a complete state went on too long")
                search.left -= block
            directory.extend(read_at(handle, cd_offset + held, block))

    entries = []
    at = 0
    for _ in range(count):
        read_directory(at + CENTRAL_LEN)
        if at + CENTRAL_LEN > len(directory) or directory[at:at + 4] != CENTRAL_SIG:
            raise Invalid("bad central directory entry")
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", directory, at + 28)
        following = at + CENTRAL_LEN + name_len + extra_len + comment_len
        read_directory(following)
        if following > len(directory):
            raise Invalid("bad central directory entry")
        flags, method = struct.unpack_from("<HH", directory, at + 8)
        crc, compressed, size = struct.unpack_from("<III", directory, at + 16)
        name = bytes(directory[at + 46:at + 46 + name_len])
        extra = directory[at + 46 + name_len:at + 46 + name_len + extra_len]
        size, compressed, offset = zip64_values(extra, size, compressed, u32_at(directory, at + 42))
        if offset >= cd_offset:
            raise Invalid("a member lies behind the central directory")
        entries.append(Entry(name, flags, method, crc, compressed, size, offset))
        at = following
    # an entry behind the count is one this check would not see, and other ZIP readers would
    if at != cd_size:
        raise Invalid("the central directory holds more than its entry count")
    return Archive(handle, entries, read_at(handle, eocd + EOCD_LEN, end - eocd - EOCD_LEN))


def is_state(handle, end):
    try:
        read_archive(handle, end)
        return True
    except Invalid:
        return False


def is_state_at(handle, eocd, end, search):
    try:
        read_archive_at(handle, eocd, end, search)
        return True
    except Invalid:
        return False


def search_back(handle, start, length, search, visit):
    """Offers each end-of-central-directory record in start..length, newest first, as (where it starts, where it ends),
    to `visit`, until it answers. Stops, as if there were no more, when `search` is spent."""
    # backwards in blocks that overlap by 3 bytes, so a signature across a block boundary is found
    block_end = length
    while block_end >= start + 4:
        block_start = max(block_end - BUFFER, start)
        block = read_at(handle, block_start, block_end - block_start)
        at = block.rfind(EOCD_SIG)
        while at >= 0:
            offset = block_start + at
            if offset + EOCD_LEN <= length:
                if search.left < SEARCH_TRY:
                    return None
                search.left -= SEARCH_TRY
                candidate = offset + EOCD_LEN + u16_at(read_at(handle, offset + 20, 2), 0)
                found = visit(offset, candidate) if candidate <= length else None
                if found is not None:
                    return found
            at = block.rfind(EOCD_SIG, 0, at + 3)
        if block_start == start:
            break
        block_end = block_start + 3
    return None


def search_gave_up(handle, length):
    """Whether a search through this file that found no state stopped at its limit, not at the start of the file: then
    that it found none says nothing about what the file is."""
    search = Search(length)
    search_back(handle, 0, length, search, lambda eocd, end: end if is_state_at(handle, eocd, end, search) else None)
    return search.left < SEARCH_TRY


def find_last_end(handle, length):
    """The end of the newest complete state: the file's length if it ends with one, else the nearest
    end-of-central-directory record before the end whose central directory reads (an interrupted addition)."""
    if is_state(handle, length):
        return length
    search = Search(length)
    return search_back(handle, 0, length, search,
                       lambda eocd, end: end if is_state_at(handle, eocd, end, search) else None)


def signature_at(handle, pos, length, signatures):
    """Whether one of `signatures` starts at `pos`, whole or cut short by the end of the file."""
    start = read_at(handle, pos, min(length - pos, 4))
    return any(signature.startswith(start) for signature in signatures)


def header_or_end_at(handle, pos, length):
    return signature_at(handle, pos, length, (LOCAL_SIG, CENTRAL_SIG))


def is_bevy_name(name):
    """Whether a member is named as the bevies of an ImageStream are: <stream>/%08d."""
    if b"/" not in name:
        return False
    number_part = name.rpartition(b"/")[2]
    return len(number_part) >= 8 and number_part.isdigit()


MEMBER, STATE, INTERRUPTED, UNKNOWN = "member", "state", "interrupted", "unknown"


def member_step(handle, pos, length):
    """The member whose local header is at `pos`: where the next one starts. Interrupted when it does not end in the
    file, and when it has no compressed size yet: factum writes it after the data. Only a stored member without
    content has those same zeros when finished, and a bevy, which holds evidence, never is one."""
    if pos + 30 > length:
        return INTERRUPTED, None
    header = read_at(handle, pos, 30)
    name_len, extra_len = struct.unpack_from("<HH", header, 26)
    data = pos + 30 + name_len + extra_len
    compressed = u32_at(header, 18)
    if compressed == 0xFFFFFFFF:
        if data > length:
            return INTERRUPTED, None
        extra = read_at(handle, pos + 30 + name_len, extra_len)
        size, compressed, _ = zip64_values(extra, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        if compressed == 0xFFFFFFFF:
            return UNKNOWN, None
        if compressed == 0:
            empty = u16_at(header, 8) == 0 and size == 0 and u32_at(header, 14) == 0
            name = read_at(handle, pos + 30, name_len)
            if not empty or is_bevy_name(name) or not header_or_end_at(handle, data, length):
                return INTERRUPTED, None
    following = data + compressed
    return (MEMBER, following) if following <= length else (INTERRUPTED, None)


def state_end(handle, pos, length):
    """Where the state whose central directory starts at `pos` ends. None for a directory that runs into the end of
    the file (interrupted while it was written); a complete one that cannot be read is an error."""
    unreadable = Invalid("the central directory at offset %d cannot be read" % pos)
    at = pos
    while at + 46 <= length:
        entry = read_at(handle, at, 46)
        if entry[:4] != CENTRAL_SIG:
            break
        at += 46 + sum(struct.unpack_from("<HHH", entry, 28))
    if at >= length:
        return None
    if not signature_at(handle, at, length, (CENTRAL_SIG, EOCD64_SIG, EOCD_SIG)):
        raise unreadable
    if at + 4 > length:
        return None
    signature = read_at(handle, at, 4)
    if signature == CENTRAL_SIG:
        return None
    if signature == EOCD64_SIG:
        at += EOCD64_LEN + LOCATOR_LEN
    if at >= length:
        return None
    if not signature_at(handle, at, length, (EOCD_SIG,)):
        raise unreadable
    if at + EOCD_LEN > length:
        return None
    # only the comment missing: that its length is damaged cannot be ruled out
    end = at + EOCD_LEN + u16_at(read_at(handle, at, EOCD_LEN), 20)
    if end <= length and is_state(handle, end):
        return end
    raise unreadable


def search_tail(handle, start, length):
    """Searches the bytes the walk could not pass: the end of the newest state among them, if any; an error when end
    records there fit their place in the file but their directory cannot be read."""
    search = Search(length)

    def visit(eocd, end):
        if is_state_at(handle, eocd, end, search):
            return end
        try:
            read_end_records(handle, eocd, end)
        except Invalid:
            return None  # the end of a file nested in the evidence: its offsets count from its own start
        raise Invalid("the state ending at offset %d is complete but cannot be read" % end)

    found = search_back(handle, start, length, search, visit)
    # given up, not done: a state may lie further back, so this is not what an interrupted addition leaves
    if found is None and search.left < SEARCH_TRY:
        raise Invalid("more end records after the last complete state than can be searched")
    return found


def walk_tail(handle, start, length):
    """Walks the members after the state ending at `start`, by their local headers. Raises Invalid when the bytes are
    more than an interrupted addition leaves: a complete state that cannot be read, or what no crash of the writer
    leaves."""
    pos = start
    while pos < length:
        if pos + 4 > length:
            step = (INTERRUPTED if header_or_end_at(handle, pos, length) else UNKNOWN), None
        else:
            signature = read_at(handle, pos, 4)
            if signature == LOCAL_SIG:
                step = member_step(handle, pos, length)
            elif signature == CENTRAL_SIG:
                end = state_end(handle, pos, length)
                step = (STATE, end) if end is not None else (INTERRUPTED, None)
            else:
                step = UNKNOWN, None
        if step[0] in (MEMBER, STATE):
            pos = step[1]
            continue
        end = search_tail(handle, pos, length)
        if end is not None:
            pos = end
        elif step[0] == UNKNOWN:
            raise Invalid("the bytes at offset %d are no ZIP header" % pos)
        else:
            return


def stored_blocks(handle, position, remaining):
    while remaining > 0:
        handle.seek(position)
        block = handle.read(min(BUFFER, remaining))
        if not block:
            return
        position += len(block)
        remaining -= len(block)
        yield block


def inflated_blocks(blocks, size):
    """No more than the size the directory gives, whatever the data inflates to."""
    inflate = zlib.decompressobj(-15)
    raw, ended = b"", False
    while size > 0 and not inflate.eof:
        if not raw and not ended:
            raw = next(blocks, None)
            ended = raw is None
            raw = raw or b""
        # also with no input left: zlib may still hold output
        block = inflate.decompress(raw, min(BUFFER, size))
        raw = inflate.unconsumed_tail
        if not block and not raw and ended:
            return
        size -= len(block)
        yield block


def member_blocks(handle, entry, differs):
    """The content of a member, in blocks. Its local header has to agree with the central directory: ZIP readers go by
    one or the other. Once read to its end, a CRC-32 that differs puts the member's name in `differs`: the content
    still counts, what is wrong may be the field."""
    shown = entry.name.decode("utf-8", "replace")
    header = read_at(handle, entry.offset, 30)
    if header[:4] != LOCAL_SIG:
        raise Invalid("no local header for %s" % shown)
    flags, method = struct.unpack_from("<HH", header, 6)
    name_len, extra_len = struct.unpack_from("<HH", header, 26)
    if (read_at(handle, entry.offset + 30, name_len) != entry.name or method != entry.method
            or (flags ^ entry.flags) & FLAGS_COMPARED):
        raise Invalid("the local header of %s differs from the central directory" % shown)
    if entry.method not in (0, 8):
        raise NotImplementedError("compression method %d of %s" % (entry.method, shown))
    blocks = stored_blocks(handle, entry.offset + 30 + name_len + extra_len, entry.compressed)
    if entry.method == 8:
        blocks = inflated_blocks(blocks, entry.size)
    crc = 0
    for block in blocks:
        crc = zlib.crc32(block, crc)
        yield block
    if crc != entry.crc:
        differs.append(shown)


def member_bytes(archive, entry, limit):
    """A member's content in memory, refused when it is larger than `limit`, and whether it has the directory's
    CRC-32."""
    differs, blocks, held = [], [], 0
    for block in member_blocks(archive.handle, entry, differs):
        held += len(block)
        if held > limit:
            raise Invalid("%s is larger than %d bytes" % (entry.name.decode("utf-8", "replace"), limit))
        blocks.append(block)
    return b"".join(blocks), not differs


def read_limited(archive, name, code, limit):
    """A member's content; None when it is not listed. One that cannot be read is a failure, not an error, and so is
    a CRC-32 that differs: the content then still counts, and the checks say the rest."""
    entry = archive.get(name)
    if entry is None:
        return None
    try:
        data, crc_matches = member_bytes(archive, entry, limit)
    except (Invalid, OSError, zlib.error, NotImplementedError) as e:
        fail(code, "%s cannot be read (%s)." % (name, e))
        return None
    message = "%s: CRC-32 differs from the central directory." % name
    if not crc_matches and message not in FAILS:
        fail(code, message)
    return data


def read(archive, name, code):
    """read_limited for what is held for the rest of the check, so it comes out of the budget."""
    entry = archive.get(name)
    if entry is not None and entry.size > MAX_IN_MEMORY:
        raise TooLarge()
    data = read_limited(archive, name, code, MAX_IN_MEMORY)
    if data is not None:
        take_memory(len(data))
    return data


def read_signature(archive, name, code):
    """A signature member: looked at once and let go, so the budget has no part in it, and there is no reason for one to
    be large. A public key can be, with its certifications."""
    return read_limited(archive, name, code, MAX_IN_MEMORY if name.endswith(SIGNATURES[1]) else MAX_SIGNATURE_MEMBER)


def is_read_metadata(name):
    """Whether the check reads a member of this name: a close's number is 32 bits, others are no close of it."""
    match = READ_METADATA.fullmatch(name)
    return match is not None and int(match.group(1) or 0) <= U32_MAX


def metadata_budget(archive, length):
    """For a file of `length` bytes: a directory can claim any compressed size, the file holds no more than it holds.
    What counts is what the check reads, so stored bytes that nothing reads buy nothing."""
    stored = sum(entry.compressed for entry in archive.entries if is_read_metadata(entry.name))
    return max(MIN_METADATA_BUDGET, min(min(stored, length) * METADATA_BUDGET_PER_STORED_BYTE, MAX_METADATA_BUDGET))


# --- content

def member_name(arn, volume):
    """The ZIP member that holds an ARN (AFF4 Standard v1.0, 5.1 and 5.2): below the volume's ARN, the rest of the
    ARN; any other ARN under its scheme and GUID URL-encoded (aff4%3A%2F%2F<guid>/...)."""
    if volume and arn.startswith(volume + "/"):
        return arn[len(volume) + 1:]
    if arn.startswith("aff4://"):
        return "aff4%3A%2F%2F" + arn[len("aff4://"):]
    return arn


def bevy_member(archive, name, differs):
    entry = archive.get(name)
    if entry is None:
        raise Invalid("member %s is missing" % name)
    try:
        data, crc_matches = member_bytes(archive, entry, MAX_IN_MEMORY)
    except NotImplementedError as e:
        raise Invalid(str(e))  # part of a stream: damage, not a file stored in a form not read
    if not crc_matches:
        differs.append(name)
    return data


def chunks_follow_each_other(index):
    """Whether each chunk starts where the one before it ended or after that, as every writer stores them. An index that
    repeats a chunk would have a few stored bytes stand for terabytes to hash."""
    end = 0
    for offset, length in struct.iter_unpack("<QI", index[:len(index) // 12 * 12]):
        if offset < end:
            return False
        end = offset + length
    return True


def image_stream(archive, graph, arn, differs):
    size = number(graph, arn, "size")
    if size is None:
        raise ValueError("it has no aff4:size")
    chunk_size = number(graph, arn, "chunkSize")
    chunk_size = 32768 if chunk_size is None else chunk_size
    per_bevy = number(graph, arn, "chunksInSegment")
    per_bevy = 2048 if per_bevy is None else per_bevy
    methods = values(graph, arn, "compressionMethod")
    compression = methods[0][1] if methods else ZLIB
    if compression != ZLIB and compression not in STORED:
        raise NotImplementedError("compression " + compression)
    # values from a container's metadata: implausible ones are refused before anything is read for them
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE or not 1 <= per_bevy <= MAX_CHUNKS_PER_SEGMENT:
        raise ValueError("implausible chunk size %d or chunks per segment %d" % (chunk_size, per_bevy))
    member = member_name(arn, archive.volume())
    position, loaded, data, index = 0, None, b"", b""
    while position < size:
        chunk_number = position // chunk_size
        bad = ValueError("chunk %d of %s is damaged" % (chunk_number, arn))
        bevy = chunk_number // per_bevy
        if bevy != loaded:
            data = bevy_member(archive, "%s/%08d" % (member, bevy), differs)
            index = bevy_member(archive, "%s/%08d.index" % (member, bevy), differs)
            if not chunks_follow_each_other(index):
                raise ValueError("bevy %d of %s is damaged: its chunks overlap" % (bevy, arn))
            loaded = bevy
        at = (chunk_number % per_bevy) * 12
        if at + 12 > len(index):
            raise bad
        offset, length = struct.unpack_from("<QI", index, at)
        if offset + length > len(data):
            raise bad
        chunk = data[offset:offset + length]
        if compression == ZLIB and length != chunk_size:
            # never more than one chunk, whatever the compressed data inflates to
            try:
                chunk = zlib.decompressobj().decompress(chunk, chunk_size + 1)
            except zlib.error:
                raise bad
            if len(chunk) > chunk_size:
                raise bad
        chunk = chunk[:min(size - chunk_number * chunk_size, chunk_size)]  # the last chunk may be padded
        start = position % chunk_size
        if start >= len(chunk):
            raise ValueError("%s ends early" % arn)
        yield chunk[start:]
        position += len(chunk) - start


def zip_segment(archive, arn, differs):
    entry = archive.get(member_name(arn, archive.volume()))
    if entry is None:
        raise Invalid("its ZIP member is missing")
    for block in member_blocks(archive.handle, entry, differs):
        yield block


def content_blocks(archive, graph, arn, differs):
    """The blocks of what is stored for `arn`; None when nothing is."""
    if has_type(graph, arn, "ZipSegment"):
        return zip_segment(archive, arn, differs)
    if has_type(graph, arn, "ImageStream"):
        return image_stream(archive, graph, arn, differs)
    return None


def check_content(graph, arn, name, blocks):
    """Hashes a file's blocks: what is wrong with them. Missing hashes are a warning of their own."""
    digests = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
    size = 0
    for block in blocks:
        size += len(block)
        for digest in digests.values():
            digest.update(block)
    problems, compared = [], 0
    for algorithm in sorted(digests):
        expected = hash_value(graph, arn, algorithm)
        if expected is not None:
            compared += 1
            if digests[algorithm].hexdigest() != expected:
                problems.append("%s: the content does not match its %s." % (name, algorithm))
    listed = number(graph, arn, "size")
    if listed is not None and listed != size:
        problems.append("%s: %d bytes stored, %d listed." % (name, size, listed))
    if not compared:
        warn("not_checked", "%s: no hash to check it against." % name)
    return problems


def check_files(archive, graph):
    checked = 0
    images = file_images(graph)
    listed = set(images)
    for arn in images:
        name = display(graph, arn)
        replacements = factum_iris(graph, arn, "replacedBy")
        problems, differs = [], []
        try:
            blocks = content_blocks(archive, graph, arn, differs)
            if blocks is not None:
                problems = check_content(graph, arn, name, blocks)
                checked += 1
            elif first_factum(graph, arn, "metadataOnly") != "true" \
                    and first_factum(graph, arn, "symlinkTarget") is None:
                problems = ["%s: no stored content, though it is neither metadata only nor a link." % name]
        except NotImplementedError as e:
            # factum stores files in one way, so another is no format it cannot read: the hashes must not be skipped by
            # naming one
            problems = ["%s: not checked (%s)." % (name, e)]
        except (Invalid, OSError, zlib.error, ValueError) as e:
            problems = ["%s: its content cannot be read (%s)." % (name, e)]
        if replacements and problems:
            # a damaged copy that was added again (Add Again) is a known fact: a warning, not a failure, but only when
            # the replacement is a file of this state with the same hashes and size; that explains its CRC-32 as well
            by = replacements.pop(0)
            if by in listed and content_identity(graph, by) == content_identity(graph, arn):
                warn("replaced_copy", "%s: the content does not match its hashes; replaced by a copy added again (%s)."
                     % (name, display(graph, by)))
            else:
                fail("stream_hash", "%s: the content does not match its hashes; replaced by a copy with different "
                                    "content (%s)." % (name, display(graph, by)))
        else:
            for problem in problems:
                fail("stream_hash", problem)
            for member in differs:
                fail("stream_hash", "%s: CRC-32 differs from the central directory (%s)." % (name, member))
        # only factum can compare a replacement with the case log, so here each one stays a warning: it may be forged
        for by in replacements:
            warn("replaced_copy", "%s: listed as replaced by %s; only factum checks that against the case log."
                 % (name, display(graph, by)))
    return checked


# --- signatures

def signature_problem(status, exit_code):
    """Why gpg's status lines are not exactly one good signature; None when they are."""
    keys = [key for key, _ in status]
    if "NO_PUBKEY" in keys:
        return "signing key not in the keyring (import information.turtle.pubkey.asc after checking its fingerprint, " \
               "or use --use-carried-key)"
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


def same_folder(one, other):
    return os.path.normcase(os.path.realpath(one)) == os.path.normcase(os.path.realpath(other))


def find_tool(name, container):
    """A program as an absolute path, None when it is not installed, or None with the reason it is not run. Windows
    looks in the current folder before the PATH, for a bare name and in shutil.which, and what lies beside a container
    or this script comes from whoever made it: a program there is not run."""
    found = shutil.which(name)
    if found is None:
        return None, None
    found = os.path.abspath(found)
    folder = os.path.dirname(found)
    try:
        script = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        script = os.getcwd()
    if (same_folder(folder, script) or same_folder(folder, os.path.dirname(os.path.abspath(container)))
            or same_folder(folder, os.getcwd())):
        return None, ("Refusing %s: %s in the current folder, the container's or this script's is not run. "
                      "Nothing was checked." % (found, name))
    return found, None


def old_gpg(program):
    """The version of gpg when it is older than 2.1, which has no --pinentry-mode; None otherwise."""
    result = subprocess.run([program, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    match = re.search(r"(\d+)\.(\d+)\S*", lines[0]) if lines else None
    if match and (int(match.group(1)), int(match.group(2))) < (2, 1):
        return match.group(0)
    return None


class Gpg(object):
    def __init__(self, program, carried_key):
        self.program = program
        self.missing = None if program else "gpg is not installed"
        if not self.missing and old_gpg(program):
            self.missing = "it needs gpg 2.1 or newer"
        self.home = tempfile.mkdtemp(prefix="fc-") if carried_key else None
        self.carried_key = carried_key
        self.signers = {}

    def run(self, args, data=None):
        # what is checked comes from the container: gpg must never ask for anything
        command = [self.program, "--batch", "--pinentry-mode", "error", "--status-fd", "2"]
        if self.home:
            command += ["--homedir", self.home]
        result = subprocess.run(command + args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = []
        for line in result.stderr.decode("utf-8", "replace").splitlines():
            if line.startswith("[GNUPG:] "):
                parts = line[9:].split(" ")
                status.append((parts[0], parts[1:]))
        return result.stdout, status, result.returncode

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

    def check(self, label, signature, key, data, workdir):
        if self.missing:
            warn("not_checked", "%s: GPG signature not checked (%s)." % (label, self.missing))
            return
        if self.home and key:
            self.run(["--import"], key)
        path = os.path.join(workdir, "signature.asc")
        with open(path, "wb") as handle:
            handle.write(signature)
        _, status, exit_code = self.run(["--verify", path, "-"], data)
        reason = signature_problem(status, exit_code)
        if reason:
            code = "key_unknown" if "NO_PUBKEY" in dict(status) else "signature_invalid"
            fail(code, "%s: GPG signature invalid (%s)." % (label, reason))
            return
        found = dict(status)
        validsig = found["VALIDSIG"]
        # the primary key, as factum reports it; field 0 may be a subkey
        fingerprint = validsig[9] if len(validsig) > 9 and validsig[9] else validsig[0]
        self.signers[fingerprint] = " ".join(found.get("GOODSIG", found.get("EXPKEYSIG"))[1:])
        expired = "EXPKEYSIG" in found
        trust = [key for key, _ in status if key.startswith("TRUST_")]
        trusted = bool(trust) and all(key in TRUSTED for key in trust)
        if not trusted and not self.carried_key:
            if not expired:
                fail("key_untrusted", "%s: GPG signing key %s is not trusted." % (label, fingerprint))
                return
            if not self.expired_key_trusted(fingerprint):
                fail("key_untrusted", "%s: GPG signing key %s has expired and is not trusted as far as gpg can tell."
                     % (label, fingerprint))
                return
        ok("%s: GPG signature good (%s)." % (label, fingerprint))
        if expired:
            warn("key_expired", "%s: GPG signing key %s has expired since." % (label, fingerprint))

    def cleanup(self):
        if self.home:
            if self.program:
                # beside gpg, for the reason gpg is found the way it is
                gpgconf = os.path.join(os.path.dirname(self.program), "gpgconf")
                try:
                    subprocess.run([gpgconf, "--homedir", self.home, "--kill", "gpg-agent"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except OSError:
                    pass
            shutil.rmtree(self.home, ignore_errors=True)


def pem_certificates(text):
    """The certificate blocks, line by line: a BEGIN line starts over, so one that never ends costs nothing more."""
    blocks, start = [], None
    for match in LINE.finditer(text):
        line = match.group()
        if line.startswith("-----BEGIN CERTIFICATE-----"):
            start = match.start()
        if line.startswith("-----END CERTIFICATE-----") and start is not None:
            blocks.append(text[start:match.end()] + "\n")
            start = None
    return blocks


def armored_der(text):
    """The DER of a PEM block of any label (gpgsm writes CMS as BEGIN SIGNED MESSAGE)."""
    body = bytearray()
    inside = False
    for match in LINE.finditer(text):
        line = match.group().strip()
        if line.startswith("-----BEGIN "):
            inside = True
        elif line.startswith("-----END "):
            break
        elif inside and line and ":" not in line:
            body += line.encode("ascii")
    if not inside:
        raise ValueError("no PEM block")
    return base64.b64decode(bytes(body), validate=True)


def signing_time(openssl, path):
    """The time a CMS signature states, as Unix time; None without one. asn1parse, as gpgsm writes BER of indefinite
    length. Only the signed attributes count (depth 5, [0] of a SignerInfo): a certificate in the signature, or the
    unsigned attributes, could hold the same object."""
    result = subprocess.run([openssl, "asn1parse", "-inform", "DER", "-in", path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    signed_attributes, stated = False, None
    for at, line in enumerate(lines):
        if re.match(r"\s*\d+:d=5\s", line):
            signed_attributes = "cont [ 0 ]" in line
        if signed_attributes and re.match(r"\s*\d+:d=7\s.*:signingTime\s*$", line):
            stated = re.search(r"(UTCTIME|GENERALIZEDTIME)\s*:(\d+)Z", "\n".join(lines[at + 1:at + 3]))
    if stated is None:
        return None
    stamp = stated.group(2)
    if stated.group(1) == "UTCTIME":
        stamp = ("19" if stamp[:2] >= "50" else "20") + stamp
    if len(stamp) != 14:
        return None
    try:
        fields = [int(stamp[:4])] + [int(stamp[i:i + 2]) for i in range(4, 14, 2)]
        return calendar.timegm(datetime.datetime(*fields).timetuple())
    except (ValueError, OverflowError):  # what it states is no date: the bytes come from the container
        return None


def der_fingerprint(pem):
    """The fingerprint gpgsm gives a certificate; None when it cannot be read."""
    try:
        return hashlib.sha1(armored_der(pem)).hexdigest()
    except ValueError:  # binascii.Error included
        return None


def check_x509(openssl, label, signature, chain, data, ca, workdir):
    """`chain` is the certificate chain stored beside the signature; None without one: the signature's own certificates
    are then what it can be checked with. Trust cannot be decided here as in factum, which has gpgsm's trust list: a
    root passed with --ca is the only one that counts."""
    if openssl is None:
        warn("not_checked", "%s: X.509 signature not checked (openssl is not installed)." % label)
        return
    try:
        der = armored_der(signature.decode("utf-8", "replace"))
    except ValueError as e:  # binascii.Error included
        fail("x509_invalid", "%s: the X.509 signature cannot be read (%s)." % (label, e))
        return
    stored = pem_certificates(chain.decode("utf-8", "replace")) if chain is not None else []
    paths = dict((name, os.path.join(workdir, name)) for name in ("sig.der", "data", "chain.pem", "root.pem", "signer"))

    def write(name, content):
        with open(paths[name], "wb") as handle:
            handle.write(content)

    def cms_verify(root, at=None):
        command = [openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", paths["sig.der"], "-content",
                   paths["data"], "-CAfile", root, "-certfile", paths["chain.pem"], "-purpose", "any",
                   "-signer", paths["signer"], "-out", os.devnull]
        result = subprocess.run(command + (["-attime", str(at)] if at is not None else []),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0, result.stderr.decode("utf-8", "replace").strip()

    try:
        write("sig.der", der)
        write("data", data)
        certificates = stored
        if not certificates:
            carried = subprocess.run([openssl, "pkcs7", "-inform", "DER", "-in", paths["sig.der"], "-print_certs"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            certificates = pem_certificates(carried.stdout.decode("utf-8", "replace"))
        if not certificates:
            fail("x509_invalid", "%s: the X.509 certificate chain is missing." % label)
            return
        write("chain.pem", "".join(certificates).encode())
        write("root.pem", (stored[-1] if stored else "".join(certificates)).encode())
        signed = signing_time(openssl, paths["sig.der"])
        if signed is None:
            fail("x509_invalid", "%s: the X.509 signature states no signing time." % label)
            return
        # at the time the signature states, so a certificate that has expired since does not count against it, and
        # every certificate of the chain must have been valid then
        good, errors = cms_verify(ca or paths["root.pem"], signed)
        if not good and ca and cms_verify(paths["root.pem"], signed)[0]:
            fail("x509_untrusted", "%s: the X.509 signature is good, but its chain does not end at your root %s."
                 % (label, os.path.basename(ca)))
            return
        if not good:
            fail("x509_invalid", "%s: X.509 signature invalid (%s)." % (label, errors[:200]))
            return
        with open(paths["signer"], "rb") as handle:
            signers = pem_certificates(handle.read().decode("utf-8", "replace"))
        still_valid, errors = cms_verify(ca or paths["root.pem"])
    except (OSError, ValueError) as e:
        fail("x509_invalid", "%s: the X.509 signature could not be checked (%s)." % (label, e))
        return
    if not still_valid and "expired" not in errors:
        fail("x509_invalid", "%s: X.509 signature invalid (%s)." % (label, errors[:200]))
        return
    if ca:
        ok("%s: X.509 signature good, chain ends at your root %s." % (label, os.path.basename(ca)))
    else:
        ok("%s: X.509 signature good against the chain it carries." % label)
        warn("not_checked", "%s: root not checked against a trusted certificate (pass --ca ROOT.pem)." % label)
    if not still_valid:
        warn("x509_expired", "%s: the X.509 signature is good, but its certificate or one in its chain has expired "
                             "since. That they were valid at signing rests on the signing time the signer stated; "
                             "nothing confirms it." % label)
    if chain is None:
        warn("x509_no_certificate", "%s: an X.509 signature without the certificate chain stored beside it." % label)
        return
    # any certificate below the root makes a good signature, so a signature alone does not say it is the examiner's
    signer = der_fingerprint(signers[0]) if signers else None
    first_stored = der_fingerprint(stored[0]) if stored else None
    if signer is None or signer != first_stored:
        fail("x509_mismatch", "%s: the X.509 signature was made by certificate %s, not by the one stored in the "
                              "container (%s)." % (label, signer, first_stored or "none readable"))


# --- states

def history_member(close, name):
    return "factum/history/%d/%s" % (close, name)


def check_hashes(label, turtle, hashes):
    if hashes is None:
        fail("turtle_hash", "%s: information.turtle.hashes is missing." % label)
        return
    try:
        graph = parse_metadata(hashes)
    except ValueError as e:
        fail("turtle_hash", "%s: information.turtle.hashes cannot be read (%s)." % (label, e))
        return
    actual = {"SHA256": hashlib.sha256(turtle).hexdigest(), "SHA512": hashlib.sha512(turtle).hexdigest()}
    compared, differ = set(), False
    for triples in graph.values():
        for _, value, _, datatype in triples:
            algorithm = algorithm_of(datatype) if datatype else None
            if algorithm in actual:
                compared.add(algorithm)
                differ = differ or value.lower() != actual[algorithm]
    if not compared:
        fail("turtle_hash", "%s: information.turtle.hashes has no SHA-256 or SHA-512." % label)
    elif differ:
        fail("turtle_hash", "%s: information.turtle does not match information.turtle.hashes." % label)
    else:
        ok("%s: information.turtle matches its %s." % (label, " and ".join(sorted(compared))))


def check_root_signatures(archive, close):
    """The root signatures of a closed current state are that close's."""
    for name in SIGNATURES:
        root = read_signature(archive, name, "history")
        kept = read_signature(archive, history_member(close, name), "history")
        if root is not None and root != kept:
            fail("history", "%s differs from the one kept for close %d." % (name, close))


def close_numbers(archive):
    """The closes kept under factum/history/<n>/; what factum does not read as a number (u32) is no close to it."""
    closes = set()
    for entry in archive.entries:
        try:
            name = entry.name.decode("utf-8")
        except UnicodeDecodeError:
            continue
        match = re.fullmatch(r"factum/history/([^/]*)/information\.turtle", name)
        close = decimal(match.group(1), U32_MAX) if match else None
        if close is not None:
            closes.add(close)
    return closes


def check_outside_closes(archive, closes):
    """A close that cannot be read is no close: what it held must not pass for something else, or for nothing."""
    kept = set(str(close).encode() for close in closes)
    outside = []
    for entry in archive.entries:
        if entry.name.startswith(HISTORY):
            number, slash, _ = entry.name[len(HISTORY):].partition(b"/")
            if not slash or number not in kept:
                outside.append(entry.name.decode("utf-8", "replace"))
    if outside:
        fail("history", "%d member(s) under factum/history/ belong to no closed state (%s)."
             % (len(outside), outside[0]))


def resolve_imports(archive, graph, volume, label):
    """Joins the secondary information stores (aff4l:imports, AFF4-L v1.0 section 9) into the graph, each checked
    against the hash the primary store gives for it (section 10.2)."""
    done = set()
    for _ in range(16):
        imports = [t[1] for t in values(graph, volume, "imports") if t[2] and t[1] not in done]
        if not imports:
            return
        for store in imports:
            done.add(store)
            name = member_name(store, volume)
            if not archive.has(name):
                fail("turtle_hash", "%s: the secondary store %s is missing." % (label, name))
                continue
            data = read(archive, name, "turtle_hash")
            if data is None:
                continue
            expected = [(a, hash_value(graph, store, a)) for a in ("SHA512", "SHA256")]
            expected = [(algorithm, value) for algorithm, value in expected if value is not None]
            if not expected:
                fail("turtle_hash", "%s: the primary store gives no hash for %s." % (label, name))
            for algorithm, value in expected:
                actual = hashlib.sha512(data) if algorithm == "SHA512" else hashlib.sha256(data)
                if actual.hexdigest() != value:
                    fail("turtle_hash", "%s: %s does not match its %s." % (label, name, algorithm))
            try:
                for subject, triples in parse_metadata(data).items():
                    graph.setdefault(subject, []).extend(triples)
            except ValueError as e:
                # this script reads what factum wrote, and factum writes nothing it cannot read
                fail("turtle_hash", "%s: %s cannot be read (%s)." % (label, name, e))


def check_numbering(closes):
    """Closes are numbered from 1 without gaps: a gap is a closed state that was removed. One finding per gap, from
    one kept state to the next: a crafted number must not make this count up to it."""
    if 0 in closes:
        closes.remove(0)
        fail("history", "A closed state numbered 0: closes are numbered from 1; it was not checked.")
    expected = 1
    for close in sorted(closes):
        if close == expected + 1:
            fail("history", "closed state %d is missing from the container (a removed close)." % expected)
        elif close > expected:
            fail("history", "closed states %d to %d are missing from the container (removed closes)."
                 % (expected, close - 1))
        expected = close + 1


def open_container(path):
    """The directory of the last complete state; None, after a failure, without one. What follows that state is an
    interrupted addition, or more than one leaves."""
    handle = open(path, "rb")
    length = handle.seek(0, 2)
    end = find_last_end(handle, length)
    if end is None:
        if search_gave_up(handle, length):
            fail("not_aff4", "No complete state was found in %s: the search through its end records stopped at its "
                             "limit, so this does not say what the file is." % path)
        else:
            fail("not_aff4", "%s is not a ZIP (AFF4) container." % path)
        return None
    if end < length:
        try:
            walk_tail(handle, end, length)
            warn("trailing_data", "%d bytes after the last complete state (an interrupted addition); the last complete "
                                  "state was checked." % (length - end))
        except Invalid as e:
            fail("trailing_data", "%d bytes after the last complete state may be more than an interrupted addition "
                                  "(%s); the last complete state was checked." % (length - end, e))
    archive = read_archive(handle, end)
    Memory.left = Memory.limit = metadata_budget(archive, length)
    return archive


def version_property(version, key):
    match = re.search("^%s=(.*)$" % key, version, re.M)
    return match.group(1).strip() if match else None


def own_hash():
    """The SHA-256 of this file: it comes with the container it checks, so nothing vouches for it but a copy to compare
    with. factum --version and the release notes give the hash."""
    try:
        with open(os.path.abspath(__file__), "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except (NameError, OSError):
        return "unknown"


def main(argv=None):
    tolerant_output()
    try:
        return check_container(argv)
    except (TooLarge, MemoryError):
        # what is left unread stays unjudged: no rule may read anything into it
        gib = float(1 << 30)
        fail("too_large", "The metadata of this container needs more memory than this check sets aside (%.1f GiB in "
                          "all, %.1f GiB for one member), so the check stopped here and did not finish. That alone "
                          "does not mean the container was altered." % (Memory.limit / gib, MAX_IN_MEMORY / gib))
        print("Result: FAIL — %d failure(s), %d warning(s)" % (len(FAILS), len(WARNINGS)))
        return 1


def check_container(argv):
    parser = argparse.ArgumentParser(description="Verify an evidence container written by factum.")
    parser.add_argument("container", help="the .aff4l file")
    parser.add_argument("--ca", help="the root certificate (PEM) the X.509 chain must end at")
    parser.add_argument("--use-carried-key", action="store_true",
                        help="verify GPG signatures against the public key the container carries, in a temporary "
                             "keyring; compare the printed fingerprint with one you received separately")
    args = parser.parse_args(argv)
    print("verify_container.py SHA-256 %s" % own_hash())
    print("Compare it with factum --version or the release notes: this script comes with the container it checks.")
    gpg_program, problem = find_tool("gpg", args.container)
    openssl, openssl_problem = find_tool("openssl", args.container)
    if problem or openssl_problem:
        print(problem or openssl_problem)
        return 1
    try:
        archive = open_container(args.container)
    except (OSError, Invalid) as e:
        fail("not_aff4", "%s is not a readable container (%s)." % (args.container, e))
        return 1
    if archive is None:
        return 1
    for name in archive.duplicates():
        fail("duplicate_member", "listed more than once: %s (ZIP tools may read a different copy than this check)."
             % name)
    version = (read(archive, "version.txt", "history") or b"").decode("utf-8", "replace")
    # this script checks what factum wrote: anything else fails, where factum, which reads other tools' containers too,
    # warns that it is not supported
    if (version_property(version, "major"), version_property(version, "minor")) != ("2", "1"):
        fail("unsupported", "Not an AFF4-L v1.0 container (version.txt: %r)." % version.strip()[:200])
        return 1
    if archive.has("information.hdt"):
        warn("not_checked", "information.hdt (an AFF4/HDT store) was not read; the Turtle metadata was checked.")
    if os.path.exists(args.container + ".1"):
        warn("not_checked", "This is one part of a multi-part container (%s.1 exists); only this part was checked."
             % args.container)
    description = read(archive, "container.description", "history")
    if not archive.has("container.description"):
        fail("history", "container.description is missing, which ties this container to its case log.")
    named = description.decode("utf-8", "replace").strip() if description is not None else archive.volume()
    if named != archive.volume():
        fail("history", "container.description names %s, the ZIP comment %s." % (named[:200], archive.volume()[:200]))
    volume = "aff4://" + re.sub("^(aff4://)+", "", named)
    current = read(archive, TURTLE, "turtle_hash")
    if current is None:
        if not archive.has(TURTLE):
            fail("turtle_hash", "information.turtle is missing.")
        return 1
    closes = close_numbers(archive)
    check_numbering(closes)
    check_outside_closes(archive, closes)
    states = []  # (label, the close it is, turtle, its hashes file, whether it is the current state)
    close_unread = False
    for n in sorted(closes):
        turtle = read(archive, history_member(n, TURTLE), "history")
        close_unread = close_unread or turtle is None
        hashes = read(archive, history_member(n, HASHES), "turtle_hash")
        states.append(("close %d" % n, n, turtle or b"", hashes, False))
    if states and states[-1][2] == current:
        label, n, turtle, hashes, _ = states[-1]
        states[-1] = (label + " (current)", n, turtle, hashes, True)
    else:
        states.append(("current (open)", None, current, read(archive, HASHES, "turtle_hash"), True))
    gpg = Gpg(gpg_program, args.use_carried_key)
    workdir = tempfile.mkdtemp(prefix="fc-")
    unsigned = False
    try:
        graphs = []  # (label, the close it is, graph) of the states whose metadata could be read
        for label, close, turtle, hashes, is_current in states:
            print(label.capitalize())
            prefix = "" if close is None else history_member(close, "")
            check_hashes(label, turtle, hashes)
            signed = False
            signature = read_signature(archive, prefix + SIGNATURES[0], "signature_invalid")
            if signature is not None:
                signed = True
                key = None
                if args.use_carried_key:
                    key = read_signature(archive, prefix + SIGNATURES[1], "signature_invalid")
                gpg.check(label, signature, key, turtle, workdir)
            x509 = read_signature(archive, prefix + SIGNATURES[2], "x509_invalid")
            if x509 is not None:
                signed = True
                chain = read_signature(archive, prefix + SIGNATURES[3], "x509_invalid")
                check_x509(openssl, label, x509, chain, turtle, args.ca, workdir)
            if close is not None and not signed:
                fail("unsigned", "%s: not signed." % label)
            if close is not None and is_current:
                check_root_signatures(archive, close)
                # what readers of the standard go by; the close's copy above is another member
                root_hashes = read(archive, HASHES, "turtle_hash")
                if root_hashes is not None or not archive.has(HASHES):
                    check_hashes(label + ", at the root", turtle, root_hashes)
            # every state factum writes takes the root signatures away, so an open state has none: one that does is a
            # close that was taken out of the directory
            root_signed = [name for name in SIGNATURES if archive.has(name)]
            if close is None and root_signed and not close_unread:
                fail("history", "%s is at the root of a state that was never closed." % root_signed[0])
            try:
                graph = parse_metadata(turtle)
            except ValueError as e:
                fail("turtle_hash", "%s: information.turtle cannot be read (%s)." % (label, e))
                continue
            resolve_imports(archive, graph, volume, label)
            # the signed metadata says which volume it describes
            if not has_type(graph, named, "ZipVolume"):
                fail("history", "%s: information.turtle does not describe the volume %s." % (label, named[:200]))
            graphs.append((label, close, graph))
        if graphs:
            newest_close, newest = graphs[-1][1:]
            listed = set(file_images(newest))
            print("Files")
            for label, close, graph in graphs[:-1]:
                for arn in file_images(graph):
                    if arn not in listed:
                        fail("history", "%s (%s) is no longer listed." % (display(graph, arn), label))
                    # the same triples, as many times each; a copy of their text here would be charged to nothing
                    elif collections.Counter(graph[arn]) != collections.Counter(newest[arn]):
                        fail("history", "%s: its metadata in %s differs from the newest state."
                             % (display(graph, arn), label))
            ok("%d file(s) checked against their hashes." % check_files(archive, newest))
            if newest_close is None:
                unsigned = True
                closed = [len(file_images(graph)) for _, close, graph in graphs if close is not None]
                if closed:
                    warn("not_signed", "%d file(s) added after the last close are not signed yet."
                         % max(len(listed) - closed[-1], 0))
                else:
                    warn("not_signed", "The container was never closed: none of its %d file(s) is signed."
                         % len(listed))
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
    # exit 0, as nothing failed; but nothing here says it is what was signed, and OK would
    result = "FAIL" if FAILS else "NOT SIGNED" if unsigned else "OK"
    print("Result: %s — %d failure(s), %d warning(s)" % (result, len(FAILS), len(WARNINGS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
