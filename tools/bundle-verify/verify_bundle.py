#!/usr/bin/env python3
"""Independent verifier for court-export bundles.

Verifies two formats, from the file alone plus the public keys the caller
pins, with no access to a log directory, a key file, a database or a network:

  witness-bundle/2   the format specified in BUNDLE_SCHEMA.md section 4
  legacy v1          bundles issued by kiss-protocol/internal/pd/export and
                     slate/internal/export, verified by the byte rule in
                     BUNDLE_SCHEMA.md section 6.1

Standard library only, on purpose. The claim being tested is that the format
is a specification rather than one repository's encoder, so this file must not
share code, a dependency or a build system with the Go producer. BLAKE3 and
Ed25519 are therefore implemented here; SHA-256 comes from hashlib.

Usage
  verify_bundle.py FILE --pin HEX [--pin HEX ...]
  verify_bundle.py FILE --pin HEX --quiet

Exit status
  0  VERIFIED
  1  FAILED       the file does not support the claim it makes
  2  ERROR        unreadable file, bad arguments
  3  UNAUTHENTICATED  a legacy bundle with no signature: its digest is carried
                 inside the document it describes, so it detects corruption and
                 does not detect editing. Never reported as verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from typing import Any

# --------------------------------------------------------------------------
# BLAKE3, unkeyed, 32-byte output. Only what the leaf and node hashes need.
# --------------------------------------------------------------------------

_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
_CHUNK_START = 1
_CHUNK_END = 2
_PARENT = 4
_ROOT = 8
_M32 = 0xFFFFFFFF
_BLOCK_LEN = 64
_CHUNK_LEN = 1024


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _M32


def _g(s: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    s[a] = (s[a] + s[b] + mx) & _M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & _M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(
    cv: list[int], block: list[int], counter: int, block_len: int, flags: int
) -> list[int]:
    s = list(cv) + _IV[:4] + [counter & _M32, (counter >> 32) & _M32, block_len, flags]
    m = list(block)
    for _ in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        m = [m[i] for i in _MSG_PERM]
    return [s[i] ^ s[i + 8] for i in range(8)] + [s[i + 8] ^ cv[i] for i in range(8)]


def _words(block: bytes) -> list[int]:
    padded = block + b"\x00" * (_BLOCK_LEN - len(block))
    return [int.from_bytes(padded[i:i + 4], "little") for i in range(0, _BLOCK_LEN, 4)]


class _Output:
    """A compression that has not happened yet: BLAKE3's output node."""

    __slots__ = ("cv", "block", "counter", "block_len", "flags")

    def __init__(self, cv, block, counter, block_len, flags):
        self.cv = cv
        self.block = block
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> list[int]:
        return _compress(
            self.cv, self.block, self.counter, self.block_len, self.flags
        )[:8]

    def root_bytes(self) -> bytes:
        out = _compress(
            self.cv, self.block, self.counter, self.block_len, self.flags | _ROOT
        )[:8]
        return b"".join(w.to_bytes(4, "little") for w in out)


def _chunk_output(chunk: bytes, chunk_index: int) -> _Output:
    blocks = [chunk[i:i + _BLOCK_LEN] for i in range(0, len(chunk), _BLOCK_LEN)]
    if not blocks:
        blocks = [b""]
    cv = _IV
    for i, block in enumerate(blocks[:-1]):
        flags = _CHUNK_START if i == 0 else 0
        cv = _Output(cv, _words(block), chunk_index, len(block), flags).chaining_value()
    last = blocks[-1]
    flags = _CHUNK_END if len(blocks) > 1 else _CHUNK_START | _CHUNK_END
    return _Output(cv, _words(last), chunk_index, len(last), flags)


def _parent_cv(left: list[int], right: list[int]) -> list[int]:
    return _compress(_IV, left + right, 0, _BLOCK_LEN, _PARENT)[:8]


def _split_point(n: int) -> int:
    """Largest power of two strictly less than n (BLAKE3's tree split)."""
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def _subtree_cv(chunks: list[bytes], start: int, count: int) -> list[int]:
    if count == 1:
        return _chunk_output(chunks[start], start).chaining_value()
    k = _split_point(count)
    return _parent_cv(
        _subtree_cv(chunks, start, k), _subtree_cv(chunks, start + k, count - k)
    )


def _serialise(words: list[int]) -> bytes:
    return b"".join(w.to_bytes(4, "little") for w in words)


def blake3(data: bytes) -> bytes:
    chunks = [data[i:i + _CHUNK_LEN] for i in range(0, len(data), _CHUNK_LEN)]
    if not chunks:
        return _chunk_output(b"", 0).root_bytes()
    if len(chunks) == 1:
        return _chunk_output(chunks[0], 0).root_bytes()
    k = _split_point(len(chunks))
    left = _subtree_cv(chunks, 0, k)
    right = _subtree_cv(chunks, k, len(chunks) - k)
    return _serialise(_compress(_IV, left + right, 0, _BLOCK_LEN, _PARENT | _ROOT)[:8])


# --------------------------------------------------------------------------
# Ed25519 verification (RFC 8032 §5.1.7). Extended coordinates.
# --------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960


class _Point:
    __slots__ = ("x", "y", "z", "t")

    def __init__(self, x, y, z=1, t=None):
        self.x = x % _P
        self.y = y % _P
        self.z = z % _P
        self.t = (self.x * self.y % _P) if t is None else t % _P

    def __eq__(self, other: "_Point") -> bool:
        return (
            (self.x * other.z - other.x * self.z) % _P == 0
            and (self.y * other.z - other.y * self.z) % _P == 0
        )


_IDENTITY = _Point(0, 1)
_BASE = _Point(_BX, _BY, 1)


def _add(p: _Point, q: _Point) -> _Point:
    a = (p.y - p.x) * (q.y - q.x) % _P
    b = (p.y + p.x) * (q.y + q.x) % _P
    c = p.t * 2 * _D * q.t % _P
    d = p.z * 2 * q.z % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return _Point(e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _double(p: _Point) -> _Point:
    a = p.x * p.x % _P
    b = p.y * p.y % _P
    c = 2 * p.z * p.z % _P
    h = a + b
    e = h - (p.x + p.y) * (p.x + p.y) % _P
    g = a - b
    f = c + g
    return _Point(e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar: int, point: _Point) -> _Point:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _decode_point(enc: bytes) -> _Point | None:
    if len(enc) != 32:
        return None
    raw = int.from_bytes(enc, "little")
    sign = (raw >> 255) & 1
    y = raw & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return _Point(x, y, 1)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    a = _decode_point(public_key)
    r = _decode_point(signature[:32])
    if a is None or r is None:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _L
    return _add(r, _multiply(k, a)) == _multiply(s, _BASE)


# --------------------------------------------------------------------------
# Merkle helpers. Mirrors the core's RFC 6962-style tree, from the spec:
#   leaf  = BLAKE3(0x00 || line bytes)
#   node  = BLAKE3(0x01 || left || right)
# --------------------------------------------------------------------------

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    return blake3(_LEAF_PREFIX + data)


def hash_node(left: bytes, right: bytes) -> bytes:
    return blake3(_NODE_PREFIX + left + right)


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    if not leaf_hashes:
        return b"\x00" * 32
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    k = _split_point(len(leaf_hashes))
    return hash_node(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))


def merkle_verify(root: bytes, leaf_hash: bytes, index: int, size: int,
                  path: list[bytes]) -> bool:
    if size == 0 or index >= size:
        return False
    return _recompute(leaf_hash, index, size, path) == root


def _recompute(h: bytes, index: int, size: int, path: list[bytes]) -> bytes | None:
    """Recompute the root from a leaf and its audit path, leaf-to-root.

    The path is consumed from the back: the outermost sibling is last. A path
    of the wrong length for the tree shape is a failure, not a zero root.
    """
    if size == 1:
        return h
    if not path:
        return None
    k = _split_point(size)
    sibling, inner = path[-1], path[:-1]
    if index < k:
        left = _recompute(h, index, k, inner)
        return None if left is None else hash_node(left, sibling)
    right = _recompute(h, index - k, size - k, inner)
    return None if right is None else hash_node(sibling, right)


# --------------------------------------------------------------------------
# Bundle verification
# --------------------------------------------------------------------------

V2_FORMAT = "witness-bundle/2"

PREIMAGE_FIELDS = [
    "bundle_id", "generated_at", "scope", "case_number", "department", "agency",
    "seal", "node_id", "entry_count", "sha256_chain", "export_actor",
    "export_role", "signed_by",
]
PREIMAGE_HEAD_FIELDS = ["size", "root", "ts", "signer_key"]

_HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")   # 32 bytes: key, root, proof node
_HEX128 = re.compile(r"\A[0-9a-fA-F]{128}\Z")  # 64 bytes: Ed25519 signature


class Failure(Exception):
    def __init__(self, step: str, detail: str):
        super().__init__(f"{step}: {detail}")
        self.step = step
        self.detail = detail


class Result:
    def __init__(self, fmt: str, header: dict[str, Any], entries: int, status: str,
                 notes: list[str]):
        self.fmt = fmt
        self.header = header
        self.entries = entries
        self.status = status
        self.notes = notes


def split_lines(data: bytes) -> list[bytes]:
    if not data:
        raise Failure("split", "file is empty")
    if b"\r" in data:
        raise Failure("split", "file contains CR; the format is \\n terminated")
    if not data.endswith(b"\n"):
        raise Failure("split", "file does not end with a newline")
    lines = data[:-1].split(b"\n")
    if any(line == b"" for line in lines):
        raise Failure("split", "file contains a blank line")
    return lines


def parse_header(line: bytes) -> dict[str, Any]:
    text = line.decode("utf-8")
    try:
        header = json.loads(text)
    except json.JSONDecodeError as exc:
        raise Failure("split", f"header is not JSON: {exc}") from exc
    if not isinstance(header, dict):
        raise Failure("split", "header is not a JSON object")
    return header


def _require(header: dict[str, Any], field: str) -> Any:
    if field not in header:
        raise Failure("header", f"missing field {field!r}")
    return header[field]


def _as_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Failure("header", f"{field!r} is not an integer")
    if value < 0:
        raise Failure("header", f"{field!r} is negative")
    return value


def _as_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise Failure("header", f"{field!r} is not a string")
    if "\n" in value or "\r" in value:
        raise Failure("preimage", f"{field!r} contains a newline")
    return value


def _hex32(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise Failure("header", f"{field!r} is not 64 hex characters")
    return bytes.fromhex(value)


def _hexsig(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not _HEX128.match(value):
        raise Failure("signature", f"{field!r} is not 128 hex characters")
    return bytes.fromhex(value)


def v2_preimage(header: dict[str, Any]) -> bytes:
    """The bytes witness-bundle/2 signs: BUNDLE_SCHEMA.md section 4.3."""
    head = header["log_head"]
    if not isinstance(head, dict):
        raise Failure("header", "'log_head' is not an object")
    out = [V2_FORMAT]
    for field in PREIMAGE_FIELDS:
        if field == "entry_count":
            out.append(f"{field}={_as_int(_require(header, field), field)}")
        else:
            out.append(f"{field}={_as_str(header.get(field, ''), field)}")
    for field in PREIMAGE_HEAD_FIELDS:
        if field == "size":
            out.append(f"log_head.{field}={_as_int(_require(head, field), field)}")
        else:
            out.append(f"log_head.{field}={_as_str(head.get(field, ''), field)}")
    return ("\n".join(out) + "\n").encode("utf-8")


def _pinned(key_hex: str, pins: list[bytes], what: str) -> bytes:
    raw = _hex32(key_hex, what)
    if not any(raw == pin for pin in pins):
        raise Failure("pin", f"{what} {key_hex} is not in the pinned set")
    return raw


def verify_v2(lines: list[bytes], header: dict[str, Any],
              pins: list[bytes], notes: list[str]) -> Result:
    """The steps of BUNDLE_SCHEMA.md section 4.7, in the order stated there."""
    if header.get("format") != V2_FORMAT:
        raise Failure("dispatch", f"unknown format {header.get('format')!r}")

    entries = lines[1:]
    count = _as_int(_require(header, "entry_count"), "entry_count")

    # 3. both keys must be pinned, before any signature is believed.
    export_pub = _pinned(_as_str(_require(header, "signed_by"), "signed_by"),
                         pins, "bundle signer")
    head = header["log_head"]
    if not isinstance(head, dict):
        raise Failure("header", "'log_head' is not an object")
    head_pub = _pinned(_as_str(_require(head, "signer_key"), "log_head.signer_key"),
                       pins, "log head signer")

    # 4. bundle signature over the line preimage.
    signature = _hexsig(_require(header, "signature"), "signature")
    if not ed25519_verify(export_pub, v2_preimage(header), signature):
        raise Failure("signature", "bundle signature does not verify")

    # 5. the header must describe the bytes that follow it.
    if len(entries) != count:
        raise Failure("count", f"entry_count {count}, file has {len(entries)} lines")
    digest = hashlib.sha256(b"".join(entries)).hexdigest()
    if digest != _as_str(_require(header, "sha256_chain"), "sha256_chain").lower():
        raise Failure("digest", "sha256_chain does not match the entry lines")

    # 6. the head is the node's statement about the log it kept.
    size = _as_int(_require(head, "size"), "log_head.size")
    root = _hex32(_require(head, "root"), "log_head.root")
    head_sig = _hexsig(_require(head, "sig"), "log_head.sig")
    if not ed25519_verify(head_pub, size.to_bytes(8, "big") + root, head_sig):
        raise Failure("head", "log head signature does not verify")

    # 7. the case claim, and the entry sequence it is made about.
    scope = _as_str(_require(header, "scope"), "scope")
    if scope not in ("case", "log"):
        raise Failure("scope", f"unknown scope {scope!r}")
    case_number = _as_str(header.get("case_number", ""), "case_number")
    if scope == "case" and not case_number:
        raise Failure("scope", "scope=case requires a non-empty case_number")
    if scope == "log" and case_number:
        raise Failure("scope", "scope=log requires an empty case_number")
    if scope == "log" and count != size:
        raise Failure("scope",
                      f"scope=log with entry_count {count} under a head of {size}")

    seqs: list[int] = []
    previous = 0
    for line in entries:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise Failure("entries", f"entry line is not JSON: {exc}") from exc
        if not isinstance(entry, dict):
            raise Failure("entries", "entry line is not a JSON object")
        seq = _as_int(_require(entry, "seq"), "entry.seq")
        if seq <= previous:
            raise Failure("entries", f"seq {seq} is not ascending (after {previous})")
        previous = seq
        seqs.append(seq)
        if scope == "case":
            payload = entry.get("data")
            got = payload.get("case_number") if isinstance(payload, dict) else None
            if got != case_number:
                raise Failure(
                    "scope",
                    f"entry seq {seq} has case_number {got!r}, header says {case_number!r}",
                )

    # 8. every entry is the leaf its proof claims, under that root.
    proofs: dict[int, dict[str, Any]] = {}
    raw_proofs = _require(header, "proofs")
    if not isinstance(raw_proofs, list):
        raise Failure("proofs", "'proofs' is not an array")
    for proof in raw_proofs:
        if not isinstance(proof, dict):
            raise Failure("proofs", "proof is not an object")
        seq = _as_int(_require(proof, "seq"), "proof.seq")
        if seq in proofs:
            raise Failure("proofs", f"duplicate proof for seq {seq}")
        proofs[seq] = proof
    if len(proofs) != len(entries):
        raise Failure("proofs", f"{len(proofs)} proofs for {len(entries)} entries")

    for line, seq in zip(entries, seqs):
        proof = proofs.get(seq)
        if proof is None:
            raise Failure("proofs", f"entry seq {seq} has no inclusion proof")
        index = _as_int(_require(proof, "index"), "proof.index")
        proof_size = _as_int(_require(proof, "size"), "proof.size")
        if proof_size != size:
            raise Failure(
                "proofs",
                f"entry seq {seq}: proof names a tree of {proof_size}, head is {size}",
            )
        if index != seq - 1:
            raise Failure(
                "proofs", f"entry seq {seq}: proof index {index}, expected {seq - 1}",
            )
        raw_path = _require(proof, "path")
        if not isinstance(raw_path, list):
            raise Failure("proofs", f"entry seq {seq}: 'path' is not an array")
        path = []
        for node in raw_path:
            if not isinstance(node, str) or not _HEX64.match(node):
                raise Failure("proofs", f"entry seq {seq}: malformed proof node")
            path.append(bytes.fromhex(node))
        if not merkle_verify(root, hash_leaf(line), index, proof_size, path):
            raise Failure("inclusion",
                          f"entry seq {seq} is not in the tree the head signed")

    notes.append(f"head: {size} leaves, root {root.hex()[:16]}…")
    notes.append(f"pins: bundle {export_pub.hex()[:16]}…, head {head_pub.hex()[:16]}…")
    return Result(V2_FORMAT, header, count, "VERIFIED", notes)


def strip_v1_signature(header: bytes, signature_hex: str) -> bytes:
    """Remove the top-level "signature" member from a v1 header line."""
    token = b',"signature":"' + signature_hex.encode() + b'"'
    if header.count(token) != 1:
        raise Failure(
            "payload",
            "cannot locate the signature member in the header; "
            "the file is not the shape either implementation writes",
        )
    return header.replace(token, b"", 1)


def v1_payload(header: bytes, entries: list[bytes], signature_hex: str) -> bytes:
    """Rebuild the bytes bundlePayload signed: BUNDLE_SCHEMA.md section 6.1."""
    marker = b'"entries":null'
    if header.count(marker) != 1:
        raise Failure("payload", 'header has no single "entries":null placeholder')
    stripped = strip_v1_signature(header, signature_hex) if signature_hex else header
    if not entries:
        return stripped
    head, tail = stripped.split(marker, 1)
    return head + b'"entries":[' + b",".join(entries) + b"]" + tail


def verify_v1(lines: list[bytes], header: dict[str, Any],
              pins: list[bytes], notes: list[str]) -> Result:
    if header.get("format") not in (None, ""):
        raise Failure("dispatch", f"unknown format {header.get('format')!r}")

    raw_header = lines[0]
    entries = lines[1:]
    signature_hex = _as_str(header.get("signature", ""), "signature")
    count = _as_int(_require(header, "entry_count"), "entry_count")

    payload = v1_payload(raw_header, entries, signature_hex)

    if len(entries) != count:
        raise Failure("count", f"entry_count {count}, file has {len(entries)} lines")
    digest = hashlib.sha256(b"".join(entries)).hexdigest()
    chain = _as_str(_require(header, "sha256_chain"), "sha256_chain").lower()
    if chain != digest:
        raise Failure("digest", "sha256_chain does not match the entry lines")

    notes.append("legacy v1: no format marker, no log head, no inclusion proof")
    if not signature_hex:
        notes.append(
            "no signature: sha256_chain is carried inside the document it "
            "describes, so it detects corruption but not editing"
        )
        return Result("witness-bundle/1 (legacy)", header, count,
                      "UNAUTHENTICATED", notes)
    if not pins:
        raise Failure("pin", "bundle is signed but no pinned key was supplied")
    signature = _hexsig(signature_hex, "signature")

    verified_with = None
    for pin in pins:
        if ed25519_verify(pin, payload, signature):
            verified_with = pin
            break
    if verified_with is None:
        raise Failure("signature", "no pinned key verifies this bundle")
    notes.append(f"signature: OK with pinned key {verified_with.hex()[:16]}…")
    return Result("witness-bundle/1 (legacy)", header, count, "VERIFIED", notes)


def verify(data: bytes, pins: list[bytes]) -> Result:
    lines = split_lines(data)
    header = parse_header(lines[0])
    notes: list[str] = []
    if "format" in header:
        return verify_v2(lines, header, pins, notes)
    return verify_v1(lines, header, pins, notes)


def summarise(result: Result, quiet: bool) -> int:
    if quiet:
        print(result.status)
        return 0 if result.status == "VERIFIED" else 3
    h = result.header
    print(f"format            {result.fmt}")
    for field in ("bundle_id", "generated_at", "case_number", "agency", "node_id"):
        if h.get(field):
            print(f"{field:<17} {h[field]}")
    print(f"entries           {result.entries}")
    for note in result.notes:
        print(f"                  {note}")
    print(f"RESULT            {result.status}")
    if result.status == "VERIFIED":
        return 0
    print("                  Unauthenticated is not verified: the digest is "
          "unkeyed and travels with the data.")
    return 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_bundle.py",
        description="Verify a witness-bundle/2 or legacy v1 court-export bundle.",
    )
    parser.add_argument("file", help="bundle file (.ndjson)")
    parser.add_argument(
        "--pin", action="append", default=[], metavar="HEX",
        help="hex Ed25519 public key to trust; repeat for each key",
    )
    parser.add_argument("--quiet", action="store_true",
                        help="print only the status word")
    args = parser.parse_args(argv)

    pins: list[bytes] = []
    for raw in args.pin:
        value = raw.strip().lower()
        if not _HEX64.match(value):
            print(f"error: --pin {raw!r} is not a 32-byte hex public key",
                  file=sys.stderr)
            return 2
        pins.append(bytes.fromhex(value))

    try:
        with open(args.file, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        return summarise(verify(data, pins), args.quiet)
    except Failure as exc:
        print(f"file              {args.file}")
        print(f"RESULT            FAILED at {exc.step}")
        print(f"                  {exc.detail}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
