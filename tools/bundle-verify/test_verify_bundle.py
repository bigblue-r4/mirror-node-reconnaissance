#!/usr/bin/env python3
"""Tests for verify_bundle.py.

Run from the repository root:

    python3 -m unittest discover -s tools/bundle-verify -v

The fixtures in testdata/ were emitted by the producers themselves, not by this
verifier:

  v1-kiss.ndjson        kiss-protocol/internal/pd/export, Signed, 2 entries
  v1-slate.ndjson       slate/internal/export, Signed, 2 entries
  v1-kiss-empty.ndjson  same package, zero entries
  v1-unsigned.ndjson    same package, never signed (--sign is optional)
  v2-case.ndjson        4 case entries out of a real 500-record store log,
                        scope=case, head + one proof per entry
  v2-log.ndjson         12 entries, scope=log
  *.pub                 the public keys those bundles were signed with

v2 has no producer yet, so those two were emitted by a scratch Go program
written from BUNDLE_SCHEMA.md section 4 -- deliberately not sharing code with
this verifier. That is the point of the exercise: two encoders, one spec.

The signing helper below exists so a test can forge a bundle that is properly
signed but dishonest. Tampering with a fixture's bytes is not enough to reach
the inclusion check: sha256_chain covers the entry lines and is itself signed,
so an edit trips the digest first. A malicious exporter with a valid, pinned key
is the adversary the proofs exist for.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import verify_bundle as vb

HERE = Path(__file__).resolve().parent
DATA = HERE / "testdata"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def fixture(name: str) -> bytes:
    return (DATA / name).read_bytes()


def pins(*names: str) -> list[bytes]:
    return [bytes.fromhex((DATA / name).read_text().strip()) for name in names]


def header_of(data: bytes) -> dict:
    return json.loads(data.split(b"\n", 1)[0])


def entry_lines(data: bytes) -> list[bytes]:
    return data.rstrip(b"\n").split(b"\n")[1:]


def assemble(header: dict, entries: list[bytes]) -> bytes:
    """A bundle file: compact header line, then the entry lines unchanged."""
    line = json.dumps(header, separators=(",", ":")).encode()
    return line + b"\n" + b"".join(line + b"\n" for line in entries)


def _encode_point(point: vb._Point) -> bytes:
    zinv = pow(point.z, vb._P - 2, vb._P)
    x = point.x * zinv % vb._P
    y = point.y * zinv % vb._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


class Key:
    """An Ed25519 key pair, so forged bundles can be signed as a real one."""

    def __init__(self, seed: bytes):
        h = hashlib.sha512(seed).digest()
        scalar = int.from_bytes(h[:32], "little")
        scalar &= (1 << 254) - 8
        scalar |= 1 << 254
        self._scalar = scalar
        self._prefix = h[32:]
        self.public = _encode_point(vb._multiply(scalar, vb._BASE))

    def sign(self, message: bytes) -> bytes:
        r = int.from_bytes(
            hashlib.sha512(self._prefix + message).digest(), "little"
        ) % vb._L
        r_enc = _encode_point(vb._multiply(r, vb._BASE))
        k = int.from_bytes(
            hashlib.sha512(r_enc + self.public + message).digest(), "little"
        ) % vb._L
        s = (r + k * self._scalar) % vb._L
        return r_enc + s.to_bytes(32, "little")


def revalidate(header: dict, entries: list[bytes], key: Key) -> bytes:
    """Sign a header as `key` and emit the file. Caller mutates header first."""
    header = dict(header)
    header["signed_by"] = key.public.hex()
    header.pop("signature", None)
    header["signature"] = key.sign(vb.v2_preimage(header)).hex()
    return assemble(header, entries)


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

# BLAKE3 over bytes(i % 251 for i in range(n)). Produced by lukechampine.com/
# blake3, the library both producers use; the 0- and 3-byte rows also match the
# published BLAKE3 test vectors, and 102400 spans 100 chunks so it exercises the
# tree rather than one compression.
BLAKE3_VECTORS = {
    0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    55: "d04ec5f6f5e7daf5ced7a1671fbe912580a56576c8bf6a2ed4b80e35548f9c13",
    63: "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    64: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    65: "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
    127: "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
    128: "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
    1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    3072: "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
    5000: "ee78d92070de3df1c57c37002abf0a6b1a6589acdeef4d8ffac7cf3d9e8f2836",
    16384: "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4",
    102400: "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
}

ED25519_VECTORS = [
    (
        "fe3dbaf795c8c41dc12fd58cf40fdb33d1d51f8169f9cc464bd3e7e9b7e4cc46",
        b"",
        "79482f3ccdee22790bc98162febc9056cdc2236aacca04914c111516965f9f83"
        "7f80caa5ed2fdaf99f52f381ca795aea2f423fc05254bcc615a326a672d0d208",
    ),
    (
        "fe3dbaf795c8c41dc12fd58cf40fdb33d1d51f8169f9cc464bd3e7e9b7e4cc46",
        b"hello",
        "3cff1a0a255d19c504448fba7081da5019b37a53e174e822d408bd11b25f59eb"
        "b3067c6b4784e3f93deb246dd1ba15479876c65672e5d53e6b58de9937144205",
    ),
]


class Blake3Tests(unittest.TestCase):
    def test_published_vectors(self):
        self.assertEqual(
            vb.blake3(b"").hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )
        self.assertEqual(
            vb.blake3(b"abc").hex(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        )

    def test_lengths_agree_with_the_producer_library(self):
        for length, want in BLAKE3_VECTORS.items():
            with self.subTest(length=length):
                data = bytes(i % 251 for i in range(length))
                self.assertEqual(vb.blake3(data).hex(), want)


class Ed25519Tests(unittest.TestCase):
    def test_vectors_from_go(self):
        for pub, message, sig in ED25519_VECTORS:
            with self.subTest(message=message):
                self.assertTrue(
                    vb.ed25519_verify(bytes.fromhex(pub), message, bytes.fromhex(sig))
                )
                self.assertFalse(
                    vb.ed25519_verify(bytes.fromhex(pub), message + b"x",
                                      bytes.fromhex(sig))
                )

    def test_rejects_out_of_range_scalar(self):
        pub, message, sig = ED25519_VECTORS[0]
        # S + L is not a canonical scalar; Go and this verifier must both refuse.
        raw = bytearray(bytes.fromhex(sig))
        s = int.from_bytes(raw[32:], "little") + vb._L
        raw[32:] = s.to_bytes(32, "little")
        self.assertFalse(vb.ed25519_verify(bytes.fromhex(pub), message, bytes(raw)))

    def test_signer_agrees_with_verifier(self):
        key = Key(b"p03 verifier test seed")
        message = b"witness-bundle/2\nbundle_id=x\n"
        signature = key.sign(message)
        self.assertTrue(vb.ed25519_verify(key.public, message, signature))
        self.assertFalse(vb.ed25519_verify(key.public, message[:-1], signature))

    def test_cross_check_against_cryptography(self):
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError:  # pragma: no cover - optional oracle
            self.skipTest("cryptography is not installed")
        for pub, message, sig in ED25519_VECTORS:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
                bytes.fromhex(sig), message
            )
        key = Key(b"cross check seed")
        try:
            Ed25519PublicKey.from_public_bytes(key.public).verify(
                key.sign(b"message"), b"message"
            )
        except InvalidSignature as exc:  # pragma: no cover - would be a bug here
            self.fail(f"cryptography rejects a signature this verifier makes: {exc}")


# --------------------------------------------------------------------------
# legacy v1
# --------------------------------------------------------------------------


class V1Tests(unittest.TestCase):
    def test_kiss_issued_bundle(self):
        result = vb.verify(fixture("v1-kiss.ndjson"), pins("v1-kiss.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.entries, 2)
        self.assertNotIn("format", result.header)

    def test_slate_issued_bundle(self):
        # The definition-of-done case: an independent verifier reads a bundle
        # written and signed by slate's own export package.
        result = vb.verify(fixture("v1-slate.ndjson"), pins("v1-slate.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.entries, 2)
        self.assertEqual(result.header["agency"], "Honolulu Police Department")
        self.assertIn("prev_hash", entry_lines(fixture("v1-slate.ndjson"))[0].decode())

    def test_empty_bundle_keeps_entries_null(self):
        data = fixture("v1-kiss-empty.ndjson")
        self.assertIn(b'"entries":null', data.split(b"\n")[0])
        result = vb.verify(data, pins("v1-kiss.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.entries, 0)
        self.assertEqual(
            result.header["sha256_chain"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_unsigned_bundle_is_unauthenticated(self):
        result = vb.verify(fixture("v1-unsigned.ndjson"), [])
        self.assertEqual(result.status, "UNAUTHENTICATED")
        self.assertNotEqual(result.status, "VERIFIED")

    def test_signed_bundle_without_a_pin_fails(self):
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(fixture("v1-kiss.ndjson"), [])
        self.assertEqual(ctx.exception.step, "pin")

    def test_unrelated_pin_fails(self):
        other = Key(b"not the exporter").public
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(fixture("v1-kiss.ndjson"), [other])
        self.assertEqual(ctx.exception.step, "signature")

    def test_edited_entry_fails(self):
        data = fixture("v1-kiss.ndjson").replace(b"white powder", b"white powdex", 1)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, pins("v1-kiss.pub"))
        self.assertEqual(ctx.exception.step, "digest")

    def test_dropped_entry_fails(self):
        data = fixture("v1-kiss.ndjson")
        lines = data.rstrip(b"\n").split(b"\n")
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(b"\n".join(lines[:-1]) + b"\n", pins("v1-kiss.pub"))
        self.assertEqual(ctx.exception.step, "count")

    def test_relabelled_case_fails(self):
        data = fixture("v1-kiss.ndjson").replace(
            b"CASE-2026-0042", b"CASE-2026-0043", 1
        )
        with self.assertRaises(vb.Failure):
            vb.verify(data, pins("v1-kiss.pub"))

    def test_crlf_is_refused(self):
        data = fixture("v1-kiss.ndjson").replace(b"\n", b"\r\n")
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, pins("v1-kiss.pub"))
        self.assertEqual(ctx.exception.step, "split")

    def test_missing_final_newline_is_refused(self):
        data = fixture("v1-kiss.ndjson").rstrip(b"\n")
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, pins("v1-kiss.pub"))
        self.assertEqual(ctx.exception.step, "split")

    def test_missing_entries_placeholder_is_refused(self):
        header = header_of(fixture("v1-kiss.ndjson"))
        entries = entry_lines(fixture("v1-kiss.ndjson"))
        header["entries"] = [json.loads(line) for line in entries]
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(assemble(header, entries), pins("v1-kiss.pub"))
        self.assertEqual(ctx.exception.step, "payload")

    def test_v2_bundle_is_not_downgraded_to_v1(self):
        # Strip the format marker from a v2 header: it must be refused, not
        # re-read as a legacy bundle that the digest alone would satisfy.
        header = header_of(fixture("v2-case.ndjson"))
        del header["format"]
        with self.assertRaises(vb.Failure):
            vb.verify(assemble(header, entry_lines(fixture("v2-case.ndjson"))),
                      pins("v2-case.export.pub", "v2-case.node.pub"))

    def test_unknown_format_value_is_refused(self):
        header = header_of(fixture("v2-case.ndjson"))
        header["format"] = "witness-bundle/3"
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(assemble(header, entry_lines(fixture("v2-case.ndjson"))),
                      pins("v2-case.export.pub", "v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "dispatch")


# --------------------------------------------------------------------------
# witness-bundle/2
# --------------------------------------------------------------------------


class V2Tests(unittest.TestCase):
    PINS = ("v2-case.export.pub", "v2-case.node.pub")

    def case_bundle(self) -> bytes:
        return fixture("v2-case.ndjson")

    def test_case_bundle_verifies(self):
        result = vb.verify(self.case_bundle(), pins(*self.PINS))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.header["format"], vb.V2_FORMAT)
        self.assertEqual(result.entries, 4)
        self.assertEqual(result.header["log_head"]["size"], 500)

    def test_log_bundle_verifies(self):
        result = vb.verify(fixture("v2-log.ndjson"),
                           pins("v2-log.export.pub", "v2-log.node.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.entries, result.header["log_head"]["size"])

    def test_seven_entry_log_bundle_verifies(self):
        # A 4+3 split whose right subtree splits again: three-hash audit paths
        # over an unbalanced tree. The sweep behind this fixture covered every
        # size from 1 to 8 records, including the one-leaf empty path.
        result = vb.verify(fixture("v2-seven.ndjson"),
                           pins("v2-seven.export.pub", "v2-seven.node.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.header["log_head"]["size"], 7)
        self.assertEqual(len(result.header["proofs"][0]["path"]), 3)

    def test_rust_producer_log_bundle_verifies(self):
        # Written by `mnr bundle export` from the same twelve entry lines the Go
        # fixture carries. The root and chain must agree byte for byte, which is
        # the cross-language check of the leaf rule and the tree split.
        result = vb.verify(fixture("v2-rust-log.ndjson"),
                           pins("v2-rust.export.pub", "v2-rust.node.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.entries, 12)
        go = header_of(fixture("v2-log.ndjson"))
        self.assertEqual(result.header["log_head"]["root"], go["log_head"]["root"])
        self.assertEqual(result.header["sha256_chain"], go["sha256_chain"])

    def test_rust_producer_case_bundle_verifies(self):
        # Three entries from a seven-record log, at non-contiguous seqs: the
        # proofs are taken from the full tree and their indices are seq-1.
        result = vb.verify(fixture("v2-rust-case.ndjson"),
                           pins("v2-rust.export.pub", "v2-rust.node.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.entries, 3)
        self.assertEqual(result.header["log_head"]["size"], 7)
        self.assertEqual([proof["seq"] for proof in result.header["proofs"]],
                         [2, 5, 7])

    def test_unknown_header_keys_are_ignored(self):
        # The rehearsal prototype still emitted v1's "entries":null placeholder.
        # Unknown keys are outside the preimage, so the bundle must still pass.
        header = header_of(self.case_bundle())
        header["entries"] = None
        header["x_producer"] = "scratch prototype"
        result = vb.verify(assemble(header, entry_lines(self.case_bundle())),
                           pins(*self.PINS))
        self.assertEqual(result.status, "VERIFIED")

    def test_edited_entry_fails_at_the_digest(self):
        data = self.case_bundle().replace(b"ITEM-000", b"ITEM-999", 1)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, pins(*self.PINS))
        self.assertEqual(ctx.exception.step, "digest")

    def test_dropped_entry_fails_at_the_count(self):
        data = self.case_bundle()
        lines = data.rstrip(b"\n").split(b"\n")
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(b"\n".join(lines[:-1]) + b"\n", pins(*self.PINS))
        self.assertEqual(ctx.exception.step, "count")

    def test_stripped_proofs_fail(self):
        header = header_of(self.case_bundle())
        header["proofs"] = []
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(assemble(header, entry_lines(self.case_bundle())),
                      pins(*self.PINS))
        self.assertEqual(ctx.exception.step, "proofs")

    def test_one_key_pinned_is_not_enough(self):
        for only in ("v2-case.export.pub", "v2-case.node.pub"):
            with self.subTest(pin=only):
                with self.assertRaises(vb.Failure) as ctx:
                    vb.verify(self.case_bundle(), pins(only))
                self.assertEqual(ctx.exception.step, "pin")

    def test_unrelated_pin_fails(self):
        other = Key(b"someone else").public
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(self.case_bundle(), [other])
        self.assertEqual(ctx.exception.step, "pin")

    # ---- forged but correctly signed: the adversary the proofs exist for ----

    def forged(self, mutate) -> tuple[bytes, Key]:
        header = header_of(self.case_bundle())
        entries = entry_lines(self.case_bundle())
        key = Key(b"a pinned but dishonest exporter")
        mutate(header, entries)
        return revalidate(header, entries, key), key

    def test_a_forged_bundle_signs_and_verifies_when_it_is_honest(self):
        # Control: without tampering, the forged path produces a valid bundle.
        # So every failure below is the check under test, not the harness.
        data, key = self.forged(lambda header, entries: None)
        result = vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(result.status, "VERIFIED")

    def test_signed_empty_case_bundle_verifies(self):
        # A case with no records is a real artifact: the head still proves the
        # node kept a log, and an empty proof list is the honest answer.
        def mutate(header, entries):
            entries.clear()
            header["entry_count"] = 0
            header["sha256_chain"] = hashlib.sha256(b"").hexdigest()
            header["proofs"] = []

        data, key = self.forged(mutate)
        result = vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.entries, 0)

    def test_signed_entry_outside_the_tree_fails_inclusion(self):
        # A dishonest exporter with a valid export key can re-sign the header
        # and recompute sha256_chain, but cannot make an entry a leaf of the
        # node's tree. This is the only check that catches it.
        #
        # The substituted entry keeps its seq and its case_number, so scope and
        # ordering are satisfied; only the leaf bytes differ from the tree.
        def mutate(header, entries):
            entry = json.loads(entries[0])
            entry["data"]["item_id"] = "ITEM-999"
            entries[0] = json.dumps(entry, separators=(",", ":")).encode()
            header["sha256_chain"] = hashlib.sha256(b"".join(entries)).hexdigest()

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "inclusion")

    def test_signed_proof_from_another_tree_fails(self):
        def mutate(header, entries):
            header["proofs"][0]["path"] = list(reversed(header["proofs"][0]["path"]))

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "inclusion")

    def test_signed_proof_size_disagreeing_with_the_head_fails(self):
        def mutate(header, entries):
            header["proofs"][0]["size"] = 4

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "proofs")

    def test_signed_wrong_index_fails(self):
        def mutate(header, entries):
            header["proofs"][0]["index"] = 1

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "proofs")

    def test_signed_case_relabelling_fails_scope(self):
        def mutate(header, entries):
            header["case_number"] = "CASE-B"

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "scope")

    def test_signed_scope_log_subset_fails(self):
        # scope=log claims the whole log; a subset cannot be signed as one.
        def mutate(header, entries):
            header["scope"] = "log"
            header["case_number"] = ""

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "scope")

    def test_signed_unknown_scope_fails(self):
        def mutate(header, entries):
            header["scope"] = "everything"

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "scope")

    def test_signed_duplicate_proof_fails(self):
        def mutate(header, entries):
            header["proofs"][1]["seq"] = header["proofs"][0]["seq"]

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "proofs")

    def test_signed_head_claim_about_another_size_fails(self):
        # The head signature covers size||root, so a signed bundle cannot
        # restate the head against a different tree without the node's key.
        def mutate(header, entries):
            header["log_head"]["root"] = "00" * 32

        data, key = self.forged(mutate)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "head")

    def test_newline_in_a_value_is_refused(self):
        # The injection surface of a line-oriented preimage.
        def mutate(header, entries):
            header["department"] = "Honolulu PD\nextra=field"

        header = header_of(self.case_bundle())
        entries = entry_lines(self.case_bundle())
        key = Key(b"injection")
        mutate(header, entries)
        header["signed_by"] = key.public.hex()
        data = assemble(header, entries)
        with self.assertRaises(vb.Failure) as ctx:
            vb.verify(data, [key.public] + pins("v2-case.node.pub"))
        self.assertEqual(ctx.exception.step, "preimage")


# --------------------------------------------------------------------------
# command line contract
# --------------------------------------------------------------------------


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(HERE / "verify_bundle.py"), *args],
            capture_output=True,
            text=True,
        )

    def test_verified_exits_zero(self):
        proc = self.run_cli(str(DATA / "v2-case.ndjson"),
                            "--pin", (DATA / "v2-case.export.pub").read_text().strip(),
                            "--pin", (DATA / "v2-case.node.pub").read_text().strip())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("VERIFIED", proc.stdout)

    def test_failed_exits_one(self):
        proc = self.run_cli(str(DATA / "v1-kiss.ndjson"),
                            "--pin", "00" * 32)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("FAILED at", proc.stdout)

    def test_unauthenticated_exits_three(self):
        proc = self.run_cli(str(DATA / "v1-unsigned.ndjson"))
        self.assertEqual(proc.returncode, 3)
        self.assertIn("UNAUTHENTICATED", proc.stdout)

    def test_bad_pin_exits_two(self):
        proc = self.run_cli(str(DATA / "v1-kiss.ndjson"), "--pin", "nothex")
        self.assertEqual(proc.returncode, 2)

    def test_missing_file_exits_two(self):
        proc = self.run_cli("/nonexistent/bundle.ndjson")
        self.assertEqual(proc.returncode, 2)

    def test_quiet_prints_only_the_status(self):
        proc = self.run_cli(str(DATA / "v1-kiss.ndjson"),
                            "--pin", (DATA / "v1-kiss.pub").read_text().strip(),
                            "--quiet")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "VERIFIED")


if __name__ == "__main__":
    unittest.main()
