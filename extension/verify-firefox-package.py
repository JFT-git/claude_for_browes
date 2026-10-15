#!/usr/bin/env python3
"""Check that an AMO XPI contains exactly the frozen Firefox build plus metadata.

Usage: verify-firefox-package.py <dist-directory> <signed-xpi> <expected-version>
This checks payload identity and signature-file layout, NOT cryptographic signing.
A release Firefox installation must independently accept the signing certificate.
"""
import hashlib
import io
import json
import pathlib
import stat
import sys
import zipfile

REQUIRED_SIGNATURE_FILES = frozenset({
    "META-INF/manifest.mf", "META-INF/mozilla.sf", "META-INF/mozilla.rsa",
})
COSE_SIGNATURE_FILES = frozenset({"META-INF/cose.manifest", "META-INF/cose.sig"})
ALLOWED_SIGNATURE_FILES = REQUIRED_SIGNATURE_FILES | COSE_SIGNATURE_FILES
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_PAYLOAD_BYTES = 128 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 4096


class VerificationError(Exception):
    """A safe error category; never include manifest values or archive names."""


def safe_name(name, directory=False):
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise VerificationError("unsafe-path")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise VerificationError("unsafe-path")
    if directory:
        if not name.endswith("/"):
            raise VerificationError("unsafe-path")
        name = name[:-1]
    if not name or any(part in ("", ".", "..") for part in name.split("/")):
        raise VerificationError("unsafe-path")
    return name


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate-manifest-key")
        result[key] = value
    return result


def parse_manifest(data):
    def invalid_constant(_value):
        raise VerificationError("invalid-manifest")
    try:
        manifest = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                              parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise VerificationError("invalid-manifest") from error
    if not isinstance(manifest, dict):
        raise VerificationError("invalid-manifest")
    return manifest


def addon_identity(manifest):
    try:
        identifier = manifest["browser_specific_settings"]["gecko"]["id"]
        version = manifest["version"]
    except (KeyError, TypeError) as error:
        raise VerificationError("missing-addon-identity") from error
    if not isinstance(identifier, str) or not identifier or not isinstance(version, str) or not version:
        raise VerificationError("missing-addon-identity")
    return identifier, version


def manifest_semantics(manifest):
    # JSON canonicalization ignores whitespace/key order, preserving JSON types
    # and array order (notably true vs 1, which Python equality treats as equal).
    try:
        return json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, RecursionError) as error:
        raise VerificationError("invalid-manifest") from error


def verify_package(dist_directory, signed_xpi, expected_version):
    dist = pathlib.Path(dist_directory)
    if dist.is_symlink() or not dist.is_dir():
        raise VerificationError("invalid-source-directory")
    source = {}
    source_dirs = set()
    source_total = 0
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise VerificationError("source-symlink")
        relative = safe_name(path.relative_to(dist).as_posix())
        if relative.casefold() == "meta-inf" or relative.casefold().startswith("meta-inf/"):
            raise VerificationError("source-signature-metadata")
        if path.is_dir():
            source_dirs.add(relative)
            continue
        if not stat.S_ISREG(path.stat().st_mode):
            raise VerificationError("source-nonregular-file")
        size = path.stat().st_size
        if source_total + size > MAX_PAYLOAD_BYTES or len(source) >= MAX_ENTRIES:
            raise VerificationError("source-size-limit")
        data = path.read_bytes()
        source_total += len(data)
        if source_total > MAX_PAYLOAD_BYTES:
            raise VerificationError("source-size-limit")
        source[relative] = data
    if "manifest.json" not in source:
        raise VerificationError("missing-manifest")
    source_manifest = parse_manifest(source["manifest.json"])
    source_identity = addon_identity(source_manifest)
    if not isinstance(expected_version, str) or not expected_version or source_identity[1] != expected_version:
        raise VerificationError("source-version-mismatch")
    with open(signed_xpi, "rb") as stream:
        archive = stream.read(MAX_ARCHIVE_BYTES + 1)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise VerificationError("archive-size-limit")

    payload = {}
    signatures = set()
    names = set()
    portable_names = set()
    unpacked_size = 0
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        infos = package.infolist()
        if len(infos) > MAX_ENTRIES:
            raise VerificationError("archive-entry-limit")
        for entry in infos:
            if entry.orig_filename != entry.filename:
                raise VerificationError("unsafe-path")
            name = safe_name(entry.filename, entry.is_dir())
            if name in names or name.casefold() in portable_names:
                raise VerificationError("duplicate-archive-name")
            names.add(name)
            portable_names.add(name.casefold())
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if kind not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG):
                raise VerificationError("archive-nonregular-file")
            if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise VerificationError("unsupported-archive-entry")
            if entry.is_dir():
                if entry.file_size or (name != "META-INF" and name not in source_dirs):
                    raise VerificationError("unexpected-directory")
                continue
            unpacked_size += entry.file_size
            if unpacked_size > MAX_PAYLOAD_BYTES:
                raise VerificationError("archive-size-limit")
            if name in ALLOWED_SIGNATURE_FILES:
                if not 0 < entry.file_size <= MAX_SIGNATURE_BYTES:
                    raise VerificationError("invalid-signature-metadata")
                package.read(entry)  # Also check CRC; no trust is inferred from bytes.
                signatures.add(name)
            else:
                if name.casefold().startswith("meta-inf/"):
                    raise VerificationError("unexpected-signature-metadata")
                if name not in source:
                    raise VerificationError("unexpected-payload-file")
                payload[name] = package.read(entry)

    if not REQUIRED_SIGNATURE_FILES <= signatures:
        raise VerificationError("missing-signature-metadata")
    if signatures & COSE_SIGNATURE_FILES and not COSE_SIGNATURE_FILES <= signatures:
        raise VerificationError("incomplete-cose-metadata")
    if payload.keys() != source.keys():
        raise VerificationError("missing-payload-file")
    package_manifest = parse_manifest(payload["manifest.json"])
    if addon_identity(package_manifest) != source_identity:
        raise VerificationError("addon-identity-mismatch")
    if manifest_semantics(package_manifest) != manifest_semantics(source_manifest):
        raise VerificationError("manifest-fields-changed")
    for name, content in source.items():
        if name != "manifest.json" and payload[name] != content:
            raise VerificationError("payload-bytes-changed")
    return {"ok": True, "payload_files": len(payload), "signature_files": len(signatures),
            "sha256": hashlib.sha256(archive).hexdigest(), "cryptographic_signature_verified": False}


def main(argv):
    if len(argv) != 4:
        print(json.dumps({"ok": False, "category": "usage", "arguments": "dist-directory signed-xpi expected-version"}), file=sys.stderr)
        return 1
    try:
        result = verify_package(argv[1], argv[2], argv[3])
    except VerificationError as error:
        print(json.dumps({"ok": False, "category": str(error)}), file=sys.stderr)
        return 1
    except Exception:  # Malformed input must never print names, values or a traceback.
        print(json.dumps({"ok": False, "category": "unreadable-input-or-archive"}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
