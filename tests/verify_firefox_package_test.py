"""Synthetic package tests: signature metadata is deliberately NOT a signature."""
import copy
import importlib.util
import json
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "extension/verify-firefox-package.py"
spec = importlib.util.spec_from_file_location("verify_firefox_package", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class VerifyFirefoxPackageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="firefox-package-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.manifest = {"manifest_version": 3, "name": "Synthetic add-on", "version": "2.0.6",
                         "permissions": ["proxy", "webRequestBlocking"],
                         "browser_specific_settings": {"gecko": {"id": "synthetic@example.invalid"}}}
        (self.dist / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf8")
        (self.dist / "background.js").write_bytes(b"// synthetic source\n")
        (self.dist / "assets").mkdir()
        (self.dist / "assets/icon.png").write_bytes(b"synthetic binary\0fixture")
        self.xpi = self.root / "fixture.xpi"

    def archive(self, mutate=None, signatures=None, extras=()):
        files = {p.relative_to(self.dist).as_posix(): p.read_bytes() for p in self.dist.rglob("*") if p.is_file()}
        if mutate:
            mutate(files)
        for name in signatures if signatures is not None else verifier.ALLOWED_SIGNATURE_FILES:
            files[name] = b"synthetic metadata; not a valid signature"
        with zipfile.ZipFile(self.xpi, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                z.writestr(name, data)
            for name, data in extras:
                z.writestr(name, data)

    def verify(self):
        return verifier.verify_package(self.dist, self.xpi, "2.0.6")

    def rejects(self, category):
        with self.assertRaisesRegex(verifier.VerificationError, "^" + category + "$"):
            self.verify()

    def test_valid_payload_and_formatting_only_manifest_changes(self):
        def formatting(files):
            files["manifest.json"] = json.dumps(self.manifest, indent=4, sort_keys=True).encode()
        self.archive(formatting)
        result = self.verify()
        self.assertTrue(result["ok"])
        self.assertEqual(result["payload_files"], 3)
        self.assertEqual(result["signature_files"], 5)
        self.assertFalse(result["cryptographic_signature_verified"])
        self.assertEqual(len(result["sha256"]), 64)

    def test_legacy_jar_metadata_is_allowed_but_partial_cose_is_rejected(self):
        self.archive(signatures=verifier.REQUIRED_SIGNATURE_FILES)
        self.assertEqual(self.verify()["signature_files"], 3)
        self.archive(signatures=verifier.REQUIRED_SIGNATURE_FILES | {"META-INF/cose.sig"})
        self.rejects("incomplete-cose-metadata")

    def test_unsigned_package_is_rejected(self):
        self.archive(signatures=set())
        self.rejects("missing-signature-metadata")

    def test_unknown_meta_inf_and_added_code_are_rejected(self):
        for name, category in [("META-INF/unexpected.js", "unexpected-signature-metadata"),
                               ("injected.js", "unexpected-payload-file")]:
            with self.subTest(category=category):
                self.archive(extras=[(name, b"extra")])
                self.rejects(category)

    def test_payload_modification_and_missing_file_are_rejected(self):
        self.archive(lambda files: files.update({"background.js": b"changed"}))
        self.rejects("payload-bytes-changed")
        self.archive(lambda files: files.pop("background.js"))
        self.rejects("missing-payload-file")

    def test_changed_manifest_fields_and_json_types_are_rejected(self):
        for field, value in [("permissions", ["proxy", "<all_urls>"]), ("manifest_version", True)]:
            with self.subTest(field=field):
                modified = copy.deepcopy(self.manifest)
                modified[field] = value
                self.archive(lambda files: files.update({"manifest.json": json.dumps(modified).encode()}))
                self.rejects("manifest-fields-changed")

    def test_changed_version_and_addon_id_are_rejected(self):
        for change in ("version", "id"):
            with self.subTest(change=change):
                modified = copy.deepcopy(self.manifest)
                if change == "version": modified["version"] = "9.9.9"
                else: modified["browser_specific_settings"]["gecko"]["id"] = "different@example.invalid"
                self.archive(lambda files: files.update({"manifest.json": json.dumps(modified).encode()}))
                self.rejects("addon-identity-mismatch")
        self.archive()
        with self.assertRaisesRegex(verifier.VerificationError, "source-version-mismatch"):
            verifier.verify_package(self.dist, self.xpi, "9.9.9")

    def test_duplicate_names_and_case_aliases_are_rejected(self):
        for name in ["background.js", "BACKGROUND.js"]:
            with self.subTest(alias=name), warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                self.archive(extras=[(name, b"duplicate")])
                self.rejects("duplicate-archive-name")

    def test_traversal_absolute_backslash_and_control_paths_are_rejected(self):
        for name in ["../injected.js", "/absolute.js", "assets/../injected.js", "assets//injected.js", "assets\\injected.js", "C:/injected.js", "injected\n.js"]:
            with self.subTest(path_category="unsafe"):
                self.archive(extras=[(name, b"injected")])
                self.rejects("unsafe-path")

    def test_nul_in_raw_zip_filename_is_rejected(self):
        self.archive(extras=[("unsafeX.js", b"extra")])
        archive = self.xpi.read_bytes().replace(b"unsafeX.js", b"unsafe\0.js")
        self.xpi.write_bytes(archive)
        self.rejects("unsafe-path")

    def test_symlinks_and_empty_signature_metadata_are_rejected(self):
        info = zipfile.ZipInfo("linked.js")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.archive(extras=[(info, b"background.js")])
        self.rejects("archive-nonregular-file")
        self.archive()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.xpi, "a") as z: z.writestr("META-INF/mozilla.rsa", b"")
        self.rejects("duplicate-archive-name")
        self.archive(signatures=verifier.REQUIRED_SIGNATURE_FILES - {"META-INF/mozilla.rsa"}, extras=[("META-INF/mozilla.rsa", b"")])
        self.rejects("invalid-signature-metadata")

    def test_duplicate_manifest_keys_and_nonfinite_numbers_are_rejected(self):
        for data, category in [(b'{"version":"2.0.6","version":"9.9.9"}', "duplicate-manifest-key"),
                               (b'{"manifest_version":NaN}', "invalid-manifest")]:
            with self.subTest(category=category):
                self.archive(lambda files: files.update({"manifest.json": data}))
                self.rejects(category)

    def test_source_symlinks_and_existing_signatures_are_rejected(self):
        self.archive()
        link = self.dist / "link.js"
        link.symlink_to(self.dist / "background.js")
        self.rejects("source-symlink")
        link.unlink()
        (self.dist / "META-INF").mkdir()
        self.rejects("source-signature-metadata")

    def test_cli_outputs_only_safe_categories_not_untrusted_values(self):
        secret = "synthetic-never-print-this-marker"
        self.archive(extras=[("META-INF/" + secret, b"untrusted bytes")])
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.dist), str(self.xpi), "2.0.6"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stderr)["category"], "unexpected-signature-metadata")
        self.archive()
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.dist), str(self.xpi), "2.0.6"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["cryptographic_signature_verified"])


if __name__ == "__main__":
    unittest.main()
