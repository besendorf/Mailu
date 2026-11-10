import copy
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
# Load the local experiment explicitly; do not import the unrelated PyPI
# package called 'keyring', or initialize the Flask application.
spec = importlib.util.spec_from_file_location("keyring", ROOT / "keyring.py")
keyring = importlib.util.module_from_spec(spec)
sys.modules["keyring"] = keyring
spec.loader.exec_module(keyring)

MAILBOX = "308ebd91-d9b4-4fd6-9d5a-730968f1ae59"
OTHER_MAILBOX = "78658d81-a3cb-421a-9e90-9f328aa2bc89"
PASSWORD = "a long test password 🔐"


class KeyringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = keyring.create(MAILBOX, "password", PASSWORD)

    def unlock(self, document=None, credential_id="password", secret=PASSWORD, mailbox_id=MAILBOX):
        return keyring.unlock(document if document is not None else self.document,
                              credential_id, secret, mailbox_id=mailbox_id)

    def test_round_trip_exports_openssl_compatible_key_pair(self):
        document = keyring.loads(keyring.dumps(self.document).encode())
        public_key = serialization.load_pem_public_key(keyring.public_pem(document))
        private_key = serialization.load_pem_private_key(
            keyring.private_pem(document, "password", PASSWORD, mailbox_id=MAILBOX), None,
        )
        self.assertEqual(public_key.public_numbers(), private_key.public_key().public_numbers())
        self.assertNotIn("PRIVATE KEY", keyring.dumps(document))
        self.assertNotIn(PASSWORD, keyring.dumps(document))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is not installed")
    def test_openssl_accepts_private_pem_and_derives_identical_public_key(self):
        private_pem = keyring.private_pem(self.document, "password", PASSWORD, mailbox_id=MAILBOX)
        result = subprocess.run(["openssl", "pkey", "-pubout"], input=private_pem,
                                capture_output=True, check=True)
        self.assertEqual(result.stdout, keyring.public_pem(self.document))

    def test_wrong_credential_and_missing_slot_fail(self):
        for credential_id, secret in (("password", "wrong"), ("absent", PASSWORD), ("password", "")):
            with self.subTest(credential_id=credential_id, secret=secret):
                with self.assertRaises(keyring.KeyringError):
                    self.unlock(credential_id=credential_id, secret=secret)

    def test_identity_is_supplied_by_caller(self):
        with mock.patch.object(keyring, "_derive") as derive:
            with self.assertRaises(keyring.KeyringError):
                self.unlock(mailbox_id=OTHER_MAILBOX)
            derive.assert_not_called()

    def test_enroll_replace_and_revoke_preserve_mailbox_key(self):
        before = copy.deepcopy(self.document)
        args = dict(unlock_id="password", unlock_secret=PASSWORD, mailbox_id=MAILBOX)
        added = keyring.add_credential(self.document, "app-phone", "app secret", **args)
        self.assertEqual(self.document, before)
        self.assertEqual(self.unlock().private_numbers(),
                         self.unlock(added, "app-phone", "app secret").private_numbers())
        replaced = keyring.replace_credential(added, "password", "new password", **args)
        self.assertEqual(self.unlock().private_numbers(),
                         self.unlock(replaced, secret="new password").private_numbers())
        with self.assertRaises(keyring.KeyringError):
            self.unlock(replaced)
        removed = keyring.remove_credential(
            replaced, "app-phone", unlock_id="password", unlock_secret="new password", mailbox_id=MAILBOX,
        )
        with self.assertRaises(keyring.KeyringError):
            self.unlock(removed, "app-phone", "app secret")
        self.unlock(removed, secret="new password")
        self.assertEqual(replaced["public_key"], before["public_key"])
        self.assertEqual(replaced["slots"]["app-phone"], added["slots"]["app-phone"])

    def test_ciphertext_salt_and_nonce_tampering_fail(self):
        for field in ("ciphertext", "salt", "nonce"):
            document = copy.deepcopy(self.document)
            value = bytearray(keyring._decode(document["slots"]["password"][field]))
            value[0] ^= 1
            document["slots"]["password"][field] = keyring._encode(value)
            with self.subTest(field=field), self.assertRaises(keyring.KeyringError):
                self.unlock(document)

    def test_swapped_slot_identity_and_public_key_fail(self):
        other = keyring.create(OTHER_MAILBOX, "password", PASSWORD)
        variants = []
        moved = copy.deepcopy(other)
        moved["slots"] = copy.deepcopy(self.document["slots"])
        variants.append((moved, "password", OTHER_MAILBOX))
        renamed = copy.deepcopy(self.document)
        renamed["slots"]["renamed"] = renamed["slots"].pop("password")
        variants.append((renamed, "renamed", MAILBOX))
        replaced_public = copy.deepcopy(self.document)
        replaced_public["public_key"] = other["public_key"]
        variants.append((replaced_public, "password", MAILBOX))
        for document, credential_id, mailbox_id in variants:
            with self.subTest(credential_id=credential_id, mailbox_id=mailbox_id):
                with self.assertRaises(keyring.KeyringError):
                    self.unlock(document, credential_id, mailbox_id=mailbox_id)

    def test_new_keys_and_wrappings_are_random(self):
        other = keyring.create(MAILBOX, "password", PASSWORD)
        self.assertNotEqual(other["public_key"], self.document["public_key"])
        renewed = keyring.replace_credential(
            self.document, "password", PASSWORD, unlock_id="password",
            unlock_secret=PASSWORD, mailbox_id=MAILBOX,
        )
        for field in ("salt", "nonce", "ciphertext"):
            self.assertNotEqual(renewed["slots"]["password"][field],
                                self.document["slots"]["password"][field])

    def test_invalid_metadata_rejected_before_kdf(self):
        variants = []
        for field, value in (("version", True), ("version", 2), ("mailbox_id", "user@example.org"),
                             ("slots", {}), ("slots", []), ("public_key", "a")):
            document = copy.deepcopy(self.document)
            document[field] = value
            variants.append(document)
        for field, value in (("kdf", "argon2-unlimited"), ("salt", "a"), ("nonce", ""),
                             ("ciphertext", ""), ("extra", "unexpected")):
            document = copy.deepcopy(self.document)
            document["slots"]["password"][field] = value
            variants.append(document)
        document = copy.deepcopy(self.document)
        document["slots"]["bad slot id"] = document["slots"].pop("password")
        variants.append(document)
        with mock.patch.object(keyring, "_derive") as derive:
            for document in variants:
                with self.subTest(document=document), self.assertRaises(keyring.KeyringError):
                    self.unlock(document)
            derive.assert_not_called()

    def test_json_bounds_duplicates_and_invalid_encoding(self):
        for data in (b"{" * 10000, b"\xff", b"[]", b"null", b"x" * 65537,
                     b'{"version":1,"version":1}', b'{"x":{"k":1,"k":2}}'):
            with self.subTest(data=data[:40]), self.assertRaises(keyring.KeyringError):
                keyring.loads(data)

    def test_lifecycle_rejects_destructive_mistakes(self):
        args = dict(unlock_id="password", unlock_secret=PASSWORD, mailbox_id=MAILBOX)
        for operation, extra in ((keyring.add_credential, ("password", "new")),
                                 (keyring.replace_credential, ("missing", "new")),
                                 (keyring.remove_credential, ("password",)),
                                 (keyring.remove_credential, ("missing",))):
            with self.subTest(operation=operation.__name__), self.assertRaises(keyring.KeyringError):
                operation(self.document, *extra, **args)

    def test_slot_limit(self):
        document = copy.deepcopy(self.document)
        for index in range(15):
            document["slots"][f"slot-{index}"] = document["slots"]["password"].copy()
        with self.assertRaises(keyring.KeyringError):
            keyring.add_credential(document, "too-many", "new", unlock_id="password",
                                   unlock_secret=PASSWORD, mailbox_id=MAILBOX)

    def test_invalid_creation_parameters_and_secret(self):
        with mock.patch.object(keyring, "_derive") as derive:
            for mailbox, credential_id in (("invalid", "password"), (MAILBOX, []),
                                            (MAILBOX, "x" * 65), (MAILBOX, "")):
                with self.subTest(credential_id=credential_id), self.assertRaises(keyring.KeyringError):
                    keyring.create(mailbox, credential_id, PASSWORD)
            derive.assert_not_called()
        for secret in (None, "", "\ud800", "a" * 4097):
            with self.subTest(secret=repr(secret)[:20]), self.assertRaises(keyring.KeyringError):
                keyring.create(MAILBOX, "password", secret)

    def test_exact_unicode_secret_is_preserved(self):
        document = keyring.create(MAILBOX, "password", "\u00e9")
        self.unlock(document, secret="\u00e9")
        with self.assertRaises(keyring.KeyringError):
            self.unlock(document, secret="e\u0301")


if __name__ == "__main__":
    unittest.main()
