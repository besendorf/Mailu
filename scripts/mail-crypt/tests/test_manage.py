import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import keyring
import manage


class ManageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = keyring.create("308ebd91-d9b4-4fd6-9d5a-730968f1ae59", "password", "test")

    def test_files_are_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            manage.write_document(path, self.document)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(manage.read_document(path), self.document)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                manage.write_document(path, self.document)
            self.assertEqual(path.read_bytes(), original)

    def test_symlinks_and_non_regular_files_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            manage.write_document(path, self.document)
            link = Path(directory) / "symlink.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                manage.read_document(link)
            with self.assertRaises(FileExistsError):
                manage.write_document(link, self.document)
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(keyring.KeyringError):
                manage.read_document(fifo)

    def test_interrupted_write_cleans_up_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            with mock.patch.object(manage.os, "fsync", side_effect=OSError("test write failure")):
                with self.assertRaises(OSError):
                    manage.write_document(path, self.document)
            self.assertFalse(path.exists())

    def test_noninteractive_password_entry_is_refused(self):
        with mock.patch.object(manage.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(keyring.KeyringError):
                manage.prompt_secret("Password")

    def test_init_cli_and_password_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "envelope.json"
            argv = ["init", str(path), "--mailbox-id", self.document["mailbox_id"],
                    "--credential-id", "password"]
            with mock.patch.object(manage, "prompt_secret", return_value="test"):
                self.assertEqual(manage.main(argv), 0)
            self.assertEqual(manage.read_document(path)["mailbox_id"], self.document["mailbox_id"])
        with mock.patch.object(manage.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(manage.getpass, "getpass", side_effect=["one", "two"]):
            with self.assertRaises(keyring.KeyringError):
                manage.prompt_secret("New", confirm=True)

    def test_cli_credential_lifecycle(self):
        mailbox_id = self.document["mailbox_id"]
        with tempfile.TemporaryDirectory() as directory:
            initial, added, replaced, removed = [
                str(Path(directory) / name) for name in ("initial", "added", "replaced", "removed")
            ]
            manage.write_document(initial, self.document)
            for command, source, target, slot, prompts in (
                ("add", initial, added, "phone", ["test", "phone secret"]),
                ("replace", added, replaced, "password", ["test", "new test"]),
                ("remove", replaced, removed, "phone", ["new test"]),
            ):
                argv = [command, source, target, "--mailbox-id", mailbox_id,
                        "--unlock-id", "password", "--credential-id", slot]
                with self.subTest(command=command), \
                        mock.patch.object(manage, "prompt_secret", side_effect=prompts):
                    self.assertEqual(manage.main(argv), 0)
            document = manage.read_document(removed)
            self.assertEqual(set(document["slots"]), {"password"})
            keyring.unlock(document, "password", "new test", mailbox_id=mailbox_id)
            self.assertEqual(manage.read_document(initial), self.document)


if __name__ == "__main__":
    unittest.main()
