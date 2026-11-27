"""Member 3, Milestone 2: the member builds and sends a verified decryption share."""
import json
import logging
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from treasury import founder, member
from treasury.crypto_utils import load_public_key
from treasury.opening import (DecryptionShare, OpeningError, decrypt_vault, load_public_vault,
                              public_share_key, threshold_decrypt, verify_decryption_share)


class MemberOpenShareTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = root = Path(tmp.name)
        patches = [patch.object(member, "DATA_DIR", root)]
        for name, value in (("DATA_DIR", root), ("FOUNDER_DIR", root / "founder"),
                            ("FOUNDER_PRIVATE", root / "founder" / "founder_private.pem"),
                            ("FOUNDER_PUBLIC", root / "founder.pub"), ("VAULT_DIR", root / "vault"),
                            ("GENERATIONS_DIR", root / "vault" / "generations"),
                            ("CURRENT_FILE", root / "vault" / "current.json"),
                            ("REQUESTS_DIR", root / "requests"), ("CERTS_DIR", root / "certs")):
            patches.append(patch.object(founder, name, value))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.log = logging.getLogger("test-member-m2")
        self.log.addHandler(logging.NullHandler())
        self.log.propagate = False
        for name in member.MEMBER_NAMES:
            member.init_identity(name, self.log)
        (root / "requests" / "server.json").write_text(
            (root / "requests" / "M1.json").read_text().replace('"M1"', '"server"'))
        founder.setup_ca(Mock())
        founder.sign_certificates(Mock())
        founder.setup_vault(Mock())
        self.founder_pub = load_public_key(founder.FOUNDER_PUBLIC.read_text())
        self.vault = load_public_vault(self.founder_pub, root)

    def test_body_carries_a_valid_proof_and_no_secret(self):
        body = member.build_open_share_body(member.load_identity("M3"))
        self.assertEqual(set(body), {"generation", "c1", "index", "d", "proof"})
        self.assertEqual((body["generation"], body["index"]), (self.vault.generation, 3))
        self.assertEqual(int(body["c1"], 16), self.vault.c1)
        share_file = json.loads(member.member_dir("M3").joinpath(
            "m2", "generations", self.vault.generation, "share.json").read_text())
        self.assertNotIn(share_file["s_i"], json.dumps(body))
        share = DecryptionShare.from_dict({k: body[k] for k in ("index", "d", "proof")})
        self.assertTrue(verify_decryption_share(share, self.vault.c1,
                                                public_share_key(3, self.vault.commitments)))

    def test_three_member_bodies_open_the_vault(self):
        shares = [DecryptionShare.from_dict(
            {k: v for k, v in member.build_open_share_body(member.load_identity(n)).items()
             if k in ("index", "d", "proof")}) for n in ("M2", "M4", "M5")]
        result = threshold_decrypt(self.vault.c1, self.vault.c2, self.vault.commitments,
                                   shares, self.vault.t, self.vault.n)
        self.assertEqual(decrypt_vault(result.m, self.vault), founder.VAULT_PLAINTEXT)

    def test_member_refuses_bad_share_or_missing_vault(self):
        path = member.member_dir("M1") / "m2" / "generations" / self.vault.generation / "share.json"
        record = json.loads(path.read_text())
        record["index"] = 2
        path.write_text(json.dumps(record))
        with self.assertRaises(OpeningError):
            member.build_open_share_body(member.load_identity("M1"))
        shutil.rmtree(self.root / "vault")
        with self.assertRaises(OpeningError):
            member.build_open_share_body(member.load_identity("M2"))

    def test_open_flag_sends_open_share_request(self):
        sent = []

        def fake_connect(args, identity, log, mode):
            body = member.build_open_share_body(identity, log=log) if args.open else None
            sent.append((identity.name, body["index"]))

        with patch.object(member, "connect_and_run", fake_connect), \
                patch.object(member, "get_logger", lambda name: self.log):
            self.assertEqual(member.main(["--name", "M4", "--open"]), 0)
        self.assertEqual(sent, [("M4", 4)])


if __name__ == "__main__":
    unittest.main()
