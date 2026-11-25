import unittest
from types import SimpleNamespace as N
from systemsentinel.updates import summarize_candidates


class UpdateTests(unittest.TestCase):
    def test_candidates_and_trusted_security_origin(self):
        def pkg(name, origin, upgrade=True):
            return N(name=name, is_installed=True, is_upgradable=upgrade,
                     installed=N(version="1"), candidate=N(version="2", origins=[origin]))
        ubuntu = N(origin="Ubuntu", archive="noble-security", label="Ubuntu", trusted=True)
        untrusted = N(origin="Ubuntu", archive="noble-security", label="Ubuntu", trusted=False)
        debian = N(origin="Debian", archive="stable-security", label="Debian-Security", trusted=True)
        results = summarize_candidates([pkg("other", untrusted), pkg("ubuntu", ubuntu), pkg("debian", debian), pkg("current", ubuntu, False)])
        self.assertEqual([r["package"] for r in results], ["debian", "ubuntu", "other"])
        self.assertEqual([r["security_pocket"] for r in results], [True, True, False])

    def test_release_validity_unknown_expired_and_missing(self):
        from datetime import datetime, timezone
        from pathlib import Path
        import tempfile
        from systemsentinel.updates import index_validity
        now = datetime(2026, 11, 25, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            self.assertEqual(index_validity(path, now)["status"], "missing")
            (path / "one_InRelease").write_text("Date: Tue, 24 Nov 2026 00:00:00 UTC\nValid-Until: Fri, 27 Nov 2026 00:00:00 UTC\nSHA256:\n")
            self.assertEqual(index_validity(path, now)["status"], "within_declared_validity")
            (path / "two_Release").write_text("Date: Tue, 24 Nov 2026 00:00:00 UTC\nSHA256:\n")
            self.assertEqual(index_validity(path, now)["status"], "unknown")
            (path / "three_InRelease").write_text("Valid-Until: Tue, 24 Nov 2026 00:00:00 UTC\n")
            summary = index_validity(path, now)
            self.assertEqual(summary["status"], "expired")
            self.assertEqual(summary["expired"], 1)
            self.assertEqual(summary["no_expiry"], 1)
