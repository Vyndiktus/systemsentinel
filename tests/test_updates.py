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
