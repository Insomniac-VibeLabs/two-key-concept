"""origin is passed down per call, not stored on the TwoKey, so one call cannot label another's decision."""

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class Origin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)

    def origins(self):
        return [e.body["origin"] for e in self.tk.ledger.entries if e.kind == "decision"]

    def test_no_origin_state_on_the_instance(self):
        self.tk.authorize(SEARCH, {"q": "x"}, "look", origin="cli")
        self.assertFalse(hasattr(self.tk, "_origin"))

    def test_each_call_records_its_own_origin(self):
        self.tk.authorize(SEARCH, {"q": "x"}, "look", origin="cli")
        self.tk.authorize(SEARCH, {"q": "x"}, "look")
        self.tk.authorize({"tool": "Bad Name!"}, {}, "x", origin="cli")      # early deny path
        self.tk.authorize_from_agent(None, None)                               # early deny via agent path
        self.assertEqual(self.origins(), ["cli", "library", "cli", "library"])

    def test_interleaved_calls_keep_their_origin(self):
        # A slow call that started as "cli" still records "cli" after a "library" call ran meanwhile.
        started, release = threading.Event(), threading.Event()
        real = self.tk._authorize

        def slow(*a, **kw):
            if kw.get("origin") == "cli":
                started.set()
                release.wait(5)
            return real(*a, **kw)
        with mock.patch.object(self.tk, "_authorize", side_effect=slow):
            t = threading.Thread(target=self.tk.authorize, args=(SEARCH, {"q": "x"}, "look"), kwargs={"origin": "cli"})
            t.start()
            started.wait(5)
            self.tk.authorize(SEARCH, {"q": "y"}, "look")
            release.set()
            t.join(5)
        self.assertEqual(sorted(self.origins()), ["cli", "library"])
        self.assertEqual(self.origins()[-1], "cli")


if __name__ == "__main__":
    unittest.main()
