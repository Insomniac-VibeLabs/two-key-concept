"""Gateway refusals of an authenticated token are ledgered as gateway_denied: reason, jti, tool, size, digest."""

import json
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import MAX_ARGS_BYTES
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}
SECRET = "zz-secret-argument-value-zz"


def nest(n):
    v = 1
    for _ in range(n):
        v = {"x": v}
    return v


class GatewayDenied(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", RULES, key, SPECS)
        self.tk = TwoKey(Ledger(Path(self.tmp.name, "ledger"), key), key.public_key(),
                         verify_signed(env, key.public_key()), [FixedJudge("a", "yes")], private_key=key,
                         quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT)
        self.gw = ToolGateway(self.tk.ledger, self.tk.issuer, self.tk.compiled, tools={"search": lambda a: "ok"})
        d = self.tk.authorize(SEARCH, {"q": "weather"}, "look")
        self.assertTrue(d.allowed, d.reason)
        self.token = d.token

    def denied(self):
        return [e.body for e in self.tk.ledger.entries if e.kind == "gateway_denied"]

    def ledger_text(self):
        return json.dumps([e.body for e in self.tk.ledger.entries])

    def test_unauthenticated_tokens_write_nothing(self):
        before = self.tk.ledger.size()
        for token in ("garbage", "tk1.e30.AAAA", self.token[:-4] + "AAAA", None):
            self.assertFalse(self.gw.invoke(token, "search", {"q": "x"}).allowed)
        self.assertEqual(self.tk.ledger.size(), before)

    def test_args_mismatch_is_ledgered_without_values(self):
        r = self.gw.invoke(self.token, "search", {"q": SECRET})
        self.assertEqual(r.reason, "args_mismatch")
        [body] = self.denied()
        self.assertEqual(body["reason"], "args_mismatch")
        self.assertEqual(body["tool"], "search")
        self.assertEqual(len(body["jti"]), 32)
        self.assertTrue(body["tool_args_digest"].startswith("sha256:"))
        self.assertGreater(body["tool_args_size"], 0)
        self.assertNotIn(SECRET, self.ledger_text())

    def test_huge_tool_name_is_recorded_by_size_and_digest(self):
        big = "t" * (1 << 20)
        r = self.gw.invoke(self.token, big, {"q": "weather"})
        self.assertEqual(r.reason, "tool_mismatch")
        [body] = self.denied()
        self.assertIsNone(body["tool"])
        self.assertGreater(body["tool_size"], 1 << 20)
        self.assertLess(len(self.ledger_text()), 100_000)

    def test_oversized_and_deep_arguments(self):
        self.assertEqual(self.gw.invoke(self.token, "search", {"q": SECRET * (MAX_ARGS_BYTES // 10)}).reason,
                         "args_too_large")
        self.assertEqual(self.gw.invoke(self.token, "search", {"q": nest(5000)}).reason,
                         "invalid_call:tool args are nested too deeply")
        big, deep = self.denied()
        self.assertEqual(big["reason"], "args_too_large")
        self.assertGreater(big["tool_args_size"], MAX_ARGS_BYTES)
        self.assertEqual(deep["reason"], "invalid_call:tool args are nested too deeply")
        self.assertIn("tool_args_size", deep)
        self.assertNotIn(SECRET, self.ledger_text())

    def test_replay_is_ledgered_and_success_is_not_a_deny(self):
        self.assertTrue(self.gw.invoke(self.token, "search", {"q": "weather"}).allowed)
        self.assertEqual(self.denied(), [])
        self.assertEqual(self.gw.invoke(self.token, "search", {"q": "weather"}).reason, "already_redeemed")
        self.assertEqual([b["reason"] for b in self.denied()], ["already_redeemed"])
        self.tk.ledger.verify()


if __name__ == "__main__":
    unittest.main()
