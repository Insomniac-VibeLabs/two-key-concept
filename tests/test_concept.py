"""Concept invariants: both paths, ledger, token, agent hook, no execution."""

import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from two_key.agents import MonitoredAgent, parse_proposal
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import FixedJudge


RULES = [
    {"id": "tools", "allow_only_tools": ["search", "email_draft"]},
    {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
    {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    {"id": "sensitive", "deny_if": {"data_class_in": ["medical", "classified"]}},
]
PROSE = "Never wire money. Cap spend at 200. No medical or classified data."


def _engine(tmp, votes=("yes", "yes")):
    key = generate_private_key()
    env = sign_constitution(PROSE, RULES, key)
    ledger = Ledger(Path(tmp), key)
    judges = [FixedJudge(f"j{i}", vote, provider=f"p{i}") for i, vote in enumerate(votes)]
    tk = TwoKey(ledger, key.public_key(), verify_signed(env, key.public_key()), judges,
                private_key=key, quorum=QuorumPolicy(required_yes=len(votes)), allow_test_doubles=True)
    return key, tk


class ConceptTests(unittest.TestCase):
    def test_both_paths_required_and_ledger_records_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, ("yes", "no"))
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft a note")
            self.assertFalse(decision.allowed)
            self.assertIsNone(decision.token)
            self.assertTrue(decision.path_a["allowed"])
            self.assertFalse(decision.path_b["passed"])
            kinds = [e.kind for e in tk.ledger.entries]
            self.assertIn("path_a", kinds)
            self.assertIn("path_b", kinds)
            tk.ledger.verify()

    def test_path_a_deny_still_runs_path_b(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "wire_transfer", "amount_usd": 10, "data_class": "public", "irreversible": True},
                {"to": "bob"}, "wire it")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "tools")
            self.assertIn("path_b", [e.kind for e in tk.ledger.entries])

    def test_token_single_use_and_bound_to_args(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft")
            self.assertTrue(decision.allowed)
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled,
                             tools={"email_draft": lambda a: calls.append(a) or {"ok": True}})
            first = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            replay = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            mismatch = gw.invoke(decision.token, "email_draft", {"to": "eve"})
            self.assertTrue(first.allowed)
            self.assertEqual(calls, [{"to": "ada"}])
            self.assertEqual(replay.reason, "already_redeemed")
            self.assertFalse(mismatch.allowed)

    def test_agent_hook_does_not_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            agent = MonitoredAgent("grok", "xai", "grok", "https://api.x.ai/v1", "cloud", kind="openai_compatible")
            raw = json.dumps({"tool": "email_draft", "arguments": {"to": "ada"}, "proposal": "draft a note",
                              "amount_usd": 0, "data_class": "public", "irreversible": False})
            decision = tk.authorize_from_agent(agent, raw, agent_session="sess")
            self.assertTrue(decision.allowed)
            self.assertFalse(decision.agent["trusted"])
            self.assertEqual(decision.agent["hosting"], "cloud")
            self.assertFalse(hasattr(decision, "tool_output"))

    def test_revoke_blocks_outstanding_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "search", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"q": "weather"}, "search")
            tk.revoke("principal stop")
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"search": lambda a: a})
            result = gw.invoke(decision.token, "search", {"q": "weather"})
            self.assertEqual(result.reason, "revoked_or_reloaded")

    def test_unsigned_constitution_refused(self):
        key = generate_private_key()
        env = sign_constitution(PROSE, RULES, key)
        env["signature"] = "aa"
        with self.assertRaises(Exception):
            verify_signed(env, key.public_key())

    def test_schema_400_falls_back_once(self):
        class Rec:
            def __init__(self):
                self.calls = []
            def __call__(self, url, headers, body, timeout):
                self.calls.append(body)
                if len(self.calls) == 1:
                    raise urllib.error.HTTPError("u", 400, "schema", {}, None)
                return {"choices": [{"message": {"content": json.dumps(
                    {"consistent": True, "confidence": 0.9, "rationale": "ok"})}}]}
        rec = Rec()
        judge = OpenAICompatibleJudge("x", "xai", "grok", "https://api.x.ai/v1", transport=rec)
        from two_key.action import normalize_action
        ballot = judge.score_bound(PROSE, normalize_action({"tool": "search", "data_class": "public", "irreversible": False}), "search", None, agent_session="principal-session")
        self.assertEqual(ballot.vote, "yes")
        self.assertEqual(rec.calls[0]["response_format"]["type"], "json_schema")
        self.assertEqual(rec.calls[0]["reasoning_effort"], "low")
        self.assertNotIn("reasoning_effort", rec.calls[1])
        self.assertEqual(rec.calls[1]["response_format"]["type"], "json_object")

    def test_proposal_parser_rejects_extra_keys(self):
        with self.assertRaises(Exception):
            parse_proposal(json.dumps({"tool": "search", "arguments": {}, "proposal": "x", "exec": True}))


if __name__ == "__main__":
    unittest.main()
