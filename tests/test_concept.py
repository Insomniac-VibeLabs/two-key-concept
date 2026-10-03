"""Concept invariants: both paths, ledger, token, agent hook, no execution."""

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from two_key.agents import MonitoredAgent, parse_proposal
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.gateway import ToolGateway
from two_key.judges.config import JudgeConfigError, build_credential
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.ledger import LedgerError, merkle_root
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



    def test_tool_error_does_not_consume_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft")
            calls = {"n": 0}
            def flaky(args):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError("backend down")
                return {"ok": True}
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"email_draft": flaky})
            first = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            second = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            self.assertFalse(first.allowed)
            self.assertTrue(first.reason.startswith("tool_error:"))
            self.assertTrue(second.allowed)
            self.assertEqual(calls["n"], 2)

    def test_crash_after_intent_does_not_run_tool_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"to": "ada"}, "draft")
            payload = tk.issuer.verify(decision.token)
            tk.ledger.append("redemption_started", {"jti": payload["jti"], "tool": "email_draft"})
            tk.ledger.checkpoint()
            calls = {"n": 0}
            def tool(args):
                calls["n"] += 1
                return {"ok": True}
            gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={"email_draft": tool})
            result = gw.invoke(decision.token, "email_draft", {"to": "ada"})
            self.assertFalse(result.allowed)
            self.assertEqual(result.reason, "already_attempted")
            self.assertEqual(calls["n"], 0)

    def test_merkle_does_not_duplicate_odd_leaf(self):
        leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(3)]
        root = merkle_root(leaves)
        duplicated = hashlib.sha256(b"\x01" + hashlib.sha256(b"\x01" + hashlib.sha256(b"\x00" + leaves[0]).digest() + hashlib.sha256(b"\x00" + leaves[1]).digest()).digest() + hashlib.sha256(b"\x01" + hashlib.sha256(b"\x00" + leaves[2]).digest() + hashlib.sha256(b"\x00" + leaves[2]).digest()).digest()).digest()
        self.assertNotEqual(root, duplicated)
        self.assertEqual(len(root), 32)

    def test_ledger_ciphertext_and_witness(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            raw = Path(tmp, "entries.jsonl").read_text()
            self.assertNotIn("constitution_loaded", raw)
            self.assertIn("two-key-concept-ledger-enc/1", raw)
            self.assertFalse(any(p.name == "witness.pem" for p in Path(tmp).iterdir()))
            self.assertTrue(tk.ledger.witness_path.exists())
            self.assertFalse(str(tk.ledger.witness_path).startswith(str(Path(tmp)) + "/"))
            key = tk.ledger.private_key
            Ledger(tmp, key).verify()
            with self.assertRaises(LedgerError):
                Ledger(tmp, key, ledger_key_path=Path(tmp, "missing.key"))
            with self.assertRaises(LedgerError):
                Ledger(tmp, generate_private_key())

    def test_missing_witness_refuses_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            witness = tk.ledger.witness_path
            witness.unlink()
            with self.assertRaises(LedgerError):
                tk.ledger.append("revocation", {"reason": "stop"})
                tk.ledger.checkpoint()

    def test_encrypted_ledger_reloads_in_second_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            from two_key.keys import save_private_key
            save_private_key(Path(tmp, "principal.pem"), key)
            ledger = Path(tmp, "ledger")
            led = Ledger(ledger, key)
            led.append("note", {"ok": True})
            led.checkpoint()
            script = "from two_key.ledger import Ledger; from two_key.keys import load_private_key; " \
                     "led = Ledger(%r, load_private_key(%r)); led.verify(); print(led.size())" % (str(ledger), str(Path(tmp, "principal.pem")))
            proc = subprocess.run([sys.executable, "-c", script], cwd="/tmp/two-key-concept", env={"PYTHONPATH": "/tmp/two-key-concept"},
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), "1")

    def test_stub_auth_rejected(self):
        with self.assertRaises(JudgeConfigError):
            build_credential({"type": "username_password", "username": "me", "password_env": "PW"})
        with self.assertRaises(JudgeConfigError):
            build_credential({"type": "oauth_device_code", "client_id": "x",
                              "device_authorization_endpoint": "https://example/device",
                              "token_endpoint": "https://example/token"})

    def test_cli_authorize_does_not_execute(self):
        from two_key.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            key = generate_private_key()
            from two_key.keys import save_private_key
            from two_key.constitution import save_envelope
            save_private_key(Path(tmp, "principal.pem"), key)
            save_envelope(Path(tmp, "c.json"), sign_constitution(PROSE, RULES, key))
            judges = [FixedJudge("a", "yes", provider="p0"), FixedJudge("b", "yes", provider="p1")]
            with self.assertRaises(SystemExit):
                main(["authorize", "--allow-test-doubles"])
            buf = io.StringIO()
            with patch("two_key.judges.config.load_config_file", return_value=(judges, QuorumPolicy(required_yes=2))):
                with redirect_stdout(buf):
                    with self.assertRaises(ValueError):
                        main(["authorize", "--key", str(Path(tmp, "principal.pem")),
                              "--ledger", str(Path(tmp, "ledger")),
                              "--constitution", str(Path(tmp, "c.json")),
                              "--judges", str(Path(tmp, "unused.yaml")),
                              "--tool", "email_draft", "--args", '{"to":"ada"}',
                              "--proposal", "draft"])
            self.assertNotIn("both_paths_allow", buf.getvalue())



if __name__ == "__main__":
    unittest.main()
