"""The judge-is-not-the-agent rule (owner decision, 2026-10-08).

A judge is the same specific agent when it holds the agent's credential (an API token, a username/password
pair, or a session), at any address, or when neither side has a credential on the same address.
Any model from any vendor is allowed; likely accidents are warned and recorded. Usernames and passwords are
HTTP Basic over HTTPS only and are compared as one HMAC-fingerprinted pair.
"""

import base64
import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from two_key.action import normalize_action
from two_key.agents import AgentConfigError, MonitoredAgent, load_agents
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.identity import (AgentDeclaration, IdentityError, check_separation, compare, configured_agent_identity,
                              judge_identity, separation_warnings)
from two_key.judges.base import Ballot, Judge
from two_key.judges.config import JudgeConfigError, build_credential, load_config
from two_key.judges.credentials import BasicAuthCredential, CredentialError, StaticToken
from two_key.judges.ollama import OllamaJudge
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy, _score_one

FP = b"k" * 32
SEARCH = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
BALLOT = '{"consistent": true, "confidence": 0.9, "rationale": "ok"}'


def side(model, base_url, key=None, jid="j", credential=None):
    return SimpleNamespace(judge_id=jid, model=model, base_url=base_url, provider="x",
                           credential=credential or (StaticToken(key) if key else None), tenant=None, upstream=None)


class EnvVars(unittest.TestCase):
    def setenv(self, **values):
        for k, v in values.items():
            old = os.environ.get(k)
            os.environ[k] = v
            self.addCleanup(lambda k=k, old=old: os.environ.pop(k, None) if old is None
                            else os.environ.__setitem__(k, old))


class Rule(EnvVars):
    def agent(self, **kw):
        self.setenv(RULE_AGENT_KEY="agent-key")
        decl = {"id": "agent", "model": "gpt-4o", "provider": "openai", "base_url": "https://api.openai.com/v1",
                "credential_env": "RULE_AGENT_KEY", **kw}
        return AgentDeclaration.from_mapping(decl).resolve(fp_key=FP)

    def test_the_same_credential_refuses_at_any_address(self):
        a = self.agent()
        self.assertRegex(compare(a, judge_identity(side("gpt-4o-mini", "https://api.openai.com/v1", "agent-key"), FP)),
                         "the same credential on the same address api.openai.com:443")
        for url, where in (("https://openrouter.ai/api/v1", "openrouter.ai:443"),
                           ("http://localhost:4000", "localhost:4000"),           # a pass-through proxy
                           ("https://llm.corp.example/v1", "llm.corp.example:443")):   # another name for a server
            with self.subTest(url=url):
                self.assertRegex(compare(a, judge_identity(side("gpt-4o", url, " agent-key\n"), FP)),
                                 f"the same credential \\(agent at api.openai.com:443, judge at {where}\\); "
                                 "a credential identifies its holder")
        # Same address, another key: allowed, whatever the model.
        for model in ("gpt-4o", "gpt-4o-mini", "o3"):
            self.assertIsNone(compare(a, judge_identity(side(model, "https://api.openai.com/v1", "judge-key"), FP)))

    def test_a_shared_placeholder_refuses_and_the_message_says_what_to_do(self):
        a = AgentDeclaration.from_mapping({"id": "agent", "model": "llama3.1:8b", "provider": "vllm",
                                           "base_url": "http://localhost:8000/v1", "credential_env": "RULE_PLACEHOLDER"})
        self.setenv(RULE_PLACEHOLDER="EMPTY")
        a = a.resolve(fp_key=FP)
        msg = compare(a, judge_identity(side("qwen2.5:7b", "http://localhost:8001/v1", "EMPTY"), FP))
        self.assertRegex(msg, "give each side its own value or credential: none")
        self.assertIsNone(compare(a, judge_identity(side("qwen2.5:7b", "http://localhost:8001/v1", "EMPTY-2"), FP)))
        self.assertIsNone(compare(a, judge_identity(side("qwen2.5:7b", "http://localhost:8001/v1"), FP)))

    def test_any_model_any_vendor_elsewhere_has_no_warning(self):
        a = self.agent()
        for model, url in (("claude-sonnet-4-5", "https://api.anthropic.com"), ("gemini-2.5-pro",
                           "https://generativelanguage.googleapis.com"), ("grok-4", "https://api.x.ai/v1")):
            j = judge_identity(side(model, url, "judge-key"), FP)
            self.assertIsNone(compare(a, j))
            self.assertEqual(separation_warnings(a, j), [])

    def test_keyless_on_one_address(self):
        a = AgentDeclaration.from_mapping({"id": "agent", "model": "llama3.1:8b", "provider": "ollama",
                                           "base_url": "http://localhost:11434", "credential": "none"}).resolve(fp_key=FP)
        both = judge_identity(side("qwen2.5:7b", "http://127.0.0.1:11434"), FP)
        self.assertRegex(compare(a, both), "the same address localhost:11434 and no credential on either side")
        one = judge_identity(side("qwen2.5:7b", "http://localhost:11434", "judge-key"), FP)
        self.assertIsNone(compare(a, one))
        self.assertIn("same_address_one_side_keyless", [w["check"] for w in separation_warnings(a, one)])
        other_daemon = judge_identity(side("qwen2.5:7b", "http://localhost:11435"), FP)
        self.assertIsNone(compare(a, other_daemon))

    def test_a_credential_the_connector_never_sends_is_keyless(self):
        self.setenv(RULE_UNSENT="dummy")
        a = AgentDeclaration.from_mapping({"id": "agent", "model": "llama3.1:8b", "provider": "ollama",
                                           "base_url": "http://localhost:11434", "credential": "none"}).resolve(fp_key=FP)
        cred = build_credential({"type": "env", "var": "RULE_UNSENT"})
        unsent = OllamaJudge("o", "ollama", "llama3.1:8b", "http://localhost:11434", cred)   # auth_header: none
        self.assertEqual(unsent._auth_headers(), {})
        self.assertRegex(compare(a, judge_identity(unsent, FP)), "no credential on either side")
        sent = OllamaJudge("o", "ollama", "llama3.1:8b", "http://localhost:11434", cred, auth_header="bearer")
        self.assertIsNone(compare(a, judge_identity(sent, FP)))

    def test_a_configured_agent_is_fingerprinted_by_what_it_sends(self):
        self.setenv(RULE_UNSENT="dummy")
        os.environ.pop("RULE_NEVER_SET", None)
        cred = build_credential({"type": "env", "var": "RULE_UNSENT"})
        ollama = MonitoredAgent("local", "local", "llama3.1:8b", "http://localhost:11434", "local", cred, kind="ollama")
        self.assertEqual(ollama._headers(), {})
        self.assertEqual(configured_agent_identity(ollama, FP).credentials, frozenset({"none"}))
        unreadable = MonitoredAgent("gw", "openai", "m", "https://localhost:8443/v1", "local",
                                    build_credential({"type": "env", "var": "RULE_NEVER_SET"}), kind="openai_compatible")
        with self.assertRaisesRegex(IdentityError, "credential could not be read at start-up"):
            configured_agent_identity(unreadable, FP)

    def test_an_unresolved_identity_is_warned_once(self):
        a = self.agent(base_url="https://llm.corp.example/v1", model="agent-model")
        judges = [judge_identity(side("claude-sonnet-4-5", "https://api.anthropic.com", f"k{i}", jid=f"j{i}"), FP)
                  for i in range(3)]
        with contextlib.redirect_stderr(io.StringIO()) as err:
            report = check_separation([a], judges)
        self.assertEqual([w["check"] for w in report.warnings], ["unresolved_identity"])
        self.assertEqual(err.getvalue().count("(unresolved_identity)"), 1)

    def test_refusal_message_and_warnings_are_raised_and_printed(self):
        a = self.agent()
        same = judge_identity(side("gpt-4o-mini", "https://api.openai.com/v1", "agent-key", jid="bad"), FP)
        with self.assertRaisesRegex(IdentityError, "^judge_matches_agent: a judge is the monitored agent: judge 'bad'"):
            check_separation([a], [same])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            report = check_separation([a], [judge_identity(side("gpt-4o", "https://api.openai.com/v1", "k2"), FP)])
        self.assertEqual([w["check"] for w in report.warnings], ["same_model_same_address"])
        self.assertIn("two-key: WARNING: judge 'j' vs agent 'agent'", err.getvalue())
        self.assertEqual(report.to_record()["warnings"], [dict(w) for w in report.warnings])


class Basic(EnvVars):
    def test_the_credential_is_the_pair(self):
        self.setenv(BA_USER="alice", BA_PASS="s3cret")
        self.assertEqual(BasicAuthCredential("BA_USER", "BA_PASS").get_token(), "alice:s3cret")
        self.assertNotIn("s3cret", repr(BasicAuthCredential("BA_USER", "BA_PASS")))
        self.setenv(BA_USER="al:ice")
        with self.assertRaisesRegex(CredentialError, "must not contain ':'"):
            BasicAuthCredential("BA_USER", "BA_PASS").get_token()
        with self.assertRaisesRegex(CredentialError, "BA_MISSING is not set"):
            BasicAuthCredential("BA_USER", "BA_MISSING").get_token()

    def test_config(self):
        cred = build_credential({"type": "basic", "username_env": "U", "password_env": "P"})
        self.assertEqual(cred.kind, "basic")
        for bad, pattern in (({"type": "basic", "username_env": "U"}, "needs username_env and password_env"),
                             ({"type": "basic", "username_env": "U", "password_env": "P", "user": "x"}, "only"),
                             ({"type": "basic", "username_env": "U", "password": "x"}, "secrets must not be written"),
                             ({"type": "username_password"}, "now auth type basic")):
            with self.subTest(auth=bad):
                with self.assertRaisesRegex(JudgeConfigError, pattern):
                    build_credential(bad)

    def test_https_only_and_the_header(self):
        self.setenv(BA_USER="alice", BA_PASS="s3cret")
        cred = BasicAuthCredential("BA_USER", "BA_PASS")
        for url in ("http://localhost:8000/v1", "http://192.168.1.9:8000/v1"):
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "username and password over plain HTTP"):
                    OpenAICompatibleJudge("b", "x", "m", url, cred, allow_insecure_http=True)
        with self.assertRaisesRegex(ValueError, "auth_header basic goes only with auth type basic"):
            OpenAICompatibleJudge("b", "x", "m", "https://h.example/v1", StaticToken("t"), auth_header="basic")
        with self.assertRaisesRegex(ValueError, "auth_header basic goes only with auth type basic"):
            OpenAICompatibleJudge("b", "x", "m", "https://h.example/v1", cred, auth_header="bearer")
        j = OpenAICompatibleJudge("b", "x", "m", "https://h.example/v1", cred)
        self.assertEqual(j._auth_headers(),
                         {"Authorization": "Basic " + base64.b64encode(b"alice:s3cret").decode()})
        self.assertEqual(OllamaJudge("o", "ollama", "m", base_url="https://h.example", credential=cred).auth_header,
                         "basic")
        judges, _ = load_config({"judges": [{"id": "b", "type": "openai_compatible", "model": "m",
                                             "base_url": "https://h.example/v1",
                                             "auth": {"type": "basic", "username_env": "BA_USER",
                                                      "password_env": "BA_PASS"}}],
                                 "quorum": {"required_yes": 1}})
        self.assertEqual(judges[0].auth_header, "basic")

    def test_agent_declaration_pairs_compare_with_judges(self):
        self.setenv(BA_USER="alice", BA_PASS="s3cret", BA_PASS2="other")
        decl = {"id": "agent", "model": "m", "provider": "x", "base_url": "https://h.example/v1",
                "username_env": "BA_USER", "password_env": "BA_PASS"}
        a = AgentDeclaration.from_mapping(decl).resolve(fp_key=FP)
        same = judge_identity(side("other-model", "https://h.example/v1",
                                   credential=BasicAuthCredential("BA_USER", "BA_PASS")), FP)
        self.assertRegex(compare(a, same), "the same credential on the same address h.example:443")
        other = judge_identity(side("m", "https://h.example/v1",
                                    credential=BasicAuthCredential("BA_USER", "BA_PASS2")), FP)
        self.assertIsNone(compare(a, other))
        self.assertNotIn("s3cret", str(a.to_record()))

    def test_agent_declaration_checks(self):
        self.setenv(BA_USER="alice", BA_PASS="s3cret", RULE_AGENT_KEY="k")
        base = {"id": "agent", "model": "m", "provider": "x", "base_url": "https://h.example/v1"}
        bad = [({**base, "username_env": "BA_USER"}, "declare password_env"),
               ({**base, "username_env": "BA_USER", "password_env": "BA_PASS", "credential_env": "RULE_AGENT_KEY"},
                "exactly one of"),
               ({**base, "base_url": "http://localhost:8000/v1", "username_env": "BA_USER", "password_env": "BA_PASS"},
                "only over HTTPS"),
               ({**base, "username_env": "BA_USER", "password_env": "BA_UNSET"}, "BA_UNSET is not set")]
        for decl, pattern in bad:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(IdentityError, pattern):
                    AgentDeclaration.from_mapping(decl).resolve(fp_key=FP)

    def test_monitored_agent_https_only(self):
        self.setenv(BA_USER="alice", BA_PASS="s3cret")
        spec = {"id": "a", "type": "openai_compatible", "model": "m", "base_url": "http://localhost:8000/v1",
                "auth": {"type": "basic", "username_env": "BA_USER", "password_env": "BA_PASS"}}
        with self.assertRaisesRegex(AgentConfigError, "plain HTTP"):
            load_agents({"agents": [spec]})
        [agent] = load_agents({"agents": [dict(spec, base_url="https://h.example/v1")]})
        self.assertEqual(agent._headers(), {"Authorization": "Basic " + base64.b64encode(b"alice:s3cret").decode()})

    def test_runtime_session_check_decodes_basic(self):
        self.setenv(BA_USER="alice", BA_PASS="s3cret")

        def never(*a):
            raise AssertionError("must not call the model")
        j = OpenAICompatibleJudge("b", "x", "m", "https://h.example/v1", BasicAuthCredential("BA_USER", "BA_PASS"),
                                  transport=never)
        b = j.score_bound("c", SEARCH, "", None, agent_session="alice:s3cret")
        self.assertEqual(b.error, "cloud_judge_reused_agent_session")


class ScoreOne(unittest.TestCase):
    def test_a_type_error_inside_a_judge_is_an_abstention_not_a_retry_without_the_session(self):
        class Raises(Judge):
            judge_id, provider, calls = "r", "x", []

            def score(self, *a):
                raise AssertionError("not used")

            def score_bound(self, constitution_text, action, proposal, binding, agent_session=None):
                self.calls.append(agent_session)
                raise TypeError("a bug inside the judge")
        j = Raises()
        b = _score_one(j, "c", SEARCH, "", None, agent_session="s")
        self.assertEqual((b.vote, j.calls), ("abstain", ["s"]))
        self.assertIn("TypeError", b.error)

    def test_keywords_follow_the_signature(self):
        seen = {}

        class Old(Judge):
            judge_id, provider = "o", "x"

            def score(self, *a):
                raise AssertionError("not used")

            def score_bound(self, constitution_text, action, proposal, binding, agent_session=None):
                seen["old"] = agent_session
                return Ballot("o", "x", "yes", 0.9, "")

        class Any(Judge):
            judge_id, provider = "a", "x"

            def score(self, *a):
                raise AssertionError("not used")

            def score_bound(self, constitution_text, action, proposal, binding, **kw):
                seen["any"] = kw
                return Ballot("a", "x", "yes", 0.9, "")
        class Older(Judge):
            judge_id, provider = "n", "x"

            def score(self, *a):
                raise AssertionError("not used")

            def score_bound(self, constitution_text, action, proposal, binding):
                seen["older"] = True
                return Ballot("n", "x", "yes", 0.9, "")
        for judge in (Old(), Any(), Older()):
            self.assertEqual(_score_one(judge, "c", SEARCH, "", None, "s").vote, "yes")
        self.assertEqual(seen, {"old": "s", "any": {"agent_session": "s"}, "older": True})

    def test_an_unreadable_signature_gets_every_keyword(self):
        from two_key.quorum import _accepted

        class Opaque:
            __signature__ = "not a signature"   # inspect.signature raises TypeError

            def __call__(self, *a, **kw):
                return kw
        kw = {"agent_session": "s"}
        self.assertEqual(_accepted(Opaque(), kw), kw)


class EndToEnd(EnvVars):
    def test_a_judge_holding_the_agent_session_abstains_whatever_was_declared(self):
        self.setenv(E2E_AGENT_KEY="shared-session")
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", [{"id": "t", "allow_only_tools": ["search"]}], key,
                                {"search": {"irreversible": False, "data_class_floor": "public"}})
        calls = []

        def transport(url, headers, body, timeout):
            calls.append(url)
            return {"choices": [{"message": {"content": BALLOT}}]}
        agent = {"id": "agent", "model": "gpt-4o", "provider": "openai", "base_url": "https://api.openai.com/v1",
                 "credential_env": "E2E_AGENT_KEY"}
        # The judge holds the agent's key at any address: it does not start.
        for url in ("https://api.openai.com/v1", "https://openrouter.ai/api/v1"):
            same = OpenAICompatibleJudge("s", "x", "gpt-4o-mini", url, StaticToken("shared-session"),
                                         transport=transport)
            with self.subTest(url=url), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(TwoKeyConfigError, "judge_matches_agent: .*the same credential"):
                    TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                           [same], private_key=key, quorum=QuorumPolicy(required_yes=1), monitored_agent=agent)
        # The agent is declared with the wrong key (or at the wrong address), so the judge starts. At call time
        # it presents the agent's real session: it abstains without a call, wherever it connects.
        self.setenv(E2E_AGENT_KEY="declared-key")
        j = OpenAICompatibleJudge("j", "x", "gpt-4o", "https://openrouter.ai/api/v1", StaticToken("shared-session"),
                                  transport=transport)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            tk = TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()), [j],
                        private_key=key, quorum=QuorumPolicy(required_yes=1), monitored_agent=agent)
            d = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, {}, "look",
                             agent_session="shared-session")
            ok = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, {}, "look",
                              agent_session="the-agent-session")
        self.assertFalse(d.allowed)
        self.assertEqual(d.path_b["abstain"], 1)
        self.assertTrue(ok.allowed, ok.reason)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
