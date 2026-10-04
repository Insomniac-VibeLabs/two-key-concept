"""Fix 3: a judge must not be the monitored agent. Checked at start-up from operator config only."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from two_key.action import normalize_action
from two_key.agents import load_agents
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.identity import (AgentDeclaration, credential_fingerprint, load_monitored_agent, model_maker,
                              normalize_model, resolve_upstreams)
from two_key.judges.anthropic import AnthropicJudge
from two_key.judges.credentials import EnvApiKey, StaticToken
from two_key.judges.ollama import OllamaJudge
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}
AGENT = {"id": "grok-agent", "model": "grok-4-0709", "provider": "xai", "base_url": "https://api.x.ai/v1",
         "credential_env": "SEP_AGENT_KEY"}


def claude(key="judge-anthropic-key", model="claude-sonnet-4-20250514"):
    return AnthropicJudge("claude", "anthropic", model, credential=StaticToken(key))


def oai(jid, model, base_url, key):
    return OpenAICompatibleJudge(jid, "x", model, base_url, StaticToken(key))


def start(tmp, judges, agent=AGENT, quorum=None, allow_test_doubles=True):
    key = generate_private_key()
    env = sign_constitution("Searching is fine.", RULES, key, SPECS)
    return TwoKey(Ledger(Path(tmp), key), key.public_key(), verify_signed(env, key.public_key()), judges,
                  private_key=key, quorum=quorum or QuorumPolicy(required_yes=1),
                  allow_test_doubles=allow_test_doubles, monitored_agent=agent)


class Env(unittest.TestCase):
    def setUp(self):
        os.environ["SEP_AGENT_KEY"] = "agent-secret-key"
        self.addCleanup(os.environ.pop, "SEP_AGENT_KEY", None)

    def refused(self, judges, pattern, agent=AGENT, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(TwoKeyConfigError, pattern):
                start(tmp, judges, agent, **kw)

    def started(self, judges, agent=AGENT, **kw):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return start(tmp.name, judges, agent, **kw)


class Normalization(unittest.TestCase):
    def test_model_ids(self):
        same = [("gpt-4o-2024-08-06", "openai/gpt-4o", "chatgpt-4o-latest", "gpt-4o"),
                ("claude-3-5-sonnet-20241022", "anthropic/claude-3.5-sonnet",
                 "us.anthropic.claude-3-5-sonnet-20241022-v2:0", "claude-3-5-sonnet@20241022",
                 "publishers/anthropic/models/claude-3-5-sonnet@20241022"),
                ("claude-opus-4-0", "claude-opus-4-20250514"),
                ("qwen2.5:7b", "Qwen/Qwen2.5-7B-Instruct", "qwen2.5:7b-instruct"),
                ("models/gemini-1.5-pro", "gemini-1.5-pro-002")]
        for group in same:
            self.assertEqual(len({normalize_model(m) for m in group}), 1, group)
        self.assertNotEqual(normalize_model("gpt-4o"), normalize_model("gpt-4o-mini"))
        self.assertNotEqual(normalize_model("qwen2.5:7b"), normalize_model("qwen2.5:14b"))
        self.assertEqual(model_maker("meta-llama/Llama-3.1-8B-Instruct"), "meta")

    def test_routers_resolve_to_the_real_upstream(self):
        cases = {("https://api.openai.com/v1", "gpt-4o"): {"api.openai.com"},
                 ("https://openrouter.ai/api/v1", "anthropic/claude-3.5-sonnet"): {"api.anthropic.com"},
                 ("https://res.openai.azure.com", "my-deployment"): {"api.openai.com"},
                 ("https://bedrock-runtime.us-east-1.amazonaws.com", "anthropic.claude-3-haiku-20240307-v1:0"):
                     {"api.anthropic.com"},
                 ("https://us-central1-aiplatform.googleapis.com/v1", "gemini-1.5-pro"):
                     {"generativelanguage.googleapis.com"},
                 ("http://localhost:4000", "openai/gpt-4o"): {"api.openai.com", "localhost:4000"},
                 ("https://llm.corp.example/v1", "anthropic/claude-3-5-sonnet"): {"api.anthropic.com"}}
        for (url, model), want in cases.items():
            self.assertEqual(set(resolve_upstreams(url, model)[0]), want, (url, model))
        for url, model in (("https://openrouter.ai/api/v1", "mystery-model"), ("https://llm.corp.example/v1", "gpt-4o")):
            self.assertEqual(resolve_upstreams(url, model)[0], frozenset(), (url, model))
        self.assertIn("ollama.com", resolve_upstreams("http://localhost:11434", "gpt-oss:120b-cloud")[0])

    def test_fingerprint_never_contains_the_key(self):
        fp = credential_fingerprint("sk-very-secret")
        self.assertTrue(fp.startswith("sha256:"))
        self.assertNotIn("very-secret", fp)
        self.assertEqual(credential_fingerprint(""), "none")


class Declaration(Env):
    def test_agent_must_be_declared(self):
        self.refused([FixedJudge("a", "yes")], "^monitored_agent_required: declare the monitored agent", agent=None)

    def test_every_field_is_required_and_readable(self):
        for drop in ("model", "provider", "base_url", "credential_env"):
            self.refused([claude()], "monitored_agent", agent={k: v for k, v in AGENT.items() if k != drop})
        os.environ.pop("SEP_AGENT_KEY")
        self.refused([claude()], "SEP_AGENT_KEY is not set")

    def test_credential_none_only_for_loopback_and_in_process_only_in_tests(self):
        cloud_none = dict(AGENT, credential="none")
        cloud_none.pop("credential_env")
        self.refused([claude()], "credential: none is only for", agent=cloud_none)
        self.refused([claude()], "tests only", agent=TEST_AGENT, allow_test_doubles=False)

    def test_yaml_block(self):
        d = load_monitored_agent({"judges": [], "monitored_agent": AGENT})
        self.assertEqual(d, AgentDeclaration(**AGENT))
        self.assertIsNone(load_monitored_agent({"judges": []}))


class Refusals(Env):
    def test_same_model_by_any_route(self):
        self.refused([oai("or", "x-ai/grok-4", "https://openrouter.ai/api/v1", "openrouter-key")],
                     "^judge_matches_agent: .*same model")

    def test_same_endpoint_and_model(self):
        self.refused([oai("direct", "grok-4", "https://api.x.ai/v1", "other-key")], "^judge_matches_agent: ")

    def test_same_credential(self):
        self.refused([claude(key="agent-secret-key")], "^judge_matches_agent: .*same credential fingerprint")
        os.environ["SEP_JUDGE_KEY"] = "agent-secret-key"
        self.addCleanup(os.environ.pop, "SEP_JUDGE_KEY", None)
        j = AnthropicJudge("c2", "anthropic", "claude-3-haiku", credential=EnvApiKey("SEP_JUDGE_KEY"))
        self.refused([j], "same credential fingerprint")

    def test_unresolved_router_is_a_match(self):
        self.refused([oai("gw", "judge-model", "https://llm.corp.example/v1", "gw-key")], "unresolved")
        agent = dict(AGENT, base_url="https://llm.corp.example/v1", model="agent-model")
        self.refused([claude()], "agent upstream unresolved", agent=agent)

    def test_unreadable_judge_credential(self):
        j = AnthropicJudge("c3", "anthropic", "claude-3-haiku", credential=EnvApiKey("SEP_UNSET"))
        self.refused([j], "credential could not be read")

    def test_judge_without_identity(self):
        class Custom(FixedJudge):
            is_test_double = False
        self.refused([Custom("c", "yes")], "declares no model and base_url", allow_test_doubles=False)

    def test_provider_labels_are_not_compared(self):
        # Same free-text label, different real upstream: accepted. Different label, same upstream: refused.
        tk = self.started([AnthropicJudge("c", "xai", "claude-3-haiku", credential=StaticToken("k"))])
        self.assertTrue(tk.separation.ok)
        self.refused([oai("mini", "grok-3-mini", "https://api.x.ai/v1", "judge-key")], "allow_same_provider_judge")

    def test_configured_agent_object_is_checked(self):
        os.environ["SEP_OTHER"] = "other-agent-key"
        self.addCleanup(os.environ.pop, "SEP_OTHER", None)
        agents = load_agents({"agents": [{"id": "claude-agent", "type": "anthropic", "provider": "anthropic",
                                          "model": "claude-sonnet-4-0", "auth": {"type": "env", "var": "SEP_OTHER"}}]})
        self.refused([claude()], "same model", agent=agents)


class SameProvider(Env):
    def test_refused_by_default_and_logged_when_allowed(self):
        agent = dict(AGENT, model="gpt-4o", base_url="https://api.openai.com/v1")
        judge = oai("mini", "gpt-4o-mini", "https://api.openai.com/v1", "judge-openai-key")
        self.refused([judge], "allow_same_provider_judge", agent=agent)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            tk = self.started([judge], agent, quorum=QuorumPolicy(required_yes=1, allow_same_provider_judge=True))
        rec = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body["judge_agent_separation"]
        self.assertIn("allow_same_provider_judge accepted", err.getvalue())
        self.assertTrue(rec["allow_same_provider_judge"])
        self.assertEqual(len(rec["same_provider_allowed"]), 1)
        self.refused([oai("same", "gpt-4o-2024-08-06", "https://api.openai.com/v1", "k2")], "same model", agent=agent,
                     quorum=QuorumPolicy(required_yes=1, allow_same_provider_judge=True))

    def test_same_local_endpoint(self):
        agent = {"id": "local-agent", "model": "llama3.1:8b", "provider": "ollama",
                 "base_url": "http://localhost:11434", "credential": "none"}
        self.refused([OllamaJudge("q", "ollama", "qwen2.5:7b")], "same endpoint", agent=agent)

    def test_yaml_key(self):
        from two_key.judges.config import load_config
        _, policy = load_config({"judges": [{"id": "l", "type": "ollama", "model": "m"}],
                                 "quorum": {"required_yes": 1, "allow_same_provider_judge": True}})
        self.assertTrue(policy.allow_same_provider_judge)


class Accepted(Env):
    def test_distinct_judges_start_and_the_check_is_recorded(self):
        tk = self.started([claude(), OllamaJudge("q", "ollama", "qwen2.5:7b")])
        rec = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][-1].body["judge_agent_separation"]
        ledger_text = json.dumps([e.body for e in tk.ledger.entries])
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["rule"], "judge_is_not_monitored_agent")
        self.assertEqual([a["id"] for a in rec["agents"]], ["grok-agent"])
        self.assertEqual(rec["agents"][0]["upstream"], ["api.x.ai"])
        self.assertEqual({j["id"]: j["upstream"] for j in rec["judges"]},
                         {"claude": ["api.anthropic.com"], "q": ["localhost:11434", "maker:alibaba"]})
        self.assertIn(credential_fingerprint("judge-anthropic-key"), rec["judges"][0]["credential_fingerprint"])
        for raw in ("agent-secret-key", "judge-anthropic-key"):
            self.assertNotIn(raw, ledger_text)


class RuntimeSessionCheckForEveryJudge(unittest.TestCase):
    def test_local_judge_reusing_the_agent_session_abstains(self):
        def never(*a):
            raise AssertionError("must not call the model")
        j = OllamaJudge("q", "ollama", "qwen2.5:7b", credential=StaticToken("shared"), auth_header="bearer",
                        transport=never)
        a = normalize_action({"tool": "search"})
        self.assertEqual(j.score_bound("c", a, "", None, agent_session="shared").error,
                         "cloud_judge_reused_agent_session")


if __name__ == "__main__":
    unittest.main(verbosity=2)
