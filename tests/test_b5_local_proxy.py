"""B5: a keyless local proxy or daemon serving the agent's exact model is refused unless its upstream is declared.

The agent's identity is the operator's declaration. A loopback or private endpoint can forward the same
model to the agent's provider and account without a key of its own, so with the same normalized model
its upstream and tenant are unknown until it declares ``upstream:``. A declared upstream counts as an
endpoint, tenants are scoped by the family a proxy reaches (not its address), upstream labels are
normalized, and local aliases of this machine are one endpoint.
"""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.identity import (AgentDeclaration, _own_addresses, check_separation, compare, endpoint_key,
                              judge_identity, local_alias, normalize_upstream, IdentityError)
from two_key.judges.credentials import StaticToken
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy

OPENAI_AGENT = {"id": "agent", "model": "gpt-4o", "provider": "openai", "base_url": "https://api.openai.com/v1",
                "credential_env": "B5_AGENT_KEY"}
OLLAMA_AGENT = {"id": "agent", "model": "gpt-oss:120b-cloud", "provider": "ollama",
                "base_url": "https://ollama.com", "credential_env": "B5_AGENT_KEY"}
FP = b"k" * 32
UNKNOWN = "through a local proxy or daemon"
SAME_UPSTREAM = "through the same upstream"


def judge(model, base_url, key=None, tenant=None, upstream=None, jid="j"):
    return SimpleNamespace(judge_id=jid, model=model, base_url=base_url, provider="x",
                           credential=StaticToken(key) if key else None, tenant=tenant, upstream=upstream)


class B5(unittest.TestCase):
    def setUp(self):
        os.environ["B5_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "B5_AGENT_KEY", None)

    def verdict(self, agent: dict, j) -> str | None:
        a = AgentDeclaration.from_mapping(agent).resolve(fp_key=FP)
        return compare(a, judge_identity(j, FP))

    def denied(self, agent, j, pattern):
        reason = self.verdict(agent, j)
        self.assertIsNotNone(reason, "expected a refusal")
        self.assertRegex(reason, pattern)

    def allowed(self, agent, j):
        self.assertIsNone(self.verdict(agent, j))

    # ------------------------------------------------------------ the reported gaps, now refused
    def test_keyless_local_proxy_with_the_agents_model(self):
        for model in ("gpt-4o", "openai/gpt-4o", "gpt-4o-2024-08-06"):
            with self.subTest(model=model):
                self.denied(OPENAI_AGENT, judge(model, "http://localhost:4000"), UNKNOWN)

    def test_private_address_proxy(self):
        self.denied(OPENAI_AGENT, judge("gpt-4o", "https://192.168.1.9:4000"), UNKNOWN)
        self.denied(OPENAI_AGENT, judge("gpt-4o", "https://192.168.1.9:4000", key="other-key"), UNKNOWN)

    def test_declared_upstream_is_compared(self):
        for up in ("api.openai.com", "https://API.OpenAI.com:443/v1", "api.openai.com.", ["api.openai.com"]):
            with self.subTest(upstream=up):
                self.denied(OPENAI_AGENT, judge("gpt-4o", "http://localhost:4000", upstream=up), SAME_UPSTREAM)

    def test_shared_declared_tenant_behind_a_proxy(self):
        agent = dict(OPENAI_AGENT, tenant={"project": "p1"})
        self.denied(agent, judge("gpt-4o", "http://localhost:4000", tenant={"project": "p1"}), UNKNOWN)
        self.denied(agent, judge("gpt-4o", "http://localhost:4000", tenant={"project": "P1"},
                                 upstream="api.openai.com"), "same tenant openai:project:p1")

    def test_declared_upstream_on_a_remote_router_counts_as_an_endpoint(self):
        agent = dict(OPENAI_AGENT, base_url="https://llm-router.example.com/v1", upstream="api.openai.com")
        self.denied(agent, judge("gpt-4o", "https://api.openai.com/v1", key="judge-key"), SAME_UPSTREAM)

    def test_ollama_cloud_model_through_a_local_daemon(self):
        j = judge("gpt-oss:120b-cloud", "http://localhost:11434")
        self.denied(OLLAMA_AGENT, j, UNKNOWN)
        self.denied(OLLAMA_AGENT, judge("gpt-oss:120b-cloud", "http://localhost:11434", upstream="ollama.com"),
                    SAME_UPSTREAM)
        same_account = dict(OLLAMA_AGENT, tenant={"account": "acct-a"})
        self.denied(same_account, judge("gpt-oss:120b-cloud", "http://localhost:11434", upstream="ollama.com",
                                        tenant={"account": "acct-a"}), "same tenant ollama:account:acct-a")
        # The agent's model without the -cloud suffix is the same model.
        self.denied(dict(OLLAMA_AGENT, model="gpt-oss:120b"), j, UNKNOWN)

    def test_local_aliases_are_one_endpoint(self):
        agent = {"id": "agent", "model": "llama3.1:8b", "provider": "ollama", "base_url": "http://localhost:11434",
                 "credential": "none", "upstream": "localhost:11434"}
        hosts = ["0.0.0.0", "127.1", "127.0.0.2", "localhost.localdomain", "[::1]", "[::]", "LOCALHOST"]
        own = sorted(a for a in _own_addresses() if ":" not in a and not a.startswith("127."))
        hosts += own[:1]
        for host in hosts:
            with self.subTest(host=host):
                self.assertTrue(local_alias(host.strip("[]")), host)
                self.assertEqual(endpoint_key(f"http://{host}:11434"), "localhost:11434")
                self.denied(agent, judge("llama3.1:8b", f"http://{host}:11434", upstream=f"{host}:11434"),
                            "same model 'llama3.1-8b' on the same endpoint localhost:11434")

    def test_this_machines_own_address_is_a_local_alias(self):
        from unittest import mock
        agent = {"id": "agent", "model": "llama3.1:8b", "provider": "ollama", "base_url": "http://localhost:11434",
                 "credential": "none", "upstream": "localhost:11434"}
        with mock.patch("two_key.identity._own_addresses", return_value=frozenset({"10.20.30.40", "box-name"})):
            for host in ("10.20.30.40", "box-name"):
                with self.subTest(host=host):
                    self.assertEqual(endpoint_key(f"http://{host}:11434"), "localhost:11434")
                    self.denied(agent, judge("llama3.1:8b", f"http://{host}:11434", upstream=f"{host}:11434"),
                                "on the same endpoint localhost:11434")
            self.assertFalse(local_alias("10.20.30.41"))

    def test_upstream_normalization(self):
        self.assertEqual(normalize_upstream("https://API.OpenAI.com:443/v1"), "api.openai.com")
        self.assertEqual(normalize_upstream("api.openai.com:80"), "api.openai.com")
        self.assertEqual(normalize_upstream("Gateway.example:8443"), "gateway.example:8443")
        self.assertEqual(normalize_upstream("127.0.0.1:11434"), "localhost:11434")
        self.assertEqual(normalize_upstream("maker:meta"), "maker:meta")
        for public in ("8.8.8.8", "api.openai.com", "192.168.1.9", "example.com"):
            self.assertFalse(local_alias(public), public)

    # ------------------------------------------------------------ still allowed
    def test_a_different_model_is_allowed(self):
        self.allowed(OPENAI_AGENT, judge("gpt-4o-mini", "http://localhost:4000"))
        self.allowed(OLLAMA_AGENT, judge("qwen3-coder:480b-cloud", "http://localhost:11434"))

    def test_a_different_provider_upstream_is_allowed(self):
        self.allowed(OPENAI_AGENT, judge("gpt-4o", "http://localhost:4000", upstream="api.groq.com"))
        agent = dict(OPENAI_AGENT, tenant={"project": "p1"})
        self.allowed(agent, judge("gpt-4o", "http://localhost:4000", upstream="api.groq.com",
                                  tenant={"project": "p1"}))      # p1 at Groq is not p1 at OpenAI

    def test_a_different_daemon_is_allowed(self):
        agent = {"id": "agent", "model": "llama3.1:8b", "provider": "ollama", "base_url": "http://localhost:11434",
                 "credential": "none", "upstream": "localhost:11434"}
        self.allowed(agent, judge("llama3.1:8b", "http://192.168.1.9:11434", upstream="192.168.1.9:11434"))
        remote = dict(OPENAI_AGENT, model="llama3.1:8b", base_url="https://api.together.xyz/v1")
        self.allowed(remote, judge("llama3.1:8b", "http://localhost:11434", upstream="localhost:11434"))

    def test_a_different_ollama_account_is_allowed(self):
        agent = dict(OLLAMA_AGENT, tenant={"account": "acct-a"})
        self.allowed(agent, judge("gpt-oss:120b-cloud", "http://localhost:11434", upstream="ollama.com",
                                  tenant={"account": "acct-b"}))

    def test_same_provider_on_a_different_model_or_endpoint_is_allowed(self):
        self.allowed(OPENAI_AGENT, judge("gpt-4o-mini", "https://api.openai.com/v1", key="judge-key"))
        self.allowed(OPENAI_AGENT, judge("openai/gpt-4o", "https://openrouter.ai/api/v1", key="judge-key"))
        self.allowed(OPENAI_AGENT, judge("gpt-4o", "https://my-res.openai.azure.com/openai/deployments/gpt4o",
                                         key="judge-key"))

    def test_records_show_routes_and_declared_upstream(self):
        rec = judge_identity(judge("gpt-oss:120b-cloud", "http://127.0.0.1:11434", upstream="https://ollama.com"),
                             FP).to_record()
        self.assertEqual(rec["upstream_declared"], ["ollama.com"])
        self.assertTrue(rec["local_endpoint"])
        self.assertEqual(rec["routes"], ["localhost:11434", "ollama.com"])


class EndToEnd(unittest.TestCase):
    def test_twokey_refuses_a_keyless_local_proxy_with_the_agents_model(self):
        os.environ["B5_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "B5_AGENT_KEY", None)
        key = generate_private_key()
        env = sign_constitution("Searching is fine.", [{"id": "t", "allow_only_tools": ["search"]}], key,
                                {"search": {"irreversible": False, "data_class_floor": "public"}})
        proxy = OpenAICompatibleJudge("proxy", "litellm", "gpt-4o", "http://localhost:4000/v1")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(TwoKeyConfigError, "judge_matches_agent: .*through a local proxy or daemon"):
                TwoKey(Ledger(Path(tmp, "ledger"), key), key.public_key(), verify_signed(env, key.public_key()),
                       [proxy], private_key=key, quorum=QuorumPolicy(required_yes=1), monitored_agent=OPENAI_AGENT)


if __name__ == "__main__":
    unittest.main()
