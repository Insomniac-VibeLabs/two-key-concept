"""allow_same_model_distinct_tenant: a logged opt-in, default off. It lets a judge run the agent's model on
the same endpoint or upstream only when both sides declare different tenants and both have different keys.
It is recorded in constitution_loaded (same_model_tenant_optin, both tenant labels), is part of the policy
digest, and prints a warning. A misspelled flag is refused."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.identity import TENANT_OPTIN_WARNING, AgentDeclaration, compare, judge_identity
from two_key.judges.config import JudgeConfigError, load_config
from two_key.judges.credentials import StaticToken
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.audit import policy_digest
from two_key.quorum import QuorumConfigError, QuorumPolicy

AGENT = {"id": "agent", "model": "gpt-4o", "provider": "openai", "base_url": "https://api.openai.com/v1",
         "credential_env": "OPTIN_AGENT_KEY", "tenant": {"project": "p1"}}
DAEMON = {"id": "agent", "model": "llama3.1:8b", "provider": "ollama", "base_url": "http://localhost:11434",
          "credential": "none", "upstream": "localhost:11434", "tenant": {"account": "a"}}
FP = b"k" * 32


def judge(model="gpt-4o", base_url="https://api.openai.com/v1", key="judge-key", tenant=None, upstream=None):
    return SimpleNamespace(judge_id="j", model=model, base_url=base_url, provider="x",
                           credential=StaticToken(key) if key else None, tenant=tenant, upstream=upstream)


class Compare(unittest.TestCase):
    def setUp(self):
        os.environ["OPTIN_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "OPTIN_AGENT_KEY", None)

    def verdict(self, agent, j, flag=True):
        a = AgentDeclaration.from_mapping(agent).resolve(fp_key=FP)
        return compare(a, judge_identity(j, FP), allow_same_model_distinct_tenant=flag)

    def test_distinct_tenants_and_keys_are_allowed_with_the_flag(self):
        self.assertIsNone(self.verdict(AGENT, judge(tenant={"project": "p2"})))          # same endpoint
        self.assertIsNone(self.verdict(AGENT, judge(base_url="http://localhost:4000", upstream="api.openai.com",
                                                    tenant={"project": "p2"})))          # same upstream

    def test_flag_off_still_refuses(self):
        self.assertRegex(self.verdict(AGENT, judge(tenant={"project": "p2"}), flag=False),
                         "same model 'gpt4o' on the same endpoint")
        self.assertRegex(self.verdict(AGENT, judge(base_url="http://localhost:4000", upstream="api.openai.com",
                                                   tenant={"project": "p2"}), flag=False), "through the same upstream")

    def test_same_tenant_is_refused(self):
        self.assertRegex(self.verdict(AGENT, judge(tenant={"project": "P1"})), "same model .* on the same endpoint")

    def test_one_side_without_a_tenant_is_refused(self):
        self.assertRegex(self.verdict(AGENT, judge()), "on the same endpoint")
        self.assertRegex(self.verdict(dict(AGENT, tenant=None), judge(tenant={"project": "p2"})), "on the same endpoint")

    def test_keyless_is_refused(self):
        self.assertRegex(self.verdict(DAEMON, judge("llama3.1:8b", "http://localhost:11434", key=None,
                                                    tenant={"account": "b"}, upstream="localhost:11434")),
                         "on the same endpoint localhost:11434")
        self.assertRegex(self.verdict(AGENT, judge(key=None, tenant={"project": "p2"})), "on the same endpoint")

    def test_other_refusals_are_untouched(self):
        # A local proxy with no declared upstream: its upstream and tenant are unknown.
        self.assertRegex(self.verdict(AGENT, judge(base_url="http://localhost:4000", tenant={"project": "p2"})),
                         "through a local or unrecognized proxy or daemon")
        # The same key.
        self.assertRegex(self.verdict(AGENT, judge(key="agent-key-K", tenant={"project": "p2"})),
                         "same credential fingerprint")


class Config(unittest.TestCase):
    def test_default_off_and_strict(self):
        self.assertFalse(QuorumPolicy().allow_same_model_distinct_tenant)
        self.assertIn("allow_same_model_distinct_tenant", QuorumPolicy().to_record())
        with self.assertRaisesRegex(QuorumConfigError, "allow_same_model_distinct_tenant must be a boolean"):
            QuorumPolicy(allow_same_model_distinct_tenant="yes")

    def test_misspelled_flag_is_rejected(self):
        for name in ("allow_same_model_distinct_tenants", "allow_same_model_different_tenant"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(JudgeConfigError, f"unknown quorum keys \\['{name}'\\]"):
                    load_config({"judges": [{"id": "l", "type": "ollama", "model": "m"}], "quorum": {name: True}})
        with self.assertRaises(TypeError):
            QuorumPolicy(allow_same_model_distinct_tenants=True)
        _, policy = load_config({"judges": [{"id": "l", "type": "ollama", "model": "m"}],
                                 "quorum": {"allow_same_model_distinct_tenant": True}})
        self.assertTrue(policy.allow_same_model_distinct_tenant)

    def test_policy_digest_covers_the_flag(self):
        self.assertNotEqual(policy_digest(QuorumPolicy(required_yes=1).to_record()),
                            policy_digest(QuorumPolicy(required_yes=1,
                                                       allow_same_model_distinct_tenant=True).to_record()))


class EndToEnd(unittest.TestCase):
    def setUp(self):
        os.environ["OPTIN_AGENT_KEY"] = "agent-key-K"
        self.addCleanup(os.environ.pop, "OPTIN_AGENT_KEY", None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        self.env = sign_constitution("Searching is fine.", [{"id": "t", "allow_only_tools": ["search"]}], self.key,
                                     {"search": {"irreversible": False, "data_class_floor": "public"}})

    def start(self, flag, tenant):
        j = OpenAICompatibleJudge("j", "openai", "gpt-4o", "https://api.openai.com/v1", StaticToken("judge-key"))
        j.tenant = tenant
        err = io.StringIO()
        with redirect_stderr(err):
            tk = TwoKey(Ledger(Path(self.tmp.name, f"ledger-{flag}-{bool(tenant)}"), self.key), self.key.public_key(),
                        verify_signed(self.env, self.key.public_key()), [j], private_key=self.key,
                        quorum=QuorumPolicy(required_yes=1, allow_same_model_distinct_tenant=flag),
                        monitored_agent=AGENT)
        return tk, err.getvalue()

    def test_opt_in_is_logged_digested_and_warned(self):
        tk, err = self.start(True, {"project": "p2"})
        self.assertIn(TENANT_OPTIN_WARNING, err)
        self.assertIn("same_model_tenant_optin", err)
        [loaded] = [e.body for e in tk.ledger.entries if e.kind == "constitution_loaded"]
        self.assertIs(loaded["same_model_tenant_optin"], True)
        self.assertEqual(loaded["same_model_tenant_optin_pairs"],
                         [{"agent": "agent", "judge": "j", "model": "gpt4o",
                           "agent_tenant": ["openai:project:p1"], "judge_tenant": ["openai:project:p2"]}])
        self.assertTrue(loaded["quorum_policy"]["allow_same_model_distinct_tenant"])
        self.assertEqual(loaded["policy_digest"], policy_digest(loaded["quorum_policy"]))
        self.assertIs(loaded["judge_agent_separation"]["same_model_tenant_optin"], True)

    def test_flag_off_refuses_and_does_not_warn(self):
        with self.assertRaisesRegex(TwoKeyConfigError, "judge_matches_agent: .*on the same endpoint"):
            self.start(False, {"project": "p2"})

    def test_flag_on_without_a_judge_tenant_refuses(self):
        with self.assertRaisesRegex(TwoKeyConfigError, "judge_matches_agent: .*on the same endpoint"):
            self.start(True, None)

    def test_default_records_the_opt_in_as_off(self):
        j = OpenAICompatibleJudge("j", "openai", "gpt-4o-mini", "https://api.openai.com/v1", StaticToken("judge-key"))
        err = io.StringIO()
        with redirect_stderr(err):
            tk = TwoKey(Ledger(Path(self.tmp.name, "ledger-default"), self.key), self.key.public_key(),
                        verify_signed(self.env, self.key.public_key()), [j], private_key=self.key,
                        quorum=QuorumPolicy(required_yes=1), monitored_agent=AGENT)
        self.assertNotIn("allow_same_model_distinct_tenant", err.getvalue())
        [loaded] = [e.body for e in tk.ledger.entries if e.kind == "constitution_loaded"]
        self.assertIs(loaded["same_model_tenant_optin"], False)
        self.assertEqual(loaded["same_model_tenant_optin_pairs"], [])


if __name__ == "__main__":
    unittest.main()
