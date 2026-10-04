"""A judge is local only from its endpoint host, never from the declared local_weights flag."""

import unittest

from two_key.action import normalize_action
from two_key.judges.credentials import StaticToken
from two_key.judges.ollama import OllamaJudge
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.netloc import host_is_local, host_is_loopback
from two_key.quorum import QuorumConfigError, QuorumPolicy, check_judge_set
from two_key.testing import FixedJudge

A = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})


def _never(*a):
    raise AssertionError("judge must not call its model")


class Locality(unittest.TestCase):
    def test_hosts(self):
        for h in ("localhost", "127.0.0.1", "::1", "[::1]"):
            self.assertTrue(host_is_loopback(h), h)
        for h in ("10.0.0.5", "192.168.1.9", "172.16.0.1", "fd00::1"):
            self.assertTrue(host_is_local(h), h)
            self.assertFalse(host_is_loopback(h), h)
        for h in ("ollama.com", "api.openai.com", "169.254.169.254", "8.8.8.8", "intranet.example", ""):
            self.assertFalse(host_is_local(h), h)

    def test_ollama_default_follows_the_host(self):
        self.assertTrue(OllamaJudge("l", "ollama", "qwen2.5:7b").is_local())
        lan = OllamaJudge("lan", "ollama", "qwen2.5:7b", base_url="http://192.168.1.9:11434", allow_insecure_http=True)
        self.assertTrue(lan.is_local())
        self.assertTrue(lan.is_cloud())  # not loopback: it needs the agent session check
        cloud = OllamaJudge("c", "ollama", "gpt-oss:120b-cloud", base_url="https://ollama.com")
        self.assertFalse(cloud.local_weights)
        self.assertFalse(cloud.is_local())
        self.assertTrue(cloud.is_cloud())

    def test_declared_flag_never_makes_a_remote_judge_local(self):
        for j in (OllamaJudge("c", "ollama", "m", base_url="https://ollama.com", local_weights=True),
                  OpenAICompatibleJudge("o", "openai", "gpt-4o", "https://api.openai.com/v1", local_weights=True)):
            self.assertFalse(j.is_local())
            self.assertTrue(j.is_cloud())
        floor = QuorumPolicy.high_assurance(required_yes=2)
        remote = [OllamaJudge("c", "ollama", "m", base_url="https://ollama.com", local_weights=True, vendor="x"),
                  FixedJudge("b", "yes", provider="p", vendor="y")]
        with self.assertRaises(QuorumConfigError):
            check_judge_set(remote, floor)

    def test_declared_local_cloud_judge_still_checks_the_agent_credential(self):
        j = OllamaJudge("c", "ollama", "m", base_url="https://ollama.com", local_weights=True,
                        credential=StaticToken("shared-key"), auth_header="bearer", transport=_never)
        self.assertEqual(j.score_bound("c", A, "", None).error, "cloud_judge_session_required")
        self.assertEqual(j.score_bound("c", A, "", None, agent_session="shared-key").error,
                         "cloud_judge_reused_agent_session")


if __name__ == "__main__":
    unittest.main(verbosity=2)
