"""An in-process placeholder agent is accepted only when every judge is a test double."""

import os
import tempfile
import unittest
from pathlib import Path

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.judges.anthropic import AnthropicJudge
from two_key.judges.credentials import StaticToken
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public"}}


def start(judges, allow_test_doubles=True):
    key = generate_private_key()
    env = sign_constitution("Searching is fine.", RULES, key, SPECS)
    tmp = tempfile.mkdtemp()
    return TwoKey(Ledger(Path(tmp), key), key.public_key(), verify_signed(env, key.public_key()), judges,
                  private_key=key, quorum=QuorumPolicy(required_yes=1), allow_test_doubles=allow_test_doubles,
                  monitored_agent=TEST_AGENT)


class InProcessAgent(unittest.TestCase):
    def test_all_test_doubles(self):
        self.assertTrue(start([FixedJudge("a", "yes"), FixedJudge("b", "yes")]).separation.ok)

    def test_one_real_judge_refuses_the_placeholder(self):
        real = AnthropicJudge("claude", "anthropic", "claude-sonnet-4-20250514", credential=StaticToken("k"))
        with self.assertRaisesRegex(TwoKeyConfigError, "in_process_agent_refused"):
            start([FixedJudge("a", "yes"), real])
        with self.assertRaisesRegex(TwoKeyConfigError, "in_process_agent_refused"):
            start([real])

    def test_without_allow_test_doubles(self):
        real = AnthropicJudge("claude", "anthropic", "claude-sonnet-4-20250514", credential=StaticToken("k"))
        with self.assertRaisesRegex(TwoKeyConfigError, "in_process_agent_refused"):
            start([real], allow_test_doubles=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
