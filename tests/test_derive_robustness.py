"""Fix 10: an unreadable value is a derive_failed deny, and any exception in authorize is a ledgered deny."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import DeriveError, derive
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["pay"]}]
SPECS = {"pay": {"irreversible": False, "data_class_floor": "public",
                 "amount": {"json_path": "amt", "unit": "usd"},
                 "counterparties": [{"json_path": "to", "allow": ["ada"]}]}}
CENTS = {"pay": dict(SPECS["pay"], amount={"json_path": "amt", "unit": "cents"})}
PAY = {"tool": "pay", "data_class": "public", "irreversible": False}


def engine(tmp, specs=SPECS):
    key = generate_private_key()
    env = sign_constitution("Pay ada small amounts.", RULES, key, specs)
    return TwoKey(Ledger(Path(tmp), key), key.public_key(), verify_signed(env, key.public_key()),
                  [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                  allow_test_doubles=True, monitored_agent=TEST_AGENT)


class Unreadable(unittest.TestCase):
    def test_derive_raises_only_derive_error(self):
        for value in (10**400, -(10**400), float("nan"), float("inf"), 1e308):
            for spec in (SPECS["pay"], CENTS["pay"]):
                with self.assertRaises(DeriveError):
                    derive(spec, {"amt": value, "to": "ada"})

    def test_huge_amount_is_a_derive_failed_deny(self):
        for specs in (SPECS, CENTS):
            with tempfile.TemporaryDirectory() as tmp:
                tk = engine(tmp, specs)
                d = tk.authorize(PAY, {"amt": 10**400, "to": "ada"}, "x")
                self.assertFalse(d.allowed)
                self.assertTrue(d.reason.startswith("derive_failed:"), d.reason)
                self.assertEqual([e.kind for e in tk.ledger.entries][-1], "decision")

    def test_huge_claimed_amount_is_a_malformed_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            d = tk.authorize(dict(PAY, amount_usd=10**400), {"amt": 1, "to": "ada"}, "x")
            self.assertFalse(d.allowed)
            self.assertTrue(d.reason.startswith("malformed_action:"), d.reason)

    def test_any_exception_in_authorize_is_a_ledgered_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            tk = engine(tmp)
            with patch("two_key.core.convene", side_effect=RuntimeError("boom")):
                d = tk.authorize(PAY, {"amt": 1, "to": "ada"}, "x", agent_id="ag")
            self.assertFalse(d.allowed)
            self.assertIsNone(d.token)
            self.assertEqual(d.reason, "internal_error:RuntimeError")
            last = tk.ledger.entries[-1]
            self.assertEqual((last.kind, last.body["reason"], last.body["agent"]["id"]),
                             ("decision", "internal_error:RuntimeError", "ag"))
            tk.ledger.verify()
            self.assertTrue(tk.authorize(PAY, {"amt": 1, "to": "ada"}, "x").allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
