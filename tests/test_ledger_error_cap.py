"""Ballot / VM ledger error strings are capped; type labels never use raw __name__."""
from __future__ import annotations

import unittest

from two_key.action import normalize_action
from two_key.agent_meta import (MAX_LEDGER_ERROR_CHARS, MAX_TYPE_TAG_CHARS, cap_ledger_text,
                                exception_ledger_error, type_tag)
from two_key.judges.base import Judge
from two_key.policy_vm import Op, PolicyVM
from two_key.quorum import QuorumPolicy, convene

SEARCH = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})


class CapLedgerText(unittest.TestCase):
    def test_short_unchanged(self):
        self.assertEqual(cap_ledger_text("ok"), "ok")

    def test_oversize_keeps_prefix_and_digest_of_remainder(self):
        huge = "A" * (MAX_LEDGER_ERROR_CHARS + 5000)
        out = cap_ledger_text(huge)
        self.assertTrue(out.startswith("A" * MAX_LEDGER_ERROR_CHARS))
        self.assertIn("…sha256:", out)
        self.assertNotIn("A" * (MAX_LEDGER_ERROR_CHARS + 1), out)
        self.assertLess(len(out), MAX_LEDGER_ERROR_CHARS + 80)


class QuorumExceptionCap(unittest.TestCase):
    def test_huge_judge_exception_is_capped_in_ballot(self):
        mark = "ZQXERR"

        class Boom(Judge):
            is_test_double = True
            judge_id = "boom"
            provider = "test"

            def score(self, constitution_text, action, proposal):
                raise RuntimeError(mark + "x" * (5 << 20))

        q = convene([Boom()], "Fine.", SEARCH, "look", QuorumPolicy(required_yes=1))
        err = q.ballots[0].error
        self.assertEqual(q.ballots[0].vote, "abstain")
        self.assertTrue(err.startswith("RuntimeError:"))
        self.assertIn(mark, err)
        self.assertIn("…sha256:", err)
        self.assertLess(len(err), MAX_LEDGER_ERROR_CHARS + 80)
        self.assertNotIn("x" * 1000, err)

    def test_huge_type_name_uses_type_tag_not_raw(self):
        huge = "H" * (2 << 20)
        cls = type(huge, (Exception,), {})

        class Boom(Judge):
            is_test_double = True
            judge_id = "boom"
            provider = "test"

            def score(self, constitution_text, action, proposal):
                raise cls("nope")

        q = convene([Boom()], "Fine.", SEARCH, "look", QuorumPolicy(required_yes=1))
        err = q.ballots[0].error
        tag = type_tag(cls("x"))
        self.assertLessEqual(len(tag), MAX_TYPE_TAG_CHARS)
        self.assertNotIn(huge, err)
        self.assertTrue(err.startswith(tag + ":"))


class VmFaultExceptionCap(unittest.TestCase):
    def test_huge_exception_in_vm_fault_reason_is_capped(self):
        mark = "ZQXVM"

        class BoomAction:
            def field_value(self, name):
                raise RuntimeError(mark + "y" * (5 << 20))

        vm = PolicyVM([(Op.LOAD, "tool"), (Op.PASS,)])
        r = vm.eval(BoomAction())  # type: ignore[arg-type]
        self.assertFalse(r.allowed)
        self.assertTrue(r.reason.startswith("vm_fault:"))
        self.assertIn(mark, r.reason)
        self.assertIn("…sha256:", r.reason)
        self.assertLess(len(r.reason), len("vm_fault:") + MAX_LEDGER_ERROR_CHARS + 80)
        self.assertNotIn("y" * 1000, r.reason)

    def test_vmfault_branch_reason_is_capped(self):
        """#20: dedicated VMFault path (not generic Exception) also caps reason text."""
        mark = "ZQXVMF"

        class HugeOp:
            def __repr__(self):
                return mark + "z" * (5 << 20)

        vm = PolicyVM([(HugeOp(),)])  # type: ignore[arg-type]
        r = vm.eval(object())  # type: ignore[arg-type]
        self.assertFalse(r.allowed)
        self.assertTrue(r.reason.startswith("vm_fault:"))
        self.assertIn(mark, r.reason)
        self.assertIn("…sha256:", r.reason)
        self.assertLess(len(r.reason), len("vm_fault:") + MAX_LEDGER_ERROR_CHARS + 80)
        self.assertNotIn("z" * 1000, r.reason)
        self.assertIn("VMFault", r.reason)


class ExceptionLedgerErrorHelper(unittest.TestCase):
    def test_exception_ledger_error_uses_type_tag(self):
        class WeirdName(Exception):
            pass
        WeirdName.__name__ = "W" * 500
        e = WeirdName("msg")
        out = exception_ledger_error(e)
        self.assertTrue(out.startswith(type_tag(e) + ":"))
        self.assertNotIn("W" * 100, out)


if __name__ == "__main__":
    unittest.main()
