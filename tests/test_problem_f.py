"""Problem F: a signed tool spec fills the form. A disagreeing claim denies.

A constitution cannot omit tool_specs. There is no English scanner: a
public tool may mention "classified ads", and medical text is denied only
because the tool's floor is medical.
"""

import tempfile
import unittest
from pathlib import Path

from two_key.constitution import ConstitutionError, load_unsigned, sign_constitution, verify_signed
from two_key.core import TwoKey
from two_key.derive import DeriveError, derive, join_data_class
from two_key.gateway import ToolGateway
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import FixedJudge


PROSE = "Never wire money. Cap spend at 200. No medical or classified data."
RULES = [
    {"id": "tools", "allow_only_tools": ["email_draft", "pay_bill", "summarize", "read_chart"]},
    {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    {"id": "sensitive", "deny_if": {"data_class_in": ["medical", "classified"]}},
    {"id": "blocked", "deny_counterparties": ["offshore-mule.example", "acme-scam.example"]},
]
SPECS = {
    "email_draft": {
        "irreversible": False,
        "data_class_floor": "public",
        "counterparties": [{"json_path": "to"}],
    },
    "pay_bill": {
        "irreversible": True,
        "data_class_floor": "financial",
        "amount": {"json_path": "amount", "unit": "usd", "currency_path": "currency"},
        "counterparties": [{"json_path": "to"}],
    },
    "summarize": {
        "irreversible": False,
        "data_class_floor": "public",
    },
    "read_chart": {
        "irreversible": False,
        "data_class_floor": "medical",
    },
}


def _engine(tmp, specs=SPECS, rules=RULES):
    key = generate_private_key()
    env = sign_constitution(PROSE, rules, key, specs)
    ledger = Ledger(Path(tmp), key)
    judges = [FixedJudge("j0", "yes", provider="p0", vendor="v0", local_weights=True),
              FixedJudge("j1", "yes", provider="p1", vendor="v1")]
    constitution = verify_signed(env, key.public_key())
    tk = TwoKey(ledger, key.public_key(), constitution, judges, private_key=key,
                quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True)
    return key, tk


class ProblemFTests(unittest.TestCase):
    def test_declared_zero_cannot_hide_a_bare_amount(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 0, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 4800, "currency": "usd", "to": "power-co.example", "memo": "4800"},
                "pay the bill")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "amount_mismatch")
            self.assertIn("path_b", [entry.kind for entry in tk.ledger.entries])

    def test_eur_string_and_eur_currency_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            as_text = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 0, "data_class": "financial", "irreversible": True},
                {"amount": "EUR 4800", "currency": "usd", "to": "power-co.example"},
                "pay")
            as_code = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 4800, "data_class": "financial", "irreversible": True},
                {"amount": 4800, "currency": "EUR", "to": "power-co.example"},
                "pay")
            self.assertEqual(as_text.reason, "derive_failed:amount_unreadable")
            self.assertEqual(as_code.reason, "derive_failed:amount_unit_rejected")
            self.assertIn("path_a", [entry.kind for entry in tk.ledger.entries])

    def test_counterparty_lie_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 10, "currency": "usd", "to": "offshore-mule.example"},
                "pay")
            self.assertEqual(decision.reason, "counterparty_mismatch")
            self.assertFalse(decision.allowed)

    def test_omitted_counterparty_is_filled_and_the_block_list_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True},
                {"amount": 10, "currency": "usd", "to": "offshore-mule.example"},
                "pay")
            self.assertFalse(decision.allowed)
            self.assertNotEqual(decision.reason, "counterparty_mismatch")
            self.assertEqual(decision.path_a["denied_by"], "blocked")

    def test_memo_dollars_do_not_raise_the_amount(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 10, "currency": "usd", "to": "power-co.example",
                 "memo": "prior balance was $5,000"},
                "pay the small bill")
            self.assertTrue(decision.allowed, decision.reason)
            self.assertEqual(decision.reason, "both_paths_allow")

    def test_classified_ads_on_a_public_tool_are_not_a_sensitive_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"text": "see the classified ads in the paper"},
                "summarize")
            self.assertTrue(decision.allowed, decision.reason)

    def test_medical_floor_raises_a_public_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "read_chart", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": "Pt dx: HIV+, Rx listed"},
                "read")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "sensitive")
            normalized = [entry for entry in tk.ledger.entries if entry.kind == "action_normalized"][-1]
            self.assertEqual(normalized.body["form"]["data_class"], "medical")

    def test_irreversible_claim_cannot_understate_the_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": False,
                 "counterparty": "power-co.example"},
                {"amount": 10, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(decision.reason, "irreversible_mismatch")

    def test_missing_amount_path_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "data_class": "financial", "irreversible": True},
                {"currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(decision.reason, "derive_failed:amount_missing")

    def test_gateway_recomputes_the_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            args = {"amount": 10, "currency": "usd", "to": "power-co.example"}
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                args, "pay")
            self.assertTrue(decision.allowed, decision.reason)
            gateway = ToolGateway(tk.ledger, tk.issuer, tk.compiled,
                                  tools={"pay_bill": lambda a: {"paid": a["to"]}})
            redeemed = gateway.invoke(decision.token, "pay_bill", args)
            self.assertTrue(redeemed.allowed, redeemed.reason)

    def test_spec_change_invalidates_the_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, tk = _engine(tmp)
            args = {"to": "ada@example"}
            decision = tk.authorize(
                {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False,
                 "counterparty": "ada@example"},
                args, "draft")
            self.assertTrue(decision.allowed, decision.reason)
            other = dict(SPECS)
            other["email_draft"] = dict(SPECS["email_draft"], data_class_floor="personal")
            envelope = sign_constitution(PROSE, RULES, key, other)
            other_tk = TwoKey(tk.ledger, key.public_key(), verify_signed(envelope, key.public_key()),
                              tk.judges, private_key=key, quorum=tk.quorum, allow_test_doubles=True)
            gateway = ToolGateway(tk.ledger, tk.issuer, other_tk.compiled,
                                  tools={"email_draft": lambda a: a})
            result = gateway.invoke(decision.token, "email_draft", args)
            self.assertEqual(result.reason, "constitution_mismatch")

    def test_allow_list_without_a_spec_is_refused(self):
        key = generate_private_key()
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, {})

    def test_example_rules_file_enforces_specs(self):
        root = Path(__file__).resolve().parents[1]
        _prose, rules, specs = load_unsigned(root / "examples" / "constitution.md",
                                             root / "examples" / "hard_rules.yaml")
        self.assertIn("pay_bill", specs)
        key = generate_private_key()
        envelope = sign_constitution(_prose, rules, key, specs)
        constitution = verify_signed(envelope, key.public_key())
        self.assertTrue(constitution.specs_enforced)
        self.assertEqual(constitution.tool_specs["pay_bill"]["amount"]["unit"], "usd")
        self.assertFalse(constitution.tool_specs["pay_bill"]["deny_unmapped"])
        self.assertEqual(constitution.tool_specs["summarize"]["payload"], [])

    def test_join_never_lowers_the_floor(self):
        self.assertEqual(join_data_class("public", "medical"), "medical")
        self.assertEqual(join_data_class("classified", "public"), "classified")
        self.assertEqual(join_data_class("personal", "medical"), "classified")
        self.assertEqual(join_data_class("financial", "financial"), "financial")

    def test_omitted_tool_specs_are_refused(self):
        """There is no legacy path that trusts the agent's form."""
        key = generate_private_key()
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key)
        from two_key.canonical import canonical_bytes
        from two_key.keys import fingerprint, sign
        from two_key.policy_vm import validate_rules
        rules = validate_rules(RULES)
        signed = {"prose": PROSE, "hard_rules": rules}
        envelope = {
            "format": "two-key-concept-constitution-v1",
            "signed": signed,
            "signature": sign(key, canonical_bytes(signed)),
            "fingerprint": fingerprint(key.public_key()),
        }
        with self.assertRaises(ConstitutionError):
            verify_signed(envelope, key.public_key())
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp, "rules.yaml")
            prose_path = Path(tmp, "prose.md")
            prose_path.write_text(PROSE, encoding="utf-8")
            rules_path.write_text(
                "hard_rules:\n  - id: tools\n    allow_only_tools: [search]\n",
                encoding="utf-8")
            with self.assertRaises(ConstitutionError):
                load_unsigned(prose_path, rules_path)
            rules_path.write_text("- id: tools\n  allow_only_tools: [search]\n", encoding="utf-8")
            with self.assertRaises(ConstitutionError):
                load_unsigned(prose_path, rules_path)

    def test_cents_unit_accepts_an_integral_float_only(self):
        spec = {
            "irreversible": True,
            "data_class_floor": "financial",
            "amount": {"json_path": "amount", "unit": "cents"},
            "counterparties": [],
        }
        got = derive(spec, {"amount": 1050.0})
        self.assertEqual(got.amount_usd, 10.5)
        with self.assertRaises(DeriveError) as fractional:
            derive(spec, {"amount": 10.5})
        self.assertEqual(fractional.exception.reason, "amount_unreadable")
        with self.assertRaises(DeriveError) as huge:
            derive(spec, {"amount": 10**20})
        self.assertEqual(huge.exception.reason, "amount_unreadable")

    def test_derived_amount_above_the_sanity_cap_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 0, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"amount": 10**13, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(decision.reason, "derive_failed:amount_unreadable")
            self.assertFalse(decision.allowed)

    def test_null_tool_specs_is_not_the_legacy_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yaml"
            prose = Path(tmp) / "prose.md"
            prose.write_text("Do not wire money.\n", encoding="utf-8")
            rules.write_text(
                "hard_rules:\n"
                "  - id: tools\n"
                "    allow_only_tools: [search]\n"
                "tool_specs: null\n",
                encoding="utf-8")
            with self.assertRaises(ConstitutionError):
                load_unsigned(prose, rules)

    def test_blocked_party_is_not_hidden_behind_an_allowed_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True},
                {"amount": 10, "currency": "usd",
                 "to": ["aaa-good.example", "offshore-mule.example"]},
                "pay")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.path_a["denied_by"], "blocked")

    def test_omitted_irreversible_follows_the_spec(self):
        rules = RULES + [{"id": "no-irreversible", "deny_if": {"irreversible": True}}]
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, rules=rules)
            omitted = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public"},
                {"text": "hello"}, "summarize")
            claimed = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": True},
                {"text": "hello"}, "summarize")
            self.assertTrue(omitted.allowed, omitted.reason)
            self.assertEqual(claimed.reason, "irreversible_mismatch")

    def test_unnamed_keys_stay_payload_unless_the_spec_opts_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp)
            allowed = tk.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"text": "hello", "extra": {"n": 5}},
                "summarize")
            self.assertTrue(allowed.allowed, allowed.reason)
        specs = {name: dict(spec) for name, spec in SPECS.items()}
        specs["summarize"] = dict(SPECS["summarize"], deny_unmapped=True)
        with tempfile.TemporaryDirectory() as tmp:
            _, strict = _engine(tmp, specs=specs)
            denied = strict.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"text": "hello"},
                "summarize")
            self.assertEqual(denied.reason, "derive_failed:unmapped_field")
        specs["summarize"] = dict(
            SPECS["summarize"], deny_unmapped=True, payload=[{"json_path": "note"}],
        )
        with tempfile.TemporaryDirectory() as tmp:
            _, named = _engine(tmp, specs=specs)
            decision = named.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": {"n": 5000, "text": "hello"}},
                "summarize")
            self.assertTrue(decision.allowed, decision.reason)
            form = [entry for entry in named.ledger.entries if entry.kind == "action_normalized"][-1]
            self.assertEqual(form.body["form"]["amount_usd"], 0.0)
            sibling = named.authorize(
                {"tool": "summarize", "amount_usd": 0, "data_class": "public", "irreversible": False},
                {"note": "hello", "other": 1},
                "summarize")
            self.assertEqual(sibling.reason, "derive_failed:unmapped_field")

    def test_deny_unmapped_walks_only_to_declared_paths(self):
        specs = {name: dict(spec) for name, spec in SPECS.items()}
        specs["pay_bill"] = dict(
            SPECS["pay_bill"],
            deny_unmapped=True,
            amount={"json_path": "invoice.total", "unit": "usd", "currency_path": "currency"},
        )
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, specs=specs)
            clean = {"invoice": {"total": 10}, "currency": "usd", "to": "power-co.example"}
            decision = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                clean, "pay")
            self.assertTrue(decision.allowed, decision.reason)
            nested = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"invoice": {"total": 10, "note": "x"}, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertEqual(nested.reason, "derive_failed:unmapped_field")
        specs["pay_bill"] = dict(
            specs["pay_bill"],
            payload=[{"json_path": "invoice"}],
        )
        with tempfile.TemporaryDirectory() as tmp:
            _, tk = _engine(tmp, specs=specs)
            covered = tk.authorize(
                {"tool": "pay_bill", "amount_usd": 10, "data_class": "financial", "irreversible": True,
                 "counterparty": "power-co.example"},
                {"invoice": {"total": 10, "note": "x"}, "currency": "usd", "to": "power-co.example"},
                "pay")
            self.assertTrue(covered.allowed, covered.reason)

    def test_deny_unmapped_must_be_a_boolean_and_paths_must_be_unique(self):
        key = generate_private_key()
        bad_flag = {name: dict(spec) for name, spec in SPECS.items()}
        bad_flag["summarize"] = dict(SPECS["summarize"], deny_unmapped="yes")
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, bad_flag)
        duplicate = {name: dict(spec) for name, spec in SPECS.items()}
        duplicate["email_draft"] = dict(
            SPECS["email_draft"], payload=[{"json_path": "to"}],
        )
        with self.assertRaises(ConstitutionError):
            sign_constitution(PROSE, RULES, key, duplicate)


if __name__ == "__main__":
    unittest.main()
