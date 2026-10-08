"""The maker-diversity floor compares maker names case-insensitively (and NFKC, trimmed).

``maker`` / ``min_makers`` were ``vendor`` / ``min_vendors`` through 0.2.1; the old names still work.
"""

import contextlib
import dataclasses
import io
import unittest

from two_key.judges.config import JudgeConfigError, load_config
from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.quorum import QuorumConfigError, QuorumPolicy, check_judge_set, convene, heterogeneity_shortfall
from two_key.testing import FixedJudge

POLICY = QuorumPolicy(required_yes=2, min_makers=2, min_local_judges=0, require_local_yes=False)


class MakerCase(unittest.TestCase):
    def test_case_variants_are_one_maker(self):
        for a, b in (("OpenAI", "openai"), ("openai", "OPENAI "), ("Anthropic", "ａｎｔｈｒｏｐｉｃ")):
            judges = [FixedJudge("a", "yes", maker=a), FixedJudge("b", "yes", maker=b)]
            self.assertEqual(heterogeneity_shortfall(judges, POLICY), "insufficient_makers:1<2", (a, b))
            with self.assertRaisesRegex(QuorumConfigError, "insufficient_makers:1<2"):
                check_judge_set(judges, POLICY)

    def test_provider_fallback_is_folded_too(self):
        judges = [FixedJudge("a", "yes", "XAI"), FixedJudge("b", "yes", "xai")]
        self.assertEqual(heterogeneity_shortfall(judges, POLICY), "insufficient_makers:1<2")

    def test_distinct_makers_still_count(self):
        judges = [FixedJudge("a", "yes", maker="OpenAI"), FixedJudge("b", "yes", maker="Anthropic")]
        self.assertIsNone(heterogeneity_shortfall(judges, POLICY))

    def test_convene_denies_case_variants(self):
        from two_key.action import normalize_action
        judges = [FixedJudge("a", "yes", maker="OpenAI"), FixedJudge("b", "yes", maker="openai")]
        act = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        r = convene(judges, "Be careful.", act, "look it up", POLICY)
        self.assertFalse(r.passed)
        self.assertEqual(r.reason, "judge_set_not_heterogeneous:insufficient_makers:1<2")


class ProviderCase(unittest.TestCase):
    def test_distinct_provider_count_folds_case(self):
        from two_key.action import normalize_action
        judges = [FixedJudge("a", "yes", "OpenAI"), FixedJudge("b", "yes", "openai ")]
        act = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        r = convene(judges, "Be careful.", act, "look it up", QuorumPolicy(required_yes=2, min_distinct_providers=2))
        self.assertEqual(r.reason, "insufficient_distinct_providers:1<2")


def judge_spec(jid, **extra):
    return {"id": jid, "type": "openai_compatible", "base_url": "https://api.example.com/v1", "model": "m",
            "auth": {"type": "none"}, **extra}


def quiet(fn, *a, **kw):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = fn(*a, **kw)
    return out, err.getvalue()


class OldNames(unittest.TestCase):
    """vendor and min_vendors (through 0.2.1) are deprecated aliases with a stderr note."""

    def test_policy_record_uses_the_new_key(self):
        rec = QuorumPolicy.high_assurance().to_record()
        self.assertEqual(rec["min_makers"], 2)
        self.assertNotIn("min_vendors", rec)

    def test_min_vendors_keyword(self):
        p, err = quiet(QuorumPolicy, min_vendors=3)
        self.assertEqual((p.min_makers, p.min_vendors), (3, 3))
        self.assertEqual(p, QuorumPolicy(min_makers=3))
        self.assertIn("min_vendors is deprecated; use min_makers", err)
        for build in (QuorumPolicy.high_assurance, QuorumPolicy.section4, QuorumPolicy.without_diversity_floors):
            p, err = quiet(build, min_vendors=3)
            self.assertEqual(p.min_makers, 3, build)
            self.assertIn("deprecated", err)

    def test_min_vendors_and_min_makers_together_are_refused(self):
        for build in (QuorumPolicy, QuorumPolicy.high_assurance):
            with self.assertRaisesRegex(QuorumConfigError, "not both"):
                quiet(build, min_vendors=2, min_makers=2)

    def test_replace_keeps_a_new_min_makers(self):
        p = QuorumPolicy(min_makers=3)
        self.assertEqual(dataclasses.replace(p, min_makers=1).min_makers, 1)
        self.assertEqual(p.resolved(4).min_makers, 3)

    def test_vendor_keyword_and_attribute(self):
        j, err = quiet(FixedJudge, "a", "yes", vendor="OpenAI")
        self.assertEqual((j.maker, j.vendor), ("OpenAI", "OpenAI"))
        self.assertIn("vendor is deprecated; use maker", err)
        j.vendor = "Anthropic"
        self.assertEqual(j.maker, "Anthropic")
        o, _ = quiet(OpenAICompatibleJudge, "o", "p", "m", "https://api.example.com/v1", vendor="xai")
        self.assertEqual(o.maker, "xai")
        with self.assertRaisesRegex(ValueError, "not both"):
            FixedJudge("a", "yes", maker="x", vendor="y")

    def test_judge_written_before_the_rename_keeps_its_label(self):
        from two_key.judges.base import Ballot, Judge

        class Legacy(Judge):
            vendor = "same-maker"

            def __init__(self, jid, provider):
                self.judge_id, self.provider = jid, provider

            def score(self, constitution_text, action, proposal):
                return Ballot(self.judge_id, self.provider, "yes", 0.9, "")

        class DuckTyped:
            def __init__(self, jid, provider):
                self.judge_id, self.provider, self.vendor = jid, provider, "same-maker"

        for cls in (Legacy, DuckTyped):
            judges = [cls("a", "p1"), cls("b", "p2")]
            # Two providers but one old vendor label: still one maker, so the floor is not met.
            self.assertEqual(heterogeneity_shortfall(judges, POLICY), "insufficient_makers:1<2", cls)
        self.assertEqual(Legacy("a", "p1").maker, "same-maker")
        j = Legacy("a", "p1")
        j.maker = "override"
        self.assertEqual(j.maker, "override")

    def test_config_accepts_old_keys_with_a_note(self):
        cfg = {"judges": [judge_spec("a", vendor="openai"), judge_spec("b", maker="anthropic")],
               "quorum": {"min_vendors": 2, "required_yes": 2}}
        (judges, policy), err = quiet(load_config, cfg)
        self.assertEqual([j.maker for j in judges], ["openai", "anthropic"])
        self.assertEqual(policy.min_makers, 2)
        self.assertIn("vendor is deprecated", err)
        self.assertIn("min_vendors is deprecated", err)

    def test_config_new_keys(self):
        cfg = {"judges": [judge_spec("a", maker="openai"), judge_spec("b", maker="openai")],
               "quorum": {"min_makers": 2, "required_yes": 2}}
        with self.assertRaisesRegex(JudgeConfigError, "insufficient_makers:1<2"):
            load_config(cfg)

    def test_config_refuses_both_names(self):
        with self.assertRaisesRegex(JudgeConfigError, "not both"):
            quiet(load_config, {"judges": [judge_spec("a", maker="x", vendor="x")]})
        with self.assertRaisesRegex(JudgeConfigError, "not both"):
            quiet(load_config, {"judges": [judge_spec("a")], "quorum": {"min_makers": 1, "min_vendors": 1}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
