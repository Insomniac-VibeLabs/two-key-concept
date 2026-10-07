"""The vendor-diversity floor compares vendor names case-insensitively (and NFKC, trimmed)."""

import unittest

from two_key.quorum import QuorumConfigError, QuorumPolicy, check_judge_set, convene, heterogeneity_shortfall
from two_key.testing import FixedJudge

POLICY = QuorumPolicy(required_yes=2, min_vendors=2, min_local_judges=0, require_local_yes=False)


class VendorCase(unittest.TestCase):
    def test_case_variants_are_one_vendor(self):
        for a, b in (("OpenAI", "openai"), ("openai", "OPENAI "), ("Anthropic", "ａｎｔｈｒｏｐｉｃ")):
            judges = [FixedJudge("a", "yes", vendor=a), FixedJudge("b", "yes", vendor=b)]
            self.assertEqual(heterogeneity_shortfall(judges, POLICY), "insufficient_vendors:1<2", (a, b))
            with self.assertRaisesRegex(QuorumConfigError, "insufficient_vendors:1<2"):
                check_judge_set(judges, POLICY)

    def test_provider_fallback_is_folded_too(self):
        judges = [FixedJudge("a", "yes", "XAI"), FixedJudge("b", "yes", "xai")]
        self.assertEqual(heterogeneity_shortfall(judges, POLICY), "insufficient_vendors:1<2")

    def test_distinct_vendors_still_count(self):
        judges = [FixedJudge("a", "yes", vendor="OpenAI"), FixedJudge("b", "yes", vendor="Anthropic")]
        self.assertIsNone(heterogeneity_shortfall(judges, POLICY))

    def test_convene_denies_case_variants(self):
        from two_key.action import normalize_action
        judges = [FixedJudge("a", "yes", vendor="OpenAI"), FixedJudge("b", "yes", vendor="openai")]
        act = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        r = convene(judges, "Be careful.", act, "look it up", POLICY)
        self.assertFalse(r.passed)
        self.assertEqual(r.reason, "judge_set_not_heterogeneous:insufficient_vendors:1<2")


class ProviderCase(unittest.TestCase):
    def test_distinct_provider_count_folds_case(self):
        from two_key.action import normalize_action
        judges = [FixedJudge("a", "yes", "OpenAI"), FixedJudge("b", "yes", "openai ")]
        act = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
        r = convene(judges, "Be careful.", act, "look it up", QuorumPolicy(required_yes=2, min_distinct_providers=2))
        self.assertEqual(r.reason, "insufficient_distinct_providers:1<2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
