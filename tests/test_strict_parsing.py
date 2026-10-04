"""Every JSON and YAML document is parsed strictly: a repeated key is refused, never last-one-wins."""

import tempfile
import unittest
from pathlib import Path

from two_key.agents import AgentConfigError, load_agents_file
from two_key.constitution import ConstitutionError, load_envelope, load_unsigned
from two_key.identity import IdentityError, load_monitored_agent_file
from two_key.judges.config import JudgeConfigError, load_config_file
from two_key.judges.llm import MalformedBallot, parse_ballot_strict
from two_key.strict import StrictParseError, loads_json, load_yaml

JUDGES = """judges:
  - id: a
    type: ollama
    model: llama3
"""


class Loaders(unittest.TestCase):
    def test_json_duplicate_at_any_depth(self):
        for text in ('{"a": 1, "a": 2}', '{"x": {"a": 1, "a": 2}}', '[{"a": 1, "a": 1}]'):
            with self.assertRaisesRegex(StrictParseError, "duplicate key 'a'"):
                loads_json(text)

    def test_json_non_standard_constants(self):
        for c in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaisesRegex(StrictParseError, "non-standard JSON constant"):
                loads_json('{"confidence": %s}' % c)

    def test_yaml_duplicate_at_any_depth(self):
        for text in ("a: 1\na: 2\n", "x:\n  a: 1\n  a: 2\n", "- {a: 1, a: 2}\n"):
            with self.assertRaisesRegex(StrictParseError, "duplicate key 'a'"):
                load_yaml(text)

    def test_yaml_is_still_safe(self):
        with self.assertRaises(StrictParseError):
            load_yaml("!!python/object/apply:os.system ['true']")

    def test_yaml_merge_keys_and_lists_still_load(self):
        self.assertEqual(load_yaml("b: &b {k: 1}\nm:\n  <<: *b\n  k: 2\nl: [{x: 1}, {x: 2}]\n"),
                         {"b": {"k": 1}, "m": {"k": 2}, "l": [{"x": 1}, {"x": 2}]})


class Callers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = self.dir / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_judges_yaml_duplicate_judge_field(self):
        p = self.write("judges.yaml", JUDGES + "    model: qwen2.5:7b\n")
        with self.assertRaisesRegex(JudgeConfigError, "duplicate key 'model'"):
            load_config_file(p)

    def test_judges_yaml_duplicate_top_level(self):
        p = self.write("judges.yaml", JUDGES + "quorum: {required_yes: 1}\nquorum: {required_yes: 2}\n")
        with self.assertRaisesRegex(JudgeConfigError, "duplicate key 'quorum'"):
            load_config_file(p)

    def test_judges_json_duplicate(self):
        p = self.write("judges.json", '{"judges": [{"id": "a", "type": "ollama", "model": "m", "id": "b"}]}')
        with self.assertRaisesRegex(JudgeConfigError, "duplicate key 'id'"):
            load_config_file(p)

    def test_monitored_agent_duplicate(self):
        p = self.write("judges.yaml", JUDGES + "monitored_agent:\n  model: gpt-4o\n  model: llama3\n")
        with self.assertRaisesRegex(IdentityError, "duplicate key 'model'"):
            load_monitored_agent_file(p)

    def test_agents_yaml_duplicate(self):
        p = self.write("agents.yaml", "agents:\n  - id: a\n    type: ollama\n    model: m\n    type: openai\n")
        with self.assertRaisesRegex(AgentConfigError, "duplicate key 'type'"):
            load_agents_file(p)

    def test_rules_yaml_duplicate(self):
        prose = self.write("c.md", "Be careful.\n")
        rules = self.write("rules.yaml", "hard_rules: []\ntool_specs: {}\nhard_rules: [{id: x}]\n")
        with self.assertRaisesRegex(ConstitutionError, "duplicate key 'hard_rules'"):
            load_unsigned(prose, rules)

    def test_constitution_envelope_duplicate(self):
        p = self.write("c.json", '{"format": "two-key-concept-constitution-v1", "signed": {}, "signed": {}}')
        with self.assertRaisesRegex(ConstitutionError, "duplicate key 'signed'"):
            load_envelope(p)

    def test_ballot_duplicate_verdict_is_malformed(self):
        text = '{"consistent": false, "confidence": 0.9, "rationale": "no", "consistent": true}'
        with self.assertRaisesRegex(MalformedBallot, "duplicate key 'consistent'"):
            parse_ballot_strict(text)

    def test_ballot_nan_confidence_is_malformed(self):
        with self.assertRaises(MalformedBallot):
            parse_ballot_strict('{"consistent": true, "confidence": NaN, "rationale": "ok"}')

    def test_cli_args_duplicate(self):
        from two_key.cli import main
        with self.assertRaises(SystemExit):
            main(["authorize", "--key", "/nonexistent", "--judges", "/nonexistent", "--ledger", str(self.dir / "l"),
                  "--constitution", "/nonexistent", "--tool", "t", "--args", '{"to": "a", "to": "b"}',
                  "--proposal", "{}"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
