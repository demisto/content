import json
import pytest
from ImportYARARule import build_indicator, parse_rules, parse_metadata


def open_json(path):
    with open(path) as f:
        return json.loads(f.read())


@pytest.mark.parametrize("meta", [([{"author": "Some Author"}]), ([{"Author": "Some Author"}])])
def test_parse_metadata(meta):
    result = parse_metadata(key="author", meta=meta)
    assert result == "Some Author"


def test_build_indicator():
    parsed_rule = open_json("test_data/parsed_rule.json")
    indicator = json.dumps(build_indicator(parsed_rule))

    with open("test_data/indicator.json") as f:
        expected = f.read()

    assert indicator == expected


@pytest.mark.parametrize("filename, expected_rules", [('multiple_rules.yar', 2), ('rule.yar', 1)])
def test_parse_rules(filename, expected_rules):
    with open(f'test_data/{filename}') as f:
        rules = f.read()

    result = parse_rules(rules)
    rule_count = len(result.outputs)
    assert rule_count == expected_rules
