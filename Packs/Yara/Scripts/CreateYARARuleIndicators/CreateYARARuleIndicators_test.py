import json
import pytest
from CreateYARARuleIndicators import build_indicator, parse_rules, parse_metadata, build_relationships
from unittest.mock import patch
import demistomock as demisto
from CommonServerPython import EntityRelationship


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


@pytest.mark.parametrize("indicator, response, expected_results", [
    ({"value": "Test_Rule_1", "rawrule": "rule TEST{strings: $a = \"T1534\" condition: $a}"},
     [{'Contents': '{"Attack_Pattern":["Internal Spearphishing"]}'}],
     EntityRelationship(entity_a="Test_Rule_1",
                        entity_a_type="YARA Rule",
                        entity_b="Internal Spearphishing",
                        entity_b_type="Attack Pattern",
                        name="related-to"),
     ),
    ({"value": "Test_Rule_2", "rawrule": "rule TEST{strings: $a = \"APT42\" condition: $a}"},
     [{'Contents': '{"Attack_Pattern":["Internal Spearphishing"]}'}],
     EntityRelationship(entity_a="Test_Rule_2",
                        entity_a_type="YARA Rule",
                        entity_b="APT42",
                        entity_b_type="Malware",
                        name="related-to")),
    ({"value": "Test_Rule_3", "rawrule": "rule TEST{strings: $a = \"T1534 CVE-2024-1111\" condition: $a}"},
     [{'Contents': '{"CVE":["CVE-2024-1111"]}'}],
     EntityRelationship(entity_a="Test_Rule_3",
                        entity_a_type="YARA Rule",
                        entity_b="CVE-2024-1111",
                        entity_b_type="CVE",
                        name="related-to"))
])
def test_build_relationships(indicator, response, expected_results):
    """
    Given:
        - A YARA Rule indicator with indicator strings in its metadata
    When:
        - Parsing the YARA Rule indicator to be created in XSOAR
    Then:
        - Ensure that the correct relationships are created.
    """

    with patch.object(demisto, 'executeCommand', return_value=response):
        relationships = build_relationships(indicator)
        assert relationships[0].to_context() == expected_results.to_context()
