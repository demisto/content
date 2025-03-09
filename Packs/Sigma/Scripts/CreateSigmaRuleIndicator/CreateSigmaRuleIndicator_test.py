from unittest.mock import patch

import CreateSigmaRuleIndicator
import pytest
from CreateSigmaRuleIndicator import (
    create_indicator_relationships,
    get_mitre_technique_name,
    parse_and_create_indicator,
    parse_detection_field,
    parse_tags,
    create_relationship,
    main
)

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from sigma.rule import SigmaRuleTag, SigmaRule


def load_file(path: str) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def test_create_relationship():
    indicator = "Sigma Rule"
    entity_b = "Command and Scripting Interpreter"
    entity_b_type = "Attack Pattern"
    relation_type = "detects"
    result = EntityRelationship(
        entity_a="Sigma Rule",
        entity_a_type="Sigma Rule Indicator",
        name="detects",
        reverse_name="detected-by",
        entity_b="Command and Scripting Interpreter",
        entity_b_type="Attack Pattern"
    )
    assert create_relationship(indicator, entity_b, entity_b_type, relation_type).to_context() == result.to_context()


@pytest.mark.parametrize("input, expected_result", [
    pytest.param([SigmaRuleTag(namespace='attack', name='t1059', source=None)],
                 ([{"value": "Command and Scripting Interpreter", "type": "Attack Pattern"}],
                  ["T1059 - Command and Scripting Interpreter"],
                  "CLEAR"),
                 id="Tag Creation - MITRE technique"),
    pytest.param([SigmaRuleTag(namespace="attack", name="resource-development"),
                  SigmaRuleTag(namespace='tlp', name='RED')],
                 ([], ["Resource Development"], "RED"),
                 id="Tag Creation - MITRE tactic"),
    pytest.param([SigmaRuleTag(namespace='cve', name="2024-3400")],
                 ([{"value": "CVE-2024-3400", "type": "CVE"}], ["CVE-2024-3400"], "CLEAR"),
                 id="Tag Creation - CVEs")
])
@patch.object(CreateSigmaRuleIndicator, "get_mitre_technique_name")
def test_parse_tags(mock_get_mitre_technique_name, input, expected_result):
    mock_get_mitre_technique_name.return_value = "Command and Scripting Interpreter"
    assert parse_tags(input) == expected_result


@patch.object(CreateSigmaRuleIndicator, "execute_command")
def test_get_mitre_technique_name(mock_execute_command):
    mock_execute_command.return_value = True, {"value": "Command and Scripting Interpreter"}
    mitre_id = "T1059"
    indicator_type = "Attack Pattern"
    get_mitre_technique_name(mitre_id, indicator_type)
    mock_execute_command.assert_called_with(command='SearchIndicator',
                                            args={'query': f'type:"Attack Pattern" and {mitre_id}'},
                                            fail_on_error=False)


@patch.object(CreateSigmaRuleIndicator, "create_relationship")
@patch.object(CreateSigmaRuleIndicator, "return_results")
def test_create_indicator_relationships(mock_return_results, mock_create_relationship):
    mock_create_relationship.return_value("relationship")
    indicator = "Sigma Rule Test"
    product = "Windows"
    relationships = [{"value": "Some technique", "type": "Attack Pattern"},
                     {"value": "CVE-2024-111", "type": "CVE"}]
    create_indicator_relationships(indicator, product, relationships)
    assert mock_create_relationship.call_count == 3


def test_parse_detection_field():

    with open("test_data/sigma_rule.yml") as f:
        sigma_rule = SigmaRule.from_yaml(f.read())

    result = [{'selection': 'selection', 'key': 'displaymessage', 'modifiers': '', 'values': '(1)Max sign in attempts exceeded'}]
    assert parse_detection_field(sigma_rule) == result


def test_parse_and_create_indicator():
    with open("test_data/sigma_rule.yml") as f:
        rule = f.read()
    expected_indicator = load_file("test_data/expected_indicator.json")
    result = parse_and_create_indicator(SigmaRule.from_yaml(rule), raw_rule=rule)
    assert result["indicator"] == expected_indicator["indicator"]


@patch.object(demisto, "args")
@patch.object(CreateSigmaRuleIndicator, "return_results")
@patch.object(CreateSigmaRuleIndicator, "execute_command")
def test_main(mock_executeCommand, mock_return_results, mock_args):
    with open("test_data/sigma_rule.yml") as f:
        rule = f.read()

    mock_args.return_value = {"sigma_rule_str": rule, "entry_id": "", "create_indicators": "True"}
    main()
    mock_return_results.assert_called_once()
    args, kwargs = mock_return_results.call_args
    assert args[0].readable_output == '1 Sigma Rule(s) Created.\n1 Relationship(s) Created.'
