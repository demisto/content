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


def load_file(path: str) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def test_create_relationship():
    indicator = "Sigma Rule"
    entity_b = "Command and Scripting Interpreter"
    entity_b_type = "Attack Pattern"
    result = EntityRelationship(
        entity_a="Sigma Rule",
        entity_a_type="Sigma Rule Indicator",
        name="related-to",
        entity_b="Command and Scripting Interpreter",
        entity_b_type="Attack Pattern"
    )
    assert create_relationship(indicator, entity_b, entity_b_type).to_context() == result.to_context()


@pytest.mark.parametrize("input, expected_result", [
    pytest.param(["attack.t1059"],
                 (["Command and Scripting Interpreter"], [], ["T1059 - Command and Scripting Interpreter"]),
                 id="Tag Creation - MITRE technique"),
    pytest.param(["attack.resource-development"],
                 ([], [], ["Resource Development"]),
                 id="Tag Creation - MITRE tactic"),
    pytest.param(["cve-2024-3400"],
                 ([], ["CVE-2024-3400"], ["CVE-2024-3400"]),
                 id="Tag Creation - CVEs")
])
@patch.object(CreateSigmaRuleIndicator, "get_mitre_technique_name")
def test_parse_tags(mock_get_mitre_technique_name, input, expected_result):
    mock_get_mitre_technique_name.return_value = "Command and Scripting Interpreter"
    assert parse_tags(input) == expected_result


@patch.object(demisto, "executeCommand")
def test_get_mitre_technique_name(mock_SearchIndicator):
    mitre_id = "T1059"
    get_mitre_technique_name(mitre_id)
    mock_SearchIndicator.assert_called_with("SearchIndicator", {"query": f'type:"Attack Pattern" and {mitre_id}'})


@patch.object(CreateSigmaRuleIndicator, "create_relationship")
@patch.object(CreateSigmaRuleIndicator, "return_results")
def test_create_indicator_relationships(mock_return_results, mock_create_relationship):
    mock_create_relationship.return_value("relationship")
    indicator = "Sigma Rule Test"
    product = "Windows"
    techniques = ["Some technique"]
    cves = ["CVE-2024-111"]
    create_indicator_relationships(indicator, product, techniques, cves)
    assert mock_create_relationship.call_count == 3


def test_parse_detection_field():
    detection = {
        "condition": "selection",
        "selection": {
            "QueryName|contains": ".anonfiles.com"
        }
    }

    result = [{'selection': 'selection', 'key': 'QueryName', 'modifiers': 'contains', 'values': '(1) .anonfiles.com'}]
    assert parse_detection_field(detection=detection) == result

    detection = {
        "condition": "selection and not 1 of filter_main_*",
        "filter_main_generic": {
            "RemoteName|contains": [
                ".azureedge.net/",
                ".com/",
                ".sfx.ms/",
                "download.mozilla.org/"
            ]
        },
        "selection": {
            "EventID": 16403
        }
    }

    result = [{'selection': 'filter_main_generic',
               'key': 'RemoteName',
               'modifiers': 'contains',
               'values': '(1) .azureedge.net/\n(2) .com/\n(3) .sfx.ms/\n(4) download.mozilla.org/'},
              {'selection': 'selection',
               'key': 'EventID',
               'modifiers': '',
               'values': '(1) 16403'}]

    assert parse_detection_field(detection=detection) == result


def test_parse_and_create_indicator():
    rule_dict = load_file("test_data/sigma_dict.json")
    expected_indicator = load_file("test_data/indicator.json")
    result = parse_and_create_indicator(rule_dict)
    assert result["indicator"] == expected_indicator


@patch.object(demisto, "args")
@patch.object(CreateSigmaRuleIndicator, "return_results")
@patch.object(demisto, "executeCommand")
def test_main(mock_executeCommand, mock_return_results, mock_args):
    with open("test_data/sigma_rule.yml") as f:
        rule = f.read()

    mock_args.return_value = {"sigma_rule_str": rule, "entry_id": "", "create_indicators": "True"}
    main()
    mock_return_results.assert_called_once()
    args, kwargs = mock_return_results.call_args
    assert args[0].readable_output == 'Created A new Sigma Rule indicator:\nOkta User Account Locked Out'
