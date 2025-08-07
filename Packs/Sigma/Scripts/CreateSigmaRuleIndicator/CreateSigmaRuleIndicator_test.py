from unittest.mock import patch, MagicMock
import io
import zipfile

import CreateSigmaRuleIndicator
import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from CreateSigmaRuleIndicator import (
    create_indicator_relationships,
    get_mitre_technique_name,
    parse_and_create_indicator,
    parse_detection_field,
    parse_tags,
    create_relationship,
    main,
    tim_create_indicators,
    extract_rules_from_zip
)
from sigma.rule import SigmaRule, SigmaRuleTag


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
        entity_b_type="Attack Pattern",
    )
    assert create_relationship(indicator, entity_b, entity_b_type, relation_type).to_context() == result.to_context()


@pytest.mark.parametrize(
    "input, expected_result",
    [
        pytest.param(
            [SigmaRuleTag(namespace="attack", name="t1059", source=None)],
            (
                [{"value": "Command and Scripting Interpreter", "type": "Attack Pattern"}],
                ["T1059 - Command and Scripting Interpreter"],
                "CLEAR",
            ),
            id="Tag Creation - MITRE technique",
        ),
        pytest.param(
            [SigmaRuleTag(namespace="attack", name="resource-development"), SigmaRuleTag(namespace="tlp", name="RED")],
            ([], ["Resource Development"], "RED"),
            id="Tag Creation - MITRE tactic",
        ),
        pytest.param(
            [SigmaRuleTag(namespace="cve", name="2024-3400")],
            ([{"value": "CVE-2024-3400", "type": "CVE"}], ["CVE-2024-3400"], "CLEAR"),
            id="Tag Creation - CVEs",
        ),
    ],
)
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
    mock_execute_command.assert_called_with(
        command="SearchIndicator", args={"query": f'type:"Attack Pattern" and {mitre_id}'}, fail_on_error=False
    )


@patch.object(CreateSigmaRuleIndicator, "create_relationship")
@patch.object(CreateSigmaRuleIndicator, "return_results")
def test_create_indicator_relationships(mock_return_results, mock_create_relationship):
    mock_create_relationship.return_value("relationship")
    indicator = "Sigma Rule Test"
    product = "Windows"
    relationships = [{"value": "Some technique", "type": "Attack Pattern"}, {"value": "CVE-2024-111", "type": "CVE"}]
    create_indicator_relationships(indicator, product, relationships)
    assert mock_create_relationship.call_count == 3


def test_parse_detection_field():
    with open("test_data/sigma_rule.yml") as f:
        sigma_rule = SigmaRule.from_yaml(f.read())

    result = [{"selection": "selection", "key": "displaymessage", "modifiers": "", "values": "(1)Max sign in attempts exceeded"}]
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


@patch('CreateSigmaRuleIndicator.execute_command')
@patch('CreateSigmaRuleIndicator.create_indicator_relationships')
@patch('CreateSigmaRuleIndicator.demisto.debug')
@patch('CreateSigmaRuleIndicator.time.time')
def test_tim_create_indicators(mock_time, mock_debug, mock_create_relationships, mock_execute_command):
    sample_indicators = [
        {
            "indicator": {
                "value": "Test Sigma Rule 1",
                "type": "Sigma Rule",
                "product": "windows",
            },
            "relationships": [
                {"value": "T1562 - Impair Defenses", "type": "Attack Pattern"},
                {"value": "CVE-2021-44228", "type": "CVE"},
            ],
        },
        {
            "indicator": {
                "value": "Test Sigma Rule 2",
                "type": "Sigma Rule",
                "product": "linux",
            },
            "relationships": [{"value": "S0601 - Cobalt Strike", "type": "Tool"}],
        },
    ]

    # Setup mocks
    mock_time.side_effect = [100, 105]  # Start and end times

    # Mock relationships that would be created
    mock_create_relationships.side_effect = [
        [
            EntityRelationship(entity_a="Test Sigma Rule 1", entity_a_type="Sigma Rule Indicator",
                               name="related-to", entity_b="Windows", entity_b_type="Software"),
            EntityRelationship(entity_a="Test Sigma Rule 1", entity_a_type="Sigma Rule Indicator",
                               name="detects", entity_b="T1562 - Impair Defenses", entity_b_type="Attack Pattern"),
            EntityRelationship(entity_a="Test Sigma Rule 1", entity_a_type="Sigma Rule Indicator",
                               name="detects", entity_b="CVE-2021-44228", entity_b_type="CVE")
        ],
        [
            EntityRelationship(entity_a="Test Sigma Rule 2", entity_a_type="Sigma Rule Indicator",
                               name="related-to", entity_b="Linux", entity_b_type="Software"),
            EntityRelationship(entity_a="Test Sigma Rule 2", entity_a_type="Sigma Rule Indicator",
                               name="detects", entity_b="S0601 - Cobalt Strike", entity_b_type="Tool")
        ]
    ]

    # Execute the function
    result = tim_create_indicators(sample_indicators)

    # Verify results
    assert mock_execute_command.call_count == 2
    mock_execute_command.assert_any_call("createNewIndicator", sample_indicators[0]["indicator"])
    mock_execute_command.assert_any_call("createNewIndicator", sample_indicators[1]["indicator"])

    assert mock_create_relationships.call_count == 2
    mock_create_relationships.assert_any_call("Test Sigma Rule 1", "windows", sample_indicators[0]["relationships"])
    mock_create_relationships.assert_any_call("Test Sigma Rule 2", "linux", sample_indicators[1]["relationships"])

    mock_debug.assert_called_once_with("2 indicators created. in 5 seconds")

    # Verify returned CommandResults
    assert isinstance(result, CommandResults)
    assert result.readable_output == "2 Sigma Rule(s) Created.\n5 Relationship(s) Created."
    assert len(result.relationships) == 5  # Total relationships from both indicators


def create_zip_mock(file_contents, file_names):
    """Helper to create a mock zipfile"""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        for name, content in zip(file_names, file_contents):
            zip_file.writestr(name, content)
    return zip_buffer.getvalue()


@pytest.fixture
def valid_sigma_rule():
    return '''
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: test
description: Test rule for unit testing
author: Test Author
date: 2023/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: suspicious.exe
    condition: selection
level: high
tags:
    - attack.t1055
    - attack.s0001
    - cve.2023.1234
'''


@pytest.fixture
def invalid_sigma_rule():
    return '''
title: Invalid Rule
status: test
# Missing required fields like id, detection, etc.
'''


@patch('zipfile.ZipFile')
def test_extract_rules_from_zip_successful(mock_zipfile, valid_sigma_rule):
    """Test extracting valid rules from a zip file"""

    # Setup mock zipfile with valid rules
    mock_zip_instance = MagicMock()
    mock_zipfile.return_value.__enter__.return_value = mock_zip_instance
    mock_zip_instance.namelist.return_value = ['rule1.yml', 'rule2.yml', '__pycache__/ignored.yml', '.hidden.yml']

    # Mock file content reading
    mock_file = MagicMock()
    mock_file.read.return_value = valid_sigma_rule.encode('utf-8')
    mock_zip_instance.open.return_value.__enter__.return_value = mock_file

    # Mock parse_and_create_indicator to return a predetermined value
    expected_indicator = {"indicator": {"value": "Test Rule"}, "relationships": []}
    with patch('CreateSigmaRuleIndicator.parse_and_create_indicator', return_value=expected_indicator):
        result = extract_rules_from_zip("test.zip")

    # Assertions
    assert len(result) == 2  # Should extract 2 valid files
    assert result[0] == expected_indicator
    assert result[1] == expected_indicator

    # Verify correct files were processed
    mock_zip_instance.open.assert_any_call('rule1.yml')
    mock_zip_instance.open.assert_any_call('rule2.yml')
    assert mock_zip_instance.open.call_count == 2


@patch('zipfile.ZipFile')
def test_extract_rules_from_zip_with_errors(mock_zipfile, valid_sigma_rule, invalid_sigma_rule, capfd):
    """Test handling errors during rule extraction"""

    # Setup mock zipfile with mixed valid and invalid rules
    mock_zip_instance = MagicMock()
    mock_zipfile.return_value.__enter__.return_value = mock_zip_instance
    mock_zip_instance.namelist.return_value = ['valid.yml', 'invalid.yml']

    # Setup mock file reading to return different content based on filename
    def mock_open_file(filename):
        from unittest.mock import MagicMock
        mock_file = MagicMock()
        if filename == 'valid.yml':
            mock_file.read.return_value = valid_sigma_rule.encode('utf-8')
        else:
            mock_file.read.return_value = invalid_sigma_rule.encode('utf-8')
        return mock_file

    mock_zip_instance.open.side_effect = lambda filename: MagicMock(__enter__=lambda x: mock_open_file(filename))

    # Mock SigmaRule.from_yaml to raise an exception for the invalid rule
    original_from_yaml = SigmaRule.from_yaml

    def mock_from_yaml(yaml_str):
        if "Invalid Rule" in yaml_str:
            raise Exception("Invalid rule format")
        return original_from_yaml(yaml_str)

    # Mock parse_and_create_indicator for the valid rule
    expected_indicator = {"indicator": {"value": "Test Rule"}, "relationships": []}

    with patch('sigma.rule.SigmaRule.from_yaml', side_effect=mock_from_yaml), \
            patch('CreateSigmaRuleIndicator.parse_and_create_indicator', return_value=expected_indicator):
        result = extract_rules_from_zip("test.zip")

    # Assertions
    out, err = capfd.readouterr()
    assert len(result) == 1  # Only the valid rule should be processed
    assert result[0] == expected_indicator
    assert out == 'SGM: Error parsing Sigma rule from file "invalid.yml": Invalid rule format\n'


@patch('zipfile.ZipFile')
def test_extract_rules_from_zip_empty(mock_zipfile):
    """Test extracting rules from a zip file with no valid rules"""
    # Setup mock zipfile with no valid rules
    mock_zip_instance = MagicMock()
    mock_zipfile.return_value.__enter__.return_value = mock_zip_instance
    mock_zip_instance.namelist.return_value = ['__pycache__/ignored.yml', '.hidden.yml', 'not_a_rule.txt']

    result = extract_rules_from_zip("test.zip")

    # Assertions
    assert len(result) == 0  # No valid rules should be found
    assert not mock_zip_instance.open.called  # No files should be opened
