import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest


def test_delete_rule_error(mocker):
    """
    Given:
        - The script args.
    When:
        - Running delete_rule function.
    Then:
        - Validating the outputs as expected.
    """
    from FPDeleteRule import delete_rule

    results_mock = mocker.patch.object(demisto, "results")
    delete_rule("wrong_type")
    assert (
        'Type argument must be "dest_domain", "dest_ip", "dest_host" or "url_regex". Invalid value: '
        in results_mock.call_args[0][0]["Contents"]
    )


def test_delete_rule(mocker):
    """
    Given:
        - The script args.
    When:
        - Running delete_rule function.
    Then:
        - Validating the outputs as expected.
    """
    from FPDeleteRule import delete_rule

    mocker.patch.object(demisto, "args", return_value={"tritonsystem": "tritonsystem", "value": "system"})
    execute_command_res = [{"Type": 1, "Contents": {"success": "true"}}]
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, "results")
    delete_rule("dest_domain")
    assert execute_mock.call_count == 1
    assert "Command executed successfully." in results_mock.call_args[0][0]


INVALID_VALUES = [
    ("dest_domain", "exa'mple.com"),
    ("dest_domain", "example.com;test"),
    ("dest_host", "example.com/path"),
    ("dest_host", "example com"),
    ("dest_ip", "1.1.1.1'"),
    ("dest_ip", "not-an-ip"),
    ("url_regex", "exa'mple.com"),
    ("url_regex", 'exa"mple.com'),
    ("url_regex", "line1\nline2"),
    ("url_regex", ""),
]


@pytest.mark.parametrize("rule_type, value", INVALID_VALUES)
def test_delete_rule_invalid_value(mocker, rule_type, value):
    """
    Given:
        - An invalid value for the given rule type.
    When:
        - Running delete_rule function.
    Then:
        - An error entry is returned and the command is not executed.
    """
    from FPDeleteRule import delete_rule

    mocker.patch.object(demisto, "args", return_value={"tritonsystem": "tritonsystem", "value": value})
    execute_mock = mocker.patch.object(demisto, "executeCommand")
    results_mock = mocker.patch.object(demisto, "results")
    delete_rule(rule_type)
    execute_mock.assert_not_called()
    assert results_mock.call_args[0][0]["Type"] == entryTypes["error"]


@pytest.mark.parametrize(
    "rule_type, value, expected_in_cmd",
    [
        ("dest_ip", "10.0.0.1", r"dest_ip=10\.0\.0\.1 action="),
        ("dest_ip", "2001:db8::1", r"dest_ip=2001:db8::1 action="),
        ("dest_host", "www.example.com", r"dest_host=www\.example\.com action="),
        ("dest_domain", "example.com", r"dest_domain=\"example\.com\" action="),
        ("url_regex", "example.com/path/.*", r"url_regex=\"example\.com\/path\/\.\*\" action="),
    ],
)
def test_delete_rule_valid_value(mocker, rule_type, value, expected_in_cmd):
    """
    Given:
        - A valid value for each rule type.
    When:
        - Running delete_rule function.
    Then:
        - The command is built with the escaped value.
    """
    import shlex
    from FPDeleteRule import delete_rule, FILTER_CONFIG_PATH

    mocker.patch.object(demisto, "args", return_value={"tritonsystem": "tritonsystem", "value": value})
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1, "Contents": {"success": "true"}}])
    mocker.patch.object(demisto, "results")
    delete_rule(rule_type)
    cmd = execute_mock.call_args[0][1]["cmd"]
    assert expected_in_cmd in cmd
    tokens = shlex.split(cmd)
    assert tokens[:2] == ["sed", "-i"]
    assert tokens[3:] == [FILTER_CONFIG_PATH, "&&", "/opt/WCG/bin/content_line", "-x"]
