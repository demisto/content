import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_set_rule_error_policy(mocker):
    """
    Given:
        - The script args.
    When:
        - Running seste_rule function.
    Then:
        - Validating the outputs as expected.
    """
    from FPSetRule import set_rule

    results_mock = mocker.patch.object(demisto, "results")
    set_rule("wrong_policy", "dest_domain")
    assert 'Policy argument must be "allow" or "deny". Invalid value: wrong_policy' in results_mock.call_args[0][0]["Contents"]


def test_set_rule_error_type(mocker):
    """
    Given:
        - The script args.
    When:
        - Running seste_rule function.
    Then:
        - Validating the outputs as expected.
    """
    from FPSetRule import set_rule

    results_mock = mocker.patch.object(demisto, "results")
    set_rule("allow", "wrong_type")
    assert (
        'Type argument must be "dest_domain", "dest_ip", "dest_host" or "url_regex". Invalid value: wrong_type'
        in results_mock.call_args[0][0]["Contents"]
    )


def test_set_rule(mocker):
    """
    Given:
        - The script args.
    When:
        - Running set_rule function.
    Then:
        - Validating the outputs as expected.
    """
    from FPSetRule import set_rule

    mocker.patch.object(demisto, "args", return_value={"tritonsystem": "tritonsystem", "value": "system"})
    execute_command_res = [{"Type": 1, "Contents": {"success": "true"}}]
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, "results")
    set_rule("allow", "dest_domain")
    assert execute_mock.call_count == 1
    assert "Command executed successfully." in results_mock.call_args[0][0]
