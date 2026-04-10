import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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
