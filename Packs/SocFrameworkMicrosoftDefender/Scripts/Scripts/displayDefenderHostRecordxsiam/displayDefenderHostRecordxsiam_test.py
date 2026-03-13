import sys
import types

# ---- Mock XSOAR runtime modules before importing the script ----

demisto_mock = types.SimpleNamespace()
demisto_mock.alert = lambda: {}
demisto_mock.error = lambda x: None

sys.modules["demistomock"] = demisto_mock

common = types.ModuleType("CommonServerPython")


def return_results(x):
    return x


def execute_command(command, args):
    return []


common.return_results = return_results
common.execute_command = execute_command

sys.modules["CommonServerPython"] = common

import displayDefenderHostRecordxsiam as script


def test_main_returns_host_record(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-123"
        }
    }
    host_context = [
        {
            "id": "machine-123",
            "computerDnsName": "host1.contoso.com",
            "healthStatus": "Active",
            "osPlatform": "Windows10"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    execute_command_mock = mocker.patch.object(
        script,
        "execute_command",
        return_value=host_context
    )
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    execute_command_mock.assert_called_once_with(
        "microsoft-atp-get-machine-details",
        {"machine_id": "machine-123"}
    )
    return_results_mock.assert_called_once_with({
        "id": "machine-123",
        "computerDnsName": "host1.contoso.com",
        "healthStatus": "Active",
        "osPlatform": "Windows10"
    })


def test_main_returns_error_when_alert_missing_customfields(mocker):
    alert = {}

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host details" in result
    assert "Exception thrown" in result


def test_main_returns_error_when_agentid_missing(mocker):
    alert = {
        "CustomFields": {}
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host details" in result
    assert "Exception thrown" in result


def test_main_returns_error_when_execute_command_fails(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-123"
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(
        script,
        "execute_command",
        side_effect=Exception("integration failure")
    )
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host details" in result
    assert "integration failure" in result


def test_main_returns_error_when_host_context_empty(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-123"
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script, "execute_command", return_value=[])
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host details" in result
    assert "Exception thrown" in result


def test_main_returns_first_host_record_when_multiple_returned(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-123"
        }
    }
    host_context = [
        {
            "id": "machine-123",
            "computerDnsName": "host1.contoso.com"
        },
        {
            "id": "machine-456",
            "computerDnsName": "host2.contoso.com"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script, "execute_command", return_value=host_context)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once_with({
        "id": "machine-123",
        "computerDnsName": "host1.contoso.com"
    })