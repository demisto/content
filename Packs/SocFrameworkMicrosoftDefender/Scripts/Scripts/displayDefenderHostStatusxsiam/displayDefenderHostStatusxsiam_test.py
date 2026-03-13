import sys
import types

# ---- Mock XSOAR runtime modules before importing the script ----

demisto_mock = types.SimpleNamespace()
demisto_mock.alert = lambda: {}
demisto_mock.context = lambda: {}
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

import displayDefenderHostStatusxsiam as script


def test_main_returns_host_status_with_isolate_action_list(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-123"
        }
    }
    context = {
        "MicrosoftATP": {
            "MachineAction": [
                {
                    "Type": "Investigate",
                    "CreationDateTimeUtc": "2026-03-10T10:00:00Z"
                },
                {
                    "Type": "Isolate",
                    "CreationDateTimeUtc": "2026-03-10T11:00:00Z"
                }
            ]
        }
    }
    host_record = [
        {
            "lastSeen": "2026-03-10T12:00:00Z",
            "riskScore": "High",
            "computerDnsName": "host1.contoso.com",
            "healthStatus": "Active",
            "lastIpAddress": "10.0.0.10",
            "lastExternalIpAddress": "1.2.3.4",
            "osPlatform": "Windows11"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value=context)
    execute_command_mock = mocker.patch.object(
        script,
        "execute_command",
        return_value=host_record
    )
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    execute_command_mock.assert_called_once_with(
        "microsoft-atp-get-machine-details",
        {"machine_id": "machine-123"}
    )
    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "Hostname: host1.contoso.com" in result
    assert "MDE Risk Score: 🔴 High" in result
    assert "MDE Status: 🟢 Active" in result
    assert "Last XSIAM Action: 🚫 Isolate (UTC: 2026-03-10T11:00:00Z)" in result
    assert "Last Seen: 2026-03-10T12:00:00Z" in result
    assert "Current Local IP: 10.0.0.10" in result
    assert "Current External IP: 1.2.3.4" in result
    assert "OS: Windows11" in result


def test_main_returns_host_status_with_unisolate_action_dict(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-456"
        }
    }
    context = {
        "MicrosoftATP": {
            "MachineAction": {
                "Type": "Unisolate",
                "CreationDateTimeUtc": "2026-03-11T08:30:00Z"
            }
        }
    }
    host_record = [
        {
            "lastSeen": "2026-03-11T09:00:00Z",
            "riskScore": "Medium",
            "computerDnsName": "host2.contoso.com",
            "healthStatus": "Misconfigured",
            "lastIpAddress": "10.0.0.20",
            "lastExternalIpAddress": "5.6.7.8",
            "osPlatform": "Windows10"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value=context)
    mocker.patch.object(script, "execute_command", return_value=host_record)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    result = return_results_mock.call_args[0][0]

    assert "Hostname: host2.contoso.com" in result
    assert "MDE Risk Score: 🟡 Medium" in result
    assert "MDE Status: 🟡 Misconfigured" in result
    assert "Last XSIAM Action: 🟢 Unisolate (UTC: 2026-03-11T08:30:00Z)" in result
    assert "OS: Windows10" in result


def test_main_returns_none_when_machine_action_missing(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-789"
        }
    }
    context = {}
    host_record = [
        {
            "lastSeen": "2026-03-12T09:00:00Z",
            "riskScore": "Low",
            "computerDnsName": "host3.contoso.com",
            "healthStatus": "Inactive",
            "lastIpAddress": "10.0.0.30",
            "lastExternalIpAddress": "9.9.9.9",
            "osPlatform": "Linux"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value=context)
    mocker.patch.object(script, "execute_command", return_value=host_record)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    result = return_results_mock.call_args[0][0]

    assert "Hostname: host3.contoso.com" in result
    assert "MDE Risk Score: 🟢 Low" in result
    assert "MDE Status: 🔴 Inactive" in result
    assert "Last XSIAM Action: None" in result
    assert "OS: Linux" in result


def test_main_returns_informational_risk_score(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-321"
        }
    }
    context = {}
    host_record = [
        {
            "lastSeen": "2026-03-12T10:00:00Z",
            "riskScore": "Informational",
            "computerDnsName": "host4.contoso.com",
            "healthStatus": "UnknownState",
            "lastIpAddress": "10.0.0.40",
            "lastExternalIpAddress": "8.8.8.8",
            "osPlatform": "macOS"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value=context)
    mocker.patch.object(script, "execute_command", return_value=host_record)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    result = return_results_mock.call_args[0][0]

    assert "MDE Risk Score: 🔵 Informational" in result
    assert "MDE Status: 🟤 Unknown or Offline" in result


def test_main_returns_unknown_risk_score_when_unexpected(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-654"
        }
    }
    context = {}
    host_record = [
        {
            "lastSeen": "2026-03-12T11:00:00Z",
            "riskScore": "Critical",
            "computerDnsName": "host5.contoso.com",
            "healthStatus": "Active",
            "lastIpAddress": "10.0.0.50",
            "lastExternalIpAddress": "7.7.7.7",
            "osPlatform": "WindowsServer"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value=context)
    mocker.patch.object(script, "execute_command", return_value=host_record)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    result = return_results_mock.call_args[0][0]

    assert "MDE Risk Score: 🟤 Unknown or None" in result


def test_main_returns_error_when_agentid_missing(mocker):
    alert = {
        "CustomFields": {}
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value={})
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host status" in result
    assert "Exception thrown" in result


def test_main_returns_error_when_execute_command_fails(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-123"
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value={})
    mocker.patch.object(
        script,
        "execute_command",
        side_effect=Exception("integration failure")
    )
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host status" in result
    assert "integration failure" in result


def test_main_returns_error_when_host_record_empty(mocker):
    alert = {
        "CustomFields": {
            "agentid": "machine-123"
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script.demisto, "context", return_value={})
    mocker.patch.object(script, "execute_command", return_value=[])
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host status" in result
    assert "Exception thrown" in result