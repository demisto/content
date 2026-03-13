import sys
import types
import json

# ---- Mock XSOAR runtime modules before importing the script ----

demisto_mock = types.SimpleNamespace()
demisto_mock.alert = lambda: {}
demisto_mock.error = lambda x: None

sys.modules["demistomock"] = demisto_mock

common = types.ModuleType("CommonServerPython")


class EntryType:
    NOTE = 1
    ERROR = 4


class EntryFormat:
    HTML = "html"


def return_results(x):
    return x


def execute_command(command, args):
    return []


common.EntryType = EntryType
common.EntryFormat = EntryFormat
common.return_results = return_results
common.execute_command = execute_command

sys.modules["CommonServerPython"] = common

import displayCrowdStrikeHostStatusxsiam as script


def test_fmt_status_normal():
    assert script._fmt_status("normal") == "🟢 Online"


def test_fmt_status_contained():
    assert script._fmt_status("contained") == "🔴 Contained"


def test_fmt_status_unknown():
    assert script._fmt_status("weird") == "🟤 Unknown or Offline"


def test_safe_get_returns_value():
    data = {"hostname": "host1"}

    result = script._safe_get(data, "hostname")

    assert result == "host1"


def test_safe_get_returns_default_for_missing():
    data = {}

    result = script._safe_get(data, "hostname", "unknown")

    assert result == "unknown"


def test_safe_get_returns_default_for_none():
    data = {"hostname": None}

    result = script._safe_get(data, "hostname", "unknown")

    assert result == "unknown"


def test_maybe_json_with_dict_string():
    value = '{"aid":"12345","hostname":"test-host"}'

    result = script._maybe_json(value)

    assert result == {"aid": "12345", "hostname": "test-host"}


def test_maybe_json_with_plain_string():
    value = "not json"

    result = script._maybe_json(value)

    assert result == "not json"


def test_extract_resources_from_top_level_dict():
    res = {
        "resources": [
            {"device_id": "abc", "status": "normal"}
        ]
    }

    resources, how = script._extract_resources(res)

    assert resources == [{"device_id": "abc", "status": "normal"}]
    assert how == "resources from top-level dict"


def test_extract_resources_from_contents_json_string():
    res = {
        "Contents": '{"resources":[{"device_id":"abc","status":"normal"}]}'
    }

    resources, how = script._extract_resources(res)

    assert resources == [{"device_id": "abc", "status": "normal"}]
    assert how == "resources from JSON string in Contents"


def test_extract_resources_returns_empty_when_not_found():
    res = {
        "Contents": {
            "foo": "bar"
        }
    }

    resources, how = script._extract_resources(res)

    assert resources == []
    assert "no resources" in how


def test_extract_error_message_from_error_entry():
    res = [
        {
            "Type": script.EntryType.ERROR,
            "Contents": "boom"
        }
    ]

    result = script._extract_error_message(res)

    assert result == "boom"


def test_extract_error_message_from_contents_error_dict():
    res = {
        "Contents": '{"error":"bad request"}'
    }

    result = script._extract_error_message(res)

    assert result == "bad request"


def test_main_returns_missing_agent_id_message(mocker):
    alert = {
        "CustomFields": {}
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once_with(
        "🟤 Missing agent id on the alert (CustomFields.agentid)."
    )


def test_main_returns_integration_error_message(mocker):
    alert = {
        "CustomFields": {
            "agentid": "aid-123"
        }
    }
    res = [
        {
            "Type": script.EntryType.ERROR,
            "Contents": "integration failure"
        }
    ]

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script, "execute_command", return_value=res)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once_with(
        "🔴 Error from cs-falcon-search-device: integration failure"
    )


def test_main_returns_no_host_found_message(mocker):
    alert = {
        "CustomFields": {
            "agentid": "aid-123"
        }
    }
    res = {
        "Contents": {
            "resources": []
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script, "execute_command", return_value=res)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once_with(
        "🟤 No host resource found for the provided agent id."
    )


def test_main_returns_host_status_snippet(mocker):
    alert = {
        "CustomFields": {
            "agentid": "aid-123"
        }
    }
    res = {
        "resources": [
            {
                "hostname": "host1",
                "status": "normal",
                "local_ip": "10.0.0.10",
                "external_ip": "1.2.3.4",
                "os_product_name": "Windows 11",
                "last_login_user": "scott"
            }
        ]
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script, "execute_command", return_value=res)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "Hostname: host1" in result
    assert "Status: 🟢 Online" in result
    assert "Current Local IP: 10.0.0.10" in result
    assert "Current External IP: 1.2.3.4" in result
    assert "OS: Windows 11" in result
    assert "Last Logged In User: scott" in result


def test_main_falls_back_to_os_version_and_last_logged_on_user(mocker):
    alert = {
        "CustomFields": {
            "agent_id": "aid-456"
        }
    }
    res = {
        "resources": [
            {
                "hostname": "host2",
                "status": "contained",
                "local_ip": "10.0.0.20",
                "external_ip": "5.6.7.8",
                "os_version": "macOS 14",
                "last_logged_on_user": "admin"
            }
        ]
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    execute_command_mock = mocker.patch.object(script, "execute_command", return_value=res)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    execute_command_mock.assert_called_once_with("cs-falcon-search-device", {"ids": "aid-456"})
    result = return_results_mock.call_args[0][0]

    assert "Hostname: host2" in result
    assert "Status: 🔴 Contained" in result
    assert "OS: macOS 14" in result
    assert "Last Logged In User: admin" in result


def test_main_handles_exception(mocker):
    alert = {
        "CustomFields": {
            "agentid": "aid-123"
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script, "execute_command", side_effect=Exception("kaboom"))
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There has been an issue gathering host status" in result
    assert "kaboom" in result