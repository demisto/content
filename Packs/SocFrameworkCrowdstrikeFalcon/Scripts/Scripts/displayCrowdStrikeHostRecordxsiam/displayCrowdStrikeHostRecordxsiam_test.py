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

import displayCrowdStrikeHostRecordxsiam as script


def test_fmt_status_normal():
    assert script._fmt_status("normal") == "🟢 Online"


def test_fmt_status_contained():
    assert script._fmt_status("contained") == "🔴 Contained"


def test_fmt_status_unknown():
    assert script._fmt_status("something-else") == "🟤 Unknown or Offline"


def test_maybe_json_with_dict_string():
    value = '{"aid":"12345","hostname":"test-host"}'

    result = script._maybe_json(value)

    assert result == {"aid": "12345", "hostname": "test-host"}


def test_maybe_json_with_plain_string():
    value = "not json"

    result = script._maybe_json(value)

    assert result == "not json"


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


def test_extract_resources_from_top_level_dict():
    res = {
        "resources": [
            {"device_id": "abc", "status": "normal"}
        ]
    }

    resources, how = script._extract_resources(res)

    assert resources == [{"device_id": "abc", "status": "normal"}]
    assert how == "resources from top-level dict"


def test_extract_resources_from_contents_dict():
    res = {
        "Contents": {
            "resources": [
                {"device_id": "abc", "status": "normal"}
            ]
        }
    }

    resources, how = script._extract_resources(res)

    assert resources == [{"device_id": "abc", "status": "normal"}]
    assert how == "resources from Contents"


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


def test_host_with_derived_fields_adds_status_pretty():
    host = {
        "device_id": "abc",
        "status": "contained"
    }

    result = script._host_with_derived_fields(host)

    assert result["device_id"] == "abc"
    assert result["status"] == "contained"
    assert result["status_pretty"] == "🔴 Contained"


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


def test_main_renders_host_record_html(mocker):
    alert = {
        "CustomFields": {
            "agentid": "aid-123"
        }
    }
    res = {
        "resources": [
            {
                "device_id": "aid-123",
                "hostname": "host1",
                "status": "normal"
            }
        ]
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    mocker.patch.object(script, "execute_command", return_value=res)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert result["Type"] == script.EntryType.NOTE
    assert result["ContentsFormat"] == script.EntryFormat.HTML
    assert "device_id" in result["Contents"]
    assert "aid-123" in result["Contents"]
    assert "hostname" in result["Contents"]
    assert "host1" in result["Contents"]
    assert "status_pretty" in result["Contents"]
    assert "🟢 Online" in result["Contents"]


def test_main_uses_alternate_agent_id_field(mocker):
    alert = {
        "CustomFields": {
            "agent_id": "aid-456"
        }
    }
    res = {
        "resources": [
            {
                "device_id": "aid-456",
                "status": "contained"
            }
        ]
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    execute_command_mock = mocker.patch.object(script, "execute_command", return_value=res)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    execute_command_mock.assert_called_once_with("cs-falcon-search-device", {"ids": "aid-456"})
    return_results_mock.assert_called_once()


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

    assert "There has been an issue gathering host information" in result
    assert "kaboom" in result