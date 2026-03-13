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


class EntryFormat:
    HTML = "html"


def return_results(x):
    return x


common.EntryType = EntryType
common.EntryFormat = EntryFormat
common.return_results = return_results

sys.modules["CommonServerPython"] = common

import displayCrowdStrikeEvidencexsiam as script


def test_maybe_parse_json_with_dict_string():
    value = '{"aid":"12345","hostname":"test-host"}'

    result = script._maybe_parse_json(value)

    assert result == {"aid": "12345", "hostname": "test-host"}


def test_maybe_parse_json_with_plain_string():
    value = "not json"

    result = script._maybe_parse_json(value)

    assert result == "not json"


def test_find_vendor_raw_from_customfields_rawevent():
    parsed_alert = {
        "CustomFields": {
            "rawevent": {
                "aid": "abc123",
                "hostname": "endpoint1"
            }
        }
    }

    raw_blob, where = script._find_vendor_raw(parsed_alert)

    assert raw_blob == {"aid": "abc123", "hostname": "endpoint1"}
    assert where == "CustomFields.rawevent"


def test_find_vendor_raw_from_root_original_event():
    parsed_alert = {
        "original_event": {
            "field": "value"
        }
    }

    raw_blob, where = script._find_vendor_raw(parsed_alert)

    assert raw_blob == {"field": "value"}
    assert where == "root.original_event"


def test_find_vendor_raw_not_found():
    parsed_alert = {
        "foo": "bar",
        "CustomFields": {}
    }

    raw_blob, where = script._find_vendor_raw(parsed_alert)

    assert raw_blob is None
    assert where == "not found"


def test_parse_alert_with_valid_rawjson_string():
    alert = {
        "rawJSON": '{"CustomFields":{"rawevent":{"aid":"123"}}}'
    }

    result = script._parse_alert(alert)

    assert result == {
        "CustomFields": {
            "rawevent": {
                "aid": "123"
            }
        }
    }


def test_parse_alert_with_invalid_rawjson_string():
    alert = {
        "rawJSON": "this is not valid json"
    }

    result = script._parse_alert(alert)

    assert result == {"rawJSON": "this is not valid json"}


def test_parse_alert_with_rawjson_dict():
    alert = {
        "rawJSON": {
            "CustomFields": {
                "rawevent": {"aid": "123"}
            }
        }
    }

    result = script._parse_alert(alert)

    assert result == {
        "CustomFields": {
            "rawevent": {"aid": "123"}
        }
    }


def test_render_alert_html_with_vendor_raw_dict():
    alert = {
        "rawJSON": json.dumps({
            "CustomFields": {
                "rawevent": {
                    "aid": "123",
                    "hostname": "host1"
                }
            }
        })
    }

    result = script.render_alert_html(alert)

    assert result["Type"] == script.EntryType.NOTE
    assert result["ContentsFormat"] == script.EntryFormat.HTML
    assert "aid" in result["Contents"]
    assert "123" in result["Contents"]
    assert "hostname" in result["Contents"]
    assert "host1" in result["Contents"]


def test_render_alert_html_with_vendor_raw_json_string():
    alert = {
        "rawJSON": json.dumps({
            "CustomFields": {
                "rawevent": '{"sha256":"abc","user_name":"scott"}'
            }
        })
    }

    result = script.render_alert_html(alert)

    assert result["Type"] == script.EntryType.NOTE
    assert result["ContentsFormat"] == script.EntryFormat.HTML
    assert "sha256" in result["Contents"]
    assert "abc" in result["Contents"]
    assert "user_name" in result["Contents"]
    assert "scott" in result["Contents"]


def test_render_alert_html_falls_back_to_parsed_alert_when_vendor_raw_missing():
    alert = {
        "rawJSON": json.dumps({
            "AlertID": "A-100",
            "Severity": "High",
            "CustomFields": {}
        })
    }

    result = script.render_alert_html(alert)

    assert result["Type"] == script.EntryType.NOTE
    assert result["ContentsFormat"] == script.EntryFormat.HTML
    assert "AlertID" in result["Contents"]
    assert "A-100" in result["Contents"]
    assert "Severity" in result["Contents"]
    assert "High" in result["Contents"]


def test_main_calls_return_results(mocker):
    alert = {
        "rawJSON": json.dumps({
            "CustomFields": {
                "rawevent": {
                    "aid": "123",
                    "hostname": "host1"
                }
            }
        })
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]
    assert result["Type"] == script.EntryType.NOTE
    assert result["ContentsFormat"] == script.EntryFormat.HTML
    assert "aid" in result["Contents"]
    assert "123" in result["Contents"]