import sys
import types
import json

# ---- Mock XSOAR runtime modules before importing the script ----

demisto_mock = types.SimpleNamespace()
demisto_mock.alert = lambda: {}
demisto_mock.error = lambda x: None

sys.modules["demistomock"] = demisto_mock

common = types.ModuleType("CommonServerPython")


def return_results(x):
    return x


common.return_results = return_results

sys.modules["CommonServerPython"] = common

import displayDefenderEvidencexsiam as script


def test_main_returns_dict_directly(mocker):
    alert = {
        "CustomFields": {
            "microsoftgraphsecurityalertevidence": {
                "deviceId": "abc123",
                "userAccount": "scott",
                "riskScore": "high"
            }
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once_with({
        "deviceId": "abc123",
        "userAccount": "scott",
        "riskScore": "high"
    })


def test_main_parses_json_string(mocker):
    alert = {
        "CustomFields": {
            "microsoftgraphsecurityalertevidence": json.dumps({
                "deviceId": "xyz789",
                "fileName": "bad.exe",
                "severity": "medium"
            })
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once_with({
        "deviceId": "xyz789",
        "fileName": "bad.exe",
        "severity": "medium"
    })


def test_main_returns_error_when_customfields_missing(mocker):
    alert = {}

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There seems to be an issue rendering this field" in result
    assert "microsoftgraphsecurityalertevidence" in result
    assert "Exception thrown by script" in result


def test_main_returns_error_when_key_missing(mocker):
    alert = {
        "CustomFields": {}
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There seems to be an issue rendering this field" in result
    assert "microsoftgraphsecurityalertevidence" in result
    assert "Exception thrown by script" in result


def test_main_returns_error_when_json_invalid(mocker):
    alert = {
        "CustomFields": {
            "microsoftgraphsecurityalertevidence": "{not-valid-json}"
        }
    }

    mocker.patch.object(script.demisto, "alert", return_value=alert)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There seems to be an issue rendering this field" in result
    assert "Exception thrown by script" in result


def test_main_returns_error_when_alert_is_none(mocker):
    mocker.patch.object(script.demisto, "alert", return_value=None)
    return_results_mock = mocker.patch.object(script, "return_results")

    script.main()

    return_results_mock.assert_called_once()
    result = return_results_mock.call_args[0][0]

    assert "There seems to be an issue rendering this field" in result
    assert "Exception thrown by script" in result