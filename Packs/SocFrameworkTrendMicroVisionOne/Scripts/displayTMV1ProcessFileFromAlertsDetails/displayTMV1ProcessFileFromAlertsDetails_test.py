import sys
import types

# ---- Mock XSOAR runtime modules before importing the script ----

demisto_mock = types.SimpleNamespace()
demisto_mock.context = lambda: {}
demisto_mock.incident = lambda: {}
demisto_mock.results = lambda x: x
demisto_mock.error = lambda x: None

sys.modules["demistomock"] = demisto_mock

common = types.ModuleType("CommonServerPython")
sys.modules["CommonServerPython"] = common

import displayTMV1ProcessFileFromAlertsDetails as script


def test_safe_json_loads_with_list():
    value = [{"id": "1", "type": "file_sha256"}]

    result = script.safe_json_loads(value)

    assert result == [{"id": "1", "type": "file_sha256"}]


def test_safe_json_loads_with_json_string():
    value = '[{"id":"1","type":"command_line"}]'

    result = script.safe_json_loads(value)

    assert result == [{"id": "1", "type": "command_line"}]


def test_safe_json_loads_with_invalid_json():
    value = "{bad-json}"

    result = script.safe_json_loads(value)

    assert result is None


def test_looks_like_alert_obj_with_indicators():
    obj = {
        "id": "wb-123",
        "indicators": [{"id": "1"}]
    }

    assert script.looks_like_alert_obj(obj) is True


def test_looks_like_alert_obj_with_impact_scope_entities():
    obj = {
        "id": "wb-123",
        "impact_scope": {
            "entities": [{"id": "e1"}]
        }
    }

    assert script.looks_like_alert_obj(obj) is True


def test_find_alert_in_context_finds_nested_alert():
    ctx = {
        "nested": {
            "alert": {
                "id": "wb-123",
                "indicators": [{"id": "1", "type": "command_line"}]
            }
        }
    }

    result = script.find_alert_in_context(ctx)

    assert result == {
        "id": "wb-123",
        "indicators": [{"id": "1", "type": "command_line"}]
    }


def test_find_indicators_payload_from_incident_customfields(mocker):
    incident = {
        "CustomFields": {
            "trendmicrovisiononexdrindicatorsjson": '[{"id":"1","type":"file_sha256","value":"abc"}]'
        }
    }

    mocker.patch.object(script.demisto, "incident", return_value=incident)

    indicators, source = script.find_indicators_payload({})

    assert indicators == [{"id": "1", "type": "file_sha256", "value": "abc"}]
    assert source == "incident.CustomFields.trendmicrovisiononexdrindicatorsjson"


def test_find_indicators_payload_from_context(mocker):
    mocker.patch.object(script.demisto, "incident", return_value={})
    ctx = {
        "some": {
            "nested": {
                "indicators_json": '[{"id":"2","type":"fullpath","value":"C:/Temp/bad.exe"}]'
            }
        }
    }

    indicators, source = script.find_indicators_payload(ctx)

    assert indicators == [{"id": "2", "type": "fullpath", "value": "C:/Temp/bad.exe"}]
    assert source == "context.indicators_json"


def test_normalize_indicator_with_scalar_value():
    ind = {
        "id": "1",
        "type": "command_line",
        "field": "process.command_line",
        "value": "powershell -enc abc",
        "related_entities": ["endpoint-1"],
        "provenance": ["vision-one"],
        "filter_ids": ["f1"]
    }

    result = script.normalize_indicator(ind)

    assert result["ID"] == "1"
    assert result["Type"] == "command_line"
    assert result["Field"] == "process.command_line"
    assert result["Value"] == "powershell -enc abc"
    assert result["Related Entities"] == "endpoint-1"
    assert result["Provenance"] == "vision-one"
    assert result["Filter IDs"] == "f1"


def test_normalize_indicator_with_dict_value():
    ind = {
        "id": "2",
        "type": "host",
        "value": {
            "name": "server1",
            "ips": ["10.0.0.10", "1.2.3.4"],
            "guid": "guid-123"
        }
    }

    result = script.normalize_indicator(ind)

    assert result["ID"] == "2"
    assert result["Type"] == "host"
    assert "name=server1" in result["Value"]
    assert "ips=[10.0.0.10, 1.2.3.4]" in result["Value"]
    assert "guid=guid-123" in result["Value"]


def test_extract_matched_process_events():
    alert = {
        "matched_rules": [
            {
                "name": "Rule A",
                "matched_filters": [
                    {
                        "name": "Filter 1",
                        "matched_events": [
                            {
                                "type": "PROCESS_CREATE",
                                "matched_date_time": "2026-03-13T10:05:00Z",
                                "uuid": "uuid-1"
                            },
                            {
                                "type": "NETWORK_CONNECTION",
                                "matched_date_time": "2026-03-13T10:06:00Z",
                                "uuid": "uuid-2"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    result = script.extract_matched_process_events(alert)

    assert result == [
        {
            "Time": "2026-03-13T10:05:00Z",
            "Type": "PROCESS_CREATE",
            "UUID": "uuid-1",
            "Filter": "Filter 1",
            "Rule": "Rule A",
        }
    ]


def test_main_outputs_error_when_nothing_found(mocker):
    mocker.patch.object(script.demisto, "context", return_value={})
    mocker.patch.object(script.demisto, "incident", return_value={})
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]

    assert result["ContentsFormat"] == "markdown"
    assert "Couldn’t locate a Vision One alert object in context" in result["Contents"]


def test_main_outputs_from_incident_mapped_indicators(mocker):
    ctx = {}
    incident = {
        "CustomFields": {
            "trendmicrovisiononexdrindicatorsjson": """
            [
              {"id":"1","type":"command_line","field":"process.command_line","value":"powershell -enc abc","related_entities":["endpoint-1"],"provenance":["vision-one"],"filter_ids":["f1"]},
              {"id":"2","type":"file_sha256","field":"processFileHash","value":"abcdef123456","related_entities":["endpoint-1"],"provenance":["vision-one"],"filter_ids":["f2"]},
              {"id":"3","type":"fullpath","field":"fullpath","value":"C:/Temp/bad.exe","related_entities":["endpoint-1"],"provenance":["vision-one"],"filter_ids":["f3"]}
            ]
            """
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]

    assert result["ContentsFormat"] == "markdown"
    assert "### Trend Micro Vision One — Process & File" in result["Contents"]
    assert "**Workbench ID:** `—`" in result["Contents"]
    assert "**Source:** `incident.CustomFields.trendmicrovisiononexdrindicatorsjson`" in result["Contents"]
    assert "**Command Lines**" in result["Contents"]
    assert "powershell -enc abc" in result["Contents"]
    assert "**Matched Process Events**" in result["Contents"]
    assert "_none (matched_rules not available in correlation-rule output)_" in result["Contents"]
    assert "**File Paths**" in result["Contents"]
    assert "C:/Temp/bad.exe" in result["Contents"]
    assert "**File Hashes**" in result["Contents"]
    assert "abcdef123456" in result["Contents"]


def test_main_outputs_from_context_alert_with_matched_rules(mocker):
    ctx = {
        "nested": {
            "alert": {
                "id": "wb-999",
                "indicators": [
                    {
                        "id": "1",
                        "type": "command_line",
                        "field": "process.command_line",
                        "value": "cmd.exe /c whoami",
                        "related_entities": ["endpoint-1"],
                        "provenance": ["vision-one"],
                        "filter_ids": ["f1"]
                    },
                    {
                        "id": "2",
                        "type": "file_sha256",
                        "field": "file.hash.sha256",
                        "value": "deadbeef",
                        "related_entities": ["endpoint-1"],
                        "provenance": ["vision-one"],
                        "filter_ids": ["f2"]
                    },
                    {
                        "id": "3",
                        "type": "fullpath",
                        "field": "fullpath",
                        "value": "/tmp/bad.bin",
                        "related_entities": ["endpoint-1"],
                        "provenance": ["vision-one"],
                        "filter_ids": ["f3"]
                    }
                ],
                "matched_rules": [
                    {
                        "name": "Rule A",
                        "matched_filters": [
                            {
                                "name": "Filter 1",
                                "matched_events": [
                                    {
                                        "type": "PROCESS_CREATE",
                                        "matched_date_time": "2026-03-13T10:05:00Z",
                                        "uuid": "uuid-1"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value={})
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]

    assert "**Workbench ID:** `wb-999`" in result["Contents"]
    assert "**Source:** `context.alert.indicators`" in result["Contents"]
    assert "cmd.exe /c whoami" in result["Contents"]
    assert "/tmp/bad.bin" in result["Contents"]
    assert "deadbeef" in result["Contents"]
    assert "|Time|Type|UUID|Filter|Rule|" in result["Contents"]
    assert "|2026-03-13T10:05:00Z|PROCESS_CREATE|uuid-1|Filter 1|Rule A|" in result["Contents"]


def test_main_outputs_empty_tables_when_indicators_empty(mocker):
    ctx = {}
    incident = {
        "CustomFields": {
            "trendmicrovisiononexdrindicatorsjson": "[]"
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    result = results_mock.call_args[0][0]

    assert "**Command Lines**" in result["Contents"]
    assert "**File Paths**" in result["Contents"]
    assert "**File Hashes**" in result["Contents"]
    assert "_none_" in result["Contents"]