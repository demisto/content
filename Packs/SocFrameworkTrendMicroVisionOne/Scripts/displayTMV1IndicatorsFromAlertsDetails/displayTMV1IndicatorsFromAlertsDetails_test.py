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

import displayTMV1IndicatorsFromAlertsDetails as script


def test_safe_json_loads_with_list():
    value = [{"id": "1", "type": "ip"}]

    result = script.safe_json_loads(value)

    assert result == [{"id": "1", "type": "ip"}]


def test_safe_json_loads_with_json_string():
    value = '[{"id":"1","type":"ip"}]'

    result = script.safe_json_loads(value)

    assert result == [{"id": "1", "type": "ip"}]


def test_safe_json_loads_with_invalid_json():
    value = "{not-json}"

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
        "id": "wb-456",
        "impact_scope": {
            "entities": [{"id": "entity-1"}]
        }
    }

    assert script.looks_like_alert_obj(obj) is True


def test_looks_like_alert_obj_false_when_missing_id():
    obj = {
        "indicators": [{"id": "1"}]
    }

    assert script.looks_like_alert_obj(obj) is False


def test_find_alert_in_context_finds_nested_alert():
    ctx = {
        "VisionOne.Alert_Details(val.etag && val.etag == obj.etag)": {
            "alert": {
                "id": "wb-123",
                "indicators": [{"id": "1", "type": "ip"}]
            }
        }
    }

    result = script.find_alert_in_context(ctx)

    assert result == {
        "id": "wb-123",
        "indicators": [{"id": "1", "type": "ip"}]
    }


def test_find_indicators_payload_from_incident_customfields_json(mocker):
    incident = {
        "CustomFields": {
            "trendmicrovisiononexdrindicatorsjson": '[{"id":"1","type":"ip","value":"1.2.3.4"}]'
        }
    }

    mocker.patch.object(script.demisto, "incident", return_value=incident)

    indicators, source = script.find_indicators_payload({})

    assert indicators == [{"id": "1", "type": "ip", "value": "1.2.3.4"}]
    assert source == "incident.CustomFields.trendmicrovisiononexdrindicatorsjson"


def test_find_indicators_payload_from_incident_top_level(mocker):
    incident = {
        "trendmicrovisiononexdrindicators": '[{"id":"2","type":"domain","value":"bad.com"}]'
    }

    mocker.patch.object(script.demisto, "incident", return_value=incident)

    indicators, source = script.find_indicators_payload({})

    assert indicators == [{"id": "2", "type": "domain", "value": "bad.com"}]
    assert source == "incident.trendmicrovisiononexdrindicators"


def test_find_indicators_payload_from_context(mocker):
    mocker.patch.object(script.demisto, "incident", return_value={})
    ctx = {
        "some": {
            "nested": {
                "indicators_json": '[{"id":"3","type":"host","value":"host1"}]'
            }
        }
    }

    indicators, source = script.find_indicators_payload(ctx)

    assert indicators == [{"id": "3", "type": "host", "value": "host1"}]
    assert source == "context.indicators_json"


def test_normalize_indicator_with_scalar_value():
    ind = {
        "id": "1",
        "type": "domain",
        "field": "dst.domain",
        "value": "bad.com",
        "related_entities": ["entity-1"],
        "provenance": ["vision-one"],
        "filter_ids": ["f-1"]
    }

    result = script.normalize_indicator(ind)

    assert result["ID"] == "1"
    assert result["Type"] == "domain"
    assert result["Field"] == "dst.domain"
    assert result["Value"] == "bad.com"
    assert result["Related Entities"] == "entity-1"
    assert result["Provenance"] == "vision-one"
    assert result["Filter IDs"] == "f-1"


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


def test_make_table_with_rows():
    headers = ["ID", "Type"]
    rows = [{"ID": "1", "Type": "ip"}]

    result = script.make_table(headers, rows)

    assert "|ID|Type|" in result
    assert "|1|ip|" in result


def test_main_outputs_no_indicators_message_when_none_found(mocker):
    mocker.patch.object(script.demisto, "context", return_value={})
    mocker.patch.object(script.demisto, "incident", return_value={})
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]
    assert result["ContentsFormat"] == "markdown"
    assert "Couldn’t locate indicators" in result["Contents"]


def test_main_outputs_no_indicators_when_payload_empty(mocker):
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
    assert "No indicators were returned on this alert." in result["Contents"]
    assert "incident.CustomFields.trendmicrovisiononexdrindicatorsjson" in result["Contents"]


def test_main_outputs_markdown_from_incident_customfields(mocker):
    ctx = {}
    incident = {
        "CustomFields": {
            "trendmicrovisiononexdrindicatorsjson": """
            [
              {"id":"1","type":"ip","field":"src.ip","value":"1.2.3.4","related_entities":["endpoint-1"],"provenance":["vision-one"],"filter_ids":["f1"]},
              {"id":"2","type":"domain","field":"dns.question.name","value":"bad.com","related_entities":["endpoint-2"],"provenance":["vision-one"],"filter_ids":["f2"]}
            ]
            """,
            "originalalertid": "wb-123"
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]

    assert result["ContentsFormat"] == "markdown"
    assert "Trend Micro Vision One — Indicators" in result["Contents"]
    assert "**Workbench ID:** `wb-123`" in result["Contents"]
    assert "**Total Indicators:** 2" in result["Contents"]
    assert "#### Domain" in result["Contents"]
    assert "#### Ip" in result["Contents"]
    assert "bad.com" in result["Contents"]
    assert "1.2.3.4" in result["Contents"]


def test_main_falls_back_to_alert_in_context(mocker):
    ctx = {
        "some_nested_key": {
            "alert": {
                "id": "wb-999",
                "indicators": [
                    {
                        "id": "9",
                        "type": "command_line",
                        "field": "process.command_line",
                        "value": "powershell -enc abc"
                    }
                ]
            }
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value={})
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    result = results_mock.call_args[0][0]
    assert "**Workbench ID:** `wb-999`" in result["Contents"]
    assert "**Source:** `context.alert.indicators`" in result["Contents"]
    assert "#### Command Line" in result["Contents"]
    assert "powershell -enc abc" in result["Contents"]