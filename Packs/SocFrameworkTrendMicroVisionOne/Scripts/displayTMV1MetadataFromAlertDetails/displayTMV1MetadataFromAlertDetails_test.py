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

import displayTMV1MetadataFromAlertDetails as script


def test_safe_json_loads_with_dict():
    value = {"a": 1}

    result = script.safe_json_loads(value)

    assert result == {"a": 1}


def test_safe_json_loads_with_json_string():
    value = '{"a": 1}'

    result = script.safe_json_loads(value)

    assert result == {"a": 1}


def test_safe_json_loads_with_invalid_json():
    value = "{not-json}"

    result = script.safe_json_loads(value)

    assert result is None


def test_looks_like_alert_obj_true_with_impact_scope():
    obj = {
        "id": "wb-123",
        "impact_scope": {"desktop_count": 1}
    }

    assert script.looks_like_alert_obj(obj) is True


def test_looks_like_alert_obj_true_with_indicators():
    obj = {
        "id": "wb-123",
        "indicators": [{"id": "1"}]
    }

    assert script.looks_like_alert_obj(obj) is True


def test_looks_like_alert_obj_false_without_id():
    obj = {
        "impact_scope": {"desktop_count": 1}
    }

    assert script.looks_like_alert_obj(obj) is False


def test_find_alert_and_meta_in_context_with_wrapped_alert():
    ctx = {
        "VisionOne.Alert_Details(val.etag && val.etag == obj.etag)": {
            "etag": "etag-1",
            "alert": {
                "id": "wb-123",
                "severity": "high",
                "impact_scope": {"desktop_count": 2}
            }
        }
    }

    alert, meta = script.find_alert_and_meta_in_context(ctx)

    assert alert["id"] == "wb-123"
    assert meta == {"etag": "etag-1"}


def test_find_alert_and_meta_in_context_with_direct_alert():
    ctx = {
        "nested": {
            "id": "wb-456",
            "indicators": [{"id": "1"}]
        }
    }

    alert, meta = script.find_alert_and_meta_in_context(ctx)

    assert alert["id"] == "wb-456"
    assert meta == {}


def test_make_kv_table_filters_empty_values():
    pairs = [
        ("A", "1"),
        ("B", ""),
        ("C", None),
        ("D", "2"),
    ]

    result = script.make_kv_table(pairs)

    assert "|A|1|" in result
    assert "|D|2|" in result
    assert "|B|" not in result
    assert "|C|" not in result


def test_summarize_impact_scope():
    iscope = {
        "desktop_count": 2,
        "server_count": 1,
        "entities": [{"id": "e1"}]
    }

    counts, entities = script.summarize_impact_scope(iscope)

    assert ("Desktop Count", 2) in counts
    assert ("Server Count", 1) in counts
    assert entities == [{"id": "e1"}]


def test_summarize_matched_rules():
    alert = {
        "matched_rules": [
            {
                "name": "Rule 1",
                "matched_filters": [
                    {
                        "name": "Filter A",
                        "matched_events": [{"matched_date_time": "2026-03-13T10:00:00Z"}],
                        "mitre_technique_ids": ["T1059", "T1110"]
                    }
                ]
            }
        ]
    }

    result = script.summarize_matched_rules(alert)

    assert result == [
        {
            "Rule": "Rule 1",
            "Filter": "Filter A",
            "When": "2026-03-13T10:00:00Z",
            "MITRE": "T1059, T1110",
        }
    ]


def test_get_first_nonempty():
    result = script.get_first_nonempty(None, "", [], "value", "other")

    assert result == "value"


def test_count_indicators_from_cf():
    cf = {
        "trendmicrovisiononexdrindicatorsjson": '[{"id":"1"},{"id":"2"}]'
    }

    result = script.count_indicators_from_cf(cf)

    assert result == 2


def test_main_outputs_rule_mapped_mode(mocker):
    ctx = {}
    incident = {
        "CustomFields": {
            "originalalertid": "wb-100",
            "externallink": "https://visionone.example/alerts/wb-100",
            "originalalertsource": "Trend Micro Vision One",
            "originalalertname": "Suspicious Process",
            "severity": "high",
            "trendmicrovisiononexdrpriorityscore": "85",
            "externalstatus": "open",
            "trendmicrovisiononexdrinvestigationstatus": "new",
            "source_insert_ts": "2026-03-13T12:00:00Z",
            "trendmicrovisiononexdrindicatorsjson": '[{"id":"1"},{"id":"2"},{"id":"3"}]'
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]

    assert result["ContentsFormat"] == "markdown"
    assert "### Trend Micro Vision One — Metadata" in result["Contents"]
    assert "**Mode:** `rule-mapped`" in result["Contents"]
    assert "**Workbench ID:** `wb-100`" in result["Contents"]
    assert "https://visionone.example/alerts/wb-100" in result["Contents"]
    assert "|Provider|Trend Micro Vision One|" in result["Contents"]
    assert "|Model|Suspicious Process|" in result["Contents"]
    assert "|Severity|high|" in result["Contents"]
    assert "|Score|85|" in result["Contents"]
    assert "|Indicators (count)|3|" in result["Contents"]
    assert "|Status|open|" in result["Contents"]
    assert "|Investigation Status|new|" in result["Contents"]
    assert "|Created|2026-03-13T12:00:00Z|" in result["Contents"]
    assert "_none (impact_scope not available in rule-mapped mode)_" in result["Contents"]
    assert "_none (matched_rules not available in rule-mapped mode)_" in result["Contents"]


def test_main_outputs_context_alert_mode(mocker):
    ctx = {
        "some_nested_key": {
            "etag": "etag-99",
            "alert": {
                "id": "wb-999",
                "workbench_link": "https://visionone.example/alerts/wb-999",
                "alert_provider": "Vision One",
                "model": "Malware Detected",
                "model_type": "behavior",
                "model_id": "model-1",
                "severity": "critical",
                "score": 99,
                "schema_version": "1.0",
                "incident_id": "inc-1",
                "case_id": "case-1",
                "owner_ids": ["user-1", "user-2"],
                "status": "open",
                "investigation_status": "in_progress",
                "investigation_result": "malicious",
                "created_date_time": "2026-03-13T10:00:00Z",
                "updated_date_time": "2026-03-13T11:00:00Z",
                "first_investigated_date_time": "2026-03-13T10:30:00Z",
                "impact_scope": {
                    "desktop_count": 2,
                    "server_count": 1,
                    "entities": [{"id": "e1"}]
                },
                "matched_rules": [
                    {
                        "name": "Rule A",
                        "matched_filters": [
                            {
                                "name": "Filter 1",
                                "matched_events": [{"matched_date_time": "2026-03-13T10:05:00Z"}],
                                "mitre_technique_ids": ["T1059"]
                            }
                        ]
                    }
                ],
                "indicators": [{"id": "1"}, {"id": "2"}]
            }
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value={})
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]

    assert result["ContentsFormat"] == "markdown"
    assert "**Mode:** `context-alert`" in result["Contents"]
    assert "**Workbench ID:** `wb-999`" in result["Contents"]
    assert "|Provider|Vision One|" in result["Contents"]
    assert "|Model|Malware Detected|" in result["Contents"]
    assert "|Model Type|behavior|" in result["Contents"]
    assert "|Model ID|model-1|" in result["Contents"]
    assert "|Severity|critical|" in result["Contents"]
    assert "|Score|99|" in result["Contents"]
    assert "|Schema Version|1.0|" in result["Contents"]
    assert "|Incident ID|inc-1|" in result["Contents"]
    assert "|Case ID|case-1|" in result["Contents"]
    assert "|Owner IDs|user-1, user-2|" in result["Contents"]
    assert "|Indicators (count)|2|" in result["Contents"]
    assert "|ETag|etag-99|" in result["Contents"]
    assert "|Status|open|" in result["Contents"]
    assert "|Investigation Status|in_progress|" in result["Contents"]
    assert "|Investigation Result|malicious|" in result["Contents"]
    assert "|Created|2026-03-13T10:00:00Z|" in result["Contents"]
    assert "|Updated|2026-03-13T11:00:00Z|" in result["Contents"]
    assert "|First Investigated|2026-03-13T10:30:00Z|" in result["Contents"]
    assert "|Desktop Count|2|" in result["Contents"]
    assert "|Server Count|1|" in result["Contents"]
    assert "|Rule|Filter|When|MITRE|" in result["Contents"]
    assert "|Rule A|Filter 1|2026-03-13T10:05:00Z|T1059|" in result["Contents"]


def test_main_rule_mapped_defaults_when_fields_missing(mocker):
    ctx = {}
    incident = {
        "CustomFields": {}
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    result = results_mock.call_args[0][0]

    assert "**Mode:** `rule-mapped`" in result["Contents"]
    assert "**Workbench ID:** `—`" in result["Contents"]
    assert "|Provider|Trend Micro Vision One|" in result["Contents"]
    assert "|Indicators (count)|0|" in result["Contents"]