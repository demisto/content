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

import SOCNormalizeTrendMicroVisionOne as script


def test_get_incident_cf_returns_customfields(mocker):
    incident = {
        "CustomFields": {
            "agent_id": "agent-123",
            "actor_effective_username": "scott"
        }
    }

    mocker.patch.object(script.demisto, "incident", return_value=incident)

    result = script.get_incident_cf()

    assert result == {
        "agent_id": "agent-123",
        "actor_effective_username": "scott"
    }


def test_get_incident_cf_returns_empty_dict_when_missing(mocker):
    mocker.patch.object(script.demisto, "incident", return_value={})

    result = script.get_incident_cf()

    assert result == {}


def test_first_nonempty_str_returns_first_nonempty_string():
    result = script.first_nonempty_str(None, "", "   ", "hello", "world")

    assert result == "hello"


def test_first_nonempty_str_strips_whitespace():
    result = script.first_nonempty_str("   value   ", "other")

    assert result == "value"


def test_first_nonempty_str_returns_first_meaningful_non_string():
    result = script.first_nonempty_str(None, [], {}, 42, "fallback")

    assert result == 42


def test_first_nonempty_str_returns_none_when_all_empty():
    result = script.first_nonempty_str(None, "", "   ", [], {}, ())

    assert result is None


def test_find_alert_anywhere_returns_explicit_visionone_path():
    ctx = {
        "VisionOne": {
            "Alert_Details": {
                "alert": {
                    "id": "wb-123",
                    "severity": "high"
                }
            }
        }
    }

    result = script.find_alert_anywhere(ctx)

    assert result == {
        "id": "wb-123",
        "severity": "high"
    }


def test_find_alert_anywhere_returns_none_when_missing():
    ctx = {
        "VisionOne": {
            "Alert_Details": {}
        }
    }

    result = script.find_alert_anywhere(ctx)

    assert result is None


def test_build_alert_from_rule_fields_builds_full_alert_like_object():
    cf = {
        "originalalertid": "wb-999",
        "externallink": "https://visionone.example/alerts/wb-999",
        "alert_description": "Suspicious process detected",
        "agent_id": "agent-123",
        "agent_hostname": "host1",
        "action_local_ip": "10.0.0.10",
        "actor_effective_username": "alice",
        "userid": "u-123",
        "action_file_sha256": "sha256-value",
        "action_file_md5": "md5-value",
        "actor_process_command_line": "powershell -enc abc",
        "actor_process_image_path": "C:/Temp/bad.exe",
        "actor_process_image_name": "bad.exe",
        "action_remote_ip": "8.8.8.8",
        "agent_device_domain": "corp.local",
    }

    result = script.build_alert_from_rule_fields(cf)

    assert result["id"] == "wb-999"
    assert result["workbench_link"] == "https://visionone.example/alerts/wb-999"
    assert result["description"] == "Suspicious process detected"

    entities = result["impact_scope"]["entities"]
    assert len(entities) == 2

    assert entities[0] == {
        "entity_type": "host",
        "entity_value": {
            "guid": "agent-123",
            "name": "host1",
            "ips": ["10.0.0.10"]
        }
    }
    assert entities[1] == {
        "entity_type": "account",
        "entity_value": "alice"
    }

    indicators = result["indicators"]
    assert {"type": "file_sha256", "value": "sha256-value"} in indicators
    assert {"type": "file_md5", "value": "md5-value"} in indicators
    assert {"type": "command_line", "value": "powershell -enc abc"} in indicators
    assert {"type": "fullpath", "value": "C:/Temp/bad.exe"} in indicators
    assert {"type": "ip", "value": "8.8.8.8"} in indicators
    assert {"type": "domain", "value": "corp.local"} in indicators


def test_build_alert_from_rule_fields_uses_fallback_keys():
    cf = {
        "agent_id": "agent-456",
        "agent_hostname": "host2",
        "prenatsourceip": "10.0.0.20",
        "filehash": "sha256-fallback",
        "processmd5": "md5-fallback",
        "processcmd": "cmd.exe /c whoami",
        "action_file_path": "/tmp/evil.bin",
    }

    result = script.build_alert_from_rule_fields(cf)

    entities = result["impact_scope"]["entities"]
    assert entities == [
        {
            "entity_type": "host",
            "entity_value": {
                "guid": "agent-456",
                "name": "host2",
                "ips": ["10.0.0.20"]
            }
        }
    ]

    indicators = result["indicators"]
    assert {"type": "file_sha256", "value": "sha256-fallback"} in indicators
    assert {"type": "file_md5", "value": "md5-fallback"} in indicators
    assert {"type": "command_line", "value": "cmd.exe /c whoami"} in indicators
    assert {"type": "fullpath", "value": "/tmp/evil.bin"} in indicators


def test_build_alert_from_rule_fields_uses_filename_when_no_image_path():
    cf = {
        "actor_process_image_name": "onlyname.exe"
    }

    result = script.build_alert_from_rule_fields(cf)

    assert result["indicators"] == [
        {"type": "filename", "value": "onlyname.exe"}
    ]


def test_build_alert_from_rule_fields_does_not_add_filename_when_path_exists():
    cf = {
        "actor_process_image_name": "bad.exe",
        "actor_process_image_path": "C:/Temp/bad.exe"
    }

    result = script.build_alert_from_rule_fields(cf)

    assert {"type": "fullpath", "value": "C:/Temp/bad.exe"} in result["indicators"]
    assert {"type": "filename", "value": "bad.exe"} not in result["indicators"]


def test_build_alert_from_rule_fields_defaults_id_to_dash():
    cf = {}

    result = script.build_alert_from_rule_fields(cf)

    assert result["id"] == "—"
    assert result["workbench_link"] is None
    assert result["description"] is None
    assert result["impact_scope"]["entities"] == []
    assert result["indicators"] == []


def test_build_alert_from_rule_fields_builds_account_only_when_no_host():
    cf = {
        "actor_effective_username": "bob"
    }

    result = script.build_alert_from_rule_fields(cf)

    assert result["impact_scope"]["entities"] == [
        {
            "entity_type": "account",
            "entity_value": "bob"
        }
    ]