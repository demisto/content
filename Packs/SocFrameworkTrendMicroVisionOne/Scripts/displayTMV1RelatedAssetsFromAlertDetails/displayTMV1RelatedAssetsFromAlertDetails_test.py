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

import displayTMV1RelatedAssetsFromAlertDetails as script


def test_looks_like_alert_obj_with_impact_scope_entities():
    obj = {
        "id": "wb-123",
        "impact_scope": {
            "entities": [{"entity_id": "e1"}]
        }
    }

    assert script.looks_like_alert_obj(obj) is True


def test_looks_like_alert_obj_with_indicators():
    obj = {
        "id": "wb-123",
        "indicators": [{"id": "1"}]
    }

    assert script.looks_like_alert_obj(obj) is True


def test_looks_like_alert_obj_false_without_id():
    obj = {
        "impact_scope": {
            "entities": [{"entity_id": "e1"}]
        }
    }

    assert script.looks_like_alert_obj(obj) is False


def test_find_alert_in_context_finds_nested_alert():
    ctx = {
        "nested": {
            "alert": {
                "id": "wb-123",
                "impact_scope": {
                    "entities": [{"entity_id": "host-1", "entity_type": "host"}]
                }
            }
        }
    }

    result = script.find_alert_in_context(ctx)

    assert result["id"] == "wb-123"
    assert result["impact_scope"]["entities"][0]["entity_id"] == "host-1"


def test_norm_host_entity():
    entity = {
        "entity_type": "host",
        "entity_value": {
            "name": "server1",
            "ips": ["10.0.0.10", "1.2.3.4"],
            "guid": "guid-123"
        },
        "provenance": ["vision-one"],
        "related_entities": ["acct-1"]
    }

    result = script.norm_host_entity(entity)

    assert result == {
        "GUID": "guid-123",
        "Name": "server1",
        "IPs": "10.0.0.10, 1.2.3.4",
        "Provenance": "vision-one",
        "Related Entities": "acct-1",
    }


def test_norm_account_entity():
    entity = {
        "entity_type": "account",
        "entity_value": "alice",
        "provenance": ["vision-one"],
        "related_entities": ["host-1"]
    }

    result = script.norm_account_entity(entity)

    assert result == {
        "Account": "alice",
        "Provenance": "vision-one",
        "Related Entities": "host-1",
    }


def test_norm_generic_entity_with_dict_value():
    entity = {
        "entity_type": "ip",
        "entity_id": "ip-1",
        "entity_value": {
            "address": "1.2.3.4",
            "namespace": "public"
        },
        "provenance": ["vision-one"],
        "related_entities": ["host-1"]
    }

    result = script.norm_generic_entity(entity)

    assert result["Entity ID"] == "ip-1"
    assert "address=1.2.3.4" in result["Value"]
    assert "namespace=public" in result["Value"]
    assert result["Provenance"] == "vision-one"
    assert result["Related Entities"] == "host-1"


def test_build_relationship_map():
    entities = [
        {
            "entity_id": "host-1",
            "entity_type": "host",
            "entity_value": {
                "name": "server1",
                "guid": "guid-123"
            },
            "related_entities": []
        },
        {
            "entity_id": "acct-1",
            "entity_type": "account",
            "entity_value": "alice",
            "related_entities": ["host-1"]
        }
    ]

    result = script.build_relationship_map(entities)

    assert result == [
        "- account alice → **server1**"
    ]


def test_build_fallback_assets_from_cf():
    cf = {
        "agent_id": "agent-123",
        "agent_hostname": "host1",
        "action_local_ip": "10.0.0.10",
        "mac": "aa:bb:cc:dd:ee:ff",
        "actor_effective_username": "scott",
        "userid": "u-123",
        "agent_device_domain": "corp.local",
        "action_remote_ip": "8.8.8.8",
    }

    hosts, accounts, misc = script.build_fallback_assets_from_cf(cf)

    assert hosts == [
        {
            "GUID": "agent-123",
            "Name": "host1",
            "IPs": "10.0.0.10",
            "Provenance": "Correlation Rule",
            "Related Entities": "",
        }
    ]
    assert accounts == [
        {
            "Account": "scott (id=u-123)",
            "Provenance": "Correlation Rule",
            "Related Entities": "",
        }
    ]
    assert {"Key": "MAC", "Value": "aa:bb:cc:dd:ee:ff"} in misc
    assert {"Key": "Domain", "Value": "corp.local"} in misc
    assert {"Key": "Remote IP", "Value": "8.8.8.8"} in misc


def test_main_outputs_context_alert_with_entities(mocker):
    ctx = {
        "some_nested_key": {
            "alert": {
                "id": "wb-999",
                "impact_scope": {
                    "entities": [
                        {
                            "entity_id": "host-1",
                            "entity_type": "host",
                            "entity_value": {
                                "name": "server1",
                                "ips": ["10.0.0.10"],
                                "guid": "guid-123"
                            },
                            "provenance": ["vision-one"],
                            "related_entities": []
                        },
                        {
                            "entity_id": "acct-1",
                            "entity_type": "account",
                            "entity_value": "alice",
                            "provenance": ["vision-one"],
                            "related_entities": ["host-1"]
                        },
                        {
                            "entity_id": "ip-1",
                            "entity_type": "ip",
                            "entity_value": {
                                "address": "1.2.3.4"
                            },
                            "provenance": ["vision-one"],
                            "related_entities": ["host-1"]
                        }
                    ]
                }
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
    assert "### Trend Micro Vision One — Related Assets" in result["Contents"]
    assert "**Mode:** `context-alert`" in result["Contents"]
    assert "**Workbench ID:** `wb-999`" in result["Contents"]
    assert "**By Type:** host: 1, account: 1, ip: 1" in result["Contents"]
    assert "#### Hosts" in result["Contents"]
    assert "server1" in result["Contents"]
    assert "guid-123" in result["Contents"]
    assert "#### Accounts" in result["Contents"]
    assert "alice" in result["Contents"]
    assert "#### Ip" in result["Contents"]
    assert "address=1.2.3.4" in result["Contents"]
    assert "#### Relationships" in result["Contents"]
    assert "- account alice → **server1**" in result["Contents"]


def test_main_outputs_context_alert_no_entities(mocker):
    ctx = {
        "nested": {
            "alert": {
                "id": "wb-100",
                "impact_scope": {
                    "entities": []
                }
            }
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value={})
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    result = results_mock.call_args[0][0]
    assert "**Mode:** `context-alert`" in result["Contents"]
    assert "**Workbench ID:** `wb-100`" in result["Contents"]
    assert "_No related assets present in impact scope._" in result["Contents"]


def test_main_outputs_rule_mapped_fallback(mocker):
    ctx = {}
    incident = {
        "CustomFields": {
            "originalalertid": "wb-200",
            "agent_id": "agent-123",
            "agent_hostname": "host2",
            "action_local_ip": "10.0.0.20",
            "mac": "11:22:33:44:55:66",
            "actor_effective_username": "bob",
            "userid": "u-456",
            "agent_device_domain": "example.local",
            "action_remote_ip": "9.9.9.9",
        }
    }

    mocker.patch.object(script.demisto, "context", return_value=ctx)
    mocker.patch.object(script.demisto, "incident", return_value=incident)
    results_mock = mocker.patch.object(script.demisto, "results")

    script.main()

    results_mock.assert_called_once()
    result = results_mock.call_args[0][0]

    assert result["ContentsFormat"] == "markdown"
    assert "**Mode:** `rule-mapped`" in result["Contents"]
    assert "**Workbench ID:** `wb-200`" in result["Contents"]
    assert "_Note: impact_scope/entities not available; this is best-effort from correlation rule fields._" in result["Contents"]
    assert "#### Hosts" in result["Contents"]
    assert "agent-123" in result["Contents"]
    assert "host2" in result["Contents"]
    assert "10.0.0.20" in result["Contents"]
    assert "#### Accounts" in result["Contents"]
    assert "bob (id=u-456)" in result["Contents"]
    assert "#### Other" in result["Contents"]
    assert "11:22:33:44:55:66" in result["Contents"]
    assert "example.local" in result["Contents"]
    assert "9.9.9.9" in result["Contents"]


def test_main_outputs_rule_mapped_empty(mocker):
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
    assert "#### Hosts" in result["Contents"]
    assert "#### Accounts" in result["Contents"]
    assert "#### Other" in result["Contents"]
    assert "_none_" in result["Contents"]