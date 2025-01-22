import json
import pytest
import demistomock as demisto  # noqa: F401


from GatewatcherAlertEngine import gatewatcherAlertEngine


@pytest.mark.parametrize(
    "module_name, module_data, expected_keys",
    [
        (
            "malcore",
            {
                "event": {"module": "malcore"},
                "malcore": {
                    "detail_threat_found": "some_threat",
                    "engines_last_update_date": "2025-01-01",
                    "magic_details": "PE32 executable",
                    "state": "infected",
                    "total_found": "2"
                },
            },
            [
                "malcore.detail_threat_found",
                "malcore.engines_last_update_date",
                "malcore.magic_details",
                "malcore.state",
                "malcore.total_found"
            ]
        ),
        (
            "shellcode_detect",
            {
                "event": {"module": "shellcode_detect"},
                "shellcode": {
                    "encodings": "base64,utf-8",
                    "sub_type": "embedded_shellcode"
                },
            },
            [
                "shellcode.encodings",
                "shellcode.sub_type"
            ]
        ),
        (
            "malicious_powershell_detect",
            {
                "event": {"module": "malicious_powershell_detect"},
                "malicious_powershell": {
                    "proba_obfuscated": "0.85",
                    "score": "HIGH"
                },
            },
            [
                "malicious_powershell.proba_obfuscated",
                "malicious_powershell.score"
            ]
        ),
        (
            "sigflow_alert",
            {
                "event": {"module": "sigflow_alert"},
                "sigflow": {
                    "action": "block",
                    "category": "intrusion",
                    "payload": "encrypted_payload",
                    "payload_printable": "some_printable_format"
                },
            },
            [
                "sigflow.action",
                "sigflow.category",
                "sigflow.payload",
                "sigflow.payload_printable"
            ]
        ),
        (
            "dga_detect",
            {
                "event": {"module": "dga_detect"},
                "dga": {
                    "dga_count": "10",
                    "dga_ratio": "0.75",
                    "malware_behavior_confidence": "HIGH",
                    "nx_domain_count": "5",
                    "top_DGA": "some_domain"
                },
            },
            [
                "dga.dga_count",
                "dga.dga_ratio",
                "dga.malware_behavior_confidence",
                "dga.nx_domain_count",
                "dga.top_DGA"
            ]
        ),
        (
            "ioc",
            {
                "event": {"module": "ioc"},
                "ioc": {
                    "campaigns": ["Campaign A"],
                    "case_id": "12345",
                    "categories": ["Category1", "Category2"],
                    "creation_date": "2025-01-10",
                    "description": "Some IOC description",
                    "external_links": ["http://external-link"],
                    "families": ["Family1"],
                    "kill_chain_phases": ["Phase1"],
                    "meta_data": {"extra": "info"},
                    "package_date": "2025-01-11",
                    "relations": [],
                    "signature": "Some Signature",
                    "tags": ["Tag1"],
                    "targeted_countries": ["Country1"],
                    "targeted_organizations": ["Org1"],
                    "targeted_platforms": ["Windows"],
                    "targeted_sectors": ["Sector1"],
                    "threat_actor": "ActorX",
                    "tlp": "GREEN",
                    "ttp": ["TTP1"],
                    "type": "Malware",
                    "updated_date": "2025-01-12",
                    "usage_mode": "Detection",
                    "value": "Some IOC value",
                    "vulnerabilities": ["CVE-2021-1234"]
                },
            },
            [
                "ioc.campaigns",
                "ioc.case_id",
                "ioc.categories",
                "ioc.creation_date",
                "ioc.description",
                "ioc.external_links",
                "ioc.families",
                "ioc.kill_chain_phases",
                "ioc.meta_data",
                "ioc.package_date",
                "ioc.relations",
                "ioc.signature",
                "ioc.tags",
                "ioc.targeted_countries",
                "ioc.targeted_organizations",
                "ioc.targeted_platforms",
                "ioc.targeted_sectors",
                "ioc.threat_actor",
                "ioc.tlp",
                "ioc.ttp",
                "ioc.type",
                "ioc.updated_date",
                "ioc.usage_mode",
                "ioc.value",
                "ioc.vulnerabilities"
            ]
        ),
        (
            "ransomware_detect",
            {
                "event": {"module": "ransomware_detect"},
                "ransomware": {
                    "alert_threshold": "critical",
                    "malicious_behavior_confidence": "HIGH",
                    "session_score": "95"
                },
            },
            [
                "ransomware.alert_threshold",
                "ransomware.malicious_behavior_confidence",
                "ransomware.session_score"
            ]
        ),
        (
            "beacon_detect",
            {
                "event": {"module": "beacon_detect"},
                "beacon": {
                    "active": "true",
                    "hostname_resolution": "resolved_host",
                    "id": "beacon123",
                    "mean_time_interval": "30s",
                    "possible_cnc": "some_address",
                    "session_count": "4",
                    "type": "HTTP"
                },
            },
            [
                "beacon.active",
                "beacon.hostname_resolution",
                "beacon.id",
                "beacon.mean_time_interval",
                "beacon.possible_cnc",
                "beacon.session_count",
                "beacon.type"
            ]
        ),
    ]
)
def test_gatewatcherAlertEngine(mocker, monkeypatch, module_name, module_data, expected_keys):
    """
    GIVEN a mock incident with a GatewatcherRawEvent for a specific module type
    WHEN gatewatcherAlertEngine is invoked
    THEN verify the returned raw_response contains the expected module-specific fields
    """

    # Mock demisto.incident() to return our test data
    mock_incident = {
        'CustomFields': {
            'GatewatcherRawEvent': json.dumps(module_data)
        }
    }

    mocker.patch.object(demisto, 'incident', return_value=mock_incident)

    # WHEN
    result = gatewatcherAlertEngine()

    # THEN
    assert result.raw_response is not None, "Expected a non-empty raw_response dictionary."
    for key in expected_keys:
        assert key in result.raw_response, f"Missing expected key '{key}' in raw_response."
