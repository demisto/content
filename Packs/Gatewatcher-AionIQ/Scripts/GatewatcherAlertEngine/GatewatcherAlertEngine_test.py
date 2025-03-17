import json
import pytest
import demistomock as demisto  # noqa: F401


from GatewatcherAlertEngine import gatewatcherAlertEngine


@pytest.mark.parametrize(
    "module_name, module_data, expected_keys",
    [
        (
            "active_cti",
            {
                "event": {"module": "active_cti"},
                "dns": {
                    "query": [{"type": "query"}]
                },
                "flow": {
                    "bytes_toclient": 0,
                    "bytes_toserver": 0,
                    "pkts_toclient": 0,
                    "pkts_toserver": 0,
                    "start": "2025-03-06"
                },
                "sigflow": {
                    "action": "allowed",
                    "category": "cat",
                    "gid": 0,
                    "metadata": {"created_at": ["2025"]},
                    "payload": "payload",
                    "payload_printable": "`...[^'payload_printable",
                    "rev": 0,
                    "signature": "sign",
                    "signature_id": 0,
                    "stream": 0
                }
            },
            [
                "dns.query",
                "flow.bytes_toclient",
                "flow.bytes_toserver",
                "flow.pkts_toclient",
                "flow.pkts_toserver",
                "flow.start",
                "sigflow.action",
                "sigflow.category",
                "sigflow.gid",
                "sigflow.metadata",
                "sigflow.payload",
                "sigflow.payload_printable",
                "sigflow.rev",
                "sigflow.signature",
                "sigflow.signature_id",
                "sigflow.stream"
            ]
        ),
        (
            "malcore",
            {
                "event": {"module": "malcore"},
                "malcore": {
                    "analyzed_clean": 0,
                    "analyzed_error": 0,
                    "analyzed_infected": 0,
                    "analyzed_other": 0,
                    "analyzed_suspicious": 0,
                    "analyzers_up": 0,
                    "code": 0,
                    "detail_scan_time": 0,
                    "detail_threat_found": "some_threat",
                    "detail_wait_time": 0,
                    "engine_id": {"0": {"scan_result": "INFECTED", "threat_details": "threat", "id": "abd12"}},
                    "engines_last_update_date": "2025-01-01",
                    "file_type": "type",
                    "file_type_description": "descr",
                    "magic_details": "PE32 executable",
                    "processing_time": 0,
                    "reporting_token": "token",
                    "state": "Infected",
                    "total_found": "2/16"
                },
            },
            [
                "malcore.analyzed_clean",
                "malcore.analyzed_error",
                "malcore.analyzed_infected",
                "malcore.analyzed_other",
                "malcore.analyzed_suspicious",
                "malcore.analyzers_up",
                "malcore.code",
                "malcore.detail_scan_time",
                "malcore.detail_threat_found",
                "malcore.detail_wait_time",
                "malcore.engine_id",
                "malcore.engines_last_update_date",
                "malcore.file_type",
                "malcore.file_type_description",
                "malcore.magic_details",
                "malcore.processing_time",
                "malcore.reporting_token",
                "malcore.state",
                "malcore.total_found"
            ]
        ),
        (
            "malcore_retroanalyzer",
            {
                "event": {"module": "malcore_retroanalyzer"},
                "malcore_retroanalyzer": {
                    "analyzed_clean": 0,
                    "analyzed_error": 0,
                    "analyzed_infected": 0,
                    "analyzed_other": 0,
                    "analyzed_suspicious": 0,
                    "analyzers_up": 0,
                    "code": 0,
                    "detail_scan_time": 0,
                    "detail_threat_found": "some_threat",
                    "detail_wait_time": 0,
                    "engine_id": {"0": {"scan_result": "INFECTED", "threat_details": "threat", "id": "abd12"}},
                    "engines_last_update_date": "2025-01-01",
                    "file_type": "type",
                    "file_type_description": "descr",
                    "magic_details": "PE32 executable",
                    "processing_time": 0,
                    "reporting_token": "token",
                    "state": "Infected",
                    "total_found": "2/16"
                },
            },
            [
                "malcore_retroanalyzer.analyzed_clean",
                "malcore_retroanalyzer.analyzed_error",
                "malcore_retroanalyzer.analyzed_infected",
                "malcore_retroanalyzer.analyzed_other",
                "malcore_retroanalyzer.analyzed_suspicious",
                "malcore_retroanalyzer.analyzers_up",
                "malcore_retroanalyzer.code",
                "malcore_retroanalyzer.detail_scan_time",
                "malcore_retroanalyzer.detail_threat_found",
                "malcore_retroanalyzer.detail_wait_time",
                "malcore_retroanalyzer.engine_id",
                "malcore_retroanalyzer.engines_last_update_date",
                "malcore_retroanalyzer.file_type",
                "malcore_retroanalyzer.file_type_description",
                "malcore_retroanalyzer.magic_details",
                "malcore_retroanalyzer.processing_time",
                "malcore_retroanalyzer.reporting_token",
                "malcore_retroanalyzer.state",
                "malcore_retroanalyzer.total_found"
            ]
        ),
        (
            "shellcode_detect",
            {
                "event": {"module": "shellcode_detect"},
                "shellcode": {
                    "analysis": [{"call": "call", "args": "argv", "_id": 0, "ret": "0xdeadbeef"}],
                    "encodings": [{"name": "b64", "count": 0}],
                    "id": "avezv-5654-greb",
                    "sample_id": "sample",
                    "sub_type": "embedded_shellcode"
                },
            },
            [
                "shellcode.analysis",
                "shellcode.encodings",
                "shellcode.id",
                "shellcode.sample_id",
                "shellcode.sub_type"
            ]
        ),
        (
            "malicious_powershell_detect",
            {
                "event": {"module": "malicious_powershell_detect"},
                "malicious_powershell": {
                    "id": "abcdef",
                    "proba_obfuscated": 1,
                    "sample_id": "sample",
                    "score": 0,
                    "score_details": {"test": 0}
                },
            },
            [
                "malicious_powershell.id",
                "malicious_powershell.proba_obfuscated",
                "malicious_powershell.sample_id",
                "malicious_powershell.score",
                "malicious_powershell.score_details"
            ]
        ),
        (
            "sigflow_alert",
            {
                "event": {"module": "sigflow_alert"},
                "sigflow": {
                    "action": "allowed",
                    "category": "cat",
                    "gid": 0,
                    "metadata": {"created_at": ["2025"]},
                    "payload": "payload",
                    "payload_printable": "`...[^'payload_printable",
                    "rev": 0,
                    "signature": "sign",
                    "signature_id": 0,
                    "stream": 0
                },
            },
            [
                "sigflow.action",
                "sigflow.category",
                "sigflow.gid",
                "sigflow.metadata",
                "sigflow.payload",
                "sigflow.payload_printable",
                "sigflow.rev",
                "sigflow.signature",
                "sigflow.signature_id",
                "sigflow.stream"
            ]
        ),
        (
            "dga_detect",
            {
                "event": {"module": "dga_detect"},
                "dga": {
                    "dga_count": 10,
                    "dga_ratio": 0.75,
                    "malware_behavior_confidence": 50,
                    "nx_domain_count": 5,
                    "top_DGA": ["a.fr"]
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
                    "id": "id",
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
                "ioc.id",
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
                    "alert_threshold": 0,
                    "malicious_behavior_confidence": 0,
                    "session_score": 0
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
                    "mean_time_interval": 0,
                    "possible_cnc": "some_address",
                    "session_count": 4,
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
        (
            "retrohunt",
            {
                "event": {"module": "retrohunt"},
                "ioc": {
                    "campaigns": ["Campaign A"],
                    "case_id": "12345",
                    "categories": ["Category1", "Category2"],
                    "creation_date": "2025-01-10",
                    "description": "Some IOC description",
                    "external_links": ["http://external-link"],
                    "families": ["Family1"],
                    "id": "id",
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
                "matched_event": {
                    "content": {"event": {"id": "id123"}},
                    "id": "id123"
                }
            },
            [
                "ioc.campaigns",
                "ioc.case_id",
                "ioc.categories",
                "ioc.creation_date",
                "ioc.description",
                "ioc.external_links",
                "ioc.families",
                "ioc.id",
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
                "ioc.vulnerabilities",
                "matched_event.content",
                "matched_event.id"
            ]
        )
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
