from Stairwell import (
    Client,
    variant_discovery_command,
    file_enrichment_command,
    intake_preflight_and_upload,
    ai_triage_summarize_command,
    object_sightings_command,
    object_opinions_command,
    run_to_ground_generate_command,
    asn_get_whois_command,
    hostname_get_command,
    hostname_get_resolutions_command,
    hostname_batch_get_resolutions_command,
    ipaddress_get_command,
    ipaddress_lookup_cloud_provider_command,
    ipaddress_get_hostnames_resolving_to_ip_command,
    ipaddress_get_whois_command,
    utilities_get_cloud_ip_ranges_command,
    utilities_batch_canonicalize_hostnames_command,
    utilities_batch_compute_etld_plus_one_command,
    utilities_canonicalize_hostname_command,
    utilities_compute_etld_plus_one_command,
    utilities_batch_canonicalize_urls_command,
    utilities_canonicalize_url_command,
    yara_create_rule_command,
    yara_get_rule_command,
    yara_query_matches_command,
    asset_list_command,
    asset_create_command,
    asset_get_command,
    file_command,
    ip_command,
    domain_command,
    _mal_eval_score,
    _resolve_file_source,
    _parse_int_arg,
    _hash_sha256,
    _status_code,
    test_module as run_test_module,
    MAX_DOWNLOAD_BYTES,
    RETRY_COUNT,
)
import json
import os
import socket
import tempfile
import requests
import pytest
from unittest.mock import patch, MagicMock
from CommonServerPython import CommandResults, Common, DemistoException

API_KEY = "FAKEAPIKEY"
TEST_FILE_HASH = "e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d"
TEST_OBJECT_ID = "357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


test_client = Client(api_key=API_KEY, verify=False, proxy=False)


def test_variant_discovery_command_success(requests_mock):
    mock_response = util_load_json("test_data/variant_discovery_command_result.json")

    requests_mock.get("https://app.stairwell.com/v202112/variants/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results.outputs_prefix == "Stairwell.Variants"
    assert results.outputs_key_field == "sha256"
    assert results.outputs["sha256"] == TEST_FILE_HASH
    assert results.outputs["variants"] == mock_response["variants"]
    assert "File Variants Discovered" in results.readable_output


def test_variant_discovery_command_none(requests_mock):
    mock_response = util_load_json("test_data/variant_discovery_command_results_none.json")

    requests_mock.get("https://app.stairwell.com/v202112/variants/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results.readable_output == "No variants discovered for: " + TEST_FILE_HASH
    assert results.outputs is None


def test_variant_discovery_command_notfound(requests_mock):
    mock_response = util_load_json("test_data/variant_discovery_command_results_notfound.json")

    requests_mock.get("https://app.stairwell.com/v202112/variants/" + TEST_FILE_HASH, json=mock_response, status_code=500)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results.readable_output == f"File not found or no variants available: {TEST_FILE_HASH}"


def test_file_enrichment_command(requests_mock):
    mock_response = util_load_json("test_data/file_enrichment_command_result.json")

    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, json=mock_response)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results.outputs_prefix == "Stairwell.File_Details"
    assert results.outputs_key_field == "sha256"
    assert results.outputs["sha256"] == results.outputs["summary"]["sha256"]
    assert results.outputs["raw"] == mock_response
    assert results.readable_output.startswith("# Stairwell")
    assert results.readable_output.count("00ddbafe247c891eed36bd74f66f936b") == 1
    assert "Seen Assets: 0" in results.readable_output, "this fixture has no occurrences"
    assert results.outputs["summary"]["seen_assets_count"] == 0
    assert results.outputs["summary"]["seen_environments"] == []


def test_file_enrichment_command_counts_assets_per_environment(requests_mock):
    """The reputation API reports sightings as occurrences[].assets, one entry per environment."""
    mock_response = util_load_json("test_data/file_enrichment_command_result_multiple_occurrences.json")
    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, json=mock_response)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)

    summary = results.outputs["summary"]
    assert summary["seen_assets_count"] == 2
    assert [e["environment_name"] for e in summary["seen_environments"]] == ["Ida Bear Sandbox", "Ida Bear Sandbox2"]
    assert summary["seen_environments"][0] == {
        "environment_id": "2FPYDD-8LP9XU-VYQAAC-VTRF29MT",
        "environment_name": "Ida Bear Sandbox",
        "asset_count": 1,
        "assets": [{"id": "AD64SQ-C3VABC-8HJN6L-LF2CR999", "name": "WORKGROUP\\SW-MJW-CRD-1"}],
    }
    assert "Seen Assets: 2 across 2 environments: Ida Bear Sandbox(1), Ida Bear Sandbox2(1)" in results.readable_output


def test_file_enrichment_command_single_environment(requests_mock):
    mock_response = util_load_json("test_data/file_enrichment_command_result_multiple_occurrences.json")
    mock_response["data"]["attributes"]["occurrences"] = mock_response["data"]["attributes"]["occurrences"][:1]
    mock_response["data"]["attributes"]["occurrences"][0]["assets"].append({"id": "X", "name": "second-host"})
    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, json=mock_response)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)

    assert results.outputs["summary"]["seen_assets_count"] == 2
    assert "Seen Assets: 2 in Ida Bear Sandbox" in results.readable_output


def test_file_enrichment_command_notfound(requests_mock):
    mock_response = util_load_json("test_data/file_enrichment_command_result.json")

    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, json=mock_response, status_code=404)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results.readable_output == "File not found: " + TEST_FILE_HASH


# Intake Preflight and Upload Tests
TRIAGE_REPORT = (
    "**TL;DR:** Malicious Zruner trojan dropper.\n**MALICIOUS LIKELIHOOD:** 98%\n## IOCs\n* **Registry Keys:**\n"
    "  * HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n## Key Considerations\n* **Prevalence**: 1 asset\n"
)


def _triage_response(**overrides):
    """The /v1/objects/{id}:summarize response shape: tldr, the markdown report, and its structured form."""
    response = {
        "tldr": "Malicious Zruner trojan dropper.",
        "summary": TRIAGE_REPORT,
        "summaryJson": {
            "malicious_likelihood": 98,
            "confidence": 92,
            "threat_type": "Trojan Dropper",
            "tldr": "Malicious Zruner trojan dropper.",
            "summary": ["Point 1", "Point 2"],
            "iocs": {
                "urls": ["http://example.com"],
                "file_paths_filenames": ["test.exe"],
                "registry_keys": ["SOFTWARE\\Test"],
            },
        },
    }
    response.update(overrides)
    return response


def test_ai_triage_summarize_command_success(requests_mock):
    """The War Room shows the metrics and the markdown report, never a JSON dump."""
    mock_response = _triage_response()
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json=mock_response)

    results = ai_triage_summarize_command(test_client, TEST_OBJECT_ID)

    md = results.readable_output
    assert md.startswith(f"### Stairwell AI Triage: {TEST_OBJECT_ID}")
    assert "**TL;DR:** Malicious Zruner trojan dropper." in md
    assert "| 98% | 92% | Trojan Dropper |" in md
    assert "## Key Considerations\n* **Prevalence**: 1 asset" in md, "the report is passed through as markdown"
    assert md.count("TL;DR") == 1 and "MALICIOUS LIKELIHOOD" not in md, "the report's own header lines are dropped"
    assert md.index("## IOCs") > md.index("| 98% |")
    assert "summaryJson" not in md and "{" not in md, "no JSON in the War Room"
    assert results.outputs_key_field == "hash"
    assert results.outputs["hash"] == TEST_OBJECT_ID
    assert results.outputs["malicious_likelihood"] == 98
    assert results.outputs["confidence"] == 92
    assert results.outputs["threat_type"] == "Trojan Dropper"
    assert results.outputs["tldr"] == "Malicious Zruner trojan dropper."
    assert results.outputs["summary_points"] == ["Point 1", "Point 2"]
    assert results.outputs["iocs"]["registry_keys"] == ["SOFTWARE\\Test"]
    assert results.outputs["raw"] == mock_response
    assert results.raw_response == mock_response


def test_ai_triage_summarize_command_renders_structured_form_without_report(requests_mock):
    """With no markdown report, summaryJson is rendered section by section, known keys first, unknown keys after."""
    summary_json = {
        "malicious_likelihood": 99,
        "confidence": 95,
        "threat_type": "Backdoor",
        "tldr": "Suspicious executable",
        "summary": ["Point 1"],
        "iocs": {
            "urls": ["http://evil.com"],
            "file_paths_filenames": [f"file{i}.exe" for i in range(30)],
            "registry_keys": ["SOFTWARE\\Bad"],
            "ip_addresses": ["198.51.100.1", "203.0.113.1"],
            "other": [],
        },
        "key_considerations": {
            "prevalence": "Rare malware family",
            "api_analysis": "Uses suspicious Windows APIs",
            "entropy_analysis": "High entropy sections detected",
            "steganography": None,
        },
        "guidance_for_clarity_and_impact": {
            "persistence_mechanisms": ["Registry run key", "Scheduled task"],
            "obfuscation_or_evasion_techniques": ["Packing", "Anti-debug"],
        },
        "mitre_attack_mapping": [{"technique_id": "T1543.003", "name": "Windows Service"}],
        "some_new_field": "Future content",
    }
    requests_mock.get(
        f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize",
        json={"tldr": "Suspicious executable", "summaryJson": summary_json},
    )
    md = ai_triage_summarize_command(test_client, TEST_OBJECT_ID).readable_output

    assert "**TL;DR:** Suspicious executable" in md
    assert "| 99% | 95% | Backdoor |" in md
    headings = ("## Summary", "## Indicators of compromise", "## Key considerations", "## Guidance", "## MITRE ATT&CK mapping")
    order = [md.index(h) for h in headings + ("**Some new field:** Future content",)]
    assert order == sorted(order)
    assert "### URLs\n- http://evil.com" in md
    assert "### File paths and filenames" in md and "- file24.exe" in md and "- file25.exe" not in md
    assert "- … and 5 more" in md
    assert "### IP addresses\n- 198.51.100.1\n- 203.0.113.1" in md
    assert "Other" not in md and "Steganography" not in md, "empty values are not rendered"
    assert "**API analysis:** Uses suspicious Windows APIs" in md
    assert "### Persistence mechanisms\n- Registry run key\n- Scheduled task" in md
    assert "- **Technique id:** T1543.003; **Name:** Windows Service" in md
    assert "**Some new field:** Future content" in md
    assert "{" not in md


def test_ai_triage_summarize_command_tldr_only(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json={"tldr": "Just a line."})
    results = ai_triage_summarize_command(test_client, TEST_OBJECT_ID)
    assert "**TL;DR:** Just a line." in results.readable_output
    assert results.outputs["malicious_likelihood"] is None


def test_ai_triage_summarize_command_empty_response(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json={})
    results = ai_triage_summarize_command(test_client, TEST_OBJECT_ID)
    assert "No AI Triage summary is available" in results.readable_output
    assert results.outputs["hash"] == TEST_OBJECT_ID


def test_ai_triage_summarize_command_non_dict_response_raises(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json="unexpected string")
    with pytest.raises(DemistoException, match="Unexpected AI Triage response"):
        ai_triage_summarize_command(test_client, TEST_OBJECT_ID)


def test_ai_triage_summarize_command_notfound(requests_mock):
    """Test AI Triage summarize command with 404 error"""
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", status_code=404)

    results = ai_triage_summarize_command(test_client, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Object not found" in results.readable_output


def test_ai_triage_summarize_command_missing_args():
    """Test AI Triage summarize command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ai_triage_summarize_command(test_client, "")


# Object Sightings Tests
def test_object_sightings_command_success(requests_mock):
    """Test object sightings command with successful response"""
    mock_response = {"sightings": [{"asset": {"id": "asset-1", "name": "Test Asset"}, "timestamp": "2024-01-01T00:00:00Z"}]}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", json=mock_response)

    results = object_sightings_command(test_client, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Sightings"
    assert "sightings" in results.outputs


def test_object_sightings_command_no_sightings(requests_mock):
    """Test object sightings command with no sightings"""
    mock_response = {"sightings": []}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", json=mock_response)

    results = object_sightings_command(test_client, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "No sightings found" in results.readable_output


def test_object_sightings_command_missing_args():
    """Test object sightings command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        object_sightings_command(test_client, "")


# Object Opinions Tests
def test_object_opinions_command_success(requests_mock):
    """Test object opinions command with successful response"""
    mock_response = {"opinions": [{"source": "analyst", "verdict": "malicious", "confidence": 90}]}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", json=mock_response)

    results = object_opinions_command(test_client, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Opinions"
    assert "opinions" in results.outputs


def test_object_opinions_command_no_opinions(requests_mock):
    """Test object opinions command with no opinions"""
    mock_response = {"opinions": []}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", json=mock_response)

    results = object_opinions_command(test_client, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "No opinions found" in results.readable_output


def test_object_opinions_command_missing_args():
    """Test object opinions command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        object_opinions_command(test_client, "")


# Run-To-Ground Tests
def test_run_to_ground_generate_command_success(requests_mock):
    """Test run-to-ground generate command with successful response"""
    test_client_rtg = test_client

    mock_response = {"analysis": {"objects": [TEST_OBJECT_ID, TEST_FILE_HASH], "relationships": []}}

    object_ids = f"{TEST_OBJECT_ID},{TEST_FILE_HASH}"
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", json=mock_response, status_code=200)

    results = run_to_ground_generate_command(test_client_rtg, object_ids)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.RunToGround"
    assert "analysis" in results.outputs


def test_run_to_ground_generate_command_missing_args():
    """Test run-to-ground generate command with missing arguments"""
    test_client_rtg = test_client

    with pytest.raises(DemistoException, match="Missing required arguments"):
        run_to_ground_generate_command(test_client_rtg, "")


def test_run_to_ground_generate_command_multiple_objects(requests_mock):
    """Test run-to-ground generate command with multiple object IDs"""
    test_client_rtg = test_client

    mock_response = {"analysis": {"objects": [TEST_OBJECT_ID, TEST_FILE_HASH]}}

    object_ids = f"{TEST_OBJECT_ID}, {TEST_FILE_HASH} , another-hash"
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", json=mock_response)

    results = run_to_ground_generate_command(test_client_rtg, object_ids)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.RunToGround"


# Network Intel Tests - ASN
def test_asn_get_whois_command_success(requests_mock):
    """Test ASN get whois command with successful response"""
    mock_response = {"asn": "AS12345", "organization": "Test Organization", "country": "US"}

    requests_mock.get("https://app.stairwell.com/v2/asns/12345/whois", json=mock_response)

    results = asn_get_whois_command(test_client, "12345")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.ASN.WHOIS"
    assert results.outputs.get("asn") == "AS12345"


def test_asn_get_whois_command_notfound(requests_mock):
    """Test ASN get whois command with 404 error"""
    requests_mock.get("https://app.stairwell.com/v2/asns/99999/whois", status_code=404)

    results = asn_get_whois_command(test_client, "99999")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "ASN not found" in results.readable_output


def test_asn_get_whois_command_missing_args():
    """Test ASN get whois command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        asn_get_whois_command(test_client, "")


# Network Intel Tests - Hostname
def test_hostname_get_command_success(requests_mock):
    """Test hostname get command with successful response"""
    mock_response = {"hostname": "example.com", "resolutions": [{"ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"}]}

    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com", json=mock_response)

    results = hostname_get_command(test_client, "example.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname"
    assert results.outputs.get("hostname") == "example.com"


def test_hostname_get_command_notfound(requests_mock):
    """Test hostname get command with 404 error"""
    requests_mock.get("https://app.stairwell.com/v2/hostnames/nonexistent.com", status_code=404)

    results = hostname_get_command(test_client, "nonexistent.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Hostname not found" in results.readable_output


def test_hostname_get_resolutions_command_success(requests_mock):
    """Test hostname get resolutions command with successful response"""
    mock_response = {
        "resolutions": [
            {"ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"},
            {"ip": "5.6.7.8", "timestamp": "2024-01-02T00:00:00Z"},
        ]
    }

    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com/resolutions", json=mock_response)

    results = hostname_get_resolutions_command(test_client, "example.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.Resolutions"
    assert len(results.outputs.get("resolutions", [])) == 2


def test_hostname_batch_get_resolutions_command_success(requests_mock):
    """Test hostname batch get resolutions command with successful response"""
    mock_response = {"results": {"example.com": [{"ip": "1.2.3.4"}], "test.com": [{"ip": "5.6.7.8"}]}}

    requests_mock.post("https://app.stairwell.com/v2/hostnames:batch-resolutions", json=mock_response)

    results = hostname_batch_get_resolutions_command(test_client, "example.com,test.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.BatchResolutions"


# Network Intel Tests - IP Address
def test_ipaddress_get_command_success(requests_mock):
    """Test IP address get command with successful response"""
    mock_response = {"ip": "1.2.3.4", "country": "US", "asn": "AS12345"}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4", json=mock_response)

    results = ipaddress_get_command(test_client, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress"
    assert results.outputs.get("ip") == "1.2.3.4"


def test_ipaddress_lookup_cloud_provider_command_success(requests_mock):
    """Test IP address lookup cloud provider command with successful response"""
    mock_response = {"ip": "1.2.3.4", "cloud_provider": "AWS", "region": "us-east-1"}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/provider", json=mock_response)

    results = ipaddress_lookup_cloud_provider_command(test_client, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.CloudProvider"
    assert results.outputs.get("cloud_provider") == "AWS"


def test_ipaddress_get_hostnames_resolving_to_ip_command_success(requests_mock):
    """Test IP address get hostnames resolving to IP command with successful response"""
    mock_response = {"hostnames": ["example.com", "www.example.com"]}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/hostnames", json=mock_response)

    results = ipaddress_get_hostnames_resolving_to_ip_command(test_client, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.Hostnames"
    assert len(results.outputs.get("hostnames", [])) == 2


def test_ipaddress_get_whois_command_success(requests_mock):
    """Test IP address get whois command with successful response"""
    mock_response = {"ip": "1.2.3.4", "organization": "Test Org", "country": "US"}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/whois", json=mock_response)

    results = ipaddress_get_whois_command(test_client, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.WHOIS"
    assert results.outputs.get("ip") == "1.2.3.4"


# Network Intel Tests - Utilities
def test_utilities_get_cloud_ip_ranges_command_success(requests_mock):
    """Test utilities get cloud IP ranges command with successful response"""
    mock_response = {"ranges": [{"cidr": "192.0.2.0/24", "provider": "AWS"}, {"cidr": "198.51.100.0/24", "provider": "GCP"}]}

    requests_mock.get("https://app.stairwell.com/v2/providers/ip-ranges", json=mock_response)

    results = utilities_get_cloud_ip_ranges_command(test_client)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CloudIPRanges"
    assert len(results.outputs.get("ranges", [])) == 2


def test_utilities_batch_canonicalize_hostnames_command_success(requests_mock):
    """Test utilities batch canonicalize hostnames command with successful response"""
    mock_response = {"results": {"EXAMPLE.COM": "example.com", "WWW.TEST.COM": "www.test.com"}}

    requests_mock.post("https://app.stairwell.com/v2/utilities/hostnames:batch-canonicalize", json=mock_response)

    results = utilities_batch_canonicalize_hostnames_command(test_client, "EXAMPLE.COM,WWW.TEST.COM")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedHostnames"


def test_utilities_batch_compute_etld_plus_one_command_success(requests_mock):
    """Test utilities batch compute ETLD+1 command with successful response"""
    mock_response = {"results": {"subdomain.example.com": "example.com", "www.test.co.uk": "test.co.uk"}}

    requests_mock.post("https://app.stairwell.com/v2/utilities/hostnames:batch-etld-plus-one", json=mock_response)

    results = utilities_batch_compute_etld_plus_one_command(test_client, "subdomain.example.com,www.test.co.uk")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.ETLDPlusOne"


def test_utilities_canonicalize_hostname_command_success(requests_mock):
    """Test utilities canonicalize hostname command with successful response"""
    mock_response = {"original": "EXAMPLE.COM", "canonicalized": "example.com"}

    requests_mock.get("https://app.stairwell.com/v2/utilities/hostnames:canonicalize/EXAMPLE.COM", json=mock_response)

    results = utilities_canonicalize_hostname_command(test_client, "EXAMPLE.COM")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedHostname"
    assert results.outputs.get("canonicalized") == "example.com"


def test_utilities_compute_etld_plus_one_command_success(requests_mock):
    """Test utilities compute ETLD+1 command with successful response"""
    mock_response = {"domain": "subdomain.example.com", "etld_plus_one": "example.com"}

    requests_mock.get("https://app.stairwell.com/v2/utilities/hostnames:etld-plus-one/subdomain.example.com", json=mock_response)

    results = utilities_compute_etld_plus_one_command(test_client, "subdomain.example.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.ETLDPlusOne"
    assert results.outputs.get("etld_plus_one") == "example.com"


def test_utilities_batch_canonicalize_urls_command_success(requests_mock):
    """Test utilities batch canonicalize URLs command with successful response"""
    mock_response = {"results": {"HTTPS://EXAMPLE.COM/PATH": "https://example.com/path", "HTTP://TEST.COM/": "http://test.com/"}}

    requests_mock.post("https://app.stairwell.com/v2/utilities/urls:batch-canonicalize", json=mock_response)

    results = utilities_batch_canonicalize_urls_command(test_client, "HTTPS://EXAMPLE.COM/PATH,HTTP://TEST.COM/")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedURLs"


def test_utilities_canonicalize_url_command_success(requests_mock):
    """Test utilities canonicalize URL command with successful response"""
    mock_response = {"original": "HTTPS://EXAMPLE.COM/PATH", "canonicalized": "https://example.com/path"}

    requests_mock.get("https://app.stairwell.com/v2/utilities/urls:canonicalize", json=mock_response)

    results = utilities_canonicalize_url_command(test_client, "HTTPS://EXAMPLE.COM/PATH")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedURL"
    assert results.outputs.get("canonicalized") == "https://example.com/path"


# YARA Rules Tests
def test_yara_create_rule_command_success(requests_mock):
    """Test YARA create rule command with successful response"""
    TEST_ENV = "test-environment-id"
    mock_response = {
        "name": "environments/test-environment-id/yaraRules/rule-123",
        "definition": "rule simple_rule { condition: true }",
        "state": "ACTIVE",
    }

    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules", json=mock_response)

    results = yara_create_rule_command(test_client, TEST_ENV, "rule simple_rule { condition: true }")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.YaraRule"


def test_yara_create_rule_command_missing_args():
    """Test YARA create rule command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        yara_create_rule_command(test_client, "", "rule simple_rule { condition: true }")


def test_yara_get_rule_command_success(requests_mock):
    """Test YARA get rule command with successful response"""
    TEST_ENV = "test-environment-id"
    TEST_RULE = "rule-123"
    mock_response = {
        "name": f"environments/{TEST_ENV}/yaraRules/{TEST_RULE}",
        "definition": "rule simple_rule { condition: true }",
        "state": "ACTIVE",
        "matchCounts": {},
    }

    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}", json=mock_response)

    results = yara_get_rule_command(test_client, TEST_ENV, TEST_RULE)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.YaraRule"


def test_yara_get_rule_command_notfound(requests_mock):
    """Test YARA get rule command with 404 error"""
    TEST_ENV = "test-environment-id"
    TEST_RULE = "nonexistent-rule"

    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}", status_code=404)

    results = yara_get_rule_command(test_client, TEST_ENV, TEST_RULE)

    assert isinstance(results, CommandResults)
    assert results.readable_output


def test_yara_query_matches_command_success(requests_mock):
    """Test YARA query matches command with successful response"""
    TEST_ENV = "test-environment-id"
    TEST_RULE = "rule-123"
    mock_response = {
        "objects": [
            {"sha256": TEST_FILE_HASH, "md5": "abc123", "sha1": "def456"},
        ],
        "nextPageToken": "",
    }

    requests_mock.get(
        f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}/matchingObjects", json=mock_response
    )

    results = yara_query_matches_command(test_client, TEST_ENV, TEST_RULE)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.YaraRuleMatches"


# Asset Management Tests
def test_asset_list_command_success(requests_mock):
    """Test asset list command with successful response"""
    TEST_ENV = "test-environment-id"
    mock_response = {
        "assets": [
            {"name": "assets/VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6", "label": "test-endpoint"},
            {"name": "assets/XXXX-YYYY-ZZZZ", "label": "another-endpoint"},
        ]
    }

    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json=mock_response)

    results = asset_list_command(test_client, TEST_ENV)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Assets"


def test_asset_list_command_missing_args():
    """Test asset list command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        asset_list_command(test_client, "")


def test_asset_get_command_notfound(requests_mock):
    """Test asset get command with 404 error"""
    TEST_ASSET = "NONEXISTENT-ASSET-ID"

    requests_mock.get(f"https://app.stairwell.com/v1/assets/{TEST_ASSET}", status_code=404)

    results = asset_get_command(test_client, TEST_ASSET)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "not found" in results.readable_output.lower()


# ─────────────────────────────────────────────
# _parse_int_arg Tests
# ─────────────────────────────────────────────


def test_parse_int_arg_none():
    assert _parse_int_arg(None, "test") is None


def test_parse_int_arg_valid():
    assert _parse_int_arg("42", "pageSize") == 42


def test_parse_int_arg_negative_not_allowed():
    with pytest.raises(DemistoException):
        _parse_int_arg("-1", "pageSize")


def test_parse_int_arg_not_integer():
    with pytest.raises(DemistoException):
        _parse_int_arg("abc", "pageSize")


def test_parse_int_arg_negative_allowed():
    assert _parse_int_arg("-5", "offset", allow_negative=True) == -5


# ─────────────────────────────────────────────
# Missing Args Tests for Network Intel Commands
# ─────────────────────────────────────────────


def test_hostname_get_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        hostname_get_command(test_client, "")


def test_hostname_get_resolutions_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        hostname_get_resolutions_command(test_client, "")


def test_hostname_batch_get_resolutions_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        hostname_batch_get_resolutions_command(test_client, "")


def test_ipaddress_get_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_get_command(test_client, "")


def test_ipaddress_lookup_cloud_provider_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_lookup_cloud_provider_command(test_client, "")


def test_ipaddress_get_hostnames_resolving_to_ip_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_get_hostnames_resolving_to_ip_command(test_client, "")


def test_ipaddress_get_whois_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_get_whois_command(test_client, "")


def test_utilities_batch_canonicalize_hostnames_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_batch_canonicalize_hostnames_command(test_client, "")


def test_utilities_batch_compute_etld_plus_one_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_batch_compute_etld_plus_one_command(test_client, "")


def test_utilities_canonicalize_hostname_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_canonicalize_hostname_command(test_client, "")


def test_utilities_compute_etld_plus_one_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_compute_etld_plus_one_command(test_client, "")


def test_utilities_batch_canonicalize_urls_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_batch_canonicalize_urls_command(test_client, "")


def test_utilities_canonicalize_url_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_canonicalize_url_command(test_client, "")


# ─────────────────────────────────────────────
# YARA Command Error Paths
# ─────────────────────────────────────────────


def test_yara_create_rule_command_400(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules", status_code=400)
    results = yara_create_rule_command(test_client, TEST_ENV, "rule bad { }")
    assert "Invalid YARA rule" in results.readable_output


def test_yara_create_rule_command_403(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules", status_code=403)
    results = yara_create_rule_command(test_client, TEST_ENV, "rule x { condition: true }")
    assert "Permission denied" in results.readable_output


def test_yara_query_matches_command_no_results(requests_mock):
    TEST_ENV = "test-environment-id"
    TEST_RULE = "rule-123"
    requests_mock.get(
        f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}/matchingObjects",
        json={"objects": [], "nextPageToken": ""},
    )
    results = yara_query_matches_command(test_client, TEST_ENV, TEST_RULE)
    assert "No matches found" in results.readable_output


def test_yara_query_matches_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        yara_query_matches_command(test_client, "", "rule-123")


# ─────────────────────────────────────────────
# Asset Command Error Paths
# ─────────────────────────────────────────────


def test_asset_create_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        asset_create_command(test_client, "test-env", "")


def test_asset_list_command_no_assets(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json={"assets": []})
    results = asset_list_command(test_client, TEST_ENV)
    assert "No assets found" in results.readable_output


def test_asset_list_command_404(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=404)
    results = asset_list_command(test_client, TEST_ENV)
    assert "Environment not found" in results.readable_output


def test_asset_create_command_400(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=400)
    results = asset_create_command(test_client, TEST_ENV, "bad-label")
    assert "Invalid asset parameters" in results.readable_output


def test_asset_create_command_403(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=403)
    results = asset_create_command(test_client, TEST_ENV, "test-label")
    assert "Permission denied" in results.readable_output


def test_asset_create_command_409(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=409)
    results = asset_create_command(test_client, TEST_ENV, "duplicate-label")
    assert "already exist" in results.readable_output


# ─────────────────────────────────────────────
# Object Command Error Paths
# ─────────────────────────────────────────────


def test_object_sightings_command_404(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", status_code=404)
    results = object_sightings_command(test_client, TEST_OBJECT_ID)
    assert "Object not found" in results.readable_output


def test_object_opinions_command_404(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", status_code=404)
    results = object_opinions_command(test_client, TEST_OBJECT_ID)
    assert "Object not found" in results.readable_output


def test_ai_triage_summarize_command_400(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", status_code=400)
    results = ai_triage_summarize_command(test_client, TEST_OBJECT_ID)
    assert "Invalid request" in results.readable_output


def test_run_to_ground_generate_command_400(requests_mock):
    test_client_rtg = test_client
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", status_code=400)
    results = run_to_ground_generate_command(test_client_rtg, TEST_OBJECT_ID)
    assert "Invalid object IDs" in results.readable_output


def test_run_to_ground_generate_command_404(requests_mock):
    test_client_rtg = test_client
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", status_code=404)
    results = run_to_ground_generate_command(test_client_rtg, TEST_OBJECT_ID)
    assert "not found" in results.readable_output.lower()


# ─────────────────────────────────────────────
# Optional Parameter Coverage
# ─────────────────────────────────────────────


def test_hostname_get_command_with_record_type(requests_mock):
    mock_response = {"hostname": "example.com", "records": []}
    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com", json=mock_response)
    results = hostname_get_command(test_client, "example.com", record_type="A")
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname"


def test_hostname_get_resolutions_with_time_params(requests_mock):
    mock_response = {"resolutions": []}
    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com/resolutions", json=mock_response)
    results = hostname_get_resolutions_command(
        test_client,
        "example.com",
        start_time="2024-01-01T00:00:00Z",
        end_time="2024-12-31T00:00:00Z",
    )
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.Resolutions"


def test_ipaddress_get_hostnames_resolving_to_ip_with_time_params(requests_mock):
    mock_response = {"hostnames": ["example.com"]}
    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/hostnames", json=mock_response)
    results = ipaddress_get_hostnames_resolving_to_ip_command(
        test_client,
        "1.2.3.4",
        start_time="2024-01-01T00:00:00Z",
        end_time="2024-12-31T00:00:00Z",
    )
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.Hostnames"


def test_ipaddress_get_command_404(requests_mock):
    requests_mock.get("https://app.stairwell.com/v2/ips/9.9.9.9", status_code=404)
    results = ipaddress_get_command(test_client, "9.9.9.9")
    assert "IP address not found" in results.readable_output


def test_hostname_get_resolutions_command_404(requests_mock):
    requests_mock.get("https://app.stairwell.com/v2/hostnames/nonexistent.com/resolutions", status_code=404)
    results = hostname_get_resolutions_command(test_client, "nonexistent.com")
    assert isinstance(results, CommandResults)
    assert results.readable_output


def test_asn_get_whois_command_adds_asn_to_response(requests_mock):
    """Test ASN WHOIS when response lacks 'asn' key — code should inject it"""
    mock_response = {"organization": "Test Org"}  # no "asn" key
    requests_mock.get("https://app.stairwell.com/v2/asns/99/whois", json=mock_response)
    results = asn_get_whois_command(test_client, "99")
    assert results.outputs.get("asn") == "99"


def test_yara_get_rule_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        yara_get_rule_command(test_client, "", "rule-123")


# ─────────────────────────────────────────────
# Cloud IP Ranges — Exception Paths
# ─────────────────────────────────────────────


def test_utilities_get_cloud_ip_ranges_400():
    """Cloud IP ranges 400 error (invalid provider)"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("400 Bad Request")
    results = utilities_get_cloud_ip_ranges_command(mock_client, provider="invalid-provider")
    assert "Invalid provider parameter" in results.readable_output


def test_utilities_get_cloud_ip_ranges_400_no_provider():
    """Cloud IP ranges 400 error (no provider)"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("400 Bad Request")
    results = utilities_get_cloud_ip_ranges_command(mock_client)
    assert "Bad request" in results.readable_output


def test_utilities_get_cloud_ip_ranges_404():
    """Cloud IP ranges 404 error (provider not found)"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("404 Not Found")
    results = utilities_get_cloud_ip_ranges_command(mock_client, provider="FakeProvider")
    assert "not found" in results.readable_output.lower()


def test_utilities_get_cloud_ip_ranges_other_exception():
    """Cloud IP ranges unexpected error raises"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_get_cloud_ip_ranges_command(mock_client)


def test_utilities_get_cloud_ip_ranges_with_provider(requests_mock):
    """Cloud IP ranges with provider param exercises the provider branch"""
    mock_response = {"ranges": [{"cidr": "192.0.2.0/24", "provider": "AWS"}]}
    requests_mock.get("https://app.stairwell.com/v2/providers/AWS/ip-ranges", json=mock_response)
    results = utilities_get_cloud_ip_ranges_command(test_client, provider="AWS")
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "AWS" in results.readable_output


# ─────────────────────────────────────────────
# Utilities — Exception Re-raise Paths
# ─────────────────────────────────────────────


def test_utilities_batch_canonicalize_hostnames_400():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_hostnames.side_effect = DemistoException("400 Bad Request")
    results = utilities_batch_canonicalize_hostnames_command(mock_client, "bad..host,other")
    assert "Invalid hostname format" in results.readable_output


def test_utilities_batch_canonicalize_hostnames_other_exception():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_hostnames.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_batch_canonicalize_hostnames_command(mock_client, "example.com")


def test_utilities_batch_compute_etld_plus_one_400():
    mock_client = MagicMock()
    mock_client.batch_compute_etld_plus_one.side_effect = DemistoException("400 Bad Request")
    results = utilities_batch_compute_etld_plus_one_command(mock_client, "bad..domain")
    assert "Invalid domain format" in results.readable_output


def test_utilities_batch_compute_etld_plus_one_other_exception():
    mock_client = MagicMock()
    mock_client.batch_compute_etld_plus_one.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_batch_compute_etld_plus_one_command(mock_client, "example.com")


def test_utilities_canonicalize_hostname_400():
    mock_client = MagicMock()
    mock_client.canonicalize_hostname.side_effect = DemistoException("400 Bad Request")
    results = utilities_canonicalize_hostname_command(mock_client, "bad..host")
    assert "Invalid hostname format" in results.readable_output


def test_utilities_canonicalize_hostname_other_exception():
    mock_client = MagicMock()
    mock_client.canonicalize_hostname.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_canonicalize_hostname_command(mock_client, "example.com")


def test_utilities_compute_etld_plus_one_400():
    mock_client = MagicMock()
    mock_client.compute_etld_plus_one.side_effect = DemistoException("400 Bad Request")
    results = utilities_compute_etld_plus_one_command(mock_client, "bad..domain")
    assert "Invalid domain format" in results.readable_output


def test_utilities_compute_etld_plus_one_other_exception():
    mock_client = MagicMock()
    mock_client.compute_etld_plus_one.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_compute_etld_plus_one_command(mock_client, "example.com")


def test_utilities_batch_canonicalize_urls_400():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_urls.side_effect = DemistoException("400 Bad Request")
    results = utilities_batch_canonicalize_urls_command(mock_client, "not-a-url")
    assert "Invalid URL format" in results.readable_output


def test_utilities_batch_canonicalize_urls_other_exception():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_urls.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_batch_canonicalize_urls_command(mock_client, "https://example.com")


def test_utilities_canonicalize_url_400():
    mock_client = MagicMock()
    mock_client.canonicalize_url.side_effect = DemistoException("400 Bad Request")
    results = utilities_canonicalize_url_command(mock_client, "not-a-url")
    assert "Invalid URL format" in results.readable_output


def test_utilities_canonicalize_url_other_exception():
    mock_client = MagicMock()
    mock_client.canonicalize_url.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_canonicalize_url_command(mock_client, "https://example.com")


# ─────────────────────────────────────────────
# Network Intel — Non-404 Exception Re-raises
# ─────────────────────────────────────────────


def test_ipaddress_lookup_cloud_provider_non_404():
    mock_client = MagicMock()
    mock_client.lookup_cloud_provider.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        ipaddress_lookup_cloud_provider_command(mock_client, "1.2.3.4")


def test_ipaddress_get_hostnames_resolving_to_ip_non_404():
    mock_client = MagicMock()
    mock_client.get_hostnames_resolving_to_ip.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        ipaddress_get_hostnames_resolving_to_ip_command(mock_client, "1.2.3.4")


def test_ipaddress_get_whois_non_404():
    mock_client = MagicMock()
    mock_client.get_ip_address_whois.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        ipaddress_get_whois_command(mock_client, "1.2.3.4")


def test_hostname_batch_get_resolutions_raises():
    mock_client = MagicMock()
    mock_client.batch_get_hostname_resolutions.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        hostname_batch_get_resolutions_command(mock_client, "example.com")


# ─────────────────────────────────────────────
# Batch Hostname Resolutions — With Data
# ─────────────────────────────────────────────


def test_hostname_batch_get_resolutions_with_data(requests_mock):
    """Batch resolutions with actual resolution data exercises lines 1015-1023"""
    mock_response = {
        "resolutions": [
            {
                "reversedHostname": "com.example",
                "resolutions": [{"ipAddress": "93.184.216.34", "recordType": "A", "timestamp": "2024-01-01T00:00:00Z"}],
            }
        ]
    }
    requests_mock.post(
        "https://app.stairwell.com/v2/hostnames:batch-resolutions",
        json=mock_response,
    )
    results = hostname_batch_get_resolutions_command(test_client, "example.com")
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.BatchResolutions"


# ─────────────────────────────────────────────
# File Enrichment / Variant — Non-standard Exception Re-raises
# ─────────────────────────────────────────────


def test_file_enrichment_command_non_404():
    """file_enrichment_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.get_file_reputation.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        file_enrichment_command(mock_client, TEST_FILE_HASH)


def test_variant_discovery_command_non_500():
    """variant_discovery_command re-raises non-500 DemistoException"""
    mock_client = MagicMock()
    mock_client.get_file_variants.side_effect = DemistoException("403 Forbidden")
    with pytest.raises(DemistoException):
        variant_discovery_command(mock_client, TEST_FILE_HASH)


# ─────────────────────────────────────────────
# Asset / YARA — Non-404 Exception Re-raises
# ─────────────────────────────────────────────


def test_asset_list_command_non_404():
    """asset_list_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.list_assets.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        asset_list_command(mock_client, "test-env")


def test_asset_get_command_non_404():
    """asset_get_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.get_asset.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        asset_get_command(mock_client, "test-asset")


def test_yara_query_matches_command_non_404():
    """yara_query_matches_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.query_yara_matches.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        yara_query_matches_command(mock_client, "test-env", "test-rule")


# Status code helper tests
def test_status_code_prefers_response_object():
    """_status_code reads the attached response first."""
    err = DemistoException("Error in API call [404] - Not Found", res=MagicMock(status_code=500))
    assert _status_code(err) == 500


def test_status_code_falls_back_to_message_marker():
    """_status_code parses the [NNN] marker BaseClient writes when no response is attached."""
    assert _status_code(DemistoException("Error in API call [404] - Not Found")) == 404
    assert _status_code(DemistoException("500 Server Error")) == 500
    assert _status_code(DemistoException("Connection refused")) is None


def test_status_code_ignores_digits_in_hash():
    """A hash containing '404' must not be mistaken for a 404 response."""
    err = DemistoException("Error in API call [500] - object abc404def not found")
    assert _status_code(err) == 500


def test_file_enrichment_command_500_is_raised(requests_mock):
    """A real server error must surface as an error, not as 'File not found'."""
    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, status_code=500, text="hash 404abc")
    with pytest.raises(DemistoException):
        file_enrichment_command(test_client, TEST_FILE_HASH)


TEST_MODULE_REPUTATION = "https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH
TEST_MODULE_METADATA = "https://app.stairwell.com/v1/objects/" + TEST_FILE_HASH + "/metadata"


def test_test_module_ok(requests_mock):
    requests_mock.get(TEST_MODULE_REPUTATION, json={"data": {"attributes": {"sha256": "x"}}})
    requests_mock.get(TEST_MODULE_METADATA, json={"sha256": "x"})
    assert run_test_module(test_client) == "ok"
    assert len(requests_mock.request_history) == 2, "both API hosts are checked"


@pytest.mark.parametrize("status", [401, 403])
def test_test_module_key_refused_by_reputation_api(requests_mock, status):
    requests_mock.get(TEST_MODULE_REPUTATION, status_code=status)
    requests_mock.get(TEST_MODULE_METADATA, json={})
    assert run_test_module(test_client) == (
        "Authorization Error: the API key was refused by the reputation API. Check the key in Stairwell."
    )


def test_test_module_key_refused_by_main_api(requests_mock):
    """A key the reputation host accepts can still be refused by app.stairwell.com; Test must say so."""
    requests_mock.get(TEST_MODULE_REPUTATION, json={"data": {"attributes": {}}})
    requests_mock.get(TEST_MODULE_METADATA, status_code=401, json={"code": 16, "message": "Authentication required"})
    assert run_test_module(test_client) == (
        "Authorization Error: the API key was refused by the Stairwell API. Check the key in Stairwell."
    )


def test_test_module_sample_not_visible_is_still_ok(requests_mock):
    requests_mock.get(TEST_MODULE_REPUTATION, status_code=404)
    requests_mock.get(TEST_MODULE_METADATA, status_code=404)
    assert run_test_module(test_client) == "ok"


def test_test_module_connection_error(requests_mock):
    requests_mock.get(TEST_MODULE_REPUTATION, status_code=503)
    assert run_test_module(test_client).startswith("Connection Error (reputation API)")


# ─────────────────────────────────────────────
# _resolve_file_source Tests
# ─────────────────────────────────────────────


def test_resolve_file_source_no_source():
    with pytest.raises(DemistoException, match="Missing file source"):
        _resolve_file_source()


def test_resolve_file_source_multiple_sources():
    with pytest.raises(DemistoException, match="Multiple file sources"):
        _resolve_file_source(entry_id="1@2", url="https://example.com/f")


def test_resolve_file_source_entry_id_success(tmp_path):
    f = tmp_path / "f.exe"
    f.write_bytes(b"x")
    with patch("Stairwell.demisto.getFilePath", return_value={"path": str(f), "name": "f.exe"}):
        path, name, is_temp = _resolve_file_source(entry_id="123@4")
    assert path == str(f)
    assert name == "f.exe"
    assert is_temp is False


def test_resolve_file_source_entry_id_file_not_on_disk(tmp_path):
    with patch("Stairwell.demisto.getFilePath", return_value={"path": str(tmp_path / "missing.exe"), "name": "f.exe"}):
        with pytest.raises(DemistoException, match="file not found"):
            _resolve_file_source(entry_id="123@4")


@pytest.mark.parametrize("file_info", [{"name": "f.exe"}, "not a dict", None])
def test_resolve_file_source_entry_id_bad_response(file_info):
    with patch("Stairwell.demisto.getFilePath", return_value=file_info):
        with pytest.raises(DemistoException, match="no file path in response"):
            _resolve_file_source(entry_id="123@4")


def test_resolve_file_source_url_invalid_scheme():
    with pytest.raises(DemistoException, match="Invalid URL scheme"):
        _resolve_file_source(url="ftp://example.com/file.exe")


def test_resolve_file_source_url_no_host():
    with pytest.raises(DemistoException, match="no host"):
        _resolve_file_source(url="https:///file.exe")


def _addrinfo(*addresses):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addresses]


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0", "::1", "fd00::1", "224.0.0.1"],
)
def test_resolve_file_source_url_private_host_refused(address):
    """A playbook argument must not make the engine fetch from its own network or the metadata service."""
    with patch("Stairwell.socket.getaddrinfo", return_value=_addrinfo(address)):
        with pytest.raises(DemistoException, match="not a public address"):
            _resolve_file_source(url="https://files.example.com/file.exe")


def test_resolve_file_source_url_mixed_resolution_refused():
    """One private address among public ones is enough to refuse."""
    with patch("Stairwell.socket.getaddrinfo", return_value=_addrinfo("8.8.8.8", "10.0.0.1")):
        with pytest.raises(DemistoException, match="not a public address"):
            _resolve_file_source(url="https://files.example.com/file.exe")


def test_resolve_file_source_url_unresolvable():
    with patch("Stairwell.socket.getaddrinfo", side_effect=socket.gaierror("no such host")):
        with pytest.raises(DemistoException, match="Cannot resolve download host"):
            _resolve_file_source(url="https://files.example.com/file.exe")


@pytest.fixture
def public_host():
    with patch("Stairwell.socket.getaddrinfo", return_value=_addrinfo("8.8.8.8")):
        yield


def test_resolve_file_source_url_success(requests_mock, public_host):
    requests_mock.get("https://files.example.com/malware.exe", content=b"chunk1chunk2")
    path, name, is_temp = _resolve_file_source(url="https://files.example.com/malware.exe")
    try:
        assert name == "malware.exe"
        assert is_temp is True
        with open(path, "rb") as f:
            assert f.read() == b"chunk1chunk2"
    finally:
        os.unlink(path)


def test_resolve_file_source_url_no_filename_in_path(requests_mock, public_host):
    requests_mock.get("https://files.example.com/", content=b"data")
    path, name, _ = _resolve_file_source(url="https://files.example.com/")
    os.unlink(path)
    assert name == "downloaded_file"


def test_resolve_file_source_url_redirect_not_followed(requests_mock, public_host):
    requests_mock.get(
        "https://files.example.com/file.exe", status_code=302, headers={"Location": "http://169.254.169.254/"}
    )
    with pytest.raises(DemistoException, match="redirect"):
        _resolve_file_source(url="https://files.example.com/file.exe")
    assert len(requests_mock.request_history) == 1


def test_resolve_file_source_url_error_status(requests_mock, public_host):
    requests_mock.get("https://files.example.com/file.exe", status_code=404)
    with pytest.raises(DemistoException, match="status 404"):
        _resolve_file_source(url="https://files.example.com/file.exe")


def test_resolve_file_source_url_content_length_too_large(requests_mock, public_host):
    requests_mock.get(
        "https://files.example.com/file.exe", headers={"Content-Length": str(MAX_DOWNLOAD_BYTES + 1)}, content=b""
    )
    with pytest.raises(DemistoException, match="the limit is"):
        _resolve_file_source(url="https://files.example.com/file.exe")


def test_resolve_file_source_url_body_exceeds_limit(requests_mock, public_host):
    """A body longer than the limit is cut off and the partial temp file removed."""
    created = []
    real_tmp = tempfile.NamedTemporaryFile

    def tracking_tmp(*args, **kwargs):
        f = real_tmp(*args, **kwargs)
        created.append(f.name)
        return f

    requests_mock.get("https://files.example.com/file.exe", content=b"x" * 64)
    with patch("Stairwell.MAX_DOWNLOAD_BYTES", 16), patch("Stairwell.tempfile.NamedTemporaryFile", tracking_tmp):
        with pytest.raises(DemistoException, match="exceeded"):
            _resolve_file_source(url="https://files.example.com/file.exe")
    assert created and not os.path.exists(created[0])


def test_resolve_file_source_url_timeout(requests_mock, public_host):
    requests_mock.get("https://files.example.com/file.exe", exc=requests.exceptions.Timeout())
    with pytest.raises(DemistoException, match="Timeout downloading"):
        _resolve_file_source(url="https://files.example.com/file.exe")


def test_resolve_file_source_url_connection_error(requests_mock, public_host):
    requests_mock.get("https://files.example.com/file.exe", exc=requests.exceptions.ConnectionError("refused"))
    with pytest.raises(DemistoException, match="Connection error"):
        _resolve_file_source(url="https://files.example.com/file.exe")


# ─────────────────────────────────────────────
# _hash_sha256 Tests
# ─────────────────────────────────────────────


def test_hash_sha256_error():
    with pytest.raises(DemistoException, match="Failed computing sha256"):
        _hash_sha256("/nonexistent/file.bin")


def test_hash_sha256_success(tmp_path):
    f = tmp_path / "f.bin"
    f.write_bytes(b"test content")
    assert _hash_sha256(str(f)) == "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"


# ─────────────────────────────────────────────
# intake_preflight_and_upload Tests
# ─────────────────────────────────────────────


FAKE_CONTENT_SHA256 = "98b1ae45059b004178a8eee0c1f6179dcea139c0fd8a69ee47a6f02d97af1f17"  # sha256(b"fake content")


@pytest.fixture
def war_room_file(tmp_path):
    """A War Room entry 1@2 that resolves to a real file."""
    f = tmp_path / "sample.exe"
    f.write_bytes(b"fake content")
    with patch("Stairwell.demisto.getFilePath", return_value={"path": str(f), "name": "sample.exe"}):
        yield f


def _preflight_client(fixture_name):
    client = MagicMock()
    client.intake_preflight.return_value = util_load_json(f"test_data/{fixture_name}")
    return client


def test_intake_preflight_and_upload_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments: asset_id"):
        intake_preflight_and_upload(test_client, asset_id="", entry_id="1@2")
    with pytest.raises(DemistoException, match="Missing file source: provide one of entry_id or url"):
        intake_preflight_and_upload(test_client, asset_id="test-asset")
    with pytest.raises(DemistoException, match="Multiple file sources"):
        intake_preflight_and_upload(test_client, asset_id="test-asset", entry_id="1@2", url="https://example.com/f")


def test_intake_preflight_and_upload_already_exists(war_room_file):
    client = _preflight_client("intake_preflight_already_exists.json")
    results = intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")
    assert isinstance(results, CommandResults)
    assert "already exists in Stairwell" in results.readable_output
    assert "NO_ACTION_ALREADY_EXISTS" in results.readable_output
    assert results.outputs["result"] == "already_exists"
    assert results.outputs["sha256"] == FAKE_CONTENT_SHA256
    assert "upload_status" not in results.outputs


def test_intake_preflight_and_upload_sends_filename_not_path(war_room_file):
    """The engine's local path never reaches the API; only the file name and hash do."""
    client = _preflight_client("intake_preflight_already_exists.json")
    intake_preflight_and_upload(
        client,
        asset_id="test-asset",
        entry_id="1@2",
        origin_type="web",
        origin_referrer_url="https://example.com/referrer",
        origin_host_url="https://example.com",
        origin_zone_id=123,
    )
    payload = client.intake_preflight.call_args.args[0]
    file_obj = payload["files"][0]
    assert payload["asset"] == {"id": "test-asset"}
    assert file_obj["filePath"] == "sample.exe"
    assert str(war_room_file) not in json.dumps(payload)
    assert file_obj["expected_attributes"] == {
        "identifiers": [{"sha256": FAKE_CONTENT_SHA256}]
    }
    assert file_obj["origin"] == {
        "web": {"referrer-url": "https://example.com/referrer", "host-url": "https://example.com", "zone-id": 123}
    }


def test_intake_preflight_and_upload_with_sha256_skips_hashing(war_room_file):
    client = _preflight_client("intake_preflight_already_exists.json")
    with patch("Stairwell._hash_sha256", side_effect=AssertionError("must not hash")):
        results = intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2", sha256=TEST_FILE_HASH)
    assert results.outputs["sha256"] == TEST_FILE_HASH
    payload = client.intake_preflight.call_args.args[0]
    assert payload["files"][0]["expected_attributes"]["identifiers"] == [{"sha256": TEST_FILE_HASH}]
    assert payload["files"][0]["origin"] == {"unspecified": {}}


def test_intake_preflight_and_upload_success(requests_mock, war_room_file):
    client = _preflight_client("intake_preflight_upload.json")
    requests_mock.post("https://storage.googleapis.com/upload-url", status_code=200)
    results = intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")
    assert "Upload completed successfully" in results.readable_output
    assert results.outputs["result"] == "uploaded"
    assert results.outputs["upload_status"] == 200
    assert results.raw_response == client.intake_preflight.return_value
    upload = requests_mock.request_history[0]
    assert b"policy-data" in upload.body
    assert b'filename="sample.exe"' in upload.body
    assert war_room_file.exists(), "a War Room file is not the command's to delete"


def test_intake_preflight_and_upload_removes_downloaded_file(requests_mock, tmp_path):
    client = _preflight_client("intake_preflight_upload.json")
    requests_mock.post("https://storage.googleapis.com/upload-url", status_code=200)
    f = tmp_path / "downloaded.exe"
    f.write_bytes(b"fake content")
    with patch("Stairwell._resolve_file_source", return_value=(str(f), "downloaded.exe", True)):
        intake_preflight_and_upload(client, asset_id="test-asset", url="https://files.example.com/downloaded.exe")
    assert not f.exists()


def test_intake_preflight_and_upload_removes_downloaded_file_on_failure(tmp_path):
    client = MagicMock()
    client.intake_preflight.side_effect = DemistoException("500 Server Error")
    f = tmp_path / "downloaded.exe"
    f.write_bytes(b"fake content")
    with patch("Stairwell._resolve_file_source", return_value=(str(f), "downloaded.exe", True)):
        with pytest.raises(DemistoException):
            intake_preflight_and_upload(client, asset_id="test-asset", url="https://files.example.com/downloaded.exe")
    assert not f.exists()


def test_intake_preflight_and_upload_upload_failure(requests_mock, war_room_file):
    """A failed upload is an error entry, never a success with the error in context."""
    client = _preflight_client("intake_preflight_upload.json")
    requests_mock.post("https://storage.googleapis.com/upload-url", status_code=500, text="Upload failed")
    with pytest.raises(DemistoException, match="Upload failed with status 500: Upload failed"):
        intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")


def test_intake_preflight_and_upload_upload_timeout(requests_mock, war_room_file):
    client = _preflight_client("intake_preflight_upload.json")
    requests_mock.post("https://storage.googleapis.com/upload-url", exc=requests.exceptions.Timeout())
    with pytest.raises(DemistoException, match="File upload timed out"):
        intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")


def test_intake_preflight_and_upload_upload_connection_error(requests_mock, war_room_file):
    client = _preflight_client("intake_preflight_upload.json")
    requests_mock.post("https://storage.googleapis.com/upload-url", exc=requests.exceptions.ConnectionError("refused"))
    with pytest.raises(DemistoException, match="Connection error during file upload"):
        intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")


def test_intake_preflight_and_upload_missing_upload_info(war_room_file):
    client = _preflight_client("intake_preflight_missing_upload_info.json")
    with pytest.raises(DemistoException, match="no uploadUrl/fields"):
        intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")


def test_intake_preflight_and_upload_unknown_action(war_room_file):
    client = _preflight_client("intake_preflight_unknown_action.json")
    with pytest.raises(DemistoException, match="Unrecognized preflight action"):
        intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")


@pytest.mark.parametrize("preflight", [{"someOther": "data"}, {"fileActions": []}, "not json", None])
def test_intake_preflight_and_upload_unexpected_preflight_response(war_room_file, preflight):
    client = MagicMock()
    client.intake_preflight.return_value = preflight
    with pytest.raises(DemistoException, match="Unexpected preflight response"):
        intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")


@pytest.mark.parametrize(
    "exc, message",
    [
        (DemistoException("500 Server Error"), "HTTP error during intake preflight"),
        (requests.exceptions.HTTPError("500 Server Error"), "HTTP error during intake preflight"),
        (requests.exceptions.Timeout(), "Intake preflight timed out"),
        (requests.exceptions.ConnectionError("refused"), "Connection error during intake preflight"),
    ],
)
def test_intake_preflight_and_upload_preflight_errors(war_room_file, exc, message):
    client = MagicMock()
    client.intake_preflight.side_effect = exc
    with pytest.raises(DemistoException, match=message):
        intake_preflight_and_upload(client, asset_id="test-asset", entry_id="1@2")


def test_intake_preflight_and_upload_resolve_error():
    with patch("Stairwell.demisto.getFilePath", return_value={"name": "f.exe"}):
        with pytest.raises(DemistoException, match="Failed to resolve entry ID 1@2"):
            intake_preflight_and_upload(test_client, asset_id="test-asset", entry_id="1@2")


# ─────────────────────────────────────────────
# Asset create/get: token handling and idempotency
# ─────────────────────────────────────────────


def test_asset_create_command_success(requests_mock):
    TEST_ENV = "test-environment-id"
    mock_response = {"name": "assets/VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6", "label": "test-endpoint", "uploadToken": "token-abc-123"}
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json=mock_response)

    results = asset_create_command(test_client, TEST_ENV, "test-endpoint", os_name="Linux")

    assert results.outputs_prefix == "Stairwell.Asset"
    assert results.outputs_key_field == "name"
    assert results.outputs == {"name": "assets/VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6", "label": "test-endpoint"}
    assert "token-abc-123" not in results.readable_output
    qs = requests_mock.last_request.qs
    assert qs["os"] == ["linux"]
    assert len(qs["idempotencykey"]) == 1 and qs["idempotencykey"][0], "a key is generated when none is given"


def test_asset_create_command_passes_idempotency_key(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json={"name": "assets/X"})
    asset_create_command(test_client, TEST_ENV, "test-endpoint", idempotency_key="my-key-1")
    assert requests_mock.last_request.qs["idempotencykey"] == ["my-key-1"]


def test_asset_create_command_non_dict_response(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json=["odd"])
    results = asset_create_command(test_client, TEST_ENV, "test-endpoint")
    assert results.outputs == ["odd"]


def test_asset_get_command_success(requests_mock):
    TEST_ASSET = "VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6"
    mock_response = {"name": f"assets/{TEST_ASSET}", "label": "test-endpoint", "uploadToken": "token-abc-123"}
    requests_mock.get(f"https://app.stairwell.com/v1/assets/{TEST_ASSET}", json=mock_response)

    results = asset_get_command(test_client, TEST_ASSET)

    assert results.outputs_prefix == "Stairwell.Asset"
    assert results.outputs == {"name": f"assets/{TEST_ASSET}", "label": "test-endpoint"}
    assert "token-abc-123" not in results.readable_output


def test_create_requests_retry_policy():
    """A YARA rule create has no idempotency key, so it is never retried; an asset create always has one."""
    client = Client(api_key=API_KEY)
    with patch.object(client, "_http_request", return_value={}) as http:
        client.create_yara_rule("env", "rule r { condition: true }")
        assert http.call_args.kwargs["retries"] == 0
        client.create_asset("env", "label")
        assert http.call_args.kwargs["retries"] == RETRY_COUNT
        client.intake_preflight({})
        assert http.call_args.kwargs["retries"] == RETRY_COUNT


# ─────────────────────────────────────────────
# Reputation commands: file, ip, domain
# ─────────────────────────────────────────────

RELIABILITY = "A - Completely reliable"
OBJECTS_URL = "https://app.stairwell.com/v1/objects/"
V2_URL = "https://app.stairwell.com/v2/"


def _metadata(bucket=None, severity="SEVERITY_HIGH", labels=("VB:Trojan.X",)):
    md = {
        "name": "evil.exe",
        "size": "12345",
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": TEST_FILE_HASH,
        "mimeType": "application/x-msdownload",
        "magic": "PE32 executable",
        "imphash": "abc123",
        "stairwellFirstSeenTime": "2025-04-29T19:00:00Z",
        "yaraRuleMatches": ["Win_Trojan_WannaCry", "Win_Worm_WannaCry"],
        "networkIndicators": {"ipAddresses": ["8.8.8.8"], "hostnames": ["evil.example.com"]},
    }
    if bucket:
        md["malEval"] = {"probabilityBucket": bucket, "severity": severity, "labels": list(labels)}
    return md


def _dbot(results):
    return _indicator_ctx(results, Common.DBotScore.CONTEXT_PATH)


def _indicator_ctx(results, context_path):
    entries = results.to_context()["EntryContext"][context_path]
    assert len(entries) == 1
    return entries[0]


@pytest.mark.parametrize(
    "bucket, score",
    [
        ("PROBABILITY_VERY_HIGH", 3),
        ("PROBABILITY_HIGH", 3),
        ("PROBABILITY_MEDIUM", 2),
        ("PROBABILITY_LOW", 1),
        ("PROBABILITY_UNSPECIFIED", 0),
        (None, 0),
    ],
)
def test_file_command_maleval_score(requests_mock, bucket, score):
    requests_mock.get(f"{OBJECTS_URL}{TEST_FILE_HASH}/metadata", json=_metadata(bucket))
    results = file_command(test_client, TEST_FILE_HASH, RELIABILITY)
    assert len(results) == 1
    dbot = _dbot(results[0])
    assert dbot == {
        "Indicator": TEST_FILE_HASH,
        "Type": "file",
        "Vendor": "Stairwell",
        "Score": score,
        "Reliability": RELIABILITY,
    }
    file_ctx = _indicator_ctx(results[0], Common.File.CONTEXT_PATH)
    assert ("Malicious" in file_ctx) == (score == 3)
    if score == 3:
        assert file_ctx["Malicious"] == {
            "Vendor": "Stairwell",
            "Description": f"Stairwell MalEval verdict {bucket}; severity SEVERITY_HIGH; labels VB:Trojan.X",
        }


def test_file_command_indicator_and_outputs(requests_mock):
    requests_mock.get(f"{OBJECTS_URL}{TEST_FILE_HASH}/metadata", json=_metadata("PROBABILITY_HIGH"))
    results = file_command(test_client, TEST_FILE_HASH, RELIABILITY)
    file_ctx = _indicator_ctx(results[0], Common.File.CONTEXT_PATH)
    assert file_ctx["MD5"] == "a" * 32
    assert file_ctx["SHA1"] == "b" * 40
    assert file_ctx["SHA256"] == TEST_FILE_HASH
    assert file_ctx["Size"] == 12345
    assert file_ctx["Name"] == "evil.exe"
    assert file_ctx["Type"] == "application/x-msdownload"
    assert file_ctx["Imphash"] == "abc123"
    assert file_ctx["Tags"] == ["Win_Trojan_WannaCry", "Win_Worm_WannaCry"]
    assert results[0].outputs_prefix == "Stairwell.File"
    assert results[0].outputs_key_field == "sha256"
    assert results[0].outputs["malEval"] == {
        "probabilityBucket": "PROBABILITY_HIGH",
        "severity": "SEVERITY_HIGH",
        "labels": ["VB:Trojan.X"],
    }
    assert results[0].outputs["size"] == 12345
    assert results[0].outputs["yaraRuleMatches"] == ["Win_Trojan_WannaCry", "Win_Worm_WannaCry"]
    assert results[0].outputs["networkIndicators"]["hostnames"] == ["evil.example.com"]
    assert "Win_Trojan_WannaCry" in results[0].readable_output
    assert results[0].raw_response == _metadata("PROBABILITY_HIGH")


def test_file_command_md5_lookup_fills_sha256(requests_mock):
    md5 = "c" * 32
    requests_mock.get(f"{OBJECTS_URL}{md5}/metadata", json=_metadata("PROBABILITY_LOW"))
    results = file_command(test_client, md5, RELIABILITY)
    assert _dbot(results[0])["Indicator"] == md5
    assert _indicator_ctx(results[0], Common.File.CONTEXT_PATH)["SHA256"] == TEST_FILE_HASH
    assert results[0].outputs["sha256"] == TEST_FILE_HASH


def test_file_command_not_found_is_unknown(requests_mock):
    requests_mock.get(f"{OBJECTS_URL}{TEST_FILE_HASH}/metadata", status_code=404)
    results = file_command(test_client, TEST_FILE_HASH, RELIABILITY)
    assert len(results) == 1
    assert "not found" in results[0].readable_output.lower()
    assert _dbot(results[0])["Score"] == 0
    assert results[0].outputs is None


def test_file_command_multiple_hashes_mixed(requests_mock):
    other = "d" * 64
    requests_mock.get(f"{OBJECTS_URL}{TEST_FILE_HASH}/metadata", json=_metadata("PROBABILITY_VERY_HIGH"))
    requests_mock.get(f"{OBJECTS_URL}{other}/metadata", status_code=404)
    results = file_command(test_client, f"{TEST_FILE_HASH}, {other}", RELIABILITY)
    assert [_dbot(r)["Score"] for r in results] == [3, 0]
    assert [_dbot(r)["Indicator"] for r in results] == [TEST_FILE_HASH, other]


def test_file_command_server_error_raises(requests_mock):
    requests_mock.get(f"{OBJECTS_URL}{TEST_FILE_HASH}/metadata", status_code=403)
    with pytest.raises(DemistoException):
        file_command(test_client, TEST_FILE_HASH, RELIABILITY)


def test_file_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments: file"):
        file_command(test_client, "", RELIABILITY)


def test_file_command_non_dict_response_raises(requests_mock):
    requests_mock.get(f"{OBJECTS_URL}{TEST_FILE_HASH}/metadata", json=["nope"])
    with pytest.raises(DemistoException, match="Unexpected object metadata response"):
        file_command(test_client, TEST_FILE_HASH, RELIABILITY)


IP = "52.0.0.1"
IP_DATA = {
    "ipAddress": IP,
    "geoLocation": {"country": "US", "countryName": "United States", "city": "Ashburn", "region": "Virginia"},
    "subnetInfo": {"cidr": "52.0.0.0", "prefixLength": 14},
    "asns": [16509],
    "cloudProvider": "AWS",
    "isVpn": False,
    "isDatacenter": True,
}
IP_WHOIS = {"ipAddress": IP, "record": {"rir": "ARIN", "arinOrg": {"name": "Amazon Technologies Inc."}}}
IP_HOSTS = {"hostnames": [{"canonicalHostname": "ec2-52-0-0-1.compute-1.amazonaws.com"}, "plain.example.com"]}


def test_ip_command_full(requests_mock):
    requests_mock.get(f"{V2_URL}ips/{IP}", json=IP_DATA)
    requests_mock.get(f"{V2_URL}ips/{IP}/whois", json=IP_WHOIS)
    requests_mock.get(f"{V2_URL}ips/{IP}/hostnames", json=IP_HOSTS)
    results = ip_command(test_client, IP, RELIABILITY)
    assert len(results) == 1
    assert _dbot(results[0]) == {"Indicator": IP, "Type": "ip", "Vendor": "Stairwell", "Score": 0, "Reliability": RELIABILITY}
    ip_ctx = _indicator_ctx(results[0], Common.IP.CONTEXT_PATH)
    assert ip_ctx["Address"] == IP
    assert ip_ctx["ASN"] == "16509"
    assert ip_ctx["ASOwner"] == "Amazon Technologies Inc."
    assert ip_ctx["Geo"] == {"Country": "US", "Description": "Ashburn, Virginia"}
    assert ip_ctx["Hostname"] == "ec2-52-0-0-1.compute-1.amazonaws.com"
    assert ip_ctx["Tags"] == ["stairwell:cloud-aws", "stairwell:datacenter"]
    assert results[0].outputs_prefix == "Stairwell.IP"
    assert results[0].outputs_key_field == "ip"
    assert results[0].outputs["hostnames"] == ["ec2-52-0-0-1.compute-1.amazonaws.com", "plain.example.com"]
    assert results[0].outputs["whoisOrganization"] == "Amazon Technologies Inc."
    assert results[0].outputs["asns"] == [16509]
    assert "Amazon Technologies Inc." in results[0].readable_output


def test_ip_command_optional_lookups_may_fail(requests_mock):
    """WHOIS and reverse DNS add detail; their failure does not lose the IP result."""
    requests_mock.get(f"{V2_URL}ips/8.8.8.8", json={"asns": [15169], "cloudProvider": "CLOUD_PROVIDER_UNSPECIFIED"})
    requests_mock.get(f"{V2_URL}ips/8.8.8.8/whois", status_code=500)
    requests_mock.get(f"{V2_URL}ips/8.8.8.8/hostnames", status_code=404)
    results = ip_command(test_client, "8.8.8.8", RELIABILITY)
    ip_ctx = _indicator_ctx(results[0], Common.IP.CONTEXT_PATH)
    assert ip_ctx["ASN"] == "15169"
    assert "ASOwner" not in ip_ctx
    assert "Hostname" not in ip_ctx
    assert "Tags" not in ip_ctx
    assert results[0].outputs["cloudProvider"] is None
    assert results[0].outputs["hostnames"] == []


def test_ip_command_not_found_is_unknown(requests_mock):
    requests_mock.get(f"{V2_URL}ips/8.8.8.8", status_code=404)
    results = ip_command(test_client, "8.8.8.8", RELIABILITY)
    assert "not found" in results[0].readable_output.lower()
    assert _dbot(results[0])["Score"] == 0
    assert _indicator_ctx(results[0], Common.IP.CONTEXT_PATH)["Address"] == "8.8.8.8"
    assert len(requests_mock.request_history) == 1, "no detail lookups for an unknown IP"


def test_ip_command_server_error_raises(requests_mock):
    requests_mock.get(f"{V2_URL}ips/8.8.8.8", status_code=500)
    with pytest.raises(DemistoException):
        ip_command(test_client, "8.8.8.8", RELIABILITY)


def test_ip_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments: ip"):
        ip_command(test_client, "", RELIABILITY)


DOMAIN = "many.example.com"
RESOLUTIONS = {
    "etldPlusOne": "example.com",
    "resolutions": [
        {
            "recordType": "A",
            "answer": "8.8.8.8",
            "firstSeen": "2024-01-01T00:00:00Z",
            "lastSeen": "2024-02-01T00:00:00Z",
            "observationCount": 5,
        },
        {"recordType": "A", "answer": "8.8.8.8"},
        {"recordType": "AAAA", "answer": "2001:4860:4860::8888"},
        {"recordType": "MX", "answer": "10 mx.example.com"},
        {"answer": "9.9.9.9"},
        "junk",
        {"recordType": "A"},
    ],
}


def test_domain_command_full(requests_mock):
    requests_mock.get(f"{V2_URL}hostnames/{DOMAIN}", json={"hostname": DOMAIN})
    requests_mock.get(f"{V2_URL}hostnames/{DOMAIN}/whitelist-status", json={"hostname": DOMAIN, "whitelisted": False})
    requests_mock.get(f"{V2_URL}hostnames/{DOMAIN}/resolutions", json=RESOLUTIONS)
    results = domain_command(test_client, DOMAIN, RELIABILITY)
    assert len(results) == 1
    assert _dbot(results[0]) == {
        "Indicator": DOMAIN,
        "Type": "domain",
        "Vendor": "Stairwell",
        "Score": 0,
        "Reliability": RELIABILITY,
    }
    dom_ctx = _indicator_ctx(results[0], Common.Domain.CONTEXT_PATH)
    assert dom_ctx["Name"] == DOMAIN
    assert dom_ctx["DNS"] == "8.8.8.8, 2001:4860:4860::8888, 9.9.9.9"
    assert "Tags" not in dom_ctx
    assert results[0].outputs_prefix == "Stairwell.Domain"
    assert results[0].outputs_key_field == "hostname"
    assert results[0].outputs["etldPlusOne"] == "example.com"
    assert results[0].outputs["whitelisted"] is False
    assert [(r["recordType"], r["answer"]) for r in results[0].outputs["resolutions"]] == [
        ("A", "8.8.8.8"),
        ("AAAA", "2001:4860:4860::8888"),
        ("MX", "10 mx.example.com"),
        ("A", "9.9.9.9"),
    ]
    assert results[0].outputs["resolutions"][0]["observationCount"] == 5


def test_domain_command_whitelisted_is_good(requests_mock):
    requests_mock.get(
        f"{V2_URL}hostnames/google.com",
        json={"hostname": "google.com", "resolutions": [{"recordType": "A", "answer": "8.8.8.8"}]},
    )
    requests_mock.get(f"{V2_URL}hostnames/google.com/whitelist-status", json={"whitelisted": True})
    requests_mock.get(f"{V2_URL}hostnames/google.com/resolutions", status_code=500)
    results = domain_command(test_client, "google.com", RELIABILITY)
    assert _dbot(results[0])["Score"] == 1
    dom_ctx = _indicator_ctx(results[0], Common.Domain.CONTEXT_PATH)
    assert dom_ctx["Tags"] == ["stairwell:whitelisted"]
    assert dom_ctx["DNS"] == "8.8.8.8", "resolutions embedded in the hostname response are the fallback"
    assert results[0].outputs["whitelisted"] is True


def test_domain_command_whitelist_endpoint_wins_over_embedded_flag(requests_mock):
    requests_mock.get(f"{V2_URL}hostnames/x.example.com", json={"whitelisted": True})
    requests_mock.get(f"{V2_URL}hostnames/x.example.com/whitelist-status", json={"whitelisted": False})
    requests_mock.get(f"{V2_URL}hostnames/x.example.com/resolutions", json={})
    results = domain_command(test_client, "x.example.com", RELIABILITY)
    assert _dbot(results[0])["Score"] == 0


def test_domain_command_not_found_is_unknown(requests_mock):
    requests_mock.get(f"{V2_URL}hostnames/nope.example.com", status_code=404)
    results = domain_command(test_client, "nope.example.com", RELIABILITY)
    assert "not found" in results[0].readable_output.lower()
    assert _dbot(results[0])["Score"] == 0
    assert len(requests_mock.request_history) == 1


def test_domain_command_server_error_raises(requests_mock):
    requests_mock.get(f"{V2_URL}hostnames/nope.example.com", status_code=500)
    with pytest.raises(DemistoException):
        domain_command(test_client, "nope.example.com", RELIABILITY)


def test_domain_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments: domain"):
        domain_command(test_client, "", RELIABILITY)


def test_domain_command_multiple(requests_mock):
    for d in ("a.example.com", "b.example.com"):
        requests_mock.get(f"{V2_URL}hostnames/{d}", json={})
        requests_mock.get(f"{V2_URL}hostnames/{d}/whitelist-status", json={})
        requests_mock.get(f"{V2_URL}hostnames/{d}/resolutions", json={})
    results = domain_command(test_client, "a.example.com,b.example.com", RELIABILITY)
    assert [_dbot(r)["Indicator"] for r in results] == ["a.example.com", "b.example.com"]


def test_reliability_flows_into_dbotscore(requests_mock):
    requests_mock.get(f"{V2_URL}ips/8.8.8.8", json={})
    requests_mock.get(f"{V2_URL}ips/8.8.8.8/whois", json={})
    requests_mock.get(f"{V2_URL}ips/8.8.8.8/hostnames", json={})
    results = ip_command(test_client, "8.8.8.8", "C - Fairly reliable")
    assert _dbot(results[0])["Reliability"] == "C - Fairly reliable"


@pytest.mark.parametrize(
    "mal_eval, expected",
    [
        ({"probabilityBucket": "PROBABILITY_HIGH", "severity": "SEVERITY_HIGH", "labels": ["A", "B"]},
         (3, "Stairwell MalEval verdict PROBABILITY_HIGH; severity SEVERITY_HIGH; labels A, B")),
        ({"probabilityBucket": "PROBABILITY_VERY_HIGH"}, (3, "Stairwell MalEval verdict PROBABILITY_VERY_HIGH")),
        ({"probability_bucket": "PROBABILITY_MEDIUM"}, (2, None)),
        ({"probabilityBucket": "PROBABILITY_LOW", "severity": "SEVERITY_LOW"}, (1, None)),
        ({}, (0, None)),
    ],
)
def test_mal_eval_score(mal_eval, expected):
    """Only a malicious score carries a description; it becomes File.Malicious.Description."""
    assert _mal_eval_score(mal_eval) == expected
