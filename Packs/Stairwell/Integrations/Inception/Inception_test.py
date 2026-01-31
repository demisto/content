from Inception import (
    Client, 
    variant_discovery_command, 
    file_enrichment_command, 
    intake_preflight_and_upload,
    ai_triage_summarize_command,
    object_sightings_command,
    object_detonation_trigger_command,
    object_detonation_get_command,
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
    utilities_canonicalize_url_command
)
import json
import io

API_KEY = "FAKEAPIKEY"
TEST_FILE_HASH = "e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d"
TEST_OBJECT_ID = "357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


test_client = Client(
    base_url='https://fakeapi.stairwelldemo.com',
    verify=False,
    proxy=False,
    headers={"Authorization": API_KEY}
)

test_client_v1 = Client(
    base_url='https://app.stairwell.com/v1/objects/',
    verify=False,
    proxy=False,
    headers={"X-Apikey": API_KEY}
)

test_client_network = Client(
    base_url='https://app.stairwell.com/v1/network/',
    verify=False,
    proxy=False,
    headers={"X-Apikey": API_KEY}
)


def test_variant_discovery_command_success(requests_mock):
    mock_response = util_load_json('test_data/variant_discovery_command_result.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results


def test_variant_discovery_command_none(requests_mock):
    mock_response = util_load_json('test_data/variant_discovery_command_results_none.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results


def test_variant_discovery_command_notfound(requests_mock):
    mock_response = util_load_json('test_data/variant_discovery_command_results_notfound.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response, status_code=500)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results


def test_file_enrichment_command(requests_mock):
    mock_response = util_load_json('test_data/file_enrichment_command_result.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results


def test_file_enrichment_command_notfound(requests_mock):
    mock_response = util_load_json('test_data/file_enrichment_command_result.json')

    requests_mock.get("https://fakeapi.stairwelldemo.com/" + TEST_FILE_HASH, json=mock_response, status_code=404)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results


# Intake Preflight and Upload Tests
def test_intake_preflight_and_upload_missing_args():
    """Test intake_preflight_and_upload with missing required arguments"""
    # Test missing asset_id
    results = intake_preflight_and_upload(asset_id="", file_path="/path/to/file")
    assert results.readable_output == "Missing required arguments: assetId"
    
    # Test missing file_path
    results = intake_preflight_and_upload(asset_id="test-asset", file_path="")
    assert results.readable_output == "Missing required arguments: filePath"


def test_intake_preflight_and_upload_already_exists(requests_mock):
    """Test intake_preflight_and_upload when file already exists"""
    mock_response = util_load_json('test_data/intake_preflight_already_exists.json')
    
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_response)
    
    results = intake_preflight_and_upload(asset_id="test-asset", file_path="/path/to/test/file.exe")
    
    assert results
    assert "already exists in Stairwell" in results.readable_output
    assert results.outputs.get("result") == "already_exists"
    assert "NO_ACTION_ALREADY_EXISTS" in results.readable_output


def test_intake_preflight_and_upload_success(requests_mock):
    """Test intake_preflight_and_upload with successful upload"""
    mock_preflight = util_load_json('test_data/intake_preflight_upload.json')
    
    # Mock the preflight request
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_preflight)
    
    # Mock the upload request
    requests_mock.post("https://storage.googleapis.com/upload-url", status_code=200)
    
    results = intake_preflight_and_upload(asset_id="test-asset", file_path="/path/to/test/file.exe")
    
    assert results
    assert "Upload completed successfully" in results.readable_output
    assert results.outputs.get("upload_status") == 200


def test_intake_preflight_and_upload_upload_failure(requests_mock):
    """Test intake_preflight_and_upload when upload fails"""
    mock_preflight = util_load_json('test_data/intake_preflight_upload.json')
    
    # Mock the preflight request
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_preflight)
    
    # Mock the upload request to fail
    requests_mock.post("https://storage.googleapis.com/upload-url", status_code=500, text="Upload failed")
    
    results = intake_preflight_and_upload(asset_id="test-asset", file_path="/path/to/test/file.exe")
    
    assert results
    assert "Upload failed with status 500" in results.readable_output
    assert results.outputs.get("upload_status") == 500


def test_intake_preflight_and_upload_missing_upload_info(requests_mock):
    """Test intake_preflight_and_upload when preflight requests upload but missing upload info"""
    mock_response = util_load_json('test_data/intake_preflight_missing_upload_info.json')
    
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_response)
    
    results = intake_preflight_and_upload(asset_id="test-asset", file_path="/path/to/test/file.exe")
    
    assert results
    assert "missing uploadUrl/fields" in results.readable_output
    assert results.outputs.get("error") == "missing_upload_instructions"


def test_intake_preflight_and_upload_unknown_action(requests_mock):
    """Test intake_preflight_and_upload with unknown action"""
    mock_response = util_load_json('test_data/intake_preflight_unknown_action.json')
    
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_response)
    
    results = intake_preflight_and_upload(asset_id="test-asset", file_path="/path/to/test/file.exe")
    
    assert results
    assert "Unrecognized action" in results.readable_output


def test_intake_preflight_and_upload_http_error(requests_mock):
    """Test intake_preflight_and_upload with HTTP error"""
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", status_code=500)
    
    results = intake_preflight_and_upload(asset_id="test-asset", file_path="/path/to/test/file.exe")
    
    assert results
    assert "HTTP error during Intake preflight/upload" in results.readable_output
    assert "error" in results.outputs


def test_intake_preflight_and_upload_with_sha256(requests_mock):
    """Test intake_preflight_and_upload with provided SHA256"""
    mock_response = util_load_json('test_data/intake_preflight_already_exists.json')
    
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_response)
    
    results = intake_preflight_and_upload(
        asset_id="test-asset", 
        file_path="/path/to/test/file.exe",
        sha256="e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d"
    )
    
    assert results
    assert "already exists in Stairwell" in results.readable_output


def test_intake_preflight_and_upload_with_web_origin(requests_mock):
    """Test intake_preflight_and_upload with web origin type"""
    mock_response = util_load_json('test_data/intake_preflight_already_exists.json')
    
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_response)
    
    results = intake_preflight_and_upload(
        asset_id="test-asset", 
        file_path="/path/to/test/file.exe",
        origin_type="web",
        origin_referrer_url="https://example.com/referrer",
        origin_host_url="https://example.com",
        origin_zone_id=123
    )
    
    assert results
    assert "already exists in Stairwell" in results.readable_output


def test_intake_preflight_and_upload_with_detonation_plan(requests_mock):
    """Test intake_preflight_and_upload with detonation plan"""
    mock_response = util_load_json('test_data/intake_preflight_already_exists.json')
    
    requests_mock.post("https://http.intake.app.stairwell.com/v2021.05/upload", json=mock_response)
    
    results = intake_preflight_and_upload(
        asset_id="test-asset", 
        file_path="/path/to/test/file.exe",
        detonation_plan="test-plan"
    )
    
    assert results
    assert "already exists in Stairwell" in results.readable_output


# AI Triage Tests
def test_ai_triage_summarize_command_success(requests_mock):
    """Test AI Triage summarize command with successful response"""
    mock_response = {
        "hash": TEST_OBJECT_ID,
        "raw": {
            "tldr": "This file is a highly suspicious executable.",
            "summary": "Detailed summary text",
            "summaryJson": {
                "malicious_likelihood": 95,
                "confidence": 90,
                "threat_type": "Trojan Dropper/Backdoor",
                "tldr": "This file is a highly suspicious executable.",
                "summary": ["Point 1", "Point 2"],
                "iocs": {
                    "urls": ["http://example.com"],
                    "file_paths_filenames": ["test.exe"],
                    "registry_keys": ["SOFTWARE\\Test"]
                }
            }
        }
    }
    
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json=mock_response)
    
    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert "AI Triage Summary" in results.readable_output
    assert results.outputs.get("hash") == TEST_OBJECT_ID
    assert results.outputs.get("malicious_likelihood") == 95
    assert results.outputs.get("confidence") == 90


def test_ai_triage_summarize_command_notfound(requests_mock):
    """Test AI Triage summarize command with 404 error"""
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", status_code=404)
    
    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert "Object not found" in results.readable_output


def test_ai_triage_summarize_command_missing_args():
    """Test AI Triage summarize command with missing arguments"""
    results = ai_triage_summarize_command(test_client_v1, "")
    
    assert results
    assert "Missing required arguments" in results.readable_output


# Object Sightings Tests
def test_object_sightings_command_success(requests_mock):
    """Test object sightings command with successful response"""
    mock_response = {
        "sightings": [
            {
                "asset": {"id": "asset-1", "name": "Test Asset"},
                "timestamp": "2024-01-01T00:00:00Z"
            }
        ]
    }
    
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", json=mock_response)
    
    results = object_sightings_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert results.outputs_prefix == "Stairwell.Sightings"
    assert "sightings" in results.outputs


def test_object_sightings_command_no_sightings(requests_mock):
    """Test object sightings command with no sightings"""
    mock_response = {"sightings": []}
    
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", json=mock_response)
    
    results = object_sightings_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert "No sightings found" in results.readable_output


def test_object_sightings_command_missing_args():
    """Test object sightings command with missing arguments"""
    results = object_sightings_command(test_client_v1, "")
    
    assert results
    assert "Missing required arguments" in results.readable_output


# Object Detonation Trigger Tests
def test_object_detonation_trigger_command_success(requests_mock):
    """Test object detonation trigger command with successful response"""
    mock_response = {"status": "triggered", "detonation_id": "det-123"}
    
    requests_mock.post(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/detonation:trigger", json=mock_response)
    
    results = object_detonation_trigger_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert "Detonation triggered" in results.readable_output
    assert results.outputs_prefix == "Stairwell.Detonation.Trigger"


def test_object_detonation_trigger_command_missing_args():
    """Test object detonation trigger command with missing arguments"""
    results = object_detonation_trigger_command(test_client_v1, "")
    
    assert results
    assert "Missing required arguments" in results.readable_output


# Object Detonation Get Tests
def test_object_detonation_get_command_success(requests_mock):
    """Test object detonation get command with successful response"""
    mock_response = {
        "status": "completed",
        "results": {"behavior": "malicious", "score": 95}
    }
    
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/detonation", json=mock_response)
    
    results = object_detonation_get_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert results.outputs_prefix == "Stairwell.Detonation"
    assert results.outputs.get("status") == "completed"


def test_object_detonation_get_command_missing_args():
    """Test object detonation get command with missing arguments"""
    results = object_detonation_get_command(test_client_v1, "")
    
    assert results
    assert "Missing required arguments" in results.readable_output


# Object Opinions Tests
def test_object_opinions_command_success(requests_mock):
    """Test object opinions command with successful response"""
    mock_response = {
        "opinions": [
            {"source": "analyst", "verdict": "malicious", "confidence": 90}
        ]
    }
    
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", json=mock_response)
    
    results = object_opinions_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert results.outputs_prefix == "Stairwell.Opinions"
    assert "opinions" in results.outputs


def test_object_opinions_command_no_opinions(requests_mock):
    """Test object opinions command with no opinions"""
    mock_response = {"opinions": []}
    
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", json=mock_response)
    
    results = object_opinions_command(test_client_v1, TEST_OBJECT_ID)
    
    assert results
    assert "No opinions found" in results.readable_output


def test_object_opinions_command_missing_args():
    """Test object opinions command with missing arguments"""
    results = object_opinions_command(test_client_v1, "")
    
    assert results
    assert "Missing required arguments" in results.readable_output


# Run-To-Ground Tests
def test_run_to_ground_generate_command_success(requests_mock):
    """Test run-to-ground generate command with successful response"""
    test_client_rtg = Client(
        base_url='https://app.stairwell.com/v1/',
        verify=False,
        proxy=False,
        headers={"X-Apikey": API_KEY}
    )
    
    mock_response = {
        "analysis": {
            "objects": [TEST_OBJECT_ID, TEST_FILE_HASH],
            "relationships": []
        }
    }
    
    object_ids = f"{TEST_OBJECT_ID},{TEST_FILE_HASH}"
    requests_mock.get(
        "https://app.stairwell.com/v1/generateRunToGround:generate",
        json=mock_response,
        status_code=200
    )
    
    results = run_to_ground_generate_command(test_client_rtg, object_ids)
    
    assert results
    assert results.outputs_prefix == "Stairwell.RunToGround"
    assert "analysis" in results.outputs


def test_run_to_ground_generate_command_missing_args():
    """Test run-to-ground generate command with missing arguments"""
    test_client_rtg = Client(
        base_url='https://app.stairwell.com/v1/',
        verify=False,
        proxy=False,
        headers={"X-Apikey": API_KEY}
    )
    
    results = run_to_ground_generate_command(test_client_rtg, "")
    
    assert results
    assert "Missing required arguments" in results.readable_output


def test_run_to_ground_generate_command_multiple_objects(requests_mock):
    """Test run-to-ground generate command with multiple object IDs"""
    test_client_rtg = Client(
        base_url='https://app.stairwell.com/v1/',
        verify=False,
        proxy=False,
        headers={"X-Apikey": API_KEY}
    )
    
    mock_response = {"analysis": {"objects": [TEST_OBJECT_ID, TEST_FILE_HASH]}}
    
    object_ids = f"{TEST_OBJECT_ID}, {TEST_FILE_HASH} , another-hash"
    requests_mock.get(
        "https://app.stairwell.com/v1/generateRunToGround:generate",
        json=mock_response
    )
    
    results = run_to_ground_generate_command(test_client_rtg, object_ids)
    
    assert results
    assert results.outputs_prefix == "Stairwell.RunToGround"


# Network Intel Tests - ASN
def test_asn_get_whois_command_success(requests_mock):
    """Test ASN get whois command with successful response"""
    mock_response = {
        "asn": "AS12345",
        "organization": "Test Organization",
        "country": "US"
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/asn/12345/whois", json=mock_response)
    
    results = asn_get_whois_command(test_client_network, "12345")
    
    assert results
    assert results.outputs_prefix == "Stairwell.ASN.WHOIS"
    assert results.outputs.get("asn") == "AS12345"


def test_asn_get_whois_command_notfound(requests_mock):
    """Test ASN get whois command with 404 error"""
    requests_mock.get("https://app.stairwell.com/v1/network/asn/99999/whois", status_code=404)
    
    results = asn_get_whois_command(test_client_network, "99999")
    
    assert results
    assert "ASN not found" in results.readable_output


def test_asn_get_whois_command_missing_args():
    """Test ASN get whois command with missing arguments"""
    results = asn_get_whois_command(test_client_network, "")
    
    assert results
    assert "Missing required arguments" in results.readable_output


# Network Intel Tests - Hostname
def test_hostname_get_command_success(requests_mock):
    """Test hostname get command with successful response"""
    mock_response = {
        "hostname": "example.com",
        "resolutions": [{"ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"}]
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/hostname/example.com", json=mock_response)
    
    results = hostname_get_command(test_client_network, "example.com")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Hostname"
    assert results.outputs.get("hostname") == "example.com"


def test_hostname_get_command_notfound(requests_mock):
    """Test hostname get command with 404 error"""
    requests_mock.get("https://app.stairwell.com/v1/network/hostname/nonexistent.com", status_code=404)
    
    results = hostname_get_command(test_client_network, "nonexistent.com")
    
    assert results
    assert "Hostname not found" in results.readable_output


def test_hostname_get_resolutions_command_success(requests_mock):
    """Test hostname get resolutions command with successful response"""
    mock_response = {
        "resolutions": [
            {"ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"},
            {"ip": "5.6.7.8", "timestamp": "2024-01-02T00:00:00Z"}
        ]
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/hostname/example.com/resolutions", json=mock_response)
    
    results = hostname_get_resolutions_command(test_client_network, "example.com")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Hostname.Resolutions"
    assert len(results.outputs.get("resolutions", [])) == 2


def test_hostname_batch_get_resolutions_command_success(requests_mock):
    """Test hostname batch get resolutions command with successful response"""
    mock_response = {
        "results": {
            "example.com": [{"ip": "1.2.3.4"}],
            "test.com": [{"ip": "5.6.7.8"}]
        }
    }
    
    requests_mock.post("https://app.stairwell.com/v1/network/hostname/batch/resolutions", json=mock_response)
    
    results = hostname_batch_get_resolutions_command(test_client_network, "example.com,test.com")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Hostname.BatchResolutions"


# Network Intel Tests - IP Address
def test_ipaddress_get_command_success(requests_mock):
    """Test IP address get command with successful response"""
    mock_response = {
        "ip": "1.2.3.4",
        "country": "US",
        "asn": "AS12345"
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/ipaddress/1.2.3.4", json=mock_response)
    
    results = ipaddress_get_command(test_client_network, "1.2.3.4")
    
    assert results
    assert results.outputs_prefix == "Stairwell.IPAddress"
    assert results.outputs.get("ip") == "1.2.3.4"


def test_ipaddress_lookup_cloud_provider_command_success(requests_mock):
    """Test IP address lookup cloud provider command with successful response"""
    mock_response = {
        "ip": "1.2.3.4",
        "cloud_provider": "AWS",
        "region": "us-east-1"
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/ipaddress/1.2.3.4/cloudprovider", json=mock_response)
    
    results = ipaddress_lookup_cloud_provider_command(test_client_network, "1.2.3.4")
    
    assert results
    assert results.outputs_prefix == "Stairwell.IPAddress.CloudProvider"
    assert results.outputs.get("cloud_provider") == "AWS"


def test_ipaddress_get_hostnames_resolving_to_ip_command_success(requests_mock):
    """Test IP address get hostnames resolving to IP command with successful response"""
    mock_response = {
        "hostnames": ["example.com", "www.example.com"]
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/ipaddress/1.2.3.4/hostnames", json=mock_response)
    
    results = ipaddress_get_hostnames_resolving_to_ip_command(test_client_network, "1.2.3.4")
    
    assert results
    assert results.outputs_prefix == "Stairwell.IPAddress.Hostnames"
    assert len(results.outputs.get("hostnames", [])) == 2


def test_ipaddress_get_whois_command_success(requests_mock):
    """Test IP address get whois command with successful response"""
    mock_response = {
        "ip": "1.2.3.4",
        "organization": "Test Org",
        "country": "US"
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/ipaddress/1.2.3.4/whois", json=mock_response)
    
    results = ipaddress_get_whois_command(test_client_network, "1.2.3.4")
    
    assert results
    assert results.outputs_prefix == "Stairwell.IPAddress.WHOIS"
    assert results.outputs.get("ip") == "1.2.3.4"


# Network Intel Tests - Utilities
def test_utilities_get_cloud_ip_ranges_command_success(requests_mock):
    """Test utilities get cloud IP ranges command with successful response"""
    mock_response = {
        "ranges": [
            {"cidr": "1.2.3.0/24", "provider": "AWS"},
            {"cidr": "5.6.7.0/24", "provider": "GCP"}
        ]
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/utilities/cloudipranges", json=mock_response)
    
    results = utilities_get_cloud_ip_ranges_command(test_client_network)
    
    assert results
    assert results.outputs_prefix == "Stairwell.Utilities.CloudIPRanges"
    assert len(results.outputs.get("ranges", [])) == 2


def test_utilities_batch_canonicalize_hostnames_command_success(requests_mock):
    """Test utilities batch canonicalize hostnames command with successful response"""
    mock_response = {
        "results": {
            "EXAMPLE.COM": "example.com",
            "WWW.TEST.COM": "www.test.com"
        }
    }
    
    requests_mock.post("https://app.stairwell.com/v1/network/utilities/batch/canonicalizehostnames", json=mock_response)
    
    results = utilities_batch_canonicalize_hostnames_command(test_client_network, "EXAMPLE.COM,WWW.TEST.COM")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedHostnames"


def test_utilities_batch_compute_etld_plus_one_command_success(requests_mock):
    """Test utilities batch compute ETLD+1 command with successful response"""
    mock_response = {
        "results": {
            "subdomain.example.com": "example.com",
            "www.test.co.uk": "test.co.uk"
        }
    }
    
    requests_mock.post("https://app.stairwell.com/v1/network/utilities/batch/computeetldplusone", json=mock_response)
    
    results = utilities_batch_compute_etld_plus_one_command(test_client_network, "subdomain.example.com,www.test.co.uk")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Utilities.ETLDPlusOne"


def test_utilities_canonicalize_hostname_command_success(requests_mock):
    """Test utilities canonicalize hostname command with successful response"""
    mock_response = {
        "original": "EXAMPLE.COM",
        "canonicalized": "example.com"
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/utilities/canonicalizehostname?hostname=EXAMPLE.COM", json=mock_response)
    
    results = utilities_canonicalize_hostname_command(test_client_network, "EXAMPLE.COM")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedHostname"
    assert results.outputs.get("canonicalized") == "example.com"


def test_utilities_compute_etld_plus_one_command_success(requests_mock):
    """Test utilities compute ETLD+1 command with successful response"""
    mock_response = {
        "domain": "subdomain.example.com",
        "etld_plus_one": "example.com"
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/utilities/computeetldplusone?domain=subdomain.example.com", json=mock_response)
    
    results = utilities_compute_etld_plus_one_command(test_client_network, "subdomain.example.com")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Utilities.ETLDPlusOne"
    assert results.outputs.get("etld_plus_one") == "example.com"


def test_utilities_batch_canonicalize_urls_command_success(requests_mock):
    """Test utilities batch canonicalize URLs command with successful response"""
    mock_response = {
        "results": {
            "HTTPS://EXAMPLE.COM/PATH": "https://example.com/path",
            "HTTP://TEST.COM/": "http://test.com/"
        }
    }
    
    requests_mock.post("https://app.stairwell.com/v1/network/utilities/batch/canonicalizeurls", json=mock_response)
    
    results = utilities_batch_canonicalize_urls_command(test_client_network, "HTTPS://EXAMPLE.COM/PATH,HTTP://TEST.COM/")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedURLs"


def test_utilities_canonicalize_url_command_success(requests_mock):
    """Test utilities canonicalize URL command with successful response"""
    mock_response = {
        "original": "HTTPS://EXAMPLE.COM/PATH",
        "canonicalized": "https://example.com/path"
    }
    
    requests_mock.get("https://app.stairwell.com/v1/network/utilities/canonicalizeurl?url=HTTPS://EXAMPLE.COM/PATH", json=mock_response)
    
    results = utilities_canonicalize_url_command(test_client_network, "HTTPS://EXAMPLE.COM/PATH")
    
    assert results
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedURL"
    assert results.outputs.get("canonicalized") == "https://example.com/path"
