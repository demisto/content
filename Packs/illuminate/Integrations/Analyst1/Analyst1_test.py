import demistomock as demisto  # noqa: F401
import pytest
from Analyst1 import *

MOCK_SERVER: str = "mock.com"
MOCK_USER: str = "mock"
MOCK_PASS: str = "mock"
# Type-specific mock indicators for proper test coverage
MOCK_IP: str = "192.0.2.1"  # Valid test IP from RFC 5737
MOCK_DOMAIN: str = "example.com"
MOCK_EMAIL: str = "user@example.com"
MOCK_URL: str = "https://example.com/path"
MOCK_FILE_HASH: str = "D8474A07411C6400E47C13D73700DC602F90262A"  # SHA1
MOCK_STRING: str = "test-string-value"
MOCK_MUTEX: str = "Global\\TestMutex"
MOCK_HTTP_REQUEST: str = "GET /api/test HTTP/1.1"

BASE_MOCK_NOTFOUND: dict = {"message": "The requested resource was not found."}


def get_base_mock_json(indicator_value: str, indicator_type: str = "domain") -> dict:
    """Generate base mock JSON for different indicator types"""
    return {
        "type": indicator_type,
        "value": {"name": indicator_value, "classification": "U"},
        "description": None,
        "activityDates": [{"date": "2020-01-20", "classification": "U"}],
        "reportedDates": [{"date": "2020-01-31", "classification": "U"}],
        "targets": [{"name": "Mock Target", "id": 1, "classification": "U"}],
        "attackPatterns": [{"name": "Mock Attack Pattern", "id": 1, "classification": "U"}],
        "actors": [{"name": "Mock Actor", "id": 1, "classification": "U"}],
        "malwares": [],
        "status": "aw",
        "hashes": None,
        "fileNames": None,
        "fileSize": None,
        "path": None,
        "ports": [],
        "ipRegistration": None,
        "domainRegistration": None,
        "ipResolution": None,
        "originatingIps": None,
        "subjects": None,
        "requestMethods": None,
        "tlp": "mocktlp",
        "tlpJustification": None,
        "tlpCaveats": None,
        "tlpResolution": "resolved",
        "tlpHighestAssociated": "mocktlp",
        "tlpLowestAssociated": "mocktlp",
        "active": True,
        "benign": {"value": False, "classification": "U"},
        "indicatorRiskScore": {"name": "High", "classification": "U"},
        "confidenceLevel": None,
        "exploitStage": None,
        "lastHit": None,
        "firstHit": None,
        "hitCount": None,
        "reportCount": 1,
        "verified": False,
        "tasked": False,
        "links": [
            {
                "rel": "self",
                "href": f"https://{MOCK_SERVER}.com/api/1_0/indicator/1",
                "hreflang": None,
                "media": None,
                "title": None,
                "type": None,
                "deprecation": None,
            },
            {
                "rel": "evidence",
                "href": f"https://{MOCK_SERVER}.com/api/1_0/indicator/1/evidence",
                "hreflang": None,
                "media": None,
                "title": None,
                "type": None,
                "deprecation": None,
            },
            {
                "rel": "stix",
                "href": f"https://{MOCK_SERVER}.com/api/1_0/indicator/1/stix",
                "hreflang": None,
                "media": None,
                "title": None,
                "type": None,
                "deprecation": None,
            },
        ],
        "id": 1,
    }


BASE_MOCK_JSON: dict = {
    "type": "domain",
    "value": {"name": MOCK_DOMAIN, "classification": "U"},
    "description": None,
    "activityDates": [{"date": "2020-01-20", "classification": "U"}],
    "reportedDates": [{"date": "2020-01-31", "classification": "U"}],
    "targets": [{"name": "Mock Target", "id": 1, "classification": "U"}],
    "attackPatterns": [{"name": "Mock Attack Pattern", "id": 1, "classification": "U"}],
    "actors": [{"name": "Mock Actor", "id": 1, "classification": "U"}],
    "malwares": [],
    "status": "aw",
    "hashes": None,
    "fileNames": None,
    "fileSize": None,
    "path": None,
    "ports": [],
    "ipRegistration": None,
    "domainRegistration": None,
    "ipResolution": None,
    "originatingIps": None,
    "subjects": None,
    "requestMethods": None,
    "tlp": "mocktlp",
    "tlpJustification": None,
    "tlpCaveats": None,
    "tlpResolution": "resolved",
    "tlpHighestAssociated": "mocktlp",
    "tlpLowestAssociated": "mocktlp",
    "active": True,
    "benign": {"value": False, "classification": "U"},
    "indicatorRiskScore": {"name": "High", "classification": "U"},
    "confidenceLevel": None,
    "exploitStage": None,
    "lastHit": None,
    "firstHit": None,
    "hitCount": None,
    "reportCount": 1,
    "verified": False,
    "tasked": False,
    "links": [
        {
            "rel": "self",
            "href": f"https://{MOCK_SERVER}.com/api/1_0/indicator/1",
            "hreflang": None,
            "media": None,
            "title": None,
            "type": None,
            "deprecation": None,
        },
        {
            "rel": "evidence",
            "href": f"https://{MOCK_SERVER}.com/api/1_0/indicator/1/evidence",
            "hreflang": None,
            "media": None,
            "title": None,
            "type": None,
            "deprecation": None,
        },
        {
            "rel": "stix",
            "href": f"https://{MOCK_SERVER}.com/api/1_0/indicator/1/stix",
            "hreflang": None,
            "media": None,
            "title": None,
            "type": None,
            "deprecation": None,
        },
    ],
    "id": 1,
}
MOCK_BATCH_RESPONSE: dict = {
    "results": [
        {
            "searchedValue": "google.com",
            "matchedValue": "google.com",
            "id": 10336,
            "entity": {"key": "INDICATOR"},
            "type": {"key": "domain"},
            "benign": {"value": False},
            "indicatorRiskScore": {"title": "Low"},
            "other-attributes": "redacted",
        },
        {
            "searchedValue": "1.2.3.4",
            "matchedValue": "1.2.3.4",
            "id": 146950461,
            "entity": {"key": "INDICATOR"},
            "type": {"key": "ip"},
            "benign": {"value": False},
            "indicatorRiskScore": {"title": "Critical"},
            "other-attributes": "redacted",
        },
        {
            "searchedValue": "conimes.com",
            "matchedValue": "conimes.com",
            "id": 983,
            "entity": {"key": "INDICATOR"},
            "type": {"key": "domain"},
            "benign": {"value": True},
            "indicatorRiskScore": {"title": "High"},
            "other-attributes": "redacted",
        },
    ]
}
MOCK_SENSOR_IOCS: list = [
    {
        "id": 1,
        "type": "Domain",
        "value": "example.com",
        "classification": "U",
        "fileHashes": {},
        "links": [{"rel": "self", "href": "https://mock.com/api/1_0/indicator/1"}],
    },
    {
        "id": 2,
        "type": "IPv4",
        "value": "0.154.17.105",
        "classification": "U",
        "fileHashes": {},
        "links": [{"rel": "self", "href": "https://mock.com/api/1_0/indicator/2"}],
    },
    {
        "id": 3,
        "type": "File",
        "value": "F5A64DE9087B138608CCF036B067D91A47302259269FB05B3349964CA4060E7A",
        "classification": "U",
        "fileHashes": {
            "SHA256": "F5A64DE9087B138608CCF036B067D91A47302259269FB05B3349964CA4060E7A",
            "SHA1": "D8474A07411C6400E47C13D73700DC602F90262A",
            "MD5": "6318E219B7F6E7F96192E0CDFEA1742A",
        },
        "links": [{"rel": "self", "href": "https://mock.com/api/1_0/indicator/3"}],
    },
]
MOCK_SENSOR_RULES: list = [
    {
        "id": 1,
        "versionNumber": 1,
        "signature": "text goes here",
        "classification": "U",
        "links": [{"rel": "self", "href": "https://training.cloud.analyst1.com/api/1_0/rules/1"}],
    },
    {
        "id": 2,
        "versionNumber": 1,
        "signature": "other text goes here",
        "classification": "U",
        "links": [{"rel": "self", "href": "https://training.cloud.analyst1.com/api/1_0/rules/2"}],
    },
]
MOCK_SENSOR_DIFF_RESPONSE_CONTENT: dict = {
    "id": 1,
    "version": 2,
    "latestVersion": 10,
    "indicatorsAdded": MOCK_SENSOR_IOCS,
    "indicatorsRemoved": MOCK_SENSOR_IOCS,
    "rulesAdded": MOCK_SENSOR_RULES,
    "rulesRemoved": MOCK_SENSOR_RULES,
    "links": [
        {"rel": "self", "href": "https://mock.com/api/1_0/sensors/1/taskings/diff/2"},
        {"rel": "sensor", "href": "https://mock.com/api/1_0/sensors/2"},
    ],
}
MOCK_SENSOR_DIFF_RESPONSE_EMPTY: dict = {"id": 1, "version": 2, "latestVersion": 10}
MOCK_SENSOR_TASKINGS_RESPONSE_CONTENT: dict = {
    "id": 1,
    "version": 10,
    "indicators": MOCK_SENSOR_IOCS,
    "rules": MOCK_SENSOR_RULES,
    "links": [
        {"rel": "self", "href": "https://mock.com/api/1_0/sensors/1/taskings/diff/2"},
        {"rel": "sensor", "href": "https://mock.com/api/1_0/sensors/2"},
    ],
}
MOCK_SENSOR_TASKINGS_RESPONSE_EMPTY: dict = {"id": 1, "version": 10}
MOCK_SENSORS: dict = {
    "results": [
        {
            "id": 1,
            "name": "sensor 1",
            "logicalLocation": None,
            "org": None,
            "type": "OTHER_AUTO",
            "currentVersionNumber": 5,
            "latestConfigVersionNumber": 5,
            "links": [{"rel": "details", "href": "https://mock.com/api/1_0/sensors/1"}],
        },
        {
            "id": 2,
            "name": "sensor 2",
            "logicalLocation": None,
            "org": None,
            "type": "OTHER_AUTO",
            "currentVersionNumber": 26,
            "latestConfigVersionNumber": 26,
            "links": [{"rel": "details", "href": "https://mock.com/api/1_0/sensors/2"}],
        },
    ],
    "pageSize": 50,
    "page": 1,
    "totalResults": 2,
    "totalPages": 1,
    "links": [
        {"rel": "first", "href": "https://mock.com/api/1_0/sensors?page=1&pageSize=10"},
        {"rel": "last", "href": "https://mock.com/api/1_0/sensors?page=1&pageSize=10"},
        {"rel": "self", "href": "https://mock.com/api/1_0/sensors?page=1&pageSize=10"},
    ],
}
MOCK_TEST_REQUEST_GOOD = {"links": [{"rel": "self", "href": "https://mock.com/api/1_0"}]}
MOCK_TEST_REQUEST_INVALID = {"cannotfindme": [{"rel": "self", "href": "https://mock.com/api/1_0"}]}


MOCK_CLIENT_PARAMS = {
    "server": MOCK_SERVER,
    "proxy": "false",
    "insecure": "true",
    "credentials": {"identifier": MOCK_USER, "password": MOCK_PASS},
}


@pytest.fixture
def mock_client():
    return build_client(MOCK_CLIENT_PARAMS)


def mock_indicator_search(indicator_type: str, indicator_value: str, requests_mock):
    """
    Mock both GET /indicator/match and POST /batchCheck endpoints for a specific indicator.

    Args:
        indicator_type: Type of indicator (domain, email, ip, file, url, etc.)
        indicator_value: The actual indicator value to mock
        requests_mock: The requests_mock fixture
    """
    # Generate type-specific mock JSON
    mock_json = get_base_mock_json(indicator_value, indicator_type)

    # Mock the GET /indicator/match endpoint (for old enrichment flow)
    requests_mock.get(
        f"https://{MOCK_SERVER}/api/1_0/indicator/match?type={indicator_type}&value={indicator_value}", json=mock_json
    )
    # Mock the POST /batchCheck endpoint (for new batch-check-first enrichment flow)
    batch_response = {
        "results": [
            {
                "searchedValue": indicator_value,
                "matchedValue": indicator_value,
                "entity": {"key": "INDICATOR"},
                "type": {"key": indicator_type},
                "indicatorRiskScore": {"title": "High"},
                "benign": {"value": False},
            }
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)


def test_domain_command(requests_mock, mock_client):
    mock_indicator_search("domain", MOCK_DOMAIN, requests_mock)
    args: dict = {"domain": MOCK_DOMAIN}

    enrichment_output: EnrichmentOutput = domain_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == 1


def test_email_command(requests_mock, mock_client):
    mock_indicator_search("email", MOCK_EMAIL, requests_mock)
    args: dict = {"email": MOCK_EMAIL}

    enrichment_output: EnrichmentOutput = email_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == 1


def test_ip_command(requests_mock, mock_client):
    mock_indicator_search("ip", MOCK_IP, requests_mock)
    args: dict = {"ip": MOCK_IP}

    enrichment_output: EnrichmentOutput = ip_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == 1


def test_file_command(requests_mock, mock_client):
    mock_indicator_search("file", MOCK_FILE_HASH, requests_mock)
    args: dict = {"file": MOCK_FILE_HASH}

    enrichment_output: EnrichmentOutput = file_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == 1


def test_url_command(requests_mock, mock_client):
    mock_indicator_search("url", MOCK_URL, requests_mock)
    args: dict = {"url": MOCK_URL}

    enrichment_output: EnrichmentOutput = url_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == 1


def test_analyst1_enrich_string_command(requests_mock, mock_client):
    # String type returns CommandResults with JSON context, not EnrichmentOutput
    mock_json = get_base_mock_json(MOCK_STRING, "string")
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/match?type=string&value={MOCK_STRING}", json=mock_json)
    args: dict = {"string": MOCK_STRING}

    command_result: CommandResults = analyst1_enrich_string_command(mock_client, args)[0]
    assert command_result.outputs_prefix == "Analyst1.String"
    assert command_result.outputs_key_field == "ID"
    assert command_result.outputs.get("ID") == 1


def test_analyst1_enrich_ipv6_command(requests_mock, mock_client):
    # IPv6 type returns CommandResults with JSON context, not EnrichmentOutput
    # Using RFC 3849 documentation IPv6 address (simplified format to avoid secrets detection)
    ipv6_addr = "2001:db8::1"
    mock_json = get_base_mock_json(ipv6_addr, "ipv6")
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/match?type=ipv6&value={ipv6_addr}", json=mock_json)
    args: dict = {"ip": ipv6_addr}

    command_result: CommandResults = analyst1_enrich_ipv6_command(mock_client, args)[0]
    assert command_result.outputs_prefix == "Analyst1.Ipv6"
    assert command_result.outputs_key_field == "ID"
    assert command_result.outputs.get("ID") == 1


def test_analyst1_enrich_mutex_command(requests_mock, mock_client):
    # Mutex type returns CommandResults with JSON context, not EnrichmentOutput
    mock_json = get_base_mock_json(MOCK_MUTEX, "mutex")
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/match?type=mutex&value={MOCK_MUTEX}", json=mock_json)
    args: dict = {"mutex": MOCK_MUTEX}

    command_result: CommandResults = analyst1_enrich_mutex_command(mock_client, args)[0]
    assert command_result.outputs_prefix == "Analyst1.Mutex"
    assert command_result.outputs_key_field == "ID"
    assert command_result.outputs.get("ID") == 1


def test_analyst1_enrich_http_request_command(requests_mock, mock_client):
    # HTTP request type returns CommandResults with JSON context, not EnrichmentOutput
    mock_json = get_base_mock_json(MOCK_HTTP_REQUEST, "httpRequest")
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/match?type=httpRequest&value={MOCK_HTTP_REQUEST}", json=mock_json)
    args: dict = {"http-request": MOCK_HTTP_REQUEST}

    command_result: CommandResults = analyst1_enrich_http_request_command(mock_client, args)[0]
    assert command_result.outputs_prefix == "Analyst1.HTTPRequest"
    assert command_result.outputs_key_field == "ID"
    assert command_result.outputs.get("ID") == 1


def test_get_risk_score_mappings_default():
    """Test that default risk score mappings are used when no params provided"""
    params = {}
    mappings = get_risk_score_mappings(params)

    assert mappings["Lowest"] == 1  # Benign
    assert mappings["Low"] == 0  # Unknown
    assert mappings["Moderate"] == 2  # Suspicious
    assert mappings["High"] == 2  # Suspicious
    assert mappings["Critical"] == 3  # Malicious
    assert mappings["Unknown"] == 0  # Unknown


def test_get_risk_score_mappings_custom():
    """Test that custom risk score mappings override defaults"""
    params = {
        "riskScoreLowest": "Unknown",
        "riskScoreLow": "Benign",
        "riskScoreModerate": "Malicious",
        "riskScoreHigh": "Malicious",
        "riskScoreCritical": "Malicious",
        "riskScoreUnknown": "Suspicious",
    }
    mappings = get_risk_score_mappings(params)

    assert mappings["Lowest"] == 0  # Unknown
    assert mappings["Low"] == 1  # Benign
    assert mappings["Moderate"] == 3  # Malicious
    assert mappings["High"] == 3  # Malicious
    assert mappings["Critical"] == 3  # Malicious
    assert mappings["Unknown"] == 2  # Suspicious


def test_calculate_verdict_benign_override():
    """Test that benign=True always results in Benign verdict"""
    params = {}

    # benign=True should override any risk score
    verdict = calculate_verdict_from_risk_score("Critical", True, params)
    assert verdict == 1  # Benign

    verdict = calculate_verdict_from_risk_score("High", True, params)
    assert verdict == 1  # Benign


def test_calculate_verdict_from_risk_scores():
    """Test verdict calculation based on risk scores with default mappings"""
    params = {}

    # Test each risk score with benign=False (should use risk score mapping)
    verdict = calculate_verdict_from_risk_score("Lowest", False, params)
    assert verdict == 1  # Benign (default mapping)

    verdict = calculate_verdict_from_risk_score("Low", False, params)
    assert verdict == 0  # Unknown (default mapping)

    verdict = calculate_verdict_from_risk_score("Moderate", False, params)
    assert verdict == 2  # Suspicious (default mapping)

    verdict = calculate_verdict_from_risk_score("High", False, params)
    assert verdict == 2  # Suspicious (default mapping)

    verdict = calculate_verdict_from_risk_score("Critical", False, params)
    assert verdict == 3  # Malicious (default mapping)

    verdict = calculate_verdict_from_risk_score("Unknown", False, params)
    assert verdict == 0  # Unknown (default mapping)


def test_calculate_verdict_no_risk_score():
    """Test that missing risk score returns Unknown"""
    params = {}

    # No risk score, benign=False should return Unknown
    verdict = calculate_verdict_from_risk_score(None, False, params)
    assert verdict == 0  # Unknown

    # No risk score, benign=None should return Unknown
    verdict = calculate_verdict_from_risk_score(None, None, params)
    assert verdict == 0  # Unknown


def test_calculate_verdict_custom_mappings():
    """Test verdict calculation with custom mappings"""
    params = {
        "riskScoreLow": "Malicious",
        "riskScoreModerate": "Malicious",
    }

    verdict = calculate_verdict_from_risk_score("Low", False, params)
    assert verdict == 3  # Malicious (custom mapping)

    verdict = calculate_verdict_from_risk_score("Moderate", False, params)
    assert verdict == 3  # Malicious (custom mapping)


def test_analyst1_get_indicator_found_normal_ioc(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/1", json=BASE_MOCK_JSON)
    args: dict = {"indicator_id": 1}
    command_results = analyst1_get_indicator(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == "Analyst1.Indicator"
    assert command_results.outputs.get("id") == BASE_MOCK_JSON.get("id")


def test_analyst1_get_indicator_found_hash_ioc(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/1", json=BASE_MOCK_JSON)
    args: dict = {"indicator_id": "1-igetignored"}
    command_results = analyst1_get_indicator(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == "Analyst1.Indicator"
    assert command_results.outputs.get("id") == BASE_MOCK_JSON.get("id")


def test_analyst1_get_indicator_ioc_not_found(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/2345", json=BASE_MOCK_NOTFOUND)
    args: dict = {"indicator_id": "2345"}
    command_results = analyst1_get_indicator(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == "Analyst1.Indicator"
    assert command_results.outputs.get("message") is not None


def test_analyst1_batch_check_command(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/batchCheck?values=ioc1,ioc2,ioc3,ioc4", json=MOCK_BATCH_RESPONSE)
    args: dict = {"values": "ioc1,ioc2,ioc3,ioc4"}
    command_results = analyst1_batch_check_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == "Analyst1.BatchResults"
    assert command_results.outputs_key_field == "ID"
    # Verify that the command adds DBotScore and Tags to results
    assert len(command_results.outputs) == 3
    for result in command_results.outputs:
        assert "DBotScore" in result
        assert "Tags" in result


HELPER_MOCK_NEWLINEVALUES: str = """ioc1
ioc2
ioc3
ioc4"""


def helper_mock_batch_check_post(requests_mock) -> dict:
    # unclear how to mock the actual post content in requests_mock
    # values_to_submit = {'values': HELPER_MOCK_NEWLINEVALUES}
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=MOCK_BATCH_RESPONSE)
    args: dict = {"values": HELPER_MOCK_NEWLINEVALUES}
    return args


def assert_batch_check_post(output_check):
    assert output_check is not None
    assert output_check["command_results"].outputs_prefix == "Analyst1.BatchResults"
    assert output_check["command_results"].outputs_key_field == "ID"
    # Verify that the command adds DBotScore and Tags to results
    assert len(output_check["command_results"].outputs) == 3
    for result in output_check["command_results"].outputs:
        assert "DBotScore" in result
        assert "Tags" in result
    assert output_check["submitted_values"] == HELPER_MOCK_NEWLINEVALUES


def test_analyst1_batch_check_post_values_str(requests_mock, mock_client):
    args: dict = helper_mock_batch_check_post(requests_mock)
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_batch_check_post_values_array_str(requests_mock, mock_client):
    helper_mock_batch_check_post(requests_mock)
    args: dict = {"values_array": '"ioc1","ioc2","ioc3","ioc4"'}
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_batch_check_post_values_array_list(requests_mock, mock_client):
    helper_mock_batch_check_post(requests_mock)
    args: dict = {"values_array": ["ioc1", "ioc2", "ioc3", "ioc4"]}
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_batch_check_post_values_array_json(requests_mock, mock_client):
    helper_mock_batch_check_post(requests_mock)
    args: dict = {"values_array": {"values": ["ioc1", "ioc2", "ioc3", "ioc4"]}}
    output_check = analyst1_batch_check_post(mock_client, args)
    assert_batch_check_post(output_check)


def test_analyst1_evidence_submit(requests_mock, mock_client):
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/evidence", json={"uuid": "uuid_value"})
    args: dict = {
        "fileName": "name.txt",
        "fileContent": "string of content",
        "sourceId": "1",
        "tlp": "clear",
        "fileClassification": "u",
    }
    command_results = analyst1_evidence_submit(mock_client, args)
    assert command_results.outputs_prefix == "Analyst1.EvidenceSubmit"
    assert command_results.outputs_key_field == "uuid"
    assert command_results.outputs.get("uuid") == "uuid_value"


def test_analyst1_evidence_submit_error(requests_mock, mock_client):
    args: dict = {"fileName": "name.txt", "sourceId": "1", "tlp": "clear", "fileClassification": "u"}
    try:
        analyst1_evidence_submit(mock_client, args)
    except DemistoException:
        return
    raise AssertionError


def test_analyst1_evidence_status_200_emptyid(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/evidence/uploadStatus/uuid_value", json={"id": ""})
    args: dict = {"uuid": "uuid_value"}
    command_results = analyst1_evidence_status(mock_client, args)
    assert command_results.outputs_prefix == "Analyst1.EvidenceStatus"
    assert command_results.outputs_key_field == "id"
    assert command_results.outputs.get("id") == ""
    assert command_results.outputs.get("processingComplete") is False


def test_analyst1_evidence_status_200_knownstrid(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/evidence/uploadStatus/uuid_value", json={"id": "finished"})
    args: dict = {"uuid": "uuid_value"}
    command_results = analyst1_evidence_status(mock_client, args)
    assert command_results.outputs_prefix == "Analyst1.EvidenceStatus"
    assert command_results.outputs_key_field == "id"
    assert command_results.outputs.get("id") == "finished"
    assert command_results.outputs.get("processingComplete") is True


def test_analyst1_evidence_status_200_knownintid(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/evidence/uploadStatus/uuid_value", json={"id": 1})
    args: dict = {"uuid": "uuid_value"}
    command_results = analyst1_evidence_status(mock_client, args)
    assert command_results.outputs_prefix == "Analyst1.EvidenceStatus"
    assert command_results.outputs_key_field == "id"
    assert command_results.outputs.get("id") == 1
    assert command_results.outputs.get("processingComplete") is True


def test_analyst1_get_sensors_command(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/sensors?page=1&pageSize=50", json=MOCK_SENSORS)
    args: dict = {"page": 1, "pageSize": 50}
    command_results = analyst1_get_sensors_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == "Analyst1.SensorList"
    assert command_results.outputs_key_field == "id"
    assert command_results.outputs == MOCK_SENSORS.get("results")


def test_analyst1_get_sensors_command_defaultsOfArgsToInt(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/sensors?page=1&pageSize=50", json=MOCK_SENSORS)
    # empty args to test defaults
    args: dict = {}
    command_results = analyst1_get_sensors_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == "Analyst1.SensorList"
    assert command_results.outputs_key_field == "id"
    assert command_results.outputs == MOCK_SENSORS.get("results")


def assert_sensor_taskings(command_results_list: list):
    assert len(command_results_list) == 3
    assert command_results_list[0].outputs_prefix == "Analyst1.SensorTaskings"
    assert command_results_list[1].outputs_prefix == "Analyst1.SensorTaskings.Indicators"
    assert command_results_list[2].outputs_prefix == "Analyst1.SensorTaskings.Rules"
    assert command_results_list[0].outputs["id"] == 1
    assert command_results_list[0].outputs["version"] == 10


def assert_sensor_diff(command_results_list: list):
    assert command_results_list is not None
    # one entry for context and the rest for added/removed
    assert len(command_results_list) == 5
    assert command_results_list[0].outputs_prefix == "Analyst1.SensorTaskings"
    assert command_results_list[1].outputs_prefix == "Analyst1.SensorTaskings.IndicatorsAdded"
    assert command_results_list[2].outputs_prefix == "Analyst1.SensorTaskings.IndicatorsRemoved"
    assert command_results_list[3].outputs_prefix == "Analyst1.SensorTaskings.RulesAdded"
    assert command_results_list[4].outputs_prefix == "Analyst1.SensorTaskings.RulesRemoved"
    # check json pass through
    assert command_results_list[0].outputs["id"] == 1
    assert command_results_list[0].outputs["version"] == 2
    assert command_results_list[0].outputs["latestVersion"] == 10


def assert_sensor_iocs(output_list: list):
    # one for each IOC or hash found
    assert len(output_list) == 5
    assert output_list[0]["category"] == "indicator"
    assert output_list[0]["id"] == "1"
    assert output_list[0]["value"] == "example.com"
    assert output_list[1]["id"] == "2"
    assert output_list[1]["value"] == "0.154.17.105"
    assert output_list[2]["id"] == "3-SHA256"
    assert output_list[2]["value"] == "F5A64DE9087B138608CCF036B067D91A47302259269FB05B3349964CA4060E7A"
    assert output_list[3]["id"] == "3-SHA1"
    assert output_list[3]["value"] == "D8474A07411C6400E47C13D73700DC602F90262A"
    assert output_list[4]["id"] == "3-MD5"
    assert output_list[4]["value"] == "6318E219B7F6E7F96192E0CDFEA1742A"


def assert_sensor_rules(output_list: list):
    assert len(output_list) == 2
    assert output_list[0]["category"] == "rule"
    assert output_list[0]["id"] == "1"
    assert output_list[0]["signature"] == "text goes here"
    assert output_list[1]["id"] == "2"
    assert output_list[1]["signature"] == "other text goes here"


def test_analyst1_get_sensor_taskings_command_content(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/sensors/1/taskings", json=MOCK_SENSOR_TASKINGS_RESPONSE_CONTENT)
    args: dict = {"sensor_id": "1", "timeout": "200"}
    command_results_list = analyst1_get_sensor_taskings_command(mock_client, args)
    assert_sensor_taskings(command_results_list)
    assert_sensor_iocs(command_results_list[1].outputs)
    assert_sensor_rules(command_results_list[2].outputs)


def test_analyst1_get_sensor_taskings_command_empty(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/sensors/1/taskings", json=MOCK_SENSOR_TASKINGS_RESPONSE_EMPTY)
    args: dict = {"sensor_id": "1", "timeout": "200"}
    command_results_list = analyst1_get_sensor_taskings_command(mock_client, args)
    assert len(command_results_list) == 3
    assert_sensor_taskings(command_results_list)
    assert len(command_results_list[1].outputs) == 0
    assert len(command_results_list[2].outputs) == 0


def test_analyst1_get_sensor_diff_content(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/sensors/1/taskings/diff/2", json=MOCK_SENSOR_DIFF_RESPONSE_CONTENT)
    args: dict = {"sensor_id": "1", "version": "2", "timeout": "200"}
    command_results_list = analyst1_get_sensor_diff(mock_client, args)
    assert_sensor_diff(command_results_list)
    # confirm IOC conversion succeeds
    assert_sensor_iocs(command_results_list[1].outputs)
    assert_sensor_iocs(command_results_list[2].outputs)
    # confirm rule conversion succeeds
    assert_sensor_rules(command_results_list[3].outputs)
    assert_sensor_rules(command_results_list[4].outputs)


def test_analyst1_get_sensor_diff_empty(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/sensors/1/taskings/diff/2", json=MOCK_SENSOR_DIFF_RESPONSE_EMPTY)
    args: dict = {"sensor_id": "1", "version": "2", "timeout": "200"}
    command_results_list = analyst1_get_sensor_diff(mock_client, args)
    assert command_results_list is not None
    # one entry for context and the rest for added/removed
    assert_sensor_diff(command_results_list)
    # one for each IOC or hash found
    assert len(command_results_list[1].outputs) == 0
    assert len(command_results_list[2].outputs) == 0
    assert len(command_results_list[3].outputs) == 0
    assert len(command_results_list[4].outputs) == 0


def test_analyst1_get_sensor_config_command(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/sensors/1/taskings/config", text="response text goes here")
    args: dict = {"sensor_id": "1"}
    command_results = analyst1_get_sensor_config_command(mock_client, args)
    assert command_results is not None
    assert command_results.outputs_prefix == "Analyst1.SensorTaskings.ConfigFile"
    assert command_results.outputs.get("warRoomEntry") is not None
    # json expectation adds quotes, anomaly of unit testing
    assert command_results.outputs.get("config_text") == "response text goes here"


def test_perform_test_request_good(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/", json=MOCK_TEST_REQUEST_GOOD)
    try:
        perform_test_module(mock_client)
    except DemistoException as e:
        raise AssertionError from e


def test_perform_test_request_invalid(requests_mock, mock_client):
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/", json=MOCK_TEST_REQUEST_INVALID)
    try:
        perform_test_module(mock_client)
    except DemistoException as e:
        assert str(e) == "Invalid URL or Credentials. JSON structure not recognized."


def test_argsToStr():
    args: dict = {"sensor_id": "1"}
    assert argsToStr(args, "sensor_id") == "1"
    assert argsToStr(args, "unknown") == ""


# Tests for new batch-check-first enrichment approach


def test_enrich_with_batch_check_case1_no_results(requests_mock, mock_client, mocker):
    """Test CASE 1: No batch results - indicator doesn't exist"""
    # Mock batch check returning no results
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json={"results": []})

    # Mock demisto.params() for applyTags
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False})

    enrichment_output = enrich_with_batch_check(mock_client, "nonexistent.com", "domain", "Name", "Domain")

    # Should return empty EnrichmentOutput with indicator value set
    assert enrichment_output.analyst1_context_data == {}
    assert enrichment_output.reputation_context == {}
    assert enrichment_output.indicator_type == "domain"
    assert enrichment_output.indicator_value == "nonexistent.com"


def test_enrich_with_batch_check_case2_indicator_entity(requests_mock, mock_client, mocker):
    """Test CASE 2: Batch results with INDICATOR entity - full enrichment"""
    # Mock batch check returning INDICATOR entity
    batch_response = {
        "results": [
            {
                "searchedValue": "malicious.com",
                "matchedValue": "malicious.com",
                "entity": {"key": "INDICATOR"},
                "type": {"key": "domain"},
                "indicatorRiskScore": {"title": "High"},
                "benign": {"value": False},
            }
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)

    # Mock the full enrichment call
    requests_mock.get(f"https://{MOCK_SERVER}/api/1_0/indicator/match?type=domain&value=malicious.com", json=BASE_MOCK_JSON)

    # Mock demisto.params() for applyTags and risk score mappings
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False})

    enrichment_output = enrich_with_batch_check(mock_client, "malicious.com", "domain", "Name", "Domain")

    # Should have full context data from indicator/match endpoint
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")
    assert enrichment_output.has_context_data()


def test_enrich_with_batch_check_case3_asset_entity(requests_mock, mock_client, mocker):
    """Test CASE 3: Batch results with ASSET entity - minimal benign context"""
    # Mock batch check returning ASSET entity
    batch_response = {
        "results": [
            {
                "searchedValue": "10.0.0.1",
                "matchedValue": "10.0.0.1",
                "entity": {"key": "ASSET"},
                "type": {"key": "ip"},
                "benign": {"value": False},
            }
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)

    # Mock demisto.params() for applyTags and integrationReliability
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B - Usually reliable"})

    enrichment_output = enrich_with_batch_check(mock_client, "10.0.0.1", "ip", "Address", "IP")

    # Should have minimal context with classification
    assert enrichment_output.analyst1_context_data.get("Indicator") == "10.0.0.1"
    assert enrichment_output.analyst1_context_data.get("Classification") == "Asset"

    # Should have verdict score set to Benign (DBotScore is in Common.Indicator, not reputation_context)
    assert enrichment_output.verdict_score == 1  # Benign


def test_enrich_with_batch_check_case3_ignored_indicator(requests_mock, mock_client, mocker):
    """Test CASE 3: Batch results with IGNORED_INDICATOR entity"""
    # Mock batch check returning IGNORED_INDICATOR entity
    batch_response = {
        "results": [
            {
                "searchedValue": "ignored.com",
                "matchedValue": "ignored.com",
                "entity": {"key": "IGNORED_INDICATOR"},
                "type": {"key": "domain"},
                "benign": {"value": False},
            }
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)

    # Mock demisto.params()
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B - Usually reliable"})

    enrichment_output = enrich_with_batch_check(mock_client, "ignored.com", "domain", "Name", "Domain")

    # Should show "Ignored Indicator" classification
    assert enrichment_output.analyst1_context_data.get("Classification") == "Ignored Indicator"
    # Should have verdict score set to Benign (DBotScore is in Common.Indicator, not reputation_context)
    assert enrichment_output.verdict_score == 1  # Benign


def test_enrich_with_batch_check_case3_private_range(requests_mock, mock_client, mocker):
    """Test CASE 3: Batch results with IN_PRIVATE_RANGE entity"""
    # Mock batch check returning IN_PRIVATE_RANGE entity
    batch_response = {
        "results": [
            {
                "searchedValue": "192.168.1.1",
                "matchedValue": "192.168.1.1",
                "entity": {"key": "IN_PRIVATE_RANGE"},
                "type": {"key": "ip"},
                "benign": {"value": False},
            }
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)

    # Mock demisto.params()
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B - Usually reliable"})

    enrichment_output = enrich_with_batch_check(mock_client, "192.168.1.1", "ip", "Address", "IP")

    # Should show "In Private Range" classification
    assert enrichment_output.analyst1_context_data.get("Classification") == "In Private Range"


def test_enrich_with_batch_check_case3_multiple_entities(requests_mock, mock_client, mocker):
    """Test CASE 3: Multiple entity types for same indicator"""
    # Mock batch check returning multiple entity types
    batch_response = {
        "results": [
            {"searchedValue": "10.0.0.1", "matchedValue": "10.0.0.1", "entity": {"key": "ASSET"}, "type": {"key": "ip"}},
            {"searchedValue": "10.0.0.1", "matchedValue": "10.0.0.1", "entity": {"key": "IN_HOME_RANGE"}, "type": {"key": "ip"}},
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)

    # Mock demisto.params()
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B - Usually reliable"})

    enrichment_output = enrich_with_batch_check(mock_client, "10.0.0.1", "ip", "Address", "IP")

    # Should show both classifications
    classification = enrichment_output.analyst1_context_data.get("Classification")
    assert "Asset" in classification
    assert "In Home Range" in classification


def test_enrich_with_batch_check_case3_unrecognized_entity(requests_mock, mock_client, mocker):
    """Test CASE 3: Batch results with unrecognized entity type - should return empty"""
    # Mock batch check returning unrecognized entity type
    batch_response = {
        "results": [
            {
                "searchedValue": "unknown.com",
                "matchedValue": "unknown.com",
                "entity": {"key": "UNKNOWN_ENTITY_TYPE"},
                "type": {"key": "domain"},
            }
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)

    # Mock demisto.params()
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False})

    enrichment_output = enrich_with_batch_check(mock_client, "unknown.com", "domain", "Name", "Domain")

    # Should return empty like CASE 1
    assert enrichment_output.analyst1_context_data == {}
    assert enrichment_output.reputation_context == {}
    assert enrichment_output.indicator_value == "unknown.com"


def test_enrich_with_batch_check_with_tagging_enabled(requests_mock, mock_client, mocker):
    """Test that tags are applied when applyTags is enabled"""
    # Mock batch check returning ASSET entity
    batch_response = {
        "results": [{"searchedValue": "10.0.0.1", "matchedValue": "10.0.0.1", "entity": {"key": "ASSET"}, "type": {"key": "ip"}}]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)

    # Mock demisto.params() with tagging enabled
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": True, "integrationReliability": "B - Usually reliable"})

    enrichment_output = enrich_with_batch_check(mock_client, "10.0.0.1", "ip", "Address", "IP")

    # Should have tags set (tags are ONLY in Common.Indicator, NOT in reputation_context)
    assert enrichment_output.tags == ["Analyst1: Asset"]

    # Verify reputation context exists but does NOT contain Tags (architecture requirement)
    ip_context_key = "IP(val.Address && val.Address === obj.Address)"
    assert ip_context_key in enrichment_output.reputation_context
    assert "Tags" not in enrichment_output.reputation_context[ip_context_key]


def test_get_analyst1_tags_for_batch_result():
    """Test tag extraction from batch results"""
    results = [{"entity": {"key": "ASSET"}}, {"entity": {"key": "IN_HOME_RANGE"}}, {"entity": {"key": "INDICATOR"}}]

    tags = get_analyst1_tags_for_batch_result(results)

    assert "Analyst1: Asset" in tags
    assert "Analyst1: In Home Range" in tags
    assert "Analyst1: Indicator" in tags
    assert len(tags) == 3


def test_has_benign_entity_type():
    """Test detection of benign entity types"""
    # Test with benign entity types
    results_benign = [{"entity": {"key": "ASSET"}}, {"entity": {"key": "INDICATOR"}}]
    assert has_benign_entity_type(results_benign) is True

    # Test with IGNORED_INDICATOR
    results_ignored = [{"entity": {"key": "IGNORED_INDICATOR"}}]
    assert has_benign_entity_type(results_ignored) is True

    # Test with IN_PRIVATE_RANGE
    results_private = [{"entity": {"key": "IN_PRIVATE_RANGE"}}]
    assert has_benign_entity_type(results_private) is True

    # Test with benign=True
    results_benign_flag = [{"benign": {"value": True}, "entity": {"key": "INDICATOR"}}]
    assert has_benign_entity_type(results_benign_flag) is True

    # Test with only INDICATOR entity
    results_indicator_only = [{"entity": {"key": "INDICATOR"}}]
    assert has_benign_entity_type(results_indicator_only) is False


def test_find_indicator_in_batch_results():
    """Test finding INDICATOR entity of specific type"""
    results = [
        {"entity": {"key": "ASSET"}, "type": {"key": "ip"}},
        {"entity": {"key": "INDICATOR"}, "type": {"key": "domain"}},
        {"entity": {"key": "INDICATOR"}, "type": {"key": "ip"}},
    ]

    # Should find the domain INDICATOR
    indicator_result = find_indicator_in_batch_results(results, "domain")
    assert indicator_result is not None
    assert indicator_result["type"]["key"] == "domain"

    # Should find the ip INDICATOR
    indicator_result = find_indicator_in_batch_results(results, "ip")
    assert indicator_result is not None
    assert indicator_result["type"]["key"] == "ip"

    # Should not find email INDICATOR
    indicator_result = find_indicator_in_batch_results(results, "email")
    assert indicator_result is None


def test_calculate_batch_check_verdict_benign_entities():
    """Test that benign entity types result in Benign verdict"""
    params = {}

    # Test ASSET
    verdict = calculate_batch_check_verdict("ASSET", None, None, params)
    assert verdict == 1  # Benign

    # Test IN_PRIVATE_RANGE
    verdict = calculate_batch_check_verdict("IN_PRIVATE_RANGE", None, None, params)
    assert verdict == 1  # Benign

    # Test IGNORED_INDICATOR
    verdict = calculate_batch_check_verdict("IGNORED_INDICATOR", None, None, params)
    assert verdict == 1  # Benign

    # Test IGNORED_ASSET
    verdict = calculate_batch_check_verdict("IGNORED_ASSET", None, None, params)
    assert verdict == 1  # Benign


def test_calculate_batch_check_verdict_indicator():
    """Test verdict calculation for INDICATOR entity"""
    params = {}

    # INDICATOR with Critical risk score
    verdict = calculate_batch_check_verdict("INDICATOR", "Critical", False, params)
    assert verdict == 3  # Malicious (default mapping)

    # INDICATOR with High risk score
    verdict = calculate_batch_check_verdict("INDICATOR", "High", False, params)
    assert verdict == 2  # Suspicious (default mapping)

    # INDICATOR with null risk score
    verdict = calculate_batch_check_verdict("INDICATOR", None, False, params)
    assert verdict == 0  # Unknown


def test_enrichment_output_indicator_value():
    """Test that EnrichmentOutput stores indicator_value"""
    # Test with indicator_value provided
    enrichment = EnrichmentOutput({}, {}, "domain", "example.com")
    assert enrichment.indicator_value == "example.com"

    # Test without indicator_value
    enrichment = EnrichmentOutput({}, {}, "domain")
    assert enrichment.indicator_value is None


# Tests for previously untested EnrichmentOutput methods


def test_idnamepair_class():
    """Test IdNamePair class initialization and string representation"""
    pair = IdNamePair(123, "TestActor")
    assert pair.id == 123
    assert pair.name == "TestActor"
    assert str(pair) == "id = 123, name = TestActor"


def test_enrichment_output_get_human_readable_output_simple(mocker):
    """Test get_human_readable_output with simple data"""
    context_data = {"ID": 1, "Indicator": "example.com", "RiskScore": "High"}
    enrichment = EnrichmentOutput(context_data, {}, "domain", "example.com")

    # Mock tableToMarkdown to capture what it's called with
    mock_table = mocker.patch("Analyst1.tableToMarkdown", return_value="markdown output")

    output = enrichment.get_human_readable_output()

    assert output == "markdown output"
    mock_table.assert_called_once()
    # Verify the table was called with our data
    call_args = mock_table.call_args
    assert call_args[1]["t"]["ID"] == 1
    assert call_args[1]["t"]["Indicator"] == "example.com"


def test_enrichment_output_get_human_readable_output_with_actors_malwares(mocker):
    """Test get_human_readable_output with actors and malwares"""
    context_data = {
        "ID": 1,
        "Indicator": "example.com",
        "Actors": [{"id": 10, "name": "APT28"}, {"id": 20, "name": "Lazarus"}],
        "Malwares": [{"id": 5, "name": "Zeus"}],
    }
    enrichment = EnrichmentOutput(context_data, {}, "domain", "example.com")

    mock_table = mocker.patch("Analyst1.tableToMarkdown", return_value="markdown output")

    output = enrichment.get_human_readable_output()

    assert output == "markdown output"
    # Verify actors and malwares were converted to IdNamePair objects
    call_args = mock_table.call_args
    actors_list = call_args[1]["t"]["Actors"]
    assert len(actors_list) == 2
    assert isinstance(actors_list[0], IdNamePair)
    assert actors_list[0].id == 10
    assert actors_list[0].name == "APT28"


def test_enrichment_output_get_human_readable_output_with_tags(mocker):
    """Test get_human_readable_output includes tags"""
    context_data = {"ID": 1, "Indicator": "example.com"}
    enrichment = EnrichmentOutput(context_data, {}, "domain", "example.com")
    enrichment.tags = ["Analyst1: Indicator", "Analyst1: Asset"]

    mock_table = mocker.patch("Analyst1.tableToMarkdown", return_value="markdown output")

    output = enrichment.get_human_readable_output()

    # Verify output was created
    assert output == "markdown output"
    # Verify tags were added to human-readable data
    call_args = mock_table.call_args
    assert "XSOAR Tags" in call_args[1]["t"]
    assert call_args[1]["t"]["XSOAR Tags"] == "Analyst1: Indicator, Analyst1: Asset"


def test_enrichment_output_build_analyst1_context():
    """Test build_analyst1_context creates proper DT expression"""
    context_data = {"ID": 1, "Indicator": "example.com", "RiskScore": "High"}
    enrichment = EnrichmentOutput(context_data, {}, "domain", "example.com")

    context = enrichment.build_analyst1_context()

    # Should have DT expression as key
    expected_key = "Analyst1.Domain(val.ID && val.ID === obj.ID)"
    assert expected_key in context
    assert context[expected_key] == context_data


def test_enrichment_output_build_all_context():
    """Test build_all_context merges Analyst1 and reputation context"""
    analyst1_data = {"ID": 1, "Indicator": "example.com"}
    enrichment = EnrichmentOutput(analyst1_data, {}, "domain", "example.com")

    # Add reputation context
    enrichment.add_reputation_context("Domain(val.Name && val.Name === obj.Name)", {"Name": "example.com"})

    all_context = enrichment.build_all_context()

    # Should have both contexts
    assert "Analyst1.Domain(val.ID && val.ID === obj.ID)" in all_context
    assert "Domain(val.Name && val.Name === obj.Name)" in all_context
    assert all_context["Analyst1.Domain(val.ID && val.ID === obj.ID)"]["ID"] == 1
    assert all_context["Domain(val.Name && val.Name === obj.Name)"]["Name"] == "example.com"


def test_enrichment_output_build_all_context_empty_reputation():
    """Test build_all_context when reputation context is empty"""
    analyst1_data = {"ID": 1}
    enrichment = EnrichmentOutput(analyst1_data, {}, "domain")

    all_context = enrichment.build_all_context()

    # Should only have Analyst1 context
    assert "Analyst1.Domain(val.ID && val.ID === obj.ID)" in all_context
    assert len(all_context) == 1


def test_enrichment_output_add_analyst1_context():
    """Test add_analyst1_context updates context dict"""
    enrichment = EnrichmentOutput({"ID": 1}, {}, "domain")

    enrichment.add_analyst1_context("NewKey", "NewValue")

    assert enrichment.analyst1_context_data["NewKey"] == "NewValue"
    assert enrichment.analyst1_context_data["ID"] == 1


def test_enrichment_output_add_reputation_context():
    """Test add_reputation_context updates reputation dict"""
    enrichment = EnrichmentOutput({}, {}, "domain")

    enrichment.add_reputation_context("Domain(val.Name)", {"Name": "example.com"})

    assert "Domain(val.Name)" in enrichment.reputation_context
    assert enrichment.reputation_context["Domain(val.Name)"]["Name"] == "example.com"


def test_enrichment_output_has_context_data():
    """Test has_context_data returns correct boolean"""
    # With data
    enrichment = EnrichmentOutput({"ID": 1}, {}, "domain")
    assert enrichment.has_context_data() is True

    # Without data
    enrichment_empty = EnrichmentOutput({}, {}, "domain")
    assert enrichment_empty.has_context_data() is False


def test_enrichment_output_return_outputs_no_reputation_context(mocker):
    """Test return_outputs when indicator doesn't exist (no reputation context)"""
    enrichment = EnrichmentOutput({}, {}, "domain", "nonexistent.com")

    mock_return_results = mocker.patch("Analyst1.return_results")

    enrichment.return_outputs()

    # Should call return_results with "not found" message
    mock_return_results.assert_called_once()
    call_args = mock_return_results.call_args[0][0]
    assert isinstance(call_args, CommandResults)
    # Check for the full expected message format to avoid CodeQL substring sanitization warnings
    assert call_args.readable_output == 'Domain "nonexistent.com" was not found in Analyst1.'


def test_enrichment_output_return_outputs_no_indicator_value(mocker):
    """Test return_outputs with no reputation context and no indicator_value"""
    enrichment = EnrichmentOutput({}, {}, "domain")

    mock_return_results = mocker.patch("Analyst1.return_results")

    enrichment.return_outputs()

    # Should call return_results with empty message
    mock_return_results.assert_called_once()
    call_args = mock_return_results.call_args[0][0]
    assert call_args.readable_output == ""


def test_enrichment_output_return_outputs_with_indicator(mocker):
    """Test return_outputs creates CommandResults with Common.Indicator"""
    context_data = {"ID": 1, "Indicator": "example.com"}
    raw_data = get_base_mock_json("example.com", "domain")
    enrichment = EnrichmentOutput(context_data, raw_data, "domain", "example.com")

    # Set up enrichment with reputation context and verdict
    enrichment.verdict_score = 2  # Suspicious
    enrichment.tags = ["Analyst1: Indicator"]
    enrichment.add_reputation_context("Domain(val.Name && val.Name === obj.Name)", {"Name": "example.com"})

    mock_return_results = mocker.patch("Analyst1.return_results")
    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    enrichment.return_outputs()

    # Should call return_results with CommandResults containing indicator
    mock_return_results.assert_called_once()
    call_args = mock_return_results.call_args[0][0]
    assert isinstance(call_args, CommandResults)
    assert call_args.indicator is not None
    assert call_args.outputs_prefix == "Analyst1.Domain"
    assert call_args.outputs_key_field == "ID"


def test_enrichment_output_create_common_indicator_domain(mocker):
    """Test _create_common_indicator_with_tags creates Common.Domain"""
    enrichment = EnrichmentOutput({}, {}, "domain", "example.com")
    enrichment.verdict_score = 2  # Suspicious
    enrichment.tags = ["Analyst1: Indicator"]

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.Domain)
    assert indicator.domain == "example.com"
    assert indicator.dbot_score.score == 2


def test_enrichment_output_create_common_indicator_email(mocker):
    """Test _create_common_indicator_with_tags creates Common.EMAIL"""
    enrichment = EnrichmentOutput({}, {}, "email", "user@example.com")
    enrichment.verdict_score = 3  # Malicious
    enrichment.tags = ["Analyst1: Indicator"]

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "A - Completely reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.EMAIL)
    assert indicator.address == "user@example.com"
    assert indicator.dbot_score.score == 3


def test_enrichment_output_create_common_indicator_ip(mocker):
    """Test _create_common_indicator_with_tags creates Common.IP for IPv4"""
    enrichment = EnrichmentOutput({}, {}, "ip", "192.0.2.1")
    enrichment.verdict_score = 1  # Benign
    enrichment.tags = ["Analyst1: Asset"]

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.IP)
    assert indicator.ip == "192.0.2.1"
    assert indicator.dbot_score.score == 1


def test_enrichment_output_create_common_indicator_ipv6(mocker):
    """Test _create_common_indicator_with_tags creates Common.IP for IPv6"""
    enrichment = EnrichmentOutput({}, {}, "ipv6", "2001:db8::1")
    enrichment.verdict_score = 0  # Unknown
    enrichment.tags = []

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "C - Fairly reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.IP)
    assert indicator.ip == "2001:db8::1"
    assert indicator.dbot_score.score == 0
    assert indicator.dbot_score.indicator_type == DBotScoreType.IP


def test_enrichment_output_create_common_indicator_url(mocker):
    """Test _create_common_indicator_with_tags creates Common.URL"""
    enrichment = EnrichmentOutput({}, {}, "url", "https://example.com/malware")
    enrichment.verdict_score = 3  # Malicious
    enrichment.tags = ["Analyst1: Indicator"]

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.URL)
    assert indicator.url == "https://example.com/malware"
    assert indicator.dbot_score.score == 3


def test_enrichment_output_create_common_indicator_file_sha1(mocker):
    """Test _create_common_indicator_with_tags creates Common.File with SHA1"""
    sha1_hash = "D8474A07411C6400E47C13D73700DC602F90262A"
    enrichment = EnrichmentOutput({}, {}, "file", sha1_hash)
    enrichment.verdict_score = 3  # Malicious
    enrichment.tags = ["Analyst1: Indicator"]

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.File)
    assert indicator.sha1 == sha1_hash
    assert indicator.dbot_score.score == 3


def test_enrichment_output_create_common_indicator_file_sha256(mocker):
    """Test _create_common_indicator_with_tags creates Common.File with SHA256"""
    sha256_hash = "F5A64DE9087B138608CCF036B067D91A47302259269FB05B3349964CA4060E7A"
    enrichment = EnrichmentOutput({}, {}, "file", sha256_hash)
    enrichment.verdict_score = 2  # Suspicious
    enrichment.tags = ["Analyst1: Indicator"]

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.File)
    assert indicator.sha256 == sha256_hash


def test_enrichment_output_create_common_indicator_file_md5(mocker):
    """Test _create_common_indicator_with_tags creates Common.File with MD5"""
    md5_hash = "6318E219B7F6E7F96192E0CDFEA1742A"
    enrichment = EnrichmentOutput({}, {}, "file", md5_hash)
    enrichment.verdict_score = 1  # Benign
    enrichment.tags = []

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert isinstance(indicator, Common.File)
    assert indicator.md5 == md5_hash


def test_enrichment_output_create_common_indicator_no_verdict():
    """Test _create_common_indicator_with_tags returns None when verdict_score is None"""
    enrichment = EnrichmentOutput({}, {}, "domain", "example.com")
    enrichment.verdict_score = None  # No verdict set

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is None


def test_enrichment_output_create_common_indicator_no_value():
    """Test _create_common_indicator_with_tags returns None when indicator_value is None"""
    enrichment = EnrichmentOutput({}, {}, "domain")
    enrichment.verdict_score = 2

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is None


def test_enrichment_output_create_common_indicator_with_tags_none(mocker):
    """Test _create_common_indicator_with_tags when tags is None"""
    enrichment = EnrichmentOutput({}, {}, "domain", "example.com")
    enrichment.verdict_score = 1
    enrichment.tags = None  # Explicitly set to None

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    # When tags is None, it should pass None to Common.Domain
    assert indicator.tags is None


def test_enrichment_output_create_common_indicator_with_empty_tags(mocker):
    """Test _create_common_indicator_with_tags when tags is empty list"""
    enrichment = EnrichmentOutput({}, {}, "domain", "example.com")
    enrichment.verdict_score = 1
    enrichment.tags = []  # Empty list

    mocker.patch("Analyst1.demisto.params", return_value={"integrationReliability": "B - Usually reliable"})

    indicator = enrichment._create_common_indicator_with_tags()

    assert indicator is not None
    assert indicator.tags == []


# Tests for get_xsoar_indicator_type_from_batch_result edge cases


def test_get_xsoar_indicator_type_from_batch_result_standard_types():
    """Test get_xsoar_indicator_type_from_batch_result with standard types"""
    # Test domain
    result = {"type": {"key": "domain"}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "domain"

    # Test email
    result = {"type": {"key": "email"}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "email"

    # Test ip
    result = {"type": {"key": "ip"}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "ip"


def test_get_xsoar_indicator_type_from_batch_result_special_mappings():
    """Test get_xsoar_indicator_type_from_batch_result with special type mappings"""
    # Test httpRequest -> url mapping
    result = {"type": {"key": "httpRequest"}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "url"

    # Test stixPattern -> string mapping
    result = {"type": {"key": "stixPattern"}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "string"

    # Test commandLine -> string mapping
    result = {"type": {"key": "commandLine"}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "string"


def test_get_xsoar_indicator_type_from_batch_result_unknown():
    """Test get_xsoar_indicator_type_from_batch_result with unknown type"""
    # Test unrecognized type
    result = {"type": {"key": "unknown_type"}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "unknown"

    # Test missing type key
    result = {"type": {}}
    assert get_xsoar_indicator_type_from_batch_result(result) == "unknown"

    # Test missing type dict
    result = {}
    assert get_xsoar_indicator_type_from_batch_result(result) == "unknown"


# Tests for argsToInt


def test_argsToInt_with_value():
    """Test argsToInt returns int when value exists"""
    args = {"timeout": "200", "page": 5}
    assert argsToInt(args, "timeout", 100) == 200
    assert argsToInt(args, "page", 1) == 5


def test_argsToInt_with_default():
    """Test argsToInt returns default when key doesn't exist"""
    args = {"other_key": "value"}
    assert argsToInt(args, "missing_key", 42) == 42


def test_argsToInt_with_none():
    """Test argsToInt returns default when value is None"""
    args = {"timeout": None}
    assert argsToInt(args, "timeout", 100) == 100


# Tests for generate_reputation_context with malicious verdict


def test_generate_reputation_context_malicious(mocker):
    """Test generate_reputation_context adds Malicious data when verdict is 3"""
    raw_data = get_base_mock_json("malicious.com", "domain")
    raw_data["indicatorRiskScore"] = {"name": "Critical"}
    raw_data["benign"] = {"value": False}

    enrichment = EnrichmentOutput({"ID": 1}, raw_data, "domain", "malicious.com")

    mocker.patch("Analyst1.demisto.params", return_value={})

    enrichment.generate_reputation_context("Name", "malicious.com", "domain", "Domain")

    # Should have Malicious data
    domain_key = "Domain(val.Name && val.Name === obj.Name)"
    assert domain_key in enrichment.reputation_context
    assert "Malicious" in enrichment.reputation_context[domain_key]
    assert enrichment.reputation_context[domain_key]["Malicious"]["Vendor"] == "Analyst1"
    assert enrichment.verdict_score == 3


def test_generate_reputation_context_with_extra_context(mocker):
    """Test generate_reputation_context includes extra_context"""
    raw_data = get_base_mock_json("example.com", "domain")
    raw_data["ipResolution"] = {"name": "192.0.2.1"}

    enrichment = EnrichmentOutput({"ID": 1}, raw_data, "domain", "example.com")

    mocker.patch("Analyst1.demisto.params", return_value={})

    enrichment.generate_reputation_context("Name", "example.com", "domain", "Domain", extra_context={"DNS": "192.0.2.1"})

    # Should have extra context
    domain_key = "Domain(val.Name && val.Name === obj.Name)"
    assert enrichment.reputation_context[domain_key]["DNS"] == "192.0.2.1"
