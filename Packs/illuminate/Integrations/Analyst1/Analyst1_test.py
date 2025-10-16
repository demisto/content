import demistomock as demisto  # noqa: F401
import pytest
from Analyst1 import *

MOCK_SERVER: str = "mock.com"
MOCK_USER: str = "mock"
MOCK_PASS: str = "mock"
MOCK_INDICATOR: str = "192.0.2.1"  # Valid test IP from RFC 5737

BASE_MOCK_NOTFOUND: dict = {"message": "The requested resource was not found."}
BASE_MOCK_JSON: dict = {
    "type": "domain",
    "value": {"name": f"{MOCK_INDICATOR}", "classification": "U"},
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


def mock_indicator_search(indicator_type: str, requests_mock):
    # Mock the GET /indicator/match endpoint (for old enrichment flow)
    requests_mock.get(
        f"https://{MOCK_SERVER}/api/1_0/indicator/match?type={indicator_type}&value={MOCK_INDICATOR}", json=BASE_MOCK_JSON
    )
    # Mock the POST /batchCheck endpoint (for new batch-check-first enrichment flow)
    batch_response = {
        "results": [
            {
                "searchedValue": MOCK_INDICATOR,
                "matchedValue": MOCK_INDICATOR,
                "entity": {"key": "INDICATOR"},
                "type": {"key": indicator_type},
                "indicatorRiskScore": {"title": "High"},
                "benign": {"value": False},
            }
        ]
    }
    requests_mock.post(f"https://{MOCK_SERVER}/api/1_0/batchCheck", json=batch_response)


def test_domain_command(requests_mock, mock_client):
    mock_indicator_search("domain", requests_mock)
    args: dict = {"domain": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = domain_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_email_command(requests_mock, mock_client):
    mock_indicator_search("email", requests_mock)
    args: dict = {"email": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = email_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_ip_command(requests_mock, mock_client):
    mock_indicator_search("ip", requests_mock)
    args: dict = {"ip": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = ip_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_file_command(requests_mock, mock_client):
    mock_indicator_search("file", requests_mock)
    args: dict = {"file": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = file_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_url_command(requests_mock, mock_client):
    mock_indicator_search("url", requests_mock)
    args: dict = {"url": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = url_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_analyst1_enrich_string_command(requests_mock, mock_client):
    mock_indicator_search("string", requests_mock)
    args: dict = {"string": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = analyst1_enrich_string_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_analyst1_enrich_ipv6_command(requests_mock, mock_client):
    mock_indicator_search("ipv6", requests_mock)
    args: dict = {"ip": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = analyst1_enrich_ipv6_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_analyst1_enrich_mutex_command(requests_mock, mock_client):
    mock_indicator_search("mutex", requests_mock)
    args: dict = {"mutex": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = analyst1_enrich_mutex_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


def test_analyst1_enrich_http_request_command(requests_mock, mock_client):
    mock_indicator_search("httpRequest", requests_mock)
    args: dict = {"http-request": f"{MOCK_INDICATOR}"}

    enrichment_output: EnrichmentOutput = analyst1_enrich_http_request_command(mock_client, args)[0]
    assert enrichment_output.analyst1_context_data.get("ID") == BASE_MOCK_JSON.get("id")


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
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B"})

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
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B"})

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
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B"})

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
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": False, "integrationReliability": "B"})

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
    mocker.patch("Analyst1.demisto.params", return_value={"applyTags": True, "integrationReliability": "B"})

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
