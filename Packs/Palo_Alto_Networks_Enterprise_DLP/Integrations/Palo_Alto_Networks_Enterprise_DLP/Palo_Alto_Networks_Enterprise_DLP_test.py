import json
from datetime import UTC, datetime

import demistomock as demisto
import pytest
from freezegun import freeze_time
from Palo_Alto_Networks_Enterprise_DLP import (
    DEFAULT_BASE_URL as DLP_URL,
    DEFAULT_AUTH_URL as AUTH_URL,
    Client,
    build_region_filter,
    exemption_eligible_command,
    fetch_notifications,
    main,
    parse_created_date,
    parse_dlp_report,
    parse_incident_details,
    slack_bot_message_command,
    update_incident_command,
    create_incident,
    compute_next_run,
    get_start_end_time_intervals,
    _migrate_last_run,
    START_TIMESTAMP_KEY,
    LAST_IDS_KEY,
    LAST_IDS_TIMESTAMPS_KEY,
    END_TIME_BUFFER,
)


REPORT_DATA = {
    "txn_id": "2573778324",
    "report_id": "2573778324",
    "data_profile_id": "11995149",
    "data_profile_version": 1,
    "data_profile_name": "Credit Card Match 2",
    "type": "advanced",
    "tenant_id": "1128505801991063552",
    "fileSha": "9093980f84a22659207d6a7194fc10e22416c833044a4d23f292b3a666ee66d9",
    "file_name": "Test_file.txt",
    "file_type": "txt",
    "file_size_in_bytes": 7640,
    "extracted_file_size_in_bytes": 7649,
    "detection_time": "04/01/2022 20:21:50 UTC",
    "action": "block",
    "data_pattern_rule_1_verdict": "MATCHED",
    "data_pattern_rule_2_verdict": None,
    "scanContentRawReport": {
        "data_pattern_rule_1_results": [
            {
                "data_pattern_id": "617b1867469e8924c80baeac",
                "version": 1,
                "name": "Credit Card Number",
                "technique": "regex",
                "type": "predefined",
                "strict_detection_frequency": 2,
                "proximity_detection_frequency": 10,
                "detection_frequency": 42,
                "unique_strict_detection_frequency": 1,
                "unique_checksum_detection_frequency": 0,
                "unique_proximity_detection_frequency": 5,
                "unique_detection_frequency": 7,
                "weighted_frequency": 0,
                "score": 0.0,
                "high_confidence_frequency": 10,
                "medium_confidence_frequency": 42,
                "low_confidence_frequency": 42,
                "unique_high_confidence_frequency": 5,
                "unique_medium_confidence_frequency": 7,
                "unique_low_confidence_frequency": 7,
                "matched_confidence_level": "low",
                "state": "EVALUATED",
                "detections": [
                    {
                        "left": "mastercard ************4444 \r\n************1881\r\n*********2222\r\n***********0005\r\n",
                        "right": "Cyprus CY17 0020 0128 0000 0012 0052 7600\r\nEs",
                        "detection": "************1117",
                        "origOffSet": 1484,
                        "textLength": 0,
                    }
                ],
            }
        ],
        "data_pattern_rule_2_results": None,
        "mlResponse": {
            "sha_256_original": None,
            "sha_256_extracted": None,
            "tenant_id": None,
            "report_id": None,
            "features": None,
        },
    },
    "data_profiles": [
        {
            "name": "Test Profile",
            "id": 12345,
            "version": 1,
            "is_triggered": True,
            "data_patterns": [
                {
                    "id": "pattern_id_1",
                    "is_matched": True,
                    "confidence_level": "high",
                    "occurrence_count": 5,
                    "occurrence_operator_type": "more_than_equal_to",
                    "occurrence_low": 1,
                },
                {
                    "id": "pattern_id_2",
                    "confidence_level": "low",
                    "occurrence_operator_type": "between",
                    "occurrence_low": 1,
                    "occurrence_high": 10,
                },
            ],
        }
    ],
}

INCIDENT_JSON = {
    "incidentId": "1fd24b1e-05ff-46c1-b638-a79d284dc727",
    "userId": None,
    "tenantId": "1128505801991063552",
    "reportId": "2573778324",
    "dataProfileId": 11995149,
    "dataProfileVersion": 1,
    "action": "block",
    "channel": "ngfw",
    "filename": "Test_file.txt",
    "checksum": "9093980f84a22659207d6a7194fc10e22416c833044a4d23f292b3a666ee66d9",
    "source": "ngfw",
    "scanDate": "2022-Apr-01 20:21:50 UTC",
    "createdAt": "2022-Apr-01 20:21:50 UTC",
    "incidentDetails": "QlpoOTFBWSZTWVnl2RYAAKIfgFAFfBBEAoAKv+ffqjAA2CIpoZGjEDTIZBpgGGRpppkYTIwTQGBiSp/pTZGqe1T8qMQaaeo9Nqm3YdNAidgNoZcFEJmTIP+V1xQohhqNsWERYRnKAc3TlogFoteml94kUR+lVJzjB9uhEqOgfBMrQh34ox8qYCCQo2n9WoNceFBvtSCAfMeY7sIAvtXhGQZ7UToozWEQwedzu/MRtoFMK8+ucpSbK4O7zRnPU82E9etuWR5AtmDQF5muuAczVDMFREJd+AEsRAKqdBdyRThQkFnl2RY=",  # noqa: E501
}

CREDENTIALS = {
    "credential": "",
    "credentials": {
        "id": "",
        "locked": False,
        "modified": "0001-01-01T00:00:00Z",
        "name": "",
        "password": "",
        "sortValues": None,
        "sshkey": "",
        "sshkeyPass": "",
        "user": "",
        "vaultInstanceId": "",
        "version": 0,
        "workgroup": "",
    },
    "identifier": "",
    "password": "",
    "passwordChanged": False,
}


def test_update_incident(requests_mock, mocker):
    incident_id = "abcdefg12345"
    user_id = "someone@somewhere.com"
    args = {
        "incident_id": incident_id,
        "feedback": "CONFIRMED_SENSITIVE",
        "user_id": user_id,
        "region": "us",
        "report_id": "A12345",
        "dlp_channel": "ngfw",
    }

    requests_mock.post(f"{DLP_URL}public/incident-feedback/{incident_id}?feedback_type=CONFIRMED_SENSITIVE&region=us")
    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    mocker.patch.object(demisto, "results")

    results = update_incident_command(client, args).to_context()

    request = requests_mock.last_request

    assert results["Contents"] == {"feedback": "CONFIRMED_SENSITIVE", "success": True}
    assert request.text == json.dumps({"user_id": user_id, "report_id": "A12345", "service_name": "ngfw"})


def test_update_incident_with_error_details(requests_mock, mocker):
    incident_id = "abcdefg12345"
    user_id = "someone@somewhere.com"
    args = {
        "incident_id": incident_id,
        "feedback": "SEND_NOTIFICATION_FAILURE",
        "user_id": user_id,
        "region": "us",
        "report_id": "A12345",
        "dlp_channel": "ngfw",
        "error_details": "Something went wrong",
    }

    requests_mock.post(f"{DLP_URL}public/incident-feedback/{incident_id}?feedback_type=SEND_NOTIFICATION_FAILURE&region=us")
    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    mocker.patch.object(demisto, "results")

    results = update_incident_command(client, args).to_context()

    request = requests_mock.last_request

    assert results["Contents"] == {"feedback": "SEND_NOTIFICATION_FAILURE", "success": True}
    assert request.text == json.dumps(
        {"user_id": user_id, "report_id": "A12345", "service_name": "ngfw", "error_details": "Something went wrong"}
    )


def test_get_dlp_report(requests_mock, mocker):
    report_id = 12345
    requests_mock.get(f"{DLP_URL}public/report/{report_id}?fetchSnippets=true", json={"id": "test"})
    mocker.patch.object(demisto, "command", return_value="pan-dlp-get-report")
    args = {"report_id": report_id, "fetch_snippets": "true"}
    params = {"credentials": CREDENTIALS}
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args_list[0][0]
    assert results[0]["Contents"] == {"id": "test"}


def test_parse_dlp_report(mocker):
    mocker.patch.object(demisto, "results")
    results = parse_dlp_report(REPORT_DATA).to_context()
    pattern_results = demisto.get(results["Contents"], "scanContentRawReport.data_pattern_rule_1_results", None)
    assert pattern_results is not None

    # Verify MatchedConfidenceLevel is present in DataPatternMatches
    contents = results["EntryContext"]["DLP.Report(val.DataPatternName && val.DataPatternName == obj.DataPatternName)"]
    data_pattern_matches = contents["DataPatternMatches"]
    assert len(data_pattern_matches) > 0
    assert data_pattern_matches[0]["MatchedConfidenceLevel"] == "low"

    # Verify DataProfiles is present and correctly parsed
    data_profiles = contents["DataProfiles"]
    assert len(data_profiles) == 1
    assert data_profiles[0]["Name"] == "Test Profile"
    assert data_profiles[0]["Id"] == 12345
    assert data_profiles[0]["Version"] == 1
    assert data_profiles[0]["IsTriggered"] is True
    assert len(data_profiles[0]["DataPatterns"]) == 2
    assert data_profiles[0]["DataPatterns"][0]["Id"] == "pattern_id_1"
    assert data_profiles[0]["DataPatterns"][0]["IsMatched"] is True
    assert data_profiles[0]["DataPatterns"][0]["ConfidenceLevel"] == "high"
    assert data_profiles[0]["DataPatterns"][0]["OccurrenceCount"] == 5
    assert data_profiles[0]["DataPatterns"][1]["OccurrenceOperatorType"] == "between"
    assert data_profiles[0]["DataPatterns"][1]["OccurrenceHigh"] == 10


V4_INCIDENTS_URL = "https://api.dlp.paloaltonetworks.com/v4/api/incidents"


def test_get_incidents_first_page(requests_mock):
    """
    Given:
        - A client configured with the default base URL.
    When:
        - Calling get_incidents_first_page.
    Then:
        - Ensure a POST is issued to the v4 incidents URL with a CUSTOM time range in
          milliseconds, ascending creation-date sort and a region filter expression.
    """
    mock_resp = {"rows": [], "status": "READY", "query_token": "tok-1", "total_rows": 0}
    requests_mock.post(V4_INCIDENTS_URL, json=mock_resp)

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    result, status_code = client.get_incidents_first_page(start_time_ms=1000, end_time_ms=2000, regions="us,eu")

    assert result == mock_resp
    assert status_code == 200
    assert requests_mock.last_request.url == V4_INCIDENTS_URL
    assert requests_mock.last_request.json() == {
        "time_range": "CUSTOM",
        "start_time": 1000,
        "end_time": 2000,
        "sort_by": "IncidentCreatedDate",
        "sort_order": "ASC",
        "page_size": 1000,
        "filter": "Region in ('US', 'EU')",
    }


def test_get_incidents_first_page_without_regions(requests_mock):
    """
    Given:
        - A client and no configured regions.
    When:
        - Calling get_incidents_first_page.
    Then:
        - Ensure no filter is sent, so the query covers every region the tenant can see.
    """
    requests_mock.post(V4_INCIDENTS_URL, json={"rows": [], "status": "READY"})

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    client.get_incidents_first_page(start_time_ms=1000, end_time_ms=2000, regions="")

    assert "filter" not in requests_mock.last_request.json()


def test_get_incidents_next_page(requests_mock):
    """
    Given:
        - A query token minted by a previous first-page call.
    When:
        - Calling get_incidents_next_page.
    Then:
        - Ensure a GET is issued with token, offset and pageSize on the query string.
    """
    mock_resp = {"rows": [{"incident_id": "id-1"}], "status": "READY", "total_rows": 5}
    requests_mock.get(V4_INCIDENTS_URL, json=mock_resp)

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    result, status_code = client.get_incidents_next_page("tok-1", 100, page_size=50)

    assert result == mock_resp
    assert status_code == 200
    assert requests_mock.last_request.qs == {"token": ["tok-1"], "offset": ["100"], "pagesize": ["50"]}


def test_v4_url_ignores_custom_base_path(requests_mock):
    """
    Given:
        - A base URL that is not versioned under /v1/.
    When:
        - Calling get_incidents_first_page.
    Then:
        - Ensure the v4 path is still appended to the configured host, rather than being
          derived by string replacement (which would silently no-op and fetch nothing).
    """
    requests_mock.post("https://dlp.customer.example/v4/api/incidents", json={"rows": [], "status": "READY"})

    client = Client("https://dlp.customer.example/api/", AUTH_URL, CREDENTIALS, True, False)
    client.get_incidents_first_page(start_time_ms=1000, end_time_ms=2000)

    assert requests_mock.last_request.url == "https://dlp.customer.example/v4/api/incidents"


@pytest.mark.parametrize(
    "regions, expected",
    [
        pytest.param("us", "Region in ('US')", id="single_region_uppercased"),
        pytest.param("us, eu ,ap", "Region in ('US', 'EU', 'AP')", id="multiple_regions_trimmed"),
        pytest.param("US_STG", "Region in ('US_STG')", id="underscore_allowed"),
        pytest.param("", "", id="empty_string"),
        pytest.param("us,'; DROP TABLE--", "Region in ('US')", id="injection_token_dropped"),
        pytest.param("!!!", "", id="all_tokens_invalid"),
    ],
)
def test_build_region_filter(regions, expected):
    """
    Given:
        - A comma-separated region configuration value.
    When:
        - Calling build_region_filter.
    Then:
        - Ensure valid tokens are uppercased into a filter expression and anything outside
          [A-Z0-9_] is discarded, so an operator value cannot alter the expression.
    """
    assert build_region_filter(regions) == expected


@pytest.mark.parametrize(
    "value, expected_epoch",
    [
        pytest.param(1648844510, 1648844510, id="seconds"),
        pytest.param(1648844510000, 1648844510, id="milliseconds"),
        pytest.param(1648844510000000, 1648844510, id="microseconds"),
        pytest.param("1648844510000", 1648844510, id="numeric_string"),
        pytest.param("2022-04-01 20:21:50 UTC", 1648844510, id="date_string"),
        pytest.param(None, None, id="none"),
        pytest.param("", None, id="empty_string"),
        pytest.param("not a date", None, id="unparsable"),
    ],
)
def test_parse_created_date(value, expected_epoch):
    """
    Given:
        - A created_date value in any of the units and formats the v4 API may return.
    When:
        - Calling parse_created_date.
    Then:
        - Ensure numeric values are normalized by magnitude, strings are parsed, and
          unparsable input returns None rather than raising.
    """
    result = parse_created_date(value)

    if expected_epoch is None:
        assert result is None
    else:
        assert int(result.timestamp()) == expected_epoch


@pytest.mark.parametrize(
    "error_code",
    [(401), (403)],
)
def test_refresh_token(requests_mock, mocker, error_code):
    with pytest.raises(Exception):
        report_id = 12345
        headers1 = {"Authorization": "Bearer 123", "Content-Type": "application/json"}
        requests_mock.get(f"{DLP_URL}public/report/{report_id}?fetchSnippets=true", headers=headers1, status_code=error_code)

        requests_mock.post(f"{DLP_URL}public/oauth/refreshToken", json={"access_token": "abc"})
        credentials = (
            {
                "credential": "",
                "credentials": {
                    "id": "",
                    "locked": False,
                    "modified": "0001-01-01T00:00:00Z",
                    "name": "",
                    "password": "",
                    "sortValues": None,
                    "sshkey": "",
                    "sshkeyPass": "",
                    "user": "",
                    "vaultInstanceId": "",
                    "version": 0,
                    "workgroup": "",
                },
                "identifier": "123",
                "password": "",
                "passwordChanged": False,
            },
        )
        client = Client(DLP_URL, AUTH_URL, credentials, False, False)

        client.get_dlp_report(report_id, True)

        assert client.access_token == "abc"


def test_refresh_token_with_access_token(requests_mock, mocker):
    requests_mock.post(f"{DLP_URL}public/oauth/refreshToken", json={"access_token": "abc"})
    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    client._refresh_token()
    assert client.access_token == "abc"


def test_refresh_token_with_client_credentials(requests_mock):
    credentials = {
        "credential": "test credentials",
        "credentials": {
            "id": "test credentials",
            "locked": False,
            "name": "test credentials",
            "password": "test-pass",
            "sortValues": None,
            "sshkey": "",
            "sshkeyPass": "",
            "user": "test-user",
            "vaultInstanceId": "",
            "version": 1,
            "workgroup": "",
        },
        "identifier": "test-user",
        "password": "test-pass",
        "passwordChanged": False,
    }
    requests_mock.post(AUTH_URL, json={"access_token": "abc"})
    client = Client(DLP_URL, AUTH_URL, credentials, False, False)
    assert client.access_token == "abc"


@pytest.mark.parametrize(
    "error_code",
    [(401), (403)],
)
def test_handle_4xx_errors(requests_mock, mocker, error_code):
    credentials = {
        "credential": "test credentials",
        "credentials": {
            "id": "test credentials",
            "locked": False,
            "name": "test credentials",
            "password": "test-pass",
            "sortValues": None,
            "sshkey": "",
            "sshkeyPass": "",
            "user": "test-user",
            "vaultInstanceId": "",
            "version": 1,
            "workgroup": "",
        },
        "identifier": "test-user",
        "password": "test-pass",
        "passwordChanged": False,
    }
    requests_mock.post(AUTH_URL, json={"access_token": "abc"})
    client = Client(DLP_URL, AUTH_URL, credentials, False, False)
    response_mock = mocker.MagicMock()
    response_mock.status_code = error_code  # mocker.PropertyMock(return_value=error_code)
    client._handle_4xx_errors(response_mock)
    assert client.access_token == "abc"

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, False, False)
    tokens_mocker = mocker.patch.object(client, "_refresh_token")
    client._handle_4xx_errors(response_mock)
    tokens_mocker.assert_called_with()


def test_exemption_eligible(mocker):
    args = {"data_profile": "abc"}
    params = {"dlp_exemptible_list": "abc,aaa,bbb"}
    mocker.patch.object(demisto, "results")
    results = exemption_eligible_command(args, params).to_context()
    assert results["Contents"] == {"eligible": True}


def test_exemption_eligible_wildcard(mocker):
    args = {"data_profile": "abc"}
    params = {"dlp_exemptible_list": "*"}
    mocker.patch.object(demisto, "results")
    results = exemption_eligible_command(args, params).to_context()
    assert results["Contents"] == {"eligible": True}


def test_slack_bot_message(mocker):
    params = {"dlp_slack_message": "Hello $user, your file $file_name on $app_name violated $data_profile_name"}
    args = {"user": "John Doe", "file_name": "secrets.doc", "app_name": "Google Drive", "data_profile_name": "PCI"}
    mocker.patch.object(demisto, "results")
    results = slack_bot_message_command(args, params).to_context()
    assert results["Contents"] == {"message": "Hello John Doe, your file secrets.doc on Google Drive violated PCI"}


def test_parse_incident_details():
    compressed_str = "QlpoOTFBWSZTWVnl2RYAAKIfgFAFfBBEAoAKv+ffqjAA2CIpoZGjEDTIZBpgGGRpppkYTIwTQGBiSp/pTZGqe1T8qMQaaeo9Nqm3YdNAidgNoZcFEJmTIP+V1xQohhqNsWERYRnKAc3TlogFoteml94kUR+lVJzjB9uhEqOgfBMrQh34ox8qYCCQo2n9WoNceFBvtSCAfMeY7sIAvtXhGQZ7UToozWEQwedzu/MRtoFMK8+ucpSbK4O7zRnPU82E9etuWR5AtmDQF5muuAczVDMFREJd+AEsRAKqdBdyRThQkFnl2RY="  # noqa: E501
    details = parse_incident_details(compressed_str)
    assert details["app_details"] == {"name": "Microsoft OneDrive"}


def test_query_sleep_time(requests_mock):
    requests_mock.get(f"{DLP_URL}public/seconds-between-incident-notifications-pull", json=10)
    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    time = client.query_for_sleep_time()
    assert time == 10


V4_ROW = {
    "incident_id": "1fd24b1e-05ff-46c1-b638-a79d284dc727",
    "report_id": "2573778324",
    "created_date": 1648844510000,
    "action": "block",
    "control_point": "NGFW",
    "asset_name": "Test_file.txt",
    "source": "test-user@example.com",
    "source_region": "US",
    "severity": "HIGH",
    "feedback_status": "PENDING_RESPONSE",
    "data_profile_id": 11995149,
    "data_profiles": [
        {"id": 11995148, "name": "Parent Profile", "version": 2, "is_parent": True},
        {"id": 11995149, "name": "Credit Card Match 2", "version": 1, "is_parent": False},
    ],
}


@pytest.mark.parametrize(
    "incident_type_input, expected_type",
    [
        (None, "Data Loss Prevention"),
        ("custom type", "custom type"),
    ],
)
def test_create_incident(incident_type_input, expected_type):
    """
    Given:
        - A v4 incident inventory row.
    When:
        - Calling `create_incident` with or without specifying an incident type.
    Then:
        - Ensure the incident is created with the correct type and that rawJSON keeps the
          v1 key names, including the nested previousNotification and incidentDetails
          shapes the incoming mapper reads.
    """
    created_at = parse_created_date(V4_ROW["created_date"])

    expected_raw = {
        "incidentId": V4_ROW["incident_id"],
        "userId": V4_ROW["source"],
        "tenantId": None,
        "reportId": V4_ROW["report_id"],
        "dataProfileId": V4_ROW["data_profile_id"],
        # The server derives data_profile_id from the last element, so name/version follow it.
        "dataProfileName": "Credit Card Match 2",
        "dataProfileVersion": 1,
        "action": V4_ROW["action"],
        "channel": "ngfw",
        "filename": V4_ROW["asset_name"],
        "checksum": None,
        "fileType": None,
        "source": V4_ROW["control_point"],
        "appId": None,
        "appName": None,
        "createdAt": created_at.isoformat(),
        "region": V4_ROW["source_region"],
        "previousNotification": {"feedback_status": V4_ROW["feedback_status"]},
        "incidentDetails": {"headers": [{"attribute_name": "severity", "attribute_value": V4_ROW["severity"]}]},
    }

    # Act
    if incident_type_input is None:
        result = create_incident(V4_ROW, created_at)
    else:
        result = create_incident(V4_ROW, created_at, incident_type=incident_type_input)

    # Assert
    assert result["name"] == f"Palo Alto Networks DLP Incident {V4_ROW['incident_id']}"
    assert result["type"] == expected_type
    assert result["occurred"] == created_at.isoformat()
    assert result["rawJSON"] == json.dumps(expected_raw)
    assert result["details"] == json.dumps(expected_raw)


def test_create_incident_normalizes_channel_and_tolerates_missing_fields():
    """
    Given:
        - A sparse row whose control_point uses the underscored server form and which
          carries no data profiles.
    When:
        - Calling create_incident.
    Then:
        - Ensure the channel is normalized to the hyphenated v1 form and the profile keys
          are present but empty rather than raising.
    """
    row = {"incident_id": "id-1", "control_point": "SAAS_API"}
    created_at = parse_created_date(1648844510)

    raw = json.loads(create_incident(row, created_at)["rawJSON"])

    assert raw["channel"] == "saas-api"
    assert raw["source"] == "SAAS_API"
    assert raw["dataProfileName"] is None
    assert raw["dataProfileVersion"] is None
    assert raw["previousNotification"] == {"feedback_status": None}


@pytest.mark.parametrize(
    "incident_ids_timestamps, last_run, has_new_incidents, last_queried_end_time, expected_timestamp, expected_ids",
    [
        pytest.param(
            {"id1": 1000, "id2": 2000, "id3": 2000, "id4": 1500},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_TIMESTAMPS_KEY: {"old_id": 500}},
            True,
            2000,
            2000,
            {"id2", "id3"},  # Both have timestamp 2000, within buffer (look_back=0 → cutoff = 2000-30 = 1970)
            id="multiple_incidents_different_timestamps",
        ),
        pytest.param(
            {},
            {START_TIMESTAMP_KEY: 1234567890, LAST_IDS_TIMESTAMPS_KEY: {"id1": 1234567890}},
            False,
            1234567980,  # last_queried_end_time advances by one interval (90s for this test)
            1234567980,
            {"id1"},  # last_ids_timestamps preserved from last_run
            id="no_new_incidents_advances_start_timestamp",
        ),
        pytest.param(
            {"id1": 1000},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_TIMESTAMPS_KEY: {}},
            True,
            1000,
            1000,
            {"id1"},
            id="single_incident",
        ),
        pytest.param(
            {"id1": 2000, "id2": 2000 - END_TIME_BUFFER, "id3": 2000 - END_TIME_BUFFER - 1, "id4": 2000 - 15},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_TIMESTAMPS_KEY: {}},
            True,
            2000,
            2000,
            {"id1", "id2", "id4"},  # id3 excluded (outside buffer: 2000-30-1=1969 < 1970)
            id="buffer_window_filtering",
        ),
        pytest.param(
            {"id1": 2000, "id2": 1999, "id3": 1998, "id4": 1971, "id5": 1970, "id6": 1969},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_TIMESTAMPS_KEY: {}},
            True,
            2000,
            2000,
            {"id1", "id2", "id3", "id4", "id5"},  # id6 excluded (1969 < 1970 which is 2000-30)
            id="exact_buffer_boundary",
        ),
    ],
)
def test_compute_next_run(
    incident_ids_timestamps, last_run, has_new_incidents, last_queried_end_time, expected_timestamp, expected_ids
):
    """
    Given:
        - A dictionary of incident IDs mapped to their committed timestamps.
        - A boolean indicating whether new incidents were fetched.
        - The end_time of the last queried interval.
    When:
        - Calling compute_next_run.
    Then:
        - If new incidents were fetched: returns the correct timestamp and IDs within the buffer window.
        - If no new incidents were fetched: advances start_timestamp to last_queried_end_time and
          preserves last_ids_timestamps from last_run.
    """
    result = compute_next_run(
        incident_ids_timestamps, last_run, has_new_incidents=has_new_incidents, last_queried_end_time=last_queried_end_time
    )

    assert result[START_TIMESTAMP_KEY] == expected_timestamp
    assert set(result.get(LAST_IDS_TIMESTAMPS_KEY, {}).keys()) == expected_ids


@pytest.mark.parametrize(
    "start, end, delta, expected_intervals",
    [
        pytest.param(
            0,
            900,
            300,
            [(0, 300), (300, 600), (600, 900)],
            id="even_intervals",
        ),
        pytest.param(
            0,
            1000,
            300,
            [(0, 300), (300, 600), (600, 900), (900, 1000)],
            id="uneven_intervals_capped_at_end",
        ),
        pytest.param(
            0,
            100,
            300,
            [(0, 100)],
            id="single_interval_delta_exceeds_range",
        ),
        pytest.param(
            100,
            100,
            300,
            [],
            id="empty_range",
        ),
    ],
)
def test_get_start_end_time_intervals(start, end, delta, expected_intervals):
    """
    Given:
        - Start and end timestamps with a delta.
    When:
        - Calling get_start_end_time_intervals.
    Then:
        - Ensure it returns the correct time intervals.
    """
    result = get_start_end_time_intervals(start, end, delta)

    assert result == expected_intervals


def _mock_fetch_env(mocker, last_run=None):
    """Patch the demisto side effects fetch_notifications performs."""
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value=last_run if last_run is not None else {})
    mocker.patch.object(demisto, "setIntegrationContext")


@freeze_time("2022-04-01 20:25:00 UTC")
def test_fetch_notifications_basic(requests_mock, mocker):
    """
    Given:
        - A single-page v4 inventory response with no previous last_run.
    When:
        - Calling fetch_notifications.
    Then:
        - Ensure an incident is created from the row and last_run carries the created_date
          watermark plus the ID for deduplication.
    """
    mock_resp = {"rows": [V4_ROW], "status": "READY", "query_token": "tok-1", "total_rows": 1}
    requests_mock.post(V4_INCIDENTS_URL, json=mock_resp)

    _mock_fetch_env(mocker)

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    first_fetch_timestamp = int(datetime(2022, 4, 1, 20, 23, 0, tzinfo=UTC).timestamp())

    next_run, incidents = fetch_notifications(client, "us", first_fetch_timestamp)

    assert len(incidents) == 1
    assert V4_ROW["incident_id"] in incidents[0]["name"]
    assert next_run == {
        START_TIMESTAMP_KEY: 1648844510,
        LAST_IDS_TIMESTAMPS_KEY: {V4_ROW["incident_id"]: 1648844510},
    }


@freeze_time("2026-04-01 20:25:00 UTC")
def test_fetch_notifications_lookback(requests_mock, mocker):
    """
    Given:
        - A last run with start_timestamp T and look_back_minutes=5.
    When:
        - Calling fetch_notifications.
    Then:
        - The POST body uses start_time = (T - 5*60) * 1000, so late-indexed incidents
          created before the watermark are re-queried.
    """
    start_timestamp = int(datetime(2026, 4, 1, 20, 23, 0, tzinfo=UTC).timestamp())  # T
    expected_effective_start_ms = (start_timestamp - 5 * 60) * 1000

    requests_mock.post(V4_INCIDENTS_URL, json={"rows": [], "status": "READY", "total_rows": 0})

    _mock_fetch_env(mocker, {START_TIMESTAMP_KEY: start_timestamp})

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    fetch_notifications(client, "us", first_fetch_timestamp=start_timestamp, look_back_minutes=5)

    assert requests_mock.request_history[0].json()["start_time"] == expected_effective_start_ms


@freeze_time("2026-04-01 20:25:00 UTC")
def test_fetch_notifications_advances_start_timestamp_when_no_new_incidents(requests_mock, mocker):
    """
    Given:
        - A last_run with a stale start_timestamp and an empty result set.
    When:
        - Calling fetch_notifications.
    Then:
        - Ensure start_timestamp in next_run is advanced to end_timestamp (now - buffer),
          preventing the query window from growing unboundedly on subsequent fetches.
    """
    start_timestamp = int(datetime(2026, 4, 1, 20, 23, 0, tzinfo=UTC).timestamp())

    requests_mock.post(V4_INCIDENTS_URL, json={"rows": [], "status": "READY", "total_rows": 0})

    _mock_fetch_env(mocker, {START_TIMESTAMP_KEY: start_timestamp, LAST_IDS_TIMESTAMPS_KEY: {}})

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    next_run, incidents = fetch_notifications(client, "us", first_fetch_timestamp=start_timestamp)

    assert incidents == []
    # start_timestamp must advance beyond the stale value — it should equal end_timestamp (now - buffer).
    assert next_run[START_TIMESTAMP_KEY] > start_timestamp


@freeze_time("2022-04-01 20:25:00 UTC")
def test_fetch_notifications_covers_all_regions_in_one_query(requests_mock, mocker):
    """
    Given:
        - Two configured regions and one incident in each.
    When:
        - Calling fetch_notifications.
    Then:
        - Ensure a single query covers both regions, so the watermark is derived from all of
          them rather than from whichever region happened to be queried last.
    """
    us_row = {**V4_ROW, "incident_id": "us-1", "source_region": "US", "created_date": 1648844510000}
    eu_row = {**V4_ROW, "incident_id": "eu-1", "source_region": "EU", "created_date": 1648844400000}
    requests_mock.post(
        V4_INCIDENTS_URL, json={"rows": [eu_row, us_row], "status": "READY", "query_token": "tok-1", "total_rows": 2}
    )

    _mock_fetch_env(mocker)

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    next_run, incidents = fetch_notifications(client, "us,eu", first_fetch_timestamp=1648844000)

    assert len(requests_mock.request_history) == 1
    assert requests_mock.request_history[0].json()["filter"] == "Region in ('US', 'EU')"
    assert {json.loads(incident["rawJSON"])["region"] for incident in incidents} == {"US", "EU"}
    # The watermark is the max across both regions, not whichever happened to be queried last.
    assert next_run[START_TIMESTAMP_KEY] == 1648844510


@freeze_time("2022-04-01 20:25:00 UTC")
def test_fetch_notifications_pages_until_empty_when_total_rows_missing(requests_mock, mocker):
    """
    Given:
        - A response whose total_rows is null, which the server may return.
    When:
        - Calling fetch_notifications.
    Then:
        - Ensure the walk degrades to paging until an empty page rather than raising or
          stopping after the first page.
    """
    page_1 = {**V4_ROW, "incident_id": "id-1"}
    page_2 = {**V4_ROW, "incident_id": "id-2"}
    requests_mock.post(V4_INCIDENTS_URL, json={"rows": [page_1], "status": "READY", "query_token": "tok-1", "total_rows": None})
    requests_mock.get(
        V4_INCIDENTS_URL,
        [
            {"json": {"rows": [page_2], "status": "READY"}},
            {"json": {"rows": [], "status": "READY"}},
        ],
    )

    _mock_fetch_env(mocker)

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    _, incidents = fetch_notifications(client, "us", first_fetch_timestamp=1648844000)

    assert [json.loads(incident["rawJSON"])["incidentId"] for incident in incidents] == ["id-1", "id-2"]


@freeze_time("2022-04-01 20:25:00 UTC")
def test_fetch_notifications_repolls_pending_query(requests_mock, mocker):
    """
    Given:
        - A first page that is acknowledged as PENDING with no rows.
    When:
        - Calling fetch_notifications.
    Then:
        - Ensure the query token is re-polled until rows are ready, rather than treating the
          empty PENDING page as an empty result set.
    """
    mocker.patch("Palo_Alto_Networks_Enterprise_DLP.time.sleep")
    requests_mock.post(V4_INCIDENTS_URL, json={"rows": [], "status": "PENDING", "query_token": "tok-1"})
    requests_mock.get(
        V4_INCIDENTS_URL,
        [
            {"json": {"rows": [], "status": "PENDING"}},
            {"json": {"rows": [V4_ROW], "status": "READY", "total_rows": 1}},
        ],
    )

    _mock_fetch_env(mocker)

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    _, incidents = fetch_notifications(client, "us", first_fetch_timestamp=1648844000)

    assert len(incidents) == 1
    assert V4_ROW["incident_id"] in incidents[0]["name"]


@freeze_time("2022-04-01 20:25:00 UTC")
def test_fetch_notifications_skips_duplicates_and_unparsable_rows(requests_mock, mocker):
    """
    Given:
        - A page containing an already-seen incident and one with an unparsable created_date.
    When:
        - Calling fetch_notifications.
    Then:
        - Ensure both are skipped and the fetch completes, rather than re-creating the
          duplicate or dying on the bad timestamp.
    """
    seen_row = {**V4_ROW, "incident_id": "seen-1"}
    bad_row = {**V4_ROW, "incident_id": "bad-1", "created_date": "not a date"}
    good_row = {**V4_ROW, "incident_id": "good-1"}
    requests_mock.post(
        V4_INCIDENTS_URL,
        json={"rows": [seen_row, bad_row, good_row], "status": "READY", "query_token": "tok-1", "total_rows": 3},
    )

    _mock_fetch_env(mocker, {START_TIMESTAMP_KEY: 1648844000, LAST_IDS_TIMESTAMPS_KEY: {"seen-1": 1648844000}})

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    _, incidents = fetch_notifications(client, "us", first_fetch_timestamp=1648844000)

    assert [json.loads(incident["rawJSON"])["incidentId"] for incident in incidents] == ["good-1"]


@freeze_time("2022-04-01 20:25:00 UTC")
def test_fetch_notifications_stops_at_max_fetch(requests_mock, mocker):
    """
    Given:
        - A result set larger than max_fetch.
    When:
        - Calling fetch_notifications.
    Then:
        - Ensure the walk stops at the limit and does not request a further page.
    """
    rows = [{**V4_ROW, "incident_id": f"id-{i}"} for i in range(5)]
    requests_mock.post(V4_INCIDENTS_URL, json={"rows": rows, "status": "READY", "query_token": "tok-1", "total_rows": 50})

    _mock_fetch_env(mocker)

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    _, incidents = fetch_notifications(client, "us", first_fetch_timestamp=1648844000, max_fetch=2)

    assert len(incidents) == 2
    assert len(requests_mock.request_history) == 1


@pytest.mark.parametrize(
    "last_run, start_timestamp, expected",
    [
        pytest.param(
            {LAST_IDS_TIMESTAMPS_KEY: {"id1": 1000, "id2": 2000}},
            500,
            {"id1": 1000, "id2": 2000},
            id="new_schema_returned_as_is",
        ),
        pytest.param(
            {LAST_IDS_KEY: ["id1", "id2"]},
            500,
            {"id1": 500, "id2": 500},
            id="legacy_ids_seeded_with_start_timestamp",
        ),
        pytest.param(
            {},
            500,
            {},
            id="empty_last_run_returns_empty_dict",
        ),
        pytest.param(
            {LAST_IDS_KEY: []},
            500,
            {},
            id="legacy_empty_list_returns_empty_dict",
        ),
    ],
)
def test_migrate_last_run(last_run: dict, start_timestamp: int, expected: dict):
    """
    Given:
        - A last run dict in either the new (last_ids_timestamps) or legacy (last_ids) schema,
          or an empty dict.
    When:
        - Calling _migrate_last_run with a start_timestamp.
    Then:
        - New schema is returned unchanged as a plain dict copy.
        - Legacy IDs are migrated and each ID is seeded with start_timestamp.
        - Empty / missing keys produce an empty dict.
    """
    result = _migrate_last_run(last_run, start_timestamp)
    assert result == expected
