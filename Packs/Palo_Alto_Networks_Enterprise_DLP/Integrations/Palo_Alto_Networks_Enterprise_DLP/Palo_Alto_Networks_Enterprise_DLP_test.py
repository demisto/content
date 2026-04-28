import json
from datetime import UTC

import demistomock as demisto
import pytest
from freezegun import freeze_time
from Palo_Alto_Networks_Enterprise_DLP import (
    DEFAULT_BASE_URL as DLP_URL,
    DEFAULT_AUTH_URL as AUTH_URL,
    Client,
    exemption_eligible_command,
    fetch_notifications,
    main,
    parse_dlp_report,
    parse_incident_details,
    slack_bot_message_command,
    update_incident_command,
    create_incident,
    arg_to_datetime,
    compute_next_run,
    get_start_end_time_intervals,
    START_TIMESTAMP_KEY,
    LAST_IDS_KEY,
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


def test_get_dlp_incidents(requests_mock):
    requests_mock.get(f"{DLP_URL}public/incident-notifications?regions=us", json={"us": []})
    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    result, status_code = client.get_dlp_incidents(regions="us")
    assert result == {"us": []}
    assert status_code == 200


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
        - A DLP notification containing an incident.
    When:
        - Calling `create_incident` with or without specifying an incident type.
    Then:
        - Ensure no errors due to the lack of `userId` in `INCIDENT_JSON`.
        - Ensure the incident is created with the correct type.
    """
    import copy

    # Inputs
    notification = {"incident": copy.deepcopy(INCIDENT_JSON), "previous_notifications": []}
    region = "us"

    # Prepare
    parsed_details = parse_incident_details(INCIDENT_JSON["incidentDetails"])
    occurred_time = arg_to_datetime(INCIDENT_JSON["createdAt"]).isoformat()
    user_id = parsed_details["headers"][0]["attribute_value"]  # Take `attribute_value` where `attribute_name` = "username"
    raw_data = {
        **INCIDENT_JSON,
        "userId": user_id,
        "incidentDetails": parsed_details,
        "region": region,
        "previousNotification": None,
    }

    # Act
    if incident_type_input is None:
        result = create_incident(notification, region=region)
    else:
        result = create_incident(notification, region=region, incident_type=incident_type_input)

    # Assert - check standard fields
    assert result["name"] == f"Palo Alto Networks DLP Incident {INCIDENT_JSON['incidentId']}"
    assert result["type"] == expected_type
    assert result["occurred"] == occurred_time
    assert result["rawJSON"] == json.dumps(raw_data)
    assert result["details"] == json.dumps(raw_data)


@pytest.mark.parametrize(
    "incident_ids_timestamps, last_run, expected_timestamp, expected_ids",
    [
        pytest.param(
            {"id1": 1000, "id2": 2000, "id3": 2000, "id4": 1500},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_KEY: ["old_id"]},
            2000,
            {"id2", "id3"},  # Both have timestamp 2000, within buffer
            id="multiple_incidents_different_timestamps",
        ),
        pytest.param(
            {},
            {START_TIMESTAMP_KEY: 1234567890, LAST_IDS_KEY: ["id1"]},
            1234567890,
            {"id1"},
            id="empty_incidents_returns_previous",
        ),
        pytest.param(
            {"id1": 1000},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_KEY: []},
            1000,
            {"id1"},
            id="single_incident",
        ),
        pytest.param(
            {"id1": 2000, "id2": 2000 - END_TIME_BUFFER, "id3": 2000 - END_TIME_BUFFER - 1, "id4": 2000 - 15},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_KEY: []},
            2000,
            {"id1", "id2", "id4"},  # id3 excluded (outside buffer: 2000-30-1=1969 < 1970)
            id="buffer_window_filtering",
        ),
        pytest.param(
            {"id1": 2000, "id2": 1999, "id3": 1998, "id4": 1971, "id5": 1970, "id6": 1969},
            {START_TIMESTAMP_KEY: 500, LAST_IDS_KEY: []},
            2000,
            {"id1", "id2", "id3", "id4", "id5"},  # id6 excluded (1969 < 1970 which is 2000-30)
            id="exact_buffer_boundary",
        ),
    ],
)
def test_compute_next_run(incident_ids_timestamps, last_run, expected_timestamp, expected_ids):
    """
    Given:
        - A dictionary of incident IDs mapped to their committed timestamps.
    When:
        - Calling compute_next_run.
    Then:
        - Ensure it returns the correct timestamp and IDs within the buffer window.
    """
    result = compute_next_run(incident_ids_timestamps, last_run)

    assert result[START_TIMESTAMP_KEY] == expected_timestamp
    assert set(result[LAST_IDS_KEY]) == expected_ids


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


@freeze_time("2022-04-01 20:25:00 UTC")
def test_fetch_notifications_basic(requests_mock, mocker):
    """
    Given:
        - A client and basic parameters with frozen time.
    When:
        - Calling fetch_notifications with no previous last_run.
    Then:
        - Ensure incidents are created and last_run is updated.
    """
    import re
    from datetime import datetime
    from Palo_Alto_Networks_Enterprise_DLP import LOCAL_LAST_RUN

    LOCAL_LAST_RUN.clear()

    # Mock API response
    mock_notification = {
        "incident": {
            "incidentId": "test-id-1",
            "committedAt": "2022-Apr-01 20:21:50 UTC",
            "createdAt": "2022-Apr-01 20:21:50 UTC",
            "incidentDetails": INCIDENT_JSON["incidentDetails"],
            "tenantId": "1128505801991063552",
            "reportId": "2573778324",
        },
        "previous_notifications": [],
    }

    requests_mock.get(re.compile(f"{DLP_URL}public/incident-notifications.*"), json={"us": [mock_notification]})

    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(demisto, "createIncidents")
    mocker.patch.object(demisto, "setIntegrationContext")

    client = Client(DLP_URL, AUTH_URL, CREDENTIALS, True, False)
    # Use timestamp very close to frozen time (just 2 minutes before to minimize intervals)
    first_fetch_timestamp = int(datetime(2022, 4, 1, 20, 23, 0, tzinfo=UTC).timestamp())

    next_run, incidents = fetch_notifications(client, "us", first_fetch_timestamp)

    assert len(incidents) == 1
    assert "test-id-1" in incidents[0]["name"]

    assert next_run == {"start_timestamp": 1648844510, "last_ids": ["test-id-1"]}
