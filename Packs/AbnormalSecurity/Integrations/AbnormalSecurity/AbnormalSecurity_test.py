import json
import threading
import time
from datetime import datetime, timedelta, UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import demistomock as demisto
import pytest

from AbnormalSecurity import (
    Client,
    check_the_status_of_an_action_requested_on_a_case_command,
    check_the_status_of_an_action_requested_on_a_threat_command,
    get_a_list_of_abnormal_cases_identified_by_abnormal_security_command,
    get_a_list_of_threats_command,
    get_a_list_of_vendors_command,
    get_the_details_of_a_specific_vendor_command,
    get_the_activity_of_a_specific_vendor_command,
    get_a_list_of_vendor_cases_command,
    get_the_details_of_a_vendor_case_command,
    manage_a_threat_identified_by_abnormal_security_command,
    manage_an_abnormal_case_command,
    get_details_of_an_abnormal_case_command,
    get_details_of_an_abuse_mailbox_campaign_command,
    provides_the_analysis_and_timeline_details_of_a_case_command,
    submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command,
    submit_false_negative_report_command,
    submit_false_positive_report_command,
    get_a_list_of_campaigns_submitted_to_abuse_mailbox_command,
    get_the_latest_threat_intel_feed_command,
    get_employee_identity_analysis_genome_data_command,
    get_employee_information_command,
    get_employee_login_information_for_last_30_days_in_csv_format_command,
    download_data_from_threat_log_in_csv_format_command,
    _is_skippable_error,
    get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command,
    fetch_incidents,
    build_threat_incident,
    build_account_takeover_case_incident,
    build_list_filter,
    FetchWindow,
    Deadline,
    RateLimiter,
    AuthError,
    BudgetExhaustedError,
    THREATS_SPEC,
    ABUSE_CAMPAIGNS_SPEC,
    ACCOUNT_TAKEOVER_SPEC,
    ISO_8601_FORMAT,
)
from CommonServerPython import DemistoException
from test_data.fixtures import BASE_URL, apikey
from test_data.fake_soar_api import FakeSoarApi
from test_data.mock_paginated_response import create_mock_paginator_side_effect


headers = {
    "Authorization": f"Bearer {apikey}",
}


class MockResponse:
    def __init__(self, data, status_code):
        self.data = data
        self.text = str(data)
        self.status_code = status_code
        # Add content attribute for file downloads
        self.content = data if isinstance(data, bytes) else str(data).encode("utf-8")


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_response(path):
    with open(path, encoding="utf-8") as f:
        return MockResponse(f.read(), 200)


def mock_client(mocker, response=None, side_effect=None, throw_error=False):
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"current_refresh_token": "refresh_token"})
    client = Client(server_url=BASE_URL, verify=False, proxy=False, auth=None, headers=headers)
    mocker.patch.object(client, "_http_request", return_value=response, side_effect=side_effect)

    if throw_error:
        err_msg = "Error in API call [400] - BAD REQUEST}"
        mocker.patch.object(client, "_http_request", side_effect=DemistoException(err_msg, res={}))

    return client


"""
    Command Unit Tests
"""


@pytest.fixture
def mock_get_a_list_of_threats_request(mocker):
    mocker.patch("AbnormalSecurity.Client.get_a_list_of_threats_request").return_value = util_load_json(
        "test_data/test_get_list_of_abnormal_threats.json"
    )


@pytest.fixture
def mock_get_details_of_a_threat_request(mocker):
    threat_details = util_load_json("test_data/test_get_details_of_a_threat_page2.json")
    threat_details["messages"][0]["remediationTimestamp"] = "2023-09-17T15:43:09Z"
    mocker.patch("AbnormalSecurity.Client.get_details_of_a_threat_request").return_value = threat_details


@pytest.fixture
def mock_get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(mocker):
    mocker.patch(
        "AbnormalSecurity.Client.get_a_list_of_campaigns_submitted_to_abuse_mailbox_request"
    ).return_value = util_load_json("test_data/test_get_list_of_abuse_campaigns.json")


@pytest.fixture
def mock_get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(mocker):
    mocker.patch(
        "AbnormalSecurity.Client.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request"
    ).return_value = util_load_json("test_data/test_get_list_of_abnormal_cases.json")


def test_check_the_status_of_an_action_requested_on_a_case_command(mocker):
    """
    When:
        - Checking status of an action request on a case
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_check_status_of_action_requested_on_threat.json"))
    results = check_the_status_of_an_action_requested_on_a_case_command(client, {})
    assert results.outputs.get("status") == "acknowledged"
    assert results.outputs_prefix == "AbnormalSecurity.ActionStatus"


def test_check_the_status_of_an_action_requested_on_a_threat_command(mocker):
    """
    When:
        - Checking status of an action request on a threat
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_check_status_of_action_requested_on_threat.json"))
    results = check_the_status_of_an_action_requested_on_a_threat_command(client, {})
    assert results.outputs.get("status") == "acknowledged"
    assert results.outputs_prefix == "AbnormalSecurity.ActionStatus"


def test_get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(mocker):
    """
    When:
        - Retrieving list of abnormal cases identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    # Modify the mock response to have a nextPageNumber
    abnormal_cases_list = util_load_json("test_data/test_get_list_of_abnormal_cases.json")
    abnormal_cases_list["nextPageNumber"] = 2

    client = mock_client(mocker, abnormal_cases_list)
    results = get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(client, {})
    assert results.outputs.get("cases")[0].get("caseId") == "1234"
    assert results.outputs.get("pageNumber", 0) > 0
    assert results.outputs.get("nextPageNumber") == results.outputs.get("pageNumber", 0) + 1
    assert results.outputs_prefix == "AbnormalSecurity.inline_response_200_1"


def test_get_a_list_of_threats_command(mocker):
    """
    When:
        - Retrieving list of cases identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_list_of_abnormal_threats.json"))
    results = get_a_list_of_threats_command(client, {})
    assert results.outputs.get("threats")[0].get("threatId") == "asdf097sdf907"
    assert results.outputs_prefix == "AbnormalSecurity.inline_response_200"


def test_get_a_list_of_vendors_command(mocker):
    """
    When:
        - Retrieving list of vendors identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_a_list_of_vendors.json"))
    results = get_a_list_of_vendors_command(client, {})
    assert results.outputs[0].get("vendorDomain") == "test-domain-1.com"
    assert results.outputs_prefix == "AbnormalSecurity.VendorsList"


def test_get_the_details_of_a_specific_vendor_command(mocker):
    """
    When:
        - Retrieving details of a vendor
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_the_details_of_a_specific_vendor.json"))
    results = get_the_details_of_a_specific_vendor_command(client, {"vendor_domain": "test-domain-1.com"})
    assert results.outputs.get("vendorDomain") == "test-domain-1.com"
    assert results.outputs.get("vendorContacts")[0] == "john.doe@test-domain-1.com"
    assert results.outputs_prefix == "AbnormalSecurity.VendorDetails"


def test_get_the_activity_of_a_specific_vendor_command(mocker):
    """
    When:
        - Retrieving activity of a vendor
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_the_activity_of_a_specific_vendor.json"))
    results = get_the_activity_of_a_specific_vendor_command(client, {"vendor_domain": "test-domain-1.com"})
    assert results.outputs.get("eventTimeline")[0].get("suspiciousDomain") == "test@test-domain.com"
    assert results.outputs_prefix == "AbnormalSecurity.VendorActivity"


def test_get_a_list_of_vendor_cases_command(mocker):
    """
    When:
        - Retrieving list of vendor cases identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_a_list_of_vendor_cases.json"))
    results = get_a_list_of_vendor_cases_command(client, {})
    assert results.outputs[0].get("vendorCaseId") == 123
    assert results.outputs_prefix == "AbnormalSecurity.VendorCases"


def test_get_the_details_of_a_vendor_case_command(mocker):
    """
    When:
        - Retrieving details of a vendor case
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_the_details_of_a_vendor_case.json"))
    results = get_the_details_of_a_vendor_case_command(client, {"case_id": 2})
    assert results.outputs.get("vendorCaseId") == 123
    assert results.outputs.get("timeline")[0].get("threatId") == 1234
    assert results.outputs_prefix == "AbnormalSecurity.VendorCaseDetails"


def test_get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command(mocker):
    """
    When:
        - Retrieving a list of abuse mailbox messages that is yet to be analyzed
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_a_list_of_unanalyzed_abuse_mailbox_messages.json"))
    results = get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command(client, {})
    assert results.outputs.get("results")[0].get("abx_message_id") == 123456789
    assert results.outputs.get("results")[0].get("recipient").get("email") == "john.doe@some-domain.com"
    assert results.outputs_prefix == "AbnormalSecurity.UnanalyzedAbuseCampaigns"


def test_get_details_of_an_abnormal_case_command(mocker):
    """
    When:
        - Retrieving details of an abnormal case identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_details_of_an_abnormal_case.json"))
    results = get_details_of_an_abnormal_case_command(client, {})
    assert results.outputs.get("caseId") == "1234"
    assert results.outputs.get("threatIds")[0] == "184712ab-6d8b-47b3-89d3-a314efef79e2"
    assert results.outputs_prefix == "AbnormalSecurity.AbnormalCaseDetails"


def test_manage_a_threat_identified_by_abnormal_security_command_failure(mocker):
    """
    When:
        - Cause an API error when parsing bad data
    Then
        - Assert error is thrown as expected
    """
    client = mock_client(mocker, None, False, True)
    with pytest.raises(DemistoException):
        manage_a_threat_identified_by_abnormal_security_command(client, {})


def test_manage_a_threat_identified_by_abnormal_security_command_success(mocker):
    """
    When:
        - Successfully manage a threat identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_manage_threat.json"))
    results = manage_a_threat_identified_by_abnormal_security_command(client, {})
    assert results.outputs.get("action_id") == "61e76395-40d3-4d78-b6a8-8b17634d0f5b"
    assert results.outputs_prefix == "AbnormalSecurity.ThreatManageResults"


def test_manage_an_abnormal_case_command_failure(mocker):
    """
    When:
        - Cause an API error when passing bad data
    Then
        - Assert error is thrown as expected
    """
    client = mock_client(mocker, None, False, True)
    with pytest.raises(DemistoException):
        manage_an_abnormal_case_command(client, {})


def test_manage_an_abnormal_case_command_success(mocker):
    """
    When:
        - Successfully manage a threat identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_manage_case.json"))
    results = manage_an_abnormal_case_command(client, {})
    assert results.outputs.get("action_id") == "61e76395-40d3-4d78-b6a8-8b17634d0f5b"
    assert results.outputs_prefix == "AbnormalSecurity.CaseManageResults"


def test_submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(mocker):
    """
    When:
        - Submit an inquiry
    Then
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, "Thank you for your feedback! We have sent your inquiry to our support staff.")
    args = {"reporter": "abc@def.com", "report_type": "false-positive"}

    results = submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(client, args)
    assert results.outputs_prefix == "AbnormalSecurity.SubmitInquiry"


def test_submit_a_false_negative_command(mocker):
    """
    When:
        - Submit a FN command
    Then
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, "Thank you for your feedback! We have sent your inquiry to our support staff.")
    args = {"sender_email": "abc@def.com", "recipient_email": "abc@def.com", "subject": "test"}

    results = submit_false_negative_report_command(client, args)
    assert results.readable_output == "Thank you for your feedback! We have sent your inquiry to our support staff."


def test_submit_a_false_positive_command(mocker):
    """
    When:
        - Submit a FP command
    Then
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, "Thank you for your feedback! We have sent your inquiry to our support staff.")
    args = {
        "portal_link": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/12345",
    }

    results = submit_false_positive_report_command(client, args)
    assert results.readable_output == "Thank you for your feedback! We have sent your inquiry to our support staff."


def test_get_the_latest_threat_intel_feed_command(mocker):
    """
    When:
        - Retrieve intel feed
    Then
        - Assert downloaded file name is as expected
    """
    client = mock_client(mocker, util_load_response("test_data/test_get_threat_intel_feed.json"))
    results = get_the_latest_threat_intel_feed_command(client)
    assert results["File"] == "threat_intel_feed.json"


def test_download_data_from_threat_log_in_csv_format_command(mocker):
    """
    When:
        - Downloading threat log in csv format
    Then
        - Assert downloaded file name is as expected
    """
    client = mock_client(mocker, util_load_response("test_data/test_download_data_from_threat_log_in_csv_format.csv"))
    results = download_data_from_threat_log_in_csv_format_command(client, {})

    assert results["File"] == "threat_log.csv"


def test_get_a_list_of_campaigns_submitted_to_abuse_mailbox_command(mocker):
    """
    When:
        - Retrieving list of abuse campaigns identified
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    # Modify the mock response to have a nextPageNumber
    abnormal_campaigns_list = util_load_json("test_data/test_get_list_of_abuse_campaigns.json")
    abnormal_campaigns_list["nextPageNumber"] = 2

    client = mock_client(mocker, abnormal_campaigns_list)
    results = get_a_list_of_campaigns_submitted_to_abuse_mailbox_command(client, {})
    assert results.outputs.get("campaigns")[0].get("campaignId") == "fff51768-c446-34e1-97a8-9802c29c3ebd"
    assert results.outputs.get("pageNumber", 0) > 0
    assert results.outputs.get("nextPageNumber") == results.outputs.get("pageNumber", 0) + 1
    assert results.outputs_prefix == "AbnormalSecurity.AbuseCampaign"


def test_get_details_of_an_abuse_mailbox_campaign_command(mocker):
    """
    When:
        - Retrieving details of an abuse mailbox campaign reported
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_details_of_abuse_campaign.json"))
    results = get_details_of_an_abuse_mailbox_campaign_command(client, {})
    assert results.outputs.get("campaignId") == "fff51768-c446-34e1-97a8-9802c29c3ebd"
    assert results.outputs.get("attackType") == "Attack Type: Spam"
    assert results.outputs_prefix == "AbnormalSecurity.AbuseCampaign"


def test_get_employee_identity_analysis_genome_data_command(mocker):
    """
    When:
        - Retrieving analysis histograms of employee
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_details_of_genome_data.json"))
    results = get_employee_identity_analysis_genome_data_command(client, {})
    assert len(results.outputs.get("histograms")) > 0
    assert results.outputs.get("histograms")[0]["key"] == "ip_address"
    for index, val in enumerate(results.outputs.get("histograms")[0]["values"]):
        assert val["text"] == f"ip-address-{index}"
    assert results.outputs_prefix == "AbnormalSecurity.Employee"


def test_get_employee_information_command(mocker):
    """
    When:
        - Retrieving company employee information
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_employee_info.json"))
    results = get_employee_information_command(client, {})
    assert results.outputs.get("name") == "test_name"
    assert results.outputs_prefix == "AbnormalSecurity.Employee"


def test_get_employee_login_information_for_last_30_days_in_csv_format_command(mocker):
    """
    When:
        - Downloading employee login information in csv format
    Then
        - Assert downloaded file name is as expected
    """
    client = mock_client(mocker, util_load_response("test_data/test_get_employee_login_info_csv.csv"))
    results = get_employee_login_information_for_last_30_days_in_csv_format_command(client, {})
    assert results["File"] == "employee_login_info_30_days.csv"


def test_provides_the_analysis_and_timeline_details_of_a_case_command(mocker):
    """
    When:
        - Retrieving anaylsis and timeline detail of a case
    Then
        - Assert the context data is as expected.
        - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json("test_data/test_get_case_analysis_and_timeline.json"))
    results = provides_the_analysis_and_timeline_details_of_a_case_command(client, {})
    assert len(results.outputs.get("insights")) > 0
    assert len(results.outputs.get("eventTimeline")) > 0
    assert results.outputs_prefix == "AbnormalSecurity.CaseAnalysis"


def threat_window(start, end):
    return FetchWindow(enabled=True, window_start=start, window_end=end)


def test_build_threat_incident_two_pages(mocker):
    return_val = util_load_json("test_data/test_get_details_of_a_threat.json")
    return_val["messages"][0]["remediationTimestamp"] = "2023-09-17T15:43:09Z"
    page_2 = util_load_json("test_data/test_get_details_of_a_threat_page2.json")
    page_2["messages"][0]["remediationTimestamp"] = "2023-09-17T16:43:09Z"
    client = mock_client(mocker, side_effect=[return_val, page_2])
    window = threat_window(datetime(2023, 9, 17, 14, 43, 9, tzinfo=UTC), datetime(2023, 9, 18, 14, 43, 9, tzinfo=UTC))

    incident = build_threat_incident(client, {"threatId": "asdf097sdf907"}, window, max_page_number=2)

    assert len(json.loads(incident["rawJSON"])["messages"]) == 2


def test_build_threat_incident_nanosecond_timestamp(mocker):
    threat_details = util_load_json("test_data/test_get_details_of_a_threat_page2.json")
    threat_details["messages"][0]["remediationTimestamp"] = "2023-09-17T15:43:09Z"
    client = mock_client(mocker, response=threat_details)
    window = threat_window(datetime(2023, 9, 17, 14, 0, 0, tzinfo=UTC), datetime(2023, 9, 18, 0, 0, 0, tzinfo=UTC))

    incident = build_threat_incident(client, {"threatId": "asdf097sdf907"}, window, max_page_number=1)

    assert incident["occurred"] == "2023-12-03T19:26:36.123456"


def test_build_threat_incident_filters_messages_to_window(mocker):
    """
    Given a threat whose messages were remediated at the window start, just before its end, at its end,
    before it, and one with no remediation timestamp.
    When the incident is built.
    Then only the messages in [start, end) are kept, and the missing timestamp doesn't raise.
    """
    start, end = datetime(2023, 9, 17, 14, 0, 0, tzinfo=UTC), datetime(2023, 9, 17, 17, 0, 0, tzinfo=UTC)
    mock_response = {
        "threatId": "test-threat-id",
        "messages": [
            {"receivedTime": "2023-09-17T17:00:00Z", "remediationTimestamp": "2023-09-17T17:00:00Z"},
            {"receivedTime": "2023-09-17T16:59:59Z", "remediationTimestamp": "2023-09-17T16:59:59.999999Z"},
            {"receivedTime": "2023-09-17T15:00:00Z"},
            {"receivedTime": "2023-09-17T14:00:00Z", "remediationTimestamp": "2023-09-17T14:00:00Z"},
            {"receivedTime": "2023-09-17T12:00:00Z", "remediationTimestamp": "2023-09-17T12:30:00Z"},
        ],
    }
    client = mock_client(mocker, response=mock_response)

    incident = build_threat_incident(client, {"threatId": "test-threat-id"}, threat_window(start, end), max_page_number=1)

    remediation_times = [m["remediationTimestamp"] for m in json.loads(incident["rawJSON"])["messages"]]
    assert remediation_times == ["2023-09-17T16:59:59.999999Z", "2023-09-17T14:00:00Z"]
    assert incident["occurred"] == "2023-09-17T16:59:59Z"


def test_build_threat_incident_stops_at_messages_before_window(mocker):
    page_1 = {
        "threatId": "test-threat-id",
        "messages": [
            {"receivedTime": "2023-09-17T16:00:00Z", "remediationTimestamp": "2023-09-17T16:30:00Z"},
            {"receivedTime": "2023-09-17T15:00:00Z", "remediationTimestamp": "2023-09-17T15:30:00Z"},
        ],
        "nextPageNumber": 2,
    }
    page_2 = {
        "threatId": "test-threat-id",
        "messages": [
            {"receivedTime": "2023-09-17T13:00:00Z", "remediationTimestamp": "2023-09-17T13:30:00Z"},
            {"receivedTime": "2023-09-17T12:00:00Z", "remediationTimestamp": "2023-09-17T12:30:00Z"},
        ],
    }
    client = mock_client(mocker, side_effect=[page_1, page_2])
    get_details_spy = mocker.spy(client, "get_details_of_a_threat_request")
    window = threat_window(datetime(2023, 9, 17, 14, 0, 0, tzinfo=UTC), datetime(2023, 9, 17, 17, 0, 0, tzinfo=UTC))

    incident = build_threat_incident(client, {"threatId": "test-threat-id"}, window, max_page_number=3)

    remediation_times = [m["remediationTimestamp"] for m in json.loads(incident["rawJSON"])["messages"]]
    assert remediation_times == ["2023-09-17T16:30:00Z", "2023-09-17T15:30:00Z"]
    assert [c.kwargs["page_number"] for c in get_details_spy.call_args_list] == [1, 2]


def test_build_account_takeover_case_incident(mocker):
    client = mock_client(mocker, util_load_json("test_data/test_get_details_of_an_abnormal_case.json"))
    window = threat_window(datetime(2023, 9, 17, 14, 0, 0, tzinfo=UTC), datetime(2023, 9, 17, 17, 0, 0, tzinfo=UTC))

    incident = build_account_takeover_case_incident(client, {"caseId": "1234", "description": "d"}, window)

    assert incident["genaiSummary"] == "genai_summary"
    assert incident["details"] == "d"


def test_get_paginated_threats_list(mocker):
    """
    Test the get_paginated_threats_list method to verify:
    1. It correctly handles pagination
    2. It respects the max_incidents_to_fetch parameter
    """
    # Create client
    client = Client(server_url=BASE_URL, verify=False, proxy=False, auth=None, headers=headers)

    # Create a side effect function for threats
    get_threats_side_effect = create_mock_paginator_side_effect("threat")

    # Mock the underlying get_a_list_of_threats_request method
    get_threats_mock = mocker.patch.object(client, "get_a_list_of_threats_request", side_effect=get_threats_side_effect)

    # Test case 1: Get all threats with high limit (max_incidents_to_fetch > existing items)
    # This should set page_size to the limit (10) but return only as many items as exist
    result = client.get_paginated_threats_list(filter_="test filter", max_incidents_to_fetch=10)

    # Verify the result contains threats (the exact count depends on the mock function)
    assert len(result["threats"]) > 0

    # Verify the first call was made with correct parameters
    assert get_threats_mock.call_count >= 1
    first_call_kwargs = get_threats_mock.call_args_list[0][1]
    assert first_call_kwargs["filter_"] == "test filter"
    assert first_call_kwargs["page_size"] == 10
    assert first_call_kwargs["page_number"] == 1

    # Reset the mock for the next test
    get_threats_mock.reset_mock()

    # Test case 2: Limited page size (max_incidents_to_fetch = 2)
    # With many threats available and max_incidents_to_fetch=2, we expect page_size=2
    # This should result in multiple page calls since there are more threats than fit on one page
    result = client.get_paginated_threats_list(filter_="test filter", max_incidents_to_fetch=2)

    # Verify we got threats
    assert len(result["threats"]) > 0

    # Verify each page was requested with the correct parameters
    assert get_threats_mock.call_count >= 1

    # Check first call parameters
    first_call_kwargs = get_threats_mock.call_args_list[0][1]
    assert first_call_kwargs["filter_"] == "test filter"
    assert first_call_kwargs["page_size"] == 2
    assert first_call_kwargs["page_number"] == 1

    # If there was a second call, check its parameters
    if get_threats_mock.call_count > 1:
        second_call_kwargs = get_threats_mock.call_args_list[1][1]
        assert second_call_kwargs["page_size"] == 2
        assert second_call_kwargs["page_number"] == 2

    # Reset the mock for the next test
    get_threats_mock.reset_mock()

    # Test case 3: One threat per page (max_incidents_to_fetch = 1)
    # With many threats available and max_incidents_to_fetch=1, we expect page_size=1
    # This should result in multiple page calls, one per threat
    result = client.get_paginated_threats_list(filter_="test filter", max_incidents_to_fetch=1)

    # Verify we got threats
    assert len(result["threats"]) > 0

    # Verify multiple pages were requested
    assert get_threats_mock.call_count >= 1

    # Check that all calls have the correct page_size
    for i in range(get_threats_mock.call_count):
        call_kwargs = get_threats_mock.call_args_list[i][1]
        assert call_kwargs["page_size"] == 1
        assert call_kwargs["page_number"] == i + 1

    # Reset the mock for the next test
    get_threats_mock.reset_mock()

    # Test case 4: No threats to fetch (max_incidents_to_fetch = 0)
    result = client.get_paginated_threats_list(filter_="test filter", max_incidents_to_fetch=0)

    # Verify that no threats were fetched
    assert len(result["threats"]) == 0

    # Verify that the underlying method was not called
    assert get_threats_mock.call_count == 0


def test_get_paginated_cases_list(mocker):
    """
    Test the get_paginated_cases_list method to verify:
    1. It correctly handles pagination
    2. It respects the max_incidents_to_fetch parameter
    """
    # Create client
    client = Client(server_url=BASE_URL, verify=False, proxy=False, auth=None, headers=headers)

    # Create a side effect function for cases
    get_cases_side_effect = create_mock_paginator_side_effect("case")

    # Mock the underlying get_a_list_of_abnormal_cases_identified_by_abnormal_security_request method
    get_cases_mock = mocker.patch.object(
        client, "get_a_list_of_abnormal_cases_identified_by_abnormal_security_request", side_effect=get_cases_side_effect
    )

    # Test case 1: Get all cases with high limit (max_incidents_to_fetch > existing items)
    # This should set page_size to the limit (10) but return only as many items as exist
    result = client.get_paginated_cases_list(filter_="test filter", max_incidents_to_fetch=10)

    # Verify the result contains cases (the exact count depends on the mock function)
    assert len(result["cases"]) > 0

    # Verify the first call was made with correct parameters
    assert get_cases_mock.call_count >= 1
    first_call_kwargs = get_cases_mock.call_args_list[0][1]
    assert first_call_kwargs["filter_"] == "test filter"
    assert first_call_kwargs["page_size"] == 10
    assert first_call_kwargs["page_number"] == 1

    # Reset the mock for the next test
    get_cases_mock.reset_mock()

    # Test case 2: Limited page size (max_incidents_to_fetch = 2)
    # With many cases available and max_incidents_to_fetch=2, we expect page_size=2
    # This should result in multiple page calls since there are more cases than fit on one page
    result = client.get_paginated_cases_list(filter_="test filter", max_incidents_to_fetch=2)

    # Verify we got cases
    assert len(result["cases"]) > 0

    # Verify each page was requested with the correct parameters
    assert get_cases_mock.call_count >= 1

    # Check first call parameters
    first_call_kwargs = get_cases_mock.call_args_list[0][1]
    assert first_call_kwargs["filter_"] == "test filter"
    assert first_call_kwargs["page_size"] == 2
    assert first_call_kwargs["page_number"] == 1

    # If there was a second call, check its parameters
    if get_cases_mock.call_count > 1:
        second_call_kwargs = get_cases_mock.call_args_list[1][1]
        assert second_call_kwargs["page_size"] == 2
        assert second_call_kwargs["page_number"] == 2

    # Reset the mock for the next test
    get_cases_mock.reset_mock()

    # Test case 3: One case per page (max_incidents_to_fetch = 1)
    # With many cases available and max_incidents_to_fetch=1, we expect page_size=1
    # This should result in multiple page calls, one per case
    result = client.get_paginated_cases_list(filter_="test filter", max_incidents_to_fetch=1)

    # Verify we got cases
    assert len(result["cases"]) > 0

    # Verify multiple pages were requested
    assert get_cases_mock.call_count >= 1

    # Check that all calls have the correct page_size
    for i in range(get_cases_mock.call_count):
        call_kwargs = get_cases_mock.call_args_list[i][1]
        assert call_kwargs["page_size"] == 1
        assert call_kwargs["page_number"] == i + 1

    # Reset the mock for the next test
    get_cases_mock.reset_mock()

    # Test case 4: No cases to fetch (max_incidents_to_fetch = 0)
    result = client.get_paginated_cases_list(filter_="test filter", max_incidents_to_fetch=0)

    # Verify that no cases were fetched
    assert len(result["cases"]) == 0

    # Verify that the underlying method was not called
    assert get_cases_mock.call_count == 0


def test_get_paginated_abusecampaigns_list(mocker):
    """
    Test the get_paginated_abusecampaigns_list method to verify:
    1. It correctly handles pagination
    2. It respects the max_incidents_to_fetch parameter
    """
    # Create client
    client = Client(server_url=BASE_URL, verify=False, proxy=False, auth=None, headers=headers)

    # Create a side effect function for campaigns
    get_campaigns_side_effect = create_mock_paginator_side_effect("campaign")

    # Mock the underlying get_a_list_of_campaigns_submitted_to_abuse_mailbox_request method
    get_campaigns_mock = mocker.patch.object(
        client, "get_a_list_of_campaigns_submitted_to_abuse_mailbox_request", side_effect=get_campaigns_side_effect
    )

    # Test case 1: Get all campaigns with high limit (max_incidents_to_fetch > existing items)
    # This should set page_size to the limit (10) but return only as many items as exist
    result = client.get_paginated_abusecampaigns_list(filter_="test filter", max_incidents_to_fetch=10)

    # Verify the result contains campaigns (the exact count depends on the mock function)
    assert len(result["campaigns"]) > 0

    # Verify the first call was made with correct parameters
    assert get_campaigns_mock.call_count >= 1
    first_call_kwargs = get_campaigns_mock.call_args_list[0][1]
    assert first_call_kwargs["filter_"] == "test filter"
    assert first_call_kwargs["page_size"] == 10
    assert first_call_kwargs["page_number"] == 1

    # Reset the mock for the next test
    get_campaigns_mock.reset_mock()

    # Test case 2: Limited page size (max_incidents_to_fetch = 2)
    # With many campaigns available and max_incidents_to_fetch=2, we expect page_size=2
    # This should result in multiple page calls since there are more campaigns than fit on one page
    result = client.get_paginated_abusecampaigns_list(filter_="test filter", max_incidents_to_fetch=2)

    # Verify we got campaigns
    assert len(result["campaigns"]) > 0

    # Verify each page was requested with the correct parameters
    assert get_campaigns_mock.call_count >= 1

    # Check first call parameters
    first_call_kwargs = get_campaigns_mock.call_args_list[0][1]
    assert first_call_kwargs["filter_"] == "test filter"
    assert first_call_kwargs["page_size"] == 2
    assert first_call_kwargs["page_number"] == 1

    # If there was a second call, check its parameters
    if get_campaigns_mock.call_count > 1:
        second_call_kwargs = get_campaigns_mock.call_args_list[1][1]
        assert second_call_kwargs["page_size"] == 2
        assert second_call_kwargs["page_number"] == 2

    # Reset the mock for the next test
    get_campaigns_mock.reset_mock()

    # Test case 3: One campaign per page (max_incidents_to_fetch = 1)
    # With many campaigns available and max_incidents_to_fetch=1, we expect page_size=1
    # This should result in multiple page calls, one per campaign
    result = client.get_paginated_abusecampaigns_list(filter_="test filter", max_incidents_to_fetch=1)

    # Verify we got campaigns
    assert len(result["campaigns"]) > 0

    # Verify multiple pages were requested
    assert get_campaigns_mock.call_count >= 1

    # Check that all calls have the correct page_size
    for i in range(get_campaigns_mock.call_count):
        call_kwargs = get_campaigns_mock.call_args_list[i][1]
        assert call_kwargs["page_size"] == 1
        assert call_kwargs["page_number"] == i + 1

    # Reset the mock for the next test
    get_campaigns_mock.reset_mock()

    # Test case 4: No campaigns to fetch (max_incidents_to_fetch = 0)
    result = client.get_paginated_abusecampaigns_list(filter_="test filter", max_incidents_to_fetch=0)

    # Verify that no campaigns were fetched
    assert len(result["campaigns"]) == 0

    # Verify that the underlying method was not called
    assert get_campaigns_mock.call_count == 0


def test_search_messages_command(mocker):
    """
    Test the search_messages_command to verify:
    1. It correctly formats the request parameters
    2. It returns the expected output structure
    """
    from AbnormalSecurity import search_messages_command

    # Create mock response
    mock_response = {
        "results": [
            {
                "customer_id": 12345,
                "tenant_id": 1,
                "received_time": "2024-01-15T10:30:00Z",
                "subject": "Test Message",
                "sender": "sender@example.com",
                "mailbox_name": "user@company.com",
                "abnormal_message_id": "abnormal-uuid-123",
                "decision_category": "malicious",
                "judgement": "attack",
            }
        ],
        "total": 1,
        "pageNumber": 1,
        "nextPageNumber": None,
    }

    client = mock_client(mocker, mock_response)

    args = {
        "source": "abnormal",
        "tenant_ids": "1,2,3",
        "start_time": "2024-01-01T00:00:00Z",
        "end_time": "2024-01-31T23:59:59Z",
        "subject": "Test",
        "sender_email": "sender@example.com",
        "page_number": 1,
        "page_size": 100,
    }

    results = search_messages_command(client, args)

    # Verify the output
    assert results.outputs_prefix == "AbnormalSecurity.MessageSearch"
    assert results.outputs_key_field == "abnormal_message_id"
    assert results.outputs.get("total") == 1
    assert len(results.outputs.get("results", [])) == 1
    assert results.outputs["results"][0]["abnormal_message_id"] == "abnormal-uuid-123"


def test_remediate_messages_command(mocker):
    """
    Test the remediate_messages_command to verify:
    1. It correctly handles remediation requests
    2. It returns the expected output structure
    """
    from AbnormalSecurity import remediate_messages_command

    # Create mock response
    mock_response = {"activity_log_id": 12345, "metadata": {"trace_id": "abc-123-def", "response_time": "150ms"}}

    client = mock_client(mocker, mock_response)

    args = {
        "action": "delete",
        "tenant_ids": "1,2,3",
        "source": "abnormal",
        "remediation_reason": "false_negative",
        "messages": json.dumps(
            [
                {
                    "tenant_id": 1,
                    "raw_message_id": "msg-123",
                    "abnormal_message_id": "abnormal-uuid-123",
                    "mailbox_name": "user@company.com",
                    "subject": "Test Message",
                    "sender": "sender@example.com",
                    "received_time": "2024-01-15T10:30:00Z",
                }
            ]
        ),
    }

    results = remediate_messages_command(client, args)

    # Verify the output
    assert results.outputs_prefix == "AbnormalSecurity.MessageRemediation"
    assert results.outputs_key_field == "activity_log_id"
    assert results.outputs.get("activity_log_id") == 12345


def test_remediate_messages_command_remediate_all(mocker):
    """
    Test the remediate_messages_command with remediate_all option.
    """
    from AbnormalSecurity import remediate_messages_command

    # Create mock response
    mock_response = {"activity_log_id": 12346, "metadata": {"trace_id": "xyz-456-def", "response_time": "200ms"}}

    client = mock_client(mocker, mock_response)

    args = {
        "action": "delete",
        "tenant_ids": "1",
        "source": "abnormal",
        "remediation_reason": "false_negative",
        "remediate_all": "true",
        "start_time": "2024-01-01T00:00:00Z",
        "end_time": "2024-01-31T23:59:59Z",
        "subject": "Phishing",
        "sender_email": "attacker@example.com",
    }

    results = remediate_messages_command(client, args)

    # Verify the output
    assert results.outputs_prefix == "AbnormalSecurity.MessageRemediation"
    assert results.outputs.get("activity_log_id") == 12346


def test_get_activities_list_command(mocker):
    """
    Test the get_activities_list_command to verify:
    1. It correctly formats the request parameters
    2. It returns the expected output structure
    """
    from AbnormalSecurity import get_activities_list_command

    # Create mock response
    mock_response = {
        "activities": [
            {
                "activity_id": 12345,
                "action": "remediate",
                "status": "success",
                "performed_by": "user@company.com",
                "timestamp": "2024-01-15T10:30:00Z",
                "result_count": 25,
            }
        ],
        "total": 1,
        "page": 1,
        "size": 100,
    }

    client = mock_client(mocker, mock_response)

    args = {
        "tenant_ids": "1,2,3",
        "action": "remediate",
        "status": "success",
        "start_date": "2024-01-01T00:00:00Z",
        "end_date": "2024-01-31T23:59:59Z",
        "page": 1,
        "size": 100,
    }

    results = get_activities_list_command(client, args)

    # Verify the output
    assert results.outputs_prefix == "AbnormalSecurity.Activities"
    assert results.outputs_key_field == "activity_id"
    assert results.outputs.get("total") == 1
    assert len(results.outputs.get("activities", [])) == 1
    assert results.outputs["activities"][0]["activity_id"] == 12345


def test_get_activity_status_command(mocker):
    """
    Test the get_activity_status_command to verify:
    1. It correctly formats the request parameters
    2. It returns the expected output structure with remediation details
    """
    from AbnormalSecurity import get_activity_status_command

    # Create mock response
    mock_response = {
        "activity_id": 12345,
        "action": "remediate",
        "status": "success",
        "performed_by": "user@company.com",
        "timestamp": "2024-01-15T10:30:00Z",
        "result_count": 2,
        "remediation_details": [
            {
                "tenant_id": 1,
                "raw_message_id": "msg-123",
                "subject": "Test Message 1",
                "sender": "sender1@example.com",
                "mailbox_name": "user@company.com",
                "status": "success",
                "date_remediated": "2024-01-15T10:35:00Z",
            },
            {
                "tenant_id": 1,
                "raw_message_id": "msg-124",
                "subject": "Test Message 2",
                "sender": "sender2@example.com",
                "mailbox_name": "user@company.com",
                "status": "success",
                "date_remediated": "2024-01-15T10:35:00Z",
            },
        ],
        "total": 2,
        "page": 1,
        "size": 100,
    }

    client = mock_client(mocker, mock_response)

    args = {"activity_log_id": "12345", "page": 1, "size": 100}

    results = get_activity_status_command(client, args)

    # Verify the output
    assert results.outputs_prefix == "AbnormalSecurity.ActivityStatus"
    assert results.outputs_key_field == "activity_id"
    assert results.outputs.get("activity_id") == 12345
    assert results.outputs.get("status") == "success"
    assert len(results.outputs.get("remediation_details", [])) == 2
    assert results.outputs.get("total") == 2


def test_get_activity_status_command_in_progress(mocker):
    """
    Test the get_activity_status_command when activity is in progress with null values
    """
    from AbnormalSecurity import get_activity_status_command

    # Create mock response with null values (activity in progress)
    mock_response = {
        "activity_id": 179049,
        "action": "remediation",
        "status": None,
        "performed_by": None,
        "timestamp": None,
        "result_count": None,
        "remediation_details": None,
        "total": None,
        "pageNumber": None,
        "pageSize": None,
        "metadata": {"trace_id": "2b8009b3784f4b5aa92fa203d59196f5", "response_time": "12.537802ms"},
    }

    client = mock_client(mocker, mock_response)

    args = {"activity_log_id": "179049"}

    results = get_activity_status_command(client, args)

    # Verify the output
    assert results.outputs_prefix == "AbnormalSecurity.ActivityStatus"
    assert results.outputs_key_field == "activity_id"
    assert results.outputs.get("activity_id") == 179049
    assert results.outputs.get("action") == "remediation"
    assert results.outputs.get("metadata", {}).get("trace_id") == "2b8009b3784f4b5aa92fa203d59196f5"
    # Verify readable output contains in-progress message
    assert "In Progress" in results.readable_output or "in progress" in results.readable_output


def test_download_message_attachment_command(mocker):
    """
    Test the download_message_attachment_command to verify:
    1. It correctly formats the request parameters
    2. It returns a file result
    """
    from AbnormalSecurity import download_message_attachment_command

    # Create mock response for file download
    mock_file_content = b"Mock attachment file content"
    mock_response = MockResponse(mock_file_content, 200)

    client = mock_client(mocker, mock_response)

    args = {
        "message_id": "abnormal-uuid-123",
        "attachment_name": "invoice.pdf",
        "tenant_id": 1,
        "raw_message_id": "msg-123",
        "native_user_id": "user-456",
        "recipient_mailbox": "user@company.com",
    }

    results = download_message_attachment_command(client, args)

    # Verify the file result
    assert results["File"] == "invoice.pdf"
    assert results["FileID"] is not None


def test_download_message_eml_command(mocker):
    """
    Test the download_message_eml_command to verify:
    1. It correctly formats the request parameters
    2. It returns a file result with EML format
    """
    from AbnormalSecurity import download_message_eml_command

    # Create mock response for EML file download
    mock_eml_content = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest email body"
    mock_response = MockResponse(mock_eml_content, 200)

    client = mock_client(mocker, mock_response)

    args = {"cloud_message_id": "abx:CloudMessage:12345:67890"}

    results = download_message_eml_command(client, args)

    # Verify the file result
    assert results["File"] == "abx_CloudMessage_12345_67890.eml"
    assert results["FileID"] is not None


def test_download_message_eml_command_with_quarantine(mocker):
    """
    Test the download_message_eml_command with quarantine parameters.
    """
    from AbnormalSecurity import download_message_eml_command

    # Create mock response for EML file download
    mock_eml_content = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest email body"
    mock_response = MockResponse(mock_eml_content, 200)

    client = mock_client(mocker, mock_response)

    args = {
        "cloud_message_id": "abx:CloudMessage:12345:67890",
        "quarantine_identity": "quarantine-id-123",
        "recipient_mailbox": "user@company.com",
    }

    results = download_message_eml_command(client, args)

    # Verify the file result
    assert results["File"] == "abx_CloudMessage_12345_67890.eml"
    assert results["FileID"] is not None


"""
    _is_skippable_error Unit Tests
"""


@pytest.mark.parametrize(
    "status_code, expected",
    [
        (404, True),
        (400, True),
        (410, True),
        (405, True),
        (401, False),
        (403, False),
        (429, False),
        (500, False),
        (502, False),
    ],
)
def test_is_skippable_error(status_code, expected):
    """Test that _is_skippable_error correctly categorizes errors by response status code."""
    exc = DemistoException(f"Error in API call [{status_code}]", res=MockResponse(None, status_code))
    assert _is_skippable_error(exc) == expected


def test_is_skippable_error_no_response():
    """Test that errors without a response object are not skippable."""
    exc = DemistoException("Some unexpected error with no status code")
    assert _is_skippable_error(exc) is False


"""
    fetch-incidents Tests
"""

FETCH_NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
FETCH_START = "2026-10-02T09:00:00Z"
ALL_TYPES = {"fetch_threats": True, "fetch_abuse_campaigns": True, "fetch_account_takeover_cases": True}


@pytest.fixture
def api(requests_mock, mocker):
    mocker.patch("AbnormalSecurity.get_current_datetime", return_value=FETCH_NOW)
    return FakeSoarApi(requests_mock, BASE_URL)


def run_fetch(last_run=None, **kwargs):
    options = {
        "first_fetch_time": FETCH_START,
        "fetch_threats": True,
        "fetch_abuse_campaigns": False,
        "fetch_account_takeover_cases": False,
        "polling_lag": timedelta(0),
        "max_incidents_to_fetch": 200,
        # Fast enough not to slow the tests; the limiter itself is tested on its own.
        "detail_rate_per_second": 1000,
        **kwargs,
    }
    client = Client(server_url=BASE_URL, verify=False, proxy=False, auth=None, headers=headers)
    return fetch_incidents(client=client, last_run=last_run or {}, **options)


def fetch_until_caught_up(last_run=None, max_runs=30, **kwargs):
    """Runs fetch the way XSOAR does, feeding each run's last_run into the next, until a run returns nothing."""
    last_run, emitted, all_warnings = last_run or {}, [], []
    for _ in range(max_runs):
        last_run, incidents, warnings = run_fetch(last_run, **kwargs)
        all_warnings.extend(warnings)
        if not incidents and not any(
            last_run[k]["failed"] for k in ("threats", "abuse_campaigns", "account_takeover") if k in last_run
        ):
            return last_run, emitted, all_warnings
        emitted.extend(incident["dbotMirrorId"] for incident in incidents)
    raise AssertionError("fetch never caught up")


def add_threats(api, count, start="2026-10-02T09:00:00Z", step_minutes=7):
    base = datetime.strptime(start, ISO_8601_FORMAT).replace(tzinfo=UTC)
    ids = []
    for i in range(count):
        threat_id = f"t-{i:03d}"
        api.add_threat(threat_id, (base + timedelta(minutes=step_minutes * i)).strftime(ISO_8601_FORMAT))
        ids.append(threat_id)
    return ids


def test_fetch_resumes_after_max_fetch(api):
    """
    Given 20 threats over 3 hours, more than one run's max_fetch.
    When fetch runs repeatedly with max_fetch=3.
    Then every threat becomes exactly one incident, which 2.4.9 lost by moving last_fetch to now.
    """
    ids = add_threats(api, 20, step_minutes=9)

    last_run, emitted, warnings = fetch_until_caught_up(max_incidents_to_fetch=3)

    assert sorted(emitted) == ids
    assert warnings == []
    assert last_run["threats"]["window_start"] == "2026-10-02T12:00:00Z"
    assert last_run["last_fetch"] == "2026-10-02T12:00:00Z"


def test_fetch_resumes_after_budget_exhausted(api):
    """
    Given a fake clock that advances 10s per HTTP call and a 45s budget.
    When fetch runs.
    Then it stops early without raising, and the next runs pick up the rest with nothing lost.
    """
    ids = add_threats(api, 8)
    clock = {"now": 0.0}

    def tick(_path):
        clock["now"] += 10

    api.on_call = tick
    first_run, incidents, _ = run_fetch(deadline=Deadline(45, clock=lambda: clock["now"]), detail_concurrency=1)

    assert 0 < len(incidents) < len(ids)
    assert first_run["threats"]["window_start"] == "2026-10-02T09:00:00Z"
    api.on_call = None
    _, rest, _ = fetch_until_caught_up(first_run)
    assert sorted([i["dbotMirrorId"] for i in incidents] + rest) == ids


def test_fetch_relisted_window_in_new_order_deduplicates(api):
    ids = add_threats(api, 6, step_minutes=5)
    first_run, first, _ = run_fetch(max_incidents_to_fetch=2)
    api.ascending = True

    _, rest, _ = fetch_until_caught_up(first_run, max_incidents_to_fetch=2)

    emitted = [i["dbotMirrorId"] for i in first] + rest
    assert sorted(emitted) == ids
    assert len(emitted) == len(set(emitted))


def test_fetch_5xx_on_cases_still_lets_threats_advance(api):
    add_threats(api, 3)
    api.add_case("c-1", "2026-10-02T09:30:00Z")
    api.fail(r"^/cases$", 500)

    last_run, incidents, warnings = run_fetch(**ALL_TYPES)

    assert {i["name"] for i in incidents} == {"Threat"}
    assert last_run["threats"]["window_start"] == "2026-10-02T12:00:00Z"
    assert last_run["account_takeover"]["window_start"] == "2026-10-02T09:00:00Z"
    assert any("account takeover cases failed" in w for w in warnings)
    _, rest, _ = fetch_until_caught_up(last_run, **ALL_TYPES)
    assert rest == ["c-1"]


@pytest.mark.parametrize("path, status", [(r"^/threats$", 401), (r"^/threats/", 403)])
def test_fetch_auth_error_commits_nothing(api, path, status):
    add_threats(api, 2)
    api.fail(path, status)

    with pytest.raises(AuthError):
        run_fetch()


def test_fetch_404_detail_counts_as_emitted(api):
    add_threats(api, 2)
    api.add_threat("t-gone", "2026-10-02T09:01:00Z")
    api.fail(r"^/threats/t-gone$", 404, times=None)

    last_run, incidents, warnings = run_fetch()

    assert sorted(i["dbotMirrorId"] for i in incidents) == ["t-000", "t-001"]
    assert last_run["threats"]["window_start"] == "2026-10-02T12:00:00Z"
    assert warnings == []


def test_fetch_retention_400_moves_window_forward_and_warns(api):
    add_threats(api, 1, start="2026-10-02T10:30:00Z")
    message = "Dates provided (2026-10-02 09:00:00 to 2026-10-02 10:00:00) are out of accepted data retention range"
    api.fail(r"^/threats$", 400, body={"message": message})

    _, incidents, warnings = run_fetch()

    assert [i["dbotMirrorId"] for i in incidents] == ["t-000"]
    assert len(warnings) == 1
    assert "retention" in warnings[0]


def test_fetch_other_400_does_not_skip_window(api):
    add_threats(api, 1)
    api.fail(r"^/threats$", 400, body={"message": "bad filter"})

    last_run, incidents, warnings = run_fetch()

    assert incidents == []
    assert last_run["threats"]["window_start"] == "2026-10-02T09:00:00Z"
    assert len(warnings) == 1


def test_fetch_402_on_cases_skips_account_takeover_cases_and_warns(api):
    add_threats(api, 1)
    api.add_case("c-1", "2026-10-02T09:30:00Z")
    api.fail(r"^/cases$", 402, times=None)

    last_run, incidents, warnings = run_fetch(**ALL_TYPES)

    assert [i["name"] for i in incidents] == ["Threat"]
    assert last_run["account_takeover"]["window_start"] == "2026-10-02T09:00:00Z"
    assert warnings == ["Skipped account takeover cases: the tenant isn't licensed for them."]


def test_fetch_item_failing_on_three_runs_is_skipped_with_warning(api):
    """
    Given one threat whose detail call always returns 500.
    When fetch runs three times.
    Then the others become incidents on the first run, the window waits for the bad one,
    and on the third failure it's skipped with a warning and the window advances.
    """
    add_threats(api, 3)
    api.fail(r"^/threats/t-001$", 500, times=None)

    run_1, incidents_1, warnings_1 = run_fetch()
    run_2, incidents_2, _ = run_fetch(run_1)
    run_3, incidents_3, warnings_3 = run_fetch(run_2)

    assert sorted(i["dbotMirrorId"] for i in incidents_1) == ["t-000", "t-002"]
    assert run_1["threats"]["failed"] == {"t-001": 1}
    assert run_2["threats"]["failed"] == {"t-001": 2}
    assert incidents_2 == incidents_3 == []
    assert warnings_1 == []
    assert any("t-001" in w and "3 runs" in w for w in warnings_3)
    assert run_3["threats"]["window_start"] == "2026-10-02T12:00:00Z"
    assert len(api.detail_calls("threats")) == 3 + 1 + 1


def test_fetch_bad_item_does_not_stop_others(api):
    api.add_case("c-1", "2026-10-02T09:10:00Z")
    api.add_case("c-2", "2026-10-02T09:20:00Z", firstObserved=None)
    api.add_case("c-3", "2026-10-02T09:30:00Z")

    last_run, incidents, _ = run_fetch(fetch_threats=False, fetch_account_takeover_cases=True)

    assert sorted(i["dbotMirrorId"] for i in incidents) == ["c-1", "c-3"]
    assert last_run["account_takeover"]["failed"] == {"c-2": 1}


def test_fetch_five_consecutive_failures_stop_the_type(api):
    add_threats(api, 7)
    api.add_campaign("a-1", "2026-10-02T09:30:00Z")
    api.fail(r"^/threats/", 503, times=None)

    last_run, incidents, warnings = run_fetch(fetch_abuse_campaigns=True, detail_concurrency=1)

    assert len(api.detail_calls("threats")) == 5
    assert [i["dbotMirrorId"] for i in incidents] == ["a-1"]
    assert any("5 failures in a row" in w for w in warnings)
    assert len(last_run["threats"]["failed"]) == 5


def test_fetch_overflow_halves_window_and_saves_new_end(api, mocker):
    """
    Given 6 threats in the first hour and a list page size of 2.
    When fetch runs with max_fetch=1.
    Then the window is halved until it fits in one page, the halved end is saved, and later runs
    still emit every threat once.
    """
    mocker.patch("AbnormalSecurity.LIST_PAGE_SIZE", 2)
    ids = add_threats(api, 6, step_minutes=9)

    first_run, incidents, _ = run_fetch(max_incidents_to_fetch=1)

    assert len(incidents) == 1
    assert first_run["threats"]["window_end"] < "2026-10-02T10:00:00Z"
    assert all(int(q["pageSize"]) == 2 and q.get("pageNumber", "1") == "1" for q in api.list_calls("threats"))
    _, rest, _ = fetch_until_caught_up(first_run, max_incidents_to_fetch=1)
    assert sorted([incidents[0]["dbotMirrorId"]] + rest) == ids


def test_fetch_partly_drained_window_paginates_instead_of_halving(api, mocker):
    mocker.patch("AbnormalSecurity.LIST_PAGE_SIZE", 2)
    add_threats(api, 4, step_minutes=5)
    last_run = {
        "version": 2,
        "threats": {
            "enabled": True,
            "window_start": "2026-10-02T09:00:00Z",
            "window_end": "2026-10-02T10:00:00Z",
            "emitted_ids": ["t-003"],
            "failed": {},
        },
    }

    next_run, incidents, _ = run_fetch(last_run)

    assert sorted(i["dbotMirrorId"] for i in incidents) == ["t-000", "t-001", "t-002"]
    first_window_calls = api.list_calls("threats")[:2]
    assert [q.get("pageNumber") for q in first_window_calls] == ["1", "2"]
    assert all(q["filter"].endswith("lte 2026-10-02T10:00:00Z") for q in first_window_calls)
    assert next_run["threats"]["window_start"] == "2026-10-02T12:00:00Z"


def test_build_list_filter_strings():
    window = FetchWindow(
        enabled=True,
        window_start=datetime(2026, 10, 2, 9, 0, 0, tzinfo=UTC),
        window_end=datetime(2026, 10, 2, 10, 0, 0, tzinfo=UTC),
    )

    assert (
        build_list_filter(THREATS_SPEC, window)
        == "latestTimeRemediated gte 2026-10-02T09:00:00Z and latestTimeRemediated lte 2026-10-02T10:00:00Z"
    )
    assert (
        build_list_filter(ABUSE_CAMPAIGNS_SPEC, window)
        == "lastReportedTime gte 2026-10-02T09:00:00Z and lastReportedTime lte 2026-10-02T09:59:59.999999Z"
    )
    assert (
        build_list_filter(ACCOUNT_TAKEOVER_SPEC, window)
        == "lastModifiedTime gte 2026-10-02T09:00:00Z and lastModifiedTime lte 2026-10-02T09:59:59.999999Z"
    )


def test_fetch_window_boundary_items_land_in_exactly_one_window(api):
    api.add_threat("t-edge", "2026-10-02T10:00:00Z")
    api.add_campaign("a-edge", "2026-10-02T10:00:00Z")

    _, emitted, _ = fetch_until_caught_up(fetch_abuse_campaigns=True)

    assert sorted(emitted) == ["a-edge", "t-edge"]


def test_fetch_migrates_v1_last_run(api):
    """
    Given a 2.4.9 last_run and a 2-minute polling lag.
    When the new code runs for the first time.
    Then each window starts where 2.4.9's next run would have started.
    """
    api.add_threat("t-1", "2026-10-02T10:59:00Z")

    next_run, incidents, _ = run_fetch(
        {"last_fetch": "2026-10-02T11:00:00Z"}, polling_lag=timedelta(minutes=2), max_incidents_to_fetch=0
    )

    assert next_run["version"] == 2
    assert next_run["threats"]["window_start"] == "2026-10-02T10:58:00Z"
    assert next_run["threats"]["window_end"] == "2026-10-02T11:58:00Z"
    assert next_run["last_fetch"] == "2026-10-02T10:58:00Z"
    assert "abuse_campaigns" not in next_run
    assert incidents == []
    _, incidents, _ = run_fetch(next_run, polling_lag=timedelta(minutes=2))
    assert [i["dbotMirrorId"] for i in incidents] == ["t-1"]


def test_fetch_writes_oldest_window_start_as_last_fetch_for_rollback(api):
    add_threats(api, 2)
    api.add_case("c-1", "2026-10-02T09:30:00Z")
    api.fail(r"^/cases$", 500)

    next_run, _, _ = run_fetch(**ALL_TYPES)

    assert next_run["last_fetch"] == next_run["account_takeover"]["window_start"] == "2026-10-02T09:00:00Z"


def test_fetch_newly_enabled_type_starts_at_now_minus_lag(api):
    add_threats(api, 1)
    api.add_campaign("a-old", "2026-10-02T09:30:00Z")
    api.add_campaign("a-new", "2026-10-02T11:59:30Z")
    first_run, _, _ = run_fetch()
    first_run, _, _ = run_fetch(first_run, fetch_abuse_campaigns=False)

    next_run, incidents, _ = run_fetch(first_run, fetch_abuse_campaigns=True, polling_lag=timedelta(minutes=1))

    assert next_run["abuse_campaigns"]["window_start"] == "2026-10-02T11:59:00Z"
    assert incidents == []


def test_fetch_disabled_type_keeps_its_window(api):
    first_run, _, _ = run_fetch(**ALL_TYPES)

    next_run, _, _ = run_fetch(first_run, fetch_abuse_campaigns=False)

    assert next_run["abuse_campaigns"]["enabled"] is False
    assert next_run["last_fetch"] == next_run["threats"]["window_start"]


def test_fetch_rotates_which_type_goes_first(api):
    api.add_threat("t-1", "2026-10-02T09:10:00Z")
    api.add_threat("t-2", "2026-10-02T09:20:00Z")
    api.add_campaign("a-1", "2026-10-02T09:10:00Z")
    api.add_campaign("a-2", "2026-10-02T09:20:00Z")

    run_1, incidents_1, _ = run_fetch(fetch_abuse_campaigns=True, max_incidents_to_fetch=1)
    _, incidents_2, _ = run_fetch(run_1, fetch_abuse_campaigns=True, max_incidents_to_fetch=1)

    assert [i["name"] for i in incidents_1 + incidents_2] == ["Threat", "Abuse Campaign"]


def test_fetch_with_wide_max_window_uses_one_window(api):
    add_threats(api, 1)

    next_run, incidents, _ = run_fetch(max_window_minutes=10**6)

    assert len(incidents) == 1
    assert next_run["threats"]["window_start"] == next_run["threats"]["window_end"] == "2026-10-02T12:00:00Z"


class _StubHandler(BaseHTTPRequestHandler):
    """Serves either no response at all (`hang`) or a body that trickles in a byte at a time (`drip`)."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            if self.server.mode == "hang":
                self.server.release.wait(30)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "100000")
            self.end_headers()
            while not self.server.release.wait(0.2):
                self.wfile.write(b" ")
                self.wfile.flush()
        except OSError:
            pass


@pytest.fixture
def stub_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    server.daemon_threads = True
    server.release = threading.Event()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.release.set()
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("mode", ["hang", "drip"])
def test_fetch_time_budget_bounds_hung_and_slow_responses(stub_server, mode, mocker):
    stub_server.mode = mode
    mocker.patch("AbnormalSecurity.get_current_datetime", return_value=FETCH_NOW)
    client = Client(
        server_url=f"http://127.0.0.1:{stub_server.server_port}", verify=False, proxy=False, auth=None, headers=headers
    )
    started = time.monotonic()

    next_run, incidents, _ = fetch_incidents(
        client=client,
        last_run={},
        first_fetch_time=FETCH_START,
        fetch_threats=True,
        fetch_abuse_campaigns=False,
        fetch_account_takeover_cases=False,
        fetch_time_budget=2,
    )

    assert time.monotonic() - started < 2 + 2
    assert incidents == []
    assert next_run["threats"]["window_start"] == "2026-10-02T09:00:00Z"


def test_rate_limiter_spaces_calls_with_a_burst_of_one():
    clock = {"now": 100.0}
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock["now"] += seconds

    limiter = RateLimiter(2, clock=lambda: clock["now"], sleep=sleep)

    for _ in range(3):
        limiter.acquire()

    assert sleeps == [0.5, 0.5]


def test_rate_limiter_stops_when_the_wait_would_pass_the_deadline():
    clock = {"now": 0.0}
    limiter = RateLimiter(0.1, clock=lambda: clock["now"], sleep=lambda _: None)
    limiter.acquire()

    with pytest.raises(BudgetExhaustedError):
        limiter.acquire(Deadline(5, clock=lambda: clock["now"]))


def patch_threat_details(mocker, delay):
    """Serves threat details without requests_mock, which serializes requests behind a global lock."""

    def get_details(self, threat_id, deadline=None, **kwargs):
        time.sleep(delay(threat_id))
        remediated = "2026-10-02T09:30:00Z"
        return {"threatId": threat_id, "messages": [{"receivedTime": remediated, "remediationTimestamp": remediated}]}

    return mocker.patch.object(Client, "get_details_of_a_threat_request", autospec=True, side_effect=get_details)


def test_fetch_detail_calls_stay_under_the_worker_cap(api, mocker):
    add_threats(api, 12, step_minutes=4)
    lock, in_flight = threading.Lock(), {"now": 0, "max": 0}

    def delay(_threat_id):
        with lock:
            in_flight["now"] += 1
            in_flight["max"] = max(in_flight["max"], in_flight["now"])
        time.sleep(0.05)
        with lock:
            in_flight["now"] -= 1
        return 0

    patch_threat_details(mocker, delay)
    _, incidents, _ = run_fetch(detail_concurrency=4, max_window_minutes=10**6)

    assert len(incidents) == 12
    assert in_flight["max"] == 4


def test_fetch_takes_one_rate_token_per_http_call(api, mocker):
    page = [{"receivedTime": "2026-10-02T09:10:00Z", "remediationTimestamp": "2026-10-02T09:10:00Z"}]
    api.add_threat("t-paged", "2026-10-02T09:10:00Z", message_pages=[page, page, page])
    acquire = mocker.spy(RateLimiter, "acquire")

    _, incidents, _ = run_fetch(max_window_minutes=10**6)

    assert len(json.loads(incidents[0]["rawJSON"])["messages"]) == 3
    assert len(api.detail_calls("threats")) == 3
    assert acquire.call_count == len(api.calls)


def test_fetch_429_mid_batch_keeps_completed_incidents(api):
    """
    Given 8 threats where the third one's detail call is rate limited.
    When fetch runs with 2 workers.
    Then incidents completed before the 429 are kept, the run stops, the window stays, and the
    next run emits the rest with no duplicates.
    """
    ids = add_threats(api, 8)
    api.ascending = True
    api.fail(r"^/threats/t-002$", 429)

    first_run, incidents, warnings = run_fetch(detail_concurrency=2, **ALL_TYPES)

    emitted = [i["dbotMirrorId"] for i in incidents]
    assert {"t-000", "t-001"} <= set(emitted)
    assert "t-002" not in emitted
    assert any("Rate limited" in w for w in warnings)
    assert first_run["threats"]["window_start"] == "2026-10-02T09:00:00Z"
    assert api.list_calls("abusecampaigns") == []
    _, rest, _ = fetch_until_caught_up(first_run)
    assert sorted(emitted + rest) == ids


def test_fetch_output_order_does_not_depend_on_worker_timing(api, mocker):
    add_threats(api, 10, step_minutes=5)
    # Earlier items finish last, so completion order is the reverse of list order.
    patch_threat_details(mocker, lambda threat_id: 0.1 - int(threat_id[2:]) * 0.01)

    _, concurrent, _ = run_fetch(detail_concurrency=4, max_window_minutes=10**6)
    _, serial, _ = run_fetch(detail_concurrency=1, max_window_minutes=10**6)

    assert [i["dbotMirrorId"] for i in concurrent] == [i["dbotMirrorId"] for i in serial]
