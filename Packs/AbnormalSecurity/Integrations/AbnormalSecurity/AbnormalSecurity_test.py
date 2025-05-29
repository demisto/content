import json
from datetime import datetime, timedelta, UTC
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
    generate_threat_incidents,
    get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command,
    fetch_incidents,
    ISO_8601_FORMAT,
)
from CommonServerPython import DemistoException
from test_data.fixtures import BASE_URL, apikey
from test_data.mock_paginated_response import create_mock_paginator_side_effect, create_mock_detail_side_effect


headers = {
    "Authorization": f"Bearer {apikey}",
}


class MockResponse:
    def __init__(self, data, status_code):
        self.data = data
        self.text = str(data)
        self.status_code = status_code


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


def test_fetch_threat_incidents(mocker, mock_get_a_list_of_threats_request):
    client = mock_client(mocker, util_load_json("test_data/test_get_details_of_a_threat_page2.json"))
    first_fetch_time = datetime.now().strftime(ISO_8601_FORMAT)
    _, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": "2023-09-17T14:43:09Z"},
        first_fetch_time=first_fetch_time,
        max_incidents_to_fetch=200,
        fetch_account_takeover_cases=False,
        fetch_abuse_campaigns=False,
        fetch_threats=True,
    )
    assert len(incidents) == 1


def test_fetch_cases_incidents(mocker, mock_get_a_list_of_abnormal_cases_identified_by_abnormal_security_request):
    client = mock_client(mocker, util_load_json("test_data/test_get_details_of_an_abnormal_case.json"))
    first_fetch_time = datetime.now().strftime(ISO_8601_FORMAT)
    _, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": "2023-09-17T14:43:09Z"},
        first_fetch_time=first_fetch_time,
        max_incidents_to_fetch=200,
        fetch_account_takeover_cases=True,
        fetch_abuse_campaigns=False,
        fetch_threats=False,
    )
    assert len(incidents) == 1
    assert incidents[0].get("genaiSummary") == "genai_summary"


def test_fetch_abuse_campaign_incidents(mocker, mock_get_a_list_of_campaigns_submitted_to_abuse_mailbox_request):
    client = mock_client(mocker, util_load_json("test_data/test_get_details_of_abuse_campaign.json"))
    first_fetch_time = datetime.now().strftime(ISO_8601_FORMAT)
    _, incidents = fetch_incidents(
        client=client,
        last_run={"last_fetch": "2023-09-17T14:43:09Z"},
        first_fetch_time=first_fetch_time,
        max_incidents_to_fetch=200,
        fetch_account_takeover_cases=False,
        fetch_abuse_campaigns=True,
        fetch_threats=False,
    )
    assert len(incidents) == 1


def test_get_details_of_a_threat_request_two_pages(mocker):
    return_val = util_load_json("test_data/test_get_details_of_a_threat.json")
    return_val["messages"][0]["remediationTimestamp"] = "2023-09-17T15:43:09Z"
    page_2 = util_load_json("test_data/test_get_details_of_a_threat_page2.json")
    page_2["messages"][0]["remediationTimestamp"] = "2023-09-17T16:43:09Z"

    client = mock_client(mocker, side_effect=[return_val, page_2])
    # Create datetime objects instead of using strings
    start_datetime = datetime(2023, 9, 17, 14, 43, 9, tzinfo=UTC)
    end_datetime = datetime(2023, 9, 18, 14, 43, 9, tzinfo=UTC)

    incidents = generate_threat_incidents(client, [{"threatId": "asdf097sdf907"}], 2, start_datetime, end_datetime)
    assert len(incidents) == 1
    assert len(json.loads(incidents[0].get("rawJSON")).get("messages")) == 2


def test_get_details_of_a_threat_request_single_page(mocker):
    return_val = util_load_json("test_data/test_get_details_of_a_threat_page2.json")
    return_val["messages"][0]["remediationTimestamp"] = "2023-09-17T15:43:09Z"
    client = mock_client(mocker, response=return_val)
    # Create datetime objects instead of using strings
    start_datetime = datetime(2023, 9, 17, 14, 43, 9, tzinfo=UTC)
    end_datetime = datetime(2023, 9, 18, 14, 43, 9, tzinfo=UTC)

    incidents = generate_threat_incidents(client, [{"threatId": "asdf097sdf907"}], 1, start_datetime, end_datetime)
    assert len(incidents) == 1


def test_get_details_of_a_threat_request_nanosecond_timestamp(mocker, mock_get_details_of_a_threat_request):
    client = mock_client(mocker, response=util_load_json("test_data/test_get_list_of_abnormal_threats.json"))
    last_run = {"last_fetch": "2023-09-17T14:43:09Z"}
    first_fetch_time = "3 days"
    max_incidents = 200
    # Call fetch_incidents with the polling lag
    _, incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_time,
        max_incidents_to_fetch=max_incidents,
        fetch_account_takeover_cases=False,
        fetch_abuse_campaigns=False,
        fetch_threats=True,
    )
    assert len(incidents) == 1
    assert incidents[0].get("occurred") == "2023-12-03T19:26:36.123456"


def test_polling_lag(mocker, mock_get_details_of_a_threat_request):
    """Test that polling lag is correctly applied when fetching incidents."""
    # Mock the client and its get_a_list_of_threats_request method
    return_val = util_load_json("test_data/test_get_list_of_abnormal_threats.json")
    client = mock_client(mocker, response=return_val)

    # Create a spy on the get_a_list_of_threats_request method to capture its calls
    get_threats_spy = mocker.spy(client, "get_a_list_of_threats_request")

    # Define test parameters
    last_run = {"last_fetch": "2023-09-17T14:43:09Z"}
    first_fetch_time = "3 days"
    max_incidents = 200

    # Set up a 5-minute polling lag
    polling_lag = timedelta(minutes=5)

    # Calculate expected timestamps
    original_timestamp = datetime.fromisoformat(last_run["last_fetch"][:-1]).replace(tzinfo=UTC) + timedelta(milliseconds=1)
    adjusted_start_time = original_timestamp - polling_lag
    expected_start_time = adjusted_start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Mock the get_current_datetime function to return a fixed time
    fixed_current_time = datetime(2023, 9, 18, 14, 43, 9, tzinfo=UTC)
    mocker.patch("AbnormalSecurity.get_current_datetime", return_value=fixed_current_time)

    # Calculate expected end time based on the fixed current time
    adjusted_end_time = fixed_current_time - polling_lag
    expected_end_time = adjusted_end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    expected_filter = f"latestTimeRemediated gte {expected_start_time} and latestTimeRemediated lte {expected_end_time}"

    # Call fetch_incidents with the polling lag
    _, _ = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_time,
        max_incidents_to_fetch=max_incidents,
        fetch_account_takeover_cases=False,
        fetch_abuse_campaigns=False,
        fetch_threats=True,
        polling_lag=polling_lag,
    )

    # Check that the method was called with the expected filter
    get_threats_spy.assert_called_once()
    call_args = get_threats_spy.call_args[1]

    # Assert that the filter matches our expected filter
    assert call_args["filter_"] == expected_filter
    assert call_args["page_size"] == 100


def test_get_details_of_a_threat_request_time_window_filtering(mocker):
    """Test that messages outside the time window are filtered out."""
    # Create a mock response with 3 messages
    mock_response = {
        "threatId": "test-threat-id",
        "messages": [
            {
                "threatId": "test-threat-id",
                "receivedTime": "2023-09-17T15:00:00Z",
                "remediationTimestamp": "2023-09-17T15:30:00Z",  # Inside window
            },
            {
                "threatId": "test-threat-id",
                "receivedTime": "2023-09-17T16:00:00Z",
                "remediationTimestamp": "2023-09-17T16:30:00Z",  # Inside window
            },
            {
                "threatId": "test-threat-id",
                "receivedTime": "2023-09-17T12:00:00Z",
                "remediationTimestamp": "2023-09-17T12:30:00Z",  # Outside window (before start_time)
            },
        ],
    }

    client = mock_client(mocker, response=mock_response)

    # Define time window that includes only the first two messages
    start_datetime = datetime(2023, 9, 17, 14, 0, 0, tzinfo=UTC)
    end_datetime = datetime(2023, 9, 17, 17, 0, 0, tzinfo=UTC)

    incidents = generate_threat_incidents(client, [{"threatId": "test-threat-id"}], 1, start_datetime, end_datetime)

    # Verify we get one incident
    assert len(incidents) == 1

    # Verify the incident contains only the messages within the time window
    incident_data = json.loads(incidents[0]["rawJSON"])
    assert len(incident_data["messages"]) == 2

    # Verify the filtered messages are the ones we expect
    remediation_times = [msg["remediationTimestamp"] for msg in incident_data["messages"]]
    assert "2023-09-17T15:30:00Z" in remediation_times
    assert "2023-09-17T16:30:00Z" in remediation_times
    assert "2023-09-17T12:30:00Z" not in remediation_times


def test_get_details_of_a_threat_request_early_exit(mocker):
    """Test that processing stops early when encountering messages outside the time window."""
    # Create mock responses for two pages
    # Page 1 with 2 messages (both inside time window)
    page_1 = {
        "threatId": "test-threat-id",
        "messages": [
            {
                "threatId": "test-threat-id",
                "receivedTime": "2023-09-17T16:00:00Z",
                "remediationTimestamp": "2023-09-17T16:30:00Z",  # Inside window (latest)
            },
            {
                "threatId": "test-threat-id",
                "receivedTime": "2023-09-17T15:00:00Z",
                "remediationTimestamp": "2023-09-17T15:30:00Z",  # Inside window
            },
        ],
        "nextPageNumber": 2,  # Indicate there's a second page
    }

    # Page 2 with 2 messages (both outside time window)
    page_2 = {
        "threatId": "test-threat-id",
        "messages": [
            {
                "threatId": "test-threat-id",
                "receivedTime": "2023-09-17T13:00:00Z",
                "remediationTimestamp": "2023-09-17T13:30:00Z",  # Outside window
            },
            {
                "threatId": "test-threat-id",
                "receivedTime": "2023-09-17T12:00:00Z",
                "remediationTimestamp": "2023-09-17T12:30:00Z",  # Outside window (earliest)
            },
        ],
        "nextPageNumber": None,  # No more pages
    }

    # Create a spy for the get_details_of_a_threat_request method
    client = mock_client(mocker, side_effect=[page_1, page_2])
    get_details_spy = mocker.spy(client, "get_details_of_a_threat_request")

    # Define time window that includes only the first two messages
    start_datetime = datetime(2023, 9, 17, 14, 0, 0, tzinfo=UTC)
    end_datetime = datetime(2023, 9, 17, 17, 0, 0, tzinfo=UTC)

    incidents = generate_threat_incidents(client, [{"threatId": "test-threat-id"}], 3, start_datetime, end_datetime)

    # Verify we get one incident
    assert len(incidents) == 1

    # Verify the incident contains only the messages within the time window
    incident_data = json.loads(incidents[0]["rawJSON"])
    assert len(incident_data["messages"]) == 2

    # Verify the filtered messages are the ones we expect (from page 1 only)
    remediation_times = [msg["remediationTimestamp"] for msg in incident_data["messages"]]
    assert "2023-09-17T16:30:00Z" in remediation_times
    assert "2023-09-17T15:30:00Z" in remediation_times
    assert "2023-09-17T13:30:00Z" not in remediation_times
    assert "2023-09-17T12:30:00Z" not in remediation_times

    # Verify that get_details_of_a_threat_request was called exactly twice
    # (once for page 1, once for page 2 where we encounter messages outside the time window and exit early)
    assert get_details_spy.call_count == 2

    # Verify the calls were made with the correct page numbers
    first_call_args = get_details_spy.call_args_list[0][1]
    second_call_args = get_details_spy.call_args_list[1][1]
    assert first_call_args["page_number"] == 1
    assert second_call_args["page_number"] == 2


def test_pagination_methods_in_fetch_incidents(mocker):
    """
    Test that the pagination methods are called correctly from fetch_incidents.
    This test verifies:
    1. The methods are called with the correct parameters
    2. The pagination logic is executed as expected
    3. The returned incidents are correctly processed
    """
    # Create mock pagination side effects for threats, cases, and campaigns
    threat_list_side_effect = create_mock_paginator_side_effect("threat")
    case_list_side_effect = create_mock_paginator_side_effect("case")
    campaign_list_side_effect = create_mock_paginator_side_effect("campaign")

    # Create mock detail side effects
    threat_detail_side_effect = create_mock_detail_side_effect("threat")
    case_detail_side_effect = create_mock_detail_side_effect("case")
    campaign_detail_side_effect = create_mock_detail_side_effect("campaign")

    # Create client
    client = Client(server_url=BASE_URL, verify=False, proxy=False, auth=None, headers=headers)

    # Get threat response samples for the mock
    threat_page1 = threat_list_side_effect(page_number=1, page_size=2)
    threat_page2 = threat_list_side_effect(page_number=2, page_size=2)

    # Get case response samples for the mock
    case_page1 = case_list_side_effect(page_number=1, page_size=2)
    case_page2 = case_list_side_effect(page_number=2, page_size=2)

    # Get campaign response samples for the mock
    campaign_page1 = campaign_list_side_effect(page_number=1, page_size=2)
    campaign_page2 = campaign_list_side_effect(page_number=2, page_size=2)

    # Extract threat IDs for detail responses - for each page we'll get exactly page_size items
    threat_ids = [threat["threatId"] for threat in threat_page1.get("threats")[:2] + threat_page2.get("threats")[:2]]
    case_ids = [case["caseId"] for case in case_page1.get("cases")[:2] + case_page2.get("cases")[:2]]
    campaign_ids = [
        campaign["campaignId"] for campaign in campaign_page1.get("campaigns")[:2] + campaign_page2.get("campaigns")[:2]
    ]

    # Combine responses for each type
    threats_combined = {"threats": threat_page1.get("threats") + threat_page2.get("threats")}

    cases_combined = {"cases": case_page1.get("cases") + case_page2.get("cases")}

    campaigns_combined = {"campaigns": campaign_page1.get("campaigns") + campaign_page2.get("campaigns")}

    # Set up test parameters
    last_run = {"last_fetch": "2023-09-17T14:43:09Z"}
    first_fetch_time = "3 days"
    max_incidents = 200
    polling_lag = timedelta(minutes=5)

    # Mock the three pagination methods
    get_paginated_threats_spy = mocker.patch.object(client, "get_paginated_threats_list", return_value=threats_combined)

    get_paginated_cases_spy = mocker.patch.object(client, "get_paginated_cases_list", return_value=cases_combined)

    get_paginated_campaigns_spy = mocker.patch.object(
        client, "get_paginated_abusecampaigns_list", return_value=campaigns_combined
    )

    # Mock the get_details methods to return appropriate data for incident generation
    mocker.patch.object(
        client, "get_details_of_a_threat_request", side_effect=lambda threat_id, **kwargs: threat_detail_side_effect(threat_id)
    )

    mocker.patch.object(
        client, "get_details_of_an_abnormal_case_request", side_effect=lambda case_id, **kwargs: case_detail_side_effect(case_id)
    )

    mocker.patch.object(
        client,
        "get_details_of_an_abuse_mailbox_campaign_request",
        side_effect=lambda campaign_id, **kwargs: campaign_detail_side_effect(campaign_id),
    )

    # Mock the get_current_datetime function to return a fixed time
    mocker.patch("AbnormalSecurity.get_current_datetime", return_value=datetime(2023, 9, 18, 14, 43, 9, tzinfo=UTC))

    # Call fetch_incidents with all three fetch options enabled
    next_run, incidents = fetch_incidents(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_time,
        max_incidents_to_fetch=max_incidents,
        fetch_account_takeover_cases=True,
        fetch_abuse_campaigns=True,
        fetch_threats=True,
        polling_lag=polling_lag,
    )

    # Verify the pagination methods were called with the correct filters

    # 1. Verify threats pagination
    get_paginated_threats_spy.assert_called_once()
    threats_call_kwargs = get_paginated_threats_spy.call_args.kwargs

    # Verify the filter contains latestTimeRemediated with adjusted time due to polling lag
    assert "latestTimeRemediated gte" in threats_call_kwargs["filter_"]
    assert "latestTimeRemediated lte" in threats_call_kwargs["filter_"]
    assert threats_call_kwargs["max_incidents_to_fetch"] == max_incidents

    # 2. Verify abuse campaigns pagination (this is called next in the code)
    get_paginated_campaigns_spy.assert_called_once()
    campaigns_call_kwargs = get_paginated_campaigns_spy.call_args.kwargs

    # Verify the filter contains lastReportedTime
    assert "lastReportedTime gte" in campaigns_call_kwargs["filter_"]
    assert "lastReportedTime lte" in campaigns_call_kwargs["filter_"]
    assert campaigns_call_kwargs["max_incidents_to_fetch"] == max_incidents - len(threat_ids)

    # 3. Verify cases pagination (this is called last in the code)
    get_paginated_cases_spy.assert_called_once()
    cases_call_kwargs = get_paginated_cases_spy.call_args.kwargs
    # Verify the filter contains lastModifiedTime
    assert "lastModifiedTime gte" in cases_call_kwargs["filter_"]
    assert "lastModifiedTime lte" in cases_call_kwargs["filter_"]
    assert cases_call_kwargs["max_incidents_to_fetch"] == max_incidents - len(threat_ids) - len(campaign_ids)

    # Verify we got the expected number of incidents
    expected_incident_count = len(threat_ids) + len(case_ids) + len(campaign_ids)
    assert len(incidents) == expected_incident_count

    # Verify the types of incidents
    threat_incidents = [i for i in incidents if i.get("name") == "Threat"]
    case_incidents = [i for i in incidents if i.get("name") == "Account Takeover Case"]
    campaign_incidents = [i for i in incidents if i.get("name") == "Abuse Campaign"]

    assert len(threat_incidents) == len(threat_ids)
    assert len(case_incidents) == len(case_ids)
    assert len(campaign_incidents) == len(campaign_ids)

    # Verify next_run contains updated last_fetch timestamp
    assert next_run.get("last_fetch", None) is not None
    assert next_run.get("last_fetch") > last_run.get("last_fetch")


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
