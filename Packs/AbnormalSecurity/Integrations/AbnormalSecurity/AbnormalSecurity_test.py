import pytest
import demistomock as demisto
import io
import json
from AbnormalSecurity import Client, check_the_status_of_an_action_requested_on_a_case_command, \
    check_the_status_of_an_action_requested_on_a_threat_command, \
    get_a_list_of_abnormal_cases_identified_by_abnormal_security_command, get_a_list_of_threats_command, \
    get_details_of_an_abnormal_case_command, manage_a_threat_identified_by_abnormal_security_command, \
    manage_an_abnormal_case_command, submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command, \
    get_the_latest_threat_intel_feed_command, download_data_from_threat_log_in_csv_format_command, \
    get_a_list_of_campaigns_submitted_to_abuse_mailbox_command, get_details_of_an_abuse_mailbox_campaign_command, \
    get_employee_identity_analysis_genome_data_command, get_employee_information_command, \
    get_employee_login_information_for_last_30_days_in_csv_format_command, \
    provides_the_analysis_and_timeline_details_of_a_case_command
from CommonServerPython import DemistoException

from test_data.fixtures \
    import BASE_URL, apikey

headers = {
    'Authorization': f"Bearer {apikey}",
}


class MockResponse:
    def __init__(self, data, status_code):
        self.data = data
        self.text = str(data)
        self.status_code = status_code


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_response(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return MockResponse(f.read(), 200)


def mock_client(mocker, http_request_result=None, throw_error=False):

    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'current_refresh_token': 'refresh_token'})
    client = Client(
        server_url=BASE_URL,
        verify=False,
        proxy=False,
        auth=None,
        headers=headers
    )
    if http_request_result:
        mocker.patch.object(client, '_http_request', return_value=http_request_result)

    if throw_error:
        err_msg = "Error in API call [400] - BAD REQUEST}"
        mocker.patch.object(client, '_http_request', side_effect=DemistoException(err_msg, res={}))

    return client


"""
    Command Unit Tests
"""


def test_check_the_status_of_an_action_requested_on_a_case_command(mocker):
    """
        When:
            - Checking status of an action request on a case
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_check_status_of_action_requested_on_threat.json'))
    results = check_the_status_of_an_action_requested_on_a_case_command(client, {})
    assert results.outputs.get('status') == 'acknowledged'
    assert results.outputs_prefix == 'AbnormalSecurity.ActionStatus'


def test_check_the_status_of_an_action_requested_on_a_threat_command(mocker):
    """
        When:
            - Checking status of an action request on a threat
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_check_status_of_action_requested_on_threat.json'))
    results = check_the_status_of_an_action_requested_on_a_threat_command(client, {})
    assert results.outputs.get('status') == 'acknowledged'
    assert results.outputs_prefix == 'AbnormalSecurity.ActionStatus'


def test_get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(mocker):
    """
        When:
            - Retrieving list of abnormal cases identified
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_list_of_abnormal_cases.json'))
    results = get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(client, {})
    assert results.outputs.get('cases')[0].get('caseId') == '1234'
    assert results.outputs.get('pageNumber', 0) > 0
    assert results.outputs.get('nextPageNumber') == results.outputs.get('pageNumber', 0) + 1
    assert results.outputs_prefix == 'AbnormalSecurity.inline_response_200_1'


def test_get_a_list_of_threats_command(mocker):
    """
        When:
            - Retrieving list of cases identified
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_list_of_abnormal_threats.json'))
    results = get_a_list_of_threats_command(client, {})
    assert results.outputs.get('threats')[0].get('threatId') == '184712ab-6d8b-47b3-89d3-a314efef79e2'
    assert results.outputs.get('pageNumber', 0) > 0
    assert results.outputs.get('nextPageNumber') == results.outputs.get('pageNumber', 0) + 1
    assert results.outputs_prefix == 'AbnormalSecurity.inline_response_200'


def test_get_details_of_an_abnormal_case_command(mocker):
    """
        When:
            - Retrieving details of an abnormal case identified
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_details_of_an_abnormal_case.json'))
    results = get_details_of_an_abnormal_case_command(client, {})
    assert results.outputs.get('caseId') == '1234'
    assert results.outputs.get('threatIds')[0] == '184712ab-6d8b-47b3-89d3-a314efef79e2'
    assert results.outputs_prefix == 'AbnormalSecurity.AbnormalCaseDetails'


def test_manage_a_threat_identified_by_abnormal_security_command_failure(mocker):
    """
        When:
            - Cause an API error when parsing bad data
        Then
            - Assert error is thrown as expected
    """
    client = mock_client(mocker, None, True)
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
    client = mock_client(mocker, util_load_json('test_data/test_manage_threat.json'))
    results = manage_a_threat_identified_by_abnormal_security_command(client, {})
    assert results.outputs.get('action_id') == '61e76395-40d3-4d78-b6a8-8b17634d0f5b'
    assert results.outputs_prefix == 'AbnormalSecurity.ThreatManageResults'


def test_manage_an_abnormal_case_command_failure(mocker):
    """
        When:
            - Cause an API error when passing bad data
        Then
            - Assert error is thrown as expected
    """
    client = mock_client(mocker, None, True)
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
    client = mock_client(mocker, util_load_json('test_data/test_manage_case.json'))
    results = manage_an_abnormal_case_command(client, {})
    assert results.outputs.get('action_id') == '61e76395-40d3-4d78-b6a8-8b17634d0f5b'
    assert results.outputs_prefix == 'AbnormalSecurity.CaseManageResults'


def test_submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(mocker):
    """
        When:
            - Submit an inquiry
        Then
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, "Thank you for your feedback! We have sent your inquiry to our support staff.")
    args = {
        "reporter": "abc@def.com",
        "report_type": "false-positive"
    }

    results = submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(client, args)
    assert results.outputs_prefix == 'AbnormalSecurity.SubmitInquiry'


def test_get_the_latest_threat_intel_feed_command(mocker):
    """
        When:
            - Retrieve intel feed
        Then
            - Assert downloaded file name is as expected
    """
    client = mock_client(mocker, util_load_response('test_data/test_get_threat_intel_feed.json'))
    results = get_the_latest_threat_intel_feed_command(client)
    assert results["File"] == 'threat_intel_feed.json'


def test_download_data_from_threat_log_in_csv_format_command(mocker):
    """
        When:
            - Downloading threat log in csv format
        Then
            - Assert downloaded file name is as expected
    """
    client = mock_client(mocker, util_load_response('test_data/test_download_data_from_threat_log_in_csv_format.csv'))
    results = download_data_from_threat_log_in_csv_format_command(client, {})

    assert results["File"] == 'threat_log.csv'


def test_get_a_list_of_campaigns_submitted_to_abuse_mailbox_command(mocker):
    """
        When:
            - Retrieving list of abuse campaigns identified
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_list_of_abuse_campaigns.json'))
    results = get_a_list_of_campaigns_submitted_to_abuse_mailbox_command(client, {})
    assert results.outputs.get('campaigns')[0].get('campaignId') == 'fff51768-c446-34e1-97a8-9802c29c3ebd'
    assert results.outputs.get('pageNumber', 0) > 0
    assert results.outputs.get('nextPageNumber') == results.outputs.get('pageNumber', 0) + 1
    assert results.outputs_prefix == 'AbnormalSecurity.AbuseCampaign'


def test_get_details_of_an_abuse_mailbox_campaign_command(mocker):
    """
        When:
            - Retrieving details of an abuse mailbox campaign reported
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_details_of_abuse_campaign.json'))
    results = get_details_of_an_abuse_mailbox_campaign_command(client, {})
    assert results.outputs.get('campaignId') == 'fff51768-c446-34e1-97a8-9802c29c3ebd'
    assert results.outputs.get('attackType') == 'Attack Type: Spam'
    assert results.outputs_prefix == 'AbnormalSecurity.AbuseCampaign.campaigns'


def test_get_employee_identity_analysis_genome_data_command(mocker):
    """
        When:
            - Retrieving analysis histograms of employee
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_details_of_genome_data.json'))
    results = get_employee_identity_analysis_genome_data_command(client, {})
    assert len(results.outputs.get('histograms')) > 0
    assert results.outputs.get('histograms')[0]['key'] == 'ip_address'
    for index, val in enumerate(results.outputs.get('histograms')[0]['values']):
        assert val["text"] == f"ip-address-{index}"
    assert results.outputs_prefix == 'AbnormalSecurity.Employee'


def test_get_employee_information_command(mocker):
    """
        When:
            - Retrieving company employee information
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_employee_info.json'))
    results = get_employee_information_command(client, {})
    assert results.outputs.get('name') == 'test_name'
    assert results.outputs_prefix == 'AbnormalSecurity.Employee'


def test_get_employee_login_information_for_last_30_days_in_csv_format_command(mocker):
    """
        When:
            - Downloading employee login information in csv format
        Then
            - Assert downloaded file name is as expected
    """
    client = mock_client(mocker, util_load_response('test_data/test_get_employee_login_info_csv.csv'))
    results = get_employee_login_information_for_last_30_days_in_csv_format_command(client, {})
    assert results["File"] == 'employee_login_info_30_days.csv'


def test_provides_the_analysis_and_timeline_details_of_a_case_command(mocker):
    """
        When:
            - Retrieving anaylsis and timeline detail of a case
        Then
            - Assert the context data is as expected.
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_case_analysis_and_timeline.json'))
    results = provides_the_analysis_and_timeline_details_of_a_case_command(client, {})
    assert len(results.outputs.get('insights')) > 0
    assert len(results.outputs.get('eventTimeline')) > 0
    assert results.outputs_prefix == 'AbnormalSecurity.CaseAnalysis'
