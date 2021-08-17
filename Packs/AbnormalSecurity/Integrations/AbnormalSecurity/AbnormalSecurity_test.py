import pytest
import demistomock as demisto
import io
import json
from AbnormalSecurity import Client, check_the_status_of_an_action_requested_on_a_case_command, \
    check_the_status_of_an_action_requested_on_a_threat_command, \
    get_a_list_of_abnormal_cases_identified_by_abnormal_security_command, get_a_list_of_threats_command, \
    get_details_of_an_abnormal_case_command, manage_a_threat_identified_by_abnormal_security_command, \
    manage_an_abnormal_case_command, submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command, \
    get_the_latest_threat_intel_feed_command
from CommonServerPython import DemistoException

from test_data.fixtures \
    import BASE_URL, apikey

headers = {
    'Authorization': f"Bearer {apikey}",
}


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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
            - Assert output prefix data is as expected
    """
    client = mock_client(mocker, util_load_json('test_data/test_get_threat_intel_feed.json'))
    results = get_the_latest_threat_intel_feed_command(client)
    assert results.outputs_prefix == 'AbnormalSecurity'
