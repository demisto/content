import demistomock as demisto
from CommonServerPython import *

import requests


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def check_the_status_of_an_action_requested_on_a_case_request(self, caseId, actionId, mock_data):
        headers = self._headers

        response = self._http_request('get', f'cases/{caseId}/actions/{actionId}', headers=headers)

        return response

    def check_the_status_of_an_action_requested_on_a_threat_request(self, threatId, actionId, mock_data):
        headers = self._headers

        response = self._http_request('get', f'threats/{threatId}/actions/{actionId}', headers=headers)

        return response

    def get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(self, filter, pageSize, pageNumber,
                                                                             mock_data):
        params = assign_params(filter=filter, pageSize=pageSize, pageNumber=pageNumber)

        headers = self._headers

        response = self._http_request('get', 'cases', params=params, headers=headers)

        return response

    def get_a_list_of_threats_request(self, filter, pageSize, pageNumber, mock_data, source):
        params = assign_params(filter=filter, pageSize=pageSize, pageNumber=pageNumber, source=source)

        headers = self._headers

        response = self._http_request('get', 'threats', params=params, headers=headers)

        return response

    def get_details_of_a_threat_request(self, threatId, mock_data):
        headers = self._headers

        response = self._http_request('get', f'threats/{threatId}', headers=headers)

        return response

    def get_details_of_an_abnormal_case_request(self, caseId, mock_data):
        headers = self._headers

        response = self._http_request('get', f'cases/{caseId}', headers=headers)

        return response

    def get_the_latest_threat_intel_feed_request(self, mock_data):

        headers = self._headers
        response = self._http_request('get', 'threat-intel', headers=headers, timeout=120)

        return response

    def manage_a_threat_identified_by_abnormal_security_request(self, threatId, mock_data, action):
        headers = self._headers
        json_data = {'action': action}

        response = self._http_request('post', f'threats/{threatId}', json_data=json_data, headers=headers)

        return response

    def manage_an_abnormal_case_request(self, caseId, mock_data, action):
        headers = self._headers
        json_data = {'action': action}

        response = self._http_request('post', f'cases/{caseId}', json_data=json_data, headers=headers)

        return response

    def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request(self, mock_data):
        headers = self._headers

        response = self._http_request('post', 'inquiry', headers=headers)

        return response


def check_the_status_of_an_action_requested_on_a_case_command(client, args):
    caseId = str(args.get('caseId', ''))
    actionId = str(args.get('actionId', ''))
    mock_data = str(args.get('mock_data', ''))

    response = client.check_the_status_of_an_action_requested_on_a_case_request(caseId, actionId, mock_data)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.ActionStatus',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def check_the_status_of_an_action_requested_on_a_threat_command(client, args):
    threatId = str(args.get('threatId', ''))
    actionId = str(args.get('actionId', ''))
    mock_data = str(args.get('mock_data', ''))

    response = client.check_the_status_of_an_action_requested_on_a_threat_request(threatId, actionId, mock_data)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.ActionStatus',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(client, args):
    filter = str(args.get('filter', ''))
    pageSize = args.get('pageSize', None)
    pageNumber = args.get('pageNumber', None)
    mock_data = str(args.get('mock_data', ''))

    response = client.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(filter, pageSize, pageNumber,
                                                                                           mock_data)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.inline_response_200_1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_threats_command(client, args):
    filter = str(args.get('filter', ''))
    pageSize = args.get('pageSize', None)
    pageNumber = args.get('page_number', None)
    mock_data = str(args.get('mock_data', ''))
    source = str(args.get('source', ''))

    response = client.get_a_list_of_threats_request(filter, pageSize, pageNumber, mock_data, source)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.inline_response_200',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def get_details_of_a_threat_command(client, args):
    threatId = str(args.get('threatId', ''))
    mock_data = str(args.get('mock_data', ''))

    response = client.get_details_of_a_threat_request(threatId, mock_data)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.ThreatDetails',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_details_of_an_abnormal_case_command(client, args):
    caseId = str(args.get('caseId', ''))
    mock_data = str(args.get('mock_data', ''))

    response = client.get_details_of_an_abnormal_case_request(caseId, mock_data)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.AbnormalCaseDetails',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_the_latest_threat_intel_feed_command(client, args):
    mock_data = str(args.get('mock_data', ''))

    response = client.get_the_latest_threat_intel_feed_request(mock_data)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def manage_a_threat_identified_by_abnormal_security_command(client, args):
    threatId = str(args.get('threatId', ''))
    action = str(args.get('action', ''))
    mock_data = str(args.get('mock_data', ''))

    response = client.manage_a_threat_identified_by_abnormal_security_request(threatId, mock_data, action)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def manage_an_abnormal_case_command(client, args):
    caseId = str(args.get('caseId', ''))
    action = str(args.get('action', ''))
    mock_data = str(args.get('mock_data', ''))

    response = client.manage_an_abnormal_case_request(caseId, mock_data, action)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(client, args):
    mock_data = str(args.get('mock_data', ''))

    response = client.submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request(mock_data)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client):
    # Run a sample request to retrieve mock data
    client.get_details_of_a_threat_request('test', None)
    demisto.results("ok")


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    mock_data = str(args.get('mock-data', ''))
    if mock_data.lower() == "true":
        headers['Mock-Data'] = "True"
    headers['Authorization'] = f'Bearer {params["api_key"]}'
    headers['Soar-Integration-Origin'] = "Cortex XSOAR"

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'abnormal-security-check-case-action-status':
                check_the_status_of_an_action_requested_on_a_case_command,
            'abnormal-security-check-threat-action-status':
                check_the_status_of_an_action_requested_on_a_threat_command,
            'abnormal-security-list-abnormal-cases-identified-by-abnormal-security':
                get_a_list_of_abnormal_cases_identified_by_abnormal_security_command,
            'abnormal-security-list-threats':
                get_a_list_of_threats_command,
            'abnormal-security-get-threat':
                get_details_of_a_threat_command,
            'abnormal-security-get-abnormal-case':
                get_details_of_an_abnormal_case_command,
            'abnormal-security-get-latest-threat-intel-feed': get_the_latest_threat_intel_feed_command,
            'abnormal-security-manage-threat-identified-by-abnormal-security':
                manage_a_threat_identified_by_abnormal_security_command,
            'abnormal-security-manage-abnormal-case':
                manage_an_abnormal_case_command,
            'abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement-by-abnormal-security':
                submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command,
        }

        if command == 'test-module':
            headers['Mock-Data'] = "True"
            test_client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)
            test_module(test_client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
