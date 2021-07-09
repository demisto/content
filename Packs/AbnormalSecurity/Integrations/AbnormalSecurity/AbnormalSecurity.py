import demistomock as demisto
from CommonServerPython import *

import requests

requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def check_the_status_of_an_action_requested_on_a_case_request(self, case_id, action_id):
        headers = self._headers

        response = self._http_request('get', f'cases/{case_id}/actions/{action_id}', headers=headers)

        return response

    def check_the_status_of_an_action_requested_on_a_threat_request(self, threat_id, action_id):
        headers = self._headers

        response = self._http_request('get', f'threats/{threat_id}/actions/{action_id}', headers=headers)

        return response

    def get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(self, filter_, page_size, page_number):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number)

        headers = self._headers

        response = self._http_request('get', 'cases', params=params, headers=headers)

        return response

    def get_a_list_of_threats_request(self, filter_, page_size, page_number, source):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, source=source)

        headers = self._headers

        response = self._http_request('get', 'threats', params=params, headers=headers)

        return response

    def get_details_of_a_threat_request(self, threat_id):
        headers = self._headers

        response = self._http_request('get', f'threats/{threat_id}', headers=headers)

        return response

    def get_details_of_an_abnormal_case_request(self, case_id):
        headers = self._headers

        response = self._http_request('get', f'cases/{case_id}', headers=headers)

        return response

    def get_the_latest_threat_intel_feed_request(self):

        headers = self._headers
        response = self._http_request('get', 'threat-intel', headers=headers, timeout=120)

        return response

    def manage_a_threat_identified_by_abnormal_security_request(self, threat_id, action):
        headers = self._headers
        json_data = {'action': action}

        response = self._http_request('post', f'threats/{threat_id}', json_data=json_data, headers=headers)

        return response

    def manage_an_abnormal_case_request(self, case_id, action):
        headers = self._headers
        json_data = {'action': action}

        response = self._http_request('post', f'cases/{case_id}', json_data=json_data, headers=headers)

        return response

    def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request(self, reporter, report_type):
        headers = self._headers
        json_data = {
            'reporter': reporter,
            'report_type': report_type,
        }
        response = self._http_request('post', 'inquiry', json_data=json_data, headers=headers)

        return response


def check_the_status_of_an_action_requested_on_a_case_command(client, args):
    case_id = str(args.get('case_id', ''))
    action_id = str(args.get('action_id', ''))

    response = client.check_the_status_of_an_action_requested_on_a_case_request(case_id, action_id)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.ActionStatus',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def check_the_status_of_an_action_requested_on_a_threat_command(client, args):
    threat_id = str(args.get('threat_id', ''))
    action_id = str(args.get('action_id', ''))

    response = client.check_the_status_of_an_action_requested_on_a_threat_request(threat_id, action_id)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.ActionStatus',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(client, args):
    filter_ = str(args.get('filter', ''))
    page_size = args.get('page_size', None)
    page_number = args.get('page_number', None)

    response = client.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(filter_, page_size, page_number)
    markdown = '### List of Cases\n'
    markdown += tableToMarkdown('Case IDs', response.get('cases', []), headers=['caseId', 'description'])
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.inline_response_200_1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_threats_command(client, args):
    filter_ = str(args.get('filter', ''))
    page_size = args.get('page_size', None)
    page_number = args.get('page_number', None)
    source = str(args.get('source', ''))

    response = client.get_a_list_of_threats_request(filter_, page_size, page_number, source)
    markdown = '### List of Threats\n'
    markdown += tableToMarkdown('Threat IDs', response.get('threats'), headers=['threatId'])
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.inline_response_200',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )
    return command_results


def get_details_of_a_threat_command(client, args):
    threat_id = str(args.get('threat_id', ''))

    response = client.get_details_of_a_threat_request(threat_id)
    headers = [
        'subject',
        'fromAddress',
        'fromName',
        'toAddresses',
        'recipientAddress',
        'receivedTime',
        'attackType',
        'attackStrategy',
        'returnPath'
    ]
    markdown = tableToMarkdown(
        f"Messages in Threat {response.get('threatId', '')}", response.get('messages', []), headers=headers)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.ThreatDetails',
        outputs_key_field='threatId',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_details_of_an_abnormal_case_command(client, args):
    case_id = str(args.get('case_id', ''))

    response = client.get_details_of_an_abnormal_case_request(case_id)
    headers = [
        'caseId',
        'severity',
        'affectedEmployee',
        'firstObserved',
        'threatIds'
    ]
    markdown = tableToMarkdown(
        f"Details of Case {response.get('caseId', '')}", response, headers=headers)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.AbnormalCaseDetails',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_the_latest_threat_intel_feed_command(client, args=None):

    response = client.get_the_latest_threat_intel_feed_request()
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def manage_a_threat_identified_by_abnormal_security_command(client, args):
    threat_id = str(args.get('threat_id', ''))
    action = str(args.get('action', ''))

    response = client.manage_a_threat_identified_by_abnormal_security_request(threat_id, action)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.ThreatManageResults',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def manage_an_abnormal_case_command(client, args):
    case_id = str(args.get('case_id', ''))
    action = str(args.get('action', ''))

    response = client.manage_an_abnormal_case_request(case_id, action)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.CaseManageResults',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(client, args):
    reporter = str(args.get('reporter', ''))
    report_type = str(args.get('report_type', ''))
    response = client.submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request(reporter, report_type)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.SubmitInquiry',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client):
    # Run a sample request to retrieve mock data
    client.get_a_list_of_threats_request(None, None, None, None)
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
        client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'abnormal-security-check-case-action-status':
                check_the_status_of_an_action_requested_on_a_case_command,
            'abnormal-security-check-threat-action-status':
                check_the_status_of_an_action_requested_on_a_threat_command,
            'abnormal-security-list-abnormal-cases':
                get_a_list_of_abnormal_cases_identified_by_abnormal_security_command,
            'abnormal-security-list-threats':
                get_a_list_of_threats_command,
            'abnormal-security-get-threat':
                get_details_of_a_threat_command,
            'abnormal-security-get-abnormal-case':
                get_details_of_an_abnormal_case_command,
            'abnormal-security-get-latest-threat-intel-feed': get_the_latest_threat_intel_feed_command,
            'abnormal-security-manage-threat':
                manage_a_threat_identified_by_abnormal_security_command,
            'abnormal-security-manage-abnormal-case':
                manage_an_abnormal_case_command,
            'abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement':
                submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command,
        }

        if command == 'test-module':
            headers['Mock-Data'] = "True"
            test_client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)
            test_module(test_client)
        elif command in commands:
            return_results(commands[command](client, args))  # type: ignore
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
