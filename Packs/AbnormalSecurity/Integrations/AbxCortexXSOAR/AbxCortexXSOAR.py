import demistomock as demisto
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)


    def check_the_status_of_an_action_requested_on_a_case_request(self, caseId, actionId):

        headers = self._headers

        response = self._http_request('get', f'cases/{caseId}/actions/{actionId}', headers=headers)

        return response


    def check_the_status_of_an_action_requested_on_a_threat_request(self, threatId, actionId):

        headers = self._headers

        response = self._http_request('get', f'threats/{threatId}/actions/{actionId}', headers=headers)

        return response


    def get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(self, filter_, pageSize, pageNumber):
        params = assign_params(filter=filter, pageSize=pageSize, pageNumber=pageNumber)

        headers = self._headers

        response = self._http_request('get', 'cases', params=params, headers=headers)

        return response


    def get_a_list_of_threats_request(self, filter_, pageSize, pageNumber):
        params = assign_params(filter=filter, pageSize=pageSize, pageNumber=pageNumber)

        headers = self._headers

        response = self._http_request('get', 'threats', params=params, headers=headers)

        return response


    def get_details_of_a_threat_request(self, threatId):

        headers = self._headers

        response = self._http_request('get', f'threats/{threatId}', headers=headers)

        return response


    def get_details_of_an_abnormal_case_request(self, caseId):

        headers = self._headers

        response = self._http_request('get', f'cases/{caseId}', headers=headers)

        return response


    def get_the_latest_threat_intel_feed_request(self):

        headers = self._headers

        response = self._http_request('get', 'threat-intel', headers=headers)

        return response


    def manage_a_threat_identified_by_abnormal_security_request(self, threatId):

        headers = self._headers

        response = self._http_request('post', f'threats/{threatId}', headers=headers)

        return response


    def manage_an_abnormal_case_request(self, caseId):

        headers = self._headers

        response = self._http_request('post', f'cases/{caseId}', headers=headers)

        return response


    def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request(self):

        headers = self._headers

        response = self._http_request('post', 'inquiry', headers=headers)

        return response




def check_the_status_of_an_action_requested_on_a_case_command(client, args):
    caseId = str(args.get('caseId', ''))
    actionId = str(args.get('actionId', ''))

    response = client.check_the_status_of_an_action_requested_on_a_case_request(caseId, actionId)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR.ActionStatus',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def check_the_status_of_an_action_requested_on_a_threat_command(client, args):
    threatId = str(args.get('threatId', ''))
    actionId = str(args.get('actionId', ''))

    response = client.check_the_status_of_an_action_requested_on_a_threat_request(threatId, actionId)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR.ActionStatus',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(client, args):
    filter_ = str(args.get('filter', ''))
    pageSize = args.get('pageSize', None)
    pageNumber = args.get('pageNumber', None)

    response = client.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(filter_, pageSize, pageNumber)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR.inline_response_200_1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_threats_command(client, args):
    filter_ = str(args.get('filter', ''))
    pageSize = args.get('pageSize', None)
    pageNumber = args.get('pageNumber', None)

    response = client.get_a_list_of_threats_request(filter_, pageSize, pageNumber)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR.inline_response_200',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_details_of_a_threat_command(client, args):
    threatId = str(args.get('threatId', ''))

    response = client.get_details_of_a_threat_request(threatId)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR.ThreatDetails',
        outputs_key_field='threatId',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_details_of_an_abnormal_case_command(client, args):
    caseId = str(args.get('caseId', ''))

    response = client.get_details_of_an_abnormal_case_request(caseId)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR.AbnormalCaseDetails',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_the_latest_threat_intel_feed_command(client, args):

    response = client.get_the_latest_threat_intel_feed_request()
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def manage_a_threat_identified_by_abnormal_security_command(client, args):
    threatId = str(args.get('threatId', ''))

    response = client.manage_a_threat_identified_by_abnormal_security_request(threatId)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def manage_an_abnormal_case_command(client, args):
    caseId = str(args.get('caseId', ''))

    response = client.manage_an_abnormal_case_request(caseId)
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(client, args):

    response = client.submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request()
    command_results = CommandResults(
        outputs_prefix='AbxCortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client):
    # Test functions here
    return_results('ok')


def main():

    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['Authorization'] = params['api_key']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)
        
        commands = {
    		'abxcortexxsoar-check-the-status-of-an-action-requested-on-a-case': check_the_status_of_an_action_requested_on_a_case_command,
			'abxcortexxsoar-check-the-status-of-an-action-requested-on-a-threat': check_the_status_of_an_action_requested_on_a_threat_command,
			'abxcortexxsoar-get-a-list-of-abnormal-cases-identified-by-abnormal-security': get_a_list_of_abnormal_cases_identified_by_abnormal_security_command,
			'abxcortexxsoar-get-a-list-of-threats': get_a_list_of_threats_command,
			'abxcortexxsoar-get-details-of-a-threat': get_details_of_a_threat_command,
			'abxcortexxsoar-get-details-of-an-abnormal-case': get_details_of_an_abnormal_case_command,
			'abxcortexxsoar-get-the-latest-threat-intel-feed': get_the_latest_threat_intel_feed_command,
			'abxcortexxsoar-manage-a-threat-identified-by-abnormal-security': manage_a_threat_identified_by_abnormal_security_command,
			'abxcortexxsoar-manage-an-abnormal-case': manage_an_abnormal_case_command,
			'abxcortexxsoar-submit-an-inquiry-to-request-a-report-on-misjudgement-by-abnormal-security': submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
