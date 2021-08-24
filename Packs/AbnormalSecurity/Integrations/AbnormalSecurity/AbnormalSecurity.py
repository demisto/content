import demistomock as demisto
from CommonServerPython import *

import requests

requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def check_the_status_of_an_action_requested_on_a_case_request(self, case_id, action_id, subtenant):
        params = assign_params(subtenant)
        headers = self._headers

        response = self._http_request('get', f'cases/{case_id}/actions/{action_id}', params=params, headers=headers)

        return response

    def check_the_status_of_an_action_requested_on_a_threat_request(self, threat_id, action_id, subtenant):
        params = assign_params(subtenant)
        headers = self._headers

        response = self._http_request('get', f'threats/{threat_id}/actions/{action_id}', params=params, headers=headers)

        return response

    def download_data_from_threat_log_in_csv_format_request(self, filter_, source, subtenant):
        params = assign_params(filter=filter_, source=source, subtenant=subtenant)

        headers = self._headers

        response = self._http_request('get', 'threats_export/csv', params=params, headers=headers, resp_type='response')
        return response

    def get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(self, filter_, page_size, page_number, subtenant):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, subtenant=subtenant)

        headers = self._headers

        response = self._http_request('get', 'cases', params=params, headers=headers)

        return response

    def get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(self, filter_, page_size, page_number, subtenant):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, subtenant=subtenant)

        headers = self._headers

        response = self._http_request('get', 'abusecampaigns', params=params, headers=headers)

        return response

    def get_a_list_of_threats_request(self, filter_, page_size, page_number, source, subtenant=None):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, source=source, subtenant=subtenant)

        headers = self._headers

        response = self._http_request('get', 'threats', params=params, headers=headers)

        return response

    def get_details_of_a_threat_request(self, threat_id, subtenant):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request('get', f'threats/{threat_id}', params=params, headers=headers)

        return response

    def get_details_of_an_abnormal_case_request(self, case_id, subtenant):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request('get', f'cases/{case_id}', params=params, headers=headers)

        return response

    def get_details_of_an_abuse_mailbox_campaign_request(self, campaign_id, subtenant):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request('get', f'abusecampaigns/{campaign_id}', params=params, headers=headers)

        return response

    def get_employee_identity_analysis_genome_data_request(self, email_address):

        headers = self._headers

        response = self._http_request('get', f'employee/{email_address}/identity', headers=headers)

        return response

    def get_employee_information_request(self, email_address):

        headers = self._headers

        response = self._http_request('get', f'employee/{email_address}', headers=headers)

        return response

    def get_employee_login_information_for_last_30_days_in_csv_format_request(self, email_address):

        headers = self._headers

        response = self._http_request('get', f'employee/{email_address}/logins', headers=headers, resp_type='response')

        return response

    def get_the_latest_threat_intel_feed_request(self):

        headers = self._headers
        response = self._http_request('get', 'threat-intel', headers=headers, timeout=120, resp_type='response')

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

    def provides_the_analysis_and_timeline_details_of_a_case_request(self, case_id, subtenant):
        params = assign_params(subtenant=subtenant)
        headers = self._headers

        response = self._http_request('get', f'cases/{case_id}/analysis', params=params, headers=headers)

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
    subtenant = args.get('subtenant', None)

    response = client.check_the_status_of_an_action_requested_on_a_case_request(case_id, action_id, subtenant)
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
    subtenant = args.get('subtenant', None)

    response = client.check_the_status_of_an_action_requested_on_a_threat_request(threat_id, action_id, subtenant)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.ActionStatus',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def download_data_from_threat_log_in_csv_format_command(client, args):
    filter_ = str(args.get('filter', ''))
    source = str(args.get('source', ''))
    subtenant = args.get('subtenant', None)

    response = client.download_data_from_threat_log_in_csv_format_request(filter_, source, subtenant)
    filename = 'threat_log.csv'
    file_content = response.text

    results = fileResult(filename, file_content)

    return results


def get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(client, args):
    filter_ = str(args.get('filter', ''))
    page_size = args.get('page_size', None)
    page_number = args.get('page_number', None)
    subtenant = args.get('subtenant', None)

    response = client.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(
        filter_,
        page_size,
        page_number,
        subtenant
    )
    markdown = '### List of Cases\n'
    markdown += tableToMarkdown(
        'Case IDs', response.get('cases', []), headers=['caseId', 'description'], removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.inline_response_200_1',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_campaigns_submitted_to_abuse_mailbox_command(client, args):
    filter_ = str(args.get('filter', ''))
    page_size = args.get('page_size', None)
    page_number = args.get('page_number', None)
    subtenant = args.get('subtenant', None)

    response = client.get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(filter_, page_size, page_number, subtenant)
    markdown = '### List of Abuse Mailbox Campaigns\n'
    markdown += tableToMarkdown('Campaign IDs', response.get('campaigns', []), headers=['campaignId'], removeNull=True)

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.AbuseCampaign',
        outputs_key_field='campaignId',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_threats_command(client, args):
    filter_ = str(args.get('filter', ''))
    page_size = args.get('page_size', None)
    page_number = args.get('page_number', None)
    source = str(args.get('source', ''))
    subtenant = args.get('subtenant', None)

    response = client.get_a_list_of_threats_request(filter_, page_size, page_number, source, subtenant)
    markdown = '### List of Threats\n'
    markdown += tableToMarkdown('Threat IDs', response.get('threats'), headers=['threatId'], removeNull=True)
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
    subtenant = args.get('subtenant', None)

    response = client.get_details_of_a_threat_request(threat_id, subtenant)
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
        f"Messages in Threat {response.get('threatId', '')}",
        response.get('messages', []),
        headers=headers,
        removeNull=True
    )

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
    subtenant = args.get('subtenant', None)
    response = client.get_details_of_an_abnormal_case_request(case_id, subtenant)
    headers = [
        'caseId',
        'severity',
        'affectedEmployee',
        'firstObserved',
        'threatIds'
    ]
    markdown = tableToMarkdown(
        f"Details of Case {response.get('caseId', '')}", response, headers=headers, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.AbnormalCaseDetails',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_details_of_an_abuse_mailbox_campaign_command(client, args):
    campaign_id = str(args.get('campaign_id', ''))
    subtenant = args.get('subtenant', None)

    response = client.get_details_of_an_abuse_mailbox_campaign_request(campaign_id, subtenant)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.AbuseCampaign.campaigns',
        outputs_key_field='campaignId',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_employee_identity_analysis_genome_data_command(client, args):
    email_address = str(args.get('email_address', ''))

    response = client.get_employee_identity_analysis_genome_data_request(email_address)

    headers = ['description', 'key', 'name', 'values']

    markdown = tableToMarkdown(
        f"Analysis of {email_address}", response.get('histograms', []), headers=headers, removeNull=True)

    response["email"] = email_address
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.Employee',
        outputs_key_field='email',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_employee_information_command(client, args):
    email_address = str(args.get('email_address', ''))

    response = client.get_employee_information_request(email_address)
    command_results = CommandResults(
        outputs_prefix='AbnormalSecurity.Employee',
        outputs_key_field='email',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_employee_login_information_for_last_30_days_in_csv_format_command(client, args):
    email_address = str(args.get('email_address', ''))

    response = client.get_employee_login_information_for_last_30_days_in_csv_format_request(email_address)
    filename = 'employee_login_info_30_days.csv'
    file_content = response.text

    results = fileResult(filename, file_content)

    return results


def get_the_latest_threat_intel_feed_command(client, args=None):

    response = client.get_the_latest_threat_intel_feed_request()
    filename = 'threat_intel_feed.json'
    file_content = response.text
    results = fileResult(filename, file_content)

    return results


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


def provides_the_analysis_and_timeline_details_of_a_case_command(client, args):
    case_id = str(args.get('case_id', ''))
    subtenant = args.get('subtenant', None)
    response = client.provides_the_analysis_and_timeline_details_of_a_case_request(case_id, subtenant)
    insight_headers = [
        'signal',
        'description'
    ]
    markdown = tableToMarkdown(
        f"Insights for {case_id}", response.get('insights', []), headers=insight_headers, removeNull=True)

    timeline_headers = [
        'event_timestamp',
        'category',
        'title',
        'field_labels',
        'ip_address',
        'description',
        'location',
        'sender',
        'subject',
        'title',
        'flagging detectors',
        'rule_name'
    ]

    markdown += tableToMarkdown(
        f"Event Timeline for {response.get('caseId', '')}",
        response.get('eventTimeline', []),
        headers=timeline_headers,
        removeNull=True
    )

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.CaseAnalysis',
        outputs_key_field='caseId',
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
            'abnormal-security-download-threat-log-csv': download_data_from_threat_log_in_csv_format_command,
            'abnormal-security-list-abnormal-cases':
                get_a_list_of_abnormal_cases_identified_by_abnormal_security_command,
            'abnormal-security-list-abuse-mailbox-campaigns': get_a_list_of_campaigns_submitted_to_abuse_mailbox_command,
            'abnormal-security-list-threats':
                get_a_list_of_threats_command,
            'abnormal-security-get-threat':
                get_details_of_a_threat_command,
            'abnormal-security-get-abnormal-case':
                get_details_of_an_abnormal_case_command,
            'abnormal-security-get-abuse-mailbox-campaign': get_details_of_an_abuse_mailbox_campaign_command,
            'abnormal-security-get-employee-identity-analysis': get_employee_identity_analysis_genome_data_command,
            'abnormal-security-get-employee-information': get_employee_information_command,
            'abnormal-security-get-employee-last-30-days-login-csv':
                get_employee_login_information_for_last_30_days_in_csv_format_command,
            'abnormal-security-get-latest-threat-intel-feed': get_the_latest_threat_intel_feed_command,
            'abnormal-security-manage-threat':
                manage_a_threat_identified_by_abnormal_security_command,
            'abnormal-security-manage-abnormal-case':
                manage_an_abnormal_case_command,
            'abnormal-security-get-case-analysis-and-timeline': provides_the_analysis_and_timeline_details_of_a_case_command,
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
