import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from typing import Any
import logging
from datetime import datetime, timedelta


import urllib3

urllib3.disable_warnings()


DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 600
FETCH_LIMIT = 200
MAX_PAGE_SIZE = 100


XSOAR_SEVERITY_BY_AMP_SEVERITY = {
    "Low": IncidentSeverity.LOW,
    "Medium": IncidentSeverity.MEDIUM,
    "High": IncidentSeverity.HIGH,
    "Critical": IncidentSeverity.CRITICAL,
}

ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class FetchIncidentsError(Exception):
    """Raised when there's an error in fetching incidents."""


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth, timeout=2400)

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

    def get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(self, filter_='', page_size=None, page_number=None,
                                                                             subtenant=None):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, subtenant=subtenant)

        headers = self._headers

        response = self._http_request('get', 'cases', params=params, headers=headers)

        return response

    def get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(self, filter_='', page_size=None, page_number=None,
                                                                   subtenant=None, subject=None, sender=None, recipient=None,
                                                                   reporter=None, attackType=None, threatType=None):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, subtenant=subtenant, subject=subject,
                               sender=sender, recipient=recipient, reporter=reporter, attackType=attackType,
                               threatType=threatType)

        headers = self._headers

        response = self._http_request('get', 'abusecampaigns', params=params, headers=headers)

        return response

    def get_a_list_of_threats_request(self, filter_='', page_size=None, page_number=None, source=None, subtenant=None,
                                      subject=None, sender=None, recipient=None, topic=None, attackType=None, attackVector=None):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, source=source, subtenant=subtenant,
                               subject=subject, sender=sender, recipient=recipient, topic=topic, attackType=attackType,
                               attackVector=attackVector)

        headers = self._headers

        response = self._http_request('get', 'threats', params=params, headers=headers)

        response = self._remove_keys_from_response(response, ["pageNumber", "nextPageNumber"])

        return response

    def get_details_of_a_threat_request(self, threat_id, subtenant=None, page_size=None, page_number=None):
        headers = self._headers
        params = assign_params(subtenant=subtenant, pageSize=page_size, pageNumber=page_number)

        response = self._http_request('get', f'threats/{threat_id}', params=params, headers=headers)

        return response

    def get_details_of_an_abnormal_case_request(self, case_id, subtenant=None):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request('get', f'cases/{case_id}', params=params, headers=headers)

        return response

    def get_details_of_an_abuse_mailbox_campaign_request(self, campaign_id, subtenant=None):
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

    def submit_false_negative_report_request(self, recipient_email, sender_email, subject):
        headers = self._headers
        json_data = {
            "report_type": "false-negative",
            "recipient_email": recipient_email,
            "sender_email": sender_email,
            "subject": subject
        }
        response = self._http_request('post', 'detection360/reports', json_data=json_data, headers=headers)

        return response

    def submit_false_positive_report_request(self, portal_link):
        headers = self._headers
        json_data = {
            "report_type": "false-positive",
            'portal_link': portal_link,
        }
        response = self._http_request('post', 'detection360/reports', json_data=json_data, headers=headers)

        return response

    def get_a_list_of_vendors_request(self, page_size, page_number):
        params = assign_params(pageSize=page_size, pageNumber=page_number)

        headers = self._headers

        response = self._http_request("get", "vendors", params=params, headers=headers)

        response = self._remove_keys_from_response(response, ["pageNumber", "nextPageNumber"])

        return response["vendors"]

    def get_the_details_of_a_specific_vendor_request(self, vendorDomain):
        headers = self._headers

        response = self._http_request("get", f"vendors/{vendorDomain}/details", headers=headers)

        return response

    def get_the_activity_of_a_specific_vendor_request(self, vendorDomain):
        headers = self._headers

        response = self._http_request("get", f"vendors/{vendorDomain}/activity", headers=headers)

        return response

    def get_a_list_of_vendor_cases_request(self, filter_, page_size, page_number):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number)

        headers = self._headers

        response = self._http_request("get", "vendor-cases", params=params, headers=headers)

        response = self._remove_keys_from_response(response, ["pageNumber", "nextPageNumber"])

        return response["vendorCases"]

    def get_the_details_of_a_vendor_case_request(self, caseId):
        headers = self._headers

        response = self._http_request("get", f"vendor-cases/{caseId}", headers=headers)

        return response

    def get_a_list_of_unanalyzed_abuse_mailbox_campaigns_request(self, start, end):
        params = assign_params(start=start, end=end)

        headers = self._headers

        response = self._http_request("get", "abuse_mailbox/not_analyzed", params=params, headers=headers)

        return response

    def _remove_keys_from_response(self, response, keys_to_remove):
        """Removes specified keys from the response."""
        for key in keys_to_remove:
            response.pop(key, None)
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
    markdown = tableToMarkdown(
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
    subject = args.get('subject', None)
    sender = args.get('sender', None)
    recipient = args.get('recipient', None)
    reporter = args.get('reporter', None)
    attackType = args.get('attackType', None)
    threatType = args.get('threatType', None)

    response = client.get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(
        filter_, page_size, page_number, subtenant, subject, sender, recipient, reporter, attackType, threatType)
    markdown = tableToMarkdown('Campaign IDs', response.get('campaigns', []), headers=['campaignId'], removeNull=True)

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
    subject = args.get('subject', None)
    sender = args.get('sender', None)
    recipient = args.get('recipient', None)
    topic = args.get('topic', None)
    attackType = args.get('attackType', None)
    attackVector = args.get('attackVector', None)

    response = client.get_a_list_of_threats_request(
        filter_, page_size, page_number, source, subtenant, subject, sender, recipient, topic, attackType, attackVector)
    markdown = tableToMarkdown('Threat IDs', response.get('threats'), headers=['threatId'], removeNull=True)
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
    page_size = args.get('page_size', None)
    page_number = args.get('page_number', None)

    response = client.get_details_of_a_threat_request(threat_id, subtenant, page_size, page_number)
    headers = [
        'subject',
        'fromAddress',
        'fromName',
        'toAddresses',
        'recipientAddress',
        'receivedTime',
        'attackType',
        'attackStrategy',
        'abxMessageId',
        'abxPortalUrl',
        'attachmentCount',
        'attachmentNames',
        'attackVector',
        'attackedParty',
        'autoRemediated',
        'impersonatedParty',
        'internetMessageId',
        'isRead',
        'postRemediated',
        'remediationStatus',
        'remediationTimestamp',
        'sentTime',
        'threatId',
        'ccEmails',
        'replyToEmails',
        'returnPath',
        'senderDomain',
        'senderIpAddress',
        'summaryInsights',
        'urlCount'
        'urls'
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
        outputs_prefix='AbnormalSecurity.AbuseCampaign',
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
        f"Analysis of {email_address}", response.get('data', []), headers=headers, removeNull=True)

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


def submit_false_negative_report_command(client, args):
    recipient_email = str(args.get('recipient_email', ''))
    sender_email = str(args.get('sender_email', ''))
    subject = str(args.get('subject', ''))
    response = client.submit_false_negative_report_request(recipient_email, sender_email, subject)
    command_results = CommandResults(
        readable_output=response,
        raw_response=response
    )

    return command_results


def submit_false_positive_report_command(client, args):
    portal_link = str(args.get('portal_link', ''))
    response = client.submit_false_positive_report_request(portal_link)
    command_results = CommandResults(
        readable_output=response,
        raw_response=response
    )

    return command_results


def get_a_list_of_vendors_command(client, args):
    page_size = str(args.get('page_size', ''))
    page_number = str(args.get('page_number', ''))
    response = client.get_a_list_of_vendors_request(page_size, page_number)
    markdown = tableToMarkdown('Vendor Domains', response, headers=['vendorDomain'], removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.VendorsList',
        outputs_key_field='vendorDomain',
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_the_details_of_a_specific_vendor_command(client, args):
    vendor_domain: str = args['vendor_domain']
    response = client.get_the_details_of_a_specific_vendor_request(vendor_domain)
    markdown = tableToMarkdown('Vendor Domain', response, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.VendorDetails',
        outputs_key_field='vendorDomain',
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_the_activity_of_a_specific_vendor_command(client, args):
    vendor_domain: str = args['vendor_domain']
    response = client.get_the_activity_of_a_specific_vendor_request(vendor_domain)
    markdown = tableToMarkdown('Vendor Activity', response.get('eventTimeline'), removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.VendorActivity',
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_a_list_of_vendor_cases_command(client, args):
    filter_ = str(args.get('filter', ''))
    page_size = str(args.get('page_size', ''))
    page_number = str(args.get('page_number', ''))

    response = client.get_a_list_of_vendor_cases_request(filter_, page_size, page_number)
    markdown = tableToMarkdown('Vendor Case IDs', response, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.VendorCases',
        outputs_key_field="vendorCaseId",
        outputs=response,
        raw_response=response
    )

    return command_results


def get_the_details_of_a_vendor_case_command(client, args):
    case_id: str = args['case_id']
    response = client.get_the_details_of_a_vendor_case_request(case_id)
    markdown = tableToMarkdown('Case Details', response, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.VendorCaseDetails',
        outputs_key_field='vendorCaseId',
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command(client, args):
    start = str(args.get('start', ''))
    end = str(args.get('end', ''))

    response = client.get_a_list_of_unanalyzed_abuse_mailbox_campaigns_request(start, end)
    markdown = tableToMarkdown('Unanalyzed Abuse Mailbox Campaigns', response.get('results', []), removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix='AbnormalSecurity.UnanalyzedAbuseCampaigns',
        outputs_key_field='abx_message_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def generate_threat_incidents(client, threats):
    incidents = []
    for threat in threats:
        threat_details = client.get_details_of_a_threat_request(threat["threatId"])
        received_time = threat_details["messages"][0].get("receivedTime")
        incident = {
            "dbotMirrorId": str(threat["threatId"]),
            "name": "Threat",
            "occurred": received_time[:26] if len(received_time) > 26 else received_time,
            "details": "Threat",
            "rawJSON": json.dumps(threat_details) if threat_details else {}
        }
        incidents.append(incident)
    return incidents


def generate_abuse_campaign_incidents(client, campaigns):
    incidents = []
    for campaign in campaigns:
        campaign_details = client.get_details_of_an_abuse_mailbox_campaign_request(campaign["campaignId"])
        first_reported = campaign_details["firstReported"]
        incident = {
            "dbotMirrorId": str(campaign["campaignId"]),
            "name": "Abuse Campaign",
            "occurred": first_reported[:26] if len(first_reported) > 26 else first_reported,
            'details': "Abuse Campaign",
            "rawJSON": json.dumps(campaign_details) if campaign_details else {}
        }
        incidents.append(incident)
    return incidents


def generate_account_takeover_cases_incidents(client, cases):
    incidents = []
    for case in cases:
        case_details = client.get_details_of_an_abnormal_case_request(case["caseId"])
        incident = {"dbotMirrorId": str(case["caseId"]), "name": "Account Takeover Case",
                    "occurred": case_details["firstObserved"], 'details': case['description'],
                    "rawJSON": json.dumps(case_details) if case_details else {}}
        incidents.append(incident)
    return incidents


def fetch_incidents(
        client: Client,
        last_run: dict[str, Any],
        first_fetch_time: str,
        fetch_threats: bool,
        fetch_abuse_campaigns: bool,
        fetch_account_takeover_cases: bool,
        max_incidents_to_fetch: Optional[int] = FETCH_LIMIT,
        polling_lag: Optional[timedelta] = timedelta(minutes=0),
):
    """
    Fetch incidents from various sources (threats, abuse campaigns, and account takeovers).

    Parameters:
    - client (Client): Client object to interact with the API.
    - last_run (Dict[str, Any]): Dictionary containing details about the last time incidents were fetched.
    - first_fetch_time (str): ISO formatted string indicating the first time from which to start fetching incidents.
    - max_incidents_to_fetch (int, optional): Maximum number of incidents to fetch. Defaults to FETCH_LIMIT.
    - polling_lag (int, optional): Time in minutes to subtract from polling time window for data consistency. Defaults to 5.

    Returns:
    - Tuple[Dict[str, str], List[Dict]]: Tuple containing a dictionary with the `last_fetch` time and a list of fetched incidents.
    """

    try:
        last_fetch = last_run.get("last_fetch", first_fetch_time)
        last_fetch_datetime = datetime.fromisoformat(last_fetch[:-1]).astimezone(timezone.utc)
        # Apply polling lag to the last fetch time
        last_fetch_datetime -= polling_lag
        last_fetch = last_fetch_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")

        current_datetime = datetime.utcnow().astimezone(timezone.utc)
        current_iso_format_time = current_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        all_incidents = []

        if fetch_threats:
            threats_filter = f"receivedTime gte {last_fetch}"
            threats_response = client.get_a_list_of_threats_request(filter_=threats_filter, page_size=100)
            all_incidents += generate_threat_incidents(client, threats_response.get('threats', []))

        if fetch_abuse_campaigns:
            abuse_campaigns_filter = f"lastReportedTime gte {last_fetch}"
            abuse_campaigns_response = client.get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(
                filter_=abuse_campaigns_filter, page_size=100)
            all_incidents += generate_abuse_campaign_incidents(client, abuse_campaigns_response.get('campaigns', []))

        if fetch_account_takeover_cases:
            account_takeover_cases_filter = f"lastModifiedTime gte {last_fetch}"
            account_takeover_cases_response = client.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(
                filter_=account_takeover_cases_filter, page_size=100)
            all_incidents += generate_account_takeover_cases_incidents(
                client, account_takeover_cases_response.get('cases', []))

    except Exception as e:
        logging.error(f"Failed fetching incidents: {e}")
        raise FetchIncidentsError(f"Error while fetching incidents: {e}")

    next_run = {
        "last_fetch": current_iso_format_time
    }

    return next_run, all_incidents[:max_incidents_to_fetch]


def test_module(client):
    # Run a sample request to retrieve mock data
    client.get_a_list_of_threats_request(None, None, None, None)
    demisto.results("ok")


def main():  # pragma: nocover
    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    is_fetch = params.get('isFetch')
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
            # Threat commands
            'abnormal-security-list-threats':
                get_a_list_of_threats_command,
            'abnormal-security-get-threat':
                get_details_of_a_threat_command,
            'abnormal-security-manage-threat':
                manage_a_threat_identified_by_abnormal_security_command,
            'abnormal-security-check-threat-action-status':
                check_the_status_of_an_action_requested_on_a_threat_command,
            'abnormal-security-download-threat-log-csv': download_data_from_threat_log_in_csv_format_command,

            # Case commands
            'abnormal-security-list-abnormal-cases':
                get_a_list_of_abnormal_cases_identified_by_abnormal_security_command,
            'abnormal-security-get-abnormal-case':
                get_details_of_an_abnormal_case_command,
            'abnormal-security-manage-abnormal-case':
                manage_an_abnormal_case_command,
            'abnormal-security-check-case-action-status':
                check_the_status_of_an_action_requested_on_a_case_command,
            'abnormal-security-get-case-analysis-and-timeline':
                provides_the_analysis_and_timeline_details_of_a_case_command,

            # Threat Intel commands
            'abnormal-security-get-latest-threat-intel-feed': get_the_latest_threat_intel_feed_command,

            # Abuse Mailbox commands
            'abnormal-security-list-abuse-mailbox-campaigns': get_a_list_of_campaigns_submitted_to_abuse_mailbox_command,
            'abnormal-security-get-abuse-mailbox-campaign': get_details_of_an_abuse_mailbox_campaign_command,
            "abnormal-security-list-unanalyzed-abuse-mailbox-campaigns":
                get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command,

            # Employee commands
            'abnormal-security-get-employee-identity-analysis': get_employee_identity_analysis_genome_data_command,
            'abnormal-security-get-employee-information': get_employee_information_command,
            'abnormal-security-get-employee-last-30-days-login-csv':
                get_employee_login_information_for_last_30_days_in_csv_format_command,

            # Detection 360 commands
            'abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement':
                submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command,
            'abnormal-security-submit-false-negative-report':
                submit_false_negative_report_command,
            'abnormal-security-submit-false-positive-report':
                submit_false_positive_report_command,

            # Vendor commands
            "abnormal-security-list-vendors":
                get_a_list_of_vendors_command,
            "abnormal-security-get-vendor-details":
                get_the_details_of_a_specific_vendor_command,
            "abnormal-security-get-vendor-activity":
                get_the_activity_of_a_specific_vendor_command,

            # Vendor case commands
            "abnormal-security-list-vendor-cases":
                get_a_list_of_vendor_cases_command,
            "abnormal-security-get-vendor-case-details":
                get_the_details_of_a_vendor_case_command,

        }

        if command == 'test-module':
            headers['Mock-Data'] = "True"
            test_client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)
            test_module(test_client)
        elif command == 'fetch-incidents' and is_fetch:
            max_incidents_to_fetch = arg_to_number(params.get("max_fetch", FETCH_LIMIT))
            fetch_threats = params.get("fetch_threats", False)
            # Get the polling lag time parameter
            polling_lag_minutes = int(params.get('polling_lag', 5))
            polling_lag_delta = timedelta(minutes=polling_lag_minutes)
            fetch_abuse_campaigns = params.get("fetch_abuse_campaigns", False)
            fetch_account_takeover_cases = params.get("fetch_account_takeover_cases", False)
            first_fetch_datetime = arg_to_datetime(arg=params.get("first_fetch"), arg_name="First fetch time", required=True)
            if first_fetch_datetime:
                first_fetch_time = first_fetch_datetime.strftime(ISO_8601_FORMAT)
            else:
                first_fetch_time = datetime.now().strftime(ISO_8601_FORMAT)
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                max_incidents_to_fetch=max_incidents_to_fetch,
                fetch_threats=fetch_threats,
                fetch_abuse_campaigns=fetch_abuse_campaigns,
                fetch_account_takeover_cases=fetch_account_takeover_cases,
                polling_lag=polling_lag_delta
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, args))  # type: ignore
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
