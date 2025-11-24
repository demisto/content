import logging
from datetime import datetime, timedelta
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

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
TIME_FORMAT_WITHMS = "%Y-%m-%dT%H:%M:%S.%fZ"


def try_str_to_datetime(time: str) -> datetime:
    """
    Try to convert a string to a datetime object.
    """
    try:
        return datetime.strptime(time, ISO_8601_FORMAT).astimezone(timezone.utc)
    except Exception as _:
        pass
    return datetime.strptime((time[:26] + "Z") if len(time) > 26 else time, TIME_FORMAT_WITHMS).astimezone(timezone.utc)


def get_current_datetime() -> datetime:
    return datetime.utcnow().astimezone(timezone.utc)


class FetchIncidentsError(Exception):
    """Raised when there's an error in fetching incidents."""


class Client(BaseClient):
    CASES = "cases"
    ABUSE_CAMPAIGNS = "abusecampaigns"
    THREATS = "threats"

    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth, timeout=2400)

    def check_the_status_of_an_action_requested_on_a_case_request(self, case_id, action_id, subtenant):
        params = assign_params(subtenant)
        headers = self._headers

        response = self._http_request("get", f"cases/{case_id}/actions/{action_id}", params=params, headers=headers)

        return response

    def check_the_status_of_an_action_requested_on_a_threat_request(self, threat_id, action_id, subtenant):
        params = assign_params(subtenant)
        headers = self._headers

        response = self._http_request("get", f"threats/{threat_id}/actions/{action_id}", params=params, headers=headers)

        return response

    def download_data_from_threat_log_in_csv_format_request(self, filter_, source, subtenant):
        params = assign_params(filter=filter_, source=source, subtenant=subtenant)

        headers = self._headers

        response = self._http_request("get", "threats_export/csv", params=params, headers=headers, resp_type="response")
        return response

    def get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(
        self, filter_="", page_size=None, page_number=None, subtenant=None
    ):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, subtenant=subtenant)

        headers = self._headers

        response = self._http_request("get", "cases", params=params, headers=headers)

        return response

    def get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(
        self,
        filter_="",
        page_size=None,
        page_number=None,
        subtenant=None,
        subject=None,
        sender=None,
        recipient=None,
        reporter=None,
        attackType=None,
        threatType=None,
    ):
        params = assign_params(
            filter=filter_,
            pageSize=page_size,
            pageNumber=page_number,
            subtenant=subtenant,
            subject=subject,
            sender=sender,
            recipient=recipient,
            reporter=reporter,
            attackType=attackType,
            threatType=threatType,
        )

        headers = self._headers

        response = self._http_request("get", "abusecampaigns", params=params, headers=headers)

        return response

    def get_a_list_of_threats_request(
        self,
        filter_="",
        page_size=None,
        page_number=None,
        source=None,
        subtenant=None,
        subject=None,
        sender=None,
        recipient=None,
        topic=None,
        attackType=None,
        attackVector=None,
    ):
        params = assign_params(
            filter=filter_,
            pageSize=page_size,
            pageNumber=page_number,
            source=source,
            subtenant=subtenant,
            subject=subject,
            sender=sender,
            recipient=recipient,
            topic=topic,
            attackType=attackType,
            attackVector=attackVector,
        )

        headers = self._headers

        response = self._http_request("get", "threats", params=params, headers=headers)

        return response

    def get_page_number_and_max_iterations(self, max_incidents_to_fetch):
        page_size = min(max_incidents_to_fetch, 100)
        max_iterations = (max_incidents_to_fetch // page_size) + 1
        return page_size, max_iterations

    def get_paginated_cases_list(self, filter_="", max_incidents_to_fetch=FETCH_LIMIT):
        cases_response: dict[str, list[dict]] = {"cases": []}
        if max_incidents_to_fetch < 1:
            return cases_response

        page_number, current_iteration = 1, 1
        page_size, max_iterations = self.get_page_number_and_max_iterations(max_incidents_to_fetch)

        while page_number is not None:
            response = self.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(
                filter_=filter_, page_size=page_size, page_number=page_number
            )
            cases_response["cases"].extend(response.get("cases", []))
            page_number = response.get("nextPageNumber", None)
            current_iteration += 1
            if current_iteration > max_iterations:
                break
        return cases_response

    def get_paginated_threats_list(self, filter_="", max_incidents_to_fetch=FETCH_LIMIT):
        threats_response: dict[str, list[dict]] = {"threats": []}
        if max_incidents_to_fetch < 1:
            return threats_response

        page_number, current_iteration = 1, 1
        page_size, max_iterations = self.get_page_number_and_max_iterations(max_incidents_to_fetch)

        while page_number is not None:
            response = self.get_a_list_of_threats_request(filter_=filter_, page_size=page_size, page_number=page_number)
            threats_response["threats"].extend(response.get("threats", []))
            page_number = response.get("nextPageNumber", None)
            current_iteration += 1
            if current_iteration > max_iterations:
                break
        return threats_response

    def get_paginated_abusecampaigns_list(self, filter_="", max_incidents_to_fetch=FETCH_LIMIT):
        campaigns_response: dict[str, list[dict]] = {"campaigns": []}
        if max_incidents_to_fetch < 1:
            return campaigns_response

        page_number, current_iteration = 1, 1
        page_size, max_iterations = self.get_page_number_and_max_iterations(max_incidents_to_fetch)

        while page_number is not None:
            response = self.get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(
                filter_=filter_, page_size=page_size, page_number=page_number
            )
            campaigns_response["campaigns"].extend(response.get("campaigns", []))
            page_number = response.get("nextPageNumber", None)
            current_iteration += 1
            if current_iteration > max_iterations:
                break
        return campaigns_response

    def get_details_of_a_threat_request(self, threat_id, subtenant=None, page_size=None, page_number=None):
        """
        Get details of a specific threat with pagination support.

        Args:
            threat_id (str): The ID of the threat to get details for
            subtenant (str, optional): The subtenant ID
            page_size (int, optional): The number of items per page
            page_number (int, optional): The page number (zero-based)

        Returns:
            dict: The threat details with pagination
        """
        headers = self._headers
        params = assign_params(subtenant=subtenant, pageSize=page_size, pageNumber=page_number)

        response = self._http_request("get", f"threats/{threat_id}", params=params, headers=headers)

        return response

    def get_details_of_an_abnormal_case_request(self, case_id, subtenant=None):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request("get", f"cases/{case_id}", params=params, headers=headers)

        return response

    def get_details_of_an_abuse_mailbox_campaign_request(self, campaign_id, subtenant=None):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request("get", f"abusecampaigns/{campaign_id}", params=params, headers=headers)

        return response

    def get_employee_identity_analysis_genome_data_request(self, email_address):
        headers = self._headers

        response = self._http_request("get", f"employee/{email_address}/identity", headers=headers)

        return response

    def get_employee_information_request(self, email_address):
        headers = self._headers

        response = self._http_request("get", f"employee/{email_address}", headers=headers)

        return response

    def get_employee_login_information_for_last_30_days_in_csv_format_request(self, email_address):
        headers = self._headers

        response = self._http_request("get", f"employee/{email_address}/logins", headers=headers, resp_type="response")

        return response

    def get_the_latest_threat_intel_feed_request(self):
        headers = self._headers
        response = self._http_request("get", "threat-intel", headers=headers, timeout=120, resp_type="response")

        return response

    def manage_a_threat_identified_by_abnormal_security_request(self, threat_id, action):
        headers = self._headers
        json_data = {"action": action}

        response = self._http_request("post", f"threats/{threat_id}", json_data=json_data, headers=headers)

        return response

    def manage_an_abnormal_case_request(self, case_id, action):
        headers = self._headers
        json_data = {"action": action}

        response = self._http_request("post", f"cases/{case_id}", json_data=json_data, headers=headers)

        return response

    def provides_the_analysis_and_timeline_details_of_a_case_request(self, case_id, subtenant):
        params = assign_params(subtenant=subtenant)
        headers = self._headers

        response = self._http_request("get", f"cases/{case_id}/analysis", params=params, headers=headers)

        return response

    def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request(self, reporter, report_type):
        headers = self._headers
        json_data = {
            "reporter": reporter,
            "report_type": report_type,
        }
        response = self._http_request("post", "inquiry", json_data=json_data, headers=headers)

        return response

    def submit_false_negative_report_request(self, recipient_email, sender_email, subject):
        headers = self._headers
        json_data = {
            "report_type": "false-negative",
            "recipient_email": recipient_email,
            "sender_email": sender_email,
            "subject": subject,
        }
        response = self._http_request("post", "detection360/reports", json_data=json_data, headers=headers)

        return response

    def submit_false_positive_report_request(self, portal_link):
        headers = self._headers
        json_data = {
            "report_type": "false-positive",
            "portal_link": portal_link,
        }
        response = self._http_request("post", "detection360/reports", json_data=json_data, headers=headers)

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
    case_id = str(args.get("case_id", ""))
    action_id = str(args.get("action_id", ""))
    subtenant = args.get("subtenant", None)

    response = client.check_the_status_of_an_action_requested_on_a_case_request(case_id, action_id, subtenant)
    command_results = CommandResults(
        outputs_prefix="AbnormalSecurity.ActionStatus", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def check_the_status_of_an_action_requested_on_a_threat_command(client, args):
    threat_id = str(args.get("threat_id", ""))
    action_id = str(args.get("action_id", ""))
    subtenant = args.get("subtenant", None)

    response = client.check_the_status_of_an_action_requested_on_a_threat_request(threat_id, action_id, subtenant)
    command_results = CommandResults(
        outputs_prefix="AbnormalSecurity.ActionStatus", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def download_data_from_threat_log_in_csv_format_command(client, args):
    filter_ = str(args.get("filter", ""))
    source = str(args.get("source", ""))
    subtenant = args.get("subtenant", None)

    response = client.download_data_from_threat_log_in_csv_format_request(filter_, source, subtenant)
    filename = "threat_log.csv"
    file_content = response.text

    results = fileResult(filename, file_content)

    return results


def get_a_list_of_abnormal_cases_identified_by_abnormal_security_command(client, args):
    filter_ = str(args.get("filter", ""))
    page_size = args.get("page_size", None)
    page_number = args.get("page_number", None)
    subtenant = args.get("subtenant", None)

    response = client.get_a_list_of_abnormal_cases_identified_by_abnormal_security_request(
        filter_, page_size, page_number, subtenant
    )
    markdown = tableToMarkdown("Case IDs", response.get("cases", []), headers=["caseId", "description"], removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.inline_response_200_1",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_a_list_of_campaigns_submitted_to_abuse_mailbox_command(client, args):
    filter_ = str(args.get("filter", ""))
    page_size = args.get("page_size", None)
    page_number = args.get("page_number", None)
    subtenant = args.get("subtenant", None)
    subject = args.get("subject", None)
    sender = args.get("sender", None)
    recipient = args.get("recipient", None)
    reporter = args.get("reporter", None)
    attackType = args.get("attackType", None)
    threatType = args.get("threatType", None)

    response = client.get_a_list_of_campaigns_submitted_to_abuse_mailbox_request(
        filter_, page_size, page_number, subtenant, subject, sender, recipient, reporter, attackType, threatType
    )
    markdown = tableToMarkdown("Campaign IDs", response.get("campaigns", []), headers=["campaignId"], removeNull=True)

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.AbuseCampaign",
        outputs_key_field="campaignId",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_a_list_of_threats_command(client, args):
    filter_ = str(args.get("filter", ""))
    page_size = args.get("page_size", None)
    page_number = args.get("page_number", None)
    source = str(args.get("source", ""))
    subtenant = args.get("subtenant", None)
    subject = args.get("subject", None)
    sender = args.get("sender", None)
    recipient = args.get("recipient", None)
    topic = args.get("topic", None)
    attackType = args.get("attackType", None)
    attackVector = args.get("attackVector", None)

    response = client.get_a_list_of_threats_request(
        filter_, page_size, page_number, source, subtenant, subject, sender, recipient, topic, attackType, attackVector
    )
    markdown = tableToMarkdown("Threat IDs", response.get("threats"), headers=["threatId"], removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.inline_response_200",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )
    return command_results


def get_details_of_a_threat_command(client, args):
    threat_id = str(args.get("threat_id", ""))
    subtenant = args.get("subtenant", None)
    page_size = args.get("page_size", None)
    page_number = args.get("page_number", None)

    response = client.get_details_of_a_threat_request(threat_id, subtenant, page_size, page_number)
    headers = [
        "subject",
        "fromAddress",
        "fromName",
        "toAddresses",
        "recipientAddress",
        "receivedTime",
        "attackType",
        "attackStrategy",
        "abxMessageId",
        "abxPortalUrl",
        "attachmentCount",
        "attachmentNames",
        "attackVector",
        "attackedParty",
        "autoRemediated",
        "impersonatedParty",
        "internetMessageId",
        "isRead",
        "postRemediated",
        "remediationStatus",
        "remediationTimestamp",
        "sentTime",
        "threatId",
        "ccEmails",
        "replyToEmails",
        "returnPath",
        "senderDomain",
        "senderIpAddress",
        "summaryInsights",
        "urlCounturls",
    ]
    markdown = tableToMarkdown(
        f"Messages in Threat {response.get('threatId', '')}", response.get("messages", []), headers=headers, removeNull=True
    )

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.ThreatDetails",
        outputs_key_field="threatId",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_details_of_an_abnormal_case_command(client, args):
    case_id = str(args.get("case_id", ""))
    subtenant = args.get("subtenant", None)
    response = client.get_details_of_an_abnormal_case_request(case_id, subtenant)
    headers = ["caseId", "severity", "affectedEmployee", "firstObserved", "threatIds", "genai_summary"]
    markdown = tableToMarkdown(f"Details of Case {response.get('caseId', '')}", response, headers=headers, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.AbnormalCaseDetails",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_details_of_an_abuse_mailbox_campaign_command(client, args):
    campaign_id = str(args.get("campaign_id", ""))
    subtenant = args.get("subtenant", None)

    response = client.get_details_of_an_abuse_mailbox_campaign_request(campaign_id, subtenant)
    command_results = CommandResults(
        outputs_prefix="AbnormalSecurity.AbuseCampaign", outputs_key_field="campaignId", outputs=response, raw_response=response
    )

    return command_results


def get_employee_identity_analysis_genome_data_command(client, args):
    email_address = str(args.get("email_address", ""))

    response = client.get_employee_identity_analysis_genome_data_request(email_address)

    headers = ["description", "key", "name", "values"]

    markdown = tableToMarkdown(f"Analysis of {email_address}", response.get("data", []), headers=headers, removeNull=True)

    response["email"] = email_address
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.Employee",
        outputs_key_field="email",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_employee_information_command(client, args):
    email_address = str(args.get("email_address", ""))

    response = client.get_employee_information_request(email_address)
    command_results = CommandResults(
        outputs_prefix="AbnormalSecurity.Employee", outputs_key_field="email", outputs=response, raw_response=response
    )

    return command_results


def get_employee_login_information_for_last_30_days_in_csv_format_command(client, args):
    email_address = str(args.get("email_address", ""))

    response = client.get_employee_login_information_for_last_30_days_in_csv_format_request(email_address)
    filename = "employee_login_info_30_days.csv"
    file_content = response.text

    results = fileResult(filename, file_content)

    return results


def get_the_latest_threat_intel_feed_command(client, args=None):
    response = client.get_the_latest_threat_intel_feed_request()
    filename = "threat_intel_feed.json"
    file_content = response.text
    results = fileResult(filename, file_content)

    return results


def manage_a_threat_identified_by_abnormal_security_command(client, args):
    threat_id = str(args.get("threat_id", ""))
    action = str(args.get("action", ""))

    response = client.manage_a_threat_identified_by_abnormal_security_request(threat_id, action)
    command_results = CommandResults(
        outputs_prefix="AbnormalSecurity.ThreatManageResults", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def manage_an_abnormal_case_command(client, args):
    case_id = str(args.get("case_id", ""))
    action = str(args.get("action", ""))

    response = client.manage_an_abnormal_case_request(case_id, action)
    command_results = CommandResults(
        outputs_prefix="AbnormalSecurity.CaseManageResults", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def provides_the_analysis_and_timeline_details_of_a_case_command(client, args):
    case_id = str(args.get("case_id", ""))
    subtenant = args.get("subtenant", None)
    response = client.provides_the_analysis_and_timeline_details_of_a_case_request(case_id, subtenant)
    insight_headers = ["signal", "description"]
    markdown = tableToMarkdown(f"Insights for {case_id}", response.get("insights", []), headers=insight_headers, removeNull=True)

    timeline_headers = [
        "event_timestamp",
        "category",
        "title",
        "field_labels",
        "ip_address",
        "description",
        "location",
        "sender",
        "subject",
        "title",
        "flagging detectors",
        "rule_name",
    ]

    markdown += tableToMarkdown(
        f"Event Timeline for {response.get('caseId', '')}",
        response.get("eventTimeline", []),
        headers=timeline_headers,
        removeNull=True,
    )

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.CaseAnalysis",
        outputs_key_field="caseId",
        outputs=response,
        raw_response=response,
    )

    return command_results


def submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command(client, args):
    reporter = str(args.get("reporter", ""))
    report_type = str(args.get("report_type", ""))
    response = client.submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_request(reporter, report_type)
    command_results = CommandResults(
        outputs_prefix="AbnormalSecurity.SubmitInquiry", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def submit_false_negative_report_command(client, args):
    recipient_email = str(args.get("recipient_email", ""))
    sender_email = str(args.get("sender_email", ""))
    subject = str(args.get("subject", ""))
    response = client.submit_false_negative_report_request(recipient_email, sender_email, subject)
    command_results = CommandResults(readable_output=response, raw_response=response)

    return command_results


def submit_false_positive_report_command(client, args):
    portal_link = str(args.get("portal_link", ""))
    response = client.submit_false_positive_report_request(portal_link)
    command_results = CommandResults(readable_output=response, raw_response=response)

    return command_results


def get_a_list_of_vendors_command(client, args):
    page_size = str(args.get("page_size", ""))
    page_number = str(args.get("page_number", ""))
    response = client.get_a_list_of_vendors_request(page_size, page_number)
    markdown = tableToMarkdown("Vendor Domains", response, headers=["vendorDomain"], removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.VendorsList",
        outputs_key_field="vendorDomain",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_the_details_of_a_specific_vendor_command(client, args):
    vendor_domain: str = args["vendor_domain"]
    response = client.get_the_details_of_a_specific_vendor_request(vendor_domain)
    markdown = tableToMarkdown("Vendor Domain", response, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.VendorDetails",
        outputs_key_field="vendorDomain",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_the_activity_of_a_specific_vendor_command(client, args):
    vendor_domain: str = args["vendor_domain"]
    response = client.get_the_activity_of_a_specific_vendor_request(vendor_domain)
    markdown = tableToMarkdown("Vendor Activity", response.get("eventTimeline"), removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.VendorActivity",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_a_list_of_vendor_cases_command(client, args):
    filter_ = str(args.get("filter", ""))
    page_size = str(args.get("page_size", ""))
    page_number = str(args.get("page_number", ""))

    response = client.get_a_list_of_vendor_cases_request(filter_, page_size, page_number)
    markdown = tableToMarkdown("Vendor Case IDs", response, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.VendorCases",
        outputs_key_field="vendorCaseId",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_the_details_of_a_vendor_case_command(client, args):
    case_id: str = args["case_id"]
    response = client.get_the_details_of_a_vendor_case_request(case_id)
    markdown = tableToMarkdown("Case Details", response, removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.VendorCaseDetails",
        outputs_key_field="vendorCaseId",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command(client, args):
    start = str(args.get("start", ""))
    end = str(args.get("end", ""))

    response = client.get_a_list_of_unanalyzed_abuse_mailbox_campaigns_request(start, end)
    markdown = tableToMarkdown("Unanalyzed Abuse Mailbox Campaigns", response.get("results", []), removeNull=True)
    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.UnanalyzedAbuseCampaigns",
        outputs_key_field="abx_message_id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def generate_threat_incidents(client, threats, max_page_number, start_datetime, end_datetime):
    incidents = []
    for threat in threats:
        page_number = 1
        all_messages, all_filtered_messages = [], []
        while page_number is not None:
            threat_details = client.get_details_of_a_threat_request(threat["threatId"], page_number=page_number)
            for message in threat_details["messages"]:
                all_messages.append(message)
                remediation_datetime = try_str_to_datetime(message.get("remediationTimestamp"))
                if remediation_datetime and start_datetime <= remediation_datetime <= end_datetime:
                    all_filtered_messages.append(message)
                if remediation_datetime and remediation_datetime < start_datetime:
                    break
            page_number = threat_details.get("nextPageNumber", None)
            if page_number is not None and page_number > max_page_number:
                break

        received_time = ""
        threat_details["messages"] = all_filtered_messages or all_messages
        if threat_details.get("messages", []):
            received_time = threat_details["messages"][0].get("receivedTime")

        incident = {
            "dbotMirrorId": str(threat["threatId"]),
            "name": "Threat",
            "occurred": received_time[:26] if len(received_time) > 26 else received_time,
            "details": "Threat",
            "rawJSON": json.dumps(threat_details) if threat_details else {},
        }
        incidents.append(incident)
    return incidents


def generate_abuse_campaign_incidents(client, campaigns):
    incidents = []
    for campaign in campaigns:
        campaign_details = client.get_details_of_an_abuse_mailbox_campaign_request(campaign["campaignId"])
        first_reported = campaign_details.get("firstReported", "")
        incident = {
            "dbotMirrorId": str(campaign.get("campaignId", "")),
            "name": "Abuse Campaign",
            "occurred": first_reported[:26] if len(first_reported) > 26 else first_reported,
            "details": "Abuse Campaign",
            "rawJSON": json.dumps(campaign_details) if campaign_details else {},
        }
        incidents.append(incident)
    return incidents


def generate_account_takeover_cases_incidents(client, cases):
    incidents = []
    for case in cases:
        case_details = client.get_details_of_an_abnormal_case_request(case["caseId"])
        incident = {
            "dbotMirrorId": str(case["caseId"]),
            "name": "Account Takeover Case",
            "occurred": case_details["firstObserved"],
            "details": case["description"],
            "genaiSummary": case_details["genai_summary"],
            "rawJSON": json.dumps(case_details) if case_details else {},
        }
        incidents.append(incident)
    return incidents


def fetch_incidents(
    client: Client,
    last_run: dict[str, Any],
    first_fetch_time: str,
    fetch_threats: bool,
    fetch_abuse_campaigns: bool,
    fetch_account_takeover_cases: bool,
    max_page_number: int = 8,
    max_incidents_to_fetch: int = FETCH_LIMIT,
    polling_lag: timedelta = timedelta(minutes=0),
):
    """
    Fetch incidents from various sources (threats, abuse campaigns, and account takeovers).

    Parameters:
    - client (Client): Client object to interact with the API.
    - last_run (Dict[str, Any]): Dictionary containing details about the last time incidents were fetched.
    - first_fetch_time (str): ISO formatted string indicating the first time from which to start fetching incidents.
    - max_page_number (int): Maximum number of pages to fetch for incidents.
    - max_incidents_to_fetch (int, optional): Maximum number of incidents to fetch. Defaults to FETCH_LIMIT.
    - polling_lag (int, optional): Time in minutes to subtract from polling time window for data consistency. Defaults to 0.

    Returns:
    - Tuple[Dict[str, str], List[Dict]]: Tuple containing a dictionary with the `last_fetch` time and a list of fetched incidents.
    """
    try:
        last_fetch = last_run.get("last_fetch", first_fetch_time)
        last_fetch = datetime.fromisoformat(last_fetch[:-1]).astimezone(timezone.utc)

        current_datetime = get_current_datetime()
        start_time = last_fetch + timedelta(milliseconds=1)  # Not to overlap with previous polling window
        end_time = get_current_datetime()

        if polling_lag is not None:
            start_time = start_time - polling_lag
            end_time = end_time - polling_lag

        start_timestamp = start_time.strftime(ISO_8601_FORMAT)
        end_timestamp = end_time.strftime(ISO_8601_FORMAT)

        all_incidents = []
        current_pending_incidents_to_fetch = max_incidents_to_fetch
        threat_incidents, abuse_campaign_incidents, account_takeover_cases_incidents = [], [], []

        if fetch_threats and current_pending_incidents_to_fetch > 0:
            threats_filter = f"latestTimeRemediated gte {start_timestamp} and latestTimeRemediated lte {end_timestamp}"
            threats_response = client.get_paginated_threats_list(
                filter_=threats_filter, max_incidents_to_fetch=current_pending_incidents_to_fetch
            )
            threat_incidents = generate_threat_incidents(
                client, threats_response.get("threats", []), max_page_number, start_time, end_time
            )
        current_pending_incidents_to_fetch -= len(threat_incidents)

        if fetch_abuse_campaigns and current_pending_incidents_to_fetch > 0:
            abuse_campaigns_filter = f"lastReportedTime gte {start_timestamp} and lastReportedTime lte {end_timestamp}"
            abuse_campaigns_response = client.get_paginated_abusecampaigns_list(
                filter_=abuse_campaigns_filter, max_incidents_to_fetch=current_pending_incidents_to_fetch
            )
            abuse_campaign_incidents = generate_abuse_campaign_incidents(client, abuse_campaigns_response.get("campaigns", []))
        current_pending_incidents_to_fetch -= len(abuse_campaign_incidents)

        if fetch_account_takeover_cases and current_pending_incidents_to_fetch > 0:
            account_takeover_cases_filter = f"lastModifiedTime gte {start_timestamp} and lastModifiedTime lte {end_timestamp}"
            account_takeover_cases_response = client.get_paginated_cases_list(
                filter_=account_takeover_cases_filter, max_incidents_to_fetch=current_pending_incidents_to_fetch
            )
            account_takeover_cases_incidents = generate_account_takeover_cases_incidents(
                client, account_takeover_cases_response.get("cases", [])
            )

        all_incidents = threat_incidents + abuse_campaign_incidents + account_takeover_cases_incidents
    except Exception as e:
        logging.error(f"Failed fetching incidents: {e}")
        raise FetchIncidentsError(f"Error while fetching incidents: {e}")

    next_run = {"last_fetch": current_datetime.strftime(ISO_8601_FORMAT)}

    return next_run, all_incidents[:max_incidents_to_fetch]


def test_module(client):
    # Run a sample request to retrieve mock data
    client.get_a_list_of_threats_request(None, None, None, None)
    demisto.results("ok")


def main():  # pragma: nocover
    params = demisto.params()
    args = demisto.args()
    url = params.get("url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    is_fetch = params.get("isFetch")
    headers = {}
    mock_data = str(args.get("mock-data", ""))
    if mock_data.lower() == "true":
        headers["Mock-Data"] = "True"
    headers["Authorization"] = f'Bearer {params["api_key"]}'
    headers["Soar-Integration-Origin"] = "Cortex XSOAR"
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            # Threat commands
            "abnormal-security-list-threats": get_a_list_of_threats_command,
            "abnormal-security-get-threat": get_details_of_a_threat_command,
            "abnormal-security-manage-threat": manage_a_threat_identified_by_abnormal_security_command,
            "abnormal-security-check-threat-action-status": check_the_status_of_an_action_requested_on_a_threat_command,
            "abnormal-security-download-threat-log-csv": download_data_from_threat_log_in_csv_format_command,
            # Case commands
            "abnormal-security-list-abnormal-cases": get_a_list_of_abnormal_cases_identified_by_abnormal_security_command,
            "abnormal-security-get-abnormal-case": get_details_of_an_abnormal_case_command,
            "abnormal-security-manage-abnormal-case": manage_an_abnormal_case_command,
            "abnormal-security-check-case-action-status": check_the_status_of_an_action_requested_on_a_case_command,
            "abnormal-security-get-case-analysis-and-timeline": provides_the_analysis_and_timeline_details_of_a_case_command,
            # Threat Intel commands
            "abnormal-security-get-latest-threat-intel-feed": get_the_latest_threat_intel_feed_command,
            # Abuse Mailbox commands
            "abnormal-security-list-abuse-mailbox-campaigns": get_a_list_of_campaigns_submitted_to_abuse_mailbox_command,
            "abnormal-security-get-abuse-mailbox-campaign": get_details_of_an_abuse_mailbox_campaign_command,
            "abnormal-security-list-unanalyzed-abuse-mailbox-campaigns": get_a_list_of_unanalyzed_abuse_mailbox_campaigns_command,
            # Employee commands
            "abnormal-security-get-employee-identity-analysis": get_employee_identity_analysis_genome_data_command,
            "abnormal-security-get-employee-information": get_employee_information_command,
            "abnormal-security-get-employee-last-30-days-login-csv":  # noqa: E501
            get_employee_login_information_for_last_30_days_in_csv_format_command,
            # Detection 360 commands
            "abnormal-security-submit-inquiry-to-request-a-report-on-misjudgement":  # noqa: E501
            submit_an_inquiry_to_request_a_report_on_misjudgement_by_abnormal_security_command,
            "abnormal-security-submit-false-negative-report": submit_false_negative_report_command,
            "abnormal-security-submit-false-positive-report": submit_false_positive_report_command,
            # Vendor commands
            "abnormal-security-list-vendors": get_a_list_of_vendors_command,
            "abnormal-security-get-vendor-details": get_the_details_of_a_specific_vendor_command,
            "abnormal-security-get-vendor-activity": get_the_activity_of_a_specific_vendor_command,
            # Vendor case commands
            "abnormal-security-list-vendor-cases": get_a_list_of_vendor_cases_command,
            "abnormal-security-get-vendor-case-details": get_the_details_of_a_vendor_case_command,
        }

        if command == "test-module":
            headers["Mock-Data"] = "True"
            test_client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers, auth=None)
            test_module(test_client)
        elif command == "fetch-incidents" and is_fetch:
            max_incidents_to_fetch = arg_to_number(params.get("max_fetch", FETCH_LIMIT))
            fetch_threats = params.get("fetch_threats", False)
            # Get the polling lag time parameter
            polling_lag_minutes = int(params.get("polling_lag", 2))
            max_page_number = int(params.get("max_page_number", 8))
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
                max_incidents_to_fetch=max_incidents_to_fetch or FETCH_LIMIT,
                fetch_threats=fetch_threats,
                fetch_abuse_campaigns=fetch_abuse_campaigns,
                fetch_account_takeover_cases=fetch_account_takeover_cases,
                max_page_number=max_page_number,
                polling_lag=polling_lag_delta,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, args))  # type: ignore
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
