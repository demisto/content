import asyncio
import sys
import threading
import time
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from ContentClientApiModule import *  # noqa: F401

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

# 4xx status codes that indicate systemic issues and should NOT be skipped
NON_SKIPPABLE_STATUS_CODES = {401, 403, 429}

LAST_RUN_VERSION = 2
# Each fetch window is listed as one page of this many IDs. A window with more items is halved
# instead of paginated, because list endpoints page by offset over live data and are not sorted by
# the field the window filters on, so paginating can skip an item that changes mid-pagination.
LIST_PAGE_SIZE = 500
DEFAULT_FETCH_TIME_BUDGET_SECONDS = 150
DEFAULT_MAX_WINDOW_MINUTES = 1440
DEFAULT_DETAIL_CONCURRENCY = 4
# Well under the SOAR API's limit of 300 requests a minute per customer, which other clients share.
DEFAULT_DETAIL_RATE_PER_SECOND = 2.0
CASE_MODE_CREATED = "created"
CASE_MODE_MODIFIED = "modified"
CASE_FETCH_MODES = {"Last modified time": CASE_MODE_MODIFIED, "Created time": CASE_MODE_CREATED}
MIN_REQUEST_SECONDS = 1.0
MAX_ITEM_FAILURES = 3
MAX_CONSECUTIVE_FAILURES = 5
# 50,000 items in one window. Only a window that can't be halved further, or that's already partly
# emitted, is paginated, so this guards against a page number that never runs out.
MAX_LIST_PAGES = 100


def _is_skippable_error(e: DemistoException) -> bool:
    """Check if a DemistoException from an API call is a 4xx error that can be safely skipped.

    Skippable errors are client errors (4xx) that are specific to a single entity
    (e.g., 404 Not Found, 410 Gone). Non-skippable errors indicate systemic issues
    (401 Unauthorized, 403 Forbidden, 429 Rate Limit) and should be raised.

    Args:
        e: The DemistoException raised by _http_request.

    Returns:
        True if the error can be safely skipped, False otherwise.
    """
    status_code = _status_code(e)
    return status_code is not None and 400 <= status_code < 500 and status_code not in NON_SKIPPABLE_STATUS_CODES


def _status_code(e: Exception) -> int | None:
    return getattr(getattr(e, "response", None), "status_code", None)


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


class AuthError(Exception):
    """Raised on a 401 or 403, which no retry can fix, so the fetch run commits nothing."""


class RateLimitedError(Exception):
    """Raised on a 429. The API asks for a ~60s wait, longer than is worth spending in one run."""


class BudgetExhaustedError(Exception):
    """Raised when the fetch time budget has run out before or during an HTTP call."""


class Deadline:
    """Wall-clock budget shared by every HTTP call in one fetch run.

    XSOAR kills a fetch-incidents run after 3 minutes and discards its results, so the run has to stop
    on its own in time to save its progress.
    """

    def __init__(self, seconds: float, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._expires_at = clock() + seconds

    def remaining(self) -> float:
        return self._expires_at - self._clock()

    def expired(self) -> bool:
        return self.remaining() < MIN_REQUEST_SECONDS

    def request_timeout(self) -> float:
        remaining = self.remaining()
        if remaining < MIN_REQUEST_SECONDS:
            raise BudgetExhaustedError
        return remaining


class Client(ContentClient):
    CASES = "cases"
    ABUSE_CAMPAIGNS = "abusecampaigns"
    THREATS = "threats"

    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(
            base_url=server_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
            auth=auth,
            timeout=2400,
            # No retries, as in earlier versions; fetch retries a failed call on its next run instead.
            retry_policy=RetryPolicy(max_attempts=1),
            # Fetch stops one incident type after MAX_CONSECUTIVE_FAILURES. A breaker shared by the
            # whole client would also stop the other types, and would count skippable 404s.
            circuit_breaker=CircuitBreakerPolicy(failure_threshold=sys.maxsize),
            client_name="AbnormalSecurity",
        )

    def limit_rate(self, rate_per_second: float) -> None:
        """Caps the requests this client sends, from all threads together, at `rate_per_second`."""
        self._rate_limiter = TokenBucketRateLimiter(RateLimitPolicy(rate_per_second=rate_per_second))

    def _http_request(self, *args, deadline: Deadline | None = None, **kwargs):
        """Fetch passes a `deadline`, which caps the whole call, from waiting for a rate token to
        reading the body, at the time left.

        With a deadline, a 401 or 403 raises `AuthError` and a 429 raises `RateLimitedError`.
        """
        if deadline is None:
            return super()._http_request(*args, **kwargs)
        try:
            response = asyncio.run(asyncio.wait_for(self._request(*args, **kwargs), deadline.request_timeout()))
        except TimeoutError as e:
            raise BudgetExhaustedError from e
        except ContentClientAuthenticationError as e:
            raise AuthError(str(e)) from e
        except ContentClientRateLimitError as e:
            raise RateLimitedError(str(e)) from e
        try:
            return response.json()
        except ValueError as e:
            raise DemistoException(f"The response from {response.url} isn't valid JSON: {e}", e) from e

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
        self, filter_="", page_size=None, page_number=None, subtenant=None, deadline=None
    ):
        params = assign_params(filter=filter_, pageSize=page_size, pageNumber=page_number, subtenant=subtenant)

        headers = self._headers

        response = self._http_request("get", "cases", params=params, headers=headers, deadline=deadline)

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
        deadline=None,
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

        response = self._http_request("get", "abusecampaigns", params=params, headers=headers, deadline=deadline)

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
        deadline=None,
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

        response = self._http_request("get", "threats", params=params, headers=headers, deadline=deadline)

        return response

    def get_details_of_a_threat_request(self, threat_id, subtenant=None, page_size=None, page_number=None, deadline=None):
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

        response = self._http_request("get", f"threats/{threat_id}", params=params, headers=headers, deadline=deadline)

        return response

    def get_details_of_an_abnormal_case_request(self, case_id, subtenant=None, deadline=None):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request("get", f"cases/{case_id}", params=params, headers=headers, deadline=deadline)

        return response

    def get_details_of_an_abuse_mailbox_campaign_request(self, campaign_id, subtenant=None, deadline=None):
        headers = self._headers
        params = assign_params(subtenant=subtenant)

        response = self._http_request("get", f"abusecampaigns/{campaign_id}", params=params, headers=headers, deadline=deadline)

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

    def search_messages_request(self, source, tenant_ids, filters, page_number=None, page_size=None):
        """
        Search for messages using the SOAR Message Search API.

        Args:
            source (str): Message source (abnormal|quarantine)
            tenant_ids (list): List of tenant IDs
            filters (dict): Search filters
            page_number (int, optional): Page number (default 1)
            page_size (int, optional): Page size (default 100, max 1000)

        Returns:
            dict: Search results with messages, pagination, and metadata
        """
        params = assign_params(pageNumber=page_number, pageSize=page_size)
        headers = self._headers

        json_data = {
            "source": source,
            "tenant_ids": tenant_ids,
            "filters": filters,
        }

        response = self._http_request("post", "search", params=params, json_data=json_data, headers=headers)

        return response

    def remediate_messages_request(
        self, action, tenant_ids, source, remediation_reason, messages=None, remediate_all=False, search_filters=None, **kwargs
    ):
        """
        Remediate messages using the SOAR Message Remediation API.

        Args:
            action (str): Action to perform (delete|move_to_inbox|submit_to_d360|reclassify)
            tenant_ids (list): List of tenant IDs
            source (str): Message source (abnormal|quarantine)
            remediation_reason (str): Reason for remediation
            messages (list, optional): List of message objects to remediate
            remediate_all (bool, optional): Whether to remediate all matching messages
            search_filters (dict, optional): Search filters when remediate_all=True
            **kwargs: Additional optional parameters (target_folder, submit_d360_case)

        Returns:
            dict: Remediation response with activity_log_id and metadata
        """
        headers = self._headers

        json_data = {
            "action": action,
            "tenant_ids": tenant_ids,
            "source": source,
            "remediation_reason": remediation_reason,
            "remediate_all": remediate_all,
        }

        if messages:
            json_data["messages"] = messages
        if search_filters:
            json_data["search_filters"] = search_filters

        # Add optional parameters
        if "target_folder" in kwargs:
            json_data["target_folder"] = kwargs["target_folder"]
        if "submit_d360_case" in kwargs:
            json_data["submit_d360_case"] = kwargs["submit_d360_case"]

        response = self._http_request("post", "search/remediate", json_data=json_data, headers=headers)

        return response

    def get_activities_list_request(self, tenant_ids, action=None, page_number=None, page_size=None):
        """
        Get list of activity logs using the SOAR Activity Logs API.

        Args:
            tenant_ids (list): List of tenant IDs (passed as query parameters)
            action (str, optional): Filter by action (search|remediation|csv_export)
            page_number (int, optional): Page number (default 1)
            page_size (int, optional): Page size (default 100, max 1000)

        Returns:
            dict: Activity logs with pagination and metadata
        """
        params = assign_params(action=action, pageNumber=page_number, pageSize=page_size, tenant_ids=tenant_ids)
        headers = self._headers

        response = self._http_request("get", "search/activities", params=params, headers=headers)

        return response

    def get_activity_status_request(self, activity_log_id, page=None, size=None):
        """
        Get status of a specific activity using the SOAR Activity Status API.

        Args:
            activity_log_id (str): Activity log ID
            page (int, optional): Page number (default 1)
            size (int, optional): Page size (default 100, max 1000)

        Returns:
            dict: Activity status with remediation details and metadata
        """
        params = assign_params(page=page, size=size)
        headers = self._headers

        response = self._http_request("get", f"search/activities/{activity_log_id}/status", params=params, headers=headers)

        return response

    def download_message_attachment_request(
        self, message_id, attachment_name, tenant_id, raw_message_id, native_user_id, recipient_mailbox
    ):
        """
        Download a message attachment using the SOAR Attachment Download API.

        Args:
            message_id (str): Abnormal message ID (can be negative)
            attachment_name (str): Name of the attachment to download
            tenant_id (int): Tenant ID for the message
            raw_message_id (str): Cloud provider message ID (O365/GSuite)
            native_user_id (str): Cloud provider user ID
            recipient_mailbox (str): Mailbox email address

        Returns:
            Response: HTTP response object containing the attachment file
        """
        params = assign_params(
            message_id=message_id,
            attachment_name=attachment_name,
            tenant_id=tenant_id,
            raw_message_id=raw_message_id,
            native_user_id=native_user_id,
            recipient_mailbox=recipient_mailbox,
        )
        headers = self._headers

        response = self._http_request(
            "get", "search/messages/attachments/download", params=params, headers=headers, resp_type="response"
        )

        return response

    def download_message_eml_request(self, cloud_message_id, quarantine_identity=None, recipient_mailbox=None):
        """
        Download a message in EML format using the SOAR EML Download API.

        Args:
            cloud_message_id (str): The cloud_message_id from search results (format: abx:CloudMessage:...)
            quarantine_identity (str, optional): Quarantine identifier (required for quarantine messages)
            recipient_mailbox (str, optional): Recipient email address (required for quarantine messages)

        Returns:
            Response: HTTP response object containing the EML file (RFC822 format)
        """
        params = assign_params(quarantineIdentity=quarantine_identity, recipientMailbox=recipient_mailbox)
        headers = self._headers

        response = self._http_request(
            "get", f"search/messages/{cloud_message_id}/eml", params=params, headers=headers, resp_type="response"
        )

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


def search_messages_command(client, args):  # pragma: no cover
    """
    Search for messages using the SOAR Message Search API.
    """
    source = str(args.get("source", ""))
    tenant_ids = argToList(args.get("tenant_ids", []))
    page_number = arg_to_number(args.get("page_number"))
    page_size = arg_to_number(args.get("page_size"))

    # Build filters dictionary
    filters = {}
    if args.get("start_time"):
        filters["start_time"] = str(args.get("start_time"))
    if args.get("end_time"):
        filters["end_time"] = str(args.get("end_time"))
    if args.get("subject"):
        filters["subject"] = str(args.get("subject"))
    if args.get("sender_email"):
        filters["sender_email"] = str(args.get("sender_email"))
    if args.get("sender_name"):
        filters["sender_name"] = str(args.get("sender_name"))
    if args.get("recipient_email"):
        filters["recipient_email"] = str(args.get("recipient_email"))
    if args.get("recipient_name"):
        filters["recipient_name"] = str(args.get("recipient_name"))
    if args.get("attachment_name"):
        filters["attachment_name"] = str(args.get("attachment_name"))
    if args.get("attachment_md5_hash"):
        filters["attachment_md5_hash"] = str(args.get("attachment_md5_hash"))
    if args.get("internet_message_id"):
        filters["internet_message_id"] = str(args.get("internet_message_id"))
    if args.get("body_link"):
        filters["body_link"] = str(args.get("body_link"))
    if args.get("sender_ip"):
        filters["sender_ip"] = str(args.get("sender_ip"))
    if args.get("judgement"):
        filters["judgement"] = str(args.get("judgement"))
    if args.get("use_sender_regex") is not None:
        filters["use_sender_regex"] = argToBoolean(args.get("use_sender_regex"))
    if args.get("use_recipient_regex") is not None:
        filters["use_recipient_regex"] = argToBoolean(args.get("use_recipient_regex"))
    if args.get("show_graymail") is not None:
        filters["show_graymail"] = argToBoolean(args.get("show_graymail"))

    response = client.search_messages_request(source, tenant_ids, filters, page_number, page_size)

    headers = [
        "abnormal_message_id",
        "subject",
        "sender",
        "mailbox_name",
        "received_time",
        "decision_category",
        "judgement",
    ]
    markdown = tableToMarkdown(
        f"Message Search Results (Total: {response.get('total', 0)})",
        response.get("results", []),
        headers=headers,
        removeNull=True,
    )

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.MessageSearch",
        outputs_key_field="abnormal_message_id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def remediate_messages_command(client, args):  # pragma: no cover
    """
    Remediate messages using the SOAR Message Remediation API.
    """
    action = str(args.get("action", ""))
    tenant_ids = argToList(args.get("tenant_ids", []))
    source = str(args.get("source", ""))
    remediation_reason = str(args.get("remediation_reason", ""))
    remediate_all = argToBoolean(args.get("remediate_all", False))

    # Optional parameters
    kwargs = {}
    if args.get("target_folder"):
        kwargs["target_folder"] = str(args.get("target_folder"))
    if args.get("submit_d360_case") is not None:
        kwargs["submit_d360_case"] = argToBoolean(args.get("submit_d360_case"))

    # Handle messages or search_filters
    messages = None
    search_filters = None

    if remediate_all:
        # Build search filters for remediate_all
        search_filters = {}
        if args.get("start_time"):
            search_filters["start_time"] = str(args.get("start_time"))
        if args.get("end_time"):
            search_filters["end_time"] = str(args.get("end_time"))
        if args.get("subject"):
            search_filters["subject"] = str(args.get("subject"))
        if args.get("sender_email"):
            search_filters["sender_email"] = str(args.get("sender_email"))
        if args.get("sender_name"):
            search_filters["sender_name"] = str(args.get("sender_name"))
        if args.get("recipient_email"):
            search_filters["recipient_email"] = str(args.get("recipient_email"))
        if args.get("recipient_name"):
            search_filters["recipient_name"] = str(args.get("recipient_name"))
        if args.get("attachment_name"):
            search_filters["attachment_name"] = str(args.get("attachment_name"))
        if args.get("attachment_md5_hash"):
            search_filters["attachment_md5_hash"] = str(args.get("attachment_md5_hash"))
        if args.get("internet_message_id"):
            search_filters["internet_message_id"] = str(args.get("internet_message_id"))
        if args.get("body_link"):
            search_filters["body_link"] = str(args.get("body_link"))
        if args.get("sender_ip"):
            search_filters["sender_ip"] = str(args.get("sender_ip"))
        if args.get("judgement"):
            search_filters["judgement"] = str(args.get("judgement"))
        if args.get("use_sender_regex") is not None:
            search_filters["use_sender_regex"] = argToBoolean(args.get("use_sender_regex"))
        if args.get("use_recipient_regex") is not None:
            search_filters["use_recipient_regex"] = argToBoolean(args.get("use_recipient_regex"))
        if args.get("show_graymail") is not None:
            search_filters["show_graymail"] = argToBoolean(args.get("show_graymail"))
    else:
        # Parse messages JSON
        messages_json = args.get("messages")
        if messages_json:
            try:
                messages = json.loads(messages_json) if isinstance(messages_json, str) else messages_json
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON format for messages: {e}")

    response = client.remediate_messages_request(
        action, tenant_ids, source, remediation_reason, messages, remediate_all, search_filters, **kwargs
    )

    markdown = f"## Message Remediation Initiated\n\n**Activity Log ID:** {response.get('activity_log_id', 'N/A')}"

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.MessageRemediation",
        outputs_key_field="activity_log_id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_activities_list_command(client, args):
    """
    Get list of activity logs using the SOAR Activity Logs API.
    """
    tenant_ids = argToList(args.get("tenant_ids", []))
    action = args.get("action")
    page_number = arg_to_number(args.get("page_number"))
    page_size = arg_to_number(args.get("page_size"))

    response = client.get_activities_list_request(tenant_ids, action, page_number, page_size)

    headers = ["activity_id", "action", "status", "performed_by", "timestamp", "result_count"]
    markdown = tableToMarkdown(
        f"Activity Logs (Total: {response.get('total', 0)})", response.get("activities", []), headers=headers, removeNull=True
    )

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.Activities",
        outputs_key_field="activity_id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_activity_status_command(client, args):
    """
    Get status of a specific activity using the SOAR Activity Status API.
    """
    activity_log_id = str(args.get("activity_log_id", ""))
    page = arg_to_number(args.get("page"))
    size = arg_to_number(args.get("size"))

    response = client.get_activity_status_request(activity_log_id, page, size)

    # Create markdown for activity summary
    summary_headers = ["activity_id", "action", "status", "performed_by", "timestamp", "result_count"]
    summary_data = {
        "activity_id": response.get("activity_id"),
        "action": response.get("action"),
        "status": response.get("status") or "In Progress",
        "performed_by": response.get("performed_by") or "N/A",
        "timestamp": response.get("timestamp") or "N/A",
        "result_count": response.get("result_count") if response.get("result_count") is not None else "N/A",
    }
    markdown = tableToMarkdown("Activity Status", [summary_data], headers=summary_headers)

    # Add metadata information if available
    if response.get("metadata"):
        metadata = response.get("metadata")
        markdown += f"\n**Trace ID:** {metadata.get('trace_id', 'N/A')}"
        markdown += f"\n**Response Time:** {metadata.get('response_time', 'N/A')}"

    # Add remediation details table if available
    if response.get("remediation_details"):
        detail_headers = [
            "tenant_id",
            "subject",
            "sender",
            "mailbox_name",
            "status",
            "date_remediated",
        ]
        markdown += "\n\n" + tableToMarkdown(
            f"Remediation Details (Total: {response.get('total', 0)})",
            response.get("remediation_details", []),
            headers=detail_headers,
            removeNull=True,
        )
    elif response.get("status") is None or response.get("result_count") is None:
        # Activity is likely still in progress
        markdown += "\n\n**Note:** Activity is in progress. Details will be available once the activity completes."

    command_results = CommandResults(
        readable_output=markdown,
        outputs_prefix="AbnormalSecurity.ActivityStatus",
        outputs_key_field="activity_id",
        outputs=response,
        raw_response=response,
    )

    return command_results


def download_message_attachment_command(client, args):
    """
    Download a message attachment using the SOAR Attachment Download API.
    """
    message_id = str(args.get("message_id", ""))
    attachment_name = str(args.get("attachment_name", ""))
    tenant_id = arg_to_number(args.get("tenant_id"))
    raw_message_id = str(args.get("raw_message_id", ""))
    native_user_id = str(args.get("native_user_id", ""))
    recipient_mailbox = str(args.get("recipient_mailbox", ""))

    response = client.download_message_attachment_request(
        message_id, attachment_name, tenant_id, raw_message_id, native_user_id, recipient_mailbox
    )

    # Return the file to XSOAR
    file_content = response.content
    results = fileResult(attachment_name, file_content)

    return results


def download_message_eml_command(client, args):
    """
    Download a message in EML format using the SOAR EML Download API.
    """
    cloud_message_id = str(args.get("cloud_message_id", ""))
    quarantine_identity = args.get("quarantine_identity")
    recipient_mailbox = args.get("recipient_mailbox")

    response = client.download_message_eml_request(cloud_message_id, quarantine_identity, recipient_mailbox)

    # Generate filename from cloud_message_id
    # Replace special characters to create a valid filename
    safe_filename = cloud_message_id.replace(":", "_").replace("/", "_")
    filename = f"{safe_filename}.eml"

    # Return the EML file to XSOAR
    file_content = response.content
    results = fileResult(filename, file_content)

    return results


def floor_to_second(dt: datetime) -> datetime:
    return dt.replace(microsecond=0)


def format_timestamp(dt: datetime) -> str:
    return dt.strftime(ISO_8601_FORMAT)


def parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, ISO_8601_FORMAT).replace(tzinfo=timezone.utc)


@dataclass
class FetchWindow:
    """Progress through one incident type's time window, persisted in `last_run`.

    The window only moves forward once every item listed in it has become an incident or been
    skipped, so a run that stops early is picked up by the next run without losing anything.
    """

    window_start: datetime
    window_end: datetime
    emitted_ids: list[str] = field(default_factory=list)
    failed: dict[str, int] = field(default_factory=dict)
    # Which timestamp the Account Takeover case window filters on; None for the other types.
    mode: str | None = None

    @classmethod
    def new(cls, start: datetime, upper: datetime, max_window: timedelta, mode: str | None = None) -> "FetchWindow":
        return cls(window_start=start, window_end=_next_window_end(start, upper, max_window), mode=mode)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FetchWindow":
        return cls(
            window_start=parse_timestamp(data["window_start"]),
            window_end=parse_timestamp(data["window_end"]),
            emitted_ids=list(data.get("emitted_ids") or []),
            failed=dict(data.get("failed") or {}),
            mode=data.get("mode"),
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "window_start": format_timestamp(self.window_start),
            "window_end": format_timestamp(self.window_end),
            "emitted_ids": self.emitted_ids,
            "failed": self.failed,
        }
        if self.mode is not None:
            data["mode"] = self.mode
        return data

    def is_empty(self) -> bool:
        return self.window_end <= self.window_start

    def is_untouched(self) -> bool:
        return not self.emitted_ids and not self.failed

    def advance(self, upper: datetime, max_window: timedelta) -> None:
        self.window_start = self.window_end
        self.window_end = _next_window_end(self.window_start, upper, max_window)
        self.emitted_ids = []
        self.failed = {}

    def restart(self, upper: datetime, max_window: timedelta) -> None:
        """Re-lists the window from its current start, e.g. after it starts filtering on another field."""
        self.window_end = _next_window_end(self.window_start, upper, max_window)
        self.emitted_ids = []
        self.failed = {}

    def extend_if_empty(self, upper: datetime, max_window: timedelta) -> None:
        if self.is_empty():
            self.window_end = _next_window_end(self.window_start, upper, max_window)


def _next_window_end(start: datetime, upper: datetime, max_window: timedelta) -> datetime:
    return max(start, min(start + max_window, upper))


@dataclass(frozen=True)
class FetchTypeSpec:
    """How one incident type is listed and turned into incidents."""

    key: str
    label: str
    list_key: str
    id_key: str
    filter_field: str
    # `/threats` treats `lte` as exclusive; `/cases` and `/abusecampaigns` treat it as inclusive.
    end_inclusive: bool
    list_method: str
    builder: Callable[..., dict]
    # Filter field by `FetchWindow.mode`, for types whose window can filter on more than one field.
    mode_filter_fields: dict[str, str] | None = None


def build_threat_incident(
    client: Client, threat: dict, window: FetchWindow, deadline: Deadline | None = None, max_page_number: int = 8
) -> dict:
    """Builds the incident for one threat, keeping the messages remediated inside the window."""
    page_number: int | None = 1
    all_messages, all_filtered_messages = [], []
    threat_details: dict = {}
    while page_number is not None:
        threat_details = client.get_details_of_a_threat_request(threat["threatId"], page_number=page_number, deadline=deadline)
        for message in threat_details.get("messages", []):
            all_messages.append(message)
            timestamp = message.get("remediationTimestamp")
            if not timestamp:
                continue
            remediation_datetime = try_str_to_datetime(timestamp)
            if window.window_start <= remediation_datetime < window.window_end:
                all_filtered_messages.append(message)
            if remediation_datetime < window.window_start:
                break
        page_number = threat_details.get("nextPageNumber")
        if page_number is not None and page_number > max_page_number:
            break

    received_time = ""
    threat_details["messages"] = all_filtered_messages or all_messages
    if threat_details["messages"]:
        received_time = threat_details["messages"][0].get("receivedTime") or ""

    return {
        "dbotMirrorId": str(threat["threatId"]),
        "name": "Threat",
        "occurred": received_time[:26],
        "details": "Threat",
        "rawJSON": json.dumps(threat_details),
    }


def build_abuse_campaign_incident(client: Client, campaign: dict, window: FetchWindow, deadline: Deadline | None = None, **_):
    campaign_details = client.get_details_of_an_abuse_mailbox_campaign_request(campaign["campaignId"], deadline=deadline)
    first_reported = campaign_details.get("firstReported", "")
    return {
        "dbotMirrorId": str(campaign.get("campaignId", "")),
        "name": "Abuse Campaign",
        "occurred": first_reported[:26],
        "details": "Abuse Campaign",
        "rawJSON": json.dumps(campaign_details),
    }


def build_account_takeover_case_incident(client: Client, case: dict, window: FetchWindow, deadline: Deadline | None = None, **_):
    case_details = client.get_details_of_an_abnormal_case_request(case["caseId"], deadline=deadline)
    return {
        "dbotMirrorId": str(case["caseId"]),
        "name": "Account Takeover Case",
        "occurred": case_details["firstObserved"],
        "details": case["description"],
        "genaiSummary": case_details["genai_summary"],
        "rawJSON": json.dumps(case_details),
    }


THREATS_SPEC = FetchTypeSpec(
    key="threats",
    label="threats",
    list_key="threats",
    id_key="threatId",
    filter_field="latestTimeRemediated",
    end_inclusive=False,
    list_method="get_a_list_of_threats_request",
    builder=build_threat_incident,
)
ABUSE_CAMPAIGNS_SPEC = FetchTypeSpec(
    key="abuse_campaigns",
    label="abuse campaigns",
    list_key="campaigns",
    id_key="campaignId",
    filter_field="lastReportedTime",
    end_inclusive=True,
    list_method="get_a_list_of_campaigns_submitted_to_abuse_mailbox_request",
    builder=build_abuse_campaign_incident,
)
ACCOUNT_TAKEOVER_SPEC = FetchTypeSpec(
    key="account_takeover",
    label="account takeover cases",
    list_key="cases",
    id_key="caseId",
    filter_field="lastModifiedTime",
    end_inclusive=True,
    list_method="get_a_list_of_abnormal_cases_identified_by_abnormal_security_request",
    builder=build_account_takeover_case_incident,
    # Filtering on lastModifiedTime re-creates a case as a new incident every time it's modified,
    # resolved or reopened; createdTime emits each case once.
    mode_filter_fields={CASE_MODE_CREATED: "createdTime", CASE_MODE_MODIFIED: "lastModifiedTime"},
)
FETCH_TYPE_SPECS = (THREATS_SPEC, ABUSE_CAMPAIGNS_SPEC, ACCOUNT_TAKEOVER_SPEC)


def build_list_filter(spec: FetchTypeSpec, window: FetchWindow) -> str:
    field_name = spec.filter_field
    if spec.mode_filter_fields and window.mode:
        field_name = spec.mode_filter_fields[window.mode]
    start = format_timestamp(window.window_start)
    if spec.end_inclusive:
        end = (window.window_end - timedelta(microseconds=1)).strftime(TIME_FORMAT_WITHMS)
    else:
        end = format_timestamp(window.window_end)
    return f"{field_name} gte {start} and {field_name} lte {end}"


def migrate_last_run(
    last_run: dict[str, Any],
    first_fetch: datetime,
    now: datetime,
    polling_lag: timedelta,
    max_window: timedelta,
    enabled: dict[str, bool],
    case_mode: str = CASE_MODE_MODIFIED,
) -> tuple[dict[str, FetchWindow], int]:
    """Loads the per-type windows from `last_run`, upgrading the 2.4.9 `{"last_fetch": ...}` format.

    Returns:
        The windows by type key, and the rotation offset for the type order.
    """
    upper = floor_to_second(now - polling_lag)
    windows: dict[str, FetchWindow] = {}
    offset = 0
    if last_run.get("version") == LAST_RUN_VERSION:
        offset = int(last_run.get("type_order_offset", 0))
        windows = {spec.key: FetchWindow.from_dict(last_run[spec.key]) for spec in FETCH_TYPE_SPECS if spec.key in last_run}
    else:
        # 2.4.9's next run would have started at `last_fetch - polling_lag`, so starting there leaves no gap.
        if last_run.get("last_fetch"):
            start = floor_to_second(parse_timestamp(last_run["last_fetch"]) - polling_lag)
        else:
            start = floor_to_second(first_fetch)
        windows = {spec.key: FetchWindow.new(start, upper, max_window) for spec in FETCH_TYPE_SPECS if enabled[spec.key]}

    for spec in FETCH_TYPE_SPECS:
        mode = case_mode if spec.mode_filter_fields else None
        window = windows.get(spec.key)
        if not enabled[spec.key]:
            windows.pop(spec.key, None)
        elif window is None:
            # A newly enabled type starts at the current time, as 2.4.9 did, instead of replaying a backlog.
            windows[spec.key] = FetchWindow.new(upper, upper, max_window, mode=mode)
        elif mode is not None and (window.mode or CASE_MODE_MODIFIED) != mode:
            window.mode = mode
            window.restart(upper, max_window)
        else:
            window.mode = mode
            window.extend_if_empty(upper, max_window)
    return windows, offset


@dataclass
class FetchRun:
    """What every incident type shares during one fetch run."""

    client: Client
    deadline: Deadline
    upper: datetime
    max_window: timedelta
    concurrency: int
    max_page_number: int
    warnings: list[str] = field(default_factory=list)


def _list_page(run: FetchRun, spec: FetchTypeSpec, window: FetchWindow, page_number: int) -> dict:
    request = getattr(run.client, spec.list_method)
    return request(
        filter_=build_list_filter(spec, window), page_size=LIST_PAGE_SIZE, page_number=page_number, deadline=run.deadline
    )


def list_window_snapshot(run: FetchRun, spec: FetchTypeSpec, window: FetchWindow) -> list[dict]:
    """Lists every item in the window, halving the window until it fits in one page.

    A window that already has emitted or failed IDs is paginated instead of halved, since halving
    it would drop the record of what the next window has already emitted.
    """
    response = _list_page(run, spec, window, 1)
    while response.get("nextPageNumber") and window.is_untouched() and _span_seconds(window) >= 2:
        window.window_end = window.window_start + timedelta(seconds=_span_seconds(window) // 2)
        demisto.debug(f"Halved the {spec.label} window to end at {format_timestamp(window.window_end)}")
        response = _list_page(run, spec, window, 1)
    items = list(response.get(spec.list_key) or [])
    next_page = response.get("nextPageNumber")
    while next_page:
        if next_page > MAX_LIST_PAGES:
            raise DemistoException(f"Listing {spec.label} returned more than {MAX_LIST_PAGES} pages")
        response = _list_page(run, spec, window, next_page)
        items.extend(response.get(spec.list_key) or [])
        next_page = response.get("nextPageNumber")
    return items


def _span_seconds(window: FetchWindow) -> int:
    return int((window.window_end - window.window_start).total_seconds())


def _is_retention_error(e: Exception) -> bool:
    # The error message includes the response body, which names the retention range.
    return _status_code(e) == 400 and "retention" in str(e).lower()


def _run_stopping_error(e: Exception, deadline: Deadline) -> Exception | None:
    """Returns the error to stop the whole run with, or None if only this item or list call failed."""
    if isinstance(e, AuthError | RateLimitedError | BudgetExhaustedError):
        return e
    if deadline.expired():
        return BudgetExhaustedError()
    return None


def build_incidents(
    run: FetchRun, spec: FetchTypeSpec, items: list[dict], window: FetchWindow
) -> Generator[tuple[dict, dict | Exception | None], None, None]:
    """Yields `(item, incident_or_exception)` in list order, so the output doesn't depend on timing.

    Items not started because an earlier one stopped the run yield None. Workers share one `Client`,
    which is safe to use from several threads; only the caller updates the window.
    """
    stop = threading.Event()

    def build(item: dict) -> dict | Exception | None:
        if stop.is_set():
            return None
        if run.deadline.expired():
            stop.set()
            return BudgetExhaustedError()
        try:
            return spec.builder(run.client, item, window, deadline=run.deadline, max_page_number=run.max_page_number)
        except Exception as e:
            if _run_stopping_error(e, run.deadline) is not None:
                stop.set()
            return e

    executor = ThreadPoolExecutor(max_workers=run.concurrency)
    try:
        futures = [(item, executor.submit(build, item)) for item in items]
        for item, future in futures:
            yield item, future.result()
    finally:
        stop.set()
        executor.shutdown(wait=True, cancel_futures=True)


def _list_error_reason(run: FetchRun, spec: FetchTypeSpec, window: FetchWindow, e: Exception) -> str | None:
    """Handles a failed list call. Returns why the type stops, or None if the window was skipped instead."""
    if spec is THREATS_SPEC and _is_retention_error(e):
        run.warnings.append(
            f"Skipped {spec.label} from {format_timestamp(window.window_start)} to "
            f"{format_timestamp(window.window_end)}: outside the data retention period."
        )
        window.advance(run.upper, run.max_window)
        return None
    if _status_code(e) == 402:
        # Starting over at now each run means licensing the tenant later doesn't replay a backlog.
        window.window_start = run.upper
        window.restart(run.upper, run.max_window)
        run.warnings.append(f"Skipped {spec.label}: the tenant isn't licensed for them.")
        return "not_licensed"
    run.warnings.append(f"Listing {spec.label} failed; will retry next run: {e}")
    return "list_error"


def _build_batch(run: FetchRun, spec: FetchTypeSpec, window: FetchWindow, batch: list[dict], incidents: list[dict]) -> bool:
    """Turns `batch` into incidents and records each outcome in the window.

    Returns:
        False if the type stopped after too many failures in a row. A run-stopping error is raised
        after the incidents other workers already completed are kept.
    """
    consecutive_failures = 0
    stop_error: Exception | None = None
    results = build_incidents(run, spec, batch, window)
    for item, result in results:
        item_id = str(item[spec.id_key])
        if isinstance(result, dict):
            incidents.append(result)
            window.emitted_ids.append(item_id)
            window.failed.pop(item_id, None)
            consecutive_failures = 0
            continue
        if result is None:
            continue
        stop_error = stop_error or _run_stopping_error(result, run.deadline)
        if stop_error is not None:
            continue
        if isinstance(result, DemistoException) and _is_skippable_error(result):
            demisto.debug(f"{spec.label} item {item_id} returned a skippable error, skipping: {result}")
            window.emitted_ids.append(item_id)
            consecutive_failures = 0
            continue
        failures = window.failed.pop(item_id, 0) + 1
        if failures >= MAX_ITEM_FAILURES:
            run.warnings.append(f"Skipped {spec.label} item {item_id} after it failed on {failures} runs: {result}")
            window.emitted_ids.append(item_id)
        else:
            demisto.debug(f"{spec.label} item {item_id} failed (attempt {failures}), will retry: {result}")
            window.failed[item_id] = failures
        consecutive_failures += 1
        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            results.close()
            run.warnings.append(f"Stopped fetching {spec.label} after {consecutive_failures} failures in a row: {result}")
            return False
    if stop_error is not None:
        raise stop_error
    return True


def fetch_type(run: FetchRun, spec: FetchTypeSpec, window: FetchWindow, quota: int) -> tuple[list[dict], str]:
    """Turns the type's items into incidents, window by window, until something stops it.

    Returns:
        The incidents, and why the type stopped: `caught_up`, `max_fetch`, `budget`, `rate_limited`,
        `item_errors`, `errors`, `list_error` or `not_licensed`. An `AuthError` propagates.
    """
    incidents: list[dict] = []
    try:
        while not window.is_empty():
            if len(incidents) >= quota:
                return incidents, "max_fetch"
            try:
                items = list_window_snapshot(run, spec, window)
            except Exception as e:
                stop_error = _run_stopping_error(e, run.deadline)
                if stop_error is not None:
                    raise stop_error from e
                reason = _list_error_reason(run, spec, window, e)
                if reason is None:
                    continue
                return incidents, reason

            done = set(window.emitted_ids)
            pending = list({str(item[spec.id_key]): item for item in items if str(item[spec.id_key]) not in done}.values())
            batch = pending[: quota - len(incidents)]
            if not _build_batch(run, spec, window, batch, incidents):
                return incidents, "errors"
            if len(batch) < len(pending):
                return incidents, "max_fetch"
            if window.failed:
                return incidents, "item_errors"
            window.advance(run.upper, run.max_window)
    except BudgetExhaustedError:
        return incidents, "budget"
    except RateLimitedError as e:
        run.warnings.append(f"Rate limited while fetching {spec.label}; will resume next run: {e}")
        return incidents, "rate_limited"
    return incidents, "caught_up"


RUN_STOPPING_REASONS = {"budget", "rate_limited"}


def fetch_settings_from_params(params: dict[str, Any]) -> dict[str, Any]:
    """Reads the advanced fetch params. XSOAR doesn't add yml defaults to instances created before
    the params existed, so an unset param falls back to the code default, which matches the yml
    default."""

    def positive(name: str, default: float, cast: Callable[[Any], float]) -> Any:
        value = params.get(name)
        if value in (None, ""):
            return default
        try:
            number = cast(value)
        except ValueError as e:
            raise DemistoException(f"{name} must be a number, got {value}") from e
        if number <= 0:
            raise DemistoException(f"{name} must be greater than 0, got {value}")
        return number

    case_fetch_mode = params.get("case_fetch_mode") or "Last modified time"
    if case_fetch_mode not in CASE_FETCH_MODES:
        raise DemistoException(f"Unknown case fetch mode: {case_fetch_mode}. Use one of: {', '.join(CASE_FETCH_MODES)}")
    return {
        "fetch_time_budget": positive("fetch_time_budget", DEFAULT_FETCH_TIME_BUDGET_SECONDS, float),
        "max_window_minutes": positive("max_window_minutes", DEFAULT_MAX_WINDOW_MINUTES, int),
        "detail_concurrency": positive("detail_concurrency", DEFAULT_DETAIL_CONCURRENCY, int),
        "detail_rate_per_second": positive("detail_rate_per_second", DEFAULT_DETAIL_RATE_PER_SECOND, float),
        "case_fetch_mode": CASE_FETCH_MODES[case_fetch_mode],
    }


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
    fetch_time_budget: float = DEFAULT_FETCH_TIME_BUDGET_SECONDS,
    max_window_minutes: int = DEFAULT_MAX_WINDOW_MINUTES,
    detail_concurrency: int = DEFAULT_DETAIL_CONCURRENCY,
    detail_rate_per_second: float = DEFAULT_DETAIL_RATE_PER_SECOND,
    case_fetch_mode: str = CASE_MODE_MODIFIED,
    deadline: Deadline | None = None,
) -> tuple[dict[str, Any], list[dict], list[str]]:
    """
    Fetch incidents from threats, abuse campaigns and account takeover cases.

    Each type keeps its own resumable window in `last_run`, so a run that stops early (at
    `max_incidents_to_fetch`, at the time budget, or on errors) loses nothing. A 401 or 403 raises
    `AuthError`, and the caller commits nothing.

    Returns:
        The next `last_run`, the incidents, and warnings to show in the instance's health.
    """
    deadline = deadline or Deadline(fetch_time_budget)
    client.limit_rate(detail_rate_per_second)
    now = get_current_datetime()
    polling_lag = polling_lag or timedelta(0)
    max_window = timedelta(minutes=max_window_minutes)
    upper = floor_to_second(now - polling_lag)
    enabled = {
        THREATS_SPEC.key: bool(fetch_threats),
        ABUSE_CAMPAIGNS_SPEC.key: bool(fetch_abuse_campaigns),
        ACCOUNT_TAKEOVER_SPEC.key: bool(fetch_account_takeover_cases),
    }
    first_fetch = arg_to_datetime(first_fetch_time) or now
    if first_fetch.tzinfo is None:
        first_fetch = first_fetch.replace(tzinfo=timezone.utc)
    windows, offset = migrate_last_run(last_run, first_fetch, now, polling_lag, max_window, enabled, case_fetch_mode)

    specs = [spec for spec in FETCH_TYPE_SPECS if enabled[spec.key]]
    if specs:
        rotation = offset % len(specs)
        specs = specs[rotation:] + specs[:rotation]

    run = FetchRun(client, deadline, upper, max_window, detail_concurrency, max_page_number)
    incidents: list[dict] = []
    summary: dict[str, Any] = {}
    for spec in specs:
        quota = max_incidents_to_fetch - len(incidents)
        if quota <= 0:
            break
        type_incidents, reason = fetch_type(run, spec, windows[spec.key], quota)
        incidents.extend(type_incidents)
        summary[spec.key] = {"emitted": len(type_incidents), "stop_reason": reason}
        if reason in RUN_STOPPING_REASONS:
            break
    demisto.debug(f"AbnormalSecurity fetch summary: {json.dumps(summary)}")

    next_run: dict[str, Any] = {
        "version": LAST_RUN_VERSION,
        "type_order_offset": offset + 1,
        **{key: window.to_dict() for key, window in windows.items()},
    }
    starts = [window.window_start for window in windows.values()]
    # 2.4.9 only reads `last_fetch`, so writing the oldest window start lets a rollback resume without a gap.
    next_run["last_fetch"] = format_timestamp(min(starts) if starts else upper)
    return next_run, incidents, run.warnings


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
            # SOAR Message Search and Respond commands
            "abnormal-security-search-messages": search_messages_command,
            "abnormal-security-remediate-messages": remediate_messages_command,
            "abnormal-security-list-activities": get_activities_list_command,
            "abnormal-security-get-activity-status": get_activity_status_command,
            "abnormal-security-download-message-attachment": download_message_attachment_command,
            "abnormal-security-download-message-eml": download_message_eml_command,
        }

        if command == "test-module":  # pragma: no cover
            headers["Mock-Data"] = "True"
            test_client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers, auth=None)
            test_module(test_client)
        elif command == "fetch-incidents" and is_fetch:  # pragma: no cover
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
            # An AuthError reaches return_error below, so the instance shows as errored and nothing is committed.
            next_run, incidents, warnings = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                max_incidents_to_fetch=max_incidents_to_fetch or FETCH_LIMIT,
                fetch_threats=fetch_threats,
                fetch_abuse_campaigns=fetch_abuse_campaigns,
                fetch_account_takeover_cases=fetch_account_takeover_cases,
                max_page_number=max_page_number,
                polling_lag=polling_lag_delta,
                **fetch_settings_from_params(params),
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            if warnings:
                demisto.updateModuleHealth("; ".join(warnings))
        elif command in commands:
            return_results(commands[command](client, args))  # type: ignore
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
