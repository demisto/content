from typing import Any
import urllib3
from CommonServerPython import *

urllib3.disable_warnings()

allowed_reason_values_str = (
    "phishing, brand_abuse, impersonating_application, unofficial_application_distribution, "
    "malicious_content, social_media_impersonation, social_media_employee_impersonation, "
    "fake_job_post, sensitive_file_on_antivirus_repository, instant_messaging_impersonation, other"
)


class Client(BaseClient):
    """
    Client to use in the Cyberint Takedown integration.
    """

    def __init__(
        self,
        base_url: str,
        access_token: str,
        verify: bool = False,
        proxy: bool = False,
    ):
        params = demisto.params()
        self._cookies = {"access_token": access_token}
        self._headers = {
            "X-Integration-Type": "XSOAR",
            "X-Integration-Instance-Name": demisto.integrationInstance(),
            "X-Integration-Instance-Id": "",
            "X-Integration-Customer-Name": params.get("client_name", ""),
            "X-Integration-Version": "1.1.9",
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    @logger
    def submit_takedown_request(
        self,
        customer: str | None,
        reason: str | None,
        url: str | None,
        brand: str | None,
        original_url: str | None,
        alert_id: int | None,
        note: str | None,
    ) -> dict:
        """
        Retrieve a list of alerts according to parameters.

        Args:
            url (str): Index of page to return.

        Returns:
            response (Response): API response from Cyberint.
        """
        body = {
            "customer": customer,
            "reason": reason,
            "url": url,
            "brand": brand,
            "original_url": original_url,
            "alert_id": alert_id,
            "note": note,
        }
        body = remove_empty_elements(body)
        response = self._http_request(method="POST", json_data=body, cookies=self._cookies, url_suffix="takedown/api/v1/submit")
        return response

    @logger
    def retrieve_takedown_requests(
        self,
        customer_id: str | None = None,
        action: str | None = None,
        alert_id: int | None = None,
        alert_ref_id: str | None = None,
        blocked_date: str | None = None,
        sent_date: str | None = None,
        brand: str | None = None,
        created_date: str | None = None,
        customer: str | None = None,
        domain: str | None = None,
        email_ticket_id: str | None = None,
        hostname: str | None = None,
        id: str | None = None,
        last_action_date: str | None = None,
        last_email_date: str | None = None,
        last_monitored_date: str | None = None,
        last_seen_date: str | None = None,
        last_submit_date: str | None = None,
        metadata_date: str | None = None,
        reason: str | None = None,
        requested_by: str | None = None,
        status: str | None = None,
        url: str | None = None,
    ) -> dict:
        """
        Retrieve a list of alerts according to parameters.

        Args:
            Various filter parameters.

        Returns:
            response (dict): API response from Cyberint.
        """
        filters = {
            "actions": {"action": action} if action else None,
            "alert_id": alert_id,
            "alert_ref_id": alert_ref_id,
            "blocklist_requests": {"blocked_date": blocked_date, "sent_date": sent_date} if blocked_date or sent_date else None,
            "brand": brand,
            "created_date": created_date,
            "customer": customer,
            "domain": domain,
            "email_ticket_id": email_ticket_id,
            "hostname": hostname,
            "id": id,
            "last_action_date": last_action_date,
            "last_email_date": last_email_date,
            "last_monitored_date": last_monitored_date,
            "last_seen_date": last_seen_date,
            "last_submit_date": last_submit_date,
            "metadata": {"date": metadata_date} if metadata_date else None,
            "reason": reason,
            "requested_by": requested_by,
            "status": status,
            "url": url,
        }

        body = {
            "customer_id": customer_id,
            "filters": remove_empty_elements(filters),
        }

        response = self._http_request(method="POST", json_data=body, cookies=self._cookies, url_suffix="takedown/api/v1/request")
        return response


def test_module(client):
    """Test module for Cyberint integration."""
    try:
        client.retrieve_takedown_requests(customer_id="Cyberint", url="https://cyberint.com")
        return "ok"
    except DemistoException as exc:
        error_msg = str(exc)

        if "[403] - Forbidden" in error_msg:
            return "ok"
        elif "[401] - Unauthorized" in error_msg:
            raise DemistoException("Authentication failed: Invalid API token")
        else:
            # Re-raise the original exception for all other cases
            raise exc


def submit_takedown_request_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Submits a takedown request and formats the output.

    Args:
        client: Cyberint API Client.
        args: Command arguments.

    Returns:
        CommandResults: Formatted takedown request.
    """
    # Define allowed reason values
    allowed_reasons = [
        "phishing",
        "brand_abuse",
        "impersonating_application",
        "unofficial_application_distribution",
        "malicious_content",
        "social_media_impersonation",
        "social_media_employee_impersonation",
        "fake_job_post",
        "sensitive_file_on_antivirus_repository",
        "instant_messaging_impersonation",
        "other",
    ]

    # Validate reason value
    reason = args.get("reason")
    if reason:
        reason = reason.lower()
        if reason and reason not in allowed_reasons:
            errormsg = f"Invalid reason provided: {reason}. Allowed values are: {allowed_reason_values_str}"
            demisto.error(errormsg)
            raise DemistoException(errormsg)

    response = client.submit_takedown_request(
        customer=args.get("customer"),
        reason=reason,
        url=args.get("url"),
        brand=args.get("brand"),
        original_url=args.get("original_url"),
        alert_id=args.get("alert_id"),
        note=args.get("note"),
    )

    data = response.get("data", {})
    takedown_request = data.get("takedown_request", {})

    formatted_request = [
        {
            "reason": takedown_request.get("reason"),
            "url": takedown_request.get("url"),
            "original_url": takedown_request.get("original_url"),
            "customer": takedown_request.get("customer"),
            "status": takedown_request.get("status"),
            "brand": takedown_request.get("brand"),
            "alert_ref_id": takedown_request.get("alert_ref_id"),
            "alert_id": takedown_request.get("alert_id"),
            "hosting_providers": takedown_request.get("hosting_providers"),
            "name_servers": takedown_request.get("name_servers"),
            "escalation_actions": takedown_request.get("escalation_actions"),
            "last_escalation_date": takedown_request.get("last_escalation_date"),
            "last_status_change_date": takedown_request.get("last_status_change_date"),
            "last_seen_date": takedown_request.get("last_seen_date"),
            "created_date": takedown_request.get("created_date"),
            "status_reason": takedown_request.get("status_reason"),
            "id": takedown_request.get("id"),
        }
    ]

    human_readable = tableToMarkdown(
        "Takedown Request",
        formatted_request,
        headers=[
            "reason",
            "url",
            "original_url",
            "customer",
            "status",
            "brand",
            "alert_ref_id",
            "alert_id",
            "hosting_providers",
            "name_servers",
            "escalation_actions",
            "last_escalation_date",
            "last_status_change_date",
            "last_seen_date",
            "created_date",
            "status_reason",
            "id",
        ],
        headerTransform=takedown_response_header_transformer,
        removeNull=True,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Cyberint.takedowns_submit",
        outputs_key_field="id",
        raw_response=takedown_request,
        outputs=takedown_request,
    )


def retrieve_takedown_requests_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Retrieves takedown requests and formats the output.

    Args:
        client: Cyberint API Client.
        args: Command arguments.

    Returns:
        CommandResults: Formatted takedown requests.
    """
    # Define allowed reason values
    allowed_reasons = [
        "phishing",
        "brand_abuse",
        "impersonating_application",
        "unofficial_application_distribution",
        "malicious_content",
        "social_media_impersonation",
        "social_media_employee_impersonation",
        "fake_job_post",
        "sensitive_file_on_antivirus_repository",
        "instant_messaging_impersonation",
        "other",
    ]

    # Validate reason value
    reason = args.get("reason")
    if reason:
        reason = reason.lower()
        if reason and reason not in allowed_reasons:
            errormsg = f"Invalid reason provided: {reason}. Allowed values are: {allowed_reason_values_str}"
            demisto.error(errormsg)
            raise DemistoException(errormsg)

    response = client.retrieve_takedown_requests(**args)
    data = response.get("data", {})
    takedown_requests = data.get("takedown_requests", [])

    formatted_requests = [
        {
            "reason": reason,
            "url": req.get("url"),
            "original_url": req.get("original_url"),
            "customer": req.get("customer"),
            "status": req.get("status"),
            "brand": req.get("brand"),
            "alert_ref_id": req.get("alert_ref_id"),
            "alert_id": req.get("alert_id"),
            "hosting_providers": req.get("hosting_providers"),
            "name_servers": req.get("name_servers"),
            "escalation_actions": req.get("escalation_actions"),
            "last_escalation_date": req.get("last_escalation_date"),
            "last_status_change_date": req.get("last_status_change_date"),
            "last_seen_date": req.get("last_seen_date"),
            "created_date": req.get("created_date"),
            "status_reason": req.get("status_reason"),
            "id": req.get("id"),
        }
        for req in takedown_requests
    ]

    human_readable = tableToMarkdown(
        "Takedown Requests",
        formatted_requests,
        headers=[
            "reason",
            "url",
            "original_url",
            "customer",
            "status",
            "brand",
            "alert_ref_id",
            "alert_id",
            "hosting_providers",
            "name_servers",
            "escalation_actions",
            "last_escalation_date",
            "last_status_change_date",
            "last_seen_date",
            "created_date",
            "status_reason",
            "id",
        ],
        headerTransform=takedown_response_header_transformer,
        removeNull=False,
    )

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="Cyberint.takedowns_list",
        outputs_key_field="id",
        raw_response=takedown_requests,
        outputs=takedown_requests,
    )


@logger
def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()

    base_url = params.get("url")
    access_token = params.get("access_token").get("password")
    insecure = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            access_token=access_token,
            verify=insecure,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "cyberint-takedown-url":
            return_results(submit_takedown_request_command(client, args))

        elif command == "cyberint-retrieve-takedowns":
            return_results(retrieve_takedown_requests_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


def takedown_response_header_transformer(header: str) -> str:
    """
    Returns a correct header.
    Args:
        header (Str): header.
    Returns:
        header (Str).
    """
    if header == "customer_id":
        return "Customer ID"
    if header == "actions":
        return "Actions"
    if header == "alert_id":
        return "Alert ID"
    if header == "alert_ref_id":
        return "Alert Ref ID"
    if header == "blocked_date":
        return "Blocklist Blocked Date"
    if header == "sent_date":
        return "Blocklist Sent Date"
    if header == "brand":
        return "Brand"
    if header == "created_date":
        return "Created Date"
    if header == "customer":
        return "Customer"
    if header == "domain":
        return "Domain"
    if header == "email_ticket_id":
        return "Email Ticket ID"
    if header == "hostname":
        return "Hostname"
    if header == "id":
        return "ID"
    if header == "last_action_date":
        return "Last Action Date"
    if header == "last_email_date":
        return "Last Email Date"
    if header == "last_monitored_date":
        return "Last Monitored Date"
    if header == "last_seen_date":
        return "Last Seen Date"
    if header == "last_submit_date":
        return "Last Submit Date"
    if header == "metadata":
        return "Metadata"
    if header == "reason":
        return "Reason"
    if header == "requested_by":
        return "Requested By"
    if header == "status":
        return "Status"
    if header == "url":
        return "URL"
    return string_to_table_header(header)


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
