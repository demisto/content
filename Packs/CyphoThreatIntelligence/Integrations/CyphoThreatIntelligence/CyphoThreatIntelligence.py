import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime
import dateparser
import json
import requests


class Client(BaseClient):
    def __init__(self, base_url: str, api_key: str, verify: bool):
        headers = {"X-Auth-Token": api_key, "Content-Type": "application/json"}
        super().__init__(base_url=base_url, verify=verify, headers=headers)

    def get_issues(self, tenant: str, since: str, until: str, limit: int = 50, page: int = 1, status: str = None) -> dict:
        params = {"tenant": tenant, "since": since, "until": until, "page": page, "limit": limit}
        if status:
            params["alert_status"] = status
        return self._http_request(method="POST", url_suffix="/issues", params=params, json_data={})

    def get_categories(self, tenant: str) -> dict:
        return self._http_request(method="GET", url_suffix="/categories", params={"tenant": tenant})

    def get_issue_by_id(self, tenant: str, ticket_id: str) -> dict:
        return self._http_request(method="GET", url_suffix=f"/issues/{ticket_id}", params={"tenant": tenant})

    def assign_issue(self, tenant: str, ticket_id: str, user_email: str, assignee_email: str) -> dict:
        data = {"assignees": [assignee_email]}
        params = {"tenant": tenant, "ticket_id": ticket_id, "user_email": user_email}
        return self._http_request(method="PUT", url_suffix="/issues/update", params=params, json_data=data)

    def add_comment(self, tenant: str, ticket_id: str, user_email: str, status_reason: str) -> dict:
        params = {"tenant": tenant, "ticket_id": ticket_id, "user_email": user_email, "status_reason": status_reason}
        return self._http_request(method="PUT", url_suffix="/issues/update", params=params, json_data={})

    def update_severity(self, tenant: str, ticket_id: str, user_email: str, severity: str) -> dict:
        params = {"tenant": tenant, "ticket_id": ticket_id, "user_email": user_email, "severity": severity}
        return self._http_request(method="PUT", url_suffix="/issues/update", params=params, json_data={})

    def download_attachment_url(self, url: str) -> bytes:
        resp = requests.get(url, verify=self._verify)
        resp.raise_for_status()
        return resp.content

    def approve_or_dismiss_issue(self, tenant: str, ticket_id: str, user_email: str, approve: bool) -> dict:
        params = {"tenant": tenant, "ticket_id": ticket_id, "user_email": user_email, "approve": str(approve).lower()}
        return self._http_request(method="POST", url_suffix="/issues/approve", params=params)


def test_module_command(client: Client, tenant: str) -> str:
    response = client.get_categories(tenant)
    if response.get("status") is True:
        return "ok"
    raise DemistoException("Test failed: Unexpected response or status is not true.")


def assign_incident_command(client: Client, args: dict, tenant: str):
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")

    if not all([ticket_id, user_email]):
        raise DemistoException("Required arguments: 'ticket_id' and 'user_email'.")

    response = client.assign_issue(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        assignee_email=user_email
    )

    if response.get("status") is True:
        return f"Issue `{ticket_id}` was successfully assigned to `{user_email}`."
    else:
        raise DemistoException(f"Failed to assign issue. Message: {response.get('msg')}")


def add_comment_command(client: Client, args: dict, tenant: str):
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")
    status_reason = args.get("status_reason")

    if not all([ticket_id, user_email, status_reason]):
        raise DemistoException("Required arguments: 'ticket_id', 'user_email', and 'status_reason'.")

    response = client.add_comment(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        status_reason=status_reason
    )

    if response.get("status") is True:
        return f"Comment added to issue `{ticket_id}` by `{user_email}`."
    else:
        raise DemistoException(f"Failed to add comment: {response.get('msg')}")


def update_severity_command(client: Client, args: dict, tenant: str):
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")
    severity = args.get("severity")

    if not all([ticket_id, user_email, severity]):
        raise DemistoException("Missing required arguments: 'ticket_id', 'user_email', and 'severity'.")

    response = client.update_severity(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        severity=severity
    )

    if response.get("status") is True:
        return f"Issue `{ticket_id}` severity successfully updated to `{severity}` by `{user_email}`."
    else:
        raise DemistoException(f"Failed to update severity: {response.get('msg')}")


def download_attachment_command(client: Client, args: dict, tenant: str):
    ticket_id = args.get("ticket_id")
    if not ticket_id:
        raise DemistoException("Missing required argument: 'ticket_id'.")

    try:
        issue_resp = client.get_issue_by_id(tenant=tenant, ticket_id=ticket_id)
        issue_data = issue_resp.get("data", {})
        attachments = issue_data.get("attachments", [])
    except Exception as e:
        return_results(f"Failed to retrieve issue '{ticket_id}': {str(e)}")
        return

    if not attachments:
        return_results(f"No attachments found for issue '{ticket_id}'.")
        return

    file_results = []
    success_count = 0
    failed_downloads = []

    for attachment in attachments:
        url = attachment.get("name")
        if not url:
            demisto.debug(f"Attachment entry missing 'name': {attachment}")
            continue

        try:
            content = client.download_attachment_url(url)
            filename = url.split("/")[-1] or f"{ticket_id}_attachment"
            file_results.append(fileResult(filename, content))
            success_count += 1
        except Exception as e:
            demisto.error(f"Failed to download attachment from '{url}': {str(e)}")
            failed_downloads.append(url)

    if file_results:
        message = f"Successfully downloaded {success_count} attachment(s) for issue '{ticket_id}'."
        if failed_downloads:
            message += f"\nFailed to download {len(failed_downloads)} attachment(s)."
        results = [CommandResults(readable_output=message)] + file_results
        return_results(results)
    else:
        return_results(f"Failed to download any attachments for issue '{ticket_id}'.")


def get_incident_command(client: Client, args: dict, tenant: str):
    ticket_id = args.get("ticket_id")
    if not ticket_id:
        raise DemistoException("The argument 'ticket_id' is required.")

    try:
        demisto.debug(f"[Cypho Debug] Fetching incident with ticket_id={ticket_id}")
        response = client.get_issue_by_id(tenant=tenant, ticket_id=ticket_id)
    except Exception as e:
        raise DemistoException(f"Failed to fetch incident with ticket_id '{ticket_id}': {str(e)}")

    data = response.get("data", {})
    json_str = json.dumps(data, indent=2)
    file_name = f"incident_{ticket_id}.json"
    return fileResult(file_name, json_str)


def approve_or_dismiss_issue_command(client: Client, args: dict, tenant: str):
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")
    approve_str = args.get("approve")

    if not all([ticket_id, user_email, approve_str]):
        raise DemistoException("Required arguments: 'ticket_id', 'user_email', and 'approve'.")

    approve_str_lower = approve_str.lower()
    if approve_str_lower not in ("true", "false"):
        raise DemistoException("The 'approve' argument must be 'true' or 'false'.")

    approve = approve_str_lower == "true"

    response = client.approve_or_dismiss_issue(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        approve=approve
    )

    if response.get("status") is True:
        action = "approved" if approve else "dismissed"
        return f"Issue `{ticket_id}` successfully {action}."
    else:
        raise DemistoException(f"Failed to approve/dismiss issue: {response.get('msg')}")


def fetch_incidents(client: Client, last_run: dict, first_fetch: str, tenant: str, max_fetch: int) -> tuple[list, dict]:
    last_fetch_time = last_run.get("last_fetch_time")
    if not last_fetch_time:
        last_fetch_time = dateparser.parse(first_fetch).replace(microsecond=0).isoformat() + "Z"

    until_time = (datetime.utcnow() - timedelta(seconds=5)).replace(microsecond=0).isoformat() + "Z"

    page = 1
    incidents = []
    buffer_ticket_ids = set(last_run.get("buffer_ticket_ids", []))

    while len(incidents) < max_fetch:
        response = client.get_issues(
            tenant=tenant,
            since=last_fetch_time,
            until=until_time,
            limit=50,
            page=page
        )

        issues = response.get("data", {}).get("issues", [])
        if not issues:
            break

        for issue in issues:
            ticket_id = issue.get("ticket_id")
            created_at = issue.get("created_at") or until_time
            if not created_at.endswith("Z"):
                created_at += "Z"

            # Avoid duplicates with same timestamp
            if created_at == last_fetch_time and ticket_id in buffer_ticket_ids:
                continue

            incidents.append({
                "name": f"Cypho Issue {ticket_id} - {issue.get('title')}",
                "occurred": created_at,
                "rawJSON": json.dumps(issue)
            })

        if len(issues) < 50:
            break
        page += 1

    incidents.sort(key=lambda x: x["occurred"])

    max_created_at = last_fetch_time
    if incidents:
        max_created_at = incidents[-1]["occurred"]

    # Update buffer ticket IDs safely
    new_buffer_ticket_ids = list(
        buffer_ticket_ids.union({
            json.loads(incident["rawJSON"]).get("ticket_id")
            for incident in incidents
            if incident["occurred"] == max_created_at
        })
    )

    next_run = {
        "last_fetch_time": max_created_at,
        "buffer_ticket_ids": new_buffer_ticket_ids
    }

    return incidents, next_run


def main():
    params = demisto.params()
    base_url = params.get("url")
    tenant = params.get("tenant", "")
    first_fetch = params.get("first_fetch", "3 days ago")
    max_fetch = int(params.get("max_fetch", 50))
    api_key = params.get("apikey", {}).get("password") if isinstance(params.get("apikey"), dict) else params.get("apikey")
    insecure = params.get("insecure", False)

    client = Client(base_url=base_url, api_key=api_key, verify=not insecure)
    command = demisto.command()

    try:
        if command == "test-module":
            return_results(test_module_command(client, tenant))

        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, last_run, first_fetch, tenant, max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "cypho-get-incident":
            return_results(get_incident_command(client, demisto.args(), tenant))

        elif command == "cypho-assign-incident":
            return_results(assign_incident_command(client, demisto.args(), tenant))

        elif command == "cypho-add-comment":
            return_results(add_comment_command(client, demisto.args(), tenant))

        elif command == "cypho-update-severity":
            return_results(update_severity_command(client, demisto.args(), tenant))

        elif command == "cypho-download-attachment":
            return_results(download_attachment_command(client, demisto.args(), tenant))

        elif command == "cypho-approve-dismiss-issue":
            return_results(approve_or_dismiss_issue_command(client, demisto.args(), tenant))

        else:
            return_error(f"Unknown command: {command}")

    except Exception as e:
        return_error(f"Cypho Integration Error: {str(e)}", error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
