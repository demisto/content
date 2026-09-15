import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime, timedelta
from typing import Any
import dateparser
import json
import requests


class Client(BaseClient):
    def __init__(self, base_url: str, api_key: str, verify: bool):
        headers = {
            "X-Auth-Token": api_key,
            "Content-Type": "application/json",
        }
        super().__init__(base_url=base_url, verify=verify, headers=headers)

    def get_issues(
        self,
        tenant: str,
        since: str,
        until: str,
        limit: int = 50,
        page: int = 1,
        status: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "tenant": tenant,
            "since": since,
            "until": until,
            "page": page,
            "limit": limit,
        }
        if status:
            params["alert_status"] = status

        return self._http_request(
            method="POST",
            url_suffix="/issues",
            params=params,
            json_data={},
        )

    def get_categories(self, tenant: str) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/categories",
            params={"tenant": tenant},
        )

    def get_issue_by_id(self, tenant: str, ticket_id: str) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/issues/{ticket_id}",
            params={"tenant": tenant},
        )

    def assign_issue(
        self,
        tenant: str,
        ticket_id: str,
        user_email: str,
        assignee_email: str,
    ) -> dict[str, Any]:
        params = {
            "tenant": tenant,
            "ticket_id": ticket_id,
            "user_email": user_email,
        }
        data = {"assignees": [assignee_email]}
        return self._http_request(
            method="PUT",
            url_suffix="/issues/update",
            params=params,
            json_data=data,
        )

    def add_comment(
        self,
        tenant: str,
        ticket_id: str,
        user_email: str,
        status_reason: str,
    ) -> dict[str, Any]:
        params = {
            "tenant": tenant,
            "ticket_id": ticket_id,
            "user_email": user_email,
            "status_reason": status_reason,
        }
        return self._http_request(
            method="PUT",
            url_suffix="/issues/update",
            params=params,
            json_data={},
        )

    def update_severity(
        self,
        tenant: str,
        ticket_id: str,
        user_email: str,
        severity: str,
    ) -> dict[str, Any]:
        params = {
            "tenant": tenant,
            "ticket_id": ticket_id,
            "user_email": user_email,
            "severity": severity,
        }
        return self._http_request(
            method="PUT",
            url_suffix="/issues/update",
            params=params,
            json_data={},
        )

    def download_attachment_url(self, url: str) -> bytes:
        response = requests.get(url, verify=self._verify, timeout=30)
        response.raise_for_status()
        return response.content

    def approve_or_dismiss_issue(
        self,
        tenant: str,
        ticket_id: str,
        user_email: str,
        approve: bool,
    ) -> dict[str, Any]:
        params = {
            "tenant": tenant,
            "ticket_id": ticket_id,
            "user_email": user_email,
            "approve": str(approve).lower(),
        }
        return self._http_request(
            method="POST",
            url_suffix="/issues/approve",
            params=params,
        )


def test_module_command(client: Client, tenant: str) -> str:
    response = client.get_categories(tenant)
    if response.get("status") is True:
        return "ok"
    raise DemistoException("Test failed: Unexpected response.")


def assign_incident_command(client: Client, args: dict[str, Any], tenant: str) -> str:
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")

    if not isinstance(ticket_id, str) or not ticket_id:
        raise DemistoException("ticket_id is required and must be a string")
    if not isinstance(user_email, str) or not user_email:
        raise DemistoException("user_email is required and must be a string")

    response = client.assign_issue(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        assignee_email=user_email,
    )

    if response.get("status") is True:
        return f"Issue `{ticket_id}` was successfully assigned to `{user_email}`"

    raise DemistoException(f"Failed to assign issue: {response.get('msg')}")


def add_comment_command(client: Client, args: dict[str, Any], tenant: str) -> str:
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")
    status_reason = args.get("status_reason")

    if not isinstance(ticket_id, str) or not ticket_id:
        raise DemistoException("ticket_id is required and must be a string")
    if not isinstance(user_email, str) or not user_email:
        raise DemistoException("user_email is required and must be a string")
    if not isinstance(status_reason, str) or not status_reason:
        raise DemistoException("status_reason is required and must be a string")

    response = client.add_comment(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        status_reason=status_reason,
    )

    if response.get("status") is True:
        return f"Comment added to issue `{ticket_id}` by `{user_email}`"

    raise DemistoException(f"Failed to add comment: {response.get('msg')}")


def update_severity_command(client: Client, args: dict[str, Any], tenant: str) -> str:
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")
    severity = args.get("severity")

    if not isinstance(ticket_id, str) or not ticket_id:
        raise DemistoException("ticket_id is required and must be a string")
    if not isinstance(user_email, str) or not user_email:
        raise DemistoException("user_email is required and must be a string")
    if not isinstance(severity, str) or not severity:
        raise DemistoException("severity is required and must be a string")

    response = client.update_severity(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        severity=severity,
    )

    if response.get("status") is True:
        return f"Issue `{ticket_id}` severity updated to `{severity}`"

    raise DemistoException(f"Failed to update severity: {response.get('msg')}")


def download_attachment_command(client: Client, args: dict[str, Any], tenant: str) -> None:
    ticket_id = args.get("ticket_id")
    if not isinstance(ticket_id, str) or not ticket_id:
        raise DemistoException("ticket_id is required and must be a string")

    issue_resp = client.get_issue_by_id(tenant=tenant, ticket_id=ticket_id)
    attachments = issue_resp.get("data", {}).get("attachments", [])

    if not attachments:
        return_results(f"No attachments found for issue `{ticket_id}`")
        return

    results: list[Any] = []
    for attachment in attachments:
        url = attachment.get("name")
        if not isinstance(url, str) or not url:
            continue

        content = client.download_attachment_url(url)
        filename = url.split("/")[-1] or f"{ticket_id}_attachment"
        results.append(fileResult(filename, content))

    return_results(results)


def get_incident_command(client: Client, args: dict[str, Any], tenant: str):
    ticket_id = args.get("ticket_id")
    if not isinstance(ticket_id, str) or not ticket_id:
        raise DemistoException("ticket_id is required and must be a string")

    response = client.get_issue_by_id(tenant=tenant, ticket_id=ticket_id)
    data = response.get("data", {})
    return fileResult(f"incident_{ticket_id}.json", json.dumps(data, indent=2))


def approve_or_dismiss_issue_command(
    client: Client,
    args: dict[str, Any],
    tenant: str,
) -> str:
    ticket_id = args.get("ticket_id")
    user_email = args.get("user_email")
    approve_str = args.get("approve")

    if not isinstance(ticket_id, str) or not ticket_id:
        raise DemistoException("ticket_id is required and must be a string")
    if not isinstance(user_email, str) or not user_email:
        raise DemistoException("user_email is required and must be a string")
    if not isinstance(approve_str, str):
        raise DemistoException("approve must be 'true' or 'false'")

    approve_lower = approve_str.lower()
    if approve_lower not in ("true", "false"):
        raise DemistoException("approve must be 'true' or 'false'")

    approve = approve_lower == "true"

    response = client.approve_or_dismiss_issue(
        tenant=tenant,
        ticket_id=ticket_id,
        user_email=user_email,
        approve=approve,
    )

    action = "approved" if approve else "dismissed"
    if response.get("status") is True:
        return f"Issue `{ticket_id}` successfully {action}"

    raise DemistoException(f"Failed to approve/dismiss issue: {response.get('msg')}")


def fetch_incidents(
    client: Client,
    last_run: dict[str, Any],
    first_fetch: str,
    tenant: str,
    max_fetch: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    last_fetch_time = last_run.get("last_fetch_time")

    if not last_fetch_time:
        parsed_time = dateparser.parse(first_fetch)
        if not parsed_time:
            raise DemistoException(f"Could not parse first_fetch: {first_fetch}")
        last_fetch_time = parsed_time.replace(microsecond=0).isoformat() + "Z"

    until_time = (datetime.utcnow() - timedelta(seconds=5)).replace(microsecond=0).isoformat() + "Z"

    incidents: list[dict[str, Any]] = []
    page = 1
    buffer_ticket_ids = set(last_run.get("buffer_ticket_ids", []))

    while len(incidents) < max_fetch:
        response = client.get_issues(
            tenant=tenant,
            since=last_fetch_time,
            until=until_time,
            page=page,
            limit=50,
        )

        issues = response.get("data", {}).get("issues", [])
        if not issues:
            break

        for issue in issues:
            ticket_id = issue.get("ticket_id")
            created_at = issue.get("created_at") or until_time
            if not created_at.endswith("Z"):
                created_at += "Z"

            if created_at == last_fetch_time and ticket_id in buffer_ticket_ids:
                continue

            incidents.append(
                {
                    "name": f"Cypho Issue {ticket_id} - {issue.get('title')}",
                    "occurred": created_at,
                    "rawJSON": json.dumps(issue),
                }
            )

        if len(issues) < 50:
            break
        page += 1

    incidents.sort(key=lambda x: x["occurred"])
    max_created_at = incidents[-1]["occurred"] if incidents else last_fetch_time

    new_buffer_ticket_ids = list(
        {json.loads(i["rawJSON"]).get("ticket_id") for i in incidents if i["occurred"] == max_created_at}
    )

    return incidents, {
        "last_fetch_time": max_created_at,
        "buffer_ticket_ids": new_buffer_ticket_ids,
    }


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
            incidents, next_run = fetch_incidents(
                client,
                last_run,
                first_fetch,
                tenant,
                max_fetch,
            )
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
            download_attachment_command(client, demisto.args(), tenant)

        elif command == "cypho-approve-dismiss-issue":
            return_results(approve_or_dismiss_issue_command(client, demisto.args(), tenant))

        else:
            return_error(f"Unknown command: {command}")

    except Exception as e:
        return_error(f"Cypho Integration Error: {str(e)}", error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
