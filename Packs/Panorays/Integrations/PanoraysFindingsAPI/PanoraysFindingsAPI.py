import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import json
from typing import Any

urllib3.disable_warnings()


class Client(BaseClient):
    def get_company_findings(self, limit: int, page: int) -> dict[str, Any]:
        params = {"limit": limit, "page": page}
        return self._http_request(method="GET", url_suffix="/v2/findings", params=params)


def verify_module(client: Client) -> str:
    try:
        client._http_request("GET", "/v2/findings", params={"limit": 1})
        return "ok"
    except Exception as e:
        if "Unauthorized" in str(e) or "Forbidden" in str(e):
            raise Exception("Authorization Error: check your API Key.") from e
        raise e


def finding_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = int(args.get("limit") or 50)
    page = int(args.get("page") or 1)
    raw_response = client.get_company_findings(limit=limit, page=page)
    findings = raw_response.get("data", [])

    markdown_data = []
    for finding in findings:
        markdown_data.append(
            {
                "Finding ID": finding.get("id"),
                "Category": finding.get("category"),
                "Affected Asset": finding.get("asset_name"),
                "Risk Level": finding.get("severity"),
                "State": finding.get("status"),
            }
        )

    markdown = tableToMarkdown(f"Panorays Findings (Page {page})", markdown_data, removeNull=True)
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Panorays.Finding",
        outputs_key_field="id",
        outputs=findings,
        raw_response=raw_response,
    )


def fetch_incidents_command(client: Client, last_run: dict, first_fetch_time: str, max_fetch: int) -> tuple[dict, list[dict]]:
    last_fetch = last_run.get("last_fetch")
    if last_fetch:
        last_fetch_time = arg_to_datetime(last_fetch)
    else:
        last_fetch_time = arg_to_datetime(first_fetch_time)

    raw_response = client.get_company_findings(limit=max_fetch, page=1)
    findings = raw_response.get("data", [])

    incidents = []
    latest_created_time = last_fetch_time

    for finding in findings:
        finding_time = arg_to_datetime(finding.get("insert_ts"))

        if last_fetch_time and finding_time and finding_time <= last_fetch_time:
            continue

        incidents.append(
            {
                "name": f"Panorays Finding: {finding.get('asset_name', 'Unknown')}",
                "details": finding.get("finding_text", ""),
                "occurred": finding.get("insert_ts"),
                "rawJSON": json.dumps(finding),
            }
        )

        if finding_time and (not latest_created_time or finding_time > latest_created_time):
            latest_created_time = finding_time

    next_run = {"last_fetch": latest_created_time.strftime("%Y-%m-%dT%H:%M:%SZ") if latest_created_time else last_fetch}
    return next_run, incidents


def main() -> None:
    try:
        params = demisto.params()
        command = demisto.command()

        api_key = params.get("apikey")
        base_url = params.get("url", "https://api.panoraysapp.com")

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        verify_certificate = not bool(params.get("insecure", False))
        proxy = bool(params.get("proxy", False))

        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, headers=headers)

        if command == "test-module":
            return_results(verify_module(client))
        elif command == "panorays-finding-list":
            return_results(finding_list_command(client, demisto.args()))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            first_fetch_time = params.get("first_fetch", "3 days")
            max_fetch = int(params.get("max_fetch") or 50)

            next_run, incidents = fetch_incidents_command(client, last_run, first_fetch_time, max_fetch)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()