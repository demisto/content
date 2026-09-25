import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import json
import traceback
import urllib3
from typing import Any

urllib3.disable_warnings()


class XSOARClient(BaseClient):

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool,
                 api_key_id: str = ''):
        headers: dict[str, str] = {
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if api_key_id:
            headers["x-xdr-auth-id"] = api_key_id
        self._is_xsoar8 = bool(api_key_id)
        super().__init__(
            base_url=base_url,
            headers=headers,
            verify=verify,
            proxy=proxy,
        )

    def _url_suffix(self, path: str) -> str:
        if self._is_xsoar8:
            return f"/xsoar/public/v1{path}"
        return path

    def search_incidents(
        self,
        query: str = "",
        from_date: str | None = None,
        to_date: str | None = None,
        size: int = 50,
        page: int = 0,
    ) -> list:
        filter_body: dict[str, Any] = {}
        if query:
            filter_body["query"] = query
        if from_date:
            filter_body["fromDate"] = from_date
        if to_date:
            filter_body["toDate"] = to_date

        body: dict[str, Any] = {
            "filter": filter_body,
            "page": page,
            "size": size,
            "sort": [{"field": "created", "asc": True}],
        }

        response = self._http_request(
            method="POST",
            url_suffix=self._url_suffix("/incidents/search"),
            json_data=body,
        )

        return response.get("data") or []

    def get_incident(self, incident_id: str) -> dict | None:
        incidents = self.search_incidents(query=f"id:{incident_id}", size=1)
        return incidents[0] if incidents else None

    def get_incident_entries(self, incident_id: str) -> list:
        try:
            response = self._http_request(
                method="POST",
                url_suffix=self._url_suffix(f"/investigation/{incident_id}"),
                json_data={},
            )
            return response if isinstance(response, list) else []
        except Exception as exc:
            demisto.debug(f"Could not fetch entries for incident {incident_id}: {exc}")
            return []


def map_xsoar_incident_to_xsiam(incident: dict, incident_type: str | None = None) -> dict:
    mapped: dict[str, Any] = {
        "name": incident.get("name", ""),
        "occurred": incident.get("occurred") or incident.get("created", ""),
        "severity": incident.get("severity", 0),
        "type": incident_type or incident.get("type", ""),
        "rawJSON": json.dumps(incident),
        "dbotMirrorId": str(incident.get("id", "")),
        "details": incident.get("details", ""),
        "CustomFields": {
            "xsoar6incidentid": str(incident.get("id", "")),
            "xsoar6owner": incident.get("owner", ""),
            "xsoar6status": incident.get("status", 0),
            "xsoar6type": incident.get("type", ""),
            "xsoar6closedate": incident.get("closed", ""),
            "xsoar6closereason": incident.get("closeReason", ""),
        },
    }
    return mapped


def test_module(client: XSOARClient) -> str:
    try:
        client.search_incidents(size=1)
        return "ok"
    except Exception as exc:
        raise DemistoException(f"Test failed: {exc}")


def fetch_incidents(
    client: XSOARClient,
    max_fetch: int,
    first_fetch: str,
    query: str,
    incident_type: str | None,
) -> None:
    last_run = demisto.getLastRun() or {}
    last_fetch_ts: str | None = last_run.get("last_fetch")
    last_fetched_ids: list[str] = last_run.get("last_fetched_ids", [])

    if last_fetch_ts:
        from_date = last_fetch_ts
    else:
        first_dt = arg_to_datetime(first_fetch or "3 days")
        if not first_dt:
            first_dt = arg_to_datetime("3 days")
        from_date = first_dt.isoformat() if first_dt else ""

    demisto.debug(f"XSOAR6Collector fetch-incidents: from_date={from_date}, query={query}")

    raw_incidents = client.search_incidents(
        query=query,
        from_date=from_date,
        size=max_fetch,
    )

    incidents: list[dict] = []
    latest_created = last_fetch_ts or ""
    current_ids: list[str] = []

    for inc in raw_incidents:
        inc_id = str(inc.get("id", ""))
        inc_created = inc.get("created", "")

        # Deduplication: skip incidents already fetched in the previous cycle
        if inc_created == last_fetch_ts and inc_id in last_fetched_ids:
            demisto.debug(f"XSOAR6Collector: skipping duplicate incident {inc_id}")
            continue

        mapped = map_xsoar_incident_to_xsiam(inc, incident_type)
        incidents.append(mapped)

        # Track the newest created timestamp
        if inc_created and inc_created >= latest_created:
            if inc_created > latest_created:
                latest_created = inc_created
                current_ids = [inc_id]
            else:
                current_ids.append(inc_id)

    # Persist state for the next run
    new_last_run: dict[str, Any] = {
        "last_fetch": latest_created or from_date,
        "last_fetched_ids": current_ids,
    }

    demisto.debug(
        f"XSOAR6Collector: fetched {len(incidents)} incidents, "
        f"new last_run={json.dumps(new_last_run)}"
    )

    demisto.setLastRun(new_last_run)
    demisto.incidents(incidents)


def get_incidents_command(client: XSOARClient, args: dict) -> CommandResults:
    query = args.get("query", "")
    limit = arg_to_number(args.get("limit", "50")) or 50
    from_date = args.get("from_date")
    to_date = args.get("to_date")

    # Resolve relative date strings
    if from_date:
        dt = arg_to_datetime(from_date)
        from_date = dt.isoformat() if dt else from_date
    if to_date:
        dt = arg_to_datetime(to_date)
        to_date = dt.isoformat() if dt else to_date

    incidents = client.search_incidents(
        query=query,
        from_date=from_date,
        to_date=to_date,
        size=limit,
    )

    readable = tableToMarkdown(
        "XSOAR 6 Incidents",
        incidents,
        headers=["id", "name", "type", "severity", "status", "owner", "created"],
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="XSOAR6.Incidents",
        outputs_key_field="id",
        outputs=incidents,
        raw_response=incidents,
    )


def get_incident_command(client: XSOARClient, args: dict) -> CommandResults:
    incident_id = args.get("incident_id", "")
    if not incident_id:
        raise DemistoException("incident_id is required.")

    incident = client.get_incident(incident_id)
    if not incident:
        return CommandResults(readable_output=f"No incident found with ID {incident_id}.")

    readable = tableToMarkdown(
        f"XSOAR 6 Incident {incident_id}",
        incident,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable,
        outputs_prefix="XSOAR6.Incident",
        outputs_key_field="id",
        outputs=incident,
        raw_response=incident,
    )



def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params.get("url", "").rstrip("/")
    api_creds = params.get("api_key", {})
    api_key = api_creds.get("password", "") if isinstance(api_creds, dict) else api_creds
    api_key_id = params.get("api_key_id", "")
    verify = not argToBoolean(params.get("insecure", True))
    proxy = argToBoolean(params.get("proxy", False))
    max_fetch = arg_to_number(params.get("max_fetch", "50")) or 50
    first_fetch = params.get("first_fetch", "3 days")
    query = params.get("query", "")
    incident_type = params.get("incident_type")

    demisto.debug(f"XSOAR6Collector: command={command}")

    try:
        client = XSOARClient(
            base_url=base_url,
            api_key=api_key,
            verify=verify,
            proxy=proxy,
            api_key_id=api_key_id,
        )

        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "fetch-incidents":
            fetch_incidents(
                client=client,
                max_fetch=max_fetch,
                first_fetch=first_fetch,
                query=query,
                incident_type=incident_type,
            )

        elif command == "xsoar6-get-incidents":
            result = get_incidents_command(client, args)
            return_results(result)

        elif command == "xsoar6-get-incident":
            result = get_incident_command(client, args)
            return_results(result)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as exc:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(exc)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
