import requests
import json
import time
import demistomock as demisto
from datetime import datetime
from typing import Any
from CommonServerPython import *

THREATMON_PAGE_SIZE = 10
MAX_PAGES_PER_RUN = 100  # Max pages fetched per XSOAR run (1000 incidents) to avoid timeout


class Client:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.headers = {"X-COMPANY-API-KEY": api_key, "accept": "application/json"}

    def get_incidents(self, last_incident_id=None, page=0):
        """Fetches incidents from Threatmon API using pagination and lastIncidentId filtering."""

        url = f"{self.api_url}/vulnerabilities/{page}"
        if last_incident_id:
            url += f"?afterAlarmCode={last_incident_id}"

        response = requests.get(url, headers=self.headers)

        if response.status_code != 200:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

        return response.json()

    def set_status(self, data):
        """Updates incidents on Threatmon API using PATCH request and pagination."""

        url = f"{self.api_url}/incident/status"
        response = requests.patch(url, headers=self.headers, json=data)

        if response.status_code == 200:
            return {"message": "status updated successfully"}
        else:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

    def request_takedown(self, finding_id: int, finding: str):
        """Submits a takedown request for a specific finding (alarm row)."""

        url = f"{self.api_url}/takedown"
        payload = {"findingId": finding_id, "finding": finding}
        response = requests.post(url, headers=self.headers, json=payload)

        if response.status_code == 200:
            return {"message": "Takedown request submitted successfully"}
        elif response.status_code == 404:
            raise Exception(f"Finding not found: findingId={finding_id}")
        elif response.status_code == 409:
            raise Exception(f"A takedown request already exists for findingId={finding_id}")
        elif response.status_code == 403:
            raise Exception("Takedown quota exceeded. Please contact ThreatMon.")
        elif response.status_code == 400:
            raise Exception("This finding is not eligible for a takedown request.")
        else:
            raise Exception(f"API Error: {response.status_code} - {response.text}")


def convert_to_demisto_severity(severity: str) -> int:
    """Maps Threatmon severity to Cortex XSOAR severity (1 to 4)."""
    severity_mapping = {"Information": 1, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return severity_mapping.get(severity, 1)


def fetch_incidents(client: Client, last_run: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetches new incidents from Threatmon API using pagination and latest lastIncidentId logic.

    Fetches at most MAX_PAGES_PER_RUN pages per XSOAR run to avoid timeout. Pagination state
    is saved in last_run so subsequent runs continue from where the previous run left off.
    last_incident_id is only advanced once the current batch is fully consumed to ensure
    consistent afterAlarmCode filtering across pages.
    """

    last_incident_id = last_run.get("last_incident_id")

    if last_incident_id is None:
        last_incident_id = demisto.params().get("lastIncidentId")

    if last_incident_id is None:
        last_incident_id = 0

    try:
        last_incident_id = int(last_incident_id)
    except (ValueError, TypeError):
        last_incident_id = 0

    try:
        page = int(last_run.get("page", 0))
    except (ValueError, TypeError):
        page = 0
    # max_seen_id tracks the highest alarmCode seen across pages within the current batch.
    # It is kept separate from last_incident_id so that afterAlarmCode stays constant
    # for all pages of a batch (changing it mid-batch would shift page offsets).
    try:
        max_seen_id = int(last_run.get("max_seen_id", last_incident_id))
    except (ValueError, TypeError):
        max_seen_id = last_incident_id
    incidents = []
    pages_fetched = 0

    while pages_fetched < MAX_PAGES_PER_RUN:
        response = client.get_incidents(last_incident_id=last_incident_id, page=page)

        alerts = response.get("data", [])

        if not alerts:
            # Batch complete: advance the filter cursor and reset page
            last_incident_id = max_seen_id
            page = 0
            last_run.pop("max_seen_id", None)
            break

        for alert in alerts:
            incident_id = 0
            raw_alarm_code = alert.get("alarmCode")
            if raw_alarm_code is not None:
                try:
                    incident_id = int(raw_alarm_code)
                except (ValueError, TypeError):
                    demisto.debug(f"Invalid alarmCode value received from API: {raw_alarm_code}. Defaulting incident_id to 0.")
            title = alert.get("title", "Unknown Threat")
            description = alert.get("description", "No description available")
            severity = alert.get("severity", "Low")
            status = alert.get("status", "New")
            alarm_date = alert.get("alarmDate", datetime.utcnow().isoformat())

            incident = {
                "name": f"Threatmon Alert: {title}",
                "details": description,
                "severity": convert_to_demisto_severity(severity),
                "occurred": alarm_date,
                "rawJSON": json.dumps(alert),
                "labels": [{"type": "Status", "value": status}],
            }
            incidents.append(incident)
            max_seen_id = max(max_seen_id, incident_id)

        pages_fetched += 1
        page += 1

        if len(alerts) < THREATMON_PAGE_SIZE:
            # Last page of batch: advance cursor and reset
            last_incident_id = max_seen_id
            page = 0
            last_run.pop("max_seen_id", None)
            break

        time.sleep(1)
    else:
        # Reached MAX_PAGES_PER_RUN with more pages remaining — save state for next run.
        # last_incident_id stays unchanged so afterAlarmCode filter remains consistent.
        last_run["max_seen_id"] = max_seen_id

    last_run["last_incident_id"] = last_incident_id
    last_run["page"] = page
    return incidents, last_run


def test_module(client):
    """Tests API connectivity and authentication."""
    try:
        response = client.get_incidents(page=0)

        # Check for expected successful response
        if isinstance(response, dict) and "data" in response:
            return "ok"

        # Check if API returned an error message
        if isinstance(response, dict) and "message" in response:
            return_error(f"Test failed: {response.get('message')}")

        # Generic unexpected structure
        return_error("Test failed: Unexpected API response structure.")

    except DemistoException as e:
        if "401" in str(e) or "403" in str(e):
            return_error("Test failed: Authentication error. Please check your API credentials.")
        elif "500" in str(e):
            return_error("Test failed: Server error (500). Please try again later.")
        else:
            return_error(f"Test failed: {str(e)}")

    except Exception as e:
        return_error(f"Test failed: {str(e)}")


def change_incident_status(client: Client, args: dict[str, Any]) -> CommandResults:
    code = args.get("alarmId")
    status = args.get("status")
    data = {"status": status, "alarmIds": [code]}
    changingStatus = client.set_status(data=data)
    if changingStatus:
        return CommandResults(readable_output=f"Incident {code} status changed to {changingStatus}")
    else:
        return CommandResults(readable_output=f"Failed to change status for incident {code}.")


def request_takedown_command(client: Client, args: dict[str, Any]) -> CommandResults:
    finding_id_raw = args.get("findingId")
    finding = args.get("finding")

    if not finding_id_raw:
        raise ValueError("findingId argument is required.")
    if not finding:
        raise ValueError("finding argument is required.")

    try:
        finding_id = int(finding_id_raw)
    except (ValueError, TypeError):
        raise ValueError(f"findingId must be a valid integer, got: {finding_id_raw}")

    result = client.request_takedown(finding_id=finding_id, finding=finding)
    return CommandResults(readable_output=result.get("message", "Takedown request submitted."))


def main():
    """Main function called by Cortex XSOAR."""
    try:
        params = demisto.params()
        api_url = params.get("url", "https://external.threatmonit.io/api/threatmon/external/v1")
        credentials = params.get("credentials", {})
        api_key = credentials.get("password")
        client = Client(api_url, api_key)
        command = demisto.command()

        if command == "test-module":
            return_results(test_module(client))
        elif command == "threatmon_update_incident_status":
            return_results(change_incident_status(client, demisto.args()))
        elif command == "threatmon_request_takedown":
            return_results(request_takedown_command(client, demisto.args()))
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun() or {}
            incidents, last_run = fetch_incidents(client, last_run)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)

    except Exception as e:
        return_error(f"Error in Threatmon integration: {str(e)}")


if __name__ in ("__main__", "builtin", "builtins"):
    main()
