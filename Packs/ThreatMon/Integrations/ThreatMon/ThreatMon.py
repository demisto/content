import requests
import json
import time
import demistomock as demisto
from datetime import datetime
from typing import Any
from CommonServerPython import *

THREATMON_PAGE_SIZE = 10


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


def convert_to_demisto_severity(severity: str) -> int:
    """Maps Threatmon severity to Cortex XSOAR severity (1 to 4)."""
    severity_mapping = {"Information": 1, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return severity_mapping.get(severity, 1)


def fetch_incidents(client: Client, last_run: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetches new incidents from Threatmon API using pagination and latest lastIncidentId logic."""

    last_incident_id = last_run.get("last_incident_id", None) or demisto.params().get("lastIncidentId", None)
    page = int(last_run.get("page", 0))  # Get last stored page or default to 0
    incidents = []

    while True:
        response = client.get_incidents(last_incident_id=last_incident_id, page=page)

        alerts = response.get("data", [])
        total_records = response.get("totalRecords", 0)

        if not alerts:
            break  # No more data to fetch

        for alert in alerts:
            incident_id = alert.get("alarmCode")
            title = alert.get("title", "Unknown Threat")
            description = alert.get("description", "No description available")
            severity = alert.get("severity", "Low")
            status = alert.get("status", "New")
            alarm_date = alert.get("alarmDate", datetime.utcnow().isoformat())

            # Cortex XSOAR Incident format
            incident = {
                "name": f"Threatmon Alert: {title}",
                "details": description,
                "severity": convert_to_demisto_severity(severity),
                "occurred": alarm_date,
                "rawJSON": json.dumps(alert),
                "labels": [{"type": "Status", "value": status}],
            }
            incidents.append(incident)

            # Update the last known incident ID
            last_incident_id = max(last_incident_id or 0, incident_id)

        # Stop fetching if we reach the last page
        if len(alerts) < THREATMON_PAGE_SIZE or (total_records and len(incidents) >= total_records):
            break
        time.sleep(1)
    # Store last fetched page and last incident ID in XSOAR
    last_run["last_incident_id"] = last_incident_id
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
        elif command == "fetch-incidents":
            last_run = demisto.getLastRun() or {}
            incidents, last_run = fetch_incidents(client, last_run)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)

    except Exception as e:
        return_error(f"Error in Threatmon integration: {str(e)}")


if __name__ in ("__main__", "builtin", "builtins"):
    main()
