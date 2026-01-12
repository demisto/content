from CommonServerPython import *

""" IMPORTS """

import json
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" GLOBALS/PARAMS """
API_KEY = demisto.params().get("apikey")
# Remove trailing slash to prevent wrong URL path to serviceaa
SERVER = demisto.params().get("url", "")
USE_SSL = not demisto.params().get("insecure", False)
# Service base URL
BASE_URL = SERVER + "/api/v2/"
# Headers to be sent in requests
HEADERS = {"x-api-key": API_KEY, "accept": "application/json", "Content-Type": "application/json"}

""" HELPER FUNCTIONS """


def http_request(method, full_url, params=None, data=None):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(method, full_url, verify=USE_SSL, params=params, json=data, headers=HEADERS)
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        return_error(
            f"Error in API call to Indeni Integration [{res.status_code}] - {res.reason} for endpoint {full_url}"
        )

    return res.json()


def item_to_incident(item):
    incident = {}

    # Incident occurrence time, usually item creation date in service
    incident["occurred"] = item.get("create_at")
    incident["updated"] = item.get("updated_at")
    incident["name"] = item.get("headline")
    incident["rawJSON"] = json.dumps(item)

    indeni_severity = item.get("severity").get("level")
    # Demisto: CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, Unknown: 0
    # Indeni: CRITICAL: 0, ERROR: 1, WARN: 2, INFO: 3
    if indeni_severity == 0:
        demisto_severity = 4
    elif indeni_severity == 1:
        demisto_severity = 3
    elif indeni_severity == 2:
        demisto_severity = 2
    elif indeni_severity == 3:
        demisto_severity = 1
    else:
        demisto_severity = 0
    incident["severity"] = demisto_severity

    alert_blocks = item.get("alert_blocks")
    details = ""
    for block in alert_blocks:
        details = details + block.get("header") + "\n"
        if block.get("body") is not None:
            details = details + block.get("body") + "\n"
    incident["details"] = details

    return incident


""" COMMANDS + REQUESTS FUNCTIONS """


def test_module(base_url):
    """
    Performs basic get request to get item samples
    """
    http_request("GET", base_url + "labels")
    demisto.results("ok")


def get_device_request(device_id, base_url):
    # The service endpoint to request from
    endpoint_url = "devices/" + device_id
    # Send a request using our http_request wrapper
    response = http_request("GET", base_url + endpoint_url)
    return response


def get_alert_detail_request(alert_id, base_url):
    endpoint_url = "issues/" + alert_id
    response = http_request("GET", base_url + endpoint_url)
    return response


def get_all_active_issues(per_page, sort_by, base_url):
    issues: list[dict] = []
    # The service endpoint to request from
    endpoint_url = "issues"
    # Dictionary of params for the request
    params = {"page": 1, "per_page": per_page, "sort_by": sort_by, "resolved": "false"}
    # Send a request using our http_request wrapper
    response = http_request("GET", base_url + endpoint_url, params)
    # testing remove the loop
    while response:
        issues.extend(response)
        params["page"] = params["page"] + 1
        response = http_request("GET", base_url + endpoint_url, params)
    return issues


def get_limited_active_issues(per_page, alert_id_index, size, only_Pan_Cve_Issues, lowest_issue_severity_level, base_url):
    issues = []
    issue_count = 0
    # The service endpoint to request from
    endpoint_url = "issues"
    # Dictionary of params for the request
    params = {"page": 1, "per_page": per_page, "sort_by": "alert_id.asc", "resolved": "false"}
    # Send a request using our http_request wrapper
    response = http_request("GET", base_url + endpoint_url, params)
    # testing remove the loop
    while response:
        for item in response:
            alert_id = item.get("alert_id")
            if alert_id <= alert_id_index:
                continue
            else:
                alert_id_index = alert_id
                if (only_Pan_Cve_Issues is False) or (
                    only_Pan_Cve_Issues and item.get("unique_identifier").startswith("panos_vulnerability")
                ):
                    alert_severity_level = item.get("severity").get("level")
                    if alert_severity_level <= lowest_issue_severity_level:
                        issues.append(item)
                        issue_count = issue_count + 1
                        if issue_count == size:
                            return issues, alert_id_index
        params["page"] = params["page"] + 1
        response = http_request("GET", base_url + endpoint_url, params)
    return issues, alert_id_index


def get_device_info(base_url):
    device_id = demisto.args().get("device_id")
    device_response = get_device_request(device_id, base_url)

    content = {
        "DeviceId": device_id,
        "DeviceIP": device_response.get("ip_address"),
        "DeviceName": device_response.get("tags").get("device-name"),
        "DeviceModel": device_response.get("tags").get("model"),
        "OSVersion": device_response.get("tags").get("os.version"),
        "CriticalAlertStats": device_response.get("alert_statistics").get("CRITICAL"),
        "ErrorAlertStats": device_response.get("alert_statistics").get("ERROR"),
        "WarnAlertStats": device_response.get("alert_statistics").get("WARN"),
        "InfoAlertStats": device_response.get("alert_statistics").get("INFO"),
    }
    ec = {"Indeni.DeviceInfo(val.DeviceId==obj.DeviceId)": content}

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": content,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("Device Info", content, removeNull=True),
            "EntryContext": ec,
        }
    )


def get_alert_info(base_url):
    alert_id = demisto.args().get("alert_id")
    alert_response = get_alert_detail_request(alert_id, base_url)

    ec = {
        "Indeni.AlertInfo(val.AlertId==obj.AlertId)": {
            "AlertId": alert_id,
            "Headline": alert_response.get("headline"),
            "DeviceId": alert_response.get("device_id"),
            "AlertType": alert_response.get("unique_identifier"),
        }
    }
    # ADD HUMAN READABLE FOR ALERT BLOCKS
    human_format = alert_response
    if "notes" in human_format:
        n = human_format["notes"]
        human_format["notes"] = "\n".join([a["text"] for a in n]) if isinstance(n, list) else n
    if "alert_blocks" in human_format:
        n = human_format["alert_blocks"]
        if isinstance(n, list):
            bodies: list[str] = []
            for a in n:
                body = a.get("body", None)
                if body:
                    bodies.append(body)
            if len(bodies) > 0:
                human_format["alert_blocks"] = "\n".join(bodies)
        else:
            human_format["alert_blocks"] = n

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": alert_response,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(f"Alert ID {alert_id}", human_format, removeNull=True),
            "EntryContext": ec,
        }
    )


def get_alert_summary(base_url):
    alert_type = demisto.args().get("alert_type_identifier")
    active_alerts = get_all_active_issues(500, "created_at.desc", base_url)
    devices = []
    for alert in active_alerts:
        if alert.get("unique_identifier") == alert_type:
            device_response = get_device_request(alert.get("device_id"), base_url)
            device_name = device_response.get("name")

            alert_response = get_alert_detail_request(alert.get("id"), base_url)
            items = []
            for alert_block in alert_response.get("alert_blocks"):
                if alert_block.get("type") == "items":
                    for alert_item in alert_block.get("items"):
                        items.append({"Name": alert_item.get("name"), "Description": alert_item.get("description")})
            devices.append({"DeviceName": device_name, "DeviceId": alert.get("device_id"), "Items": items})

    content = {"Indeni.AffectedDevices(val.AlertType == obj.AlertType)": {"AlertType": alert_type, "Device": devices}}

    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": content,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(f"Devices Experiencing Alert {alert_type}", devices, removeNull=True),
            "EntryContext": content,
        }
    )


def post_note(base_url):
    alert_id = demisto.args().get("alert_id")
    alert_note = demisto.args().get("note")

    endpoint_url = "issues/" + alert_id + "/notes"
    body = {"text": alert_note}
    http_request("POST", base_url + endpoint_url, data=body)


def get_notes(base_url):
    alert_id = demisto.args().get("alert_id")
    endpoint_url = "issues/" + alert_id + "/notes"
    response = http_request("GET", base_url + endpoint_url)
    readable_notes = []
    context_notes = {"AlertID": alert_id}
    notes = []
    for note in response:
        text = note.get("text", None)
        if text:
            readable_notes.append({"note": text, "timestamp": timestamp_to_datestring(note.get("timestamp"))})
            notes.append(text)
    if len(notes) > 0:
        context_notes["Note"] = notes

    content = {"Indeni.AlertInfo(val.AlertID == obj.AlertID)": context_notes}
    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": content,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown("Issue Notes", readable_notes, removeNull=True),
            "EntryContext": content,
        }
    )


def archive_issue(base_url):
    alert_id = demisto.args().get("alert_id")
    endpoint_url = "issues/" + alert_id
    body = {"archived": True}
    http_request("PATCH", base_url + endpoint_url, data=body)


def unarchive_issue(base_url):
    alert_id = demisto.args().get("alert_id")
    endpoint_url = "issues/" + alert_id
    body = {"archived": False}
    http_request("PATCH", base_url + endpoint_url, data=body)


# Indeni: CRITICAL: 0, ERROR: 1, WARN: 2, INFO: 3
def issue_severity_to_issue_level(issue_severity):
    if issue_severity == "CRITICAL":
        return 0
    elif issue_severity == "ERROR":
        return 1
    elif issue_severity == "WARN":
        return 2
    elif issue_severity == "INFO":
        return 3
    else:
        return -1


def fetch_incidents(base_url):
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    alert_id_index = last_run.get("alert_id", 0)
    only_pan_cve_issues = demisto.params().get("onlyPullPanCveIssues", False)
    max_pull_size = int(demisto.params().get("maxPullSize", 20))
    lowest_issue_severity = demisto.params().get("issueSeverity", "INFO")
    lowest_issue_severity_level = issue_severity_to_issue_level(lowest_issue_severity)
    incidents = []

    # Handle first time fetch, fetch only currently un-resolved active issues
    result = get_limited_active_issues(
        100, alert_id_index, max_pull_size, only_pan_cve_issues, lowest_issue_severity_level, base_url
    )
    for item in result[0]:
        incident = item_to_incident(item)
        incidents.append(incident)

    demisto.setLastRun({"alert_id": result[1]})
    demisto.incidents(incidents)

    """ COMMANDS MANAGER / SWITCH PANEL """


def main():
    try:
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration test button.
            test_module(BASE_URL)
        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            fetch_incidents(BASE_URL)
        elif demisto.command() == "indeni-get-device-info":
            get_device_info(BASE_URL)
        elif demisto.command() == "indeni-get-alert-info":
            get_alert_info(BASE_URL)
        elif demisto.command() == "indeni-get-alert-summary":
            get_alert_summary(BASE_URL)
        elif demisto.command() == "indeni-post-note":
            post_note(BASE_URL)
            demisto.results("Done")
        elif demisto.command() == "indeni-archive-issue":
            archive_issue(BASE_URL)
            demisto.results("Done")
        elif demisto.command() == "indeni-unarchive-issue":
            unarchive_issue(BASE_URL)
            demisto.results("Done")
        elif demisto.command() == "indeni-get-notes":
            get_notes(BASE_URL)
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
