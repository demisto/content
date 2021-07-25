import json
import requests
import urllib3
import traceback
from typing import Any, Dict


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
VERSION = "1.0.0"


""" CLIENT CLASS """


class Client(BaseClient):
    pass


def deviceToMarkdown(device):
    nl = '\n'
    markdown = f"---{nl}### Device {device.get('model')}{nl}"
    markdown += f"**Model Name**: {device.get('model')}{nl}"
    markdown += f"**Vendor**: {device.get('vendor')}{nl}"
    markdown += f"**Series**: {device.get('series')}{nl}"
    markdown += f"**Categories**: {','.join(device.get('categories'))}{nl}"
    markdown += f"**DeviceID**: {device.get('device_key')}{nl}"
    markdown += f"**Match Score**: {round(device.get('score')*100,2)}%{nl}"
    firmwares = device.get('firmware')
    markdown += tableToMarkdown(
        "Firmwares",
        firmwares,
        headers=['firmwareid', 'version', 'name']
    )
    return markdown


def getEditIssue(returnFields):
    def editIssue(issue):
        if not isinstance(issue, dict):
            key = returnFields[0]
            if key == "risk":
                issue = str(round(issue * 100, 2)) + '%'
            data = dict()
            data[key] = issue
            return data
        else:
            field = issue.get('risk')
            if field is not None:
                issue['risk'] = str(round(int(field) * 100, 2)) + '%'
            return issue
    return editIssue


def arcusteam_get_devices(client: Client, args: Dict[str, Any]):
    """
    Search for matching devices giving a device name
    :param device_name: device name to search for in the DB.
    :return: List of matching devices for the given device.
    """
    url = urljoin(client._base_url, "/get_devices")
    payload = {
        "vendor": args.get("vendor", ""),
        "model": args.get("model", ""),
        "series": args.get("series", ""),
        "firmware_version": args.get("firmware_version", ""),
        "version": VERSION
    }
    result = requests.request("POST", url, headers=client._headers, data=json.dumps(payload))
    resultJson = result.json()
    markdown = '## Found ' + str(len(resultJson)) + ' devices\n'
    markdown += "".join(list(map(deviceToMarkdown, resultJson)))
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="ArcusTeamDevices",
        outputs_key_field="",
        outputs={'devices': resultJson},
    )


def arcusteam_get_vulnerabilities(client: Client, args: Dict[str, Any]) -> CommandResults:
    url = urljoin(client._base_url, "/get_vulnerabilities")
    returnFields = str(args.get("return_fields")).split(',')
    payload = {
        "firmwareId": args.get("firmware_id", ""),
        "version": VERSION,
        "deviceId": args.get("device_id", ""),
        "pageSize": int(args.get("page_size", 10)),
        "page": int(args.get("page_number", 1)),
        "sortOrder": args.get("sort_order", "desc"),
        "sortField": args.get("sort_field", "risk"),
        "returnFields": str(args.get("return_fields")).split(','),

    }
    result = requests.request("POST", url, headers=client._headers, data=json.dumps(payload))
    if len(result.json().get('code', '')) > 0:
        raise Exception(result.json().get('message'))
    resultJson = result.json()
    resultJson['results'] = list(map(getEditIssue(returnFields), resultJson.get("results")))
    markdown = '## Scan results\n'

    if len(resultJson.get('results')) > 0:
        markdown += tableToMarkdown(
            'Number of CVE\'s found: ' + str(resultJson.get("max_items")),
            resultJson.get('results'),
            headers=list(resultJson.get('results')[0].keys())
        )
    else:
        markdown += "No results"

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="ArcusTeamVulnerabilities",
        outputs_key_field="",
        outputs=result.json(),
    )


def test_module(client):
    return 'ok'

""" MAIN FUNCTION """


def main() -> None:
    """
    Main function, parses params and runs command functions
    :return:
    :rtype:
    """

    api_key = demisto.params().get("ApiKey")

    client_id = demisto.params().get("ClientID")

    # get the service API url
    base_url = urljoin(demisto.params()["url"], "/api/v10/xsoar")

    url = urljoin(demisto.params()["url"], "/api/v10/auth/login_apikey")

    payload = {
        "apiKey": api_key,
        "clientID": client_id,
    }

    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    result = requests.request("POST", url, headers=headers, data=json.dumps(payload))
    readable_output = result.json()
    access_token = readable_output["access_token"]

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer " + access_token
    }

    verify_certificate = not demisto.params().get("insecure", False)

    proxy = demisto.params().get("proxy", False)

    try:
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )
        if demisto.command() == "arcusteam-get-devices":
            return_results(arcusteam_get_devices(client, demisto.args()))

        if demisto.command() == "test-module":
            return_results(test_module(client))

        elif demisto.command() == "arcusteam-get-vulnerabilities":
            return_results(arcusteam_get_vulnerabilities(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
