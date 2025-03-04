import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import traceback
from typing import Any


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
VERSION = "1.0.0"


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, authentication_url: str, client_id: str, api_key: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        payload = {
            "apiKey": api_key,
            "clientID": client_id,
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        authentication_response = self.get_authentication_token(authentication_url, headers, payload)
        access_token = authentication_response["access_token"]
        headers["Authorization"] = "Bearer " + access_token
        self.headers = headers

    def get_devices(self, vendor, model, series, firmware_version):
        return self._http_request(
            method="POST",
            url_suffix="/get_devices",
            headers=self.headers,
            json_data={
                "vendor": vendor,
                "model": model,
                "series": series,
                "firmware_version": firmware_version,
                "version": VERSION,
            },
        )

    def get_vulnerabities(self, firmwareId, deviceId, pageSize, page, sortField, sortOrder, returnFields):
        return self._http_request(
            method="POST",
            url_suffix="/get_vulnerabilities",
            headers=self.headers,
            json_data={
                "firmwareId": firmwareId,
                "version": VERSION,
                "deviceId": deviceId,
                "pageSize": pageSize,
                "page": page,
                "sortOrder": sortOrder,
                "sortField": sortField,
                "returnFields": returnFields,
            },
        )

    def get_authentication_token(self, authentication_url: str, headers: dict, payload: dict):
        return self._http_request(method="POST", full_url=authentication_url, headers=headers, json_data=payload)


def deviceToMarkdown(device):
    nl = "\n"
    markdown = f"---{nl}### Device {device.get('model')}{nl}"
    markdown += f"**Model Name**: {device.get('model')}{nl}"
    markdown += f"**Vendor**: {device.get('vendor')}{nl}"
    markdown += f"**Series**: {device.get('series')}{nl}"
    markdown += f"**Categories**: {','.join(device.get('categories'))}{nl}"
    markdown += f"**DeviceID**: {device.get('device_key')}{nl}"
    markdown += f"**Match Score**: {round(device.get('score')*100,2)}%{nl}"
    firmwares = device.get("firmware")
    markdown += tableToMarkdown("Firmwares", firmwares, headers=["firmwareid", "version", "name"])
    return markdown


def getEditIssue(returnFields):
    def editIssue(issue):
        if not isinstance(issue, dict):
            key = returnFields[0]
            if key == "risk":
                issue = str(round(issue * 100, 2)) + "%"
            data = {}
            data[key] = issue
            return data
        else:
            field = issue.get("risk")
            if field is not None:
                issue["risk"] = str(round(float(field) * 100, 2)) + "%"
            return issue

    return editIssue


def arcusteam_get_devices(client: Client, args: dict[str, Any]):
    """
    Search for matching devices giving a device name
    :param device_name: device name to search for in the DB.
    :return: List of matching devices for the given device.
    """
    result = client.get_devices(
        vendor=args.get("vendor", ""),
        model=args.get("model", ""),
        series=args.get("series", ""),
        firmware_version=args.get("firmware_version", ""),
    )
    markdown = "## Found " + str(len(result)) + " devices\n"
    markdown += "".join(list(map(deviceToMarkdown, result)))
    return CommandResults(
        readable_output=markdown, outputs_prefix="ArcusTeamDevices", outputs_key_field="", outputs={"devices": result}
    )


def arcusteam_get_vulnerabilities(client: Client, args: dict[str, Any]) -> CommandResults:
    returnFields = str(args.get("return_fields", "risk,cve")).split(",")
    firmwareId = args.get("firmware_id", "")
    deviceId = args.get("device_id", "")
    pageSize = int(args.get("page_size", 10))
    page = int(args.get("page_number", 1))
    sortOrder = args.get("sort_order", "desc")
    sortField = args.get("sort_field", "risk")

    result = client.get_vulnerabities(firmwareId, deviceId, pageSize, page, sortField, sortOrder, returnFields)
    if len(result.get("code", "")) > 0:
        raise Exception(result.get("message"))
    result["results"] = list(map(getEditIssue(returnFields), result.get("results")))
    markdown = "## Scan results\n"

    if len(result.get("results")) > 0:
        markdown += tableToMarkdown(
            "Number of CVE's found: " + str(result.get("max_items")),
            result.get("results"),
            headers=list(result.get("results")[0].keys()),
        )
    else:
        markdown += "No results"

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="ArcusTeamVulnerabilities",
        outputs_key_field="",
        outputs=result,
    )


""" MAIN FUNCTION """


def main() -> None:
    """
    Main function, parses params and runs command functions
    :return:
    :rtype:
    """

    api_key = demisto.params().get("api_key")

    client_id = demisto.params().get("client_id")

    # get the service API url
    base_url = urljoin(demisto.params()["url"], "/api/v10/xsoar")

    authentication_url = urljoin(demisto.params()["url"], "/api/v10/auth/login_apikey")

    verify_certificate = not demisto.params().get("insecure", False)

    proxy = demisto.params().get("proxy", False)

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            authentication_url=authentication_url,
            client_id=client_id,
            api_key=api_key,
        )
        if demisto.command() == "arcusteam-get-devices":
            return_results(arcusteam_get_devices(client, demisto.args()))

        if demisto.command() == "arcusteam-get-vulnerabilities":
            return_results(arcusteam_get_vulnerabilities(client, demisto.args()))

        if demisto.command() == "test-module":
            return_results("ok")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
