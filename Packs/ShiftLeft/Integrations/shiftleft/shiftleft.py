"""ShiftLeft CORE Integration for Cortex XSOAR (aka Demisto)
"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import traceback
from typing import Dict, Any

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class ShiftLeftClient(BaseClient):
    """Client class to interact with ShiftLeft V4 api"""

    def get_scopes(self, org_id: str):
        """Get user scopes"""
        return self._http_request(
            method="GET",
            url_suffix=f"/orgs/{org_id}/my_scopes",
        )

    def list_apps(
            self,
            org_id: str,
    ) -> Dict[str, str]:
        """Returns list of apps"""
        return self._http_request(
            method="GET",
            url_suffix=f"/orgs/{org_id}/apps",
        )

    def list_app_findings(
            self,
            org_id: str,
            app_name: str,
            severity: Union[str, List[str], None],
            type: Union[str, List[str], None],
            version: Union[str, None],
    ) -> Dict[str, str]:
        """Returns list of findings"""
        return self._http_request(
            method="GET",
            url_suffix=f"/orgs/{org_id}/apps/{app_name}/findings",
            params={"severity": severity, "type": type, "version": version},
        )


def test_module(client: ShiftLeftClient, org_id: str) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ""
    try:
        result = client.get_scopes(org_id)
        message = "ok" if result and result.get("ok") else "Unauthorized"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure access token is correctly set"
        else:
            raise e
    return message


def list_apps_command(client: ShiftLeftClient, org_id: str) -> CommandResults:
    result = client.list_apps(org_id)
    apps: Any = result.get("response") if result.get("ok") else []
    for a in apps:
        if a.get("tags"):
            a["labels"] = "\n".join([f'`{t.get("key")}`: {t.get("value")}' for t in a.get("tags")])
    if apps:
        markdown = f"### Apps List ({len(apps)})\n"
        markdown += tableToMarkdown(
            "",
            apps,
            headers=[
                "id",
                "name",
                "labels",
            ],
        )
        return CommandResults(
            readable_output=markdown,
            outputs_prefix="ShiftLeft.Apps",
            outputs_key_field="id",
            outputs=apps,
        )
    else:
        return CommandResults(readable_output="No apps were found.")


def list_app_secrets_command(client: ShiftLeftClient, org_id: str, args: Dict[str, Any]) -> CommandResults:
    app_name = args.get("app_name")
    if not app_name:
        raise ValueError("Shiftleft error: app_name not specified")
    version = args.get("version")
    entropy = args.get("entropy", 0.48)
    result = client.list_app_findings(org_id, app_name, None, "secret", version)
    response: Any = result.get("response") if result.get("ok") else {}
    findings = response.get("findings", {})
    filtered_findings = [
        f
        for f in findings
        if float(f.get("details", {}).get("entropy", 0)) > float(entropy)
    ]
    for f in filtered_findings:
        f["secret"] = ""
        f["fileName"] = ""
        details = f.get("details")
        if details:
            f["secret"] = details.get("secret", "")
            f["fileName"] = details.get("fileName", "")
            if details.get("vcsUrl"):
                f[
                    "fileName"
                ] = f'[{details.get("fileName", "Location")}]({details.get("vcsUrl")})'
    scan = response.get("scan", [])
    if scan:
        scan = [scan]
    if response:
        markdown = "### Scan Info\n"
        markdown += tableToMarkdown(
            "",
            scan,
            headers=[
                "id",
                "app",
                "language",
                "version",
                "started_at",
                "completed_at",
                "number_of_expressions",
            ],
        )
        markdown += "\n### Recommendation\n"
        if len(filtered_findings):
            markdown += "\nPlease review the secrets in this list!"
        else:
            markdown += "\nNo secrets in this app require your attention."
        markdown += f"\n### ShiftLeft Findings ({len(filtered_findings)})\n"
        markdown += tableToMarkdown(
            "",
            filtered_findings,
            headers=[
                "id",
                "title",
                "secret",
                "fileName",
            ],
        )
        return CommandResults(
            readable_output=markdown,
            outputs_prefix="ShiftLeft.Secrets",
            outputs_key_field="",
            outputs=response,
        )
    else:
        return CommandResults()


def list_app_findings_command(client: ShiftLeftClient, org_id: str, args: Dict[str, Any]) -> CommandResults:
    app_name = args.get("app_name")
    if not app_name:
        raise ValueError("Shiftleft error: app_name not specified")
    severity = argToList(args.get("severity", "critical"))
    app_type = argToList(args.get("type", "vuln"))
    version = args.get("version")
    result = client.list_app_findings(org_id, app_name, severity, app_type, version)
    response: Any = result.get("response") if result.get("ok") else {}
    findings = response.get("findings", {})
    scan = response.get("scan", [])
    if scan:
        scan = [scan]
    # Exclude SDL
    filtered_findings = [
        f
        for f in findings
        if f.get("owasp_category") not in ("a3-sensitive-data-exposure")
    ]
    reachable_oss_found = False
    for f in filtered_findings:
        f["sink_method"] = ""
        f["source_method"] = ""
        f["file_locations"] = ""
        f["reachable_oss"] = ""
        f["cves"] = ""
        if f.get("details"):
            details = f.get("details")
            f["sink_method"] = details.get("sink_method", "")
            f["source_method"] = details.get("source_method", "")
            f["file_locations"] = "\n".join(details.get("file_locations", [])) + "\n"
        if f.get("related_findings"):
            oss_vuln = f.get("related_findings").get("oss_vuln")
            if oss_vuln:
                reachable_oss_found = True
                f["reachable_oss"] = len(oss_vuln)
                cve_tags = []
                for ov in oss_vuln:
                    cve_tags += [
                        t.get("value")
                        for t in ov.get("tags", [])
                        if t.get("key") in ("cve")
                    ]
                f["cves"] = "\n".join(cve_tags)
    if response:
        markdown = "### Scan Info\n"
        markdown += tableToMarkdown(
            "",
            scan,
            headers=[
                "id",
                "app",
                "language",
                "version",
                "started_at",
                "completed_at",
                "number_of_expressions",
            ],
        )
        markdown += "\n### Recommendation\n"
        if reachable_oss_found:
            markdown += "\nFindings with attacker-reachable opensource vulnerabilities requires your attention!"
        else:
            markdown += "\nNo findings with attacker-reachable opensource vulnerabilities was found."
        markdown += f"\n### ShiftLeft Findings ({len(filtered_findings)})\n"
        markdown += tableToMarkdown(
            "",
            filtered_findings,
            headers=[
                "id",
                "severity",
                "title",
                "file_locations",
                "cves",
            ],
        )
        return CommandResults(
            readable_output=markdown,
            outputs_prefix="ShiftLeft",
            outputs_key_field="scan.id",
            outputs=response,
        )
    else:
        return CommandResults(
            outputs_prefix="ShiftLeft",
            outputs_key_field="",
            outputs={},
        )


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    org_id = params.get("org_id")
    access_token = params.get("access_token")
    if not org_id or not access_token:
        return_error("Shiftleft error: Both organization id and access token must be set.")
    # get the service API url
    base_url = "https://www.shiftleft.io/api/v4"  # disable-secrets-detection

    verify_certificate = True

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        headers: Dict = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }

        client = ShiftLeftClient(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, org_id)
            return_results(result)

        elif command == "shiftleft-list-app-findings":
            return_results(list_app_findings_command(client, org_id, demisto.args()))

        elif command == "shiftleft-list-app-secrets":
            return_results(list_app_secrets_command(client, org_id, demisto.args()))

        elif command == "shiftleft-list-apps":
            return_results(list_apps_command(client, org_id))

        else:
            raise NotImplementedError(f'{command} is not an existing Shiftleft command')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
