from collections.abc import Callable
from datetime import datetime, timedelta
from dateutil.parser import parse as parse_iso
import json
from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *

from CommonServerUserPython import *

# disable insecure warnings
urllib3.disable_warnings()

FETCH_LIMIT_MAX = 10000
CURSOR_DELIM = "###"


class Client(BaseClient):
    def get_cves(self, params):
        """
        Send the request for list_cves_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            List: The response.
            [
                {
                    "content":"Use-after-free vulnerability in bzip2recover...",
                    "cve_code":"CVE-2016-3189",
                    "last_modified":"2023-11-07T01:32:12.723Z",
                    "level":"level_medium",
                    "published":"2016-06-30T15:59:01.470Z",
                    "score":6.5,
                    "score_v2":4.3,
                    "score_v3":6.5,
                    "score_custom":"None",
                    "epss":0.03568,
                    "exploit_code_maturity":"proof_of_concept",
                    "note_custom":"None",
                    "exploitable":true,
                    "technologies":[
                        {
                            "vendor":"bzip",
                            "product":"bzip2"
                        },
                        {
                            "vendor":"python",
                            "product":"python"
                        }
                    ],
                    "cvss":{
                        "id":16778278,
                        "access_vector":"access_vector_network",
                        "access_complexity":"access_complexity_medium",
                        "authentication":"authentication_none",
                        "confidentiality_impact":"confidentiality_impact_none",
                        "integrity_impact":"integrity_impact_none",
                        "availability_impact":"availability_impact_partial"
                    },
                    "cvss_v3":{
                        "access_vector":"access_vector_network",
                        "access_complexity":"access_complexity_low",
                        "privileges_required":"privileges_required_none",
                        "user_interaction":"user_interaction_required",
                        "scope":"scope_unchanged",
                        "confidentiality_impact":"confidentiality_impact_none",
                        "integrity_impact":"integrity_impact_none",
                        "availability_impact":"availability_impact_high"
                    },
                    "cvss_custom":"None",
                    "cwe":{
                        "cwe_id":"NVD-CWE-Other",
                        "capecs":[

                        ],
                        "attacks":[

                        ]
                    }
                },
                ...
            ]
        """

        path = "/api/v3/vulnerabilities/cve_announcements"

        if "per_page" not in params:
            demisto.info('Fetching 500 CVEs per request by default. You can override this by specifying the "per_page" parameter')
            params["per_page"] = 500

        if "hard_limit" not in params:
            demisto.info(
                "Fetching up to 2000 CVEs by default, in order to limit "
                "performance issues. You can override this by specifying the "
                '"hard_limit" parameter'
            )
            params["hard_limit"] = 2000

        # if a page is given in params, we will fetch only the provided page
        if "page" in params:
            response = self._http_request(method="GET", url_suffix=path, params=params)
        # if no page is given, we will fetch all the cves
        else:
            demisto.info('Fetching all CVEs by default. You can override this by specifying the "page" parameter')
            response = []
            # we start at page 1
            curr_page = 1
            params["page"] = curr_page
            raw_response = self._http_request(
                method="GET",
                url_suffix=path,
                resp_type="response",  # used to get the headers of the response
                params=params,
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers["x-per-page"])
            paginate_total_results = int(raw_response.headers["x-total"])
            demisto.debug(
                f'Fetched page {curr_page} of '
                f'{paginate_total_results//paginate_objperpage} '
                f'(total results: {paginate_total_results}) '
                f'- hard limit for results: {params["hard_limit"]}'
            )
            # we now iterate through all pages
            while (curr_page * paginate_objperpage < paginate_total_results) and (
                curr_page * paginate_objperpage < int(params["hard_limit"])
            ):
                curr_page += 1
                params["page"] = curr_page
                raw_response = self._http_request(
                    method="GET",
                    url_suffix=path,
                    resp_type="response",  # used to get the headers of the response
                    params=params,
                )
                response += raw_response.json()
                demisto.debug(
                    f'Fetched page {curr_page} of '
                    f'{paginate_total_results//paginate_objperpage} '
                    f'(total results: {paginate_total_results}) '
                    f'- hard limit for results: {params["hard_limit"]}'
                )

        return response

    def get_one_cve(self, params):
        """
        Send the request for fetch_cve_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.
            {
                "content":"Microsoft Outlook Remote Code Execution Vulnerability",
                "cve_code":"CVE-2024-21413",
                "last_modified":"2024-05-28T22:15:34.720Z",
                "level":"level_critical",
                "published":"2024-02-13T17:16:00.137Z",
                "score":9.8,
                "score_v2":"None",
                "score_v3":9.8,
                "score_custom":"None",
                "epss":0.00586,
                "exploit_code_maturity":"proof_of_concept",
                "note_custom":"None",
                "exploitable":true,
                "servers":[
                    {
                        "id":1257,
                        "hostname":"WIN-4DBFESNOHB",
                        "os":{
                            "key":"windows_2019",
                            "name":"Windows Server 2019",
                            "arch":"AMD64",
                            "eol":"2029-01-09",
                            "short_name":"Windows 2019",
                            "type":"Os::Windows"
                        },
                        "updates":[
                            {
                            "id":442580,
                            "ignored":false,
                            "patchable":false,
                            "target":{
                                "vendor":"None",
                                "product":"Microsoft Office 365 ProPlus - en-us",
                                "type":"Packages::WinApp",
                                "version":"16130.20990"
                            },
                            "current":{
                                "vendor":"None",
                                "product":"Microsoft Office 365 ProPlus - en-us",
                                "type":"Packages::WinApp",
                                "version":"11328.20512"
                            }
                            }
                        ],
                        "detected_at":"2024-02-13T23:08:32.113Z",
                        "active":true,
                        "ignored":false,
                        "fixed_at":"None",
                        "environmental_score":9.3,
                        "prioritized":true
                    },
                    ...
                ],
                "technologies":[
                    {
                        "vendor":"microsoft",
                        "product":"365_apps"
                    },
                    ...
                ],
                "cvss":"None",
                "cvss_v3":{
                    "access_vector":"access_vector_network",
                    "access_complexity":"access_complexity_low",
                    "privileges_required":"privileges_required_none",
                    "user_interaction":"user_interaction_none",
                    "scope":"scope_unchanged",
                    "confidentiality_impact":"confidentiality_impact_high",
                    "integrity_impact":"integrity_impact_high",
                    "availability_impact":"availability_impact_high"
                },
                "cvss_custom":"None",
                "cwe":{
                    "cwe_id":"NVD-CWE-noinfo",
                    "capecs":[

                    ],
                    "attacks":[

                    ]
                },
                "security_announcements":[
                    {
                        "sa_code":"CVE-2024-21413",
                        "type":"SecurityAnnouncements::MicrosoftCve",
                        "link":"https://msrc.microsoft.com/[...]/CVE-2024-21413",
                        "level":"level_unknown"
                    },
                    ...
                ],
                "references":[
                    {
                        "code":"CERT-EU-2024-019",
                        "source":"CERT_EU",
                        "url":"https://cert.europa.eu/publications/security-advisories/2024-019/"
                    },
                    ...
                ]
                }
        """

        if "cve_code" not in params:
            raise DemistoException("Please provide a CVE cve_code")

        path = "/api/v3/vulnerabilities/cve_announcements/" + str(params["cve_code"])

        response = self._http_request(method="GET", url_suffix=path, params=params)

        return response

    def get_assets(self, params):
        """
        Send the request for list_assets_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            List: The response.
            [
                {
                    "id": 912,
                    "hostname": "ip-192-168-0-214",
                    "description": "Lorem ipsum dolor sit ame",
                    "last_communication": "2020-11-10T16:36:29.000+01:00",
                    "reboot_required": null,
                    "boot_at": null,
                    "category": "server",
                    "created_at": "2017-01-24T09:33:08.000+01:00",
                    "environment": {
                        "id": 34,
                        "name": "High",
                        "confidentiality_requirement": "confidentiality_requirement_high",
                        "integrity_requirement": "integrity_requirement_high",
                        "availability_requirement": "availability_requirement_high",
                        "ceiling_cvss_v3": null
                    },
                    "os": {
                        "key": "ubuntu_1404_64",
                        "name": "Ubuntu 14.04 LTS",
                        "arch": "x86_64",
                        "eol": "2019-04-01",
                        "short_name": "Ubuntu 14.04",
                        "type": "Os::Ubuntu"
                    },
                    "groups": [
                        {
                            "id": 617,
                            "name": "ENV_PRODUCTION",
                            "description": null,
                            "color": "#12AFCB"
                        },
                        ...
                    ]
                },...
            ]
        """

        path = "/api/v3/vulnerabilities/servers"

        # if a page is given in params, we will fetch only the provided page
        if "page" in params:
            response = self._http_request(method="GET", url_suffix=path, params=params)
        # if no page is given, we will fetch all the assets
        else:
            demisto.info('Fetching all CVEs by default. You can override this by specifying the "page" parameter')
            response = []
            # we start at page 1
            curr_page = 1
            params["page"] = curr_page
            raw_response = self._http_request(
                method="GET",
                url_suffix=path,
                resp_type="response",  # used to get the headers of the response
                params=params,
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers["x-per-page"])
            paginate_total_results = int(raw_response.headers["x-total"])
            # we now iterate through all pages
            while curr_page * paginate_objperpage < paginate_total_results:
                curr_page += 1
                params["page"] = curr_page
                raw_response = self._http_request(
                    method="GET",
                    url_suffix=path,
                    resp_type="response",  # used to get the headers of the response
                    params=params,
                )
                response += raw_response.json()

        return response

    def get_one_asset(self, params, namespace="vulnerabilities"):
        """
        Send the request for fetch_asset_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.
            {
                "id": 1197,
                "hostname": "WIN-GNVEC8UIKUD",
                "description": "Machine Windows de démonstration",
                "last_communication": "2019-09-13T09:14:34.000Z",
                "reboot_required": false,
                "addresses": [
                    "WIN-GNVEC8UIKUD",
                    "127.0.0.1"
                ],
                "updates_count": 9,
                "boot_at": null,
                "category": "server",
                "created_at": "2019-09-10T14:59:23.000Z",
                "cve_announcements_count": 1684,
                "analyzed_at": "2022-06-08T07:57:47.440Z",
                "prioritized_cve_announcements_count": 624,
                "status": "server_vulnerable",
                "cve_announcements": [
                    {
                    "cve_code": "CVE-2024-4775",
                    "score": null,
                    "environmental_score": null,
                    "epss": null,
                    "ignored": false,
                    "active": true,
                    "detected_at": "2024-05-14T14:42:47.842Z",
                    "fixed_at": null,
                    "published": "2024-05-14T16:15:15.890Z",
                    "prioritized": false
                    },
                    ...
                ],
                "security_issues": [
                    {
                    "id": 44,
                    "sid": "PENTEST-2021-REF-1",
                    "level": "level_critical",
                    "title": "Résultat d'un test d'intrusion",
                    "description": "Description technique du résultat de test d'intrusion",
                    "editable": true,
                    "detected_at": "2020-11-12T14:56:17.241Z",
                    "status": "ignored"
                    },
                    ...
                ],
                "os": {
                    "key": "windows_2012_r2",
                    "name": "Windows Server 2012 R2",
                    "arch": null,
                    "eol": "2023-10-10",
                    "short_name": "Windows 2012 R2",
                    "type": "Os::Windows"
                },
                "environment": {
                    "id": 34,
                    "name": "High",
                    "confidentiality_requirement": "confidentiality_requirement_high",
                    "integrity_requirement": "integrity_requirement_high",
                    "availability_requirement": "availability_requirement_high",
                    "ceiling_cvss_v3": null
                },
                "groups": [
                    {
                    "id": 807,
                    "name": "APP_Web",
                    "description": null,
                    "color": "#12AFCB"
                    },
                    ...
                ],
                "compliance_repositories": [
                        {
                            "id": 18,
                            "name": "Security_Best_Practices",
                            "description": null,
                            "color": "#336699"
                        }
                    ],
                "updates": [
                    {
                        "id": 428477,
                        "ignored": false,
                        "patchable": true,
                        "target": {
                            "vendor": null,
                            "product": "KB4041085",
                            "type": "Packages::Kb",
                            "version": "dc4eb637-5391-4ca8-8f08-98584d61effa"
                        },
                        "current": null,
                        "cve_announcements": [
                            "CVE-2015-2479",
                            "CVE-2015-2480",
                            "CVE-2015-2481",
                            "CVE-2017-0248",
                            "CVE-2017-0160"
                        ]
                    },
                    ...
                ]
                }
        """

        if "id" not in params:
            raise DemistoException("Please provide an asset ID")

        path = "/api/v3/" + str(namespace) + "/servers/" + str(params["id"])

        response = self._http_request(method="GET", url_suffix=path, params=params)

        return response

    def get_sysadmin_assets(self, params):
        """
        Retrieve servers from the /assets/servers route (a.k.a. \"Sysadmin\" view).
        Behaviour (pagination, logging) intentionally mirrors get_assets() but
        returns the raw payload from the /api/v3/assets/servers endpoint without
        any field normalization.
        """
        path = "/api/v3/assets/servers"

        # if a page is given in params, we will fetch only the provided page
        if "page" in params:
            response = self._http_request(method="GET", url_suffix=path, params=params)
        # if no page is given, we will fetch all the assets
        else:
            demisto.info('Fetching all Sysadmin Assets by default. You can override this by specifying the "page" parameter')
            response = []
            curr_page = 1
            params["page"] = curr_page
            raw_response = self._http_request(
                method="GET",
                url_suffix=path,
                resp_type="response",  # used to get the headers of the response
                params=params,
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers.get("x-per-page", len(response) or 1))
            paginate_total_results = int(raw_response.headers.get("x-total", len(response)))
            while curr_page * paginate_objperpage < paginate_total_results:
                curr_page += 1
                params["page"] = curr_page
                raw_response = self._http_request(
                    method="GET",
                    url_suffix=path,
                    resp_type="response",
                    params=params,
                )
                response += raw_response.json()

        return response

    def get_sysadmin_one_asset(self, params):
        """
        Retrieve a single server from the /assets/servers/<ID> route (Sysadmin view).
        Expects: params['id'] (int).
        """

        path = f"/api/v3/assets/servers/{str(params.get('id'))}"
        response = self._http_request(method="GET", url_suffix=path, params=params)
        return response

    def get_compliance_assets(self, params):
        """
        Retrieve assets from the /compliance/assets route (Compliance view).
        Behaviour mirrors get_assets() but returns native /compliance payloads.
        """
        path = "/api/v3/compliance/assets"

        # if a page is given in params, we will fetch only the provided page
        if "page" in params:
            response = self._http_request(method="GET", url_suffix=path, params=params)
        # if no page is given, we will fetch all the assets
        else:
            demisto.info('Fetching all Compliance Assets by default. You can override this by specifying the "page" parameter')
            response = []
            curr_page = 1
            params["page"] = curr_page
            raw_response = self._http_request(
                method="GET",
                url_suffix=path,
                resp_type="response",
                params=params,
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers.get("x-per-page", len(response) or 1))
            paginate_total_results = int(raw_response.headers.get("x-total", len(response)))
            while curr_page * paginate_objperpage < paginate_total_results:
                curr_page += 1
                params["page"] = curr_page
                raw_response = self._http_request(
                    method="GET",
                    url_suffix=path,
                    resp_type="response",
                    params=params,
                )
                response += raw_response.json()

        return response

    def get_compliance_one_asset(self, params):
        """
        Retrieve a single asset from the /compliance/servers/<ID> route (Compliance view).
        Expects: params['id'] (int).
        Returns: JSON payload from the /api/v3/compliance/servers/{id} endpoint.
        """

        path = f"/api/v3/compliance/servers/{params.get('id')}"
        response = self._http_request(method="GET", url_suffix=path, params=params)
        return response

    def upload_declarative_data(self, output_text: str, timeout: int = 90):
        """
        Upload Declarative Data (airgap scan result text) via v2 endpoint.
        Mirrors the official CLI behaviour.
        """
        path = "/api/v2/cbw_scans/scripts"
        return self._http_request(
            method="POST",
            url_suffix=path,
            json_data={"output": output_text},
            timeout=timeout,
        )

    def get_declarative_data(self, server_id: int):
        """
        Read Declarative Data for a server (GET /api/v3/servers/{id}/info).
        Returns the raw text blob.
        """
        path = f"/api/v3/servers/{server_id}/info"
        return self._http_request(method="GET", url_suffix=path, resp_type="text")

    def get_security_issues(self, params):
        """
        Send the request for list_security_issues_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            List: The response.
            [
                {
                    "id": 44,
                    "sid": "PENTEST-2021-REF-1",
                    "level": "level_critical",
                    "title": "Résultat d'un test d'intrusion",
                    "description": "Description technique du résultat de test d'intrusion",
                    "editable": true
                },
                ...
            ]
        """

        path = "/api/v3/security_issues"

        if "per_page" not in params:
            demisto.info(
                "Fetching 500 Security Issues per request by default. "
                'You can override this by specifying the "per_page" parameter'
            )
            params["per_page"] = 500

        # if a page is given in params, we will fetch only the provided page
        if "page" in params:
            response = self._http_request(method="GET", url_suffix=path, params=params)
        # if no page is given, we will fetch all the Security Issues
        else:
            demisto.info('Fetching all Security Issues by default. You can override this by specifying the "page" parameter')
            response = []
            # we start at page 1
            curr_page = 1
            params["page"] = curr_page
            raw_response = self._http_request(
                method="GET",
                url_suffix=path,
                resp_type="response",  # used to get the headers of the response
                params=params,
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers["x-per-page"])
            paginate_total_results = int(raw_response.headers["x-total"])
            demisto.debug(f"Fetched page {curr_page} of \
                {paginate_total_results//paginate_objperpage} \
                (total results: {paginate_total_results})")
            # we now iterate through all pages
            while curr_page * paginate_objperpage < paginate_total_results:
                curr_page += 1
                params["page"] = curr_page
                raw_response = self._http_request(
                    method="GET",
                    url_suffix=path,
                    resp_type="response",  # used to get the headers of the response
                    params=params,
                )
                response += raw_response.json()
                demisto.debug(
                    f"Fetched page {curr_page} of "
                    f"{paginate_total_results//paginate_objperpage} "
                    f"(total results: {paginate_total_results})"
                )

        return response

    def get_one_security_issue(self, params):
        """
        Send the request for fetch_security_issue_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.

        """

        if "id" not in params:
            raise DemistoException("Please provide a Security Issues ID")

        path = "/api/v3/security_issues/" + str(params["id"])

        response = self._http_request(method="GET", url_suffix=path, params=params)

        return response

    def ping(self):
        """
        Send the request to ping the Cyberwatch scanner.
        Args:
            None.
        Returns:
            Dict: The response.
        """

        path = "/api/v3/ping"
        response = self._http_request(method="GET", url_suffix=path)

        return response


def test_module(client: Client) -> str:
    """
    Lists queries and return the processed results.
    Args:
        client (Client): The Cyberwatch client object.
        type (str): query time to filter by.
    Returns:
        Dict: The response from the server.
        str: The processed human readable.
        Dict: The relevant section from the response.
    """
    try:
        client.ping()
        return "ok"
    except Exception:
        raise Exception("Authorization Error: please check your API Key and Secret Key")


""" HELPERS """


def _build_declarative_payload(hostname: str, data_json: str) -> str:
    """
    Build a minimal Declarative Data text blob from hostname + JSON string.
    Example:
        hostname=Test
        data_json='{"metadata": "metadate", "foo": "bar"}'
    =>
        HOSTNAME:Test
        METADATA:metadate
        FOO:bar
    """
    try:
        extra = json.loads(data_json) if data_json else {}
    except Exception as e:
        raise DemistoException(f"Invalid JSON in 'data' argument: {e!s}")

    lines = [f"HOSTNAME:{hostname}"]
    for k, v in extra.items():
        # simple upper-case key mapping
        lines.append(f"{str(k).upper()}:{v}")
    return "\n".join(lines) + "\n"


def send_declarative_data_asset_command(client: Client, args: Dict[str, Any]):
    """
    Upload Declarative Data to Cyberwatch.
    Required args: hostname (str), data (JSON string)
    """
    hostname: str = cast(str, args["hostname"])

    data_json: str = str(args.get("data", "{}"))

    # Pre‑check to avoid creating a new server
    matches = client.get_assets({"hostname": hostname, "per_page": 1, "page": 1})
    if not matches:
        raise DemistoException(f"Hostname '{hostname}' not found in Cyberwatch. Upload cancelled to avoid auto creation.")
    server_id_known: int = matches[0]["id"]

    blob = _build_declarative_payload(hostname, data_json)
    result: dict[str, Any] = client.upload_declarative_data(blob) or {}
    result.setdefault("matched_server_id", server_id_known)

    readable = {
        "hostname": hostname,
        "server_id": result.get("server_id"),
        "matched_server_id": server_id_known,
        "status": result.get("status") or "submitted",
        "message": result.get("message") or "",
    }

    return CommandResults(
        outputs=result,
        outputs_prefix="Cyberwatch.DeclarativeDataUpload",
        raw_response=result,
        readable_output=tableToMarkdown(
            "Cyberwatch Declarative Data Upload",
            readable,
            ["hostname", "server_id", "matched_server_id", "status", "message"],
            removeNull=True,
        ),
    )


def get_declarative_data_asset_command(client: Client, args: Dict[str, Any]):
    """
    Retrieve Declarative Data for a server.
    Required: id
    """
    server_id: int = int(args["id"])
    raw_text = client.get_declarative_data(int(server_id))  # this is a string now

    readable_output = f"### Cyberwatch Declarative Data (server {server_id})\n```\n{raw_text}\n```"

    return CommandResults(
        outputs={"id": int(server_id), "raw": raw_text},
        outputs_prefix="Cyberwatch.DeclarativeData",
        raw_response=raw_text,
        readable_output=readable_output,
    )


def iso8601_to_human(iso8601_str, default_value=""):
    """
    Convert ISO8601 string to human readable date time.
    Args:
        iso8601_str (str): iso 8601 string.
        default_value (str): the default return value
    Returns:
        str: human readable date time string based on Cortex Python Convention.
    """
    if iso8601_str:
        # Sometimes, Cyberwatch API sends the datetime in a Zulu format
        # We need to convert it to a datetime object
        if iso8601_str[-1] == "Z":
            return datetime.strptime(iso8601_str, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%dT%H:%M:%S")
        else:
            # The string is indeed in ISO8601 format
            dt = datetime.fromisoformat(iso8601_str)
            # Convert to UTC
            dt_utc = dt - (dt.utcoffset() or timedelta())
            # Format to the desired human-readable format
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%S")

    return default_value


def to_utc(dt_str: str) -> datetime:
    """
    Converts an ISO 8601 or Z date string to a UTC **aware** datetime.
    If the string has no timezone, UTC is assumed.
    """
    dt = parse_iso(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _as_list(value):
    """Allows accepting either a single value or a JSON list."""
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


def cve_passes_filters(cve: dict, filt: dict) -> bool:
    """
    Returns True if the CVE satisfies all the provided filters.
    Args:
        cve (dict): A dictionary representing the CVE details. Expected keys include:
            - "active" (bool): Indicates if the CVE is active.
            - "ignored" (bool): Indicates if the CVE is ignored.
            - "prioritized" (bool): Indicates if the CVE is prioritized.
            - "cve_code" (str): The CVE identifier.
            - "score" (float): The score of the CVE.
            - "epss" (float): The EPSS score of the CVE.
        filt (dict): A dictionary of filters to apply. Supported keys include:
            - "active" (bool): Filter by active status (default is True).
            - "ignored" (bool): Filter by ignored status (default is False).
            - "prioritized" (bool): Filter by prioritized status.
            - "cve_code" (str or list): Filter by specific CVE code(s).
            - "min_cvss" (float): Minimum CVSS score to include.
            - "min_epss" (float): Minimum EPSS score to include.
    Returns:
        bool: True if the CVE matches all the specified filters, False otherwise.
    """
    if filt.get("active", True) is False and cve.get("active", True) is False:
        return False
    if filt.get("active") is True and not cve.get("active", True):
        return False

    if filt.get("ignored", False) is False and cve.get("ignored", False):
        return False
    if filt.get("ignored") is True and not cve.get("ignored", False):
        return False

    if "prioritized" in filt and cve.get("prioritized") != filt["prioritized"]:
        return False

    if (codes := _as_list(filt.get("cve_code"))) and cve["cve_code"] not in codes:
        return False

    # Scores numériques
    cvss = cve.get("score") or 0
    epss = cve.get("epss") or 0

    if (min_cvss := filt.get("min_cvss")) is not None and cvss < float(min_cvss):
        return False

    return not ((min_epss := filt.get("min_epss")) is not None and epss < float(min_epss))


def _initial_last_run(first_fetch: str) -> dict[str, Any]:
    """Return a fresh last-run dict when none is stored yet."""
    start_ms, _ = parse_date_range(first_fetch, to_timestamp=True)
    return {
        "last_success": int(start_ms / 1000),
        "cycle_start": int(datetime.now(timezone.utc).timestamp()),
        "server_id": None,
        "cve_id": None,
    }


def fetch_incidents(client: Client, params: dict[str, Any]) -> None:
    """
    Incremental incident fetch with a resumable cursor.

    The last-run object is stored directly as a dict:
        {
            "last_success": int,        # lower bound (inclusive)
            "cycle_start": int,         # upper bound (exclusive)
            "server_id": int | None,    # bookmark within assets
            "cve_id": str | None        # bookmark within CVEs
        }
    """
    first_fetch = params.get("first_fetch", "3 days")
    max_fetch = min(int(params.get("max_fetch", 200)), FETCH_LIMIT_MAX)

    asset_filters = json.loads(params.get("asset_filters", "{}") or "{}")
    cve_filters = json.loads(params.get("cve_filters", "{}") or '{"ignored": false}')

    # 1. Load / initialise cursor
    last_run: dict[str, Any] = demisto.getLastRun() or {}
    if not last_run:
        last_run = _initial_last_run(first_fetch)

    last_success_ts: int = last_run["last_success"]
    cycle_start_ts: int = last_run["cycle_start"] or int(datetime.now(timezone.utc).timestamp())
    resume_server_id: int | None = last_run.get("server_id")
    resume_cve_id: str | None = last_run.get("cve_id")

    # 2. Main fetch loop
    incidents: list[dict[str, Any]] = []
    hit_limit = False
    last_asset_id: int | None = None
    last_cve_code: str | None = None

    assets = client.get_assets(asset_filters)
    for asset in assets:
        # Fast-forward to the bookmarked asset (if any)
        if resume_server_id is not None and asset["id"] != resume_server_id:
            continue

        full_asset = client.get_one_asset({"id": asset["id"]})

        skipping_cves = resume_server_id == asset["id"] and resume_cve_id is not None
        for cve in full_asset.get("cve_announcements", []):
            if skipping_cves:
                if cve["cve_code"] == resume_cve_id:
                    skipping_cves = False
                continue

            detected_ts = int(to_utc(cve.get("detected_at")).timestamp())

            if detected_ts <= last_success_ts or detected_ts > cycle_start_ts:
                continue
            if not cve_passes_filters(cve, cve_filters):
                continue

            incidents.append(
                {
                    "name": f"{cve['cve_code']} on {asset['hostname']}",
                    "occurred": datetime.utcfromtimestamp(detected_ts).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "rawJSON": json.dumps(
                        {
                            "cve": cve["cve_code"],
                            "score": cve["score"],
                            "environmental_score": cve.get("environmental_score"),
                            "epss": cve.get("epss"),
                            "ignored": cve.get("ignored", False),
                            "active": cve.get("active", True),
                            "detected_at": cve.get("detected_at"),
                            "prioritized": cve.get("prioritized", False),
                            "server_id": asset["id"],
                        }
                    ),
                }
            )

            last_asset_id = asset["id"]
            last_cve_code = cve["cve_code"]

            if len(incidents) >= max_fetch:
                hit_limit = True
                break

        # After the first asset is processed, clear resume markers
        resume_server_id = None
        resume_cve_id = None

        if hit_limit:
            break

    # 3. Persist new cursor
    if hit_limit:
        # Still mid-cycle: keep last_success as-is, bookmark position.
        new_last_run = {
            "last_success": last_success_ts,
            "cycle_start": cycle_start_ts,
            "server_id": last_asset_id,
            "cve_id": last_cve_code,
        }
    else:
        # Finished the cycle: advance last_success and clear bookmarks.
        new_last_run = {
            "last_success": cycle_start_ts,
            "cycle_start": None,
            "server_id": None,
            "cve_id": None,
        }

    demisto.incidents(incidents)
    demisto.setLastRun(new_last_run)


def list_cves_command(client: Client, args: Dict[str, Any]):
    """
    List CVEs.
    Args:
        client (Client): The Cyberwatch client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results, response, human readable section, context entries.
    """

    cves = client.get_cves(args)

    if len(cves) == 0:
        raise DemistoException("No CVEs found")

    readable_headers = ["cve_code", "content", "published", "last_modified", "level", "score", "epss", "cvss_v3"]

    readable_cves = [
        {
            "cve_code": cve["cve_code"],
            "content": cve["content"],
            "published": iso8601_to_human(cve["published"]),
            "last_modified": iso8601_to_human(cve["last_modified"]),
            "level": cve["level"],
            "score": str(cve["score"]),
            "epss": str(cve["epss"]),
            "cvss_v3": cve["cvss_v3"],
        }
        for cve in cves
    ]

    return CommandResults(
        outputs=createContext(cves, removeNull=True),
        outputs_prefix="Cyberwatch.CVE",
        raw_response=cves,
        outputs_key_field="cve_code",
        readable_output=tableToMarkdown(
            "Cyberwatch CVEs",
            readable_cves,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
            date_fields=["published", "last_modified"],
        ),
    )


def fetch_cve_command(client: Client, args: Dict[str, Any]):
    """
    List one CVE with all its details.
    Args:
        client (Client): The Cyberwatch client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results, response, human readable section, context entries.
    """

    cve = client.get_one_cve(args)

    if len(cve) == 0:
        raise DemistoException("CVE not found")

    readable_headers = [
        "cve_code",
        "content",
        "published",
        "last_modified",
        "level",
        "score",
        "epss",
        "cvss_v3",
        "servers_count",
        "security_announcements_count",
    ]

    readable_cve = {
        "cve_code": cve["cve_code"],
        "content": cve["content"],
        "published": iso8601_to_human(cve["published"]),
        "last_modified": iso8601_to_human(cve["last_modified"]),
        "level": cve["level"],
        "score": str(cve["score"]),
        "epss": str(cve["epss"]),
        "cvss_v3": cve["cvss_v3"],
        "servers_count": str(len(cve["servers"])),
        "security_announcements_count": str(len(cve["security_announcements"])),
    }

    return CommandResults(
        outputs=createContext(cve, removeNull=True),
        outputs_prefix="Cyberwatch.CVE",
        raw_response=cve,
        outputs_key_field="cve_code",
        readable_output=tableToMarkdown(
            "Cyberwatch CVE",
            readable_cve,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
            date_fields=["published", "last_modified"],
        ),
    )


def list_assets_command(client: Client, args: Dict[str, Any]):
    """
    List assets.
    Args:
        client (Client): The Cyberwatch client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results, response, human readable section, context entries.
    """

    assets = client.get_assets(args)

    if len(assets) == 0:
        raise DemistoException("No assets found")

    readable_headers = [
        "id",
        "hostname",
        "reboot_required",
        "category",
        "last_communication",
        "os",
        "environment",
        "groups",
        "cve_announcements_count",
        "prioritized_cve_announcements_count",
        "updates_count",
        "compliance_repositories",
    ]

    readable_assets = [
        {
            "id": str(asset["id"]),
            "hostname": asset["hostname"],
            "reboot_required": str(asset["reboot_required"]),
            "category": asset["category"],
            "last_communication": iso8601_to_human(asset["last_communication"]),
            "os": asset["os"].get("name") if asset["os"] else None,
            "environment": asset["environment"].get("name") if asset["environment"] else None,
            "groups": [g.get("name") for g in asset["groups"]],
            "cve_announcements_count": str(asset["cve_announcements_count"]),
            "prioritized_cve_announcements_count": str(asset["prioritized_cve_announcements_count"]),
            "updates_count": str(asset["updates_count"]),
            "compliance_repositories": [c.get("name") for c in asset["compliance_repositories"]],
        }
        for asset in assets
    ]

    return CommandResults(
        outputs=createContext(assets, removeNull=True),
        outputs_prefix="Cyberwatch.Asset",
        raw_response=assets,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Assets",
            readable_assets,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
            date_fields=["last_communication"],
        ),
    )


def fetch_asset_command(client: Client, args: Dict[str, Any]):
    """
    Fetch one asset with all its data from the /vulnerabilities namespace
    Args:
        client (Client): The Cyberwatch client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results, response, human readable section, context entries.
    """

    asset = client.get_one_asset(args)

    if len(asset) == 0:
        raise DemistoException("Asset not found")

    readable_headers = [
        "id",
        "hostname",
        "description",
        "reboot_required",
        "category",
        "last_communication",
        "os",
        "environment",
        "groups",
        "cve_announcements_count",
        "prioritized_cve_announcements_count",
        "updates_count",
        "compliance_repositories",
    ]

    readable_asset = {
        "id": str(asset["id"]),
        "hostname": asset["hostname"],
        "description": str(asset["description"]),
        "reboot_required": str(asset["reboot_required"]),
        "category": str(asset["category"]),
        "last_communication": iso8601_to_human(asset["last_communication"]),
        "os": asset["os"].get("name") if asset["os"] else None,
        "environment": asset["environment"].get("name"),
        "groups": [g.get("name") for g in asset["groups"]],
        "cve_announcements_count": str(asset["cve_announcements_count"]),
        "prioritized_cve_announcements_count": str(asset["prioritized_cve_announcements_count"]),
        "updates_count": str(asset["updates_count"]),
        "compliance_repositories": [c.get("name") for c in asset["compliance_repositories"]],
    }

    return CommandResults(
        outputs=createContext(asset, removeNull=False),
        outputs_prefix="Cyberwatch.Asset",
        raw_response=asset,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Asset",
            readable_asset,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
            date_fields=["last_communication"],
        ),
    )


def fetch_asset_full_command(client: Client, args: Dict[str, Any]):
    """
    Fetch one asset with all its data from both /vulnerabilities and /assets namespaces
    Args:
        client (Client): The Cyberwatch client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results, response, human readable section, context entries.
    """

    # Fetch data from namespaces vulns and assets
    asset_vulns = client.get_one_asset(args)
    asset_additional_details = client.get_one_asset(args, namespace="assets")

    # Merge data
    asset = {**asset_vulns, **asset_additional_details}

    if len(asset) == 0:
        raise DemistoException("Asset not found")

    readable_headers = [
        "id",
        "hostname",
        "description",
        "reboot_required",
        "category",
        "last_communication",
        "os",
        "environment",
        "groups",
        "cve_announcements_count",
        "prioritized_cve_announcements_count",
        "updates_count",
        "compliance_repositories",
        "packages_count",
        "metadata_count",
        "services_count",
        "ports_count",
        "connector_type",
    ]

    readable_asset = {
        "id": str(asset["id"]),
        "hostname": asset["hostname"],
        "description": str(asset["description"]),
        "reboot_required": str(asset["reboot_required"]),
        "category": str(asset["category"]),
        "last_communication": iso8601_to_human(asset["last_communication"]),
        "os": asset["os"].get("name") if asset["os"] else None,
        "environment": asset["environment"].get("name"),
        "groups": [g.get("name") for g in asset["groups"]],
        "cve_announcements_count": str(asset["cve_announcements_count"]),
        "prioritized_cve_announcements_count": str(asset["prioritized_cve_announcements_count"]),
        "updates_count": str(asset["updates_count"]),
        "compliance_repositories": [c.get("name") for c in asset["compliance_repositories"]],
        "packages_count": str(len(asset["packages"])),
        "metadata_count": str(len(asset["metadata"])),
        "services_count": str(len(asset["services"])),
        "ports_count": str(len(asset["ports"])),
        "connector_type": asset["connector"].get("type") if asset["connector"] else None,
    }

    return CommandResults(
        outputs=createContext(asset, removeNull=False),
        outputs_prefix="Cyberwatch.Asset",
        raw_response=asset,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Asset",
            readable_asset,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
            date_fields=["last_communication"],
        ),
    )


def list_security_issues_command(client: Client, args: Dict[str, Any]):
    """
    List security issues.
    Args:
        client (Client): The Cyberwatch client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results, response, human readable section, context entries.
    """

    secissues = client.get_security_issues(args)

    if len(secissues) == 0:
        raise DemistoException("No security issues found")

    readable_headers = ["id", "sid", "level", "title", "description"]

    readable_secissues = [
        {
            "id": str(secissue["id"]),
            "sid": str(secissue["sid"]),
            "level": str(secissue["level"]),
            "title": str(secissue["title"]),
            "description": str(secissue["description"]),
        }
        for secissue in secissues
    ]

    return CommandResults(
        outputs=createContext(secissues, removeNull=True),
        outputs_prefix="Cyberwatch.SecurityIssue",
        raw_response=secissues,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Security Issues", readable_secissues, readable_headers, removeNull=False, is_auto_json_transform=True
        ),
    )


def fetch_security_issue_command(client: Client, args: Dict[str, Any]):
    """
    Fetch one security issue with all its data.
    Args:
        client (Client): The Cyberwatch client object.
        args (Dict): demisto.args() object.
    Returns:
        CommandResults: command results, response, human readable section, context entries.
    """

    secissue = client.get_one_security_issue(args)

    if len(secissue) == 0:
        raise DemistoException("Security Issue not found")

    readable_headers = ["id", "sid", "title", "description", "servers_count", "cve_announcements_count"]

    readable_secissue = {
        "id": str(secissue["id"]),
        "sid": str(secissue["sid"]),
        "title": str(secissue["title"]),
        "description": str(secissue["description"]),
        "servers_count": str(len(secissue["servers"])),
        "cve_announcements_count": str(len(secissue["cve_announcements"])),
    }

    return CommandResults(
        outputs=createContext(secissue, removeNull=False),
        outputs_prefix="Cyberwatch.SecurityIssue",
        raw_response=secissue,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Security Issue", readable_secissue, readable_headers, removeNull=False, is_auto_json_transform=True
        ),
    )


def list_sysadmin_assets_command(client: Client, args: Dict[str, Any]):
    assets = client.get_sysadmin_assets(args)

    if len(assets) == 0:
        return_results("No Sysadmin assets found.")

    # minimal readable table: id, hostname, last_communication, category
    readable_headers = ["id", "hostname", "last_communication", "category"]
    readable_assets = [
        {
            "id": str(a.get("id")),
            "hostname": a.get("hostname"),
            "last_communication": iso8601_to_human(a.get("last_communication")),
            "category": a.get("category"),
        }
        for a in assets
    ]

    return CommandResults(
        outputs=createContext(assets, removeNull=True),
        outputs_prefix="Cyberwatch.SysadminAsset",
        raw_response=assets,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Sysadmin Assets",
            readable_assets,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
            date_fields=["last_communication"],
        ),
    )


def fetch_sysadmin_asset_command(client: Client, args: Dict[str, Any]):
    asset = client.get_sysadmin_one_asset(args)

    if len(asset) == 0:
        return_results(f"Sysadmin asset with {args.get('id')} not found.")

    readable_headers = [
        "id",
        "hostname",
        "description",
        "last_communication",
        "category",
        "deploying_period_id",
        "rebooting_period_id",
        "policy_id",
        "ignoring_policy_id",
    ]
    readable_asset = {
        "id": str(asset.get("id")),
        "hostname": asset.get("hostname"),
        "description": str(asset.get("description")),
        "last_communication": iso8601_to_human(asset.get("last_communication")),
        "category": str(asset.get("category")),
        "deploying_period_id": str(asset.get("deploying_period_id")),
        "rebooting_period_id": str(asset.get("rebooting_period_id")),
        "policy_id": str(asset.get("policy_id")),
        "ignoring_policy_id": str(asset.get("ignoring_policy_id")),
    }

    return CommandResults(
        outputs=createContext(asset, removeNull=False),
        outputs_prefix="Cyberwatch.SysadminAsset",
        raw_response=asset,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Sysadmin Asset",
            readable_asset,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
            date_fields=["last_communication"],
        ),
    )


def list_compliance_assets_command(client: Client, args: Dict[str, Any]):
    assets = client.get_compliance_assets(args)

    if len(assets) == 0:
        return_results("No Compliance assets found.")

    readable_headers = ["id", "hostname", "status", "compliance_rules_failed_count", "compliance_rules_succeed_count"]
    readable_assets = [
        {
            "id": str(a.get("id")),
            "hostname": a.get("hostname"),
            "status": a.get("status"),
            "compliance_rules_failed_count": str(a.get("compliance_rules_failed_count")),
            "compliance_rules_succeed_count": str(a.get("compliance_rules_succeed_count")),
        }
        for a in assets
    ]

    return CommandResults(
        outputs=createContext(assets, removeNull=True),
        outputs_prefix="Cyberwatch.ComplianceAsset",
        raw_response=assets,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Compliance Assets",
            readable_assets,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
        ),
    )


def fetch_compliance_asset_command(client: Client, args: Dict[str, Any]):
    asset = client.get_compliance_one_asset(args)

    if len(asset) == 0:
        return_results(f"Compliance asset with {args.get('id')} not found.")

    readable_headers = [
        "id",
        "hostname",
        "status",
        "compliance_rules_count",
        "compliance_rules_failed_count",
        "compliance_rules_succeed_count",
        "compliance_repositories",
    ]
    readable_asset = {
        "id": str(asset.get("id")),
        "hostname": asset.get("hostname"),
        "status": asset.get("status"),
        "compliance_rules_count": str(asset.get("compliance_rules_count")),
        "compliance_rules_failed_count": str(asset.get("compliance_rules_failed_count")),
        "compliance_rules_succeed_count": str(asset.get("compliance_rules_succeed_count")),
        "compliance_repositories": [c.get("name") for c in asset.get("compliance_repositories", [])],
    }

    return CommandResults(
        outputs=createContext(asset, removeNull=False),
        outputs_prefix="Cyberwatch.ComplianceAsset",
        raw_response=asset,
        outputs_key_field="id",
        readable_output=tableToMarkdown(
            "Cyberwatch Compliance Asset",
            readable_asset,
            readable_headers,
            removeNull=False,
            is_auto_json_transform=True,
        ),
    )


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    verify_ssl = not params.get("unsecure", False)
    proxy = params.get("proxy", False)
    access_key = params.get("api_access_key")
    secret_key = params.get("api_secret_key")
    base_url = params.get("master_scanner_url")

    demisto.info(f"Executing command {command}")

    # convert params provided as list to actual lists
    for key in args:
        if "[]" in key:
            args[key] = argToList(args[key])

    command_dict: Dict[str, Callable] = {
        "test-module": test_module,
        "cyberwatch-list-assets": list_assets_command,
        "cyberwatch-fetch-asset": fetch_asset_command,
        "cyberwatch-fetch-asset-fulldetails": fetch_asset_full_command,
        "cyberwatch-list-cves": list_cves_command,
        "cyberwatch-fetch-cve": fetch_cve_command,
        "cyberwatch-list-securityissues": list_security_issues_command,
        "cyberwatch-fetch-securityissue": fetch_security_issue_command,
        "cyberwatch-list-sysadmin-assets": list_sysadmin_assets_command,
        "cyberwatch-fetch-sysadmin-asset": fetch_sysadmin_asset_command,
        "cyberwatch-list-compliance-assets": list_compliance_assets_command,
        "cyberwatch-fetch-compliance-asset": fetch_compliance_asset_command,
        "cyberwatch-send-declarative-data-asset": send_declarative_data_asset_command,
        "cyberwatch-get-declarative-data-asset": get_declarative_data_asset_command,
    }

    try:
        client = Client(base_url=base_url, verify=verify_ssl, auth=(access_key, secret_key), proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command == "fetch-incidents":
            fetch_incidents(client, params)
        else:
            return_results(command_dict[command](client, args))
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
