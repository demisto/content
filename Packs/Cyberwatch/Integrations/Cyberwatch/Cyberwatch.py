import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import urllib3
from datetime import datetime, timedelta
from typing import Any
from collections.abc import Callable

# disable insecure warnings
urllib3.disable_warnings()


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

        path = '/api/v3/vulnerabilities/cve_announcements'

        if 'per_page' not in params:
            demisto.info('Fetching 500 CVEs per request by default. '
                         'You can override this by specifying the "per_page" parameter')
            params['per_page'] = 500

        if 'hard_limit' not in params:
            demisto.info('Fetching up to 2000 CVEs by default, in order to limit '
                         'performance issues. You can override this by specifying the '
                         '"hard_limit" parameter')
            params['hard_limit'] = 2000

        # if a page is given in params, we will fetch only the provided page
        if 'page' in params:
            response = self._http_request(
                method='GET',
                url_suffix=path,
                params=params
            )
        # if no page is given, we will fetch all the cves
        else:
            demisto.info('Fetching all CVEs by default. '
                         'You can override this by specifying the "page" parameter')
            response = []
            # we start at page 1
            curr_page = 1
            params['page'] = curr_page
            raw_response = self._http_request(
                method='GET',
                url_suffix=path,
                resp_type='response',  # used to get the headers of the response
                params=params
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers['x-per-page'])
            paginate_total_results = int(raw_response.headers['x-total'])
            demisto.debug(f'Fetched page {curr_page} of '
                          f'{paginate_total_results//paginate_objperpage} '
                          f'(total results: {paginate_total_results}) '
                          f'- hard limit for results: {params["hard_limit"]}')
            # we now iterate through all pages
            while (curr_page * paginate_objperpage < paginate_total_results) and \
                    (curr_page * paginate_objperpage < int(params['hard_limit'])):
                curr_page += 1
                params['page'] = curr_page
                raw_response = self._http_request(
                    method='GET',
                    url_suffix=path,
                    resp_type='response',  # used to get the headers of the response
                    params=params
                )
                response += raw_response.json()
                demisto.debug(f'Fetched page {curr_page} of '
                              f'{paginate_total_results//paginate_objperpage} '
                              f'(total results: {paginate_total_results}) '
                              f'- hard limit for results: {params["hard_limit"]}')

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

        if 'cve_code' not in params:
            raise DemistoException('Please provide a CVE cve_code')

        path = '/api/v3/vulnerabilities/cve_announcements/' + str(params['cve_code'])

        response = self._http_request(
            method='GET',
            url_suffix=path,
            params=params
        )

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

        path = '/api/v3/vulnerabilities/servers'

        # if a page is given in params, we will fetch only the provided page
        if 'page' in params:
            response = self._http_request(
                method='GET',
                url_suffix=path,
                params=params
            )
        # if no page is given, we will fetch all the assets
        else:
            demisto.info('Fetching all CVEs by default. '
                         'You can override this by specifying the "page" parameter')
            response = []
            # we start at page 1
            curr_page = 1
            params['page'] = curr_page
            raw_response = self._http_request(
                method='GET',
                url_suffix=path,
                resp_type='response',  # used to get the headers of the response
                params=params
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers['x-per-page'])
            paginate_total_results = int(raw_response.headers['x-total'])
            # we now iterate through all pages
            while curr_page * paginate_objperpage < paginate_total_results:
                curr_page += 1
                params['page'] = curr_page
                raw_response = self._http_request(
                    method='GET',
                    url_suffix=path,
                    resp_type='response',  # used to get the headers of the response
                    params=params
                )
                response += raw_response.json()

        return response

    def get_one_asset(self, params, namespace='vulnerabilities'):
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

        if 'id' not in params:
            raise DemistoException('Please provide an asset ID')

        path = '/api/v3/' + str(namespace) + '/servers/' + str(params['id'])

        response = self._http_request(
            method='GET',
            url_suffix=path,
            params=params
        )

        return response

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

        path = '/api/v3/security_issues'

        if 'per_page' not in params:
            demisto.info('Fetching 500 Security Issues per request by default. '
                         'You can override this by specifying the "per_page" parameter')
            params['per_page'] = 500

        # if a page is given in params, we will fetch only the provided page
        if 'page' in params:
            response = self._http_request(
                method='GET',
                url_suffix=path,
                params=params
            )
        # if no page is given, we will fetch all the Security Issues
        else:
            demisto.info('Fetching all Security Issues by default. '
                         'You can override this by specifying the "page" parameter')
            response = []
            # we start at page 1
            curr_page = 1
            params['page'] = curr_page
            raw_response = self._http_request(
                method='GET',
                url_suffix=path,
                resp_type='response',  # used to get the headers of the response
                params=params
            )
            response += raw_response.json()
            paginate_objperpage = int(raw_response.headers['x-per-page'])
            paginate_total_results = int(raw_response.headers['x-total'])
            demisto.debug(f'Fetched page {curr_page} of \
                {paginate_total_results//paginate_objperpage} \
                (total results: {paginate_total_results})')
            # we now iterate through all pages
            while curr_page * paginate_objperpage < paginate_total_results:
                curr_page += 1
                params['page'] = curr_page
                raw_response = self._http_request(
                    method='GET',
                    url_suffix=path,
                    resp_type='response',  # used to get the headers of the response
                    params=params
                )
                response += raw_response.json()
                demisto.debug(f'Fetched page {curr_page} of '
                              f'{paginate_total_results//paginate_objperpage} '
                              f'(total results: {paginate_total_results})')

        return response

    def get_one_security_issue(self, params):
        """
        Send the request for fetch_security_issue_command.
        Args:
            fields (str): The fields to include in the response.
        Returns:
            Dict: The response.

        """

        if 'id' not in params:
            raise DemistoException('Please provide a Security Issues ID')

        path = '/api/v3/security_issues/' + str(params['id'])

        response = self._http_request(
            method='GET',
            url_suffix=path,
            params=params
        )

        return response

    def ping(self):
        """
        Send the request to ping the Cyberwatch scanner.
        Args:
            None.
        Returns:
            Dict: The response.
        """

        path = '/api/v3/ping'
        response = self._http_request(
            method='GET',
            url_suffix=path
        )

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


''' HELPERS '''


def iso8601_to_human(iso8601_str, default_value=''):
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
        if iso8601_str[-1] == 'Z':
            return datetime.strptime(iso8601_str, '%Y-%m-%dT%H:%M:%S.%fZ').strftime(
                "%Y-%m-%dT%H:%M:%S")
        else:
            # The string is indeed in ISO8601 format
            dt = datetime.fromisoformat(iso8601_str)
            # Convert to UTC
            dt_utc = dt - (dt.utcoffset() or timedelta())
            # Format to the desired human-readable format
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%S")

    return default_value


''' FUNCTIONS '''


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
        raise DemistoException('No CVEs found')

    readable_headers = ['cve_code', 'content', 'published', 'last_modified', 'level',
                        'score', 'epss', 'cvss_v3']

    readable_cves = [{
        'cve_code': cve['cve_code'],
        'content': cve['content'],
        'published': iso8601_to_human(cve['published']),
        'last_modified': iso8601_to_human(cve['last_modified']),
        'level': cve['level'],
        'score': str(cve['score']),
        'epss': str(cve['epss']),
        'cvss_v3': cve['cvss_v3']
    } for cve in cves]

    return CommandResults(
        outputs=createContext(cves, removeNull=True),
        outputs_prefix='Cyberwatch.CVE',
        raw_response=cves,
        outputs_key_field='cve_code',
        readable_output=tableToMarkdown('Cyberwatch CVEs', readable_cves, readable_headers,
                                        removeNull=False, is_auto_json_transform=True,
                                        date_fields=['published', 'last_modified'])
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
        raise DemistoException('CVE not found')

    readable_headers = ['cve_code', 'content', 'published', 'last_modified', 'level', 'score',
                        'epss', 'cvss_v3', 'servers_count', 'security_announcements_count']

    readable_cve = {
        'cve_code': cve['cve_code'],
        'content': cve['content'],
        'published': iso8601_to_human(cve['published']),
        'last_modified': iso8601_to_human(cve['last_modified']),
        'level': cve['level'],
        'score': str(cve['score']),
        'epss': str(cve['epss']),
        'cvss_v3': cve['cvss_v3'],
        'servers_count': str(len(cve['servers'])),
        'security_announcements_count': str(len(cve['security_announcements']))
    }

    return CommandResults(
        outputs=createContext(cve, removeNull=True),
        outputs_prefix='Cyberwatch.CVE',
        raw_response=cve,
        outputs_key_field='cve_code',
        readable_output=tableToMarkdown('Cyberwatch CVE', readable_cve, readable_headers,
                                        removeNull=False, is_auto_json_transform=True,
                                        date_fields=['published', 'last_modified'])
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
        raise DemistoException('No assets found')

    readable_headers = ['id', 'hostname', 'reboot_required', 'category',
                        'last_communication', 'os', 'environment', 'groups',
                        'cve_announcements_count', 'prioritized_cve_announcements_count',
                        'updates_count', 'compliance_repositories']

    readable_assets = [{
        'id': str(asset['id']),
        'hostname': asset['hostname'],
        'reboot_required': str(asset['reboot_required']),
        'category': asset['category'],
        'last_communication': iso8601_to_human(asset['last_communication']),
        'os': asset['os'].get('name') if asset['os'] else None,
        'environment': asset['environment'].get('name') if asset['environment'] else None,
        'groups': [g.get('name') for g in asset['groups']],
        'cve_announcements_count': str(asset['cve_announcements_count']),
        'prioritized_cve_announcements_count': str(asset['prioritized_cve_announcements_count']),
        'updates_count': str(asset['updates_count']),
        'compliance_repositories': [c.get('name') for c in asset['compliance_repositories']]
    } for asset in assets]

    return CommandResults(
        outputs=createContext(assets, removeNull=True),
        outputs_prefix='Cyberwatch.Asset',
        raw_response=assets,
        outputs_key_field='id',
        readable_output=tableToMarkdown('Cyberwatch Assets', readable_assets, readable_headers,
                                        removeNull=False, is_auto_json_transform=True,
                                        date_fields=['last_communication'])
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
        raise DemistoException('Asset not found')

    readable_headers = ['id', 'hostname', 'description', 'reboot_required', 'category',
                        'last_communication', 'os', 'environment', 'groups',
                        'cve_announcements_count', 'prioritized_cve_announcements_count',
                        'updates_count', 'compliance_repositories']

    readable_asset = {
        'id': str(asset['id']),
        'hostname': asset['hostname'],
        'description': str(asset['description']),
        'reboot_required': str(asset['reboot_required']),
        'category': str(asset['category']),
        'last_communication': iso8601_to_human(asset['last_communication']),
        'os': asset['os'].get('name') if asset['os'] else None,
        'environment': asset['environment'].get('name'),
        'groups': [g.get('name') for g in asset['groups']],
        'cve_announcements_count': str(asset['cve_announcements_count']),
        'prioritized_cve_announcements_count': str(asset['prioritized_cve_announcements_count']),
        'updates_count': str(asset['updates_count']),
        'compliance_repositories': [c.get('name') for c in asset['compliance_repositories']]
    }

    return CommandResults(
        outputs=createContext(asset, removeNull=False),
        outputs_prefix='Cyberwatch.Asset',
        raw_response=asset,
        outputs_key_field='id',
        readable_output=tableToMarkdown('Cyberwatch Asset', readable_asset, readable_headers,
                                        removeNull=False, is_auto_json_transform=True,
                                        date_fields=['last_communication'])
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
    asset_additional_details = client.get_one_asset(args, namespace='assets')

    # Merge data
    asset = {**asset_vulns, **asset_additional_details}

    if len(asset) == 0:
        raise DemistoException('Asset not found')

    readable_headers = ['id', 'hostname', 'description', 'reboot_required', 'category',
                        'last_communication', 'os', 'environment', 'groups',
                        'cve_announcements_count', 'prioritized_cve_announcements_count',
                        'updates_count', 'compliance_repositories', 'packages_count',
                        'metadata_count', 'services_count', 'ports_count', 'connector_type']

    readable_asset = {
        'id': str(asset['id']),
        'hostname': asset['hostname'],
        'description': str(asset['description']),
        'reboot_required': str(asset['reboot_required']),
        'category': str(asset['category']),
        'last_communication': iso8601_to_human(asset['last_communication']),
        'os': asset['os'].get('name') if asset['os'] else None,
        'environment': asset['environment'].get('name'),
        'groups': [g.get('name') for g in asset['groups']],
        'cve_announcements_count': str(asset['cve_announcements_count']),
        'prioritized_cve_announcements_count': str(asset['prioritized_cve_announcements_count']),
        'updates_count': str(asset['updates_count']),
        'compliance_repositories': [c.get('name') for c in asset['compliance_repositories']],
        'packages_count': str(len(asset['packages'])),
        'metadata_count': str(len(asset['metadata'])),
        'services_count': str(len(asset['services'])),
        'ports_count': str(len(asset['ports'])),
        'connector_type': asset['connector'].get('type') if asset['connector'] else None
    }

    return CommandResults(
        outputs=createContext(asset, removeNull=False),
        outputs_prefix='Cyberwatch.Asset',
        raw_response=asset,
        outputs_key_field='id',
        readable_output=tableToMarkdown('Cyberwatch Asset', readable_asset, readable_headers,
                                        removeNull=False, is_auto_json_transform=True,
                                        date_fields=['last_communication'])
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
        raise DemistoException('No security issues found')

    readable_headers = ['id', 'sid', 'level', 'title', 'description']

    readable_secissues = [{
        'id': str(secissue['id']),
        'sid': str(secissue['sid']),
        'level': str(secissue['level']),
        'title': str(secissue['title']),
        'description': str(secissue['description'])
    } for secissue in secissues]

    return CommandResults(
        outputs=createContext(secissues, removeNull=True),
        outputs_prefix='Cyberwatch.SecurityIssue',
        raw_response=secissues,
        outputs_key_field='id',
        readable_output=tableToMarkdown('Cyberwatch Security Issues', readable_secissues,
                                        readable_headers, removeNull=False,
                                        is_auto_json_transform=True)
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
        raise DemistoException('Security Issue not found')

    readable_headers = ['id', 'sid', 'title', 'description',
                        'servers_count', 'cve_announcements_count']

    readable_secissue = {
        'id': str(secissue['id']),
        'sid': str(secissue['sid']),
        'title': str(secissue['title']),
        'description': str(secissue['description']),
        'servers_count': str(len(secissue['servers'])),
        'cve_announcements_count': str(len(secissue['cve_announcements']))
    }

    return CommandResults(
        outputs=createContext(secissue, removeNull=False),
        outputs_prefix='Cyberwatch.SecurityIssue',
        raw_response=secissue,
        outputs_key_field='id',
        readable_output=tableToMarkdown('Cyberwatch Security Issue', readable_secissue,
                                        readable_headers, removeNull=False,
                                        is_auto_json_transform=True)
    )


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    verify_ssl = not params.get('unsecure', False)
    proxy = params.get('proxy', False)
    access_key = params.get('api_access_key')
    secret_key = params.get('api_secret_key')
    base_url = params.get('master_scanner_url')

    demisto.info(f'Executing command {command}')

    # convert params provided as list to actual lists
    for key in args:
        if '[]' in key:
            args[key] = argToList(args[key])

    command_dict: Dict[str, Callable] = {
        'test-module': test_module,
        'cyberwatch-list-assets': list_assets_command,
        'cyberwatch-fetch-asset': fetch_asset_command,
        'cyberwatch-fetch-asset-fulldetails': fetch_asset_full_command,
        'cyberwatch-list-cves': list_cves_command,
        'cyberwatch-fetch-cve': fetch_cve_command,
        'cyberwatch-list-securityissues': list_security_issues_command,
        'cyberwatch-fetch-securityissue': fetch_security_issue_command
    }

    try:
        client = Client(
            base_url=base_url,
            verify=verify_ssl,
            auth=(access_key, secret_key),
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        else:
            return_results(command_dict[command](client, args))
    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error: {str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
