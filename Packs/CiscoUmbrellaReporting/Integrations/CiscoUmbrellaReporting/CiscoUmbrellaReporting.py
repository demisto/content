import demistomock as demisto
import copy

from CommonServerPython import *
from typing import Dict, List, Optional
from requests.auth import HTTPBasicAuth
from datetime import datetime
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

COUNT = 0
DEFAULT_PAGE_SIZE = 50
FROM_DATE = "-7days"
TO_DATE = "now"
OFFSET = 0
INTEGRATION_CONTEXT_NAME = 'UmbrellaReporting'
TOKEN_ENDPOINT = "https://management.api.umbrella.com/auth/v2/oauth2/token"
IP_PARAM = 'ip'
DOMAIN_PARAM = 'domains'
SHA256_PARAM = 'sha256'
INTRUSION_ACTION = 'intrusion_action'
DATE_TIME_FORMAT = "%b %d, %Y %H:%M %p"
PAGE_NUMBER_ERROR_MSG = 'Invalid Input Error: page number should be greater ' \
                        'than zero.'

ACTIVITY_TRAFFIC_TYPE_DICT = {
    "dns": ["limit", "from", "to", "offset", "domains", "ip", "verdict",
            "threats", "threat_types", "identity_types", "page", "page_size"],
    "proxy": ["limit", "from", "to", "offset", "domains", "ip", "verdict",
              "threats", "threat_types", "urls", "ports", "identity_types",
              "file_name", "amp_disposition", "page", "page_size"],
    "firewall": ["limit", "from", "to", "offset", "ip", "ports", "verdict",
                 "page", "page_size"],
    "intrusion": ["limit", "from", "to", "offset", "ip", "ports",
                  "signatures", "intrusion_action", "page", "page_size"],
    "ip": ["limit", "from", "to", "offset", "ip", "ports", "identity_types",
           "verdict", "page", "page_size"],
    "amp": ["limit", "from", "to", "offset", "amp_disposition", "sha256",
            "page", "page_size"]
}

SUMMARY_TYPE_DICT = {
    "all": ["limit", "from", "to", "offset", "domains", "urls", "ip",
            "identity_types", "verdict", "file_name", "threats",
            "threat_types", "amp_disposition", "page", "page_size", "ports"],
    "category": ["limit", "from", "to", "offset", "domains", "urls", "ip",
                 "identity_types", "verdict", "file_name", "threats",
                 "threat_types", "amp_disposition", "page", "page_size"],
    "destination": ["limit", "from", "to", "offset", "domains", "urls", "ip",
                    "identity_types", "verdict", "file_name", "threats",
                    "threat_types", "amp_disposition", "page", "page_size"],
    "intrusion_rule": ["limit", "from", "to", "offset", "signatures", "ip",
                       "identity_types", "intrusion_action", "ports", "page",
                       "page_size"]
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this implementation, no special attributes defined
    """
    def __init__(self, base_url: str, organisation_id: str,
                 secret_key: str, client_key: str,
                 verify=None,
                 proxy=None):
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            ok_codes=(200,),
        )
        self.token_url = TOKEN_ENDPOINT
        self.secret_key = secret_key
        self.client_key = client_key
        self.organisation_id = organisation_id

    def access_token(self):
        """
        Generate Access token
        :return: access_token
        """
        payload = {
            "grant_type": 'client_credentials'
        }

        token_response = requests.post(url=self.token_url, auth=HTTPBasicAuth(
            username=self.client_key, password=self.secret_key), data=payload)
        if token_response.status_code == 401:
            raise DemistoException(
                "Authorization Error: The provided credentials for "
                "Cisco Umbrella Reporting are invalid. Please provide "
                "valid Client ID and Client Secret.")
        elif token_response.status_code >= 400:
            raise DemistoException("Error: something went wrong, please try "
                                   "again.")

        return token_response.json().get('access_token')

    def fetch_data_from_cisco_api(self, end_point: str, params: dict) -> Dict:
        """
        : param end_point: Cisco Umbrella Reporting endpoint
        :return: return the raw api response from Cisco Umbrella Reporting API.
        """
        return self.query(end_point, params)

    def query(self, end_point: str, params: dict) -> Dict:
        """
        :param end_point: Cisco Umbrella Reporting endpoint
        :param params: Kwargs
        :return: return the raw api response from Cisco Umbrella Reporting API.

        """
        result: Dict = {}
        url_path = f'{self._base_url}/v2/organizations' \
                   f'/{self.organisation_id}/{end_point}'
        access_token = self.access_token()
        payload: Dict = {}
        response = requests.get(
            url=url_path,
            headers={'Authorization': f'Bearer {access_token}'},
            data=payload,
            params=params,
            allow_redirects=False,
        )
        if response.status_code in range(300, 310):
            # payload = {}
            response = requests.get(
                response.headers['Location'],
                headers={'Authorization': f'Bearer {access_token}'},
                data={}, allow_redirects=True)
            if response.ok:
                result = response.json()
        elif response.status_code >= 400:
            error_message = response.json().get("data", {}).get("error")
            if "invalid organization" in error_message:
                raise DemistoException("Authorization Error: The provided Organization ID is invalid.")
            elif "unauthorized" in error_message:
                raise DemistoException(
                    "Authorization Error: The provided credentials for Cisco "
                    "Umbrella Reporting are invalid. Please provide a valid "
                    "Client ID and Client Secret.")
            raise DemistoException(error_message)

        return result

    def test_module(self) -> str:
        """
        Tests API connectivity and authentication
        When 'ok' is returned it indicates the integration works like
        it is supposed to and connection to the service is successful.
        :return: connection ok
        :Raises exceptions if something goes wrong.
        """
        if not self.organisation_id.isdigit():
            raise DemistoException("Invalid Input Error:The Organization ID "
                                   "must be a number.")
        token = self.access_token()
        url = f'{self._base_url}/v2/organizations/{self.organisation_id}/activity'

        payload: Dict = {}
        params: Dict = {
            "limit": 1,
            "from": "-1days",
            "to": "now",
            "offset": 0
        }
        response = requests.get(
            url=url,
            headers={'Authorization': f'Bearer {token}'},
            data=payload,
            params=params,
            allow_redirects=False,
        )
        if response.status_code >= 400:
            error_message = response.json().get("data", {}).get("error")
            if "invalid organization" in error_message:
                raise DemistoException("Authorization Error: The provided Organization ID is invalid.")
            elif "unauthorized" in error_message:
                raise DemistoException(
                    "Authorization Error: The provided credentials for Cisco "
                    "Umbrella Reporting are invalid. Please provide a valid "
                    "Client ID and Client Secret.")
            raise DemistoException(error_message)
        return 'ok'


''' HELPER FUNCTIONS '''


def check_valid_indicator_value(indicator_type: str,
                                indicator_value: str) -> bool:
    """

    :param indicator_type: Indicator type provided in the command
    :param indicator_value: Indicator value provided in the command
    :return: true if the provided indicator values are valid.

    """
    # not using default urlRegex for domain validation
    # as it is failing in some cases, for example
    # 'fluber12.duckdns.org' is validated as invalid
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
        r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
        r'[A-Za-z]$'  # Last character of the gTLD
    )

    if indicator_type == DOMAIN_PARAM:
        indicator_value_list = argToList(indicator_value)
        for domain in indicator_value_list:
            if not re.match(domain_regex, domain):
                raise ValueError(
                    f'Domain {domain} is invalid')
    elif indicator_type == IP_PARAM:
        if not is_ip_valid(indicator_value, accept_v6_ips=True):  # check IP's validity
            raise ValueError(f'IP "{indicator_value}" is not valid')
    if indicator_type == SHA256_PARAM:
        if not re.match(sha256Regex, indicator_value):
            raise ValueError(
                f'SHA256 value {indicator_value} is invalid')
    if indicator_type == INTRUSION_ACTION:
        intrusion_list = argToList(indicator_value)
        for intrusion in intrusion_list:
            if intrusion not in ["would_block", "blocked", "detected"]:
                raise ValueError("Invalid input Error: supported values for "
                                 "intrusion_action are: 'would_block', 'blocked' and 'detected'.")

    return True


def get_command_title_string(sub_context: str, page: Optional[int],
                             page_size: Optional[int]) -> str:
    """
    : param sub_context: Commands sub_context
    : param page: page_number
    : param page_size: page_size
    : return: returns the title for the readable output
    """
    if page and page_size and (page > 0 and page_size > 0):
        return f"{sub_context} List\nShowing page {page}\nCurrent page size:" \
               f" {page_size}"

    return f"{sub_context} List"


def destination_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    destination_list = []
    for destination in results:
        category = [label.get("label") for label in destination.get(
            "categories", [])]
        new = {
            'Destination': destination.get('domain', ''),
            'Category': ", ".join(category),
            'Allowed': destination.get('counts', {}).get('allowedrequests', ''),
            'Blocked': destination.get('counts', {}).get('blockedrequests', ''),
            'Requests': destination.get('counts', {}).get('requests', '')
        }
        destination_list.append(new)
    headers = destination_list[0] if destination_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, destination_list, headers=headers,
                               removeNull=True)
    return markdown


def categories_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """

    categories_list = []
    for category in results:
        new = {
            "Category": category.get('category', {}).get("label", ""),
            "Type": category.get('category', {}).get("type", ""),
            "Activity": category.get("count", 0)
        }
        categories_list.append(new)
    headers = categories_list[0] if categories_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, categories_list, headers=headers,
                               removeNull=True)
    return markdown


def summary_lookup_to_markdown(summary: Dict, title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        summary (dict): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """

    summary_list = []
    new = {
        'Application': summary.get('applications', 0),
        'Allowed Application': summary.get('applicationsallowed', 0),
        'Blocked Application': summary.get('applicationsblocked', 0),
        'Category': summary.get('categories', 0),
        'Domain': summary.get('domains', 0),
        'File': summary.get('files', 0),
        'File Type': summary.get('filetypes', 0),
        'Identity': summary.get('identities', 0),
        'Identity Type': summary.get('identitytypes', 0),
        'Policy Category': summary.get('policycategories', 0),
        'Policy Request': summary.get('policyrequests', 0),
        'Request': summary.get('requests', 0),
        'Allowed Request': summary.get('requestsallowed', 0),
        'Blocked Request': summary.get('requestsblocked', 0)
    }
    summary_list.append(new)

    headers = summary_list[0] if summary_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_list, headers=headers,
                               removeNull=True)
    return markdown


def summary_category_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    summary_category = []
    for summary_cat in results:
        summary = summary_cat.get('summary', {})
        new = {
            'Category Type': summary_cat.get('category', {}).get('type', ''),
            'Category Name': summary_cat.get('category', {}).get('label', ''),
            'Application': summary.get('applications', 0),
            'Allowed Application': summary.get('applicationsallowed', 0),
            'Blocked Application': summary.get('applicationsblocked', 0),
            'Category': summary.get('categories', 0),
            'Domain': summary.get('domains', 0),
            'File': summary.get('files', 0),
            'File Type': summary.get('filetypes', 0),
            'Identity': summary.get('identities', 0),
            'Identity Type': summary.get('identitytypes', 0),
            'Policy Category': summary.get('policycategories', 0),
            'Policy Request': summary.get('policyrequests', 0),
            'Request': summary.get('requests', 0),
            'Allowed Request': summary.get('requestsallowed', 0),
            'Blocked Request': summary.get('requestsblocked', 0)
        }
        summary_category.append(new)

    headers = summary_category[0] if summary_category else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_category, headers=headers,
                               removeNull=True)
    return markdown


def summary_rule_lookup_to_markdown(results: List[Dict], title: str):
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    summary_rule = []
    for result in results:
        sigantures = result.get('signatures', [])
        for sign in sigantures:
            new = {
                "Blocked": sign.get('counts').get('blocked'),
                "Detected": sign.get('counts').get('detected'),
                "Would Block": sign.get('counts').get('wouldblock'),
                "Last Event": sign.get('lasteventat')
            }
            summary_rule.append(new)
    headers = ['Blocked', 'Detected', 'Would Block', "Last Event"]
    return tableToMarkdown(title, summary_rule, headers=headers, removeNull=True)


def summary_destination_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    summary_dest = []
    for destination in results:
        summary = destination.get('summary', {})
        new = {
            'Destination': destination.get('domain', ''),
            'Application': summary.get('applications', 0),
            'Allowed Application': summary.get('applicationsallowed', 0),
            'Blocked Application': summary.get('applicationsblocked', 0),
            'Category': summary.get('categories', 0),
            'Domain': summary.get('domains', 0),
            'File': summary.get('files', 0),
            'File Type': summary.get('filetypes', 0),
            'Identity': summary.get('identities', 0),
            'Identity Type': summary.get('identitytypes', 0),
            'Policy Category': summary.get('policycategories', 0),
            'Policy Request': summary.get('policyrequests', 0),
            'Request': summary.get('requests', 0),
            'Allowed Request': summary.get('requestsallowed', int),
            'Blocked Request': summary.get('requestsblocked', 0)
        }
        summary_dest.append(new)
    headers = summary_dest[0] if summary_dest else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, summary_dest, headers=headers,
                               removeNull=True)
    return markdown


def identities_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    identities_list = []
    for identity in results:
        new = {
            "Identity": identity.get('identity', {}).get("label", ""),
            "Requests": identity.get('requests', 0)
        }
        identities_list.append(new)
    headers = identities_list[0] if identities_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, identities_list, headers=headers,
                               removeNull=True)
    return markdown


def file_type_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    file_list = []
    for file in results:
        category = []
        type_list = []
        for label in file.get('categories', []):
            category.append(label.get("label", ''))
            type_list.append(label.get("type", ''))
        new = {
            "Requests": file.get("requests", ''),
            "Identity Count": file.get("identitycount", ''),
            "SHA256": file.get('sha256', ''),
            "Category": ", ".join(category),
            "Category Type": ", ".join(type_list),
            "File Name": ", ".join(file.get("filenames", [])),
            "File Types": ", ".join(file.get("filetypes", []))
        }
        file_list.append(new)
    headers = file_list[0] if file_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, file_list, headers=headers,
                               removeNull=True)
    return markdown


def event_types_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    event_list = []
    for event in results:
        new = {
            "Event Type": event.get('eventtype', ''),
            "Count": event.get('count', 0)
        }
        event_list.append(new)
    headers = event_list[0] if event_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, event_list, headers=headers,
                               removeNull=True)
    return markdown


def threat_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    threat_list = []
    for threat in results:
        new = {
            "Threat": threat.get('threat', ''),
            "Threat Type": threat.get('threattype', ''),
            "Count": threat.get('count', 0)
        }
        threat_list.append(new)
    headers = threat_list[0] if threat_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, threat_list, headers=headers, removeNull=True)
    return markdown


def activity_build_data(activity: Dict) -> dict:
    """
    Build activity data
    Args:
        activity (dict): Single object from cisco data
    Returns:
        Return activity data
    """
    category = [label.get("label") for label in
                activity.get("categories", [])]
    identity = [label.get("label") for label in
                activity.get("identities", [])]
    signature_cve = activity["signature"].get("cves") if activity.get(
        "signature") else []
    signature_lebel = activity["signature"].get("label") if activity.get(
        "signature") else ""
    all_application = []
    application_category = []
    for application in activity.get("allapplications", []):
        all_application.append(application.get("label"))
        application_category.append(
            application.get("category").get("label"))
    timestamp = activity.get("timestamp", 0)
    timestamp_string = datetime.utcfromtimestamp(
        timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
    activity_data = {
        "category": category,
        "identity": identity,
        "all_application": all_application,
        "application_category": application_category,
        "timestamp_string": timestamp_string,
        "signature_cve": signature_cve,
        "signature_lebel": signature_lebel
    }
    return activity_data


def activity_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    activity_list = []
    for activity in results:
        activity_data = activity_build_data(activity)
        new = {
            "Request": activity.get("type", ''),
            "Identity": ", ".join(activity_data.get('identity', [])),
            "Policy or Ruleset Identity": ", ".join(activity_data.get(
                'identity', [])),
            "Destination": activity.get("domain", ''),
            "Internal IP": activity.get("internalip", ''),
            "External IP": activity.get("externalip", ''),
            "DNS Type": activity.get("querytype", ''),
            "Action": activity.get("verdict", ''),
            "Categories": ", ".join(activity_data.get('category', [])),
            "Public Application": ", ".join(activity_data.get(
                'all_application', [])),
            "Application Category": ", ".join(activity_data.get(
                'application_category', [])),
            "Date & Time": activity_data.get('timestamp_string')
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers,
                               removeNull=True)
    return markdown


def activity_dns_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    activity_list = []
    for activity in results:
        activity_data = activity_build_data(activity)
        new = {
            "Identity": ", ".join(activity_data.get('identity', [])),
            "Policy or Ruleset Identity": ", ".join(activity_data.get(
                'identity', [])),
            "Destination": activity.get("domain", ''),
            "Internal IP": activity.get("internalip", ''),
            "External IP": activity.get("externalip", ''),
            "DNS Type": activity.get("querytype", ''),
            "Action": activity.get("verdict", ''),
            "Categories": ", ".join(activity_data.get('category', [])),
            "Public Application": ", ".join(activity_data.get(
                'all_application', [])),
            "Application Category": ", ".join(activity_data.get(
                'application_category', [])),
            "Date & Time": activity_data.get('timestamp_string')
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


def activity_proxy_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    activity_list = []
    for activity in results:
        activity_data = activity_build_data(activity)
        new = {
            "Identity": ", ".join(activity_data.get('identity', [])),
            "Policy or Ruleset Identity": ", ".join(activity_data.get(
                'identity', [])),
            "Internal IP": activity.get("internalip", ''),
            "External IP": activity.get("externalip", ''),
            "Action": activity.get("verdict", ''),
            "Categories": ", ".join(activity_data.get('category', [])),
            "Public Application": ", ".join(activity_data.get(
                'all_application', [])),
            "Application Category": ", ".join(activity_data.get(
                'application_category', [])),
            "Date & Time": activity_data.get('timestamp_string')
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


def activity_firewall_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    activity_list = []
    for activity in results:
        activity_data = activity_build_data(activity)
        new = {
            "Identity": ", ".join(activity_data.get('identity', [])),
            "Policy or Ruleset Identity": ", ".join(activity_data.get(
                'identity', [])),
            "Destination IP": activity.get("destinationip", ''),
            "Source IP": activity.get("sourceip", ''),
            "Source Port": activity.get("sourceport", ''),
            "Destination Port": activity.get("destinationport", ''),
            "Protocol": activity["protocol"].get("label") if activity.get(
                "protocol") else '',
            "Rule": activity["rule"].get("label") if activity.get("rule") else '',
            "Type": activity.get("type", ''),
            "Action": activity.get("verdict", ''),
            "Public Application": ", ".join(activity_data.get(
                'all_application', [])),
            "Direction": activity.get("direction", ''),
            "Date & Time": activity_data.get('timestamp_string')
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


def activity_intrusion_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    activity_list = []
    for activity in results:
        activity_data = activity_build_data(activity)
        new = {
            "Identity": ", ".join(activity_data.get('identity', [])),
            "Classification": activity.get("classification", ''),
            "Destination IP": activity.get("destinationip", ''),
            "Source IP": activity.get("sourceip", ''),
            "Source Port": activity.get("sourceport", ''),
            "Destination Port": activity.get("destinationport", ''),
            "Protocol": activity["protocol"].get("label") if activity.get(
                "protocol") else '',
            "Severity": activity.get("severity", ''),
            "CVE": ", ".join(activity_data.get('signature_cve', [])),
            "Signature": activity_data.get('signature_lebel'),
            "Type": activity.get("type", ''),
            "Action": activity.get("verdict", ''),
            "Date & Time": activity_data.get('timestamp_string')
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


def activity_ip_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    activity_list = []
    for activity in results:
        activity_data = activity_build_data(activity)
        new = {
            "Identity": ", ".join(activity_data.get('identity', [])),
            "Destination IP": activity.get("destinationip", ''),
            "Source IP": activity.get("sourceip", ''),
            "Source Port": activity.get("sourceport", ''),
            "Destination Port": activity.get("destinationport", ''),
            "Categories": ", ".join(activity_data.get('category', [])),
            "Type": activity.get("type", ''),
            "Action": activity.get("verdict", ''),
            "Date & Time": activity_data.get('timestamp_string')
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


def activity_amp_lookup_to_markdown(results: List[Dict], title: str) -> str:
    """
    Parsing the Cisco Umbrella Reporting data
    Args:
        results (list): Cisco Umbrella Reporting data
        title (str): Title string
    Returns:
        A string representation of the markdown table
    """
    activity_list = []
    for activity in results:
        timestamp = activity.get("timestamp", 0)
        timestamp_string = datetime.utcfromtimestamp(
            timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
        new = {
            "First Seen": activity.get("firstseenat", ''),
            "Disposition": activity.get("disposition", ''),
            "Score": activity.get("score", ''),
            "Host Name": activity.get("hostname", ''),
            "Malware": activity.get("malwarename", ''),
            "SHA256": activity.get("sha256", ''),
            "Date & Time": timestamp_string
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


def pagination(page: Optional[int], page_size: Optional[int]):
    """
    Define pagination.
    Args:
        page: The page number.
        page_size: The number of requested results per page.
    Returns:
        limit (int): Records per page.
        offset (int): The number of records to be skipped.
    """
    if (page and page <= 0) or (page_size and page_size <= 0):
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    page = 0 if not page else page - 1
    page_size = DEFAULT_PAGE_SIZE if not page_size else page_size
    limit = page_size
    offset = page * page_size
    return limit, offset


def get_param(limit: Optional[int], offset: Optional[int], args: Dict) -> Dict:
    """
    Setup parameter.
    Args:
        limit: Records per page.
        offset: The number of records to be skipped.
        args: kwargs
    Returns:
        Return arguments dict.
    """
    args["limit"] = limit if limit != 50 else args.get('limit', DEFAULT_PAGE_SIZE)
    args["offset"] = offset
    args["from"] = args.pop('from', FROM_DATE)
    args["to"] = args.pop('to', TO_DATE)
    args["threattypes"] = args.pop('threat_types', None)
    args["identitytypes"] = args.pop('identity_types', None)
    args["ampdisposition"] = args.pop("amp_disposition", None)
    args["filename"] = args.pop("file_name", None)
    args["intrusionaction"] = args.pop("intrusion_action", None)

    return args


''' COMMAND FUNCTIONS '''


def get_destinations_list_command(client: Client, args: Dict[str, Any]):
    """
    get_destinations_list_command: List of destinations ordered by the number of requests made in descending order.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    traffic_type = args.pop("traffic_type", None)
    endpoint = f"top-destinations/{traffic_type}" if traffic_type else "top-destinations"
    if sha256 := args.get('sha256'):
        check_valid_indicator_value("sha256", sha256)
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE), arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    title = get_command_title_string("Destination", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = destination_lookup_to_markdown(data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'destinations to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Destination',
        outputs_key_field='',
        outputs=data
    )


def get_categories_list_command(client: Client, args: Dict[str, Any]):
    """
    get_categories_list_command: List of categories ordered by the number of
        requests made matching the categories in descending order.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    traffic_type = args.pop("traffic_type", None)
    endpoint = f"top-categories/{traffic_type}" if traffic_type else "top-categories"
    if sha256 := args.get('sha256'):
        check_valid_indicator_value("sha256", sha256)
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    title = get_command_title_string("Category", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = categories_lookup_to_markdown(data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'category to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Category',
        outputs_key_field='',
        outputs=data
    )


def get_identities_list_command(client: Client, args: Dict[str, Any]):
    """
    get_identities_list_command: List of identities ordered by the number of requests they made in descending order.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    traffic_type = args.get("traffic_type", None)
    endpoint = f"top-identities/{traffic_type}" if traffic_type else "top-identities"
    if sha256 := args.get('sha256'):
        check_valid_indicator_value("sha256", sha256)
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    title = get_command_title_string("Identities", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = identities_lookup_to_markdown(data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'identity to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Identity',
        outputs_key_field='',
        outputs=data
    )


def get_file_list_command(client: Client, args: Dict[str, Any]):
    """
    get_file_list_command: List of files within a timeframe. Only returns proxy data.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    if sha256 := args.get('sha256'):
        check_valid_indicator_value("sha256", sha256)
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    endpoint = 'top-files'
    title = get_command_title_string("File", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = file_type_lookup_to_markdown(data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'file to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.File',
        outputs_key_field='',
        outputs=data
    )


def get_threat_list_command(client: Client, args: Dict[str, Any]):
    """
    get_threat_list_command: List of threats within a timeframe. Returns both DNS and Proxy data.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    traffic_type = args.pop("traffic_type", None)
    endpoint = f"top-threats/{traffic_type}" if traffic_type else "top-threats"
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    title = get_command_title_string("Threat", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = threat_lookup_to_markdown(data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'threat to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Threat',
        outputs_key_field='',
        outputs=data
    )


def get_event_types_list_command(client: Client, args: Dict[str, Any]):
    """
    get_event_types_list_command: List of event types ordered by the number
     of requests made for each type of event in descending order.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    endpoint = "top-eventtypes"
    title = get_command_title_string("Event Type", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = event_types_lookup_to_markdown(data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'Event to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EventType',
        outputs_key_field='',
        outputs=data
    )


def get_activity_list_command(client: Client, args: Dict[str, Any]):
    """
    get_activity_list_command: List all activity entries (dns/proxy/firewall/ip/intrusion/amp) within timeframe.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an updated
            result.
    """
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    endpoint = "activity"
    title = get_command_title_string("Activity", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = activity_lookup_to_markdown(data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'activity to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Activity',
        outputs_key_field='',
        outputs=data,
    )


def get_activity_by_traffic_type_command(client: Client, args: Dict[str, Any]):
    """
    get_activity_by_traffic_type_command: List all entries within a timeframe
     based on the activity type selected. Valid activity types are dns,
     proxy, firewall, intrusion, ip, amp.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed
         to ``return_results``, that contains an updated result.
    """
    traffic_type = args.pop("traffic_type", None)
    if traffic_type:
        endpoint = "activity/amp-retrospective" if traffic_type == "amp"\
            else f"activity/{traffic_type}"
    else:
        raise DemistoException("Please select a traffic type.")
    markdown_function = {
        "dns": activity_dns_lookup_to_markdown,
        "proxy": activity_proxy_lookup_to_markdown,
        "firewall": activity_firewall_lookup_to_markdown,
        "ip": activity_ip_lookup_to_markdown,
        "intrusion": activity_intrusion_lookup_to_markdown,
        "amp": activity_amp_lookup_to_markdown
    }
    context_output_name = {
        "dns": "ActivityDns",
        "proxy": "ActivityProxy",
        "firewall": "ActivityFirewall",
        "intrusion": "ActivityIntrusion",
        "ip": "ActivityIP",
        "amp": "ActivityAMPRetro"
    }
    traffic_type_params_list = ACTIVITY_TRAFFIC_TYPE_DICT[traffic_type]
    if not set(args.keys()).issubset(traffic_type_params_list):
        raise DemistoException(
            f"Invalid optional parameter is selected for {traffic_type}")
    if sha256 := args.get('sha256'):
        check_valid_indicator_value("sha256", sha256)
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    if intrusion_action := args.get("intrusion_action"):
        check_valid_indicator_value("intrusion_action", intrusion_action)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    title = get_command_title_string(f"{traffic_type.capitalize()} "
                                     f"Activity", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)
    data = raw_json_response.get("data", [])
    if data:
        readable_output = markdown_function[traffic_type](data, title)
    else:
        readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                          f'activity {traffic_type} to present. \n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{context_output_name[traffic_type]}',
        outputs_key_field='',
        outputs=data,
    )


def get_summary_list_command(client: Client, args: Dict[str, Any]):
    """
    get_summary_list_command: Get the summary.
    Args:
        client: Cisco Umbrella Reporting client to use.
        args: all command arguments, usually passed from ``demisto.args()``.
    Returns:
        CommandResults: A ``CommandResults`` object that is then passed
         to ``return_results``, that contains an updated result.
    """
    summary_endpoint_dict = {
        "category": "summaries-by-category",
        "destination": "summaries-by-destination",
        "intrusion_rule": "summaries-by-rule/intrusion"
    }
    summary_markdown_dict = {
        'category': summary_category_lookup_to_markdown,
        'destination': summary_destination_lookup_to_markdown,
        "intrusion_rule": summary_rule_lookup_to_markdown
    }
    context_output_name = {
        "category": "SummaryWithCategory",
        "destination": "SummaryWithDestination",
        "intrusion_rule": "SignatureListSummary"
    }
    summary_type = args.pop("summary_type", None)
    endpoint = summary_endpoint_dict.get(summary_type, "summary")
    category_type_param_list = SUMMARY_TYPE_DICT.get(summary_type,
                                                     SUMMARY_TYPE_DICT["all"])
    if not set(args.keys()).issubset(category_type_param_list):
        raise DemistoException(
            f"Invalid optional parameter is selected for {summary_type}")
    if ip := args.get('ip'):
        check_valid_indicator_value("ip", ip)
    if domains := args.get("domains"):
        check_valid_indicator_value('domains', domains)
    if intrusion_action := args.get("intrusion_action"):
        check_valid_indicator_value("intrusion_action", intrusion_action)
    page = arg_to_number(args.get('page'), arg_name='page')
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE),
                              arg_name='page_size')
    limit, offset = pagination(page, page_size)
    params = get_param(limit, offset, args)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint, params)

    if summary_type:
        data = raw_json_response.get('data', [])
        title = get_command_title_string(
            f"Summary with "
            f"{summary_type.split('_')[0].capitalize()}", page, page_size)
        if data:
            readable_output = summary_markdown_dict[summary_type](data, title)
        else:
            readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                              f'{summary_type} summary to present. \n'
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}'
                           f'.{context_output_name[summary_type]}',
            outputs_key_field='',
            outputs=data
        )

    else:
        data = raw_json_response.get('data', {})
        title = get_command_title_string("Summary", page, page_size)
        if data:
            readable_output = summary_lookup_to_markdown(data, title)
        else:
            readable_output = f'{INTEGRATION_CONTEXT_NAME} does not have ' \
                              f'summary to present. \n'
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Summary',
            outputs_key_field='',
            outputs=data
        )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()
    copy_args = copy.deepcopy(args)
    secret_key = params.get('credentials', {}).get('password')
    client_key = params.get('credentials', {}).get('identifier')
    organisation_id = params.get('organization_id')

    # get the service API url
    base_url = params.get("api_url")

    proxy = params.get('proxy', False)
    handle_proxy()
    verify_certificate = not params.get('insecure', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            organisation_id=organisation_id,
            secret_key=secret_key,
            client_key=client_key,
            proxy=proxy,
            verify=verify_certificate
        )

        commands = {
            "umbrella-reporting-destination-list":
                get_destinations_list_command,
            "umbrella-reporting-category-list":
                get_categories_list_command,
            "umbrella-reporting-identity-list":
                get_identities_list_command,
            "umbrella-reporting-event-type-list":
                get_event_types_list_command,
            "umbrella-reporting-file-list":
                get_file_list_command,
            "umbrella-reporting-threat-list":
                get_threat_list_command,
            "umbrella-reporting-activity-list":
                get_activity_list_command,
            "umbrella-reporting-activity-get":
                get_activity_by_traffic_type_command,
            "umbrella-reporting-summary-list":
                get_summary_list_command
        }
        if command == "test-module":
            return_results(client.test_module())
        elif command in commands:
            return_results(commands[command](client, copy_args))
        else:
            raise NotImplementedError
    # Log exceptions
    except Exception as e:
        return_error(
            f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
