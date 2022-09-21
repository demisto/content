from CommonServerPython import *
from typing import Tuple, Callable
from requests.auth import HTTPBasicAuth
from datetime import datetime
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CORTEX XSOAR COMMAND CONSTANTS
COUNT = 0
LIMIT = 50
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
PAGE_NUMBER_ERROR_MSG = 'Invalid input Error: page number should be greater ' \
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


class Client(BaseClient):
    def __init__(self, base_url: str, organisation_id: str,
                 secret_key: str, client_key: str,
                 verify=None,
                 proxy=None):
        BaseClient.__init__(
            self,
            base_url,
            verify=verify,
            proxy=proxy,
            ok_codes=(200,),
        )
        self.token_url = TOKEN_ENDPOINT
        self.secret_key = secret_key
        self.client_key = client_key
        self.organisation_id = int(organisation_id) if \
            organisation_id.isdigit() else organisation_id

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
            raise DemistoException("Authorization Error: Provided credentials"
                                   " for Cisco Umbrella Reporting are not valid")

        return token_response.json()['access_token']

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
            payload = {}
            response = requests.get(
                response.headers['Location'],
                headers={'Authorization': f'Bearer {access_token}'},
                data=payload, allow_redirects=True)
            if response.ok:
                result = response.json()

        return result

    def test_module(self) -> str:
        """
        :param domain: hard coded domain type
        :param value: hard coded domain value
        :return: connection ok

        """

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
                raise DemistoException("Authorization Error: Provide organization id is invalid ")
            elif "unauthorized" in error_message:
                raise DemistoException("Authorization Error: Provided credentials for Cisco Umbrella Reporting are not valid")
            raise DemistoException(error_message)
        return 'ok'


def test_module(client: Client, args: dict) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed
    to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    return client.test_module()


def check_valid_indicator_value(indicator_type: str,
                                indicator_value: str) -> bool:
    """

    :param indicator_type: Indicator type provided in the command
    :param indicator_value: Indicator value provided in the command
    :return: true if the indicator value provided for the indicator type is
    valid

    """
    # not using default urlRegex for domain validation as it is failing in
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
        r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
        r'[A-Za-z]$'  # Last character of the gTLD
    )

    if indicator_type == DOMAIN_PARAM:
        indicator_value_list = indicator_value.split(",")
        for domain in indicator_value_list:
            if not re.match(domain_regex, domain):
                raise ValueError(
                    f'Domain {domain} is invalid')
    elif indicator_type == IP_PARAM:
        if not re.match(ipv4Regex, indicator_value):
            if not re.match(ipv6Regex, indicator_value):
                raise ValueError(
                    f'IP address {indicator_value} is invalid')
            raise ValueError(
                f'IP address {indicator_value} is invalid')
    if indicator_type == SHA256_PARAM:
        if not re.match(sha256Regex, indicator_value):
            raise ValueError(
                f'SHA256 value {indicator_value} is invalid')
    if indicator_type == INTRUSION_ACTION:
        intrusion_list = indicator_value.split(",")
        for intrusion in intrusion_list:
            if intrusion not in ["would_block", "blocked", "detected"]:
                raise ValueError('Invalid input Error: supported value for '
                                 'intrusion_action are would_block, blocked, detected')

    return True


def flatten_json(response: Dict) -> Dict[str, Any]:
    """
    :param y: raw_response from Cisco Umbrella Reporting api
    :return: Flatten json response

    """
    out = {}

    def flatten(data: Any, name: str = ''):
        # If the Nested key-value
        # pair is of dict type
        if type(data) is dict:
            for record in data:
                flatten(data[record], name + record + '_')
        else:
            out[name[:-1]] = data

    flatten(response)
    return out


def get_command_title_string(sub_context: str, page: int,
                             page_size: int) -> str:
    """
    : param sub_context: Commands sub_context
    : param page: page_number
    : param page_size: page_size
    : return: returns the title for the readable output
    """
    if page and (int(page) > 0 or int(page_size) > 0):
        return f"{sub_context} List\nShowing page {page}\nCurrent page size:" \
               f" {page_size}"
    else:
        return f"{sub_context} List"


def get_flatten_json_response(raw_api_response: List[Dict]) -> List[Dict]:
    """

    :param raw_api_response: raw_api response from the API
    :return: Flatten Json response

    """
    flatten_json_response = []
    if raw_api_response:
        for obj in raw_api_response:
            flatten_json_response.append(flatten_json(obj))

    return flatten_json_response


@logger
def destination_lookup_to_markdown(results: List[Dict], title: str) -> str:
    destination_list = []
    for destination in results:
        category = [label.get("label") for label in destination.get(
            "categories", [])]
        new = {
            'Destination': destination.get('domain', ''),
            'Category': ",".join(category),
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


@logger
def categories_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Category', 'category_label', str),
        ('Type', 'category_type', str),
        ('Activity', 'count', str),
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def summary_lookup_to_markdown(results: Dict, title: str) -> str:
    out = []
    keys = [
        ('Application', 'applications', int),
        ('Allowed Application', 'applicationsallowed', int),
        ('Blocked Application', 'applicationsblocked', int),
        ('Category', 'categories', int),
        ('Domain', 'domains', int),
        ('File', 'files', int),
        ('File Type', 'filetypes', int),
        ('Identity', 'identities', int),
        ('Identity Type', 'identitytypes', int),
        ('Policy Category', 'policycategories', int),
        ('Policy Request', 'policyrequests', int),
        ('Request', 'requests', int),
        ('Allowed Request', 'requestsallowed', int),
        ('Blocked Request', 'requestsblocked', int)
    ]  # type: List[Tuple[str, str, Callable]]
    headers = [k[0] for k in keys]

    row = dict()  # type: Dict[str, Any]
    for ckey, rkey, f in keys:
        if rkey in results.keys():
            row[ckey] = f(results[rkey])
    out.append(row)
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def summary_category_lookup_to_markdown(results: Dict, title: str) -> str:
    out = []
    keys = [
        ('Category Type', 'category_type', str),
        ('Category Name', 'category_label', str),
        ('Application', 'summary_applications', int),
        ('Allowed Application', 'summary_applicationsallowed', int),
        ('Blocked Application', 'summary_applicationsblocked', int),
        ('Category', 'summary_categories', int),
        ('Domain', 'summary_domains', int),
        ('File', 'summary_files', int),
        ('File Type', 'summary_filetypes', int),
        ('Identity', 'summary_identities', int),
        ('Identity Type', 'summary_identitytypes', int),
        ('Policy Category', 'summary_policycategories', int),
        ('Policy Request', 'summary_policyrequests', int),
        ('Request', 'summary_requests', int),
        ('Allowed Request', 'summary_requestsallowed', int),
        ('Blocked Request', 'summary_requestsblocked', int)
    ]  # type: List[Tuple[str, str, Callable]]
    headers = [k[0] for k in keys]

    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def summary_rule_lookup_to_markdown(results: Dict, title: str):
    out = []
    for result in results:
        sigantures = result.get('signatures', [])
        for sign in sigantures:
            new = {
                "Blocked": sign.get('counts').get('blocked'),
                "Detected": sign.get('counts').get('detected'),
                "Would Block": sign.get('counts').get('wouldblock'),
                "Last Event": sign.get('lasteventat')
            }
            out.append(new)
    headers = ['Blocked', 'Detected', 'Would Block', "Last Event"]
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def summary_destination_lookup_to_markdown(results: Dict, title: str) -> str:
    out = []
    keys = [
        ('Destination', 'domain', str),
        ('Application', 'summary_applications', int),
        ('Allowed Application', 'summary_applicationsallowed', int),
        ('Blocked Application', 'summary_applicationsblocked', int),
        ('Category', 'summary_categories', int),
        ('Domain', 'summary_domains', int),
        ('File', 'summary_files', int),
        ('File Type', 'summary_filetypes', int),
        ('Identity', 'summary_identities', int),
        ('Identity Type', 'summary_identitytypes', int),
        ('Policy Category', 'summary_policycategories', int),
        ('Policy Request', 'summary_policyrequests', int),
        ('Request', 'summary_requests', int),
        ('Allowed Request', 'summary_requestsallowed', int),
        ('Blocked Request', 'summary_requestsblocked', int)
    ]  # type: List[Tuple[str, str, Callable]]
    headers = [k[0] for k in keys]

    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)
    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def identities_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Identity', 'identity_label', str),
        ('Requests', 'requests', int)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=False)


@logger
def file_type_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
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
            "Category": ",".join(category),
            "Category Type": ",".join(type_list),
            "File Name": ",".join(file.get("filenames", [])),
            "File Types": ",".join(file.get("filetypes", []))
        }
        file_list.append(new)
    headers = file_list[0] if file_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, file_list, headers=headers,
                               removeNull=True)
    return markdown


@logger
def event_types_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Event Type', 'eventtype', str),
        ('Count', 'count', int)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=False)


@logger
def threat_lookup_to_markdown(results: List[Dict], title: str) -> str:
    out = []

    keys = [
        ('Threat', 'threat', str),
        ('Threat Type', 'threattype', str),
        ('Count', 'count', int)
    ]  # type: List[Tuple[str, str, Callable]]

    headers = [k[0] for k in keys]
    for result in results:
        row = dict()  # type: Dict[str, Any]
        for ckey, rkey, f in keys:
            if rkey in result:
                row[ckey] = f(result[rkey])
        out.append(row)

    return tableToMarkdown(title, out, headers=headers, removeNull=True)


@logger
def activity_lookup_to_markdown(results: List[Dict], title: str) -> str:
    activity_list = []
    for activity in results:
        category = [label.get("label") for label in
                    activity.get("categories", [])]
        identity = [label.get("label") for label in
                    activity.get("identities", [])]
        all_application = []
        application_category = []
        for application in activity.get("allapplications", []):
            all_application.append(application.get("label"))
            application_category.append(
                application.get("category").get("label"))
        timestamp = activity.get("timestamp", 0)
        timestamp_string = datetime.utcfromtimestamp(
            timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
        new = {
            "Request": activity.get("type", ''),
            "Identity": ",".join(identity),
            "Policy or Ruleset Identity": ",".join(identity),
            "Destination": activity.get("domain", ''),
            "Internal IP": activity.get("internalip", ''),
            "External IP": activity.get("externalip", ''),
            "DNS Type": activity.get("querytype", ''),
            "Action": activity.get("verdict", ''),
            "Categories": ",".join(category),
            "Public Application": ",".join(all_application),
            "Application Category": ",".join(application_category),
            "Date & Time": timestamp_string
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers,
                               removeNull=True)
    return markdown


@logger
def activity_dns_lookup_to_markdown(results: List[Dict], title: str) -> str:
    activity_list = []
    for activity in results:
        category = [label.get("label") for label in activity.get(
            'categories', [])]
        identity = [label.get("label") for label in activity.get(
            'identities', [])]
        all_application = []
        application_category = []
        for application in activity.get("allapplications", []):
            all_application.append(application.get("label"))
            application_category.append(application.get(
                "category").get("label"))
        timestamp = activity.get("timestamp", 0)
        timestamp_string = datetime.utcfromtimestamp(
            timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
        new = {
            "Identity": ",".join(identity),
            "Policy or Ruleset Identity": ",".join(identity),
            "Destination": activity.get("domain", ''),
            "Internal IP": activity.get("internalip", ''),
            "External IP": activity.get("externalip", ''),
            "DNS Type": activity.get("querytype", ''),
            "Action": activity.get("verdict", ''),
            "Categories": ",".join(category),
            "Public Application": ",".join(all_application),
            "Application Category": ",".join(application_category),
            "Date & Time": timestamp_string
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


@logger
def activity_proxy_lookup_to_markdown(results: List[Dict], title: str) -> str:
    activity_list = []
    for activity in results:
        category = [label.get("label") for label in activity.get(
            'categories', [])]
        identity = [label.get("label") for label in activity.get(
            'identities', [])]
        all_application = []
        application_category = []
        for application in activity.get("allapplications", []):
            all_application.append(application.get("label"))
            application_category.append(application.get(
                "category").get("label"))
        timestamp = activity.get("timestamp", 0)
        timestamp_string = datetime.utcfromtimestamp(
            timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
        new = {
            "Identity": ",".join(identity),
            "Policy or Ruleset Identity": ",".join(identity),
            "Internal IP": activity.get("internalip", ''),
            "External IP": activity.get("externalip", ''),
            "Action": activity.get("verdict", ''),
            "Categories": ",".join(category),
            "Public Application": ",".join(all_application),
            "Application Category": ",".join(application_category),
            "Date & Time": timestamp_string
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


@logger
def activity_firewall_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
    activity_list = []
    for activity in results:
        identity = [label.get("label") for label in activity.get(
            'identities', [])]
        all_application = [application.get("label") for application in
                           activity.get("allapplications", [])]
        timestamp = activity.get("timestamp", 0)
        timestamp_string = datetime.utcfromtimestamp(
            timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
        new = {
            "Identity": ",".join(identity),
            "Policy or Ruleset Identity": ",".join(identity),
            "Destination IP": activity.get("destinationip", ''),
            "Source IP": activity.get("sourceip", ''),
            "Source Port": activity.get("sourceport", ''),
            "Destination Port": activity.get("destinationport", ''),
            "Protocol": activity["protocol"].get("label") if activity.get(
                "protocol") else '',
            "Rule": activity["rule"].get("label") if activity.get("rule") else '',
            "Type": activity.get("type", ''),
            "Action": activity.get("verdict", ''),
            "Public Application": ",".join(all_application),
            "Direction": activity.get("direction", ''),
            "Date & Time": timestamp_string
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


@logger
def activity_intrusion_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
    activity_list = []
    for activity in results:
        identity = [label.get("label") for label in activity.get(
            'identities', [])]
        signature_cve = activity["signature"].get("cves") if activity.get(
            "signature") else []
        signature_lebel = activity["signature"].get("label") if activity.get(
            "signature") else ""
        timestamp = activity.get("timestamp", 0)
        timestamp_string = datetime.utcfromtimestamp(
            timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
        new = {
            "Identity": ",".join(identity),
            "Classification": activity.get("classification", ''),
            "Destination IP": activity.get("destinationip", ''),
            "Source IP": activity.get("sourceip", ''),
            "Source Port": activity.get("sourceport", ''),
            "Destination Port": activity.get("destinationport", ''),
            "Protocol": activity["protocol"].get("label") if activity.get(
                "protocol") else '',
            "Severity": activity.get("severity", ''),
            "CVE": ",".join(signature_cve),
            "Signature": signature_lebel,
            "Type": activity.get("type", ''),
            "Action": activity.get("verdict", ''),
            "Date & Time": timestamp_string
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


@logger
def activity_ip_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
    activity_list = []
    for activity in results:
        category = [label.get("label") for label in activity.get(
            'categories', [])]
        identity = [label.get("label") for label in activity.get(
            'identities', [])]
        timestamp = activity.get("timestamp", 0)
        timestamp_string = datetime.utcfromtimestamp(
            timestamp / 1000.0).strftime(DATE_TIME_FORMAT)
        new = {
            "Identity": ",".join(identity),
            "Destination IP": activity.get("destinationip", ''),
            "Source IP": activity.get("sourceip", ''),
            "Source Port": activity.get("sourceport", ''),
            "Destination Port": activity.get("destinationport", ''),
            "Categories": ",".join(category),
            "Type": activity.get("type", ''),
            "Action": activity.get("verdict", ''),
            "Date & Time": timestamp_string
        }
        activity_list.append(new)
    headers = activity_list[0] if activity_list else {}
    headers = list(headers.keys())
    markdown = tableToMarkdown(title, activity_list, headers=headers, removeNull=True)
    return markdown


@logger
def activity_amp_lookup_to_markdown(results: List[Dict], title: str) -> \
        str:
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


@logger
def pagination(args: Dict):
    page = args.pop('page', None)
    if page and int(page) <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    page = 0 if not page else (int(page) - 1)
    page_size = int(args.pop('page_size', 0))
    args["limit"] = page_size if page_size > 0 else args.get('limit', 50)
    args['offset'] = page * page_size
    return args


@logger
def get_param(args: Dict) -> Dict:
    args["from"] = args.pop('from', FROM_DATE)
    args["to"] = args.pop('to', TO_DATE)
    args["threattypes"] = args.pop('threat_types', None)
    args["identitytypes"] = args.pop('identity_types', None)
    args["ampdisposition"] = args.pop("amp_disposition", None)
    args["filename"] = args.pop("file_name", None)
    args["intrusionaction"] = args.pop("intrusion_action", None)

    return args


def get_destinations_list(client: Client, kwargs: Dict):
    traffic_type = kwargs.pop("traffic_type", None)
    endpoint = f"top-destinations/{traffic_type}" if traffic_type else "top-destinations"
    if "sha256" in kwargs.keys():
        check_valid_indicator_value("sha256", kwargs['sha256'])
    if "ip" in kwargs.keys():
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs.keys():
        check_valid_indicator_value('domains', kwargs['domains'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', '')
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    title = get_command_title_string("Destination", page, page_size)
    raw_jason_response = client.fetch_data_from_cisco_api(endpoint,
                                                          params).get("data", [])

    return CommandResults(
        readable_output=destination_lookup_to_markdown(raw_jason_response,
                                                       title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Destination',
        outputs_key_field='',
        outputs=raw_jason_response
    )


def get_categories_list(client: Client, kwargs: Dict):
    traffic_type = kwargs.pop("traffic_type", None)
    endpoint = f"top-categories/{traffic_type}" if traffic_type else "top-categories"
    if "sha256" in kwargs:
        check_valid_indicator_value("sha256", kwargs['sha256'])
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', 0)
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    title = get_command_title_string("Category", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])
    flatten_json_response: List = []
    if raw_json_response:
        flatten_json_response = get_flatten_json_response(raw_json_response)

    return CommandResults(
        readable_output=categories_lookup_to_markdown(
            flatten_json_response,
            title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Category',
        outputs_key_field='',
        outputs=raw_json_response
    )


def get_identities_list(client: Client, kwargs: Dict):
    traffic_type = kwargs.get("traffic_type", None)
    endpoint = f"top-identities/{traffic_type}" if traffic_type else "top-identities"
    if "sha256" in kwargs:
        check_valid_indicator_value("sha256", kwargs['sha256'])
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', 0)
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    title = get_command_title_string("Identities", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])
    flatten_json_response: List = []
    if raw_json_response:
        flatten_json_response = get_flatten_json_response(raw_json_response)

    return CommandResults(
        readable_output=identities_lookup_to_markdown(
            flatten_json_response,
            title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Identity',
        outputs_key_field='',
        outputs=raw_json_response
    )


def get_file_list(client: Client, kwargs: Dict):
    if "sha256" in kwargs:
        check_valid_indicator_value("sha256", kwargs['sha256'])
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', 0)
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    endpoint = 'top-files'
    title = get_command_title_string("File", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])

    return CommandResults(
        readable_output=file_type_lookup_to_markdown(raw_json_response, title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.File',
        outputs_key_field='',
        outputs=raw_json_response
    )


def get_threat_list(client: Client, kwargs: Dict):
    traffic_type = kwargs.pop("traffic_type", None)
    endpoint = f"top-threats/{traffic_type}" if traffic_type else "top-threats"
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', 0)
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    title = get_command_title_string("Threat", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])
    flatten_json_response: List = []
    if raw_json_response:
        flatten_json_response = get_flatten_json_response(raw_json_response)

    return CommandResults(
        readable_output=threat_lookup_to_markdown(flatten_json_response,
                                                  title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Threat',
        outputs_key_field='',
        outputs=raw_json_response
    )


def get_event_types_list(client: Client, kwargs: Dict):
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', 0)
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    endpoint = "top-eventtypes"
    title = get_command_title_string("Event Type", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])
    flatten_json_response: List = []
    if raw_json_response:
        flatten_json_response = get_flatten_json_response(raw_json_response)

    return CommandResults(
        readable_output=event_types_lookup_to_markdown(flatten_json_response,
                                                       title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.EventType',
        outputs_key_field='',
        outputs=raw_json_response
    )


def get_activity_list(client: Client, kwargs: Dict):
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', '')
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    endpoint = "activity"
    title = get_command_title_string("Activity", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])

    return CommandResults(
        readable_output=activity_lookup_to_markdown(raw_json_response, title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Activity',
        outputs_key_field='',
        outputs=raw_json_response,
    )


def get_activity_by_traffic_type(client: Client, kwargs: Dict):
    traffic_type = kwargs.pop("traffic_type", None)
    if traffic_type:
        endpoint = "activity/amp-retrospective" if traffic_type == "amp"\
            else f"activity/{traffic_type}"
    else:
        endpoint = "activity"
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
    if not set(kwargs.keys()).issubset(traffic_type_params_list):
        raise DemistoException(
            f"Invalid optional parameter is selected for {traffic_type}")
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    if "sha256" in kwargs:
        check_valid_indicator_value("sha256", kwargs['sha256'])
    if "intrusion_action" in kwargs:
        check_valid_indicator_value("intrusion_action", kwargs['intrusion_action'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', 0)
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    title = get_command_title_string(f"{traffic_type.capitalize()} "
                                     f"Activity", page, page_size)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])

    return CommandResults(
        readable_output=markdown_function[traffic_type](
            raw_json_response, title),
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.{context_output_name[traffic_type]}',
        outputs_key_field='',
        outputs=raw_json_response,
    )


def get_summary_list(client: Client, kwargs: Dict):
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
    summary_type = kwargs.pop("summary_type", None)
    endpoint = summary_endpoint_dict.get(summary_type, "summary")
    category_type_param_list = SUMMARY_TYPE_DICT.get(summary_type,
                                                     SUMMARY_TYPE_DICT["all"])
    if not set(kwargs.keys()).issubset(category_type_param_list):
        raise DemistoException(
            f"Invalid optional parameter is selected for {summary_type}")
    if "ip" in kwargs:
        check_valid_indicator_value("ip", kwargs['ip'])
    if "domains" in kwargs:
        check_valid_indicator_value('domains', kwargs['domains'])
    if "intrusion_action" in kwargs:
        check_valid_indicator_value("intrusion_action", kwargs['intrusion_action'])
    page = kwargs.get("page", None)
    page_size = kwargs.get('page_size', 0)
    kwargs = pagination(kwargs)
    params = get_param(kwargs)
    raw_json_response = client.fetch_data_from_cisco_api(endpoint,
                                                         params).get("data", [])

    if summary_type:
        flatten_json_response = get_flatten_json_response(
            raw_json_response)
        title = get_command_title_string(
            f"Summary with "
            f"{summary_type.split('_')[0].capitalize()}", page, page_size)
        return CommandResults(
            readable_output=summary_markdown_dict[summary_type](
                flatten_json_response,
                title),
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}'
                           f'.{context_output_name[summary_type]}',
            outputs_key_field='',
            outputs=raw_json_response
        )

    else:
        title = get_command_title_string("Summary", page, page_size)
        return CommandResults(
            readable_output=summary_lookup_to_markdown(
                raw_json_response,
                title),
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Summary',
            outputs_key_field='',
            outputs=raw_json_response
        )


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    secret_key = demisto.params().get('credentials').get('password')
    client_key = demisto.params().get('credentials').get('identifier')
    organisation_id = demisto.params().get('organization_id')

    # get the service API url
    base_url = demisto.params().get("api_url")

    # How much time before the first fetch to retrieve incidents

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            organisation_id=organisation_id,
            secret_key=secret_key,
            client_key=client_key,
            proxy=proxy)

        commands = {
            'test-module': test_module,
            "umbrella-reporting-destination-list":
                get_destinations_list,
            "umbrella-reporting-category-list":
                get_categories_list,
            "umbrella-reporting-identity-list":
                get_identities_list,
            "umbrella-reporting-event-type-list":
                get_event_types_list,
            "umbrella-reporting-file-list":
                get_file_list,
            "umbrella-reporting-threat-list":
                get_threat_list,
            "umbrella-reporting-activity-list":
                get_activity_list,
            "umbrella-reporting-activity-get":
                get_activity_by_traffic_type,
            "umbrella-reporting-summary-list":
                get_summary_list
        }

        args = demisto.args()
        command = demisto.command()
        if command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError
    # Log exceptions
    except Exception as e:
        return_error(
            f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
