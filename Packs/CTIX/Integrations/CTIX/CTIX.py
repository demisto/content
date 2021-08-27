import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''


import base64
import hashlib
import hmac
import time
import requests
import urllib.parse
import urllib3
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()

'''GLOBALS'''

domain_regex = (
    "([a-z¡-\uffff0-9](?:[a-z¡-\uffff0-9-]{0,61}"
    "[a-z¡-\uffff0-9])?(?:\\.(?!-)[a-z¡-\uffff0-9-]{1,63}(?<!-))*"
    "\\.(?!-)(?!(jpg|jpeg|exif|tiff|tif|png|gif|otf|ttf|fnt|dtd|xhtml|css"
    "|html)$)(?:[a-z¡-\uffff-]{2,63}|xn--[a-z0-9]{1,59})(?<!-)\\.?$"
    "|localhost)"
)

REGEX_MAP = {
    'url': re.compile(urlRegex, regexFlags),
    'domain': re.compile(domain_regex, regexFlags),
    'hash': re.compile(hashRegex, regexFlags)
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """
        Client to use in the CTIX integration. Overrides BaseClient
    """
    def __init__(self, base_url: str, access_id: str, secret_key: str, verify: bool, proxies: dict) -> None:
        self.base_url = base_url
        self.access_id = access_id
        self.secret_key = secret_key
        self.verify = verify
        self.proxies = proxies

    def signature(self, expires: int) -> str:
        to_sign = "%s\n%i" % (self.access_id, expires)
        return base64.b64encode(
            hmac.new(
                self.secret_key.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1
            ).digest()
        ).decode("utf-8")

    def http_request(self, full_url: str, **kwargs):
        """
        A wrapper to send requests and handle responses.
        """
        expires = int(time.time() + 5)
        kwargs["AccessID"] = self.access_id
        kwargs["Expires"] = expires
        kwargs["Signature"] = self.signature(expires)

        full_url = full_url + "?" + urllib.parse.urlencode(kwargs)
        resp = (requests.get(full_url, verify=self.verify, proxies=self.proxies))
        status_code = resp.status_code
        try:
            resp.raise_for_status()  # Raising an exception for non-200 status code
        except requests.exceptions.HTTPError as e:
            err_msg = 'Error in API call [{}]' \
                .format(resp.status_code)
            raise DemistoException(err_msg, e)
        json_data = resp.json()
        response = {"data": json_data, "status": status_code}
        return response

    def test_auth(self):
        client_url = self.base_url + "ping/"
        return self.http_request(client_url)

    def get_ip_details(self, ip: list, enhanced: bool = False):
        """Gets the IP Details

        :type ip: ``list``
        :param ip: IP address

        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the IP Details as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        ip_string = ",".join(ip)

        if enhanced and argToBoolean(enhanced):
            params = {"enhanced_search": ip_string}
        else:
            params = {"q": ip_string}

        url_suffix = "objects/indicator/"
        client_url = self.base_url + url_suffix
        return self.http_request(full_url=client_url, **params)

    def get_domain_details(self, domain: list, enhanced: bool = False):
        """Gets the Domain Details

        :type domain: ``list``
        :param domain: domain name

        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the domain details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        domain_string = ",".join(domain)

        if enhanced and argToBoolean(enhanced):
            params = {"enhanced_search": domain_string}
        else:
            params = {"q": domain_string}

        url_suffix = "objects/indicator/"
        client_url = self.base_url + url_suffix
        return self.http_request(full_url=client_url, **params)

    def get_url_details(self, url: list, enhanced: bool = False):
        """Gets the URL Details

        :type url: ``list``
        :param url: url name
        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the url details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        url_string = ",".join(url)

        if enhanced and argToBoolean(enhanced):
            params = {"enhanced_search": url_string}
        else:
            params = {"q": url_string}

        url_suffix = "objects/indicator/"
        client_url = self.base_url + url_suffix
        return self.http_request(full_url=client_url, **params)

    def get_file_details(self, file: list, enhanced: bool = False):
        """Gets the File Details

        :type file: ``list``
        :param file: file name

        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the file details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        file_string = ",".join(file)
        if enhanced and argToBoolean(enhanced):
            params = {"enhanced_search": file_string}
        else:
            params = {"q": file_string}

        url_suffix = "objects/indicator/"
        client_url = self.base_url + url_suffix
        return self.http_request(full_url=client_url, **params)


''' HELPER FUNCTIONS '''


def to_dbot_score(ctix_score: int) -> int:
    """
    Maps CTIX Score to DBotScore
    """
    if ctix_score == 0:
        dbot_score = Common.DBotScore.NONE  # unknown
    elif ctix_score <= 30:
        dbot_score = Common.DBotScore.GOOD  # good
    elif ctix_score <= 70:
        dbot_score = Common.DBotScore.SUSPICIOUS  # suspicious
    else:
        dbot_score = Common.DBotScore.BAD
    return dbot_score


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    """
    Performs basic get request to get sample ip details.
    """
    client.test_auth()
    # test was successful
    demisto.results('ok')


def ip_details_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    ip command: Returns IP details for a list of IPs
    """
    ip_addresses_string = args.get('ip')
    ip_addresses_array = argToList(ip_addresses_string)
    invalid_ips = []

    for ip_address in ip_addresses_array:  # Check for Valid IP Inputs
        if not is_ip_valid(ip_address, accept_v6_ips=True):
            invalid_ips.append(ip_address)

    if invalid_ips:
        return_warning('The following IP Addresses were found invalid: {}'.format(', '.join(invalid_ips)),
                       exit=len(invalid_ips) == len(ip_addresses_array))

    enhanced = argToBoolean(args.get('enhanced', False))
    response = client.get_ip_details(ip_addresses_array, enhanced)
    ip_list = response.get("data", {}).get("results", {})
    ip_data_list = []
    for ip_data in ip_list:
        score = to_dbot_score(ip_data.get("score", 0))
        dbot_score = Common.DBotScore(
            indicator=ip_data.get("name2"),
            indicator_type=DBotScoreType.IP,
            integration_name='CTIX',
            score=score
        )
        ip_standard_context = Common.IP(
            ip=ip_data.get("name2"),
            asn=ip_data.get("asn"),
            dbot_score=dbot_score
        )
        ip_data_list.append(CommandResults(
            readable_output=tableToMarkdown('IP Data', ip_data, removeNull=True),
            outputs_prefix='CTIX.IP',
            outputs_key_field='name2',
            outputs=ip_data,
            indicator=ip_standard_context
        ))

    return ip_data_list


def domain_details_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    domain command: Returns domain details for a list of domains
    """
    domain_string = args.get('domain')
    domain_array = argToList(domain_string)
    invalid_domains = []

    for domain in domain_array:  # Check for Valid Domain Inputs
        if not REGEX_MAP['domain'].match(domain):
            invalid_domains.append(domain)

    if invalid_domains:
        return_warning('The following Domains were found invalid: {}'.format(', '.join(invalid_domains)),
                       exit=len(invalid_domains) == len(domain_array))

    enhanced = argToBoolean(args.get('enhanced', False))
    response = client.get_domain_details(domain_array, enhanced)
    domain_list = response.get("data", {}).get("results", {})
    domain_data_list = []
    for domain_data in domain_list:
        score = to_dbot_score(domain_data.get("score", 0))
        dbot_score = Common.DBotScore(
            indicator=domain_data.get("name2"),
            indicator_type=DBotScoreType.DOMAIN,
            integration_name='CTIX',
            score=score
        )
        domain_standard_context = Common.Domain(
            domain=domain_data.get("name2"),
            dbot_score=dbot_score
        )
        domain_data_list.append(CommandResults(
            readable_output=tableToMarkdown('Domain Data', domain_data, removeNull=True),
            outputs_prefix='CTIX.Domain',
            outputs_key_field='name2',
            outputs=domain_data,
            indicator=domain_standard_context
        ))

    return domain_data_list


def url_details_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    url command: Returns URL details for a list of URL
    """
    url_string = args.get('url')
    url_array = argToList(url_string)
    invalid_urls = []

    for url in url_array:  # Check for Valid URL Inputs
        if not REGEX_MAP['url'].match(url):
            invalid_urls.append(url)
    if invalid_urls:
        return_warning('The following URLs were found invalid: {}'.format(', '.join(invalid_urls)),
                       exit=len(invalid_urls) == len(url_array))

    enhanced = argToBoolean(args.get('enhanced', False))
    response = client.get_url_details(url_array, enhanced)
    url_list = response.get("data", {}).get("results", {})
    url_data_list = []
    for url_data in url_list:
        score = to_dbot_score(url_data.get("score", 0))
        dbot_score = Common.DBotScore(
            indicator=url_data.get("name2"),
            indicator_type=DBotScoreType.URL,
            integration_name='CTIX',
            score=score,
        )
        url_standard_context = Common.URL(
            url=url_data.get("name2"),
            dbot_score=dbot_score
        )
        url_data_list.append(CommandResults(
            readable_output=tableToMarkdown('URL Data', url_data, removeNull=True),
            outputs_prefix='CTIX.URL',
            outputs_key_field='name2',
            outputs=url_data,
            indicator=url_standard_context
        ))

    return url_data_list


def file_details_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    file command: Returns FILE details for a list of FILE
    """
    file_string = args.get('file')
    file_array = argToList(file_string)
    invalid_hashes = []
    for file in file_array:  # Check for Valid File Inputs
        if not REGEX_MAP['hash'].match(file):
            invalid_hashes.append(file)

    if invalid_hashes:
        return_warning('The following Hashes were found invalid: {}'.format(', '.join(invalid_hashes)),
                       exit=len(invalid_hashes) == len(file_array))

    enhanced = argToBoolean(args.get('enhanced', False))
    response = client.get_file_details(file_array, enhanced)
    file_list = response.get("data", {}).get("results", {})
    file_data_list = []
    for file_data in file_list:
        score = to_dbot_score(file_data.get("score", 0))
        dbot_score = Common.DBotScore(
            indicator=file_data.get("name2"),
            indicator_type=DBotScoreType.FILE,
            integration_name='CTIX',
            score=score
        )
        file_standard_context = Common.File(
            name=file_data.get("name2"),
            dbot_score=dbot_score
        )
        file_data_list.append(CommandResults(
            readable_output=tableToMarkdown('File Data', file_data, removeNull=True),
            outputs_prefix='CTIX.File',
            outputs_key_field='name2',
            outputs=file_data,
            indicator=file_standard_context
        ))

    return file_data_list


def main() -> None:

    base_url = demisto.params().get('base_url')
    access_id = demisto.params().get('access_id')
    secret_key = demisto.params().get('secret_key')
    verify = not demisto.params().get('insecure', False)
    proxies = handle_proxy(proxy_param_name="proxy")

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            access_id=access_id,
            secret_key=secret_key,
            verify=verify,
            proxies=proxies,
        )

        if demisto.command() == 'test-module':
            test_module(client)
        elif demisto.command() == 'ip':
            return_results(ip_details_command(client, demisto.args()))
        elif demisto.command() == 'domain':
            return_results(domain_details_command(client, demisto.args()))
        elif demisto.command() == 'url':
            return_results(url_details_command(client, demisto.args()))
        elif demisto.command() == 'file':
            return_results(file_details_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
