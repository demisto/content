import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''


import base64
import hashlib
import hmac
import time
import json
import requests
import urllib.parse
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        expires = int(time.time() + 30)
        request_type = kwargs.pop("request_type", "get")
        data = kwargs.get("data")
        kwargs["AccessID"] = self.access_id
        kwargs["Expires"] = expires
        kwargs["Signature"] = self.signature(expires)

        full_url = full_url + "?" + urllib.parse.urlencode(kwargs)
        if request_type == "get":
            resp = requests.get(full_url, verify=self.verify, proxies=self.proxies)
        else:
            headers = {"content-type": "application/json"}
            resp = requests.post(
                full_url,
                data=data,
                verify=self.verify,
                proxies=self.proxies,
                headers=headers,
            )
        status_code = resp.status_code
        try:
            resp.raise_for_status()  # Raising an exception for non-200 status code
        except requests.exceptions.HTTPError as e:
            err_msg = f"Error in API call {[resp.status_code]}"
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

    def create_intel(self, data: dict):
        """
        Makes post call and creates Intel In CTIX Platform
        :type data: ``dict``
        :param data: Intel data

        :return: dict containing post call response returned from the API
        :rtype: ``Dict[str, Any]``
        """
        url_suffix = "create-intel/"
        client_url = self.base_url + url_suffix
        return self.http_request(
            full_url=client_url, data=json.dumps(data), request_type="post"
        )

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


def ip_details_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
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
    ip_map = {ip.get("name2"): ip for ip in ip_list}

    for ip_obj in ip_addresses_array:
        if ip_obj not in ip_map:
            ip_map.update({ip_obj: []})

    ip_data_list = []
    for ip_key, ip_data in ip_map.items():
        if ip_data:
            score = to_dbot_score(ip_data.get("score", 0))
            dbot_score = Common.DBotScore(
                indicator=ip_data.get("name2"),
                indicator_type=DBotScoreType.IP,
                integration_name='CTIX',
                score=score,
                reliability=demisto.params().get('integrationReliability')
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
        else:
            dbot_score = Common.DBotScore(
                indicator=ip_key,
                indicator_type=DBotScoreType.IP,
                integration_name="CTIX",
                score=0,
                reliability=demisto.params().get('integrationReliability')
            )
            ip_standard_context = Common.IP(
                ip=ip_key,
                dbot_score=dbot_score
            )
            ip_data_list.append(CommandResults(
                readable_output=f'No matches found for IP {ip_key}',
                outputs_prefix='CTIX.IP',
                outputs_key_field='name2',
                outputs=ip_data,
                indicator=ip_standard_context
            ))

    return ip_data_list


def domain_details_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
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
    domain_map = {domain.get("name2"): domain for domain in domain_list}

    for domain_obj in domain_array:
        if domain_obj not in domain_map:
            domain_map.update({domain_obj: []})

    domain_data_list = []
    for domain_key, domain_data in domain_map.items():
        if domain_data:
            score = to_dbot_score(domain_data.get("score", 0))
            dbot_score = Common.DBotScore(
                indicator=domain_key,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name='CTIX',
                score=score,
                reliability=demisto.params().get('integrationReliability')
            )
            domain_standard_context = Common.Domain(
                domain=domain_key,
                dbot_score=dbot_score
            )
            domain_data_list.append(CommandResults(
                readable_output=tableToMarkdown('Domain Data', domain_data, removeNull=True),
                outputs_prefix='CTIX.Domain',
                outputs_key_field='name2',
                outputs=domain_data,
                indicator=domain_standard_context
            ))
        else:
            dbot_score = Common.DBotScore(
                indicator=domain_key,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name="CTIX",
                score=0,
                reliability=demisto.params().get('integrationReliability')
            )
            domain_standard_context = Common.Domain(
                domain=domain_key,
                dbot_score=dbot_score
            )
            domain_data_list.append(CommandResults(
                readable_output=f'No matches found for Domain {domain_key}',
                outputs_prefix='CTIX.Domain',
                outputs_key_field='name2',
                outputs=domain_data,
                indicator=domain_standard_context
            ))

    return domain_data_list


def url_details_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
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
    url_map = {url["name2"]: url for url in url_list}

    for url_obj in url_array:
        if url_obj not in url_map:
            url_map.update({url_obj: []})

    url_data_list = []
    for url_key, url_data in url_map.items():
        if url_data:
            score = to_dbot_score(url_data.get("score", 0))
            dbot_score = Common.DBotScore(
                indicator=url_key,
                indicator_type=DBotScoreType.URL,
                integration_name='CTIX',
                score=score,
                reliability=demisto.params().get('integrationReliability')
            )
            url_standard_context = Common.URL(
                url=url_key,
                dbot_score=dbot_score
            )
            url_data_list.append(CommandResults(
                readable_output=tableToMarkdown('URL Data', url_data, removeNull=True),
                outputs_prefix='CTIX.URL',
                outputs_key_field='name2',
                outputs=url_data,
                indicator=url_standard_context,
            ))
        else:
            dbot_score = Common.DBotScore(
                indicator=url_key,
                indicator_type=DBotScoreType.URL,
                integration_name="CTIX",
                score=0,
                reliability=demisto.params().get('integrationReliability')
            )
            url_standard_context = Common.URL(
                url=url_key,
                dbot_score=dbot_score
            )
            url_data_list.append(CommandResults(
                readable_output=f'No matches found for URL {url_key}',
                outputs_prefix='CTIX.URL',
                outputs_key_field='name2',
                outputs=url_data,
                indicator=url_standard_context
            ))

    return url_data_list


def file_details_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
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
    file_map = {file["name2"]: file for file in file_list}

    for file_obj in file_array:
        if file_obj not in file_map:
            file_map.update({file_obj: []})
    file_data_list = []
    for file_key, file_data in file_map.items():
        hash_type = get_hash_type(file_key)
        if file_data:
            score = to_dbot_score(file_data.get("score", 0))
            dbot_score = Common.DBotScore(
                indicator=file_key,
                indicator_type=DBotScoreType.FILE,
                integration_name='CTIX',
                score=score,
                reliability=demisto.params().get('integrationReliability')
            )
            file_standard_context = Common.File(
                name=file_key,
                dbot_score=dbot_score
            )
            if hash_type == "md5":
                file_standard_context.md5 = file_key
            elif hash_type == "sha1":
                file_standard_context.sha1 = file_key
            elif hash_type == "sha256":
                file_standard_context.sha256 = file_key
            elif hash_type == "sha512":
                file_standard_context.sha512 = file_key

            file_data_list.append(CommandResults(
                readable_output=tableToMarkdown('File Data', file_data, removeNull=True),
                outputs_prefix='CTIX.File',
                outputs_key_field='name2',
                outputs=file_data,
                indicator=file_standard_context
            ))
        else:
            dbot_score = Common.DBotScore(
                indicator=file_key,
                indicator_type=DBotScoreType.FILE,
                integration_name="CTIX",
                score=0,
                reliability=demisto.params().get('integrationReliability')
            )
            file_standard_context = Common.File(
                name=file_key,
                dbot_score=dbot_score
            )
            if hash_type == "md5":
                file_standard_context.md5 = file_key
            elif hash_type == "sha1":
                file_standard_context.sha1 = file_key
            elif hash_type == "sha256":
                file_standard_context.sha256 = file_key
            elif hash_type == "sha512":
                file_standard_context.sha512 = file_key

            file_data_list.append(CommandResults(
                readable_output=f'No matches found for FILE {file_key}',
                outputs_prefix='CTIX.File',
                outputs_key_field='name2',
                outputs=file_data,
                indicator=file_standard_context
            ))
    return file_data_list


def create_intel_command(client: Client, args: dict[str, Any]) -> dict:
    """
    create_intel command: Creates Intel in CTIX
    """
    data = {
        "ips": args.get("ips", []),
        "urls": args.get("urls", []),
        "domains": args.get("domains", []),
        "files": args.get("files", []),
        "emails": args.get("emails", []),
        "malwares": args.get("malwares", []),
        "threat_actors": args.get("threat_actors", []),
        "attack_patterns": args.get("attack_patterns", []),
        "title": args.get("title"),
        "description": args.get("description"),
        "confidence": args.get("confidence"),
        "tlp": args.get("tlp"),
    }
    create_intel_response = client.create_intel(data)
    return {
        "CTIX": {
            "Intel": {
                "response": create_intel_response.get("data"),
                "status": create_intel_response.get("status")
            }
        }
    }


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
        elif demisto.command() == 'ctix-create-intel':
            return_results(create_intel_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
