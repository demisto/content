import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
'''IMPORTS'''


import base64
import hashlib
import hmac
import time
import requests
import urllib
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


class Client:
    """
    Client class to interact with the service API
    """
    def __init__(self, base_url: str, access_id: str, secret_key: str) -> None:
        self.base_url = base_url
        self.access_id = access_id
        self.secret_key = secret_key

    def signature(self, expires: int) -> str:
        to_sign = "%s\n%i" % (self.access_id, expires)
        return base64.b64encode(hmac.new(
            self.secret_key.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1).digest()
                                ).decode("utf-8")

    def http_request(self, **params):
        """
        A wrapper to send requests and handle responses.
        """
        expires = int(time.time() + 5)
        params["AccessID"] = self.access_id
        params["Expires"] = expires
        params["Signature"] = self.signature(expires)
        url_suffix = "objects/indicator/"
        url = self.base_url + url_suffix + "?" + urllib.parse.urlencode(params)
        try:
            resp = (requests.get(url))
            status_code = resp.status_code
            if status_code != 200:
                return_error('Error in API call to CTIX. Status Code: ' + str(resp.status_code))
            json_data = resp.json()
            response = {"data": json_data, "status": status_code}
            return response
        except Exception as e:
            LOG(e)
            return_error(str(e))

    def get_ip_details(self, ip: list, enhanced: bool = False) -> Dict[str, Any]:
        """Gets the IP Details

        :type ip: ``str``
        :param ip: IP address

        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the IP Details as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        ip_string = ",".join(ip)

        if enhanced == "True":
            params = {"enhanced_search": ip_string}
        else:
            params = {"q": ip_string}
        return self.http_request(**params)

    def get_domain_details(self, domain: list, enhanced: bool = False) -> Dict[str, Any]:
        """Gets the Domain Details

        :type domain: ``str``
        :param domain: domain name

        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the domain details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        domain_string = ",".join(domain)

        if enhanced == "True":
            params = {"enhanced_search": domain_string}
        else:
            params = {"q": domain_string}

        return self.http_request(**params)

    def get_url_details(self, url: list, enhanced: bool = False) -> Dict[str, Any]:
        """Gets the URL Details

        :type url: ``str``
        :param url: url name

        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the url details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        url_string = ",".join(url)

        if enhanced == "True":
            params = {"enhanced_search": url_string}
        else:
            params = {"q": url_string}

        return self.http_request(**params)

    def get_file_details(self, file: list, enhanced: bool = False) -> Dict[str, Any]:
        """Gets the File Details

        :type file: ``str``
        :param file: file name

        :type enhanced: ``bool``
        :param enhanced: Enhanced search flag

        :return: dict containing the file details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        file_string = ",".join(file)
        if enhanced == "True":
            params = {"enhanced_search": file_string}
        else:
            params = {"q": file_string}

        return self.http_request(**params)


''' HELPER FUNCTIONS '''


def to_dbot_score(ctix_score: int) -> Common.DBotScore:
    """
    Maps CTIX Score to DBotScore
    """
    if ctix_score == 0:
        dbot_score = Common.DBotScore.NONE  # unknown
    elif ctix_score <= 30:
        dbot_score = Common.DBotScore.GOOD  # good
    elif ctix_score <=70:
        dbot_score = Common.DBotScore.SUSPICIOUS  # suspicious
    else:
        dbot_score = Common.DBotScore.BAD
    return dbot_score


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    """
    Performs basic get request to get sample ip details.
    """
    client.get_ip_details(ip="8.208.20.145", enhanced=False)

    # test was successful
    demisto.results('ok')


def ip_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    ip command: Returns IP details for a list of IPs
    """
    ip_addresses_string = args.get('ip')
    ip_addresses_array = argToList(ip_addresses_string)

    for ip_address in ip_addresses_array: # Check for Valid IP Inputs
        if not is_ip_valid(ip_address, accept_v6_ips=True):
            return_error('{0} is not a valid IP Address.'.format(ip_address))

    enhanced = args.get('enhanced')
    response = client.get_ip_details(ip_addresses_array, enhanced)
    ip_list = response.get("data", {}).get("results", {})
    ip_data_list, ip_standard_list = [], []
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
        ip_standard_list.append(ip_standard_context)
        ip_data_list.append(ip_data)

    readable_output = tableToMarkdown('IP List', ip_data_list, removeNull=True)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CTIX.IP',
        outputs_key_field='name2',
        outputs=ip_data_list,
        indicators=ip_standard_list
    )


def domain_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    domain command: Returns domain details for a list of domains
    """
    domain_string = args.get('domain')
    domain_array = argToList(domain_string)

    for domain in domain_array:  # Check for Valid Domain Inputs
        if not REGEX_MAP['domain'].match(domain):
            return_error('{0} is not a valid domain.'.format(domain))
    enhanced = args.get('enhanced')
    response = client.get_domain_details(domain_array, enhanced)
    domain_list = response.get("data", {}).get("results", {})
    domain_data_list, domain_standard_list = [], []
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
        domain_standard_list.append(domain_standard_context)
        domain_data_list.append(domain_data)

    readable_output = tableToMarkdown('Domain List', domain_data_list, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CTIX.Domain',
        outputs_key_field='name2',
        outputs=domain_data_list,
        indicators=domain_standard_list
    )


def url_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    url command: Returns URL details for a list of URL
    """
    url_string = args.get('url')
    url_array = argToList(url_string)

    for url in url_array:  # Check for Valid URL Inputs
        if not REGEX_MAP['url'].match(url):
            return_error('{0} is not a valid url.'.format(url))
    enhanced = args.get('enhanced')
    response = client.get_url_details(url_array, enhanced)
    url_list = response.get("data", {}).get("results", {})
    url_data_list, url_standard_list = [], []
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
        url_standard_list.append(url_standard_context)
        url_data_list.append(url_data)

    readable_output = tableToMarkdown('URL List', url_data_list, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CTIX.URL',
        outputs_key_field='name2',
        outputs=url_data_list,
        indicators=url_standard_list
    )


def file_details_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    file command: Returns FILE details for a list of FILE
    """
    file_string = args.get('file')
    file_array = argToList(file_string)

    for file in file_array:  # Check for Valid File Inputs
        if not REGEX_MAP['hash'].match(file):
            return_error('{0} is not a valid file.'.format(file))
    enhanced = args.get('enhanced')
    response = client.get_file_details(file_array, enhanced)
    file_list = response.get("data", {}).get("results", {})
    file_data_list, file_standard_list = [], []
    for file_data in file_list:
        score = to_dbot_score(file_data.get("score",0))
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
        file_standard_list.append(file_standard_context)
        file_data_list.append(file_data)

    readable_output = tableToMarkdown('File List', file_data_list, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CTIX.File',
        outputs_key_field='name2',
        outputs=file_data_list,
        indicators=file_standard_list
    )


def main() -> None:

    base_url = demisto.params().get('base_url')
    access_id = demisto.params().get('access_id')
    secret_key = demisto.params().get('secret_key')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            access_id=access_id,
            secret_key=secret_key)

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
