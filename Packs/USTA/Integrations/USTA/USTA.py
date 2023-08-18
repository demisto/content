import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

import hashlib
import json
import traceback
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES'''
VERIFY_SSL = not demisto.params().get('insecure', False)

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
handle_proxy()


def test_module() -> str:
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        url = demisto.params().get('url')[:-1] if str(demisto.params().get('url')).endswith('/') \
            else demisto.params().get('url')
        CREDENTIALS = demisto.params().get('apikey')
        # AUTH_HEADERS = {'Content-Type': 'application/json'}

        params = "TOKEN " + CREDENTIALS
        headers = {"Authorization": params,
                   "Content-Type": "application/json"
                   }

        base_url = urljoin(url, '/api')
        endpoint = "/threat-stream/malicious-urls?format=json"

        url = urljoin(base_url, endpoint)
        req = requests.get(url, headers=headers, verify=VERIFY_SSL)
        status = req.status_code
        if status != 200:
            return str(status)
    except Exception as e:
        if ('Forbidden' in str(e)):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any SOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_malicious_url(self, param: dict) -> Dict[str, Any]:
        """Gets the Malicious url using the '/threat-stream/malicious-urls' API endpoint

        :return: dict containing the Malicious URL details as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/threat-stream/malicious-urls',
            params=param
        )

    def get_malware_hash(self, param: dict) -> Dict[str, Any]:
        """Gets the Malicious hashs using the '/threat-stream/malware-hashs' API endpoint

        :return: dict containing the Malicious Hash details as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/threat-stream/malware-hashs',
            params=param
        )

    def get_phishing_sites(self, param: dict) -> Dict[str, Any]:
        """Available for all Phishing Sites created for your company that using the '/threat-stream/phishing-sites' API endpoint

        :return: dict containing the Phishing Site details as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/threat-stream/phishing-sites',
            params=param
        )

    def get_identity_leaks(self, param: dict) -> Dict[str, Any]:
        """Gets the Leaked Accounts related your company using the '/threat-stream/identity-leaks' API endpoint

        :return: dict containing the Account details as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/threat-stream/identity-leaks',
            params=param
        )

    def get_stolen_client_accounts(self, param: dict) -> Dict[str, Any]:
        """Gets the Stolen Client Accounts related any service using the '/threat-stream/stolen-client-accounts' API endpoint

        :return: dict containing the Accounts details as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/threat-stream/stolen-client-accounts',
            params=param
        )

    def get_domain(self, param: dict) -> Dict[str, Any]:
        """Gets the Domain details using the '/threat-stream/domain' API endpoint

        :return: dict containing the Domain details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='POST',
            url_suffix='/threat-stream/domain',
            json_data=param
        )

    def get_ip_address(self, param: dict) -> Dict[str, Any]:
        """Gets the IP details using the '/threat-stream/ip-address' API endpoint

        :return: dict containing the IP details as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='POST',
            url_suffix='/threat-stream/ip-address',
            json_data=param
        )


def search_malicious_urls(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Gets the Malicious url using the '/threat-stream/malicious-urls' API endpoint

        :type format: ``str``
        :param - format: It determines the data type of the response that will return via API.
        :Available values : json, stix, stix2, txt. Default value : json

        :type url: ``str``
        :param - url: For filtering with URL

        :type is_domain: ``boolean``
        :param - is_domain: Provides filtering for data with or without domain names

        :type url_type: ``str``
        :param - url_type: For filtering with URL Type.
        :Available values : Phishing, C2, Downloader

        :type tag: ``str``
        :param - tag: For filtering with tags

        :type start: ``str``
        :param - start: Starting parameter for analysis

        :type end: ``str``
        :param - end: End parameter for analysis
        """
    url = args.get('url')
    is_domain = args.get('is_domain')
    url_type = args.get('url_type')
    tag = args.get('tag')
    start = args.get('start')
    end = args.get('end')
    formatType = args.get('format')

    param = {}

    if start:
        startDate = timeToEpoch(start)
    else:
        startDate = start

    if end:
        endDate = timeToEpoch(end)
    else:
        endDate = end

    param = {
        'url': url,
        'is_domain': is_domain,
        'url_type': url_type,
        'tag': tag,
        'start': startDate,
        'end': endDate,
        'format': formatType
    }

    maliciousURL = client.get_malicious_url(param=param)

    readable_output = tableToMarkdown('Malicious URL', maliciousURL)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='USTA.Malicious_URL',
        outputs_key_field='url',
        outputs=maliciousURL
    )


def search_malware_hashs(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Gets the Malicious hashs using the '/threat-stream/malware-hashs' API endpoint

        :type format: ``str``
        :param - format: It determines the data type of the response that will return via API.
        :Available values : json, stix, stix2, txt. Default value : json

        :type md5: ``str``
        :param - md5: For filtering with md5

        :type sha1: ``boolean``
        :param - sha1: For filtering with sha1.

        :type tag: ``str``
        :param - tag: For filtering with tags

        :type start: ``str``
        :param - start: Starting parameter for analysis

        :type end: ``str``
        :param - end: End parameter for analysis
        """
    md5 = args.get('md5')
    sha1 = args.get('sha1')
    tag = args.get('tag')
    start = args.get('start')
    end = args.get('end')
    formatType = args.get('format')

    if start:
        startDate = timeToEpoch(start)
    else:
        startDate = start

    if end:
        endDate = timeToEpoch(end)
    else:
        endDate = end

    param = {
        'md5': md5,
        'sha1': sha1,
        'tag': tag,
        'start': startDate,
        'end': endDate,
        'format': formatType
    }

    malwareHash = client.get_malware_hash(param=param)

    readable_output = tableToMarkdown('Malware Hashs', malwareHash)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='USTA.Malware_Hash',
        outputs_key_field='md5',
        outputs=malwareHash
    )


def search_phishing_sites(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Available for all Phishing Sites created for your company that using the '/threat-stream/phishing-sites' API endpoint

        :type status: ``str``
        :param - status: For filtering with status
        :Available values : open, close, in_progress, out_of_scope, passive

        :type source: ``str``
        :param - source: For filtering with source

        :type page: ``str``
        :param - page: For pagination
        """
    status = args.get('status')
    source = args.get('source')
    page = args.get('page')

    param = {
        'status': status,
        'source': source,
        'page': page
    }

    phishingSites = client.get_phishing_sites(param=param)

    readable_output = tableToMarkdown('Phishing Sites', phishingSites)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='USTA.Phishing_Sites',
        outputs_key_field='results',
        outputs=phishingSites
    )


def search_identity_leaks(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Gets the Leaked Accounts related your company using the '/threat-stream/identity-leaks' API endpoint

        :type start: ``str``
        :param - start: Starting parameter for analysis

        :type end: ``str``
        :param - end: End parameter for analysis
        """
    start = args.get('start')
    end = args.get('end')

    if start:
        startDate = timeToEpoch(start)
    else:
        startDate = start

    if end:
        endDate = timeToEpoch(end)
    else:
        endDate = end

    param = {
        'start': startDate,
        'end': endDate
    }

    identityLeaks = client.get_identity_leaks(param=param)

    readable_output = tableToMarkdown('Identity Leaks', identityLeaks)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='USTA.Identity_Leaks',
        outputs_key_field='signature',
        outputs=identityLeaks
    )


def search_stolen_client_accounts(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Gets the Stolen Client Accounts related any service using the '/threat-stream/stolen-client-accounts' API endpoint

        :type username: ``str``
        :param - username: For filtering with username

        :type password: ``boolean``
        :param - password: For filtering with password

        :type source: ``str``
        :param - source: For filtering with source

        :type start: ``str``
        :param - start: Starting parameter for analysis

        :type end: ``str``
        :param - end: End parameter for analysis
        """
    username = args.get('username')
    password = args.get('password')
    source = args.get('source')
    start = args.get('start')
    end = args.get('end')

    if start:
        startDate = timeToEpoch(start)
    else:
        startDate = start

    if end:
        endDate = timeToEpoch(end)
    else:
        endDate = end

    param = {
        'username': username,
        'password': password,
        'source': source,
        'start': startDate,
        'end': endDate
    }

    stolenClientAccounts = client.get_stolen_client_accounts(param=param)

    readable_output = tableToMarkdown('Stolen Client Accounts', stolenClientAccounts)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='USTA.Stolen_Client_Accounts',
        outputs_key_field='username',
        outputs=stolenClientAccounts
    )


def search_domain(client: Client, args: Dict[str, Any]) -> CommandResults:

    domain = args.get('domain')

    param = {
        'domain': domain
    }

    maliciousDomain = client.get_domain(param=param)

    readable_output = tableToMarkdown('Malicious Domain', maliciousDomain)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='USTA.Malicious_Domain',
        outputs_key_field='domain',
        outputs=maliciousDomain
    )


def search_ip_address(client: Client, args: Dict[str, Any]) -> CommandResults:

    ip_address = args.get('ip_address')

    param = {
        'ip_address': ip_address
    }

    maliciousIPAddress = client.get_ip_address(param=param)

    readable_output = tableToMarkdown('Malicious IP Address', maliciousIPAddress)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='USTA.Malicious_IP_Address',
        outputs_key_field='ip_address',
        outputs=maliciousIPAddress
    )


def send_referrer_url() -> CommandResults:

    url = demisto.params().get('url')[:-1] if str(demisto.params().get('url')).endswith('/') \
        else demisto.params().get('url')
    CREDENTIALS = demisto.params().get('apikey')
    # AUTH_HEADERS = {'Content-Type': 'application/json'}

    params = "TOKEN " + CREDENTIALS
    headers = {"Authorization": params,
               "Content-Type": "application/json"
               }

    base_url = urljoin(url, '/api')
    endpoint = "/threat-stream/referrers"

    url = urljoin(base_url, endpoint)

    addresses = [demisto.args().get('address')]

    data = []
    for address in addresses:
        addressParam = {
            'address': address
        }
        data.append(addressParam)

    req = requests.post(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    referredResult = json.loads(req.content)

    readable_output = tableToMarkdown('Referred Result', referredResult)

    return CommandResults(
        readable_output=readable_output,
        outputs=referredResult
    )


def search_specific_identity_leaks() -> CommandResults:

    url = demisto.params().get('url')[:-1] if str(demisto.params().get('url')).endswith('/') \
        else demisto.params().get('url')
    CREDENTIALS = demisto.params().get('apikey')
    # AUTH_HEADERS = {'Content-Type': 'application/json'}

    params = "TOKEN " + CREDENTIALS
    headers = {"Authorization": params,
               "Content-Type": "application/json"
               }

    base_url = urljoin(url, '/api')
    endpoint = "/threat-stream/identity-leaks"

    url = urljoin(base_url, endpoint)

    identities = demisto.args().get('identity_number')
    identityList = identities.split(",")

    hashedIdentities = encodeData(identityList)

    mappingHashIdentity = []
    for i in range(len(identityList)):
        mappingDict = {
            'Identity': identityList[i],
            'Identity Hash': hashedIdentities[i]
        }
        mappingHashIdentity.append(mappingDict)

    data = {
        'signatures': hashedIdentities
    }

    req = requests.patch(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    identityLeaks = json.loads(req.content)

    readable_output = tableToMarkdown('Identity Leaks', identityLeaks)
    readable_output += tableToMarkdown('Identity Hash Mapping', mappingHashIdentity)

    return CommandResults(
        readable_output=readable_output,
        outputs=identityLeaks
    )


def close_incident() -> CommandResults:

    url = demisto.params().get('url')[:-1] if str(demisto.params().get('url')).endswith('/') \
        else demisto.params().get('url')
    CREDENTIALS = demisto.params().get('apikey')
    # AUTH_HEADERS = {'Content-Type': 'application/json'}

    params = "TOKEN " + CREDENTIALS
    headers = {"Authorization": params,
               "Content-Type": "application/json"
               }

    base_url = urljoin(url, '/api')
    endpoint = "/threat-stream/close-ticket"

    url = urljoin(base_url, endpoint)

    inc_id = demisto.args().get('id')
    data = {
        'id': inc_id
    }

    req = requests.patch(url, headers=headers, data=json.dumps(data), verify=VERIFY_SSL)
    closedIncident = json.loads(req.content)

    readable_output = tableToMarkdown('Close Incident', closedIncident)

    return CommandResults(
        readable_output=readable_output,
        outputs=closedIncident
    )


def encodeData(identities: list) -> list:
    hashedList = []
    for identity in identities:
        hashedIdentity = hashlib.sha256((hashlib.md5(identity.encode())).hexdigest().encode()).hexdigest()  # nosec
        hashedList.append(hashedIdentity)
    return hashedList


def timeToEpoch(time: str):
    timeParameterList = time.split("-")
    if len(timeParameterList) != 5:
        error_message = "Time arguments is wrong, be sure to enter as in the example."
        return_error(error_message)
    else:
        epochTime = datetime(int(timeParameterList[0]), int(timeParameterList[1]), int(timeParameterList[2]),
                             int(timeParameterList[3]), int(timeParameterList[4])).strftime('%s')
        return epochTime


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    CREDENTIALS = demisto.params().get('apikey')
    # AUTH_HEADERS = {'Content-Type': 'application/json'}

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    ''' EXECUTION '''
    # LOG('command is %s' % (demisto.command(), ))
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        params = "TOKEN " + CREDENTIALS
        headers = {'Authorization': params,
                   'Content-Type': 'application/json'
                   }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            demisto.results(test_module())
        elif demisto.command() == 'usta-get-malicious-urls':
            return_results(search_malicious_urls(client, demisto.args()))
        elif demisto.command() == 'usta-get-malware-hashs':
            return_results(search_malware_hashs(client, demisto.args()))
        elif demisto.command() == 'usta-get-phishing-sites':
            return_results(search_phishing_sites(client, demisto.args()))
        elif demisto.command() == 'usta-get-identity-leaks':
            return_results(search_identity_leaks(client, demisto.args()))
        elif demisto.command() == 'usta-get-stolen-client-accounts':
            return_results(search_stolen_client_accounts(client, demisto.args()))
        elif demisto.command() == 'usta-get-domain':
            return_results(search_domain(client, demisto.args()))
        elif demisto.command() == 'usta-get-ip-address':
            return_results(search_ip_address(client, demisto.args()))
        elif demisto.command() == 'usta-send-referrer-url':
            return_results(send_referrer_url())
        elif demisto.command() == 'usta-search-specific-identity-leaks':
            return_results(search_specific_identity_leaks())
        elif demisto.command() == 'usta-close-incident':
            return_results(close_incident())

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
