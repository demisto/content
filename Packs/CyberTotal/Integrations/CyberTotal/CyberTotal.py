import traceback
from typing import Any, Dict, List
from urllib.parse import urlparse
from datetime import timezone

import dateparser
import requests

import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
''' CLIENT CLASS '''


class Client(BaseClient):

    def parse_reputation(self, cybertotal_result: dict, resource: str) -> Dict[str, Any]:
        scan_time = datetime.fromtimestamp(cybertotal_result['scan_time'], timezone.utc).isoformat()
        permalink = cybertotal_result['url']
        url_path = urlparse(permalink).path
        (_, _, task_id) = url_path.rpartition('/')

        result = {
            "permalink": permalink,
            "resource": resource,
            "positive_detections": 0,
            "detection_engines": 0,
            "scan_date": scan_time,
            "task_id": task_id,
            "detection_ratio": "0/0"
        }

        if 'basic' not in cybertotal_result:
            result["message"] = "search success with no basic in cybertotal result"
            return result
        positive_detections = 0
        detection_engines = 0
        if 'reputation' in cybertotal_result['basic']:
            if 'avVenders' in cybertotal_result['basic']['reputation']:
                detection_engines = len(cybertotal_result['basic']['reputation']['avVenders'])
                for avVender in cybertotal_result['basic']['reputation']['avVenders']:
                    if avVender['detected']:
                        positive_detections = positive_detections + 1
        result['positive_detections'] = positive_detections
        result['detection_engines'] = detection_engines
        result['detection_ratio'] = str(positive_detections) + '/' + str(detection_engines)
        result['message'] = 'search success'
        if 'score' in cybertotal_result['basic']:
            result['severity'] = cybertotal_result['basic']['score'].get('severity', -1)
            result['confidence'] = cybertotal_result['basic']['score'].get('confidence', -1)
            result['threat'] = cybertotal_result['basic']['score'].get('threat', '')
        return result

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Gets the IP reputation using the '/_api/search/ip/basic' API endpoint

        :type ip: ``str``
        :param ip: IP address to get the reputation for

        :return: dict containing the IP reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        cybertotal_result = self._http_request(
            method='GET',
            url_suffix=f'/_api/search/ip/basic/{ip}'
        )
        if 'task_state' in cybertotal_result:
            return {'task_state': cybertotal_result['task_state'], 'message': 'this search is in progress, try again later...'}

        return self.parse_reputation(cybertotal_result, ip)

    def get_url_reputation(self, url: str) -> Dict[str, Any]:
        """Gets the URL reputation using the '/_api/search/url/basic' API endpoint

        :type url: ``str``
        :param url: URL to get the reputation for

        :return: dict containing the URL reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        cybertotal_result = self._http_request(
            method='GET',
            url_suffix=f'/_api/search/url/basic?q={url}'
        )
        if 'task_state' in cybertotal_result:
            return {'task_state': cybertotal_result['task_state'], 'message': 'this search is in progress, try again later...'}

        return self.parse_reputation(cybertotal_result, url)

    def get_file_reputation(self, _hash: str) -> Dict[str, Any]:
        """Gets the File reputation using the '/_api/search/hash/basic' API endpoint

        :type file: ``str``
        :param file: File to get the reputation for

        :return: dict containing the File reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        cybertotal_result = self._http_request(
            method='GET',
            url_suffix=f'/_api/search/hash/basic/{_hash}'
        )
        if 'task_state' in cybertotal_result:
            return {'task_state': cybertotal_result['task_state'], 'message': 'this search is in progress, try again later...'}

        result = self.parse_reputation(cybertotal_result, _hash)

        if 'BasicInfo' not in cybertotal_result['basic']:
            result["message"] = "search success with no BasicInfo in cybertotal result"
            return result

        basic = cybertotal_result['basic']['BasicInfo']
        result['size'] = basic.get('filesize', '')
        result['md5'] = basic.get('md5', '')
        result['sha1'] = basic.get('sha1', '')
        result['sha256'] = basic.get('sha256', '')
        result['extension'] = basic.get('file_type_extension', '')
        result['name'] = basic.get('display_name', '')
        if type(result['name']) is list:
            result['name'] = ', '.join(result['name'])
        return result

    def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Gets the Domain reputation using the '/_api/search/domain/basic' API endpoint

        :type domain: ``str``
        :param domain: Domain to get the reputation for

        :return: dict containing the Domain reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        cybertotal_result = self._http_request(
            method='GET',
            url_suffix=f'/_api/search/domain/basic/{domain}'
        )
        if 'task_state' in cybertotal_result:
            return {'task_state': cybertotal_result['task_state'], 'message': 'this search is in progress, try again later...'}

        return self.parse_reputation(cybertotal_result, domain)

    def parse_whois(self, cybertotal_result: dict, resource: str) -> Dict[str, Any]:
        scan_time = datetime.fromtimestamp(cybertotal_result['scan_time'], timezone.utc).isoformat()
        permalink = cybertotal_result['url']
        url_path = urlparse(permalink).path
        (_, _, task_id) = url_path.rpartition('/')

        result = dict()
        if 'whois' in cybertotal_result:
            if len(cybertotal_result['whois']) > 0:
                result = cybertotal_result['whois'].pop(0)
        result['permalink'] = permalink,
        result['resource'] = resource,
        result['scan_date'] = dateparser.parse(scan_time).strftime("%Y-%m-%d %H:%M:%S"),
        result['task_id'] = task_id
        result['message'] = "search success"
        if 'createdAt' in result:
            result['createdAt'] = datetime.fromtimestamp(result['createdAt'], timezone.utc).isoformat()
        if 'updatedAt' in result:
            result['updatedAt'] = datetime.fromtimestamp(result['updatedAt'], timezone.utc).isoformat()
        if 'registrarCreatedAt' in result:
            result['registrarCreatedAt'] = datetime.fromtimestamp(result['registrarCreatedAt'], timezone.utc).isoformat()
        if 'registrarUpdatedAt' in result:
            result['registrarUpdatedAt'] = datetime.fromtimestamp(result['registrarUpdatedAt'], timezone.utc).isoformat()
        if 'registrarExpiresAt' in result:
            result['registrarExpiresAt'] = datetime.fromtimestamp(result['registrarExpiresAt'], timezone.utc).isoformat()
        if 'auditCreatedAt' in result:
            result['auditCreatedAt'] = datetime.fromtimestamp(result['auditCreatedAt'], timezone.utc).isoformat()
        if 'auditUpdatedAt' in result:
            result['auditUpdatedAt'] = datetime.fromtimestamp(result['auditUpdatedAt'], timezone.utc).isoformat()
        if 'rawResponse' in result:
            result.pop('rawResponse')
        return result

    def get_ip_whois(self, ip: str) -> Dict[str, Any]:
        """Gets the IP-whois information using the '/_api/search/ip/whois' API endpoint

        :type ip: ``str``
        :param ip: IP address to get the whois information for

        :return: dict containing the IP whois information as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        cybertotal_result = self._http_request(
            method='GET',
            url_suffix=f'/_api/search/ip/whois/{ip}'
        )
        if 'task_state' in cybertotal_result:
            return {'task_state': cybertotal_result['task_state'], 'message': 'this search is in progress, try again later...'}

        return self.parse_whois(cybertotal_result, ip)

    def get_url_whois(self, url: str) -> Dict[str, Any]:
        """Gets the URL-whois information using the '/_api/search/url/whois' API endpoint

        :type url: ``str``
        :param url: URL to get the whois information for

        :return: dict containing the URL whois information as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        cybertotal_result = self._http_request(
            method='GET',
            url_suffix=f'/_api/search/url/whois?q={url}'
        )
        if 'task_state' in cybertotal_result:
            return {'task_state': cybertotal_result['task_state'], 'message': 'this search is in progress, try again later...'}

        return self.parse_whois(cybertotal_result, url)

    def get_domain_whois(self, domain: str) -> Dict[str, Any]:
        """Gets the Domain-whois information using the '/_api/search/domain/whois' API endpoint

        :type domain: ``str``
        :param domain: Domain to get the whois information for

        :return: dict containing the Domain whois information as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        cybertotal_result = self._http_request(
            method='GET',
            url_suffix=f'/_api/search/domain/whois/{domain}'
        )
        if 'task_state' in cybertotal_result:
            return {'task_state': cybertotal_result['task_state'], 'message': 'this search is in progress, try again later...'}

        return self.parse_whois(cybertotal_result, domain)


def ip_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> List[CommandResults]:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: CyberTotal client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['ip']`` is a list of IPs or a single IP
        ``args['threshold']`` threshold to determine whether an IP is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an IP is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains IPs

    :rtype: ``CommandResults``
    """

    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    command_results: List[CommandResults] = []
    ip_message_list: List[Dict[str, Any]] = []

    for ip in ips:
        ip_data = client.get_ip_reputation(ip)
        if 'task_state' in ip_data:
            task_state = ip_data.get('task_state', 'none')
            demisto.debug(f'search this ip {ip} on cybertotal with status: {task_state}')
            ip_message_list.append({'ip': ip})
            continue

        reputation = int(ip_data.get('positive_detections', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name='CyberTotal',
            score=score,
            malicious_description=f'CyberTotal returned reputation {reputation}'
        )

        ip_standard_context = Common.IP(
            ip=ip,
            detection_engines=ip_data.get('detection_engines', None),
            positive_engines=ip_data.get('positive_detections', None),
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown(f'IP: {ip}', ip_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix='CyberTotal.IP',
                outputs_key_field='task_id',
                outputs=ip_data,
                indicator=ip_standard_context
            )
        )

    if len(ip_message_list) > 0:
        readable_output = tableToMarkdown('IP search in progress , please try again later', ip_message_list)
        command_results.append(
            CommandResults(
                readable_output=readable_output,
            )
        )

    return command_results


def url_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> List[CommandResults]:
    """url command: Returns URL reputation for a list of URLs

    :type client: ``Client``
    :param Client: CyberTotal client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['url']`` is a list of URLs or a single URL
        ``args['threshold']`` threshold to determine whether an URL is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an URL is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains URLs

    :rtype: ``CommandResults``
    """

    urls = argToList(args.get('url'))
    if len(urls) == 0:
        raise ValueError('URL(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    url_message_list: List[Dict[str, Any]] = []
    command_results: List[CommandResults] = []

    for url in urls:
        url_raw_response = client.get_url_reputation(url)
        if 'task_state' in url_raw_response:
            task_state = url_raw_response.get('task_state', 'none')
            demisto.debug(f'search this url {url} on cybertotal with status: {task_state}')
            url_message_list.append({'url': url})
            continue

        reputation = int(url_raw_response.get('positive_detections', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name='CyberTotal',
            score=score,
            malicious_description=f'CyberTotal returned reputation {reputation}'
        )

        url_standard_context = Common.URL(
            url=url,
            detection_engines=url_raw_response.get('detection_engines'),
            positive_detections=url_raw_response.get('positive_detections'),
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown(f'URL {url}', url_raw_response)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix='CyberTotal.URL',
                outputs_key_field='task_id',
                outputs=url_raw_response,
                indicator=url_standard_context
            )
        )

    if len(url_message_list) > 0:
        readable_output = tableToMarkdown('URL search in progress , please try again later', url_message_list)
        command_results.append(
            CommandResults(
                readable_output=readable_output
            )
        )

    return command_results


def file_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> List[CommandResults]:
    """file command: Returns File reputation for a list of Files

    :type client: ``Client``
    :param Client: CyberTotal client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['file']`` is a list of Files or a single File
        ``args['threshold']`` threshold to determine whether an File is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an File is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Files

    :rtype: ``CommandResults``
    """

    hashs = argToList(args.get('file'))
    if len(hashs) == 0:
        raise ValueError('HASH(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    hash_message_list: List[Dict[str, Any]] = []
    command_results: List[CommandResults] = []

    for _hash in hashs:
        hash_reputation_response = client.get_file_reputation(_hash)
        if 'task_state' in hash_reputation_response:
            task_state = hash_reputation_response.get('task_state', 'none')
            demisto.debug(f'search this file {_hash} on cybertotal with status: {task_state}')
            hash_message_list.append({'file': _hash})
            continue

        reputation = int(hash_reputation_response.get('positive_detections', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        dbot_score = Common.DBotScore(
            indicator=_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name='CyberTotal',
            score=score,
            malicious_description=f'CyberTotal returned reputation {reputation}'
        )

        hash_standard_context = Common.File(
            md5=hash_reputation_response.get('md5', None),
            sha1=hash_reputation_response.get('sha1', None),
            sha256=hash_reputation_response.get('sha256', None),
            size=hash_reputation_response.get('size', None),
            extension=hash_reputation_response.get('extension', None),
            name=hash_reputation_response.get('name', None),
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown(f'File {_hash}', hash_reputation_response)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix='CyberTotal.File',
                outputs_key_field='task_id',
                outputs=hash_reputation_response,
                indicator=hash_standard_context
            )
        )

    if len(hash_message_list) > 0:
        readable_output = tableToMarkdown('File search in progress , please try again later', hash_message_list)
        command_results.append(
            CommandResults(
                readable_output=readable_output
            )
        )

    return command_results


def domain_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> List[CommandResults]:
    """domain command: Returns Domain reputation for a list of Domains

    :type client: ``Client``
    :param Client: CyberTotal client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['domain']`` is a list of Domains or a single Domain
        ``args['threshold']`` threshold to determine whether an Domain is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an Domain is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    # Context standard for Domain class
    domain_message_list: List[Dict[str, Any]] = []
    command_results: List[CommandResults] = []

    for domain in domains:
        domain_data = client.get_domain_reputation(domain)
        if 'task_state' in domain_data:
            task_state = domain_data.get('task_state', 'none')
            demisto.debug(f'search this domain {domain} on cybertotal with status: {task_state}')
            domain_message_list.append({'domain': domain})
            continue
        reputation = int(domain_data.get('positive_detections', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        dbot_score = Common.DBotScore(
            indicator=domain,
            integration_name='CyberTotal',
            indicator_type=DBotScoreType.DOMAIN,
            score=score,
            malicious_description=f'CyberTotal returned reputation {reputation}'
        )

        domain_standard_context = Common.Domain(
            domain=domain,
            positive_detections=domain_data.get('positive_detections', None),
            detection_engines=domain_data.get('detection_engines', None),
            dbot_score=dbot_score
        )

        readable_output = tableToMarkdown(f'Domain {domain}', domain_data)

        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix='CyberTotal.Domain',
                outputs_key_field='task_id',
                outputs=domain_data,
                indicator=domain_standard_context
            )
        )

    if len(domain_message_list) > 0:
        readable_output = tableToMarkdown('Domain search in progress , please try again later', domain_message_list)
        command_results.append(
            CommandResults(
                readable_output=readable_output
            )
        )

    return command_results


def ip_whois_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """cybertotal-ip-whois command: Returns IP whois information for a list of IPs

    :type client: ``Client``
    :param Client: CyberTotal client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['ip']`` is a list of IPs or a single IP

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains IPs

    :rtype: ``CommandResults``
    """

    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    ip_data_list: List[Dict[str, Any]] = []

    for ip in ips:
        ip_data = client.get_ip_whois(ip)
        ip_data_list.append(ip_data)

    return CommandResults(
        outputs_prefix='CyberTotal.WHOIS-IP',
        outputs_key_field='task_id',
        outputs=ip_data_list
    )


def url_whois_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """cybertotal-url-whois command: Returns URL whois information for a list of URLs

    :type client: ``Client``
    :param Client: CyberTotal client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['url']`` is a list of URLs or a single URL

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains URLs

    :rtype: ``CommandResults``
    """

    urls = argToList(args.get('url'))
    if len(urls) == 0:
        raise ValueError('URL(s) not specified')

    url_data_list: List[Dict[str, Any]] = []

    for url in urls:
        url_data = client.get_url_whois(url)
        url_data_list.append(url_data)

    return CommandResults(
        outputs_prefix='CyberTotal.WHOIS-URL',
        outputs_key_field='task_id',
        outputs=url_data_list
    )


def domain_whois_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """cybertotal-domain-whois command: Returns Domain whois information for a list of Domains

    :type client: ``Client``
    :param Client: CyberTotal client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['domain']`` is a list of Domains or a single Domain

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('Domain(s) not specified')

    domain_data_list: List[Dict[str, Any]] = []

    for domain in domains:
        domain_data = client.get_domain_whois(domain)
        domain_data_list.append(domain_data)

    return CommandResults(
        outputs_prefix='CyberTotal.WHOIS-Domain',
        outputs_key_field='task_id',
        outputs=domain_data_list
    )


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :type client: ``Client``
    :param Client: CyberTotal client to use
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        client.get_domain_reputation('abc.com')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def main() -> None:

    verify_certificate = not demisto.params().get('insecure', False)
    cybertotal_url = demisto.params().get('url')
    cybertotal_token = demisto.params().get('token')

    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Token {cybertotal_token}'
        }
        client = Client(
            base_url=cybertotal_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'ip':
            default_threshold = int(demisto.params().get('threshold_ip', '10'))
            return_results(ip_reputation_command(client, demisto.args(), default_threshold))

        elif demisto.command() == 'url':
            default_threshold = int(demisto.params().get('threshold_url', '10'))
            return_results(url_reputation_command(client, demisto.args(), default_threshold))

        elif demisto.command() == 'domain':
            default_threshold = int(demisto.params().get('threshold_domain', '10'))
            return_results(domain_reputation_command(client, demisto.args(), default_threshold))

        elif demisto.command() == 'file':
            default_threshold = int(demisto.params().get('threshold_hash', '10'))
            return_results(file_reputation_command(client, demisto.args(), default_threshold))

        elif demisto.command() == 'cybertotal-ip-whois':
            return_results(ip_whois_command(client, demisto.args()))

        elif demisto.command() == 'cybertotal-url-whois':
            return_results(url_whois_command(client, demisto.args()))

        elif demisto.command() == 'cybertotal-domain-whois':
            return_results(domain_whois_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
