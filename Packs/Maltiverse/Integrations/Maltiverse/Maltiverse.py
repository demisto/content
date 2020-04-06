import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Tuple, Dict, Any
from _collections import defaultdict
import requests
import hashlib

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SERVER_URL = 'https://api.maltiverse.com'
DBOT_SCORE_KEY = 'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)'
DEFAULT_THRESHOLD = 5


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class NotFoundError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, url: str, use_ssl: bool, use_proxy: bool, auth_token=None):
        self.auth_token = auth_token
        super().__init__(url, verify=use_ssl, proxy=use_proxy, headers={'Accept': 'application/json'})
        if self.auth_token:
            self._headers.update({'Authorization': 'Bearer ' + self.auth_token})

    def http_request(self, method, url_suffix):
        ok_codes = (200, 403, 404, 500)  # includes responses that are ok (200) and error responses that should be
        # handled by the client and not in the BaseClient  todo: check if should add 400/401
        try:
            res = self._http_request(method, url_suffix, resp_type='response', ok_codes=ok_codes)
            if res.status_code == 200:
                try:
                    return res.json()
                except ValueError as exception:
                    raise DemistoException('Failed to parse json object from response: {}'
                                           .format(res.content), exception)

            if res.status_code == 403 or res.status_code == 500:
                try:
                    err_msg = str(res.json())
                    if self.auth_token:
                        err_msg += ' - Check server URL and API key'
                    else:
                        err_msg += " - Check server URL or try using an API key"
                except ValueError:
                    err_msg = 'Check server URL or API key'
                raise DemistoException(err_msg)

            if res.status_code == 404:
                raise NotFoundError('Page Not Found')

        except Exception as e:
            raise e

    def ip_report(self, ip: str) -> dict:
        if not is_ip_valid(ip):
            raise DemistoException('The given IP was invalid')
        return self.http_request('GET', f'/ip/{ip}')

    def url_report(self, url: str) -> dict:
        sha256_url = urlToSHA256(url)
        try:
            report = self.http_request('GET', f'/url/{sha256_url}')
            return report
        except NotFoundError:
            LOG(f'URL {url} was not found')
            return {'NotFound': True}
        except Exception as e:
            raise e

    def domain_report(self, domain: str) -> dict:
        return self.http_request('GET', f'/hostname/{domain}')

    def file_report(self, sha256: str) -> dict:
        try:
            report = self.http_request('GET', f'/sample/{sha256}')
            return report
        except NotFoundError:
            LOG(f'file {sha256} was not found')
            return {'NotFound': True}
        except Exception as e:
            raise e


def test_module(client=None):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: Maltiverse client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        client.http_request('GET', '/ip/8.8.8.8')
        return 'ok'
    except NotFoundError as e:
        return_error(e.message + ' - Check server URL')
    except Exception as e:
        raise e


def calculate_score(positive_detections: int, classification: str, threshold: int, anti_virus: int = 0) -> int:
    """
    Calculates Demisto score based on the classification of Maltiverse and number of positive detections in the blacklist.

    Args:
        positive_detections (int): the number of items in the blacklist
        classification (str): the classification given to the IoC by Maltiverse. Can be one of: neutral, whitelist,
        suspicious, malicious
        threshold (int): the score threshold configured by the user.
        anti_virus (int) - optional: used to calculate the score only in the case that the IoC is a file. Indicates the
        number of items in the list of antivirus detections.

    Returns:
        int - Demisto's score for the indicator
    """
    if positive_detections == 0 and classification == 'neutral':
        return 0
    elif classification == 'whitelist':
        return 1
    elif positive_detections <= threshold and classification != 'malicious':
        if anti_virus > 1:
            return 3
        return 2
    elif positive_detections > threshold or classification == 'malicious':
        return 3
    else:  # if reached this line there is a problem with the logic
        return -1


def urlToSHA256(url: str) -> str:
    """
    Converts a url into its SHA256 hash.

    Args:
        url (str): the url that should be converted into  SHA256

    Returns:
        str - the SHA256 hash of the url
    """
    return hashlib.sha256(url.encode('utf-8')).hexdigest()


# todo: remove this function after talking to Yuval
def create_blacklist_context(blacklist):
    """
    Creates the Blacklist part of the context.

    Args:
        blacklist (dict): the 'blacklist' field of the report, containing all information required for the blacklist
        part in the context.

    Returns:
        dict - the dictionary that should be added into the context
    """
    all_fields = [blacklist[i][field] for field in
                  ['description', 'first_seen', 'last_seen', 'source'] for i in range(len(blacklist))]
    description = all_fields[:len(blacklist)]
    first_seen = all_fields[len(blacklist): 2 * len(blacklist)]
    last_seen = all_fields[2 * len(blacklist): 3 * len(blacklist)]
    source = all_fields[3 * len(blacklist):]
    blacklist_context = {
        'Blacklist': {
            'Description': description,
            'FirstSeen': first_seen,
            'LastSeen': last_seen,
            'Source': source
        }
    }

    return blacklist_context


def ip_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes IP enrichment against Maltiverse.

    Args:
        client (Client): Maltiverse client.
        args (Dict[str, str]): the arguments for the command.
    Returns:
        str: human readable presentation of the IP report.
        dict: the results to return into Demisto's context.
        Any: the raw data from Maltiverse client (used for debugging).
    """

    threshold = int(args.get('threshold', DEFAULT_THRESHOLD))
    markdown = ''
    context: dict = defaultdict(list)
    reports = []

    for ip in argToList(args.get('ip')):
        report = client.ip_report(ip)
        positive_detections = len(report.get('blacklist', []))

        # blacklist_context = create_blacklist_context(report.get('blacklist', []))
        blacklist_context = {'Blacklist': report.get('blacklist', [])}

        outputs = {
            'Address': report.get('ip_addr', ''),
            'Geo': {'Country': report.get('country_code', '')},
            'PositiveDetections': positive_detections,
            'Malicious': {'Description': [blacklist_context['Blacklist'][i]['description'] for i in
                                          range(len(report.get('blacklist', [])))]}
        }

        additional_info = {string_to_context_key(field): report.get(field, '') for field in
                           ['classification', 'tag']}
        additional_info['Address'] = report.get('ip_addr', '')

        dbot_score = {'Indicator': report.get('ip_addr', ''), 'Type': 'ip', 'Vendor': 'Maltiverse',
                      'Score': calculate_score(positive_detections, report.get('classification', ''), threshold)}

        maltiverse_ip = {**blacklist_context, **additional_info}

        context[outputPaths['ip']].append(outputs)
        context[f'Maltiverse.{outputPaths["ip"]}'].append(maltiverse_ip)
        context[DBOT_SCORE_KEY].append(dbot_score)

        md_outputs = {
            'IP.Address': report.get('ip_addr', ''),
            'IP.Geo.Country': report.get('country_code', ''),
            'IP.PositiveDetections': positive_detections,
            'IP.Malicious.Description': [blacklist_context['Blacklist'][i]['description'] for i in
                                         range(len(report.get('blacklist', [])))]
        }
        markdown += tableToMarkdown(f'Maltiverse IP reputation for: {report["ip_addr"]}\n', md_outputs, removeNull=True)
        reports.append(report)

    return markdown, context, reports


def url_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
     Executes URL enrichment against Maltiverse.

     Args:
         client (Client): Maltiverse client.
         args (Dict[str, str]): the arguments for the command.
     Returns:
         str: human readable presentation of the URL report.
         dict: the results to return into Demisto's context.
         Any: the raw data from Maltiverse client (used for debugging).
     """

    threshold = int(args.get('threshold', DEFAULT_THRESHOLD))
    markdown = ''
    context: dict = defaultdict(list)
    reports = []

    for url in argToList(args.get('url', '')):
        report = client.url_report(url)
        if 'NotFound' in report:
            markdown += f'No results found for {url}'
            break
        positive_detections = len(report.get('blacklist', []))
        # blacklist_context = create_blacklist_context(report.get('blacklist', []))
        blacklist_context = {'Blacklist': report.get('blacklist', [])}

        outputs = {'Data': report.get('url', ''),
                   'PositiveDetections': positive_detections
                   }

        dbot_score = {'Indicator': report.get('hostname', ''), 'Type': 'url', 'Vendor': 'Maltiverse',
                      'Score': calculate_score(positive_detections, report.get('classification', ''), threshold)}

        maltiverse_url = {string_to_context_key(field): report.get(field, '') for field in
                          ['classification', 'tag', 'modification_time', 'creation_time', 'hostname', 'domain', 'tld']}
        maltiverse_url['Address'] = report.get('url', '')
        maltiverse_url = {**maltiverse_url, **blacklist_context}

        md_info = {
            'URL.Data': report.get('url', ''),
            'URL.PositiveDetections': positive_detections,
            'Maltiverse.URL.Domain': report.get('domain', ''),
            'Maltiverse.URL.ModificationTime': report.get('modification_time', ''),
            'Maltiverse.URL.CreationTime': report.get('creation_time', '')
        }
        if positive_detections > 0:
            malicious_info = {
                'Malicious': {
                    'Description': [blacklist_context['Blacklist'][i]['description'] for i in
                                    range(len(report.get('blacklist', [])))],
                    'Vendor': 'Maltiverse'
                }
            }
            outputs = {**outputs, **malicious_info}
            md_info['URL.Malicious.Description'] = [blacklist_context['Blacklist'][i]['description'] for i in
                                                    range(len(report.get('blacklist', [])))],
            md_info['URL.Malicious.Vendor'] = 'Maltiverse'

        context[outputPaths['url']].append(outputs)
        context[DBOT_SCORE_KEY].append(dbot_score)
        context[f'Maltiverse.{outputPaths["url"]}'].append(maltiverse_url)

        markdown += tableToMarkdown(f'Maltiverse URL Reputation for: {report["url"]}\n',
                                    md_info, removeNull=True)
        reports.append(report)

    return markdown, context, reports


def domain_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
     Executes domain enrichment against Maltiverse.

     Args:
         client (Client): Maltiverse client.
         args (Dict[str, str]): the arguments for the command.
     Returns:
         str: human readable presentation of the domain report.
         dict: the results to return into Demisto's context.
         Any: the raw data from Maltiverse client (used for debugging).
     """
    threshold = int(args.get('threshold', DEFAULT_THRESHOLD))
    markdown = ''
    context: dict = defaultdict(list)
    reports = []

    for domain in argToList(args.get('domain', '')):
        report = client.domain_report(domain)
        positive_detections = len(report.get('blacklist', []))

        outputs = {string_to_context_key(field): report.get(field, '') for field in
                   ['creation_time', 'modification_time', 'tld']
                   }
        outputs['Name'] = report.get('hostname', '')
        outputs['ASName'] = report.get('as_name', '')

        dbot_score = {'Indicator': report.get('hostname', ''), 'Type': 'Domain', 'Vendor': 'Maltiverse',
                      'Score': calculate_score(positive_detections, report.get('classification', ''), threshold)}

        blacklist_context = {'Blacklist': report.get('blacklist', [])}

        # todo: remove after asking Yuval
        resolvedIP_info = {
            'ResolvedIP':
                {
                    'IP': [report['resolved_ip'][i]['ip_addr'] for i in range(len(report['resolved_ip']))],
                    'Timestamp': [report['resolved_ip'][i]['timestamp'] for i in range(len(report['resolved_ip']))]
                }
        }

        maltiverse_domain = {string_to_context_key(field): report.get(field, '') for field in
                             ['creation_time', 'modification_time', 'tld', 'classification', 'tag']
                             }
        maltiverse_domain['Address'] = report.get('hostname', '')
        maltiverse_domain['ResolvedIP'] = report.get('resolved_ip', '')
        maltiverse_domain = {**maltiverse_domain, **blacklist_context}
        # maltiverse_domain = {**maltiverse_domain, **resolvedIP_info}

        context[outputPaths['domain']].append(outputs)
        context[DBOT_SCORE_KEY].append(dbot_score)
        context[f'Maltiverse.{outputPaths["domain"]}'].append(maltiverse_domain)

        md_info = {
            'Domain.Name': report.get('hostname', ''),
            'Domain.CreationDate': report.get('creation_time', ''),
            'Domain.ModificationDate': report.get('modification_time', ''),
            'Maltiverse.Domain.ModificationTime': report.get('modification_time', ''),
            'Maltiverse.Domain.CreationTime': report.get('creation_time', ''),
            'Maltiverse.Domain.ResolvedIP.IP': [report['resolved_ip'][i]['ip_addr'] for i in
                                                range(len(report['resolved_ip']))]
        }

        markdown += tableToMarkdown(f'Maltiverse Domain Reputation for: {report["hostname"]}\n',
                                    md_info, removeNull=True)
        reports.append(report)

    return markdown, context, reports


def file_command(client: Client, args: Dict[str, str]) -> Tuple[str, dict, Any]:
    """
    Executes file hash enrichment against Maltiverse.

    Args:
        client (Client): Maltiverse client.
        args (Dict[str, str]): the arguments for the command.

    Returns:
         str: human readable presentation of the file hash report.
         dict: the results to return into Demisto's context.
         Any: the raw data from Maltiverse client (used for debugging).
    """
    threshold = int(args.get('threshold', DEFAULT_THRESHOLD))
    markdown = ''
    context: dict = defaultdict(list)
    reports = []

    for file in argToList(args.get('file', '')):
        report = client.file_report(file)
        if 'NotFound' in report:
            markdown += f'No results found for {file}'
            break
        positive_detections = len(report.get('blacklist', []))

        outputs = {string_to_context_key(field): report.get(field, '') for field in
                   ['md5', 'sha1', 'sha256', 'size', 'type']
                   }
        outputs['Name'] = report['filename'][0]
        outputs['Extension'] = (report['filename'][0]).split('.')[-1]
        outputs['Path'] = report['process_list'][0]['normalizedpath']

        dbot_score = {'Indicator': report['filename'][0], 'Type': 'File', 'Vendor': 'Maltiverse',
                      'Score': calculate_score(positive_detections, report.get('classification', ''), threshold,
                                               len(report.get('antivirus', [])))}

        blacklist_context = {'Blacklist': report.get('blacklist', [])}

        process_list = {
            'ProcessList': {
                string_to_context_key(field): report['process_list'][0][field] for field in
                ['name', 'normalizedpath', 'sha256', 'uid']
            }
        }
        file_malicious = {
            'Malicious': {
                'Vendor': 'Maltiverse',
                'Description': [blacklist_context['Blacklist'][i]['description'] for i in
                                range(len(report.get('blacklist', [])))],
            }
        }

        maltiverse_file = {string_to_context_key(field): report.get(field, '') for field in
                           ['score', 'classification', 'modification_time', 'creation_time', 'size', 'contacted_host',
                            'dns_request']}
        maltiverse_file['PositiveDetections'] = positive_detections
        maltiverse_file['Name'] = report['filename'][0]
        maltiverse_file['Tag'] = report.get('tag', '')
        maltiverse_file = {**maltiverse_file, **process_list}
        maltiverse_file = {**maltiverse_file, **blacklist_context}
        if positive_detections > 0:
            maltiverse_file = {**maltiverse_file, **file_malicious}

        context[outputPaths['file']].append(outputs)
        context[DBOT_SCORE_KEY].append(dbot_score)
        context[f'Maltiverse.{outputPaths["file"]}'].append(maltiverse_file)

        md_info = {
            'File.Name': report['filename'][0],
            'File.MD5': report.get('md5', ''),
            'File.Type': report.get('type', ''),
            'Maltiverse.File.PositiveDetections': positive_detections,
            'Maltiverse.File.Classification': report.get('classification', '')
        }

        markdown += tableToMarkdown(f'Maltiverse File Reputation for: {report["filename"][0]}\n',
                                    md_info, removeNull=True)
        reports.append(report)

    return markdown, context, reports


def main():
    params = demisto.params()
    server_url = params.get('server_url') if params.get('server_url') else SERVER_URL

    client = Client(url=server_url,
                    use_ssl=not params.get('insecure', False),
                    use_proxy=params.get('proxy', False),
                    auth_token=params.get('api_key', None))

    commands = {
        'ip': ip_command,
        'url': url_command,
        'domain': domain_command,
        'file': file_command,
    }

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            demisto.results(test_module(client))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
