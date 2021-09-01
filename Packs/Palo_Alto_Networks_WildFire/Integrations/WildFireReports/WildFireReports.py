import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
PARAMS = demisto.params()
URL = PARAMS.get('server')
TOKEN = PARAMS.get('token')
USE_SSL = not PARAMS.get('insecure', False)
FILE_TYPE_SUPPRESS_ERROR = PARAMS.get('suppress_file_type_error')
RELIABILITY = PARAMS.get('integrationReliability', DBotScoreReliability.B) or DBotScoreReliability.B
DEFAULT_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
MULTIPART_HEADERS = {'Content-Type': "multipart/form-data; boundary=upload_boundry"}
WILDFIRE_REPORT_DT_FILE = "WildFire.Report(val.SHA256 && val.SHA256 == obj.SHA256 || val.MD5 && val.MD5 == obj.MD5 ||" \
                          " val.URL && val.URL == obj.URL)"

if URL and not URL.endswith('/publicapi'):
    if URL[-1] != '/':
        URL += '/'
    URL += 'publicapi'

URL_DICT = {
    'upload_url': '/submit/link',
    'report': '/get/report',
}


ERROR_DICT = {
    '401': 'Unauthorized, API key invalid',
    '404': 'Not Found, The report was not found',
    '405': 'Method Not Allowed, Method other than POST used',
    '413': 'Request Entity Too Large, Sample file size over max limit',
    '415': 'Unsupported Media Type',
    '418': 'Unsupported File Type Sample, file type is not supported',
    '419': 'Request quota exceeded',
    '420': 'Insufficient arguments',
    '421': 'Invalid arguments',
    '500': 'Internal error',
    '502': 'Bad Gateway',
    '513': 'File upload failed'
}


class NotFoundError(Exception):
    """ Report or File not found. """

    def __init__(self, *args):  # real signature unknown
        pass


''' HELPER FUNCTIONS '''


def http_request(url: str, method: str, headers: dict = None, body=None, params=None, files=None,
                 resp_type: str = 'xml', return_raw: bool = False):
    LOG('running request with url=%s' % url)
    result = requests.request(
        method,
        url,
        headers=headers,
        data=body,
        verify=USE_SSL,
        params=params,
        files=files
    )
    if str(result.reason) == 'Not Found':
        raise NotFoundError('Not Found.')

    if result.status_code < 200 or result.status_code >= 300:
        if str(result.status_code) in ERROR_DICT:
            if result.status_code == 418 and FILE_TYPE_SUPPRESS_ERROR:
                demisto.results({
                    'Type': 11,
                    'Contents': f'Request Failed with status: {result.status_code}'
                                f' Reason is: {ERROR_DICT[str(result.status_code)]}',
                    'ContentsFormat': formats['text']
                })
                sys.exit(0)
            else:
                raise Exception(f'Request Failed with status: {result.status_code}'
                                f' Reason is: {ERROR_DICT[str(result.status_code)]}')
        else:
            raise Exception(f'Request Failed with status: {result.status_code} Reason is: {result.reason}')
    if result.text.find("Forbidden. (403)") != -1:
        raise Exception('Request Forbidden - 403, check SERVER URL and API Key')

    if (('Content-Type' in result.headers and result.headers['Content-Type'] == 'application/octet-stream') or (
            'Transfer-Encoding' in result.headers and result.headers['Transfer-Encoding'] == 'chunked')) and return_raw:
        return result

    if resp_type == 'json':
        return result.json()
    try:
        json_res = json.loads(xml2json(result.text))
        return json_res
    except Exception as exc:
        demisto.error(f'Failed to parse response to json. Error: {exc}')
        raise Exception(f'Failed to parse response to json. response: {result.text}')


def hash_args_handler(sha256=None, md5=None):
    # Hash argument used in wildfire-report
    inputs = argToList(sha256) if sha256 else argToList(md5)
    for element in inputs:
        if sha256Regex.match(element) or md5Regex.match(element):
            continue
        raise Exception('Invalid hash. Only SHA256 and MD5 are supported.')

    return inputs


def wildfire_upload_url(upload):
    upload_url_uri = URL + URL_DICT["upload_url"]
    body = '''--upload_boundry
Content-Disposition: form-data; name="apikey"

{apikey}
--upload_boundry
Content-Disposition: form-data; name="link"

{link}
--upload_boundry--'''.format(apikey=TOKEN, link=upload)

    result = http_request(
        upload_url_uri,
        'POST',
        headers=MULTIPART_HEADERS,
        body=body
    )

    return result


def create_feed_related_indicators_object(feed_related_indicators):
    """
    This function is used while enhancing the integration, enabling the use of Common.FeedRelatedIndicators object

    """
    feed_related_indicators_objects_list = []
    for item in feed_related_indicators:
        feed_related_indicators_objects_list.append(Common.FeedRelatedIndicators(value=item['value'],
                                                                                 indicator_type=item['type']))
    return feed_related_indicators_objects_list


def create_behaviors_object(behaviors):
    """
    This function is used while enhancing the integration, enabling the use of Common.Behaviors object

    """
    behaviors_objects_list = []
    for item in behaviors:
        behaviors_objects_list.append(Common.Behaviors(details=item['details'], action=item['action']))
    return behaviors_objects_list


def parse_file_report(reports, file_info):
    udp_ip = []
    udp_port = []
    tcp_ip = []
    tcp_port = []
    dns_query = []
    dns_response = []
    evidence_md5 = []
    evidence_text = []
    feed_related_indicators = []
    behavior = []

    # When only one report is in response, it's returned as a single json object and not a list.
    if not isinstance(reports, list):
        reports = [reports]

    for report in reports:
        if 'network' in report and report["network"]:
            if 'UDP' in report["network"]:
                for udp_obj in report["network"]["UDP"]:
                    if '-ip' in udp_obj:
                        udp_ip.append(udp_obj["-ip"])
                        feed_related_indicators.append({'value': udp_obj["-ip"], 'type': 'IP'})
                    if '-port' in udp_obj:
                        udp_port.append(udp_obj["-port"])
            if 'TCP' in report["network"]:
                for tcp_obj in report["network"]["TCP"]:
                    if '-ip' in tcp_obj:
                        tcp_ip.append(tcp_obj["-ip"])
                        feed_related_indicators.append({'value': tcp_obj["-ip"], 'type': 'IP'})
                    if '-port' in tcp_obj:
                        tcp_port.append(tcp_obj['-port'])
            if 'dns' in report["network"]:
                for dns_obj in report["network"]["dns"]:
                    if '-query' in dns_obj:
                        dns_query.append(dns_obj['-query'])
                    if '-response' in dns_obj:
                        dns_response.append(dns_obj['-response'])
            if 'url' in report["network"]:
                url = ''
                if '@host' in report["network"]["url"]:
                    url = report["network"]["url"]["@host"]
                if '@uri' in report["network"]["url"]:
                    url += report["network"]["url"]["@uri"]
                if url:
                    feed_related_indicators.append({'value': url, 'type': 'URL'})

        if 'evidence' in report and report["evidence"]:
            if 'file' in report["evidence"]:
                if isinstance(report["evidence"]["file"], dict) and 'entry' in report["evidence"]["file"]:
                    if '-md5' in report["evidence"]["file"]["entry"]:
                        evidence_md5.append(report["evidence"]["file"]["entry"]["-md5"])
                    if '-text' in report["evidence"]["file"]["entry"]:
                        evidence_text.append(report["evidence"]["file"]["entry"]["-text"])

        if 'elf_info' in report and report["elf_info"]:
            if 'Domains' in report["elf_info"]:
                if isinstance(report["elf_info"]["Domains"], dict) and 'entry' in report["elf_info"]["Domains"]:
                    for domain in report["elf_info"]["Domains"]["entry"]:
                        feed_related_indicators.append({'value': domain, 'type': 'Domain'})
            if 'IP_Addresses' in report["elf_info"]:
                if isinstance(report["elf_info"]["IP_Addresses"], dict) and 'entry' in\
                        report["elf_info"]["IP_Addresses"]:
                    for ip in report["elf_info"]["IP_Addresses"]["entry"]:
                        feed_related_indicators.append({'value': ip, 'type': 'IP'})
            if 'suspicious' in report["elf_info"]:
                if 'entry' in report["elf_info"]['suspicious']:
                    for entry_obj in report["elf_info"]['suspicious']['entry']:
                        if '#text' in entry_obj and '@description' in entry_obj:
                            behavior.append({'details': entry_obj['#text'], 'action': entry_obj['@description']})
            if 'URLs' in report["elf_info"]:
                if 'entry' in report["elf_info"]['URLs']:
                    for url in report["elf_info"]['URLs']['entry']:
                        feed_related_indicators.append({'value': url, 'type': 'URL'})

    outputs = {
        'Status': 'Success',
        'SHA256': file_info.get('sha256')
    }

    if len(udp_ip) > 0 or len(udp_port) > 0 or len(tcp_ip) > 0 or len(tcp_port) > 0 or dns_query or dns_response:

        outputs["Network"] = {}

        if len(udp_ip) > 0 or len(udp_port) > 0:
            outputs["Network"]["UDP"] = {}
            if len(udp_ip) > 0:
                outputs["Network"]["UDP"]["IP"] = udp_ip
            if len(udp_port) > 0:
                outputs["Network"]["UDP"]["Port"] = udp_port

        if len(tcp_ip) > 0 or len(tcp_port) > 0:
            outputs["Network"]["TCP"] = {}
            if len(tcp_ip) > 0:
                outputs["Network"]["TCP."]["IP"] = tcp_ip
            if len(tcp_port) > 0:
                outputs["Network"]["TCP"]["Port"] = tcp_port

        if len(dns_query) > 0 or len(dns_response) > 0:
            outputs["Network"]["DNS"] = {}
            if len(dns_query) > 0:
                outputs["Network"]["DNS"]["Query"] = dns_query
            if len(dns_response) > 0:
                outputs["Network"]["DNS"]["Response"] = dns_response

    if len(evidence_md5) > 0 or len(evidence_text) > 0:
        outputs["Evidence"] = {}
        if len(evidence_md5) > 0:
            outputs["Evidence"]["md5"] = evidence_md5
        if len(evidence_text) > 0:
            outputs["Evidence"]["Text"] = evidence_text

    feed_related_indicators = create_feed_related_indicators_object(feed_related_indicators)
    behavior = create_behaviors_object(behavior)
    return outputs, feed_related_indicators, behavior


def prettify_report_entry(file_info):
    pretty_report = {
        'MD5': file_info["md5"],
        'SHA256': file_info["sha256"],
        'Status': 'Completed'
    }
    if 'filetype' in file_info:
        pretty_report["FileType"] = file_info["filetype"]
    if 'size' in file_info:
        pretty_report["Size"] = file_info["size"]
    if 'url' in file_info:
        pretty_report["URL"] = file_info["url"]

    return pretty_report


def create_file_report(file_hash: str, reports, file_info, format_: str = 'xml', verbose: bool = False):
    outputs, feed_related_indicators, behavior = parse_file_report(reports, file_info)

    dbot_score = 3 if file_info["malware"] == 'yes' else 1

    dbot_score_object = Common.DBotScore(indicator=file_hash, indicator_type=DBotScoreType.FILE,
                                         integration_name='WildFire', score=dbot_score)
    file = Common.File(dbot_score=dbot_score_object, name=file_info.get('filename'),
                       file_type=file_info.get('filetype'), md5=file_info.get('md5'), sha1=file_info.get('sha1'),
                       sha256=file_info.get('sha256'), size=file_info.get('size'),
                       feed_related_indicators=feed_related_indicators, tags=['malware'], behaviors=behavior)

    if format_ == 'pdf':
        get_report_uri = URL + URL_DICT["report"]
        params = {
            'apikey': TOKEN,
            'format': 'pdf',
            'hash': file_hash
        }

        res_pdf = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params, return_raw=True)

        file_name = 'wildfire_report_' + file_hash + '.pdf'
        file_type = entryTypes['entryInfoFile']
        result = fileResult(file_name, res_pdf.content, file_type)  # will be saved under 'InfoFile' in the context.
        demisto.results(result)
        human_readable = tableToMarkdown('WildFire File Report - PDF format', prettify_report_entry(file_info))

    else:
        human_readable = tableToMarkdown('WildFire File Report', prettify_report_entry(file_info))
        if verbose:
            for report in reports:
                if isinstance(report, dict):
                    human_readable += tableToMarkdown('Report ', report, list(report), removeNull=True)

    return human_readable, outputs, file


def wildfire_get_file_report(file_hash: str, args: dict):
    get_report_uri = URL + URL_DICT["report"]
    params = {'apikey': TOKEN, 'format': 'xml', 'hash': file_hash}

    # necessarily one of them as passed the hash_args_handler
    sha256 = file_hash if sha256Regex.match(file_hash) else None
    md5 = file_hash if md5Regex.match(file_hash) else None
    entry_context = {key: value for key, value in (['MD5', md5], ['SHA256', sha256]) if value}

    try:
        json_res = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params)
        reports = json_res.get('wildfire', {}).get('task_info', {}).get('report')
        file_info = json_res.get('wildfire').get('file_info')

        verbose = args.get('verbose', 'false').lower() == 'true'
        format_ = args.get('format', 'xml')

        if reports and file_info:
            human_readable, entry_context, indicator = create_file_report(file_hash, reports, file_info, format_,
                                                                          verbose)

        else:
            entry_context['Status'] = 'Pending'
            human_readable = 'The sample is still being analyzed. Please wait to download the report.'
            indicator = None

    except NotFoundError as exc:
        entry_context['Status'] = 'NotFound'
        human_readable = 'Report not found.'
        dbot_score_file = 0
        json_res = ''
        dbot_score_object = Common.DBotScore(
            indicator=file_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name='WildFire',
            score=dbot_score_file,
            reliability=RELIABILITY,
        )
        indicator = Common.File(dbot_score=dbot_score_object, md5=md5, sha256=sha256)
        demisto.error(f'Report not found. Error: {exc}')

    finally:
        try:
            command_results = CommandResults(outputs_prefix=WILDFIRE_REPORT_DT_FILE,
                                             outputs=remove_empty_elements(entry_context),
                                             readable_output=human_readable, indicator=indicator, raw_response=json_res)
            return command_results, entry_context['Status']
        except Exception:
            raise DemistoException('Error while trying to get the report from the API.')


''' COMMAND FUNCTIONS '''


def test_module():
    if wildfire_upload_url('https://www.demisto.com'):
        demisto.results('ok')


def wildfire_get_report_command(args):
    """
    Args:
        args: the command arguments from demisto.args(), including url or file hash (sha256 or md5) to query on

    Returns:
        A single or list of CommandResults, and the status of the reports of the url or file of interest.

    """
    command_results_list = []
    if 'sha256' in args:
        sha256 = args.get('sha256')
    elif 'hash' in args:
        sha256 = args.get('hash')
    else:
        sha256 = None
    md5 = args.get('md5')
    inputs = hash_args_handler(sha256, md5)

    for element in inputs:
        command_results = wildfire_get_file_report(element, args)
        command_results_list.append(command_results)

    return command_results_list


''' MAIN FUNCTION '''


def main():
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        handle_proxy()

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module()

        elif command == 'wildfire-report':
            return_results(wildfire_get_report_command(demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
