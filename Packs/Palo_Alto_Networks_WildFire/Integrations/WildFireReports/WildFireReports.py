import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


class NotFoundError(Exception):
    """ Report or File not found. """

    def __init__(self, *args):  # real signature unknown
        pass


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url, verify=True, proxy=False, ok_codes=(), headers=None, auth=None, token=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self.token = token

    def test(self):
        body = f'''--upload_boundry
Content-Disposition: form-data; name="apikey"

{self.token}
--upload_boundry
Content-Disposition: form-data; name="link"

https://www.demisto.com
--upload_boundry--'''

        self._http_request(
            'POST',
            url_suffix='/submit/link',
            headers={'Content-Type': "multipart/form-data; boundary=upload_boundry"},
            data=body,
            resp_type='response'
        )

    def get_file_report(self, file_hash: str, file_format: str = 'xml', resp_type: str = 'json') -> Dict[str, Any]:
        return self._http_request(
            'POST',
            url_suffix='/get/report',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            params={'apikey': self.token, 'format': file_format, 'hash': file_hash},
            resp_type=resp_type,
        )


''' HELPER FUNCTIONS '''


def hash_args_handler(sha256=None, md5=None):
    # Hash argument used in wildfire-report
    inputs = argToList(sha256) if sha256 else argToList(md5)
    for element in inputs:
        if sha256Regex.match(element) or md5Regex.match(element):
            continue
        raise Exception('Invalid hash. Only SHA256 and MD5 are supported.')

    return inputs


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
                if isinstance(report["elf_info"]["IP_Addresses"], dict) and 'entry' in \
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


def create_file_report(client, file_hash: str, reports, file_info):
    outputs, feed_related_indicators, behavior = parse_file_report(reports, file_info)

    dbot_score = 3 if file_info["malware"] == 'yes' else 1

    dbot_score_object = Common.DBotScore(indicator=file_hash, indicator_type=DBotScoreType.FILE,
                                         integration_name='WildFire', score=dbot_score)
    file = Common.File(dbot_score=dbot_score_object, name=file_info.get('filename'),
                       file_type=file_info.get('filetype'), md5=file_info.get('md5'), sha1=file_info.get('sha1'),
                       sha256=file_info.get('sha256'), size=file_info.get('size'),
                       feed_related_indicators=feed_related_indicators, tags=['malware'], behaviors=behavior)

    res_pdf = client.get_file_report(file_hash, 'pdf', 'response')

    file_name = 'wildfire_report_' + file_hash + '.pdf'
    file_type = entryTypes['entryInfoFile']
    result = fileResult(file_name, res_pdf.content, file_type)  # will be saved under 'InfoFile' in the context.
    demisto.results(result)
    human_readable = tableToMarkdown('WildFire File Report - PDF format', prettify_report_entry(file_info))

    return human_readable, outputs, file


''' COMMAND FUNCTIONS '''


def test_module(client):
    try:
        client.test()
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def wildfire_get_report_command(client, args, reliability):
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
        sha256 = element if sha256Regex.match(element) else None
        md5 = element if md5Regex.match(element) else None
        entry_context = {key: value for key, value in (['MD5', md5], ['SHA256', sha256]) if value}

        try:
            res = client.get_file_report(element)
            reports = res.get('wildfire', {}).get('task_info', {}).get('report')
            file_info = res.get('wildfire').get('file_info')

            if reports and file_info:
                human_readable, entry_context, indicator = create_file_report(client, element, reports, file_info)

            else:
                human_readable = 'The sample is still being analyzed. Please wait to download the report.'
                entry_context['Status'] = 'Pending'
                indicator = None

        except NotFoundError as exc:
            human_readable = 'Report not found.'
            entry_context['Status'] = 'NotFound'
            dbot_score_file = 0
            dbot_score_object = Common.DBotScore(
                indicator=element,
                indicator_type=DBotScoreType.FILE,
                integration_name='WildFire',
                score=dbot_score_file,
                reliability=reliability,
            )
            indicator = Common.File(dbot_score=dbot_score_object, md5=md5, sha256=sha256)
            res = ''
            demisto.error(f'Report not found. Error: {exc}')

        finally:
            try:
                wildfire_report_dt_file = "WildFire.Report(val.SHA256 && val.SHA256 == obj.SHA256 || " \
                                          "val.MD5 && val.MD5 == obj.MD5)"
                command_results = CommandResults(
                    outputs_prefix=wildfire_report_dt_file,
                    outputs=remove_empty_elements(entry_context),
                    readable_output=human_readable,
                    indicator=indicator,
                    raw_response=res,
                )
            except Exception:
                raise DemistoException('Error while trying to get the report from the API.')

        command_results_list.append(command_results)

    return command_results_list


''' MAIN FUNCTION '''


def main():
    command = demisto.command()
    params = demisto.params()
    base_url = params.get('server')
    if base_url and base_url[-1] == '/':
        base_url = base_url[:-1]
    if base_url and not base_url.endswith('/publicapi'):
        base_url += '/publicapi'
    token = params.get('token')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    reliability = params.get('integrationReliability', DBotScoreReliability.B) or DBotScoreReliability.B
    args = demisto.args()

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            token=token,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy,
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'wildfire-report':
            return_results(wildfire_get_report_command(client, args, reliability))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
