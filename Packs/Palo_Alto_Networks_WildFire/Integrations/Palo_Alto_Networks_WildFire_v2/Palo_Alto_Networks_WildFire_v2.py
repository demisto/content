import shutil
from typing import Callable, Tuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''
PARAMS = demisto.params()
URL = PARAMS.get('server')
TOKEN = PARAMS.get('token') or (PARAMS.get('credentials') or {}).get('password')
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
    'verdict': '/get/verdict',
    'verdicts': '/get/verdicts',
    'upload_file': '/submit/file',
    'upload_url': '/submit/link',
    'upload_file_url': '/submit/url',
    'report': '/get/report',
    'sample': '/get/sample',
    'webartifacts': '/get/webartifacts',
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

VERDICTS_DICT = {
    '0': 'benign',
    '1': 'malware',
    '2': 'grayware',
    '4': 'phishing',
    '-100': 'pending, the sample exists, but there is currently no verdict',
    '-101': 'error',
    '-102': 'unknown, cannot find sample record in the database',
    '-103': 'invalid hash value',
    '-104': 'flawed submission, please re-submit the file',
}

VERDICTS_TO_DBOTSCORE = {
    '0': 1,
    '1': 3,
    '2': 2,
    '4': 3,
    '-100': 0,
    '-101': 0,
    '-102': 0,
    '-103': 0,
    '-104': 0,
}

''' HELPER FUNCTIONS '''


class NotFoundError(Exception):
    """ Report or File not found. """

    def __init__(self, *args):  # real signature unknown
        pass


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


def prettify_upload(upload_body):
    pretty_upload = {
        'MD5': upload_body["md5"],
        'SHA256': upload_body["sha256"],
        'Status': 'Pending'
    }
    if 'filetype' in upload_body:
        pretty_upload["FileType"] = upload_body["filetype"]
    if 'size' in upload_body:
        pretty_upload["Size"] = upload_body["size"]
    if 'url' in upload_body:
        pretty_upload["URL"] = upload_body["url"]

    return pretty_upload


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


def prettify_verdict(verdict_data):
    pretty_verdict = {}

    if 'md5' in verdict_data:
        pretty_verdict["MD5"] = verdict_data["md5"]
    if 'sha256' in verdict_data:
        pretty_verdict["SHA256"] = verdict_data["sha256"]

    pretty_verdict["Verdict"] = verdict_data["verdict"]
    pretty_verdict["VerdictDescription"] = VERDICTS_DICT[verdict_data["verdict"]]

    return pretty_verdict


def prettify_url_verdict(verdict_data: Dict) -> Dict:
    pretty_verdict = {
        'URL': verdict_data.get('url'),
        'Verdict': verdict_data.get('verdict'),
        'VerdictDescription': VERDICTS_DICT[verdict_data.get('verdict', '')],
        'Valid': verdict_data.get('valid'),
        'AnalysisTime': verdict_data.get('analysis_time')
    }

    return pretty_verdict


def create_dbot_score_from_verdict(pretty_verdict):
    if 'SHA256' not in pretty_verdict and 'MD5' not in pretty_verdict:
        raise Exception('Hash is missing in WildFire verdict.')

    if pretty_verdict["Verdict"] not in VERDICTS_TO_DBOTSCORE:
        raise Exception('This hash verdict is not mapped to a DBotScore. Contact Demisto support for more information.')

    dbot_score = [
        {'Indicator': pretty_verdict["SHA256"] if 'SHA256' in pretty_verdict else pretty_verdict["MD5"],
         'Type': 'hash',
         'Vendor': 'WildFire',
         'Score': VERDICTS_TO_DBOTSCORE[pretty_verdict["Verdict"]],
         'Reliability': RELIABILITY
         },
        {'Indicator': pretty_verdict["SHA256"] if 'SHA256' in pretty_verdict else pretty_verdict["MD5"],
         'Type': 'file',
         'Vendor': 'WildFire',
         'Score': VERDICTS_TO_DBOTSCORE[pretty_verdict["Verdict"]],
         'Reliability': RELIABILITY
         }
    ]
    return dbot_score


def create_dbot_score_from_url_verdict(pretty_verdict: Dict) -> List:
    if pretty_verdict.get('Verdict') not in VERDICTS_TO_DBOTSCORE:
        dbot_score = [
            {'Indicator': pretty_verdict.get('URL'),
             'Type': 'url',
             'Vendor': 'WildFire',
             'Score': 0,
             'Reliability': RELIABILITY
             }
        ]
    else:
        dbot_score = [
            {'Indicator': pretty_verdict.get('URL'),
             'Type': 'url',
             'Vendor': 'WildFire',
             'Score': VERDICTS_TO_DBOTSCORE[pretty_verdict['Verdict']],
             'Reliability': RELIABILITY
             }
        ]
    return dbot_score


def prettify_verdicts(verdicts_data):
    pretty_verdicts_arr = []

    for verdict_data in verdicts_data:
        pretty_verdict = {}
        if 'md5' in verdict_data:
            pretty_verdict["MD5"] = verdict_data["md5"]
        if 'sha256' in verdict_data:
            pretty_verdict["SHA256"] = verdict_data["sha256"]

        pretty_verdict["Verdict"] = verdict_data["verdict"]
        pretty_verdict["VerdictDescription"] = VERDICTS_DICT[verdict_data["verdict"]]

        pretty_verdicts_arr.append(pretty_verdict)

    return pretty_verdicts_arr


def create_dbot_score_from_verdicts(pretty_verdicts):
    dbot_score_arr = []

    for pretty_verdict in pretty_verdicts:

        if 'SHA256' not in pretty_verdict and 'MD5' not in pretty_verdict:
            raise Exception('Hash is missing in WildFire verdict.')
        if pretty_verdict["Verdict"] not in VERDICTS_TO_DBOTSCORE:
            raise Exception(
                'This hash verdict is not mapped to a DBotScore. Contact Demisto support for more information.')

        dbot_score_type_hash = {
            'Indicator': pretty_verdict["SHA256"] if "SHA256" in pretty_verdict else pretty_verdict["MD5"],
            'Type': 'hash',
            'Vendor': 'WildFire',
            'Score': VERDICTS_TO_DBOTSCORE[pretty_verdict["Verdict"]],
            'Reliability': RELIABILITY
        }
        dbot_score_type_file = {
            'Indicator': pretty_verdict["SHA256"] if "SHA256" in pretty_verdict else pretty_verdict["MD5"],
            'Type': 'file',
            'Vendor': 'WildFire',
            'Score': VERDICTS_TO_DBOTSCORE[pretty_verdict["Verdict"]],
            'Reliability': RELIABILITY
        }
        dbot_score_arr.append(dbot_score_type_hash)
        dbot_score_arr.append(dbot_score_type_file)

    return dbot_score_arr


def hash_args_handler(sha256=None, md5=None):
    # hash argument used in wildfire-report, wildfire-verdict commands
    inputs = argToList(sha256) if sha256 else argToList(md5)
    for element in inputs:
        if sha256Regex.match(element) or md5Regex.match(element):
            continue
        raise Exception('Invalid hash. Only SHA256 and MD5 are supported.')

    return inputs


def file_args_handler(file=None, sha256=None, md5=None):
    # file/md5/sha256 are used in file command
    if (file and not md5 and not sha256) or (not file and md5 and not sha256) or (not file and md5 and not sha256):
        if file:
            inputs = argToList(file)
        elif md5:
            inputs = argToList(md5)
        else:
            inputs = argToList(sha256)

        for element in inputs:
            if sha256Regex.match(element) or md5Regex.match(element) or sha1Regex.match(element):
                continue
            raise Exception('Invalid hash. Only SHA256 and MD5 are supported.')

        return inputs
    raise Exception('Specify exactly 1 of the following arguments: file, sha256, md5.')


def hash_list_to_file(hash_list):
    file_path = demisto.uniqueFile()
    with open(file_path, 'w') as file:
        file.write("\n".join(hash_list))

    return [file_path]


''' COMMANDS '''


def test_module():
    if wildfire_upload_url('https://www.demisto.com')[1]:
        demisto.results('ok')


@logger
def wildfire_upload_file(upload):
    upload_file_uri = URL + URL_DICT["upload_file"]
    body = {'apikey': TOKEN}

    file_path = demisto.getFilePath(upload)['path']
    file_name = demisto.getFilePath(upload)['name']

    try:
        shutil.copy(file_path, file_name)
    except Exception as exc:
        demisto.error(f'Failed to prepare file for upload. Error: {exc}')
        raise Exception('Failed to prepare file for upload.')

    try:
        with open(file_name, 'rb') as file:
            result = http_request(
                upload_file_uri,
                'POST',
                body=body,
                files={'file': file}
            )
    finally:
        shutil.rmtree(file_name, ignore_errors=True)

    upload_file_data = result["wildfire"]["upload-file-info"]

    return result, upload_file_data


def wildfire_upload_file_with_polling_command(args):
    return run_polling_command(args, 'wildfire-upload', wildfire_upload_file_command,
                               wildfire_get_report_command, 'FILE')


def wildfire_upload_file_command(args) -> list:
    assert_upload_argument(args)
    uploads = argToList(args.get('upload'))
    command_results_list = []
    for upload in uploads:
        result, upload_body = wildfire_upload_file(upload)
        pretty_upload_body = prettify_upload(upload_body)
        human_readable = tableToMarkdown('WildFire Upload File', pretty_upload_body, removeNull=True)
        command_results = (CommandResults(outputs_prefix=WILDFIRE_REPORT_DT_FILE,
                                          outputs=pretty_upload_body, readable_output=human_readable,
                                          raw_response=result))
        command_results_list.append(command_results)
    return command_results_list


@logger
def wildfire_upload_file_url(upload):
    upload_file_url_uri = URL + URL_DICT["upload_file_url"]
    body = f'''--upload_boundry
Content-Disposition: form-data; name="apikey"

{TOKEN}
--upload_boundry
Content-Disposition: form-data; name="url"

{upload}
--upload_boundry--'''

    result = http_request(
        upload_file_url_uri,
        'POST',
        headers=MULTIPART_HEADERS,
        body=body
    )

    upload_file_url_data = result["wildfire"]["upload-file-info"]

    return result, upload_file_url_data


def wildfire_upload_file_url_with_polling_command(args) -> list:
    return run_polling_command(args, 'wildfire-upload-file-url', wildfire_upload_file_url_command,
                               wildfire_get_report_command, 'URL')


def wildfire_upload_file_url_command(args) -> list:
    assert_upload_argument(args)
    command_results_list = []
    uploads = argToList(args.get('upload'))
    for upload in uploads:
        result, upload_body = wildfire_upload_file_url(upload)
        pretty_upload_body = prettify_upload(upload_body)
        human_readable = tableToMarkdown('WildFire Upload File URL', pretty_upload_body, removeNull=True)
        command_results = CommandResults(outputs_prefix=WILDFIRE_REPORT_DT_FILE, outputs=pretty_upload_body,
                                         readable_output=human_readable, raw_response=result)
        command_results_list.append(command_results)
    return command_results_list


@logger
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

    upload_url_data = result["wildfire"]["submit-link-info"]

    return result, upload_url_data


def wildfire_upload_url_command(args) -> list:
    assert_upload_argument(args)
    command_results_list = []
    uploads = argToList(args.get('upload'))
    for upload in uploads:
        result, upload_url_data = wildfire_upload_url(upload)
        pretty_upload_body = prettify_upload(upload_url_data)
        human_readable = tableToMarkdown('WildFire Upload URL', pretty_upload_body, removeNull=True)
        command_results = CommandResults(outputs_prefix=WILDFIRE_REPORT_DT_FILE,
                                         outputs=pretty_upload_body, readable_output=human_readable,
                                         raw_response=result)
        command_results_list.append(command_results)
    return command_results_list


def wildfire_upload_url_with_polling_command(args):
    return run_polling_command(args, 'wildfire-upload-url', wildfire_upload_url_command,
                               wildfire_get_report_command, 'URL')


def get_results_function_args(outputs, uploaded_item, args):
    """
    This function is used for the polling flow. After calling a upload command on a url\file, in order to check the
    status of the call, we need to retrieve the suitable identifier to call the results command on. for uploading a url,
     the identifier is the url itself, but for a file we need to extract the file hash from the results of the initial
     upload call. Therefore, this function extract that identifier from the data inserted to the context data by the
      upload command. The function also adds the 'verbose' and 'format' arguments that were given priorly to the upload
      command.
    Args:
        outputs: the context data from the search command
        uploaded_item: 'FILE' or 'URL'
        args: the args initially inserted to the upload function that initiated the polling sequence

    Returns:

    """
    results_function_args = {}
    if uploaded_item == 'FILE':
        identifier = {'md5': outputs.get('MD5')}
    else:
        identifier = {'url': outputs.get('URL')}
    results_function_args.update(identifier)

    results_function_args.update({key: value for key, value in args.items() if key in ['verbose', 'format']})
    return results_function_args


def run_polling_command(args: dict, cmd: str, upload_function: Callable, results_function: Callable, uploaded_item):
    """
    This function is generically handling the polling flow. In the polling flow, there is always an initial call that
    starts the uploading to the API (referred here as the 'upload' function) and another call that retrieves the status
    of that upload (referred here as the 'results' function).
    The run_polling_command function runs the 'upload' function and returns a ScheduledCommand object that schedules
    the next 'results' function, until the polling is complete.
    Args:
        args: the arguments required to the command being called, under cmd
        cmd: the command to schedule by after the current command
        upload_function: the function that initiates the uploading to the API
        results_function: the function that retrieves the status of the previously initiated upload process
        uploaded_item: the type of item being uploaded

    Returns:

    """
    ScheduledCommand.raise_error_if_not_supported()
    command_results_list = []
    interval_in_secs = int(args.get('interval_in_seconds', 60))
    # distinguish between the initial run, which is the upload run, and the results run
    is_new_search = 'url' not in args and 'md5' not in args and 'sha256' not in args and 'hash' not in args
    if is_new_search:
        assert_upload_argument(args)
        for upload in argToList(args['upload']):
            # narrow the args to the current single url or file
            args['upload'] = upload
            # create new search
            command_results = upload_function(args)[0]
            outputs = command_results.outputs
            results_function_args = get_results_function_args(outputs, uploaded_item, args)
            # schedule next poll
            polling_args = {
                'interval_in_seconds': interval_in_secs,
                'polling': True,
                **results_function_args,
            }
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=interval_in_secs,
                args=polling_args,
                timeout_in_seconds=600)
            command_results.scheduled_command = scheduled_command
            command_results_list.append(command_results)
        return command_results_list
    # not a new search, get search status
    command_results_list, status = results_function(args)
    if status != 'Success':
        # schedule next poll
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=600)

        command_results_list = [CommandResults(scheduled_command=scheduled_command)]
    return command_results_list


@logger
def wildfire_get_verdict(file_hash: Optional[str] = None, url: Optional[str] = None) -> Tuple[dict, dict]:
    get_verdict_uri = URL + URL_DICT["verdict"]
    if file_hash:
        body = 'apikey=' + TOKEN + '&hash=' + file_hash  # type: ignore[operator]
    else:
        body = 'apikey=' + TOKEN + '&url=' + url  # type: ignore[operator]

    result = http_request(get_verdict_uri, 'POST', headers=DEFAULT_HEADERS, body=body)
    verdict_data = result["wildfire"]["get-verdict-info"]

    return result, verdict_data


def wildfire_get_verdict_command():
    file_hashes = hash_args_handler(demisto.args().get('hash', ''))
    urls = argToList(demisto.args().get('url', ''))
    if not urls and not file_hashes:
        raise Exception('Either hash or url must be provided.')
    if file_hashes:
        for file_hash in file_hashes:
            result, verdict_data = wildfire_get_verdict(file_hash=file_hash)

            pretty_verdict = prettify_verdict(verdict_data)
            human_readable = tableToMarkdown('WildFire Verdict', pretty_verdict, removeNull=True)

            dbot_score_list = create_dbot_score_from_verdict(pretty_verdict)
            entry_context = {
                "WildFire.Verdicts(val.SHA256 && val.SHA256 == obj.SHA256 || val.MD5 && val.MD5 == obj.MD5)":
                    pretty_verdict,
                "DBotScore": dbot_score_list
            }
            demisto.results({
                'Type': entryTypes['note'],
                'Contents': result,
                'ContentsFormat': formats['json'],
                'HumanReadable': human_readable,
                'ReadableContentsFormat': formats['markdown'],
                'EntryContext': entry_context
            })
    else:
        for url in urls:
            result, verdict_data = wildfire_get_verdict(url=url)
            pretty_verdict = prettify_url_verdict(verdict_data)
            human_readable = tableToMarkdown('WildFire URL Verdict', pretty_verdict, removeNull=True)

            dbot_score_list = create_dbot_score_from_url_verdict(pretty_verdict)
            entry_context = {
                "WildFire.Verdicts(val.url && val.url == obj.url)":
                    pretty_verdict,
                "DBotScore": dbot_score_list
            }

            demisto.results({
                'Type': entryTypes['note'],
                'Contents': result,
                'ContentsFormat': formats['json'],
                'HumanReadable': human_readable,
                'ReadableContentsFormat': formats['markdown'],
                'EntryContext': entry_context
            })


@logger
def wildfire_get_verdicts(file_path):
    get_verdicts_uri = URL + URL_DICT["verdicts"]
    body = {'apikey': TOKEN}

    try:
        with open(file_path, 'rb') as file:
            result = http_request(
                get_verdicts_uri,
                'POST',
                body=body,
                files={'file': file}
            )
    finally:
        shutil.rmtree(file_path, ignore_errors=True)

    verdicts_data = result["wildfire"]["get-verdict-info"]

    return result, verdicts_data


@logger
def wildfire_get_verdicts_command():
    if ('EntryID' in demisto.args() and 'hash_list' in demisto.args()) or (
            'EntryID' not in demisto.args() and 'hash_list' not in demisto.args()):
        raise Exception('Specify exactly 1 of the following arguments: EntryID, hash_list.')

    if 'EntryID' in demisto.args():
        inputs = argToList(demisto.args().get('EntryID'))
        paths = [demisto.getFilePath(element)['path'] for element in inputs]

    else:
        paths = hash_list_to_file(argToList(demisto.args().get('hash_list')))

    for file_path in paths:
        result, verdicts_data = wildfire_get_verdicts(file_path)

        pretty_verdicts = prettify_verdicts(verdicts_data)
        human_readable = tableToMarkdown('WildFire Verdicts', pretty_verdicts, removeNull=True)

        dbot_score_list = create_dbot_score_from_verdicts(pretty_verdicts)

        entry_context = {
            "WildFire.Verdicts(val.SHA256 && val.SHA256 == obj.SHA256 || val.MD5 && val.MD5 == obj.MD5)":
                pretty_verdicts,
            "DBotScore": dbot_score_list
        }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': result,
            'ContentsFormat': formats['json'],
            'HumanReadable': human_readable,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': entry_context
        })


@logger
def wildfire_get_webartifacts(url: str, types: str) -> dict:
    get_webartifacts_uri = f'{URL}{URL_DICT["webartifacts"]}'
    params = {
        'apikey': TOKEN,
        'url': url,
    }
    if types:
        params['types'] = types

    result = http_request(
        get_webartifacts_uri,
        'POST',
        headers=DEFAULT_HEADERS,
        params=params,
        return_raw=True
    )
    return result


@logger
def wildfire_get_url_webartifacts_command():
    urls = argToList(demisto.args().get('url'))
    types = demisto.args().get('types', '')

    for url in urls:
        try:
            result = wildfire_get_webartifacts(url, types)
            file_entry = fileResult(f'{url}_webartifacts.tgz', result.content, entryTypes['entryInfoFile'])
            demisto.results(file_entry)
        except NotFoundError as exc:
            demisto.error(f'Webartifacts were not found. Error: {exc}')
            return_results('Webartifacts were not found. For more info contact your WildFire representative.')


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


def create_file_report(file_hash: str, reports, file_info, format_: str = 'xml', verbose: bool = False):

    outputs, feed_related_indicators, behavior = parse_file_report(reports, file_info)

    dbot_score = 3 if file_info["malware"] == 'yes' else 1

    dbot_score_object = Common.DBotScore(indicator=file_hash, indicator_type=DBotScoreType.FILE,
                                         integration_name='WildFire', score=dbot_score, reliability=RELIABILITY)
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


def get_sha256_of_file_from_report(report):
    if maec_packages := report.get('maec_packages'):
        for item in maec_packages:
            if hashes := item.get('hashes'):
                return hashes.get('SHA256')
    return None


@logger
def wildfire_get_url_report(url: str) -> Tuple:
    """
    This functions is used for retrieving the results of a previously uploaded url.
    Args:
        url: The url of interest.

    Returns:
        A CommandResults object with the results of the request and the status of that upload (Pending/Success/NotFound).

    """

    get_report_uri = f"{URL}{URL_DICT['report']}"
    params = {'apikey': TOKEN, 'url': url}
    entry_context = {'URL': url}

    try:
        response = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params, resp_type='json')
        report = response.get('result').get('report')

        if not report:
            entry_context['Status'] = 'Pending'
            human_readable = 'The sample is still being analyzed. Please wait to download the report.'

        else:
            entry_context['Status'] = 'Success'
            report = json.loads(report) if type(report) is not dict else report
            report.update(entry_context)
            sha256_of_file_in_url = get_sha256_of_file_from_report(report)
            human_readable_dict = {'SHA256': sha256_of_file_in_url, 'URL': url, 'Status': 'Success'}
            human_readable = tableToMarkdown(f'Wildfire URL report for {url}', t=human_readable_dict, removeNull=True)

    except NotFoundError:
        entry_context['Status'] = 'NotFound'
        human_readable = 'Report not found.'
        report = ''
    except Exception as e:
        entry_context['Status'] = ''
        human_readable = f'Error while requesting the report: {e}.'
        report = ''
        demisto.error(f'Error while requesting the given report. Error: {e}')

    finally:
        command_results = CommandResults(outputs_prefix='WildFire.Report', outputs_key_field='url',
                                         outputs=report, readable_output=human_readable, raw_response=report)
        return command_results, entry_context['Status']


@logger
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
            human_readable, entry_context, indicator = create_file_report(file_hash,
                                                                          reports, file_info, format_, verbose)

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
            reliability=RELIABILITY)
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


def wildfire_get_report_command(args):
    """
    Args:
        args: the command arguments from demisto.args(), including url or file hash (sha256 or md5) to query on

    Returns:
        A single or list of CommandResults, and the status of the reports of the url or file of interest.
        Note that the status is only used for the polling sequence, where the command will always receive a single
        file or url. Hence, when running this command via the polling sequence, the CommandResults list will contain a
        single item, and the status will represent that result's status.

    """
    command_results_list = []
    urls = argToList(args.get('url', ''))
    if 'sha256' in args:
        sha256 = args.get('sha256')
    elif 'hash' in args:
        sha256 = args.get('hash')
    else:
        sha256 = None
    md5 = args.get('md5')
    inputs = urls if urls else hash_args_handler(sha256, md5)

    for element in inputs:
        command_results, status = wildfire_get_url_report(element) if urls else wildfire_get_file_report(element, args)
        command_results_list.append(command_results)

    return command_results_list, status


def wildfire_file_command(args):
    inputs = file_args_handler(args.get('file'), args.get('md5'), args.get('sha256'))
    command_results_list = []
    for element in inputs:
        if sha1Regex.match(element):
            demisto.results({
                'Type': 11,
                'Contents': 'WildFire file hash reputation supports only MD5, SHA256 hashes',
                'ContentsFormat': formats['text']
            })
        else:
            command_results = wildfire_get_file_report(element, args)[0]
            command_results_list.append(command_results)
            return command_results


def wildfire_get_sample(file_hash):
    get_report_uri = URL + URL_DICT["sample"]
    params = {
        'apikey': TOKEN,
        'hash': file_hash
    }
    result = http_request(get_report_uri, 'POST', headers=DEFAULT_HEADERS, params=params, return_raw=True)
    return result


def wildfire_get_sample_command():
    if 'sha256' in demisto.args() or 'hash' in demisto.args():
        sha256 = demisto.args().get('sha256', None)
    else:
        sha256 = None
    md5 = demisto.args().get('md5', None)
    inputs = hash_args_handler(sha256, md5)

    for element in inputs:
        try:
            result = wildfire_get_sample(element)
            # filename will be found under the Content-Disposition header in the format
            # attachment; filename=<FILENAME>.000
            content_disposition = result.headers.get('Content-Disposition')
            raw_filename = content_disposition.split('filename=')[1]
            # there are 2 dots in the filename as the response saves the packet capture file
            # need to extract the string until the second occurrence of the dot char
            file_name = '.'.join(raw_filename.split('.')[:2])
            # will be saved under 'File' in the context, can be further investigated.
            file_entry = fileResult(file_name, result.content)
            demisto.results(file_entry)
        except NotFoundError as exc:
            demisto.error(f'Sample was not found. Error: {exc}')
            demisto.results(
                'Sample was not found. '
                'Please note that grayware and benign samples are available for 14 days only. '
                'For more info contact your WildFire representative.')


def assert_upload_argument(args):
    """
    Assert the upload argument is inserted when running the command without the builtin polling flow.
    The upload argument is only required when polling is false.
    """
    if not args.get('upload'):
        raise ValueError('Please specify the item you wish to upload using the \'upload\' argument.')


def main():
    command = demisto.command()
    args = demisto.args()
    LOG(f'command is {command}')

    try:
        if not TOKEN:
            raise DemistoException('API Key must be provided.')
        # Remove proxy if not set to true in params
        handle_proxy()

        if command == 'test-module':
            test_module()

        elif command == 'wildfire-upload':
            if args.get('polling') == 'true':
                return_results(wildfire_upload_file_with_polling_command(args))
            else:
                return_results(wildfire_upload_file_command(args))

        elif command in ['wildfire-upload-file-remote', 'wildfire-upload-file-url']:
            if args.get('polling') == 'true':
                return_results(wildfire_upload_file_url_with_polling_command(args))
            else:
                return_results(wildfire_upload_file_url_command(args))

        elif command == 'wildfire-upload-url':
            if args.get('polling') == 'true':
                return_results(wildfire_upload_url_with_polling_command(args))
            else:
                return_results(wildfire_upload_url_command(args))

        elif command == 'wildfire-report':
            return_results(wildfire_get_report_command(args)[0])

        elif command == 'file':
            return_results(wildfire_file_command(args))

        elif command == 'wildfire-get-sample':
            wildfire_get_sample_command()

        elif command == 'wildfire-get-verdict':
            wildfire_get_verdict_command()

        elif command == 'wildfire-get-verdicts':
            wildfire_get_verdicts_command()

        elif command == 'wildfire-get-url-webartifacts':
            wildfire_get_url_webartifacts_command()

    except Exception as err:
        return_error(str(err))

    finally:
        LOG.print_log()


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
