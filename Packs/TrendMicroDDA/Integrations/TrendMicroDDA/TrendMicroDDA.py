import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
from datetime import datetime
import uuid
import json
import requests
import re
import platform
import os.path
import copy

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]  # pylint: disable=no-member

if not demisto.params().get("proxy", True):
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]
    del os.environ["http_proxy"]
    del os.environ["https_proxy"]

# HELPER FUNCTIONS #


def load_host_url():
    ''' loads the host url from the configuration or strips the server url to get valid host url '''
    host = demisto.params()['ip_address']
    if host:
        # strip https://www. of the server address //disable-secrets-detection
        url = re.compile(r"https?://(www\.)?")
        host = url.sub('', demisto.params()['server']).strip().strip('/')
        # strip :{port} of the server address
        host = host.split(':')[0]
    return host


def hash_file(filename):
    '''Calculate the SHA1 of a file'''
    # The function was taken from here:
    # https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file#answer-3431838
    h = hashlib.sha1()  # nosec
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_url(url):
    '''Calculate the SHA1 of a URL'''
    h = hashlib.sha1()  # nosec
    h.update(url.encode('utf-8'))
    return h.hexdigest()


def get_epoch_time():
    '''Get the epoch time (for the X-DTAS-Time header value.'''
    epoch_time = str(int(time.time()))
    return epoch_time


def get_epoch_from_datetime(dt):
    '''Calculate epoch time from a datetime object'''
    epoch_format = str(int(time.mktime(dt.timetuple())))
    return epoch_format


def calculate_checksum(api_key, headers, body=''):
    ''' Generates a Checksum for the api call '''
    if not API_KEY:
        raise DemistoException('API key must be provided.')
    temp = api_key
    if 'X-DTAS-ChecksumCalculatingOrder' in headers:
        x_dtas_checksum_calculating_order_list = headers['X-DTAS-ChecksumCalculatingOrder'].split(",")
        for key in x_dtas_checksum_calculating_order_list:
            temp += headers[key]
    else:
        for key, value in headers.items():
            if ('X-DTAS-' in key and 'X-DTAS-Checksum' not in key and 'X-DTAS-ChecksumCalculatingOrder' not in key):
                temp += value

    temp += body
    return hashlib.sha1(temp.encode('utf-8'))  # nosec


def http_request(uri, method, headers, body={}, params={}, files={}):
    ''' Makes an API call to the server URL with the supplied uri, method, headers, body and params '''
    url = f'{SERVER_URL}/{uri}'
    if method not in ['put', 'post']:
        body = json.dumps(body)
    res = requests.request(
        method,
        url,
        headers=headers,
        data=body,
        verify=USE_SSL,
        params=params,
        files=files
    )

    if (res.status_code != 102 and (res.status_code < 200 or res.status_code >= 300)):
        raise Exception('Got status code ' + str(res.status_code) + ' with body '
                        + str(res.content) + ' with headers ' + str(res.headers))
    return res


def file_uploaded_to_incident(file, file_sha1):
    ''' Converts an uploaded file to a Demisto incident '''
    incident = {}  # type: Dict[str, Any]
    incident["name"] = "Incident: %s " % (file_sha1)
    incident["occurred"] = str(CURRENT_TIME)
    incident["rawJSON"] = "TODO"

    labels = []  # type: list
    incident["labels"] = labels
    return incident


def binary_to_boolean_str(binary):
    if (binary == '0'):
        return 'False'
    else:
        return 'True'


def binary_to_boolean(binary):
    return binary == '0'


# GLOBAL VARIABLES #
API_KEY = demisto.params().get('credentials_api_key', {}).get('password') or demisto.params().get('apiKey')
PROTOCOL_VERSION = demisto.params()['protocol_version']
SERVER_URL = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
USE_SSL = not demisto.params().get('insecure', True)
UUID = str(uuid.uuid4())
HOST = load_host_url()

DEFAULT_HEADERS = {
    'X-DTAS-ProtocolVersion': PROTOCOL_VERSION,
    'X-DTAS-ClientUUID': UUID,
    'X-DTAS-Time': get_epoch_time(),
    'X-DTAS-Challenge': str(uuid.uuid4()),
    'X-DTAS-ProductName': 'TDA',
    'X-DTAS-ClientHostname': platform.node(),
    'X-DTAS-SourceID': '1',
    'X-DTAS-SourceName': 'DemistoIntegration',
}
if HOST:
    DEFAULT_HEADERS['Host'] = HOST


# for fetch incident
CURRENT_TIME = datetime.utcnow()

# COMMAND FUNCTIONS #


def register():
    headers_register = copy.deepcopy(DEFAULT_HEADERS)
    tmp_checksum = calculate_checksum(API_KEY, headers_register)
    headers_register['X-DTAS-Checksum'] = tmp_checksum.hexdigest()
    http_request(
        'web_service/sample_upload/register',
        'get',
        headers_register
    )


def unregister():
    headers_unregister = copy.deepcopy(DEFAULT_HEADERS)
    tmp_checksum = calculate_checksum(API_KEY, headers_unregister)
    headers_unregister['X-DTAS-Checksum'] = tmp_checksum.hexdigest()
    http_request(
        'web_service/sample_upload/unregister',
        'get',
        headers_unregister
    )


def test():
    headers_test = copy.deepcopy(DEFAULT_HEADERS)
    tmp_checksum = calculate_checksum(API_KEY, headers_test)
    headers_test['X-DTAS-Checksum'] = tmp_checksum.hexdigest()
    http_request(
        'web_service/sample_upload/test_connection',
        'get',
        headers_test
    )
    demisto.results('ok')


def prettify_simple_upload_sample_file(sha1):
    pretty_sample = {
        'SHA1': sha1.upper()
    }
    return pretty_sample


def simple_upload_sample_file(sample_file):
    '''Upload a file to Deep Discovery Analyzer for analysis'''
    with open(demisto.getFilePath(sample_file)['path'], 'rb') as f:
        headers_simple_upload_sample_file = {
            'X-DTAS-ProtocolVersion': PROTOCOL_VERSION,
            'X-DTAS-ClientUUID': UUID,
            'X-DTAS-SourceID': '1',
            'X-DTAS-SourceName': 'DemistoIntegration',
            'X-DTAS-SHA1': hash_file(demisto.getFilePath(sample_file)['path']),
            'X-DTAS-Time': get_epoch_time(),
            'X-DTAS-SampleType': '0',  # 0 for file, 1 for URL
            'X-DTAS-Challenge': str(uuid.uuid4()),
            'X-DTAS-ChecksumCalculatingOrder': "X-DTAS-ProtocolVersion,X-DTAS-ClientUUID,X-DTAS-SourceID,X-DTAS-SourceName,"
                                               + "X-DTAS-SHA1,X-DTAS-Time,X-DTAS-SampleType,X-DTAS-Challenge",
        }
        tmp_checksum = calculate_checksum(API_KEY, headers_simple_upload_sample_file)
        headers_simple_upload_sample_file['X-DTAS-Checksum'] = tmp_checksum.hexdigest()
        cmd_url = 'web_service/sample_upload/simple_upload_sample'
        res = http_request(
            cmd_url,
            'post',
            headers_simple_upload_sample_file,
            files={'uploadsample': f}
        )
    pretty_res = prettify_simple_upload_sample_file(headers_simple_upload_sample_file['X-DTAS-SHA1'])
    return res, pretty_res


def simple_upload_sample_file_command():
    sample_file = demisto.args().get('entryID')
    res, pretty_res = simple_upload_sample_file(sample_file)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': 'File was uploaded to Trend Micro DDA successfully',
        'EntryContext': {
            'TrendMicroDDA.Submission(val.SHA1 && val.SHA1==obj.SHA1)': pretty_res
        }
    })


def prettify_simple_upload_sample_url(url, sha1):
    pretty_sample = {
        'SHA1': sha1.upper(),
        'URL': url
    }
    return pretty_sample


def simple_upload_sample_url(sample_url):
    '''Upload a URL to Analyzer for analysis'''
    headers_simple_upload_sample_url = {
        'X-DTAS-ProtocolVersion': PROTOCOL_VERSION,
        'X-DTAS-ClientUUID': UUID,
        'X-DTAS-SourceID': '1',
        'X-DTAS-SourceName': 'DemistoIntegration',
        'X-DTAS-SHA1': hash_url(sample_url),
        'X-DTAS-Time': get_epoch_time(),
        'X-DTAS-SampleType': '1',  # 0 for file, 1 for URL
        'X-DTAS-Challenge': str(uuid.uuid4()),
        'X-DTAS-ChecksumCalculatingOrder': "X-DTAS-ProtocolVersion,X-DTAS-ClientUUID,X-DTAS-SourceID,X-DTAS-SourceName,"
                                           + "X-DTAS-SHA1,X-DTAS-Time,X-DTAS-SampleType,X-DTAS-Challenge",
    }
    tmp_checksum = calculate_checksum(API_KEY, headers_simple_upload_sample_url)
    headers_simple_upload_sample_url['X-DTAS-Checksum'] = tmp_checksum.hexdigest()

    cmd_url = 'web_service/sample_upload/simple_upload_sample'
    res = http_request(
        cmd_url,
        'post',
        headers_simple_upload_sample_url,
        files={'uploadsample': sample_url}
    )

    pretty_res = prettify_simple_upload_sample_url(sample_url, headers_simple_upload_sample_url['X-DTAS-SHA1'])
    return res, pretty_res


def simple_upload_sample_url_command():
    sample_url = demisto.args().get('url')
    res, pretty_res = simple_upload_sample_url(sample_url)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': str(res.headers),
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('URL was uploaded to Trend Micro DDA successfully', pretty_res),
        'EntryContext': {
            'TrendMicroDDA.Submission(val.SHA1 && val.SHA1==obj.SHA1)': pretty_res
        }
    })


def get_sample(sha1, archive_type, archive_encrypted, archive_name):
    '''Issue a request to retrieve an archive of the sample given its SHA1 hash'''
    if not (re.match(r'\b[0-9a-fA-F]{40}\b', sha1)):
        return_error(f'Provided SHA1: {sha1} is unvalid.')

    headers_get_sample = copy.deepcopy(DEFAULT_HEADERS)
    headers_get_sample['X-DTAS-SHA1'] = sha1  # SHA1 of the file/URL to download
    headers_get_sample['X-DTAS-ArchiveType'] = archive_type
    headers_get_sample['X-DTAS-ArchiveEncrypted'] = archive_encrypted

    tmp_checksum = calculate_checksum(API_KEY, headers_get_sample)
    headers_get_sample['X-DTAS-Checksum'] = tmp_checksum.hexdigest()

    cmd_url = 'web_service/sample_upload/get_sample'
    res = http_request(
        cmd_url,
        'get',
        headers_get_sample
    )
    file = fileResult(archive_name, res.content)

    return res, file


def get_sample_command():
    sha1 = demisto.args()['sha1']
    archive_type = demisto.args()['type']
    archive_encrypted = demisto.args()['encrypted']
    archive_name = demisto.args()['archive_name'] if 'archive_name' in demisto.args() else sha1
    archive_name += f'.{archive_type}'
    res, file = get_sample(sha1, archive_type, archive_encrypted, archive_name)

    return demisto.results(file)


def get_sample_list(interval_start, interval_end, interval_type):

    try:
        interval_start_dt = datetime.strptime(interval_start, "%Y-%m-%d %H:%M:%S")
        interval_end_dt = datetime.strptime(interval_end, "%Y-%m-%d %H:%M:%S")
    except BaseException:
        return_error('Given interval times are not in the required format, which is: YYYY-MM-DD HH:MM:SS, '
                     + 'e.g. 2008-11-22 19:53:42')

    headers_get_sample_list = copy.deepcopy(DEFAULT_HEADERS)
    headers_get_sample_list['X-DTAS-IntervalStartingPoint'] = get_epoch_from_datetime(interval_start_dt)
    headers_get_sample_list['X-DTAS-IntervalEndPoint'] = get_epoch_from_datetime(interval_end_dt)
    headers_get_sample_list['X-DTAS-IntervalType'] = interval_type

    tmp_checksum = calculate_checksum(API_KEY, headers_get_sample_list)
    headers_get_sample_list['X-DTAS-Checksum'] = tmp_checksum.hexdigest()

    cmd_url = 'web_service/sample_upload/get_sample_list'
    res = http_request(
        cmd_url,
        'get',
        headers_get_sample_list
    )

    return res  # returns a list of SHA1 of the samples


def get_sample_list_command():
    '''Issue a request to get a semi-colon separated values list of submissions within the given time interval'''
    interval_start = demisto.args()['interval_start']
    interval_end = demisto.args()['interval_end']
    interval_type = demisto.args()['interval_type']
    result = get_sample_list(interval_start, interval_end, interval_type)
    if result.text:
        sha1_list = result.text.split(';')
        hr = '### Trend Micro DDA submissions SHA1\n'
        for sha1 in sha1_list:
            hr += f'- {sha1}\n'

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': result.text,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr
        })
    else:
        demisto.results('No results found.')


def build_report(res, threshold, status, verbose):
    report_json = json.loads(xml2json(res.text.encode('utf-8')))
    reports = report_json['REPORTS']
    # true if list, false if dict
    reports_type_is_list = isinstance(reports['FILE_ANALYZE_REPORT'], list)
    hr = {}  # type: Dict[str, Union[str, Dict[str, str]]]

    if isinstance(reports, dict):
        image_type_dict = reports.get('IMAGE_TYPE', {})
        if isinstance(image_type_dict, dict):
            image_type_dict = image_type_dict.get('TYPE', {})

            if isinstance(image_type_dict, dict):
                image_type = image_type_dict.get('#text', 'Unknown')
            else:
                image_type = 'Unknown'

        else:
            image_type = 'Unknown'
    else:
        image_type = 'Unknown'

    hr_headers = {
        'Risk Level': reports['OVERALL_RISK_LEVEL'],
        'Image Type': image_type,
        'Sum of Files Analyzed': (len(reports['FILE_ANALYZE_REPORT'])) if reports_type_is_list else '1',
    }

    context = {}  # type: Dict[str, Any]
    dbot_score = 0
    context['DBotScore'] = {
        'Vendor': 'Trend Micro DDA',
        'Score': dbot_score,  # check that------------------ TODO --------------------
        'Type': 'hash',
        'Indicator': reports['FILE_ANALYZE_REPORT']['FileSHA1'] if not reports_type_is_list
        else reports['FILE_ANALYZE_REPORT'][0]['FileSHA1']
    }
    # if type is list, the submission was divided to sub-files and the first file_analyze_report is of the main submission
    # context['DBotScore.Indicator'] = reports['FILE_ANALYZE_REPORT']['FileSHA1']
    # if not reports_type_is_list else reports['FILE_ANALYZE_REPORT'][0]['FileSHA1']

    if not reports_type_is_list:  # if the submission doesn't have sub-files
        file_analyze_report = reports['FILE_ANALYZE_REPORT']
        hr['File Name'] = file_analyze_report['OrigFileName']
        hr['Malware Source IP'] = file_analyze_report['MalwareSourceIP']
        hr['Malware Source Host'] = file_analyze_report['MalwareSourceHost']
        hr['Total Dropped Files'] = file_analyze_report['DroppedFiles']['@Total']
        hr['Deny List'] = binary_to_boolean_str(file_analyze_report['IsDenylisted'])
        hr['White List'] = binary_to_boolean_str(file_analyze_report['IsWhitelisted'])

        if '#text' in file_analyze_report['VirusName']:  # the submission has a detection
            hr['Detection Name'] = file_analyze_report['VirusName']['#text']
        # set the filename
        filename = hr['Detection Name'] if ('Detection Name' in hr) else file_analyze_report['FileSHA1']
        if filename and '.' not in filename:
            filename = str(filename) + ".txt"

        # add data regarding the submission to the context
        context['TrendMicroDDA.Submission(val.SHA1 && val.SHA1==obj.SHA1)'] = {
            'Status': status,
            'RiskLevel': reports['OVERALL_RISK_LEVEL'],
            'SHA1': file_analyze_report['FileSHA1'],
            'SHA256': file_analyze_report['FileSHA256'],
            'MD5': file_analyze_report['FileMD5'],
            'VirusDetected': binary_to_boolean(file_analyze_report['VirusDetected']),
        }

        if file_analyze_report['TrueFileType'] == 'URL':
            # add the URL address
            context[outputPaths['url']] = {
                'Data': file_analyze_report['OrigFileName']
            }
        else:
            context[outputPaths['file']] = {
                'MD5': file_analyze_report['FileMD5'],
                'SHA1': file_analyze_report['FileSHA1'],
                'SHA256': file_analyze_report['FileSHA256'],
                'Size': file_analyze_report['FileSize'],
                'Name': file_analyze_report['OrigFileName'],
            }

        # add data regarding the submission to the context if file is malicious
        if (reports['OVERALL_RISK_LEVEL'] >= threshold):
            if file_analyze_report['TrueFileType'] == 'URL':
                context[outputPaths['url']].update({
                    'Malicious': {
                        'Vendor': 'Trend Micro DDA',
                        'Description': 'RiskLevel: ' + reports['OVERALL_RISK_LEVEL']
                    }
                })
            else:
                context[outputPaths['file']].update({
                    'Malicious': {
                        'Vendor': 'Trend Micro DDA',
                        'Description': 'RiskLevel: ' + reports['OVERALL_RISK_LEVEL']
                    }
                })

        # extracting IP and Domains from the report
        if file_analyze_report['MalwareSourceIP']:
            context['IP.Address(val.Address && val.Address == obj.Address)'] = file_analyze_report['MalwareSourceIP']
        if file_analyze_report['MalwareSourceHost']:
            context['Domain.Name(val.Name && val.Name == obj.Name)'] = file_analyze_report['MalwareSourceHost']
        if verbose == 'true':
            dropped_files = file_analyze_report['DroppedFiles']
            if 'FileItem' in dropped_files and 'DownloadURL' in dropped_files['FileItem']:
                context['URL.Data(val.Data && val.Data == obj.Data)'] = dropped_files['FileItem']['DownloadURL']
                hr['Download URL'] = dropped_files['FileItem']['DownloadURL']
                context['TrendMicroDDA.Submission'].update({
                    'DownloadURL': dropped_files['FileItem']['DownloadURL']
                })

    else:  # if the submission have sub-files

        main_file_analyze_report = reports['FILE_ANALYZE_REPORT'][0]

        # add data to the war room
        hr = copy.deepcopy(reports['FILE_ANALYZE_REPORT'])
        for item in hr:
            item['File Name'] = item['OrigFileName']  # type: ignore
            item['Detection Name'] = item['VirusName']['#text'] if '#text' in item['VirusName'] else None  # type: ignore
            item['Malware Source IP'] = item['MalwareSourceIP']  # type: ignore
            item['Malware Source Host'] = item['MalwareSourceHost']  # type: ignore
            if verbose == 'true':
                item['Download URL'] = item['DroppedFiles'].get('FileItem')  # type: ignore
            item['Deny List'] = binary_to_boolean_str(item['IsDenylisted']) if item['IsDenylisted'] else None  # type: ignore
            item['White List'] = binary_to_boolean_str(item['IsWhitelisted']) if item['IsWhitelisted'] else None  # type: ignore

        # set the filename
        filename = main_file_analyze_report['OrigFileName']
        if filename and '.' not in filename:
            filename = str(filename) + ".txt"

        # This section was commented out because it used an undefined variable download_url_list.
        # Need to check again if it should be moving to GA.

        # if verbose == 'true':
        #     hr['Download URL'] = download_url_list
        #     context['URL.Data(val.Data && val.Data == obj.Data)'] = download_url_list
        #     context['TrendMicroDDA.Submission'].update({
        #         'DownloadURL': download_url_list
        #     })

        # add data regarding the submission to the context
        file_analyzed_list = []
        for file_analyzed in reports['FILE_ANALYZE_REPORT'][1:]:  # iterate over all the subfiles excluding the main file
            file_analyzed_dict = {
                'SHA1': file_analyzed['FileSHA1'],
                'SHA256': file_analyzed['FileSHA256'],
                'MD5': file_analyzed['FileMD5'],
                'Name': file_analyzed['VirusName']['#text'] if '#text' in file_analyzed['VirusName'] else '',
                'VirusDetected': binary_to_boolean(file_analyzed['VirusDetected']),
            }
            if file_analyzed['TrueFileType'] == 'URL':
                # add the URL address
                context[outputPaths['url']] = {
                    'Data': file_analyzed['OrigFileName']
                }
            else:
                context[outputPaths['file']] = {
                    'MD5': file_analyzed['FileMD5'],
                    'SHA1': file_analyzed['FileSHA1'],
                    'SHA256': file_analyzed['FileSHA256'],
                    'Size': file_analyzed['FileSize'],
                    'Name': file_analyzed['VirusName']['#text'] if '#text' in file_analyzed['VirusName'] else '',
                    # add score of some sort from virusdetected? ask michal.------------------ TODO --------------------
                }
            file_analyzed_list.append(file_analyzed_dict)

        context['TrendMicroDDA.Submission(val.SHA1 && val.SHA1==obj.SHA1)'] = {
            'Status': status,
            'RiskLevel': reports['OVERALL_RISK_LEVEL'],
            'SHA1': main_file_analyze_report['FileSHA1'],
            'SHA256': main_file_analyze_report['FileSHA256'],
            'MD5': main_file_analyze_report['FileMD5'],
            'VirusDetected': binary_to_boolean(main_file_analyze_report['VirusDetected']),
            'FileAnalyzed': file_analyzed_list,
        }
        if main_file_analyze_report['TrueFileType'] == 'URL':
            context['URL(val.Data && val.Data==obj.Data)'] = {
                'Data': main_file_analyze_report['OrigFileName'],
            }
        else:
            context['File(val.SHA1 && val.SHA1==obj.SHA1)'] = {
                'MD5': main_file_analyze_report['FileMD5'],
                'SHA1': main_file_analyze_report['FileSHA1'],
                'SHA256': main_file_analyze_report['FileSHA256'],
                'Size': main_file_analyze_report['FileSize'],
                'Name': main_file_analyze_report['VirusName']['#text'] if '#text' in main_file_analyze_report['VirusName']
                else '',
            }
        # add data regarding the submission to the context if it is malicious
        if (reports['OVERALL_RISK_LEVEL'] >= threshold):
            context['DBotScore.Score'] = 3
            if (main_file_analyze_report['TrueFileType'] == 'URL'):
                context[outputPaths['url']] = {
                    'Malicious': {
                        'Vendor': 'Trend Micro DDA',
                        'Description': 'RiskLevel: ' + reports['OVERALL_RISK_LEVEL']
                    }
                }
            else:
                context[outputPaths['file']] = {
                    'Malicious': {
                        'Vendor': 'Trend Micro DDA',
                        'Description': 'RiskLevel: ' + reports['OVERALL_RISK_LEVEL']
                    }
                }

        # extracting IP and Domains from the report
        if main_file_analyze_report['MalwareSourceIP']:
            context['IP.Address(val.Address && val.Address == obj.Address)'] = main_file_analyze_report['MalwareSourceIP']
        if main_file_analyze_report['MalwareSourceHost']:
            context['Domain.Name(val.Name && val.Name == obj.Name)'] = main_file_analyze_report['MalwareSourceHost']

    return context, hr, hr_headers, filename


def get_report(sha1):
    '''Issue a request to retrieve XML report for a given SHA1'''
    if not (re.match(r'\b[0-9a-fA-F]{40}\b', sha1)):
        return_error(f'Provided SHA1: {sha1} is unvalid.')

    headers_get_report = copy.deepcopy(DEFAULT_HEADERS)
    headers_get_report['X-DTAS-SHA1'] = sha1  # SHA1 of the file/URL to download
    headers_get_report['X-DTAS-Time'] = get_epoch_time()

    tmp_checksum = calculate_checksum(API_KEY, headers_get_report)
    headers_get_report['X-DTAS-Checksum'] = tmp_checksum.hexdigest()

    cmd_url = 'web_service/sample_upload/get_report'
    res = http_request(
        cmd_url,
        'get',
        headers_get_report
    )

    return res


def get_report_command():
    sha1 = demisto.args()['sha1']
    threshold = demisto.args()['threshold']
    verbose = demisto.args()['verbose']
    res = get_report(sha1)

    if res.status_code == 102:
        ec = {
            'Status': 'Analyzing',
            'SHA1': sha1
        }
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Content': {"value": res},
            'HumanReadable': 'Submission analyzation was not finished yet.',
            'EntryContext': {
                'TrendMicroDDA.Submission(val.SHA1 && val.SHA1==obj.SHA1)': ec
            }
        })
    else:
        status = 'Completed'

        context, hr, hr_headers, filename = build_report(res, threshold, status, verbose)
        markdown_table_headers = ['File Name', 'Detection Name', 'Malware Source IP', 'Malware Source Host']
        if verbose == 'true':
            markdown_table_headers.append('Download URL')
        markdown_table_headers.extend(('Deny List', 'White List'))

        tmp_file = fileResult(filename, res.text)

        demisto.results({  # add context and the Report File to the war room
            'Type': entryTypes['file'],
            'FileID': tmp_file.get('FileID'),
            'Contents': '',
            'ContentsFormat': formats['text'],
            'File': tmp_file.get('File'),
            'EntryContext': context,
        })
        demisto.results({  # add table to the war room
            'Type': entryTypes['note'],
            'Contents': res.text,
            'ContentsFormat': formats['text'],
            'HumanReadableFormat': formats['markdown'],
            'HumanReadable':
                '## Submission Report from TrendMicroDDA\n'
                + '### Risk Level: {}, Sum of Files Analyzed: {}, Image Type: {}\n'.format(
                    hr_headers['Risk Level'], hr_headers['Sum of Files Analyzed'], hr_headers['Image Type'])
                + tableToMarkdown('Report Summary', hr, headers=markdown_table_headers),
        })


def build_brief_report(res, sha1, threshold):
    report_json = json.loads(xml2json(res.text))
    brief_report_json = report_json.get('REPORT', {}).get('BRIEF_REPORT', {})
    hr = {
        'SHA1': sha1,
        'Risk Level': brief_report_json.get('RiskLevel'),
        'Status': brief_report_json.get('STATUS'),
    }
    return hr


def get_brief_report(sha1):
    if not (re.match(r'\b[0-9a-fA-F]{40}\b', sha1)):
        return_error('Provided SHA1 is unvalid.')

    headers_get_brief_report = {
        'Content-Type': 'text/plain',
        'X-DTAS-ProtocolVersion': PROTOCOL_VERSION,
        'X-DTAS-ClientUUID': UUID,
        'X-DTAS-Time': get_epoch_time(),
        'X-DTAS-Challenge': str(uuid.uuid4()),
        'X-DTAS-ChecksumCalculatingOrder': "X-DTAS-ProtocolVersion,X-DTAS-ClientUUID,X-DTAS-Time,X-DTAS-Challenge",
    }
    sha1_list = argToList(sha1)
    data = ';'.join(sha1_list)
    tmp_checksum = calculate_checksum(API_KEY, headers_get_brief_report, data)
    headers_get_brief_report['X-DTAS-Checksum'] = tmp_checksum.hexdigest()

    cmd_url = 'web_service/sample_upload/get_brief_report'
    res = http_request(
        cmd_url,
        'put',
        headers=headers_get_brief_report,
        body=data
    )
    return res


def get_brief_report_command():
    '''Issue a request to retrieve the brief XML report for a given SHA1'''
    sha1 = demisto.args()['sha1']
    threshold = demisto.args()['threshold']
    res = get_brief_report(sha1)

    hr = build_brief_report(res, sha1, threshold)
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': res.text,
        'HumanReadableFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sample Brief Report from TrendMicroDDA', hr, removeNull=True),
        # 'EntryContext': {
        #    'TrendMicroDDA.Submission(val.SHA1 && val.SHA1==obj.SHA1)': context
        # }
    })


def check_status(sha1_list):
    for sha1 in sha1_list:
        if not (re.match(r'\b[0-9a-fA-F]{40}\b', sha1)):
            return_error(f'Provided SHA1: {sha1} is unvalid.')
    manyRes = []
    manyEC = []

    for sha1 in sha1_list:
        res = get_report(sha1)
        manyRes.append(res.text)
        if res.status_code == 102:
            manyEC.append({
                'Status': 'Analyzing',
                'SHA1': sha1
            })
        else:
            manyEC.append({
                'Status': 'Completed',
                'SHA1': sha1
            })

    return manyRes, manyEC


def check_status_command():
    sha1_list = argToList(demisto.args()['sha1'])
    manyRes, manyEC, = check_status(sha1_list)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': manyRes,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Status of the submissions in TrendMicroDDA', manyEC),
        'EntryContext': {
            'TrendMicroDDA.Submission(val.SHA1 && val.SHA1==obj.SHA1)': manyEC
        }
    })


# EXECUTION
LOG(f'command is {demisto.command()}')

try:
    register()
    if demisto.command() == 'test-module':
        test()

    elif demisto.command() == 'trendmicro-dda-upload-file':
        simple_upload_sample_file_command()

    elif demisto.command() == 'trendmicro-dda-upload-url':
        simple_upload_sample_url_command()

    elif demisto.command() == 'trendmicro-dda-get-sample':
        get_sample_command()

    elif demisto.command() == 'trendmicro-dda-check-status':
        check_status_command()

    elif demisto.command() == 'trendmicro-dda-get-brief-report':
        get_brief_report_command()

    elif demisto.command() == 'trendmicro-dda-get-report':  # add !file !url command? ask anar
        get_report_command()

    elif demisto.command() == 'trendmicro-dda-get-openioc':
        # get_openioc_report_command()
        return_error("Deprecated command")

    elif demisto.command() == 'trendmicro-dda-get-sample-list':
        get_sample_list_command()

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise

finally:
    unregister()
