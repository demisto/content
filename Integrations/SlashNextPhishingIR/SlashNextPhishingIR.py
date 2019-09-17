#
# Copyright (C) SlashNext, Inc. (www.slashnext.com)
#
# License:     Subject to the terms and conditions of SlashNext EULA, SlashNext grants to Customer a non-transferable,
#              non-sublicensable, non-exclusive license to use the Software as expressly permitted in accordance with
#              Documentation or other specifications published by SlashNext. The Software is solely for Customer's
#              internal business purposes. All other rights in the Software are expressly reserved by SlashNext.
#

"""
Created on August 1, 2019

@author: Saadat Abid
"""

''' IMPORTS '''
import requests
import base64
import time

''' GLOBAL VARS '''
AUTH_KEY = demisto.params().get('apikey')

BASE_API = demisto.params().get('apiurl')
if BASE_API is None:
    BASE_API = 'https://oti.slashnext.cloud/api'

HOST_REPUTE_API = BASE_API + '/oti/v1/host/reputation'
URL_REPUTE_API = BASE_API + '/oti/v1/url/reputation'
URL_SCAN_API = BASE_API + '/oti/v1/url/scan'
URL_SCANSYNC_API = BASE_API + '/oti/v1/url/scansync'
HOST_REPORT_API = BASE_API + '/oti/v1/host/report'
DL_SC_API = BASE_API + '/oti/v1/download/screenshot'
DL_HTML_API = BASE_API + '/oti/v1/download/html'
DL_TEXT_API = BASE_API + '/oti/v1/download/text'


''' HELPERS FUNCTIONS '''

@logger
def invoke_snx_api(api_type='validation', method='POST', **kwargs):
    """
    Execute the SlashNext cloud API as per selected type of API with the given API args
    :param api_type: Corresponds to SlashNext cloud API to be invoked
    :param method: HTTP method to be used for API i.e. GET or POST
    :param host: (optional) Host (IPv4 or FQDN) name in case of host_reputation or host_report API call
    :param url: (optional) URL in of url_scan, url_scan_sync or url_reputation API call
    :param timeout: (optional) timeout in of url_scan_sync API call
    :param scanid: (optional) Scan ID in of url_scan, dl_screenshot, dl_html or dl_text API call
    :param resolution: (optional) Resolution of the screenshot in of dl_screenshot
    :param page: (optional) Page to get for host report
    :param rpp: (optional) Records per page
    :return: Response of the SlashNext web API in json format
    """
    if method == 'GET' or method == 'POST':

        response = None

        if api_type == 'validation':
            input_data = {
                'authkey': AUTH_KEY,
                'host': kwargs.get('host')
            }
            response = requests.request(method, url=HOST_REPUTE_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'host-repute':
            input_data = {
                'authkey': AUTH_KEY,
                'host': kwargs.get('host')
            }
            response = requests.request(method, url=HOST_REPUTE_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'url-repute':
            input_data = {
                'authkey': AUTH_KEY,
                'url': kwargs.get('url')
            }
            response = requests.request(method, url=URL_REPUTE_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'host-report':
            input_data = {
                'authkey': AUTH_KEY,
                'host': kwargs.get('host'),
                'page': kwargs.get('page'),
                'rpp': kwargs.get('rpp')
            }
            response = requests.request(method, url=HOST_REPORT_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'url-scan':
            input_data = {
                'authkey': AUTH_KEY,
                'url': kwargs.get('url')
            }
            response = requests.request(method, url=URL_SCAN_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'get-url-scan':
            input_data = {
                'authkey': AUTH_KEY,
                'scanid': kwargs.get('scanid')
            }
            response = requests.request(method, url=URL_SCAN_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'url-scan-sync':
            input_data = {
                'authkey': AUTH_KEY,
                'url': kwargs.get('url'),
                'timeout': kwargs.get('timeout')
            }
            response = requests.request(method, url=URL_SCANSYNC_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'dl-screenshot':
            input_data = {
                'authkey': AUTH_KEY,
                'scanid': kwargs.get('scanid'),
                'resolution': kwargs.get('resolution')
            }
            response = requests.request(method, url=DL_SC_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'dl-html':
            input_data = {
                'authkey': AUTH_KEY,
                'scanid': kwargs.get('scanid')
            }
            response = requests.request(method, url=DL_HTML_API, params=input_data, data=input_data, timeout=300)
        elif api_type == 'dl-text':
            input_data = {
                'authkey': AUTH_KEY,
                'scanid': kwargs.get('scanid')
            }
            response = requests.request(method, url=DL_TEXT_API, params=input_data, data=input_data, timeout=300)
        else:
            return_error('Invalid API type selected for execution!')

        if response.status_code == 200:
            return response.json()
        else:
            return_error('API Returned, "{}:{}"!'.format(response.status_code, response.reason))

    else:
        return_error('Unsupported HTTP method selected for API execution!')

@logger
def publish_md_and_ec(markdown, snx_contents, entry_context):
    """
    Publish the result to Demisto
    :param markdown: Human readable markdown contents
    :param snx_contents: SlashNext cloud API response contents
    :param entry_context: Output entry context
    :return: None
    """
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': snx_contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': markdown,
        'EntryContext': entry_context
    })


def get_dbot_score(verdict):
    """
    Evaluate the dbot (Demisto) score as per verdict from SlashNext cloud API
    :param verdict: SlashNext verdict on a certain IoC
    :return: Dbot score
    """
    if verdict == 'Malicious':
        return 3
    elif verdict == 'Suspicious':
        return 2
    elif verdict == 'Benign' or verdict == 'Redirector':
        return 1
    else:
        return 0


def get_dbot_std_context(indicator, ioc_type, verdict, threat_type):
    """
    Makes the dictionary for dbot score and standard Demisto contexts
    :param indicator: IoC value
    :param ioc_type: IoC type
    :param verdict: Verdict by SlashNext OTI cloud
    :param threat_type: Threat type reported by SlashNext OTI cloud
    :return: Dbot score context dictionary, dbot standard context dictionary
    """
    dbot_score = get_dbot_score(verdict)

    dbot_score_cont = {
        'Indicator': indicator,
        'Type': ioc_type,
        'Vendor': 'SlashNext',
        'Score': dbot_score
    }

    standard_cont = None
    if dbot_score == 3:
        standard_cont = {
            'Data': indicator,
            'Malicious': {
                'Vendor': 'SlashNext',
                'Description': 'Detected "{}" Activity'.format(threat_type)
            }
        }

    return dbot_score_cont, standard_cont


def get_snx_host_ioc_context(indicator, ioc_type, threat_data):
    """
    Make the dictionary for SlashNext IoC contexts for hosts
    :param indicator: IoC value
    :param ioc_type: IoC type
    :param threat_data: Threat data by SlashNext OTI cloud
    :return: SlashNext IoC context dictionary
    """
    snx_ioc_cont = {
        'Value': indicator,
        'Type': ioc_type,
        'Verdict': threat_data.get('verdict'),
        'ThreatStatus': threat_data.get('threatStatus'),
        'ThreatType': threat_data.get('threatType'),
        'ThreatName': threat_data.get('threatName'),
        'FirstSeen': threat_data.get('firstSeen'),
        'LastSeen': threat_data.get('lastSeen')
    }

    return snx_ioc_cont


def get_snx_url_ioc_context(url_data, is_scan=False):
    """
    Make the dictionary for SlashNext URL IoC contexts for URLs
    :param url_data: URL data received in json format
    :param is_scan: Is Scan ID to be included
    :return: List of SlashNext IoC context dictionaries, Entry context dictionary
    """
    snx_ioc_cont_list = []
    dbot_score_cont_list = []
    url_cont_list = []

    snx_ioc_cont = {
        'Value': url_data.get('url'),
        'Type': 'Scanned URL',
        'Verdict': url_data.get('threatData').get('verdict'),
        'ThreatStatus': url_data.get('threatData').get('threatStatus'),
        'ThreatType': url_data.get('threatData').get('threatType'),
        'ThreatName': url_data.get('threatData').get('threatName'),
        'FirstSeen': url_data.get('threatData').get('firstSeen'),
        'LastSeen': url_data.get('threatData').get('lastSeen')
    }
    if is_scan is True:
        snx_ioc_cont['ScanID'] = url_data.get('scanId')

    dbot_score_cont, url_cont = get_dbot_std_context(
        url_data.get('url'), 'url',
        url_data.get('threatData').get('verdict'),
        url_data.get('threatData').get('threatType'))
    dbot_score_cont_list.append(dbot_score_cont)
    if url_cont is not None:
        url_cont_list.append(url_cont)

    if url_data.get('landingUrl') is None:
        if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
            dbot_final_score_cont, final_url_cont = get_dbot_std_context(
                url_data.get('finalUrl'), 'url',
                url_data.get('threatData').get('verdict'),
                url_data.get('threatData').get('threatType'))
            dbot_score_cont_list.append(dbot_final_score_cont)
            if final_url_cont is not None:
                url_cont_list.append(final_url_cont)

            snx_final_ioc_cont = {
                'Value': url_data.get('finalUrl'),
                'Type': 'Final URL',
                'Verdict': url_data.get('threatData').get('verdict')
            }

            snx_ioc_cont['Final'] = snx_final_ioc_cont.copy()
            snx_ioc_cont_list.append(snx_ioc_cont)

            snx_final_ioc_cont['Value'] = '--------> {}'.format(url_data.get('finalUrl'))
            snx_ioc_cont_list.append(snx_final_ioc_cont)

        else:
            snx_ioc_cont_list.append(snx_ioc_cont)

    else:
        dbot_landing_score_cont, landing_url_cont = get_dbot_std_context(
            url_data.get('landingUrl').get('url'), 'url',
            url_data.get('landingUrl').get('threatData').get('verdict'),
            url_data.get('landingUrl').get('threatData').get('threatType'))
        dbot_score_cont_list.append(dbot_landing_score_cont)
        if landing_url_cont is not None:
            url_cont_list.append(landing_url_cont)

        snx_landing_ioc_cont = {
            'Value': url_data.get('landingUrl').get('url'),
            'Type': 'Redirected URL',
            'Verdict': url_data.get('landingUrl').get('threatData').get('verdict'),
            'ThreatStatus': url_data.get('landingUrl').get('threatData').get('threatStatus'),
            'ThreatType': url_data.get('landingUrl').get('threatData').get('threatType'),
            'ThreatName': url_data.get('landingUrl').get('threatData').get('threatName'),
            'FirstSeen': url_data.get('landingUrl').get('threatData').get('firstSeen'),
            'LastSeen': url_data.get('landingUrl').get('threatData').get('lastSeen')
        }
        if is_scan is True:
            snx_landing_ioc_cont['ScanID'] = url_data.get('landingUrl').get('scanId')

        snx_ioc_cont['Landing'] = snx_landing_ioc_cont.copy()
        snx_ioc_cont_list.append(snx_ioc_cont)

        snx_landing_ioc_cont['Value'] = '--------> {}'.format(url_data.get('landingUrl').get('url'))
        snx_ioc_cont_list.append(snx_landing_ioc_cont)

    return snx_ioc_cont_list, dbot_score_cont_list, url_cont_list


def retrieve_and_publish_host_repute(host, tag):
    """
    Retrieve the submitted host reputation from SlashNext cloud using host/reputation API and publish it
    :param host: Host whose reputation is to be determined
    :param tag: Tag for publishing results
    :return: Response from SlashNext cloud
    """
    response = invoke_snx_api(api_type='host-repute', host=host)

    if response.get('errorNo') != 0:
        return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:

        ioc_type = 'IP' if is_ip_valid(host) else 'Domain'

        host = host.encode('idna')

        dbot_score_cont, host_cont = get_dbot_std_context(
            host, ioc_type,
            response.get('threatData').get('verdict'),
            response.get('threatData').get('threatType'))

        snx_ioc_cont = get_snx_host_ioc_context(host, ioc_type, response.get('threatData'))

        ec = {
            'SlashNext.IoC(val.Value == obj.Value)': snx_ioc_cont,
            'DBotScore': dbot_score_cont,
            ioc_type: host_cont
        }

        title = 'SlashNext Phishing Incident Response - {}\n'\
                '##### host = {}'.format(tag, host)

        md = tableToMarkdown(
            title,
            snx_ioc_cont,
            ['Value',
             'Type',
             'Verdict',
             'ThreatStatus',
             'ThreatName',
             'ThreatType',
             'FirstSeen',
             'LastSeen']
        )

        publish_md_and_ec(md, snx_ioc_cont, ec)

    return response


def retrieve_and_publish_host_urls(host, tag, rpp):
    """
    Retrieve the submitted host report from SlashNext cloud using host/report API and publish it
    :param host: Host whose report is to be determined
    :param tag: Tag for publishing results
    :param rpp: Records per page corresponds to limit argument
    :return: Response from SlashNext cloud
    """
    response = invoke_snx_api(api_type='host-report', host=host, page=1, rpp=rpp)

    if response.get('errorNo') != 0:
        return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        snx_ioc_cont_list = []
        dbot_score_cont_list = []
        url_cont_list = []
        snx_ec_cont_list = []
        for url_data in response.get('urlDataList'):
            if url_data.get('threatData').get('verdict').startswith('Unrated') is False:
                snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)
                snx_ioc_cont_list.extend(snx_ioc_cont)
                dbot_score_cont_list.extend(dbot_score_cont)
                url_cont_list.extend(url_cont)
                snx_ec_cont_list.append(snx_ioc_cont[0])

        ec = {
            'SlashNext.IoC(val.Value == obj.Value)': snx_ec_cont_list,
            'DBotScore': dbot_score_cont_list,
            'URL': url_cont_list
        }

        host = host.encode('idna')

        title = 'SlashNext Phishing Incident Response - {}\n' \
                '##### host = {}'.format(tag, host)

        if response.get('normalizeData').get('normalizeStatus') == 1:
            title = title + ' *\n*' + response.get('normalizeData').get('normalizeMessage')

        md = tableToMarkdown(
            title,
            snx_ioc_cont_list,
            ['Value',
             'Type',
             'Verdict',
             'ScanID',
             'ThreatStatus',
             'ThreatName',
             'ThreatType',
             'FirstSeen',
             'LastSeen']
        )

        publish_md_and_ec(md, snx_ioc_cont_list, ec)

    return response


def download_forensics_data(scanid, tag, sc=False, html=False, txt=False):
    """
    Download the selected forensics data from SlashNext cloud
    :param scanid: Scan ID for which foresics data to download
    :param tag: String to tag the corresponding forensics data file
    :param sc: Holds true if screenshot is to be downloaded
    :param html: Holds true if the HTML is to be downloaded
    :param txt: Holds true if the text is to be downloaded
    :return: None
    """
    error_no = 0
    error_msg = 'Success'
    show_error_msg = True
    if sc is True:
        # Host Screen-shot Section
        response = invoke_snx_api(api_type='dl-screenshot', scanid=scanid, resolution='medium')

        if response.get('errorNo') != 0:
            error_no = response.get('errorNo')
            error_msg = response.get('errorMsg')
        else:
            show_error_msg = False

            sc_base64 = response.get('scData').get('scBase64')
            sc_data = base64.b64decode(sc_base64)

            sc_file = fileResult('snx_{}.jpeg'.format(scanid), sc_data, entryTypes['image'])

            demisto.results({
                'Type': entryTypes['image'],
                'ContentsFormat': formats['text'],
                'Contents': 'Forensics: Webpage Screenshot for the ' + tag,
                'File': sc_file.get('File'),
                'FileID': sc_file.get('FileID')
            })

    if html is True:
        # Host HTML Section
        response = invoke_snx_api(api_type='dl-html', scanid=scanid)

        if response.get('errorNo') == 0:
            show_error_msg = False

            html_base64 = response.get('htmlData').get('htmlBase64')
            html_data = base64.b64decode(html_base64)

            html_file = fileResult('snx_{}.html'.format(scanid), html_data, entryTypes['file'])

            demisto.results({
                'Type': entryTypes['file'],
                'ContentsFormat': formats['text'],
                'Contents': 'Forensics: Webpage HTML for the ' + tag,
                'File': html_file.get('File'),
                'FileID': html_file.get('FileID')
            })

    if txt is True:
        # Host Text Section
        response = invoke_snx_api(api_type='dl-text', scanid=scanid)

        if response.get('errorNo') == 0:
            show_error_msg = False

            text_base64 = response.get('textData').get('textBase64')
            text_data = base64.b64decode(text_base64)

            text_file = fileResult('snx_{}.txt'.format(scanid), text_data, entryTypes['file'])

            demisto.results({
                'Type': entryTypes['file'],
                'ContentsFormat': formats['text'],
                'Contents': 'Forensics: Webpage Rendered Text for the ' + tag,
                'File': text_file.get('File'),
                'FileID': text_file.get('FileID')
            })

    # Show Error Message
    if show_error_msg is True and (sc is True or html is True or txt is True):
        demisto.results('API Returned, "{}:{}"!'.format(error_no, error_msg))


''' COMMAND FUNCTIONS '''


def validate_snx_api_key():
    """
    Validate the provided SlashNext cloud API key and test connection, in case of any error exit the program
    @:return: None
    """
    response = invoke_snx_api(host='www.google.com')
    if response.get('errorNo') != 0:
        return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))

    return 'ok'


def host_reputation_command():
    """
    Execute SlashNext's host/reputation API against the requested host reputation command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'host' not in args:
        return_error('Missing required command argument "host", Please provide "host" and retry!')

    retrieve_and_publish_host_repute(host=args.get('host'), tag='Host Reputation')


def host_report_command():
    """
    Execute SlashNext's host/reputation, host/report, url/scansync, download/screenshot, download/html and download/text
    APIs against the requested host report command with given parameters
    @:return: None
    """
    args = demisto.args()

    # Host Reputation Section
    if 'host' not in args:
        return_error('Missing required command argument "host", Please provide "host" and retry!')

    response = retrieve_and_publish_host_repute(host=args.get('host'), tag='Host Report')
    if response.get('threatData').get('verdict').startswith('Unrated'):
        return

    # Host Report Section
    response = retrieve_and_publish_host_urls(host=args.get('host'), tag="Host's Latest Scanned URL", rpp=1)
    url_data = response.get('urlDataList')[0]
    scanid = url_data.get('scanId')

    # URL Scan Sync Section
    if scanid == 'N/A' or scanid is None:
        response = invoke_snx_api(api_type='url-scan-sync', url=url_data.get('url'))
        if response.get('errorNo') != 0:
            return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))

        url_data = response.get('urlData')
        scanid = url_data.get('scanId')

    # Download Screenshot, HTML and Text Section
    if url_data.get('landingUrl') is None:
        if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
            tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
        else:
            tag = 'Scanned URL = {}'.format(url_data.get('url'))
    else:
        tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

    if response.get('swlData') is None:
        download_forensics_data(scanid=scanid, tag=tag, sc=True, html=True, txt=True)


def host_urls_command():
    """
    Execute SlashNext's host/report API against the requested host urls command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'host' not in args:
        return_error('Missing required command argument "host", Please provide "host" and retry!')

    retrieve_and_publish_host_urls(host=args.get('host'), tag='Host URLs', rpp=args.get('limit'))


def url_reputation_command():
    """
    Execute SlashNext's URL/reputation API against the requested URL reputation command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'url' not in args:
        return_error('Missing required command argument "url", Please provide "url" and retry!')

    response = invoke_snx_api(api_type='url-repute', url=args.get('url'))

    if response.get('errorNo') != 0:
        return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        url_data = response.get('urlData')
        snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data)

        ec = {
            'SlashNext.IoC(val.Value == obj.Value)': snx_ioc_cont[0],
            'DBotScore': dbot_score_cont,
            'URL': url_cont
        }

        title = 'SlashNext Phishing Incident Response - URL Reputation\n'\
                '##### url = {}'.format(url_data.get('url'))

        if response.get('normalizeData').get('normalizeStatus') == 1:
            title = title + ' *\n*' + response.get('normalizeData').get('normalizeMessage')

        md = tableToMarkdown(
            title,
            snx_ioc_cont,
            ['Value',
             'Type',
             'Verdict',
             'ThreatStatus',
             'ThreatName',
             'ThreatType',
             'FirstSeen',
             'LastSeen']
        )

        publish_md_and_ec(md, snx_ioc_cont, ec)


def url_scan_command():
    """
    Execute SlashNext's URL/scan API against the requested URL scan command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'url' not in args:
        return_error('Missing required command argument "url", Please provide "url" and retry!')

    response = invoke_snx_api(api_type='url-scan', url=args.get('url'))

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "snx-scan-report" command with Scan ID = {} or '
            'running the same "snx-url-scan" command one more time.'.format(response.get('urlData').get('scanId')))
    elif response.get('errorNo') != 0:
        return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        url_data = response.get('urlData')
        scanid = url_data.get('scanId')
        snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)

        ec = {
            'SlashNext.IoC(val.Value == obj.Value)': snx_ioc_cont[0],
            'DBotScore': dbot_score_cont,
            'URL': url_cont
        }

        title = 'SlashNext Phishing Incident Response - URL Scan\n'\
                '##### url = {}'.format(url_data.get('url'))

        if response.get('normalizeData').get('normalizeStatus') == 1:
            title = title + ' *\n*' + response.get('normalizeData').get('normalizeMessage')

        md = tableToMarkdown(
            title,
            snx_ioc_cont,
            ['Value',
             'Type',
             'Verdict',
             'ScanID',
             'ThreatStatus',
             'ThreatName',
             'ThreatType',
             'FirstSeen',
             'LastSeen']
        )

        publish_md_and_ec(md, snx_ioc_cont, ec)

        if args.get('extended_info') == 'true' and response.get('swlData') is None:
            # Download Screenshot, HTML and Text Section
            if url_data.get('landingUrl') is None:
                if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
                    tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
                else:
                    tag = 'Scanned URL = {}'.format(url_data.get('url'))
            else:
                tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

            download_forensics_data(scanid=scanid, tag=tag, sc=True, html=True, txt=True)


def url_scan_sync_command():
    """
    Execute SlashNext's URL/scansync API against the requested URL scan sync command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'url' not in args:
        return_error('Missing required command argument "url", Please provide "url" and retry!')

    response = invoke_snx_api(api_type='url-scan-sync', url=args.get('url'), timeout=args.get('timeout'))

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and is taking longer than expected to complete.\n'
            'Please check back later using "snx-scan-report" command with Scan ID = {} or '
            'running the same "snx-url-scan-sync" command one more time.'.format(response.get('urlData').get('scanId')))
    elif response.get('errorNo') != 0:
        return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        url_data = response.get('urlData')
        scanid = url_data.get('scanId')
        snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)

        ec = {
            'SlashNext.IoC(val.Value == obj.Value)': snx_ioc_cont[0],
            'DBotScore': dbot_score_cont,
            'URL': url_cont
        }

        title = 'SlashNext Phishing Incident Response - URL Scan Sync\n'\
                '##### url = {}'.format(url_data.get('url'))

        if response.get('normalizeData').get('normalizeStatus') == 1:
            title = title + ' *\n*' + response.get('normalizeData').get('normalizeMessage')

        md = tableToMarkdown(
            title,
            snx_ioc_cont,
            ['Value',
             'Type',
             'Verdict',
             'ScanID',
             'ThreatStatus',
             'ThreatName',
             'ThreatType',
             'FirstSeen',
             'LastSeen']
        )

        publish_md_and_ec(md, snx_ioc_cont, ec)

        if args.get('extended_info') == 'true' and response.get('swlData') is None:
            # Download Screenshot, HTML and Text Section
            if url_data.get('landingUrl') is None:
                if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
                    tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
                else:
                    tag = 'Scanned URL = {}'.format(url_data.get('url'))
            else:
                tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

            download_forensics_data(scanid=scanid, tag=tag, sc=True, html=True, txt=True)


def scan_report_command():
    """
    Execute SlashNext's URL/scan API against the already requested URL scan command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'scanid' not in args:
        return_error('Missing required command argument "scanid", Please provide "scanid" and retry!')

    response = invoke_snx_api(api_type='get-url-scan', scanid=args.get('scanid'))

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "snx-scan-report" command with Scan ID = {}'.format(
                args.get('scanid')))
    elif response.get('errorNo') != 0:
        return_error('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        url_data = response.get('urlData')
        scanid = url_data.get('scanId')
        snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)

        ec = {
            'SlashNext.IoC(val.Value == obj.Value)': snx_ioc_cont[0],
            'DBotScore': dbot_score_cont,
            'URL': url_cont
        }

        title = 'SlashNext Phishing Incident Response - Scan Report\n'\
                '##### url = {}'.format(url_data.get('url'))

        if response.get('normalizeData').get('normalizeStatus') == 1:
            title = title + ' *\n*' + response.get('normalizeData').get('normalizeMessage')

        md = tableToMarkdown(
            title,
            snx_ioc_cont,
            ['Value',
             'Type',
             'Verdict',
             'ScanID',
             'ThreatStatus',
             'ThreatName',
             'ThreatType',
             'FirstSeen',
             'LastSeen']
        )

        publish_md_and_ec(md, snx_ioc_cont, ec)

        if args.get('extended_info') == 'true' and response.get('swlData') is None:
            # Download Screenshot, HTML and Text Section
            if url_data.get('landingUrl') is None:
                if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
                    tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
                else:
                    tag = 'Scanned URL = {}'.format(url_data.get('url'))
            else:
                tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

            download_forensics_data(scanid=scanid, tag=tag, sc=True, html=True, txt=True)


def download_screenshot_command():
    """
    Execute SlashNext's download/screenshot API against the already requested URL scan command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'scanid' not in args:
        return_error('Missing required command argument "scanid", Please provide "scanid" and retry!')

    response = invoke_snx_api(api_type='dl-screenshot', scanid=args.get('scanid'), resolution=args.get('resolution'))

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "snx-download-screenshot" command with Scan ID = {}'.format(
                args.get('scanid')))
    elif response.get('errorNo') != 0:
        demisto.results('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        sc_base64 = response.get('scData').get('scBase64')
        sc_data = base64.b64decode(sc_base64)

        sc_file = fileResult('snx_{}.jpeg'.format(args.get('scanid')), sc_data, entryTypes['image'])

        demisto.results({
            'Type': entryTypes['image'],
            'ContentsFormat': formats['text'],
            'Contents': 'Forensics: Webpage Screenshot for URL Scan ID = {}'.format(args.get('scanid')),
            'File': sc_file.get('File'),
            'FileID': sc_file.get('FileID')
        })


def download_html_command():
    """
    Execute SlashNext's download/HTML API against the already requested URL scan command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'scanid' not in args:
        return_error('Missing required command argument "scanid", Please provide "scanid" and retry!')

    response = invoke_snx_api(api_type='dl-html', scanid=args.get('scanid'))

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "snx-download-html" command with Scan ID = {}'.format(
                args.get('scanid')))
    elif response.get('errorNo') != 0:
        demisto.results('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        html_base64 = response.get('htmlData').get('htmlBase64')
        html_data = base64.b64decode(html_base64)

        html_file = fileResult('snx_{}.html'.format(args.get('scanid')), html_data, entryTypes['file'])

        demisto.results({
            'Type': entryTypes['file'],
            'ContentsFormat': formats['text'],
            'Contents': 'Forensics: Webpage HTML for URL Scan ID = {}'.format(args.get('scanid')),
            'File': html_file.get('File'),
            'FileID': html_file.get('FileID')
        })


def download_text_command():
    """
    Execute SlashNext's download/text API against the already requested URL scan command with the given parameters
    @:return: None
    """
    args = demisto.args()

    if 'scanid' not in args:
        return_error('Missing required command argument "scanid", Please provide "scanid" and retry!')

    response = invoke_snx_api(api_type='dl-text', scanid=args.get('scanid'))

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "snx-download-text" command with Scan ID = {}'.format(
                args.get('scanid')))
    elif response.get('errorNo') != 0:
        demisto.results('API Returned, "{}:{}"!'.format(response.get('errorNo'), response.get('errorMsg')))
    else:
        text_base64 = response.get('textData').get('textBase64')
        text_data = base64.b64decode(text_base64)

        text_file = fileResult('snx_{}.txt'.format(args.get('scanid')), text_data, entryTypes['file'])

        demisto.results({
            'Type': entryTypes['file'],
            'ContentsFormat': formats['text'],
            'Contents': 'Forensics: Webpage Rendered Text for URL Scan ID = {}'.format(args.get('scanid')),
            'File': text_file.get('File'),
            'FileID': text_file.get('FileID')
        })


def api_quota_command():
    """
    Execute SlashNext's API quota stats API for future API
    @:return: None
    """
    demisto.results('Coming Soon...')


''' EXECUTION '''


LOG('Command to be executed is %s.' % (demisto.command(),))

try:
    if demisto.command() == 'test-module':
        demisto.results(validate_snx_api_key())

    start_time = int(round(time.time() * 1000))

    if demisto.command() == 'snx-host-reputation':
        host_reputation_command()
    elif demisto.command() == 'snx-host-report':
        host_report_command()
    elif demisto.command() == 'snx-host-urls':
        host_urls_command()
    elif demisto.command() == 'snx-url-scan':
        url_scan_command()
    elif demisto.command() == 'snx-url-scan-sync':
        url_scan_sync_command()
    elif demisto.command() == 'snx-scan-report':
        scan_report_command()
    elif demisto.command() == 'snx-download-screenshot':
        download_screenshot_command()
    elif demisto.command() == 'snx-download-html':
        download_html_command()
    elif demisto.command() == 'snx-download-text':
        download_text_command()
    elif demisto.command() == 'snx-api-quota':
        api_quota_command()

    end_time = int(round(time.time() * 1000))
    demisto.results('Elapsed Time = {}ms'.format(end_time - start_time))

except Exception, e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)

finally:
    LOG('Command execution completed.')
