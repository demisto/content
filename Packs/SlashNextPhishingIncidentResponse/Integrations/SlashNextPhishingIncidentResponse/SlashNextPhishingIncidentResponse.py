import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import List, Dict
import requests
import base64

requests.packages.urllib3.disable_warnings()

"""
Created on August 1, 2019
Updated on April 2, 2020
Updated on September 24, 2020
Updated on August 7, 2021

@author: Saadat Abid
"""


''' GLOBAL VARS '''
AUTH_KEY = demisto.params().get('apikey')
BASE_API = demisto.params().get('apiurl', 'https://oti.slashnext.cloud/api')
if BASE_API.endswith('/'):
    BASE_API = BASE_API.strip('/')
VERIFY = not demisto.params().get('unsecure', False)

HOST_REPUTE_API = '/oti/v1/host/reputation'
URL_REPUTE_API = '/oti/v1/url/reputation'
URL_SCAN_API = '/oti/v1/url/scan'
URL_SCANSYNC_API = '/oti/v1/url/scansync'
HOST_REPORT_API = '/oti/v1/host/report'
DL_SC_API = '/oti/v1/download/screenshot'
DL_HTML_API = '/oti/v1/download/html'
DL_TEXT_API = '/oti/v1/download/text'
API_QUOTA = '/oti/v1/quota/status'


''' HELPERS FUNCTIONS '''


@logger
def http_request(endpoint, data, method='POST'):
    """
    Make the http request to SlashNext cloud API endpoint with the given API args
    :param endpoint: Corresponds to SlashNext cloud API to be invoked
    :param data: Parameter dictionary as part of data
    :param method: HTTP method to be used for API i.e. GET or POST
    :return: Response of the SlashNext web API in json format
    """
    url = BASE_API + endpoint
    data['authkey'] = AUTH_KEY

    response = requests.request(method, url=url, data=data, timeout=300, verify=VERIFY)
    if response.status_code == 200:
        try:
            return response.json()
        except Exception as e:
            return_error('Response JSON decoding failed due to {}'.format(str(e)))

    else:
        return_error('API Returned, {}:{}'.format(response.status_code, response.reason))


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
    :param ioc_type: IoC type, ip, domain or url
    :param verdict: Verdict by SlashNext OTI cloud
    :param threat_type: Threat type reported by SlashNext OTI cloud
    :return: Dbot score context dictionary, dbot standard context dictionary
    """
    dbot_score = get_dbot_score(verdict)

    dbot_score_cont = {
        'Indicator': indicator,
        'Type': ioc_type.lower(),
        'Vendor': 'SlashNext Phishing Incident Response',
        'Score': dbot_score
    }

    if ioc_type.lower() == 'ip':
        standard_cont = {
            'Address': indicator
        }
    elif ioc_type.lower() == 'domain':
        standard_cont = {
            'Name': indicator
        }
    else:
        standard_cont = {
            'Data': indicator
        }

    if dbot_score == 3:
        standard_cont['Malicious'] = {
            'Vendor': 'SlashNext Phishing Incident Response',
            'Description': 'Detected "{}" Activity'.format(threat_type)
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

    url_threat_data = url_data.get('threatData')
    snx_ioc_cont = {
        'Value': url_data.get('url'),
        'Type': 'Scanned URL',
        'Verdict': url_threat_data.get('verdict'),
        'ThreatStatus': url_threat_data.get('threatStatus'),
        'ThreatType': url_threat_data.get('threatType'),
        'ThreatName': url_threat_data.get('threatName'),
        'FirstSeen': url_threat_data.get('firstSeen'),
        'LastSeen': url_threat_data.get('lastSeen')
    }
    if is_scan is True:
        snx_ioc_cont['ScanID'] = url_data.get('scanId')

    dbot_score_cont, url_cont = get_dbot_std_context(
        url_data.get('url'), 'url',
        url_threat_data.get('verdict'),
        url_threat_data.get('threatType'))
    dbot_score_cont_list.append(dbot_score_cont)
    if url_cont is not None:
        url_cont_list.append(url_cont)

    if url_data.get('landingUrl') is None:
        if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
            dbot_final_score_cont, final_url_cont = get_dbot_std_context(
                url_data.get('finalUrl'), 'url',
                url_threat_data.get('verdict'),
                url_threat_data.get('threatType'))
            dbot_score_cont_list.append(dbot_final_score_cont)
            if final_url_cont is not None:
                url_cont_list.append(final_url_cont)

            snx_final_ioc_cont = {
                'Value': url_data.get('finalUrl'),
                'Type': 'Final URL',
                'Verdict': url_threat_data.get('verdict')
            }

            snx_ioc_cont['Final'] = snx_final_ioc_cont.copy()
            snx_ioc_cont_list.append(snx_ioc_cont)

            snx_final_ioc_cont['Value'] = '--------> {}'.format(url_data.get('finalUrl'))
            snx_ioc_cont_list.append(snx_final_ioc_cont)

        else:
            snx_ioc_cont_list.append(snx_ioc_cont)

    else:
        landing = url_data.get('landingUrl')
        landing_threat_data = landing.get('threatData')

        dbot_landing_score_cont, landing_url_cont = get_dbot_std_context(
            landing.get('url'), 'url',
            landing_threat_data.get('verdict'),
            landing_threat_data.get('threatType'))
        dbot_score_cont_list.append(dbot_landing_score_cont)
        if landing_url_cont is not None:
            url_cont_list.append(landing_url_cont)

        snx_landing_ioc_cont = {
            'Value': landing.get('url'),
            'Type': 'Redirected URL',
            'Verdict': landing_threat_data.get('verdict'),
            'ThreatStatus': landing_threat_data.get('threatStatus'),
            'ThreatType': landing_threat_data.get('threatType'),
            'ThreatName': landing_threat_data.get('threatName'),
            'FirstSeen': landing_threat_data.get('firstSeen'),
            'LastSeen': landing_threat_data.get('lastSeen')
        }
        if is_scan is True:
            snx_landing_ioc_cont['ScanID'] = landing.get('scanId')

        snx_ioc_cont['Landing'] = snx_landing_ioc_cont.copy()
        snx_ioc_cont_list.append(snx_ioc_cont)

        snx_landing_ioc_cont['Value'] = '--------> {}'.format(landing.get('url'))
        snx_ioc_cont_list.append(snx_landing_ioc_cont)

    return snx_ioc_cont_list, dbot_score_cont_list, url_cont_list


def download_forensics_data(scanid, tag, screenshot=False, html=False, txt=False):
    """
    Download the selected forensics data from SlashNext cloud
    :param scanid: Scan ID for which foresics data to download
    :param tag: String to tag the corresponding forensics data file
    :param screenshot: Holds true if screenshot is to be downloaded
    :param html: Holds true if the HTML is to be downloaded
    :param txt: Holds true if the text is to be downloaded
    :return: None
    """
    error_no = 0
    error_msg = 'Success'
    show_error_msg = True
    if screenshot is True:
        # Host Screenshot Section
        api_data = {
            'scanid': scanid,
            'resolution': 'medium'
        }
        response = http_request(endpoint=DL_SC_API, data=api_data)

        if response.get('errorNo') != 0:
            error_no = response.get('errorNo')
            error_msg = response.get('errorMsg')
        else:
            show_error_msg = False

            sc_base64 = response.get('scData').get('scBase64')
            sc_data = base64.b64decode(sc_base64)

            sc_file = fileResult('slashnext_{}.jpg'.format(scanid), sc_data, entryTypes['image'])

            demisto.results({
                'Type': entryTypes['image'],
                'ContentsFormat': formats['text'],
                'Contents': 'Forensics: Webpage Screenshot for the ' + tag,
                'File': sc_file.get('File'),
                'FileID': sc_file.get('FileID')
            })

    if html is True:
        # Host HTML Section
        api_data = {
            'scanid': scanid
        }
        response = http_request(endpoint=DL_HTML_API, data=api_data)

        if response.get('errorNo') == 0:
            show_error_msg = False

            html_base64 = response.get('htmlData').get('htmlBase64')
            html_data = base64.b64decode(html_base64)

            html_file = fileResult('slashnext_{}.html'.format(scanid), html_data, entryTypes['file'])

            demisto.results({
                'Type': entryTypes['file'],
                'ContentsFormat': formats['text'],
                'Contents': 'Forensics: Webpage HTML for the ' + tag,
                'File': html_file.get('File'),
                'FileID': html_file.get('FileID')
            })

    if txt is True:
        # Host Text Section
        api_data = {
            'scanid': scanid
        }
        response = http_request(endpoint=DL_TEXT_API, data=api_data)

        if response.get('errorNo') == 0:
            show_error_msg = False

            text_base64 = response.get('textData').get('textBase64')
            text_data = base64.b64decode(text_base64)

            text_file = fileResult('slashnext_{}.txt'.format(scanid), text_data, entryTypes['file'])

            demisto.results({
                'Type': entryTypes['file'],
                'ContentsFormat': formats['text'],
                'Contents': 'Forensics: Webpage Rendered Text for the ' + tag,
                'File': text_file.get('File'),
                'FileID': text_file.get('FileID')
            })

    # Show Error Message
    if show_error_msg is True and (screenshot is True or html is True or txt is True):
        demisto.results('API Returned, {}:{}'.format(error_no, error_msg))


''' COMMAND FUNCTIONS '''


def validate_snx_api_key():
    """
    Validate the provided SlashNext cloud API key and test connection, in case of any error exit the program
    @:return: None
    """
    api_data = {}   # type: Dict[str, str]
    response = http_request(endpoint=API_QUOTA, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return 'ok'


def ip_lookup(ip):
    """
    Execute SlashNext's host/reputation API against the requested IP address with the given parameters
    :param ip: IP address whose reputation needs to be fetched
    :return: Response of the SlashNext host/reputation API
    """
    # Create the required data dictionary for Host/Reputation
    api_data = {
        'host': ip
    }
    response = http_request(endpoint=HOST_REPUTE_API, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def ip_command():
    """
    Execute SlashNext's host/reputation API against the requested IP reputation command with the given parameters
    @:return: None
    """
    # 1. Get input host from Demisto
    ip = demisto.args().get('ip')
    if not is_ip_valid(ip):
        return_error('Invalid IP address, Please retry with a valid IP address')
    # 2. Get the host reputation from SlashNext API
    response = ip_lookup(ip=ip)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    dbot_score_cont, ip_cont = get_dbot_std_context(
        ip, 'IP', response.get('threatData').get('verdict'), response.get('threatData').get('threatType'))

    snx_ioc_cont = get_snx_host_ioc_context(ip, 'IP', response.get('threatData'))

    ec = {
        'SlashNext.IP(val.Value === obj.Value)': snx_ioc_cont,
        'DBotScore': dbot_score_cont,
        'IP': ip_cont
    }

    title = 'SlashNext Phishing Incident Response - IP Lookup\n' \
            '##### ip = {}'.format(ip)

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

    return_outputs(md, ec, snx_ioc_cont)


def domain_lookup(domain):
    """
    Execute SlashNext's host/reputation API against the requested domain with the given parameters
    :param domain: Domain whose reputation needs to be fetched
    :return: Response of the SlashNext host/reputation API
    """
    # Create the required data dictionary for Host/Reputation
    api_data = {
        'host': domain
    }
    response = http_request(endpoint=HOST_REPUTE_API, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def domain_command():
    """
    Execute SlashNext's host/reputation API against the requested domain reputation command with the given parameters
    @:return: None
    """
    # 1. Get input host from Demisto
    domain = demisto.args().get('domain')
    # 2. Get the host reputation from SlashNext API
    response = domain_lookup(domain=domain)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    dbot_score_cont, domain_cont = get_dbot_std_context(
        domain, 'Domain', response.get('threatData').get('verdict'), response.get('threatData').get('threatType'))

    snx_ioc_cont = get_snx_host_ioc_context(domain, 'Domain', response.get('threatData'))

    ec = {
        'SlashNext.Domain(val.Value === obj.Value)': snx_ioc_cont,
        'DBotScore': dbot_score_cont,
        'Domain': domain_cont
    }

    domain = domain.encode('idna')

    title = 'SlashNext Phishing Incident Response - Domain Lookup\n' \
            '##### domain = {}'.format(domain.decode())

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

    return_outputs(md, ec, snx_ioc_cont)


def url_lookup(url):
    """
    Execute SlashNext's url/reputation API against the requested url with the given parameters
    :param url: Url whose reputation needs to be fetched
    :return: Response of the SlashNext url/reputation API
    """
    # Create the required data dictionary for Url/Reputation
    api_data = {
        'url': url
    }
    response = http_request(endpoint=URL_REPUTE_API, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def url_command():
    """
    Execute SlashNext's url/reputation API against the requested url reputation command with the given parameters
    @:return: None
    """
    # 1. Get input url from Demisto
    url = demisto.args().get('url')
    # 2. Get the url reputation from SlashNext API
    response = url_lookup(url=url)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    url_data = response.get('urlData')

    snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data)

    ec = {
        'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont[0],
        'DBotScore': dbot_score_cont,
        'URL': url_cont
    }

    title = 'SlashNext Phishing Incident Response - URL Lookup\n'\
            '##### url = {}'.format(url_data.get('url'))

    if response.get('normalizeData').get('normalizeStatus') == 1:
        title += ' *\n*' + response.get('normalizeData').get('normalizeMessage')

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

    return_outputs(md, ec, snx_ioc_cont)


def host_reputation(host):
    """
    Execute SlashNext's host/reputation API against the requested host with the given parameters
    :param host: Host whose reputation needs to be fetched
    :return: Response of the SlashNext host/reputation API
    """
    # Create the required data dictionary for Host/Reputation
    api_data = {
        'host': host
    }
    response = http_request(endpoint=HOST_REPUTE_API, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def host_reputation_command():
    """
    Execute SlashNext's host/reputation API against the requested host reputation command with the given parameters
    @:return: None
    """
    # 1. Get input host from Demisto
    host = demisto.args().get('host')
    # 2. Get the host reputation from SlashNext API
    response = host_reputation(host=host)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    ioc_type = 'IP' if is_ip_valid(host) else 'Domain'

    dbot_score_cont, host_cont = get_dbot_std_context(
        host, ioc_type, response.get('threatData').get('verdict'), response.get('threatData').get('threatType'))

    snx_ioc_cont = get_snx_host_ioc_context(host, ioc_type, response.get('threatData'))

    ec = {
        'SlashNext.{}(val.Value === obj.Value)'.format(ioc_type): snx_ioc_cont,
        'DBotScore': dbot_score_cont,
        ioc_type: host_cont
    }

    host = host.encode('idna')

    title = 'SlashNext Phishing Incident Response - Host Reputation\n' \
            '##### host = {}'.format(host.decode())

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

    return_outputs(md, ec, snx_ioc_cont)


def host_report_command():
    """
    Execute SlashNext's host/reputation, host/report, url/scansync, download/screenshot, download/html and download/text
    APIs against the requested host report command with given parameters
    @:return: None
    """
    # 1. Get input host from Demisto
    host = demisto.args().get('host')
    # 2(i). Get the host reputation from SlashNext API
    response = host_reputation(host=host)
    if response.get('errorNo') != 0:
        return
    # 3(i). Parse and format the response
    ioc_type = 'IP' if is_ip_valid(host) else 'Domain'

    dbot_score_cont, host_cont = get_dbot_std_context(
        host, ioc_type, response.get('threatData').get('verdict'), response.get('threatData').get('threatType'))

    snx_ioc_cont = get_snx_host_ioc_context(host, ioc_type, response.get('threatData'))

    ec = {
        'SlashNext.{}(val.Value === obj.Value)'.format(ioc_type): snx_ioc_cont,
        'DBotScore': dbot_score_cont,
        ioc_type: host_cont
    }

    enc_host = host.encode('idna')

    title = 'SlashNext Phishing Incident Response - Host Report\n'\
            '##### host = {}'.format(enc_host.decode())

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

    return_outputs(md, ec, snx_ioc_cont)

    # In case host is Unrated, the command execution is completed else continue with host report
    if response.get('threatData').get('verdict').startswith('Unrated'):
        return

    # 2(ii). Get the host report from SlashNext API
    response = host_urls(host=host, limit=1)
    if response.get('errorNo') != 0:
        return
    # 3(ii). Parse and format the response
    url_data = response.get('urlDataList')[0]
    scanid = url_data.get('scanId')

    if scanid == 'N/A':
        # 2(iii). Get the url scan sync from SlashNext API
        response = url_scan_sync(url=url_data.get('url'), timeout=60)
        if response.get('errorNo') != 0:
            return
        # 3(iii). Parse and format the response
        url_data = response.get('urlData')
        scanid = url_data.get('scanId')

        snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)
    else:
        snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)

    ec = {
        'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont[0],
        'DBotScore': dbot_score_cont,
        'URL': url_cont
    }

    enc_host = host.encode('idna')

    title = 'SlashNext Phishing Incident Response - Latest Scanned URL\n' \
            '##### host = {}'.format(enc_host.decode())

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

    return_outputs(md, ec, snx_ioc_cont)

    # Download Screenshot, HTML and Text Section
    if url_data.get('landingUrl') is None:
        if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
            tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
        else:
            tag = 'Scanned URL = {}'.format(url_data.get('url'))
    else:
        tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

    if response.get('swlData') is None:
        download_forensics_data(scanid=scanid, tag=tag, screenshot=True, html=True, txt=True)


def host_urls(host, limit):
    """
    Execute SlashNext's host/report API against the requested host urls with the given parameters
    :param host: Host whose related/associated URLs to be fetched
    :param limit: Number of related URLs to be fetched
    :return: Response of the SlashNext host/report API
    """
    # Create the required data dictionary for Host/Report
    api_data = {
        'host': host,
        'page': 1,
        'rpp': limit
    }
    response = http_request(endpoint=HOST_REPORT_API, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def host_urls_command():
    """
    Execute SlashNext's host/report API against the requested host urls command with the given parameters
    @:return: None
    """
    # 1. Get input host and limit from Demisto
    host = demisto.args().get('host')
    limit = demisto.args().get('limit')
    # 2. Get the host report from SlashNext API
    response = host_urls(host=host, limit=limit)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    snx_ioc_cont_list = []       # type: List[Dict[str, str]]
    dbot_score_cont_list = []    # type: List[Dict[str, str]]
    url_cont_list = []           # type: List[Dict[str, str]]
    snx_ec_cont_list = []        # type: List[Dict[str, str]]
    for url_data in response.get('urlDataList'):
        if url_data.get('threatData').get('verdict').startswith('Unrated') is False:
            snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)
            snx_ioc_cont_list.extend(snx_ioc_cont)
            dbot_score_cont_list.extend(dbot_score_cont)
            url_cont_list.extend(url_cont)
            snx_ec_cont_list.append(snx_ioc_cont[0])

    ec = {}    # type: Dict[str, List[Dict[str, str]]]
    if response.get('urlDataList')[0].get('threatData').get('verdict').startswith('Unrated') is False:
        ec = {
            'SlashNext.URL(val.Value === obj.Value)': snx_ec_cont_list,
            'DBotScore': dbot_score_cont_list,
            'URL': url_cont_list
        }

    host = host.encode('idna')

    title = 'SlashNext Phishing Incident Response - Host URLs\n' \
            '##### host = {}'.format(host.decode())

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

    return_outputs(md, ec, snx_ioc_cont_list)


def url_reputation(url):
    """
    Execute SlashNext's url/reputation API against the requested url with the given parameters
    :param url: Url whose reputation needs to be fetched
    :return: Response of the SlashNext url/reputation API
    """
    # Create the required data dictionary for Url/Reputation
    api_data = {
        'url': url
    }
    response = http_request(endpoint=URL_REPUTE_API, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def url_reputation_command():
    """
    Execute SlashNext's url/reputation API against the requested url reputation command with the given parameters
    @:return: None
    """
    # 1. Get input url from Demisto
    url = demisto.args().get('url')
    # 2. Get the url reputation from SlashNext API
    response = url_reputation(url=url)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    url_data = response.get('urlData')

    snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data)

    ec = {
        'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont[0],
        'DBotScore': dbot_score_cont,
        'URL': url_cont
    }

    title = 'SlashNext Phishing Incident Response - URL Reputation\n'\
            '##### url = {}'.format(url_data.get('url'))

    if response.get('normalizeData').get('normalizeStatus') == 1:
        title += ' *\n*' + response.get('normalizeData').get('normalizeMessage')

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

    return_outputs(md, ec, snx_ioc_cont)


def url_scan(url):
    """
    Execute SlashNext's url/scan API against the requested URL scan with the given parameters
    :param url: URL to be scanned
    :return: Response of the SlashNext url/scan API
    """
    # Create the required data dictionary for URL/Scan
    api_data = {
        'url': url
    }
    response = http_request(endpoint=URL_SCAN_API, data=api_data)

    if response.get('errorNo') == 1:
        url_threat_data = response.get('urlData').get('threatData')
        snx_ioc_cont = {
            'Value': url,
            'Type': 'Scanned URL',
            'Verdict': url_threat_data.get('verdict'),
            'ThreatStatus': url_threat_data.get('threatStatus'),
            'ThreatType': url_threat_data.get('threatType'),
            'ThreatName': url_threat_data.get('threatName'),
            'FirstSeen': url_threat_data.get('firstSeen'),
            'LastSeen': url_threat_data.get('lastSeen'),
            'ScanID': response.get('urlData').get('scanId')
        }
        ec = {
            'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont
        }
        md = '### SlashNext Phishing Incident Response - URL Scan\n' \
             '##### url = {}\n' \
             'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'\
             'Please check back later using "slashnext-scan-report" command with Scan ID = {} or running the same ' \
             '"slashnext-url-scan" command one more time.'.format(url, response.get('urlData').get('scanId'))
        return_outputs(md, ec, response)
    elif response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def url_scan_command():
    """
    Execute SlashNext's URL/scan API against the requested URL scan command with the given parameters
    @:return: None
    """
    # 1. Get input url and extended_info from Demisto
    url = demisto.args().get('url')
    extended_info = demisto.args().get('extended_info')
    # 2. Get the url scan from SlashNext API
    response = url_scan(url=url)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    url_data = response.get('urlData')
    scanid = url_data.get('scanId')

    snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)

    ec = {
        'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont[0],
        'DBotScore': dbot_score_cont,
        'URL': url_cont
    }

    title = 'SlashNext Phishing Incident Response - URL Scan\n'\
            '##### url = {}'.format(url_data.get('url'))

    if response.get('normalizeData').get('normalizeStatus') == 1:
        title += ' *\n*' + response.get('normalizeData').get('normalizeMessage')

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

    return_outputs(md, ec, snx_ioc_cont)

    if extended_info == 'true' and response.get('swlData') is None:
        # Download Screenshot, HTML and Text Section
        if url_data.get('landingUrl') is None:
            if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
                tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
            else:
                tag = 'Scanned URL = {}'.format(url_data.get('url'))
        else:
            tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

        download_forensics_data(scanid=scanid, tag=tag, screenshot=True, html=True, txt=True)


def url_scan_sync(url, timeout):
    """
    Execute SlashNext's url/scansync API against the requested URL scan sync with the given parameters
    :param url: URL to be scanned
    :param timeout: Timeout value in seconds
    :return: Response of the SlashNext url/scansync API
    """
    # Create the required data dictionary for URL/ScanSync
    api_data = {
        'url': url,
        'timeout': timeout
    }
    response = http_request(endpoint=URL_SCANSYNC_API, data=api_data)

    if response.get('errorNo') == 1:
        url_threat_data = response.get('urlData').get('threatData')
        snx_ioc_cont = {
            'Value': url,
            'Type': 'Scanned URL',
            'Verdict': url_threat_data.get('verdict'),
            'ThreatStatus': url_threat_data.get('threatStatus'),
            'ThreatType': url_threat_data.get('threatType'),
            'ThreatName': url_threat_data.get('threatName'),
            'FirstSeen': url_threat_data.get('firstSeen'),
            'LastSeen': url_threat_data.get('lastSeen'),
            'ScanID': response.get('urlData').get('scanId')
        }
        ec = {
            'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont
        }
        md = '### SlashNext Phishing Incident Response - URL Scan Sync\n' \
             '##### url = {}\n' \
             'Your Url Scan request is submitted to the cloud and is taking longer than expected to complete.\n' \
             'Please check back later using "slashnext-scan-report" command with Scan ID = {} or running the same ' \
             '"slashnext-url-scan-sync" command one more time.'.format(url, response.get('urlData').get('scanId'))
        return_outputs(md, ec, response)
    elif response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def url_scan_sync_command():
    """
    Execute SlashNext's url/scansync API against the requested URL scan sync command with the given parameters
    @:return: None
    """
    # 1. Get input url, extended_info and timeout from Demisto
    url = demisto.args().get('url')
    timeout = demisto.args().get('timeout')
    extended_info = demisto.args().get('extended_info')
    # 2. Get the url scan sync from SlashNext API
    response = url_scan_sync(url=url, timeout=timeout)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    url_data = response.get('urlData')
    scanid = url_data.get('scanId')

    snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)

    ec = {
        'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont[0],
        'DBotScore': dbot_score_cont,
        'URL': url_cont
    }

    title = 'SlashNext Phishing Incident Response - URL Scan Sync\n'\
            '##### url = {}'.format(url_data.get('url'))

    if response.get('normalizeData').get('normalizeStatus') == 1:
        title += ' *\n*' + response.get('normalizeData').get('normalizeMessage')

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

    return_outputs(md, ec, snx_ioc_cont)

    if extended_info == 'true' and response.get('swlData') is None:
        # Download Screenshot, HTML and Text Section
        if url_data.get('landingUrl') is None:
            if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
                tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
            else:
                tag = 'Scanned URL = {}'.format(url_data.get('url'))
        else:
            tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

        download_forensics_data(scanid=scanid, tag=tag, screenshot=True, html=True, txt=True)


def scan_report(scanid):
    """
    Execute SlashNext's url/scan API against the already requested URL scan with the given parameters
    :param scanid: Scan ID returned by a SlashNext API earlier as a result of a scan request
    :return: Response of the SlashNext url/scan API
    """
    # Create the required data dictionary for URL/Scan
    api_data = {
        'scanid': scanid
    }
    response = http_request(endpoint=URL_SCAN_API, data=api_data)

    if response.get('errorNo') == 1:
        md = '### SlashNext Phishing Incident Response - Scan Report\n' \
             '##### scanid = {}\n' \
             'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n' \
             'Please check back later using "slashnext-scan-report" command with Scan ID = {}'.format(scanid, scanid)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': response,
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown']
        })
    elif response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def scan_report_command():
    """
    Execute SlashNext's url/scan API against the already requested URL scan command with the given parameters
    @:return: None
    """
    # 1. Get input scan id and extended_info flag from Demisto
    scanid = demisto.args().get('scanid')
    extended_info = demisto.args().get('extended_info')
    # 2. Get the scan report from SlashNext API
    response = scan_report(scanid=scanid)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    url_data = response.get('urlData')
    scanid = url_data.get('scanId')

    snx_ioc_cont, dbot_score_cont, url_cont = get_snx_url_ioc_context(url_data, is_scan=True)

    ec = {
        'SlashNext.URL(val.Value === obj.Value)': snx_ioc_cont[0],
        'DBotScore': dbot_score_cont,
        'URL': url_cont
    }

    title = 'SlashNext Phishing Incident Response - Scan Report\n'\
            '##### url = {}'.format(url_data.get('url'))

    if response.get('normalizeData').get('normalizeStatus') == 1:
        title += ' *\n*' + response.get('normalizeData').get('normalizeMessage')

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

    return_outputs(md, ec, snx_ioc_cont)

    if extended_info == 'true' and response.get('swlData') is None:
        # Download Screenshot, HTML and Text Section
        if url_data.get('landingUrl') is None:
            if url_data.get('finalUrl') is not None and url_data.get('finalUrl') != 'N/A':
                tag = 'Final URL = {}'.format(url_data.get('finalUrl'))
            else:
                tag = 'Scanned URL = {}'.format(url_data.get('url'))
        else:
            tag = 'Redirected URL = {}'.format(url_data.get('landingUrl').get('url'))

        download_forensics_data(scanid=scanid, tag=tag, screenshot=True, html=True, txt=True)


def download_screenshot(scanid, resolution='high'):
    """
    Execute SlashNext's download/screenshot API against the already requested URL scan with the given parameters
    :param scanid: Scan ID returned by a SlashNext API earlier as a result of a scan request
    :param resolution: Desired resolution of the screenshot. Currently supported values are 'high' and 'medium'
    :return: Response of the SlashNext download/screenshot API
    """
    # Create the required data dictionary for Download/Screenshot
    api_data = {
        'scanid': scanid,
        'resolution': resolution
    }
    response = http_request(endpoint=DL_SC_API, data=api_data)

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "slashnext-download-screenshot" command with Scan ID = {}'.format(scanid))
    elif response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def download_screenshot_command():
    """
    Execute SlashNext's download/screenshot API against the already requested URL scan command with the given parameters
    @:return: None
    """
    # 1. Get input scan id and resolution from Demisto
    scanid = demisto.args().get('scanid')
    resolution = demisto.args().get('resolution')
    # 2. Get the forensic webpage screenshot from SlashNext API
    response = download_screenshot(scanid=scanid, resolution=resolution)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    sc_base64 = response.get('scData').get('scBase64')
    sc_data = base64.b64decode(sc_base64)

    sc_file = fileResult('slashnext_{}.jpg'.format(scanid), sc_data, entryTypes['image'])

    demisto.results({
        'Type': entryTypes['image'],
        'ContentsFormat': formats['text'],
        'Contents': 'Forensics: Webpage Screenshot for URL Scan ID = {}'.format(scanid),
        'File': sc_file.get('File'),
        'FileID': sc_file.get('FileID')
    })


def download_html(scanid):
    """
    Execute SlashNext's download/html API against the already requested URL scan with the given parameters
    :param scanid: Scan ID returned by a SlashNext API earlier as a result of a scan request
    :return: Response of the SlashNext download/html API
    """
    # Create the required data dictionary for Download/HTML
    api_data = {
        'scanid': scanid
    }
    response = http_request(endpoint=DL_HTML_API, data=api_data)

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "slashnext-download-html" command with Scan ID = {}'.format(scanid))
    elif response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def download_html_command():
    """
    Execute SlashNext's download/HTML API against the already requested URL scan command with the given parameters
    @:return: None
    """
    # 1. Get input scan id from Demisto
    scanid = demisto.args().get('scanid')
    # 2. Get the forensic webpage HTML from SlashNext API
    response = download_html(scanid=scanid)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    html_base64 = response.get('htmlData').get('htmlBase64')
    html_data = base64.b64decode(html_base64)

    html_file = fileResult('slashnext_{}.html'.format(scanid), html_data, entryTypes['file'])

    demisto.results({
        'Type': entryTypes['file'],
        'ContentsFormat': formats['text'],
        'Contents': 'Forensics: Webpage HTML for URL Scan ID = {}'.format(scanid),
        'File': html_file.get('File'),
        'FileID': html_file.get('FileID')
    })


def download_text(scanid):
    """
    Execute SlashNext's download/text API against the already requested URL scan with the given parameters
    :param scanid: Scan ID returned by a SlashNext API earlier as a result of a scan request
    :return: Response of the SlashNext download/text API
    """
    # Create the required data dictionary for Download/Text
    api_data = {
        'scanid': scanid
    }
    response = http_request(endpoint=DL_TEXT_API, data=api_data)

    if response.get('errorNo') == 1:
        demisto.results(
            'Your Url Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'
            'Please check back later using "slashnext-download-text" command with Scan ID = {}'.format(scanid))
    elif response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def download_text_command():
    """
    Execute SlashNext's download/text API against the already requested URL scan command with the given parameters
    @:return: None
    """
    # 1. Get input scan id from Demisto
    scanid = demisto.args().get('scanid')
    # 2. Get the forensic webpage text from SlashNext API
    response = download_text(scanid=scanid)
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    text_base64 = response.get('textData').get('textBase64')
    text_data = base64.b64decode(text_base64)

    text_file = fileResult('slashnext_{}.txt'.format(scanid), text_data, entryTypes['file'])

    demisto.results({
        'Type': entryTypes['file'],
        'ContentsFormat': formats['text'],
        'Contents': 'Forensics: Webpage Rendered Text for URL Scan ID = {}'.format(scanid),
        'File': text_file.get('File'),
        'FileID': text_file.get('FileID')
    })


def api_quota():
    """
    Execute SlashNext's quota/status to get the quota status information
    :return: Response of the SlashNext quota/status API
    """
    # Create the required data dictionary for Quota/Status
    api_data = {}   # type: Dict[str, str]
    response = http_request(endpoint=API_QUOTA, data=api_data)

    if response.get('errorNo') != 0:
        return_error('API Returned, {}:{}'.format(response.get('errorNo'), response.get('errorMsg')))

    return response


def api_quota_command():
    """
    Execute SlashNext's quota/status to get the quota status information
    @:return: None
    """
    # 1. There is no parameter input required from Demisto
    # 2. Get the quota status info from SlashNext API
    response = api_quota()
    if response.get('errorNo') != 0:
        return
    # 3. Parse and format the response
    quota_data = response.get('quotaDetails')

    title = 'SlashNext Phishing Incident Response - API Quota\n'\
            '##### Note: {}'.format(quota_data.get('note'))

    snx_ioc_cont = {
        'LicensedQuota': quota_data.get('licensedQuota'),
        'RemainingQuota': quota_data.get('remainingQuota'),
        'ExpirationDate': quota_data.get('expiryDate'),
        'IsExpired': quota_data.get('isExpired')
    }

    ec = {
        'SlashNext.Quota(val.Value === obj.Value)': snx_ioc_cont
    }

    md = tableToMarkdown(
        title,
        snx_ioc_cont,
        ['LicensedQuota',
         'RemainingQuota',
         'ExpirationDate']
    )

    return_outputs(md, ec, snx_ioc_cont)


''' EXECUTION '''


def main():
    LOG('Command to be executed is {}.'.format(demisto.command()))
    handle_proxy()
    try:
        if demisto.command() == 'test-module':
            demisto.results(validate_snx_api_key())

        if demisto.command() == 'ip':
            ip_command()
        elif demisto.command() == 'domain':
            domain_command()
        elif demisto.command() == 'url':
            url_command()
        elif demisto.command() == 'slashnext-host-reputation':
            host_reputation_command()
        elif demisto.command() == 'slashnext-host-report':
            host_report_command()
        elif demisto.command() == 'slashnext-host-urls':
            host_urls_command()
        elif demisto.command() == 'slashnext-url-reputation':
            url_reputation_command()
        elif demisto.command() == 'slashnext-url-scan':
            url_scan_command()
        elif demisto.command() == 'slashnext-url-scan-sync':
            url_scan_sync_command()
        elif demisto.command() == 'slashnext-scan-report':
            scan_report_command()
        elif demisto.command() == 'slashnext-download-screenshot':
            download_screenshot_command()
        elif demisto.command() == 'slashnext-download-html':
            download_html_command()
        elif demisto.command() == 'slashnext-download-text':
            download_text_command()
        elif demisto.command() == 'slashnext-api-quota':
            api_quota_command()

    except Exception as e:
        return_error(str(e))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
