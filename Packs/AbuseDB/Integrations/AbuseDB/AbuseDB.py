import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import requests
import os
import csv

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''
VERBOSE = True
SERVER = demisto.params().get('server')
if not SERVER.endswith('/'):
    SERVER += '/'
API_KEY = demisto.params().get('apikey')
MAX_AGE = demisto.params().get('days')
THRESHOLD = demisto.params().get('threshold')
INSECURE = demisto.params().get('insecure')
TEST_IP = "127.0.0.2"
BLACKLIST_SCORE = 3
CHECK_CMD = "check"
CHECK_BLOCK_CMD = "check-block"
REPORT_CMD = "report"
BLACKLIST_CMD = 'blacklist'
ANALYSIS_TITLE = "AbuseIPDB Analysis"
BLACKLIST_TITLE = "AbuseIPDB Blacklist"
REPORT_SUCCESS = "IP address reported successfully."

API_QUOTA_REACHED_MESSAGE = 'Too many requests (possibly bad API key). Status code: 429'

HEADERS = {
    'Key': API_KEY,
    'Accept': 'application/json'
}

PROXY = demisto.params().get('proxy')
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

CATEGORIES_NAME = {
    1: 'DNS_Compromise',
    2: 'DNS_Poisoning',
    3: 'Frad_Orders',
    4: 'DDoS_Attack',
    5: 'FTP_Brute-Force',
    6: 'Ping of Death',
    7: 'Phishing',
    8: 'Fraud VoIP',
    9: 'Open_Proxy',
    10: 'Web_Spam',
    11: 'Email_Spam',
    12: 'Blog_Spam',
    13: 'VPN IP',
    14: 'Port_Scan',
    15: 'Hacking',
    16: 'SQL Injection',
    17: 'Spoofing',
    18: 'Brute_Force',
    19: 'Bad_Web_Bot',
    20: 'Exploited_Host',
    21: 'Web_App_Attack',
    22: 'SSH',
    23: 'IoT_Targeted'
}

CATEGORIES_ID = {
    "Frad_Orders": "3",
    "DDoS_Attack": "4",
    "FTP_Brute": "5",
    "Ping of Death": "6",
    "Phishing": "7",
    "Fraud VoIP": "8",
    "Open_Proxy": "9",
    "Web_Spam": "10",
    "Email_Spam": "11",
    "Blog_Spam": "12",
    "VPN IP": "13",
    "Port_Scan": "14",
    "Hacking": "15",
    "SQL Injection": "16",
    "Spoofing": "17",
    "Brute_Force": "18",
    "Bad_Web_Bot": "19",
    "Exploited_Host": "20",
    "Web_App_Attack": "21",
    "SSH": "22",
    "IoT_Targeted": "23"
}

session = requests.session()


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, headers=HEADERS, threshold=THRESHOLD):
    LOG('running request with url=%s' % (SERVER + url_suffix))
    try:
        analysis = session.request(method, SERVER + url_suffix, headers=headers, params=params, verify=not INSECURE)

        if analysis.status_code not in {200, 204, 429}:
            return_error('Bad connection attempt. Status code: ' + str(analysis.status_code))
        if analysis.status_code == 429:
            if demisto.params().get('disregard_quota'):
                return API_QUOTA_REACHED_MESSAGE
            else:
                return_error(API_QUOTA_REACHED_MESSAGE)

        return REPORT_SUCCESS if url_suffix == REPORT_CMD else analysis.json()
    except Exception as e:
        LOG(e)
        return_error(e.message)


def analysis_to_entry(info, threshold=THRESHOLD, verbose=VERBOSE):
    if not isinstance(info, list):
        info = [info]

    context_ip_generic, context_ip, human_readable, dbot_scores, timeline = [], [], [], [], []
    for analysis in info:
        ip_ec = {
            "Address": analysis.get("ipAddress"),
            "Geo": {"Country": analysis.get("countryName") or analysis.get("countryCode")}
        }
        abuse_ec = {
            "IP": {
                "Address": analysis.get("ipAddress"),
                "Geo": {"Country": analysis.get("countryName") or analysis.get("countryCode")},
                'AbuseConfidenceScore': analysis.get('abuseConfidenceScore'),
                "TotalReports": analysis.get("totalReports") or analysis.get("numReports") or "0"
            }
        }

        if verbose:
            reports = sum([report_dict.get("categories") for report_dict in analysis.get("reports")], [])  # type: list
            categories = set(filter(lambda category_id: category_id in CATEGORIES_NAME.keys(), reports))
            abuse_ec["IP"]["Reports"] = {CATEGORIES_NAME[c]: reports.count(c) for c in categories}

        human_readable.append(abuse_ec['IP'])

        dbot_score = getDBotScore(analysis, threshold)
        if dbot_score == 3:
            ip_ec["Malicious"] = abuse_ec["IP"]["Malicious"] = {
                'Vendor': "AbuseIPDB",
                'Detections': 'The address was reported as Malicious by AbuseIPDB.',
                'Description': 'The address was reported as Malicious by AbuseIPDB.'

            }
        dbot_scores.append({
            "Score": dbot_score,
            "Vendor": "AbuseIPDB",
            "Indicator": analysis.get("ipAddress"),
            "Type": "ip"
        })
        context_ip.append(abuse_ec)
        context_ip_generic.append(ip_ec)

        ip_address = analysis.get('ipAddress')
        ip_rep = scoreToReputation(dbot_score)
        timeline.append({
            'Value': ip_address,
            'Message': 'AbuseIPDB marked the indicator "{}" as *{}*'.format(ip_address, ip_rep),
            'Category': 'Integration Update'
        })

    return createEntry(context_ip, context_ip_generic, human_readable, dbot_scores, timeline, title=ANALYSIS_TITLE)


def blacklist_to_entry(data, saveToContext):
    if not isinstance(data, list):
        data = [data]

    ips = [d.get("ipAddress") for d in data]
    context = {"Blacklist": ips}
    temp = demisto.uniqueFile()
    with open(demisto.investigation()['id'] + '_' + temp, 'wb') as f:
        wr = csv.writer(f, quoting=csv.QUOTE_ALL)
        for ip in ips:
            wr.writerow([ip])
    entry = {
        'HumanReadable': '',
        'Contents': ips,
        'ContentsFormat': formats['json'],
        'Type': entryTypes['file'],
        'File': "Blacklist.csv",
        'FileID': temp,
        'EntryContext': {'AbuseIPDB': createContext(context if saveToContext else None, removeNull=True)}
    }
    return entry


def getDBotScore(analysis, threshold=THRESHOLD):
    total_reports = analysis.get("totalReports") or analysis.get("numReports") or 0
    abuse_score = int(analysis.get("abuseConfidenceScore"))
    dbot_score = 0 if total_reports == 0 else 1 if abuse_score < 20 else 2 if abuse_score < int(threshold) else 3
    return dbot_score


def createEntry(context_ip, context_ip_generic, human_readable, dbot_scores, timeline, title):
    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': context_ip,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, human_readable, removeNull=True),
        'EntryContext': {
            'IP(val.Address && val.Address == obj.Address)': createContext(context_ip_generic, removeNull=True),
            'AbuseIPDB(val.IP.Address && val.IP.Address == obj.IP.Address)': createContext(context_ip, removeNull=True),
            'DBotScore': createContext(dbot_scores, removeNull=True)
        },
        'IndicatorTimeline': timeline
    }
    return entry


''' FUNCTIONS '''


def check_ip_command(ip, days=MAX_AGE, verbose=VERBOSE, threshold=THRESHOLD):
    params = {
        "maxAgeInDays": days
    }
    if verbose:
        params['verbose'] = "verbose"
    ip_list = argToList(ip)
    entry_list = []
    for current_ip in ip_list:
        params["ipAddress"] = current_ip
        analysis = http_request("GET", url_suffix=CHECK_CMD, params=params)
        if analysis == API_QUOTA_REACHED_MESSAGE:
            continue
        analysis_data = analysis.get("data")
        entry_list.append(analysis_to_entry(analysis_data, verbose=verbose, threshold=threshold))
    return entry_list


def check_block_command(network, limit, days=MAX_AGE, threshold=THRESHOLD):
    params = {
        "network": network,
        "maxAgeInDays": days
    }
    analysis = http_request("GET", url_suffix=CHECK_BLOCK_CMD, params=params).get("data").get("reportedAddress")
    return analysis_to_entry(analysis[:int(limit) if limit.isdigit() else 40], verbose=False, threshold=threshold)


def report_ip_command(ip, categories):
    params = {
        "ip": ip,
        "categories": ",".join([CATEGORIES_ID[c] if c in CATEGORIES_ID else c for c in categories.split()])
    }
    analysis = http_request("POST", url_suffix=REPORT_CMD, params=params)
    return analysis


def get_blacklist_command(limit, days, saveToContext):
    params = {
        'maxAgeInDays': days,
        "limit": limit
    }
    analysis = http_request("GET", url_suffix=BLACKLIST_CMD, params=params)
    return analysis if type(analysis) is str else blacklist_to_entry(analysis.get("data"), saveToContext)


def test_module():
    try:
        check_ip_command(ip=TEST_IP, verbose=False)
    except Exception as e:
        LOG(e)
        return_error(e.message)
    demisto.results('ok')


def get_categories_command():
    categories = {str(key): value for key, value in CATEGORIES_NAME.items()}
    entry = {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': categories,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("AbuseIPDB report categories", categories, removeNull=True),
        'EntryContext': {'AbuseIPDB.Categories(val && val == obj)': createContext(categories, removeNull=True),
                         }
    }
    return entry


try:
    if demisto.command() == 'test-module':
        # Tests connectivity and credentails on login
        test_module()
    elif demisto.command() == 'ip':
        demisto.results(check_ip_command(**demisto.args()))
    elif demisto.command() == 'abuseipdb-check-cidr-block':
        demisto.results(check_block_command(**demisto.args()))
    elif demisto.command() == 'abuseipdb-report-ip':
        demisto.results(report_ip_command(**demisto.args()))
    elif demisto.command() == 'abuseipdb-get-blacklist':
        demisto.results(get_blacklist_command(**demisto.args()))
    elif demisto.command() == 'abuseipdb-get-categories':
        demisto.results(get_categories_command(**demisto.args()))  # type:ignore

except Exception as e:
    LOG.print_log()
    return_error(e.message)
