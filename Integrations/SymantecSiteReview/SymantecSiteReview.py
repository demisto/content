import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import requests
import json

requests.packages.urllib3.disable_warnings()

"""
GLOBAL VARIABLES
"""

VERIFY_CERTIFICATE = not demisto.params().get('unsecure', False)
BASE_URL = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

SITE_LOOKUP_HEADERS = ['URL', 'CategorizationID', 'CategorizationName', 'ResolvedIP', 'ThreatRiskLevel']
"""
Helper Functions
"""


def http_request(method, url, body=None, skip_json=False):
    res = requests.request(method, url, verify=VERIFY_CERTIFICATE, headers=HEADERS, data=body)

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to retrieve data.\n'
                     'URL: {}, Status Code: {}, Response: {}'.format(url, res.status_code, res.text))

    if not skip_json:
        try:
            return res.json()

        except ValueError as ex:
            return_error("Failed to parse the response from the service, the error was:\n{}".format(str(ex)))


"""
Symantec Site Review Commands
"""


def list_risk_levels():
    full_url = BASE_URL + '/resource/risklevels'
    res = http_request('GET', full_url)
    return res


def list_risk_levels_command():
    risk_content = []
    raw_list = list_risk_levels()

    for level in raw_list:
        content = {
            "RiskLevel": level['number'],
            "Description": level['name']
        }
        risk_content.append(content)

    md = tableToMarkdown('Threat Risk Level Descriptions', risk_content, ['RiskLevel', 'Description'])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_list,
        'HumanReadable': md,
        'EntryContext': {
            'SymantecSiteReview.RiskLevel': risk_content
        }
    })


def site_lookup(site):
    # Setting an empty 'captcha' field is required to bypass the ui captcha requirement
    req_body = {
        'url': site,
        'captcha': ''
    }

    full_url = BASE_URL + '/resource/lookup'
    res = http_request('POST', full_url, json.dumps(req_body))

    return res


def get_dbot_score(risk_level):
    if 1 <= risk_level <= 2:
        return 1
    if 3 <= risk_level <= 7:
        return 2
    if 8 <= risk_level <= 10:
        return 3

    return 0


def site_lookup_command():
    """
    urls argument can support a list separated by comma
    """
    url_dicts = []
    dbot_scores = []
    site_details = []
    site_lookups = []

    sites = demisto.args().get('url').split(',')

    for site in sites:
        site_detail = {}
        raw_lookup = site_lookup(site)

        site_detail['URL'] = raw_lookup['url']
        site_detail['CategorizationID'] = raw_lookup['categorization'][0]['num']
        site_detail['CategorizationName'] = raw_lookup['categorization'][0]['name']
        site_detail['ResolvedIP'] = raw_lookup.get('resolvedDetail', {}).get('ipAddress', '')
        site_detail['ThreatRiskLevel'] = raw_lookup.get('threatriskLevel', 0)

        url_dbot_score = get_dbot_score(site_detail['ThreatRiskLevel'])

        dbot_score = {
            'Type': 'url',
            'Vendor': 'SymantecSiteReview',
            'Indicator': raw_lookup['url'],
            'Score': url_dbot_score
        }

        url_dict = {
            'Data': site_detail['URL']
        }
        if url_dbot_score:
            risk_description = [risk['name'] for risk in list_risk_levels()
                                if risk['number'] == site_detail['ThreatRiskLevel']][0]
            url_dict['Malicious'] = {
                'Vendor': 'SymantecSiteReview',
                'Description': 'Found the site as ' + risk_description
            }

        url_dicts.append(url_dict)
        dbot_scores.append(dbot_score)
        site_lookups.append(raw_lookup)
        site_details.append(site_detail)

    md = tableToMarkdown('Lookup Categorization', site_details, SITE_LOOKUP_HEADERS, removeNull=True)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': site_lookups,
        'HumanReadable': md,
        'EntryContext': {
            'SymantecSiteReview.Site(val.URL && val.URL == obj.URL)': site_details,
            'DBotScore': dbot_scores,
            outputPaths['url']: url_dicts
        }
    })


def test():
    http_request('GET', BASE_URL, skip_json=True)
    demisto.results('ok')


LOG('command is %s' % (demisto.command(), ))
handle_proxy()
try:
    if demisto.command() == 'test-module':
        test()
    elif demisto.command() == 'symantec-site-lookup':
        site_lookup_command()
    elif demisto.command() == 'symantec-site-list-risklevels':
        list_risk_levels_command()

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
