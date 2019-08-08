import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import re
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''


API_KEY = demisto.params().get('api_key')
USE_SSL = not demisto.params().get('insecure', False)
BASE_URL = 'https://haveibeenpwned.com/api/v3'
HEADERS = {
    'hibp-api-key': API_KEY,
    'user-agent': 'DBOT-API',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

DEFAULT_DBOT_SCORE_EMAIL = 2 if demisto.params().get('default_dbot_score_email') == 'SUSPICIOUS' else 3
DEFAULT_DBOT_SCORE_DOMAIN = 2 if demisto.params().get('default_dbot_score_domain') == 'SUSPICIOUS' else 3

SAMPLE_TEST_SUFFIX = '/breaches?domain=demisto.com'
PWNED_EMAIL_SUFFIX = '/breachedaccount/'
PWNED_DOMAIN_SUFFIX = '/breaches?domain='


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None):
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )

    if res.status_code in {404}:
        return None
    elif res.status_code < 200 or 299 < res.status_code:
        demisto.error('Error ' + str(res.status_code) + '. ' + res.text)
        return None
    elif res.status_code not in {200}:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))

    return res.json()


def readable_description(desc):
    pattern = re.compile('<a href="(.+?)"(.+?)>(.+?)</a>')
    patterns_found = pattern.search(desc)
    if patterns_found:
        return '[' + patterns_found.group(3) + ']' + '(' + patterns_found.group(1) + ')'
    return desc


def data_to_md(query_type, query_arg, hibp_res):
    md = "### Have I Been Pwned query for " + query_type.lower() + ": *" + query_arg + "*\n"

    if hibp_res and len(hibp_res) > 0:
        for breach in hibp_res:
            md += "#### " + breach.Title + " (" + breach.Domain + "): " + breach.PwnCount + " records breached\n"
            md += "Date: **" + breach.BreachDate + "**\n"
            md += readable_description(breach.Description) + "\n"
            md += "Data breached: **" + breach.DataClasses + "**\n"
    else:
        md += 'No records found'

    return md


def email_to_ec(email, hibp_res):
    comp_sites = sorted([item.title for item in hibp_res])
    comp_email = dict()  # type: dict

    if len(comp_sites) > 0:
        email_context = \
            {
                'Address': email,
                'Compromised': {
                    'Vendor': 'Pwned',
                    'Reporters': ', '.join(comp_sites)
                }
            }

        if DEFAULT_DBOT_SCORE_EMAIL == 3:
            email_context['Malicious'] = \
                {
                    'Vendor': 'Pwned',
                    'Description': 'The email has been compromised'
            }

        comp_email[outputPaths['email']] = email_context

    comp_email['DBotScore'] = \
        {
            'Indicator': email,
            'Type': 'email',
            'Vendor': 'Pwned',
            'Score': DEFAULT_DBOT_SCORE_EMAIL
    }

    return comp_email


def domain_to_ec(domain, hibp_res):
    comp_sites = sorted([item.title for item in hibp_res])
    comp_domain = dict()  # type: dict

    if len(comp_sites) > 0:
        domain_context = \
            {
                'Name': domain,
                'Compromised': {
                    'Vendor': 'Pwned',
                    'Reporters': ', '.join(comp_sites)
                }
            }

        if DEFAULT_DBOT_SCORE_DOMAIN == 3:
            domain_context['Malicious'] = \
                {
                    'Vendor': 'Pwned',
                    'Description': 'The domain has been compromised'
            }

        comp_domain[outputPaths['domain']] = domain_context

    comp_domain['DBotScore'] = \
        {
            'Indicator': domain,
            'Type': 'domain',
            'Vendor': 'Pwned',
            'Score': DEFAULT_DBOT_SCORE_DOMAIN
    }

    return comp_domain


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    http_request('GET', SAMPLE_TEST_SUFFIX)
    demisto.results('ok')


def pwned_email_command():
    hibp_res = http_request('GET', PWNED_EMAIL_SUFFIX + demisto.args().get('email'))
    md = data_to_md('Email', demisto.args().get('email'), hibp_res)
    ec = email_to_ec(demisto.args().get('email'), hibp_res or [])
    return_outputs(md, ec, hibp_res)


def pwned_domain_command():
    hibp_res = http_request('GET', PWNED_DOMAIN_SUFFIX + demisto.args().get('domain'))
    md = data_to_md('Domain', demisto.args().get('domain'), hibp_res)
    ec = domain_to_ec(demisto.args().get('domain'), hibp_res or [])
    return_outputs(md, ec, hibp_res)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'pwned-email' or 'email':
        pwned_email_command()
    elif demisto.command() == 'pwned-domain' or 'domain':
        pwned_domain_command()


# Log exceptions
except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise
