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
TRUNCATE_RESPONSE_SUFFIX = '?truncateResponse=false&includeUnverified=false'

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

    if not res.status_code == 200:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))

    return res.json()


def html_description_to_human_readable(breach_description):
    """

    Args:
        breach_description: Description of breach from hibp response

    Returns: Description string that altered HTML urls to clickable urls
    for better readability in war-room

    """
    html_link_pattern = re.compile('<a href="(.+?)"(.+?)>(.+?)</a>')
    patterns_found = html_link_pattern.findall(breach_description)
    for link in patterns_found:
        link_from_desc = '[' + link[2] + ']' + '(' + link[0] + ')'
        breach_description = re.sub(html_link_pattern, link_from_desc, breach_description, count=1)
    return breach_description


def data_to_markdown(query_type, query_arg, hibp_res):
    md = "### Have I Been Pwned query for " + query_type.lower() + ": *" + query_arg + "*\n"

    if hibp_res and len(hibp_res) > 0:
        for breach in hibp_res:
            md += "#### " + breach['Title'] + " (" + breach['Domain'] + "): " + str(breach['PwnCount']) + \
                  " records breached\n"
            md += "Date: **" + breach['BreachDate'] + "**\n"
            md += html_description_to_human_readable(breach['Description']) + "\n"
            md += "Data breached: **" + ','.join(breach['DataClasses']) + "**\n"
    else:
        md += 'No records found'

    return md


def create_dbot_score_dictionary(indicator_value, indicator_type, dbot_score):
    return {
        'Indicator': indicator_value,
        'Type': indicator_type,
        'Vendor': 'Pwned',
        'Score': dbot_score
    }


def create_context_entry(context_type, context_main_value, comp_sites, malicious_score):
    context_dict = dict()  # dict

    if context_type == 'email':
        context_dict['Address'] = context_main_value
    else:
        context_dict['Name'] = context_main_value

    context_dict['Compromised'] = \
        {
            'Vendor': 'Pwned',
            'Reporters': ', '.join(comp_sites)
        }

    if malicious_score == 3:
        context_dict['Malicious'] = add_malicious_to_context(context_type)

    return context_dict


def add_malicious_to_context(malicious_type):
    return {
        'Vendor': 'Pwned',
        'Description': 'The ' + malicious_type + ' has been compromised'
    }


def email_to_entry_context(email, hibp_res):
    comp_sites = sorted([item['Title'] for item in hibp_res])
    comp_email = dict()  # type: dict
    dbot_score = 0

    if len(comp_sites) > 0:
        dbot_score = DEFAULT_DBOT_SCORE_EMAIL
        email_context = create_context_entry('email', email, comp_sites, DEFAULT_DBOT_SCORE_EMAIL)
        comp_email[outputPaths['email']] = email_context

    comp_email['DBotScore'] = create_dbot_score_dictionary(email, 'email', dbot_score)

    return comp_email


def domain_to_entry_context(domain, hibp_res):
    comp_sites = sorted([item['Title'] for item in hibp_res])
    comp_domain = dict()  # type: dict
    dbot_score = 0

    if len(comp_sites) > 0:
        dbot_score = DEFAULT_DBOT_SCORE_DOMAIN
        domain_context = create_context_entry('domain', domain, comp_sites, DEFAULT_DBOT_SCORE_DOMAIN)
        comp_domain[outputPaths['domain']] = domain_context

    comp_domain['DBotScore'] = create_dbot_score_dictionary(domain, 'domain', dbot_score)

    return comp_domain


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    http_request('GET', SAMPLE_TEST_SUFFIX)
    demisto.results('ok')


def pwned_email_command():
    email = demisto.args().get('email')
    suffix = PWNED_EMAIL_SUFFIX + email + TRUNCATE_RESPONSE_SUFFIX
    pwned_email(email, suffix)


def pwned_email(email, suffix):
    hibp_res = http_request('GET', suffix)
    md = data_to_markdown('Email', email, hibp_res)
    ec = email_to_entry_context(email, hibp_res or [])
    return_outputs(md, ec, hibp_res)


def pwned_domain_command():
    domain = demisto.args().get('domain')
    suffix = PWNED_DOMAIN_SUFFIX + domain
    pwned_domain(domain, suffix)


def pwned_domain(domain, suffix):
    hibp_res = http_request('GET', suffix)
    md = data_to_markdown('Domain', domain, hibp_res)
    ec = domain_to_entry_context(domain, hibp_res or [])
    return_outputs(md, ec, hibp_res)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'pwned-email' or demisto.command() == 'email':
        pwned_email_command()
    elif demisto.command() == 'pwned-domain' or demisto.command() == 'domain':
        pwned_domain_command()


# Log exceptions
except Exception, e:
    LOG(e.message)
    LOG.print_log()
    raise
