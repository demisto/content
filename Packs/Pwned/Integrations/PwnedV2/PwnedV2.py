from CommonServerPython import *

''' IMPORTS '''

import re
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

params = demisto.params()
VENDOR = 'Have I Been Pwned? V2'
MAX_RETRY_ALLOWED = params.get('max_retry_time', -1)
API_KEY = params.get('credentials_api_key', {}).get('password') or params.get('api_key')
USE_SSL = not params.get('insecure', False)
BASE_URL = 'https://haveibeenpwned.com/api/v3'
DEFAULT_DBOT_SCORE_EMAIL = 2 if params.get('default_dbot_score_email') == 'SUSPICIOUS' else 3
DEFAULT_DBOT_SCORE_DOMAIN = 2 if params.get('default_dbot_score_domain') == 'SUSPICIOUS' else 3

''' GLOBALS/PARAMS '''

VENDOR = 'Have I Been Pwned? V2'
SUFFIXES = {
    "email": '/breachedaccount/',
    "domain": '/breaches?domain=',
    "username": '/breachedaccount/',
    "paste": '/pasteaccount/',
    "email_truncate_verified": '?truncateResponse=false&includeUnverified=true',
    "domain_truncate_verified": '&truncateResponse=false&includeUnverified=true',
    "username_truncate_verified": '?truncateResponse=false&includeUnverified=true'
}

RETRIES_END_TIME = datetime.min

''' HELPER FUNCTIONS '''


def error_handler(res):
    if res.status_code == 404:
        raise DemistoException("No result found.")
    else:
        demisto.error(
            'Error in API call to Pwned Integration [%d]. Full text: %s' % (res.status_code, res.text))
    return_error('Error in API call to Pwned Integration [%d] - %s' % (res.status_code, res.reason))


def http_request(method, url_suffix, params=None, data=None):
    headers = {
        'hibp-api-key': API_KEY,
        'user-agent': 'DBOT-API',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    try:
        return generic_http_request(method=method,
                                    server_url=BASE_URL,
                                    verify=USE_SSL,
                                    client_headers=headers,
                                    url_suffix=url_suffix,
                                    data=data,
                                    params=params,
                                    error_handler=error_handler,
                                    status_list_to_retry=[429],
                                    retries=5,
                                    ok_codes=(200,))
    except DemistoException:
        return None


def html_description_to_human_readable(breach_description):
    """
    Converting from html description to hr
    :param breach_description: Description of breach from API response
    :return: Description string that altered HTML urls to clickable urls
    for better readability in war-room
    """
    html_link_pattern = re.compile('<a href="(.+?)"(.+?)>(.+?)</a>')
    patterns_found = html_link_pattern.findall(breach_description)
    for link in patterns_found:
        html_actual_address = link[0]
        html_readable_name = link[2]
        link_from_desc = '[' + html_readable_name + ']' + '(' + html_actual_address + ')'
        breach_description = re.sub(html_link_pattern, link_from_desc, breach_description, count=1)
    return breach_description


def data_to_markdown(query_type, query_arg, api_res, api_paste_res=None):
    records_found = False

    md = '### Have I Been Pwned query for ' + query_type.lower() + ': *' + query_arg + '*\n'

    if api_res:
        records_found = True
        for breach in api_res:
            verified_breach = 'Verified' if breach['IsVerified'] else 'Unverified'
            md += '#### ' + breach['Title'] + ' (' + breach['Domain'] + '): ' + str(breach['PwnCount']) + \
                  ' records breached [' + verified_breach + ' breach]\n'
            md += 'Date: **' + breach['BreachDate'] + '**\n\n'
            md += html_description_to_human_readable(breach['Description']) + '\n'
            md += 'Data breached: **' + ','.join(breach['DataClasses']) + '**\n'

    if api_paste_res:
        records_found = True
        pastes_list = []
        for paste_breach in api_paste_res:
            paste_entry = \
                {
                    'Source': paste_breach['Source'],
                    'Title': paste_breach['Title'],
                    'ID': paste_breach['Id'],
                    'Date': '',
                    'Amount of emails in paste': str(paste_breach['EmailCount'])
                }

            if paste_breach['Date']:
                paste_entry['Date'] = paste_breach['Date'].split('T')[0]

            pastes_list.append(paste_entry)

        md += tableToMarkdown('The email address was found in the following "Pastes":',
                              pastes_list,
                              ['ID', 'Title', 'Date', 'Source', 'Amount of emails in paste'])

    if not records_found:
        md += 'No records found'

    return md


def create_dbot_score_dictionary(indicator_value, indicator_type, dbot_score):
    return {
        'Indicator': indicator_value,
        'Type': indicator_type,
        'Vendor': VENDOR,
        'Score': dbot_score,
        'Reliability': demisto.params().get('integrationReliability')
    }


def create_context_entry(context_type, context_main_value, comp_sites, comp_pastes, malicious_score):
    context_dict = {}  # dict

    if context_type == 'email':
        context_dict['Address'] = context_main_value
    else:
        context_dict['Name'] = context_main_value

    context_dict['Pwned-V2'] = {
        'Compromised': {
            'Vendor': VENDOR,
            'Reporters': ', '.join(comp_sites + comp_pastes)
        }
    }

    if malicious_score == 3:
        context_dict['Malicious'] = add_malicious_to_context(context_type)

    return context_dict


def add_malicious_to_context(malicious_type):
    return {
        'Vendor': VENDOR,
        'Description': 'The ' + malicious_type + ' has been compromised'
    }


def email_to_entry_context(email, api_email_res, api_paste_res):
    dbot_score = 0
    comp_email = {}  # type: dict
    comp_sites = sorted([item['Title'] for item in api_email_res])
    comp_pastes = sorted({item['Source'] for item in api_paste_res})

    if len(comp_sites) > 0:
        dbot_score = DEFAULT_DBOT_SCORE_EMAIL
        email_context = create_context_entry('email', email, comp_sites, comp_pastes, DEFAULT_DBOT_SCORE_EMAIL)
        comp_email[outputPaths['email']] = email_context

    comp_email['DBotScore'] = create_dbot_score_dictionary(email, 'email', dbot_score)

    return comp_email


def domain_to_entry_context(domain, api_res):
    comp_sites = [item['Title'] for item in api_res]
    comp_sites = sorted(comp_sites)
    comp_domain = {}  # type: dict
    dbot_score = 0

    if len(comp_sites) > 0:
        dbot_score = DEFAULT_DBOT_SCORE_DOMAIN
        domain_context = create_context_entry('domain', domain, comp_sites, [], DEFAULT_DBOT_SCORE_DOMAIN)
        comp_domain[outputPaths['domain']] = domain_context

    comp_domain['DBotScore'] = create_dbot_score_dictionary(domain, 'domain', dbot_score)

    return comp_domain


def set_retry_end_time():
    global RETRIES_END_TIME
    if MAX_RETRY_ALLOWED != -1:
        RETRIES_END_TIME = datetime.now() + timedelta(seconds=int(MAX_RETRY_ALLOWED))


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(args_dict):
    """
    If the http request was successful the test will return OK
    :return: 3 arrays of outputs
    """
    http_request('GET', SUFFIXES.get("username", '') + 'test')
    return ['ok'], [None], [None]


def pwned_email_command(args_dict):
    """
    Executing the pwned request for emails list, in order to support list input, the function returns 3 lists of outputs
   :param args_dict: the demisto argument - in this case the email list is needed
   :return: 3 arrays of outputs
   """
    email_list = argToList(args_dict.get('email', ''))
    api_email_res_list, api_paste_res_list = pwned_email(email_list)

    md_list = []
    ec_list = []

    for email, api_email_res, api_paste_res in zip(email_list, api_email_res_list, api_paste_res_list):
        md_list.append(data_to_markdown('Email', email, api_email_res, api_paste_res))
        ec_list.append(email_to_entry_context(email, api_email_res or [], api_paste_res or []))
    return md_list, ec_list, api_email_res_list


def pwned_email(email_list):
    """
    Executing the http requests
    :param email_list: the email list that needed for the http requests
    :return: 2 arrays of http requests outputs
    """
    api_email_res_list = []
    api_paste_res_list = []

    for email in email_list:
        email_suffix = SUFFIXES.get("email") + email + SUFFIXES.get("email_truncate_verified")
        paste_suffix = SUFFIXES.get("paste") + email
        api_email_res_list.append(http_request('GET', url_suffix=email_suffix))
        api_paste_res_list.append(http_request('GET', url_suffix=paste_suffix))

    return api_email_res_list, api_paste_res_list


def pwned_domain_command(args_dict):
    """
    Executing the pwned request for domains list, in order to support list input, the function returns 3 lists of
    outputs
   :param args_dict: the demisto argument - in this case the domain list is needed
   :return: 3 arrays of outputs
   """
    domain_list = argToList(args_dict.get('domain', ''))
    api_res_list = pwned_domain(domain_list)

    md_list = []
    ec_list = []

    for domain, api_res in zip(domain_list, api_res_list):
        md_list.append(data_to_markdown('Domain', domain, api_res))
        ec_list.append(domain_to_entry_context(domain, api_res or []))
    return md_list, ec_list, api_res_list


def pwned_domain(domain_list):
    """
    Executing the http request
    :param domain_list: the domains list that needed for the http requests
    :return: an array of http requests outputs
    """
    api_res_list = []
    for domain in domain_list:
        suffix = SUFFIXES.get("domain") + domain + SUFFIXES.get("domain_truncate_verified")
        api_res_list.append(http_request('GET', url_suffix=suffix))
    return api_res_list


def pwned_username_command(args_dict):
    """
    Executing the pwned request for usernames list, in order to support list input, the function returns 3 lists of
    outputs
    :param args_dict: the demisto argument - in this case the username list is needed
    :return: 3 arrays of outputs
    """
    username_list = argToList(args_dict.get('username', ''))
    api_res_list = pwned_username(username_list)

    md_list = []
    ec_list = []

    for username, api_res in zip(username_list, api_res_list):
        md_list.append(data_to_markdown('Username', username, api_res))
        ec_list.append(domain_to_entry_context(username, api_res or []))
    return md_list, ec_list, api_res_list


def pwned_username(username_list):
    """
    Executing the http request
    :param username_list: the username list that needed for the http requests
    :return: an array of http requests outputs
    """
    api_res_list = []
    for username in username_list:
        suffix = SUFFIXES.get("username") + username + SUFFIXES.get("username_truncate_verified")
        api_res_list.append(http_request('GET', url_suffix=suffix))
    return api_res_list


def main():  # pragma: no cover
    if not API_KEY:
        raise DemistoException('API key must be provided.')
    command = demisto.command()
    LOG(f'Command being called is: {command}')
    try:
        handle_proxy()
        set_retry_end_time()
        commands = {
            'test-module': test_module,
            'email': pwned_email_command,
            'pwned-email': pwned_email_command,
            'domain': pwned_domain_command,
            'pwned-domain': pwned_domain_command,
            'pwned-username': pwned_username_command
        }
        if command in commands:
            md_list, ec_list, api_email_res_list = commands[command](demisto.args())
            for md, ec, api_paste_res in zip(md_list, ec_list, api_email_res_list):
                return_outputs(md, ec, api_paste_res)

    # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
