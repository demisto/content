import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from bs4 import BeautifulSoup

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params()['server'].rstrip('/')
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
BASE_URL = SERVER + '/brightmail/'
USE_SSL = not demisto.params().get('insecure', False)
COOKIES = {}  # type: ignore
TOKEN: str

BAD_DOMAINS_EMAILS_GROUP = 'Local Bad Sender Domains'
BAD_IPS_GROUP = 'Local Bad Sender IPs'

client = BaseClient(base_url=BASE_URL, verify=USE_SSL)
''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, cookies=COOKIES, data=None, headers=None):
    LOG('running request with url={}\tdata={}\theaders={}'.format(BASE_URL + url_suffix,
                                                                  data, headers))
    try:
        res = client._session.request(
            method,
            BASE_URL + url_suffix,
            verify=USE_SSL,
            data=data,
            headers=headers,
            cookies=cookies
        )

        if res.status_code not in (200, 204):
            raise Exception('Your request failed with the following error: ' + res.reason)
    except Exception as e:
        LOG(e)
        raise
    return res


def login():
    login_do_url = 'viewLogin.do'
    login_do_response = http_request('get', login_do_url, cookies=None)
    login_jsession = login_do_response.cookies.get_dict()['JSESSIONID']

    soup = BeautifulSoup(login_do_response.text, "lxml")
    hidden_tags = soup.find_all("input", type="hidden")  # Parse <input type=hidden>
    last_login = ""
    for tag in hidden_tags:
        name = tag.attrs.get('name', None)
        if name == 'lastlogin':
            last_login = tag.attrs['value']
    cookies = {
        'JSESSIONID': login_jsession
    }
    demisto.debug(f"{last_login=}")
    data = {
        'lastlogin': last_login,
        'username': USERNAME,
        'password': PASSWORD
    }
    login_url = 'login.do'
    login_response = http_request('post', login_url, cookies=cookies, data=data)

    # if JSESSIONID doesn't exist - creds may be invalid
    if 'JSESSIONID' not in login_response.cookies:
        return_error('Failed to login. Username or password may be invalid')

    jsession = login_response.cookies.get_dict()['JSESSIONID']

    # Add Jsession ID to the cookies
    COOKIES['JSESSIONID'] = jsession

    # Get Token
    login_do_url = 'admin/backup/backupNow.do'
    login_do_response = http_request('get', login_do_url)
    soup = BeautifulSoup(login_do_response.text, "lxml")
    hidden_tags = soup.find_all("input", type="hidden")  # Parse <input type=hidden>
    for tag in hidden_tags:
        name = tag.attrs.get('name', None)
        if name == 'symantec.brightmail.key.TOKEN':
            token = tag.attrs['value']
            return token
    return None


def get_selected_sender_groups(group):
    '''
    Gets bad group name, i.e. Local Bad Sender Domains, and returns the bad group identifer, i.e. 1|3
    The identifier is needed in any sent query related to the bad group
    '''
    cmd_url = 'reputation/sender-group/viewSenderGroups.do?view=badSenders'
    groups = http_request('get', cmd_url)
    soup = BeautifulSoup(groups.text, 'lxml')

    tds_group_names_array = soup.find_all('td')  # Parse <td>
    for td in tds_group_names_array:
        a_href = td.find('a')  # Parse <a>
        if a_href:
            href_string = a_href.string  # Extracts the string from the <a>string</a> tags
            checked_group = ' '.join(href_string.split())  # Removes whitespaces from string
            if checked_group == group:
                previous_td = td.previous_sibling.previous_sibling
                input_tag = previous_td.find('input')  # Parse <input> tags
                if input_tag:
                    group_number = input_tag['value']
                    return group_number
    return None


def block_request(ioc, selected_sender_groups):
    cmd_url = 'reputation/sender-group/saveSender.do'
    data = {
        'pageReuseFor': 'add',
        'selectedSenderGroups': selected_sender_groups,
        'view': 'badSenders',
        'symantec.brightmail.key.TOKEN': TOKEN,
        'addEditSenders': ioc
    }
    response = http_request('post', cmd_url, data=data)
    # Check if given domain/email address is valid and is not already blocked
    soup = BeautifulSoup(response.text, 'lxml')
    # Look for the error message
    error = soup.find('div', 'errorMessageText')
    if error:  # Error occured
        error_message = ' '.join(error.text.split())  # Removes whitespaces from string
        return error_message
    return None


def unblock_request(selected_group_member, selected_sender_groups):
    cmd_url = 'reputation/sender-group/deleteSender.do'
    data = {
        'selectedSenderGroups': selected_sender_groups,
        'view': 'badSenders',
        'symantec.brightmail.key.TOKEN': TOKEN,
        'selectedGroupMembers': int(selected_group_member)
    }
    response = http_request('post', cmd_url, data=data)
    return response


def get_blocked_request(sender_group):
    selected_sender_groups = get_selected_sender_groups(sender_group)
    cmd_url = 'reputation/sender-group/viewSenderGroup.do'
    data = {
        'selectedSenderGroups': selected_sender_groups,
        'view': 'badSenders',
        'symantec.brightmail.key.TOKEN': TOKEN
    }
    blocked = http_request('post', cmd_url, data=data)
    return blocked


def get_next_page(selected_sender_groups):
    """
    Gets next page in bad list
    """
    cmd_url = 'reputation/sender-group/viewNextPage.do'
    data = {
        'selectedSenderGroups': selected_sender_groups,
        'view': 'badSenders',
        'symantec.brightmail.key.TOKEN': TOKEN
    }
    next_page = http_request('post', cmd_url, data=data)
    return next_page


''' FUNCTIONS '''


def get_blocked_domains():
    selected_sender_groups = get_selected_sender_groups(BAD_DOMAINS_EMAILS_GROUP)
    blocked_domains = get_blocked_request(BAD_DOMAINS_EMAILS_GROUP)
    hr = '### SMG Blocked domains:\n'
    soup = BeautifulSoup(blocked_domains.text, 'lxml')
    # Handles pagination of Local Bad Sender Domains
    pages = soup.find('select', 'defaultDrop', id="pageNumber").find_all('option')
    for _i in range(len(pages)):  # Loop through all pages of blocked IP address
        tds_array = soup.find_all('td', 'paddingL3')  # Parse <td>
        for td in tds_array:
            a = td.find('a')  # Parse <a>
            if a:
                s = str(a.find_next_sibling(text=True))  # Get domain
                hr += '- ' + ''.join(s.split()) + '\n'  # Removes whitespaces from string
        # Get next page
        next_page = get_next_page(selected_sender_groups)
        soup = BeautifulSoup(next_page.text, 'lxml')

    entry = {
        'Type': entryTypes['note'],
        'Contents': hr,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr
    }
    return entry


def get_blocked_ips():
    selected_sender_groups = get_selected_sender_groups(BAD_IPS_GROUP)
    blocked_emails = get_blocked_request(BAD_IPS_GROUP)
    hr = '### SMG Blocked IP addresses:\n'
    soup = BeautifulSoup(blocked_emails.text, 'lxml')
    # Handles pagination of Local Bad Sender IPs
    pages = soup.find('select', 'defaultDrop', id="pageNumber").find_all('option')
    for _i in range(len(pages)):  # Loop through all pages of blocked IP address
        tds_array = soup.find_all('td', 'paddingL3')  # Parse <td>
        for td in tds_array:
            a = td.find('a')  # Parse <a>
            if a:
                s = str(a.find_next_sibling(text=True))  # Get IP address
                hr += '- ' + ''.join(s.split()) + '\n'  # Removes whitespaces from string
        # Get next page
        next_page = get_next_page(selected_sender_groups)
        soup = BeautifulSoup(next_page.text, 'lxml')

    entry = {
        'Type': entryTypes['note'],
        'Contents': hr,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr
    }
    return entry


def block_email(email):
    selected_sender_groups = get_selected_sender_groups(BAD_DOMAINS_EMAILS_GROUP)
    error_message = block_request(email, selected_sender_groups)
    if error_message:
        return error_message
    context = {
        'Address': email,
        'Blocked': True
    }
    ec = {
        'Email(val.Address && val.Address === obj.Address)': context
    }
    message = 'Email address ' + email + ' was blocked successfully.'
    entry = {
        'Type': entryTypes['note'],
        'Contents': message,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': message,
        'EntryContext': ec
    }
    return entry


def unblock_email(email):
    selected_sender_groups = get_selected_sender_groups(BAD_DOMAINS_EMAILS_GROUP)
    blocked_emails = get_blocked_request(BAD_DOMAINS_EMAILS_GROUP)
    # Email member number is required in order to send it in the unblock query
    soup = BeautifulSoup(blocked_emails.text, 'lxml')
    # Handles pagination of Local Bad Sender Domains
    pages = soup.find('select', 'defaultDrop', id="pageNumber").find_all('option')
    for _i in range(len(pages)):  # Loop through all pages of blocked email addresses
        tds_array = soup.find_all('td', 'paddingL3')  # Parse <td>
        for td in tds_array:
            a = td.find('a')  # Parse <a>
            if a:
                s = str(a.find_next_sibling(text=True))  # Get checked email address
                checked_email = ''.join(s.split())  # Removes whitespaces from string
                if checked_email == email:
                    href = a['href']  # Get <a href=...>
                    comma_index = href.find(',')  # Get comma sign index in string
                    selected_group_member = a['href'][comma_index + 1:-2]  # Get email member number
                    break
        # Get next page
        next_page = get_next_page(selected_sender_groups)
        soup = BeautifulSoup(next_page.text, 'lxml')

    if 'selected_group_member' not in locals():
        return 'Could not find given email address in ' + BAD_DOMAINS_EMAILS_GROUP

    unblock_request(selected_group_member, selected_sender_groups)
    context = {
        'Address': email,
        'Blocked': False
    }
    ec = {
        'Email(val.Address && val.Address === obj.Address)': context
    }
    message = 'Email address ' + email + ' was unblocked successfully.'
    entry = {
        'Type': entryTypes['note'],
        'Contents': message,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': message,
        'EntryContext': ec
    }
    return entry


def block_domain(domain):
    selected_sender_groups = get_selected_sender_groups(BAD_DOMAINS_EMAILS_GROUP)
    error_message = block_request(domain, selected_sender_groups)
    if error_message:
        return error_message
    context = {
        'Name': domain,
        'Blocked': True
    }
    ec = {
        'Domain(val.Name && val.Name === obj.Name)': context
    }
    message = 'Domain ' + domain + ' was blocked successfully.'
    entry = {
        'Type': entryTypes['note'],
        'Contents': message,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': message,
        'EntryContext': ec
    }
    return entry


def unblock_domain(domain):
    selected_sender_groups = get_selected_sender_groups(BAD_DOMAINS_EMAILS_GROUP)
    blocked_domains = get_blocked_request(BAD_DOMAINS_EMAILS_GROUP)
    # Domain member number is required in order to send it in the unblock query
    soup = BeautifulSoup(blocked_domains.text, 'lxml')
    # Handles pagination of Local Bad Sender Domains
    pages = soup.find('select', 'defaultDrop', id="pageNumber").find_all('option')
    for _i in range(len(pages)):  # Loop through all pages of blocked domains
        tds_array = soup.find_all('td', 'paddingL3')  # Parse <td>
        for td in tds_array:
            a = td.find('a')  # Parse <a>
            if a:
                s = str(a.find_next_sibling(text=True))  # Get checked domain
                checked_domain = ''.join(s.split())  # Removed whitespaces from string
                if checked_domain == domain:
                    href = a['href']  # Get <a href=...>
                    comma_index = href.find(',')  # Get comma sign index in string
                    selected_group_member = a['href'][comma_index + 1:-2]  # Get domain member number
                    break
        # Get next page
        next_page = get_next_page(selected_sender_groups)
        soup = BeautifulSoup(next_page.text, 'lxml')

    if 'selected_group_member' not in locals():
        return 'Could not find given domain in ' + BAD_DOMAINS_EMAILS_GROUP

    unblock_request(selected_group_member, selected_sender_groups)
    context = {
        'Name': domain,
        'Blocked': False
    }
    ec = {
        'Domain(val.Name && val.Name === obj.Name)': context
    }
    message = 'Domain ' + domain + ' was unblocked successfully.'
    entry = {
        'Type': entryTypes['note'],
        'Contents': message,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': message,
        'EntryContext': ec
    }
    return entry


def block_ip(ip):
    selected_sender_groups = get_selected_sender_groups(BAD_IPS_GROUP)
    error_message = block_request(ip, selected_sender_groups)
    if error_message:
        return error_message
    context = {
        'Address': ip,
        'Blocked': True
    }
    ec = {
        'IP(val.Address && val.Address === obj.Address)': context
    }
    message = 'IP address ' + ip + ' was blocked successfully.'
    entry = {
        'Type': entryTypes['note'],
        'Contents': message,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': message,
        'EntryContext': ec
    }
    return entry


def unblock_ip(ip):
    selected_sender_groups = get_selected_sender_groups(BAD_IPS_GROUP)
    blocked_ips = get_blocked_request(BAD_IPS_GROUP)
    # Domain member number is required in order to send it in the unblock query
    soup = BeautifulSoup(blocked_ips.text, 'lxml')
    # Handles pagination of Local Bad Sender IPs
    pages = soup.find('select', 'defaultDrop', id="pageNumber").find_all('option')
    for _i in range(len(pages)):  # Loop through all pages of blocked IP address
        tds_array = soup.find_all('td', 'paddingL3')  # Parse <td>
        for td in tds_array:
            a = td.find('a')  # Parse <a>
            if a:
                s = str(a.find_next_sibling(text=True))  # Get checked IP address
                checked_ip = ''.join(s.split())  # Removed whitespaces from string
                if checked_ip == ip:
                    href = a['href']  # Get <a href=...>
                    comma_index = href.find(',')  # Get comma sign index in string
                    selected_group_member = a['href'][comma_index + 1:-2]  # Get IP member number
                    break
        next_page = get_next_page(selected_sender_groups)
        soup = BeautifulSoup(next_page.text, 'lxml')

    if 'selected_group_member' not in locals():
        return 'Could not find given IP address in ' + BAD_IPS_GROUP

    unblock_request(selected_group_member, selected_sender_groups)
    context = {
        'Address': ip,
        'Blocked': False
    }
    ec = {
        'IP(val.Address && val.Address === obj.Address)': context
    }
    message = 'IP address ' + ip + ' was unblocked successfully.'
    entry = {
        'Type': entryTypes['note'],
        'Contents': message,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': message,
        'EntryContext': ec
    }
    return entry


def main():
    global TOKEN
    handle_proxy()
    TOKEN = login()

    try:
        if demisto.command() == 'test-module':
            # Checks authentication and connectivity in login() function
            demisto.results('ok')
        elif demisto.command() == 'smg-block-email':
            # demisto.results(get_selected_sender_groups())
            demisto.results(block_email(demisto.args()['email']))
        elif demisto.command() == 'smg-unblock-email':
            demisto.results(unblock_email(demisto.args()['email']))
        elif demisto.command() == 'smg-block-domain':
            demisto.results(block_domain(demisto.args()['domain']))
        elif demisto.command() == 'smg-block-ip':
            demisto.results(block_ip(demisto.args()['ip']))
        elif demisto.command() == 'smg-unblock-ip':
            demisto.results(unblock_ip(demisto.args()['ip']))
        elif demisto.command() == 'smg-unblock-domain':
            demisto.results(unblock_domain(demisto.args()['domain']))
        elif demisto.command() == 'smg-get-blocked-domains':
            demisto.results(get_blocked_domains())
        elif demisto.command() == 'smg-get-blocked-ips':
            demisto.results(get_blocked_ips())

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
