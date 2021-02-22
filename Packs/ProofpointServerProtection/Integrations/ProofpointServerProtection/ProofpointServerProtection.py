''' IMPORTS '''
import demistomock as demisto
from CommonServerPython import *

import requests
from bs4 import BeautifulSoup
import urllib
import re
from distutils.version import StrictVersion

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''

SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
USE_SSL = not demisto.params().get('unsecure', False)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36'
}

session = requests.Session()

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, headers=None, data=None, allow_redirects=True):

    LOG('Running Proofpoint Server Protection request with URL=%s' % (SERVER + url_suffix))

    try:
        res = session.request(
            method,
            SERVER + url_suffix,
            headers=headers,
            data=data,
            verify=USE_SSL,
            allow_redirects=allow_redirects
        )
        if res.status_code not in {200, 302}:
            raise Exception('Your request failed with the following error: ' + res.content + str(res.status_code))
    except Exception as e:
        LOG(e)
        raise

    return res.content


def login():

    cmd_url = '/admin'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36'
    }
    http_request('GET', cmd_url, headers=headers, allow_redirects=False)

    cookies = session.cookies.get_dict()

    data = {
        'locale': 'enus',
        'user': USERNAME,
        'pass': PASSWORD,
        'login': 'Log In',
        'pps_magic': cookies['pps_magic']
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
    }
    http_request('POST', cmd_url, headers=headers, data=data, allow_redirects=False)


def logout():
    cmd_url = '/admin?logout=1'
    http_request('GET', cmd_url)


def translate_timestamp(timestamp):
    timestamp_dict = {
        'Last15Minutes': 'minutesago 15',
        'Last60Minutes': 'minutesago 60',
        'Last3Hours': 'hoursago 3',
        'Last24Hours': 'hoursago 24',
        'Last7Days': 'daysago 7',
        'Last15Days': 'daysago 15',
        'Last30Days': 'daysago 30',
        'Last90Days': 'daysago 90'
    }
    return timestamp_dict[timestamp]


''' FUNCTIONS '''


def download_email_command():

    message_id = demisto.args()['message_id']

    response = download_email(message_id)
    parsed_response = response.replace('<br/>', '\n')
    try:
        auth_index = parsed_response.index('Authentication')
        pre_index = parsed_response.index('</PRE>')

    except ValueError:
        return_error('Could not extract email content from the server response:\n{}'.format(parsed_response))

    eml_content = parsed_response[auth_index:pre_index]
    file_name = message_id + '.eml'
    demisto.results(fileResult(file_name, eml_content))


def download_email(message_id):
    cmd_url = '/admin?module=Message&qtype=0&msgid={0}&file=quarantine/show_src.tt'.format(message_id)

    response = http_request('GET', cmd_url)

    return response


def quarantine_messages_command():

    folder = demisto.args().get('folder', '')
    sender = demisto.args().get('sender', '')
    subject = demisto.args().get('subject', '')
    recipient = demisto.args().get('recipient', '')
    if all(v is None for v in [folder, sender, subject, recipient]):
        return_error('At least one argument is required')

    response = quarantine_messages(folder, sender, subject, recipient)
    soup = BeautifulSoup(response, 'html.parser')
    # Get block_on class of type _qlist content
    block_on_class = soup.find('div', {'class': 'block_on', 'id': '_qlist'})
    # Get script tag content
    script_tag_content = block_on_class.findAll('script', type='text/javascript')
    # There are 2 script tags - we need to second one
    raw_messages_list = script_tag_content[1].text
    # Parsing the content (string) to a list that we can work with
    raw_messages_list = raw_messages_list.split('dl(')
    # We don't need the first 2 elements
    raw_messages_list = raw_messages_list[2:]
    # Extracting the data for the raw list
    messages = []

    for raw_message in raw_messages_list:
        parsed_message = raw_message.split(',')
        messages.append({
            'ID': parsed_message[2].replace('"', ''),
            'Sender': parsed_message[9].replace('"', ''),
            'Recipient': parsed_message[10].replace('"', ''),
            'Date': parsed_message[11].replace('"', ''),
            'Subject': parsed_message[12].replace('"', ''),
            'Folder': parsed_message[19].replace('"', '')
        })

    if messages:
        ec = {
            'Proofpoint.Quarantine.Message(val.ID === obj.ID)': messages
        }
        headers = ['ID', 'Sender', 'Recipient', 'Date', 'Subject', 'Folder']
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(
                'Proofpoint Protection Server Quarantine Search Messages Results',
                messages,
                headers
            ),
            'EntryContext': ec
        })
    else:
        demisto.results('No results found')


def quarantine_messages(folder, sender, subject, recipient):

    cmd_url = '/admin'
    data = {
        'module': 'Quarantine',
        'method': 'get',
        'cmd': 'search',
        'search_Folder': folder if folder else '/',  # If folder is not given, we will search in all folders
        'search_wSender': 'c',  # 'c' stands for Contains
        'search_Sender': sender,
        'search_wRecipients': 'c',
        'search_Recipients': recipient,
        'search_wSubject': 'c',
        'search_Subject': subject,
        'pps_magic': session.cookies.get_dict()['pps_magic']
    }
    raw_search_query = 'wSender=c;wRecipients=c;wSubject=c;'
    if folder:
        raw_search_query += 'Folder={};'.format(folder)
    else:
        raw_search_query += 'Folder=/;'
    if sender:
        raw_search_query += 'Sender={};'.format(sender)
    if subject:
        raw_search_query += 'Subject={};'.format(subject)
    if recipient:
        raw_search_query += 'Recipients={};'.format(recipient)
    search_query = urllib.quote(raw_search_query)
    session.cookies.set('searchquery', search_query)
    response = http_request('POST', cmd_url, data=data)
    return response


def release_email_command():

    message_id = demisto.args()['message_id']
    folder = demisto.args()['folder']
    response = release_email(message_id, folder)
    if 'message successfully' in response:
        demisto.results('Released message {} successfully'.format(message_id))
    else:
        return_error('Failed to release message')


def release_email(message_id, folder):

    cmd_url = '/admin'
    data = {
        'module': 'Quarantine',
        'cmd': 'release',
        'folder': folder,
        'message': message_id,
        'pps_magic': session.cookies.get_dict()['pps_magic']
    }
    response = http_request('POST', cmd_url, data=data)
    return response


def smart_search_command():

    sender = demisto.args().get('sender')
    recipient = demisto.args().get('recipient')
    subject = demisto.args().get('subject')
    process = demisto.args().get('process')
    sender_hostname = demisto.args().get('sender_hostname')
    attachment = demisto.args().get('attachment')
    qid = demisto.args().get('qid')
    timestamp = demisto.args().get('time')
    virus_name = demisto.args().get('virus_name')
    message_id = demisto.args().get('message_id')
    sid = demisto.args().get('sid')
    guid = demisto.args().get('guid')

    data = {
        'suborg': '-99',  # Sub-Org: -All-
        'start_date': '',
        'start_time': '',
        'end_date': '',
        'end_time': '',
        'start_date_long': '',
        'start_time_long': '',
        'end_date_long': '',
        'end_time_long': '',
        'start': 0,
        'count': 100
    }
    timestamp = translate_timestamp(timestamp)
    data['time'] = timestamp
    data['max_results'] = process
    if sender:
        data['sender'] = sender
    if recipient:
        data['recipients'] = recipient
    if subject:
        data['subject'] = subject
    if sender_hostname:
        data['sender_host'] = sender_hostname
    if attachment:
        data['attachment_names'] = attachment
    if qid:
        data['qid'] = qid
    if sid:
        data['sid'] = sid
    if message_id:
        data['message_id'] = message_id
    if virus_name:
        data['virus_names'] = virus_name
    if guid:
        data['guid'] = guid

    response = smart_search(data)
    matches = json.loads(response)['result']['match']
    if matches:
        output = []
        for match in matches:
            pretty_match = {key.replace('_', ''): value for key, value in match.items()}
            output.append(pretty_match)
        ec = {
            'Proofpoint.SmartSearch(val.QID === obj.QID)': output
        }
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Proofpoint Protection Server Smart Search Results', output),
            'EntryContext': ec
        })
    else:
        demisto.results('No results found')


def get_pps_token(pps_magic):
    try:
        cmd_url = '/admin?module=RPC&class=InputValidator&method=getSMD&pps_magic=' + pps_magic
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest'
        }
        submit_search_response = http_request('GET', cmd_url, headers=headers)
        submit_search_response_json = json.loads(submit_search_response)
        service_url = submit_search_response_json.get('serviceURL', '')
        parsed_service_url = service_url.split('pps_token=')
        pps_token = parsed_service_url[1]
        return pps_token
    except Exception as e:
        raise Exception('Failed retrieving pps_token - {}'.format(str(e)))


def smart_search(data):
    pps_magic = session.cookies.get_dict()['pps_magic']

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36',
        'Content-Type': 'application/json-rpc',
        'X-Requested-With': 'XMLHttpRequest'
    }

    submit_search_data = json.dumps({
        'params': [data],
        'method': 'submitSearch',
        'id': 1
    })
    cmd_url = '/admin?module=RPC&class=SmartSearch&method=get&pps_magic=' + pps_magic

    pps_version = demisto.params().get('version')
    if pps_version and StrictVersion(pps_version) >= StrictVersion('8.14.2'):
        pps_token = get_pps_token(pps_magic)
        cmd_url += '&pps_token=' + pps_token

    submit_search_response = http_request('POST', cmd_url, headers=headers, data=submit_search_data)

    if submit_search_response:
        job_id = json.loads(submit_search_response)['result']['job_id']
        get_search_result_data = json.dumps({
            'params': [{
                'job_id': job_id,
                'timezone_offset_minutes': -480,
                'start': 0,
                'count': 100
            }],
            'method': 'getSearchResult',
            'id': 2
        })
        search_results_response = http_request('POST', cmd_url, headers=headers, data=get_search_result_data)

        return search_results_response
    return_error('Failed to get search results')


def quarantine_folders_command():
    response = quarantine_folders()
    soup = BeautifulSoup(response, 'html.parser')
    # Get block_on class content
    class_block_on = soup.find('div', {'class': 'block_on'})
    # Get script tag content
    script_tag_content = class_block_on.findAll('script', type='text/javascript')
    # There are 2 script tags - we need to second one
    raw_folders_names = script_tag_content[1].text
    # Parsing the content (string) to a list that we can work with
    parsed_folders_names = [row.split(',') for row in raw_folders_names.split('displayFolderEntry(')]
    # Removing first and last element of the list which are empty strings
    parsed_folders_names = parsed_folders_names[1:-1]
    folders = []
    for folder in parsed_folders_names:
        # Getting the first element from each row, which is the folder name
        folders.append({'Name': folder[1].replace('"', '')})
    ec = {
        'Proofpoint.Quarantine.Folder(val.Name === obj.Name)': folders
    }
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': folders,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Proofpoint Protection Server Quarantine Folders', folders),
        'EntryContext': ec
    })


def quarantine_folders():
    cmd_url = '/admin?module=Folders'
    response = http_request('GET', cmd_url)
    return response


def add_to_blocked_senders_list_command():

    blocked_sender = demisto.args()['email']

    raw_senders_list = get_senders_list()

    current_blocked_senders_list = re.findall(r'var _blacklist = "([^"]*)";', raw_senders_list)[0]

    if current_blocked_senders_list:
        blocked_senders_list = '{0},{1}'.format(current_blocked_senders_list, blocked_sender)
    else:
        blocked_senders_list = blocked_sender
    add_to_blocked_senders_list(blocked_senders_list)

    demisto.results('Successfully added {} to the Blocked Senders list'.format(blocked_sender))


def add_to_blocked_senders_list(blocked_senders_list):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36'
    }
    pps_magic = session.cookies.get_dict()['pps_magic']
    data = {
        'pps_magic': pps_magic,
        'module': 'EnduserEntry',
        'chapter': '2',
        'subchapter': '0',
        'cmd': 'enduser_modify',
        'extracmd': '',
        'objtype': '1',
        'pass_change_attempt': '0',
        'guid': '257',
        'blacklist': blocked_senders_list
    }
    cmd_url = '/admin'
    http_request('POST', cmd_url, headers=headers, data=data)


def add_to_safe_senders_list_command():

    safe_sender = demisto.args()['email']

    raw_senders_list = get_senders_list()

    current_safe_senders_list = re.findall(r'var _whitelist = "([^"]*)";', raw_senders_list)[0]

    if current_safe_senders_list:
        safe_senders_list = '{0},{1}'.format(current_safe_senders_list, safe_sender)
    else:
        safe_senders_list = safe_sender
    add_to_safe_senders_list(safe_senders_list)

    demisto.results('Successfully added {} to the Safe Senders list'.format(safe_sender))


def add_to_safe_senders_list(safe_senders_list):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36'
    }
    pps_magic = session.cookies.get_dict()['pps_magic']
    data = {
        'pps_magic': pps_magic,
        'module': 'EnduserEntry',
        'chapter': '2',
        'subchapter': '0',
        'cmd': 'enduser_modify',
        'extracmd': '',
        'objtype': '1',
        'pass_change_attempt': '0',
        'guid': '257',
        'whitelist': safe_senders_list
    }
    cmd_url = '/admin'
    http_request('POST', cmd_url, headers=headers, data=data)


def remove_from_blocked_senders_list_command():

    unblocked_sender = demisto.args()['email']

    raw_senders_list = get_senders_list()

    current_blocked_senders_list = re.findall(r'var _blacklist = "([^"]*)";', raw_senders_list)[0]

    if unblocked_sender not in current_blocked_senders_list:
        return_error('Email is not in Blocked Senders list')

    blocked_senders_list = current_blocked_senders_list.replace(unblocked_sender, '')

    remove_from_blocked_senders_list(blocked_senders_list, unblocked_sender)

    demisto.results('Successfully removed {} from the Blocked Senders list'.format(unblocked_sender))


def remove_from_blocked_senders_list(blocked_senders_list, unblocked_sender):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36'
    }
    pps_magic = session.cookies.get_dict()['pps_magic']
    data = {
        'pps_magic': pps_magic,
        'module': 'EnduserEntry',
        'chapter': '2',
        'subchapter': '0',
        'cmd': 'enduser_modify',
        'extracmd': '',
        'objtype': '1',
        'pass_change_attempt': '0',
        'guid': '257',
        'blacklist': blocked_senders_list,
        'xblacklist': unblocked_sender
    }
    cmd_url = '/admin'
    http_request('POST', cmd_url, headers=headers, data=data)


def remove_from_safe_senders_list_command():

    unsafe_sender = demisto.args()['email']

    raw_senders_list = get_senders_list()

    current_safe_senders_list = re.findall(r'var _whitelist = "([^"]*)";', raw_senders_list)[0]

    if unsafe_sender not in current_safe_senders_list:
        return_error('Email is not in Safe Senders list')

    safe_senders_list = current_safe_senders_list.replace(unsafe_sender, '')

    remove_from_safe_senders_list(safe_senders_list, unsafe_sender)

    demisto.results('Successfully removed {} from the Safe Senders list'.format(unsafe_sender))


def remove_from_safe_senders_list(safe_senders_list, unsafe_sender):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36'
    }
    pps_magic = session.cookies.get_dict()['pps_magic']
    data = {
        'pps_magic': pps_magic,
        'module': 'EnduserEntry',
        'chapter': '2',
        'subchapter': '0',
        'cmd': 'enduser_modify',
        'extracmd': '',
        'objtype': '1',
        'pass_change_attempt': '0',
        'guid': '257',
        'whitelist': safe_senders_list,
        'xwhitelist': unsafe_sender
    }
    cmd_url = '/admin'
    http_request('POST', cmd_url, headers=headers, data=data)


def get_senders_list():

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36'
    }
    pps_magic = session.cookies.get_dict()['pps_magic']
    data = {
        'pps_magic': pps_magic,
        'module': 'EnduserEntry',
        'chapter': '2',
        'subchapter': '0',
        'cmd': 'tabs',
        'extracmd': '',
        'objtype': '1',
        'pass_change_attempt': '0',
        'guid': '257',
    }

    cmd_url = '/admin?module=EnduserEntry&load=1&guid=257&pps_magic={}'.format(pps_magic)
    http_request('GET', cmd_url, headers=headers)

    cmd_url = '/admin'
    response = http_request('POST', cmd_url, headers=headers, data=data)

    return response


''' EXECUTION CODE '''

login()

LOG('command is %s' % (demisto.command(), ))

try:
    if demisto.command() == 'test-module':
        # Tests successful login
        demisto.results('ok')

    elif demisto.command() == 'proofpoint-download-email':
        download_email_command()

    elif demisto.command() == 'proofpoint-quarantine-messages':
        quarantine_messages_command()

    elif demisto.command() == 'proofpoint-smart-search':
        smart_search_command()

    elif demisto.command() == 'proofpoint-quarantine-folders':
        quarantine_folders_command()

    elif demisto.command() == 'proofpoint-release-email':
        release_email_command()

    elif demisto.command() == 'proofpoint-add-to-blocked-senders-list':
        add_to_blocked_senders_list_command()

    elif demisto.command() == 'proofpoint-add-to-safe-senders-list':
        add_to_safe_senders_list_command()

    elif demisto.command() == 'proofpoint-remove-from-blocked-senders-list':
        remove_from_blocked_senders_list_command()

    elif demisto.command() == 'proofpoint-remove-from-safe-senders-list':
        remove_from_safe_senders_list_command()

except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise

finally:
    logout()
