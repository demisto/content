import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import socket
import struct
import time
from operator import itemgetter
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
CUSTOMER_NAME = demisto.params().get('customer_name', None)
API_KEY = demisto.params().get('api_key', None)
URL = demisto.params().get('url', None)

if URL[-1] != '/':
    URL += '/'

BASE_URL = URL + 'tx_api/v1'
DBOT_THRESHOLD = int(demisto.params().get('dbot_threshold', 70))
USE_SSL = not demisto.params().get('insecure')

''' HELPER FUNCTIONS '''


def http_request(url_suffix, commands=None):
    state = demisto.getIntegrationContext()

    session_token = state.get('session_token')

    if url_suffix != '/login':
        demisto.info('running request with url=%s with commands=%s' % (BASE_URL + url_suffix, commands))
        data = {
            'token': session_token,
            'customer_name': CUSTOMER_NAME
        }
    else:
        demisto.info('running request with url=%s' % (BASE_URL + url_suffix))
        data = {}

    if commands is not None:
        data.update(commands)

    res = requests.post(
        BASE_URL + url_suffix,
        verify=USE_SSL,
        json=data
    )

    if res.status_code != requests.codes.ok:
        if url_suffix == '/login':
            demisto.setIntegrationContext({'session_token': None,
                                           'token_expires': None
                                           })
            demisto.info(str(res.status_code) + ' from server during login. Clearing session token cache.')

        return_error('HTTP %d Error in API call to ThreatX service - %s' % (res.status_code, res.text))

    if not res.text:
        resp_json = {}  # type:dict

    try:
        resp_json = res.json()
    except ValueError:
        return_error('Could not parse the response from ThreatX: %s' % (res.text))

    if 'Ok' not in resp_json:
        if url_suffix == '/login':
            demisto.setIntegrationContext({'session_token': None,
                                           'token_expires': None
                                           })
            return_error('Login response error - %s.' % (res.text))

        return_error(res.text)

    if url_suffix == '/login':
        if 'status' in resp_json['Ok']:
            if resp_json['Ok']['status'] is not True:
                demisto.setIntegrationContext({'session_token': None,
                                               'token_expires': None
                                               })
                return_error('Invalid credentials.')

    return resp_json['Ok']


@logger
def initialize():
    endpoint = '/login'
    commands = {
        'command': 'login',
        'api_token': API_KEY
    }

    state = demisto.getIntegrationContext()

    if not state.get('session_token'):
        session_token = None
        token_expires = None
    else:
        session_token = state.get('session_token')
        token_expires = state.get('token_expires')

    demisto.info('Initializing request...')

    if session_token is None or (token_expires is not None and token_expires < int(time.time())):
        if session_token is None:
            demisto.info('Session token missing - getting new session token...')
        elif token_expires is not None and token_expires < int(time.time()):
            demisto.info('Session token expired - getting new session token...')

        r = http_request(endpoint, commands)
        demisto.setIntegrationContext({'session_token': r['token'],
                                       'token_expires': int(time.time() + (10 * 60))
                                       })
        return

    demisto.info('Cached session token not expired.')
    return


def pretty_ip(decimal_ip):
    """Convert decimal ip to dotted quad format"""
    packed_ip = struct.pack("!I", decimal_ip)
    return socket.inet_ntoa(packed_ip)


def pretty_time(input_time):
    """Convert unix epoch time to human readable format"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(input_time))


def set_dbot_score(threatx_score):
    """Set the DBot Score based on the ThreatX risk score"""
    if threatx_score >= DBOT_THRESHOLD:
        return 3
    elif threatx_score > 10:
        return 2
    else:
        return 0


''' FUNCTIONS '''


@logger
def block_ip(ip):
    commands = {
        'command': 'new_blocklist',
        'entry': {
            'ip': ip,
            'description': 'Added by ThreatX Demisto Integration',
            'created': int(time.time())
        }
    }

    return http_request('/lists', commands)


@logger
def block_ip_command():
    ip = demisto.args().get('ip', None)
    results = block_ip(ip)

    md = tableToMarkdown('Block IP',
                         results,
                         ['Result'],
                         removeNull=True)

    ec = {
        'IP(val.Address === obj.Address)': {
            'Address': ip
        }
    }

    return_outputs(md, ec, results)


@logger
def unblock_ip(ip):
    commands = {
        'command': 'delete_blocklist',
        'ip': ip
    }

    return http_request('/lists', commands)


@logger
def unblock_ip_command():
    ip = demisto.args().get('ip', None)
    results = unblock_ip(ip)

    md = tableToMarkdown('Unblock IP',
                         results,
                         ['Result'],
                         removeNull=True)

    ec = {
        'IP(val.Address === obj.Address)': {
            'Address': ip
        }
    }

    return_outputs(md, ec, results)


@logger
def blacklist_ip(ip):
    commands = {
        'command': 'new_blacklist',
        'entry': {
            'ip': ip,
            'description': 'Added by ThreatX Demisto Integration',
            'created': int(time.time())
        }
    }

    return http_request('/lists', commands)


@logger
def blacklist_ip_command():
    ip = demisto.args().get('ip', None)
    results = blacklist_ip(ip)

    md = tableToMarkdown('Blacklist IP',
                         results,
                         ['Result'],
                         removeNull=True)

    ec = {
        'IP(val.Address === obj.Address)': {
            'Address': ip
        }
    }

    return_outputs(md, ec, results)


@logger
def unblacklist_ip(ip):
    commands = {
        'command': 'delete_blacklist',
        'ip': ip
    }

    return http_request('/lists', commands)


@logger
def unblacklist_ip_command():
    ip = demisto.args().get('ip', None)
    results = unblacklist_ip(ip)

    md = tableToMarkdown('Unblacklist IP',
                         results,
                         ['Result'],
                         removeNull=True)

    ec = {
        'IP(val.Address === obj.Address)': {
            'Address': ip
        }
    }

    return_outputs(md, ec, results)


@logger
def whitelist_ip(ip):
    commands = {
        'command': 'new_whitelist',
        'entry': {
            'ip': ip,
            'description': 'Added by ThreatX Demisto Integration',
            'created': int(time.time())
        }
    }

    return http_request('/lists', commands)


@logger
def whitelist_ip_command():
    ip = demisto.args().get('ip', None)
    results = whitelist_ip(ip)

    md = tableToMarkdown('Whitelist IP',
                         results,
                         ['Result'],
                         removeNull=True)

    ec = {
        'IP(val.Address === obj.Address)': {
            'Address': ip
        }
    }

    return_outputs(md, ec, results)


@logger
def unwhitelist_ip(ip):
    commands = {
        'command': 'delete_whitelist',
        'ip': ip
    }

    return http_request('/lists', commands)


@logger
def unwhitelist_ip_command():
    ip = demisto.args().get('ip', None)
    results = unwhitelist_ip(ip)

    md = tableToMarkdown('Unwhitelist IP',
                         results,
                         ['Result'],
                         removeNull=True)

    ec = {
        'IP(val.Address === obj.Address)': {
            'Address': ip
        }
    }

    return_outputs(md, ec, results)


@logger
def get_entities(entity_name, entity_id, entity_ip, timeframe):
    commands = {
        'command': 'list',
        'query': dict()
    }  # type: dict

    if entity_name is not None:
        entity_names = entity_name.split(',')
        my_entity_name = {'codenames': entity_names}
        commands['query'].update(my_entity_name)

    if entity_id is not None:
        entity_ids = entity_id.split(',')
        my_entity_id = {'entity_ids': entity_ids}
        commands['query'].update(my_entity_id)

    if entity_ip is not None:
        entity_ips = entity_ip.split(',')
        my_entity_ip = {'ip_addresses': entity_ips}
        commands['query'].update(my_entity_ip)

    first_seen = None

    if timeframe is not None:
        if timeframe == '1-Hour':
            first_seen = int(time.time() - (60 * 60))
        elif timeframe == '1-Day':
            first_seen = int(time.time() - (24 * 60 * 60))
        elif timeframe == '1-Week':
            first_seen = int(time.time() - (7 * 24 * 60 * 60))
        elif timeframe == '1-Month':
            first_seen = int(time.time() - (31 * 24 * 60 * 60))

    if first_seen:
        my_timeframe = {'first_seen': first_seen}
        commands['query'].update(my_timeframe)

    return http_request('/entities', commands)


@logger
def get_entity_risk(entity_id):
    commands = {
        'command': 'risk_changes',
        'id': entity_id
    }

    return http_request('/entities', commands)


@logger
def get_entities_command():
    entity_name = demisto.args().get('entity_name', None)
    entity_id = demisto.args().get('entity_id', None)
    entity_ip = demisto.args().get('entity_ip', None)
    timeframe = demisto.args().get('timeframe', None)
    results = get_entities(entity_name, entity_id, entity_ip, timeframe)
    dbot_scores = []
    ip_enrich = []
    human_readable = []
    entities_context = []
    for entity in results:
        risk_score = 0
        e_risk = None
        # Grab the entity risk so we can set the Dbot score for the Actor IPs
        e_id = entity.get('id')

        if e_id:
            e_risk = get_entity_risk(e_id)

        if isinstance(e_risk, list) and e_risk:
            if isinstance(e_risk[-1], dict) and 'risk' in e_risk[-1]:
                risk_score = e_risk[-1]['risk']

        entity['risk'] = risk_score

        iplist = []

        for actor in entity.get('actors', []):
            if 'ip_address' in actor:
                ipdot = pretty_ip(actor['ip_address'])
                iplist.append(ipdot)
                actor['ip_address'] = ipdot

            if 'interval_time_start' in actor:
                actor['interval_time_start'] = pretty_time(actor['interval_time_start'])

            if 'interval_time_stop' in actor:
                actor['interval_time_stop'] = pretty_time(actor['interval_time_stop'])

            if 'fingerprint' in actor and actor.get('fingerprint') is not None:
                if 'last_seen' in actor.get('fingerprint', {}):
                    actor['fingerprint']['last_seen'] = pretty_time(actor['fingerprint']['last_seen'])

            dbscore = set_dbot_score(risk_score)

            dbot_scores.append({
                'Vendor': 'ThreatX',
                'Indicator': ipdot,
                'Type': 'ip',
                'Score': dbscore
            })

            if dbscore == 3:
                ip_enrich.append({
                    'Address': ipdot,
                    'Malicious': {
                        'Vendor': 'ThreatX',
                        'Description': 'ThreatX risk score is ' + str(risk_score)
                    }
                })
            else:
                ip_enrich.append({
                    'Address': ipdot
                })
        entities_context.append({
            'ID': e_id,
            'Name': entity['codename'],
            'IP': iplist,
            'Risk': risk_score
        })

        human_readable.append({
            'Name': entity['codename'],
            'ID': e_id,
            'IP Addresses': ', '.join(iplist),
            'ThreatX Risk Score': risk_score
        })

    ec = {
        'Threatx.Entity(val.ID && val.ID === obj.ID)': entities_context,
        'DBotScore': dbot_scores,
        'IP(val.Address === obj.Address)': ip_enrich
    }

    return_outputs(tableToMarkdown('Entities', human_readable), ec, results)


@logger
def get_entity_notes(entity_id):
    commands = {
        'command': 'notes',
        'id': entity_id
    }

    return http_request('/entities', commands)


@logger
def get_entity_notes_command():
    entity_id = demisto.args().get('entity_id', None)
    results = get_entity_notes(entity_id)

    # Reverse sort the list by timestamp
    sorted_results = sorted(results, key=itemgetter('timestamp'), reverse=True)

    # Replace dates with pretty format
    for note in sorted_results:
        if 'timestamp' in note:
            note['timestamp'] = pretty_time(note['timestamp'])

    md = tableToMarkdown('Entity Notes',
                         sorted_results,
                         headerTransform=string_to_table_header)

    ec = {
        'Threatx.Entity(val.ID && val.ID === obj.ID)': {
            'ID': entity_id,
            'Note': sorted_results
        }
    }

    return_outputs(md, ec, sorted_results)


@logger
def add_entity_note(entity_id, message):
    commands = {
        'command': 'new_note',
        'note': {
            'entity_id': entity_id,
            'content': message
        }
    }

    return http_request('/entities', commands)


@logger
def add_entity_note_command():
    entity_id = demisto.args().get('entity_id', None)
    message = demisto.args().get('message', None)
    results = add_entity_note(entity_id, message)

    md = tableToMarkdown('New Entity Note',
                         results,
                         ['Result'],
                         removeNull=True)

    return_outputs(md, None, results)


@logger
def test_module():
    commands = {
        'command': 'list'
    }

    return http_request('/users', commands)


@logger
def test_module_command():
    results = test_module()

    if isinstance(results, list):
        if results:
            if 'username' in results[0]:
                demisto.results('ok')
            else:
                return_error('Unexpected response from ThreatX.')
        else:
            return_error('Empty response from ThreatX.')
    else:
        return_error('Unrecognized response from ThreatX.')


''' EXECUTION CODE '''


demisto.info('command is %s' % (demisto.command(),))
try:
    handle_proxy()
    initialize()
    if demisto.command() == 'test-module':
        test_module_command()
    elif demisto.command() == 'threatx-block-ip':
        block_ip_command()
    elif demisto.command() == 'threatx-unblock-ip':
        unblock_ip_command()
    elif demisto.command() == 'threatx-blacklist-ip':
        blacklist_ip_command()
    elif demisto.command() == 'threatx-unblacklist-ip':
        unblacklist_ip_command()
    elif demisto.command() == 'threatx-whitelist-ip':
        whitelist_ip_command()
    elif demisto.command() == 'threatx-unwhitelist-ip':
        unwhitelist_ip_command()
    elif demisto.command() == 'threatx-get-entities':
        get_entities_command()
    elif demisto.command() == 'threatx-get-entity-notes':
        get_entity_notes_command()
    elif demisto.command() == 'threatx-add-entity-note':
        add_entity_note_command()

except Exception as e:
    return_error(str(e))
