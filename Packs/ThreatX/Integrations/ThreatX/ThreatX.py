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
CUSTOMER_NAME = ''
API_KEY = ''
BASE_URL = ''
DBOT_THRESHOLD = 70
USE_SSL = True

''' HELPER FUNCTIONS '''


def http_request(url_suffix, commands=None):
    state = demisto.getIntegrationContext()

    session_token = state.get('session_token')

    if url_suffix != '/login':
        demisto.info('running request with url={} with commands={}'.format(BASE_URL + url_suffix, commands))
        data = {
            'token': session_token,
            'customer_name': CUSTOMER_NAME
        }
    else:
        demisto.info('running request with url={}'.format(BASE_URL + url_suffix))
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
            demisto.info('{} from server during login. Clearing session token cache.'.format(res.status_code))

        raise DemistoException('HTTP {} Error in API call to ThreatX service - {}'.format(res.status_code, res.text))

    resp_json = {}  # type:dict
    try:
        resp_json = res.json()
    except ValueError:
        raise DemistoException('Could not parse the response from ThreatX: {}'.format(res.text))

    if 'Ok' not in resp_json:
        if url_suffix == '/login':
            demisto.setIntegrationContext({'session_token': None,
                                           'token_expires': None
                                           })
            raise DemistoException('Login response error - {}.'.format(res.text))

        raise DemistoException(res.text)

    if url_suffix == '/login':
        if 'status' in resp_json['Ok']:
            if resp_json['Ok']['status'] is not True:
                demisto.setIntegrationContext({'session_token': None,
                                               'token_expires': None
                                               })
                raise DemistoException('Invalid credentials.')

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
def block_ip(ip, description):
    commands = {
        'command': 'new_blocklist',
        'entry': {
            'ip': ip,
            'description': description,
            'created': int(time.time())
        }
    }

    return http_request('/lists', commands)


@logger
def block_ip_command(args):
    ips = args.get('ip', [])
    description = args.get('description', 'Added by ThreatX Demisto Integration')
    results = []
    errors = []
    for ip in argToList(ips):
        try:
            ip_result = block_ip(ip, description)
        except Exception as error:
            demisto.error('failed block ip: {}\n{}'.format(ip, traceback.format_exc()))
            errors.append('Failed to block ip: {} error: {}'.format(ip, error))
        else:
            results.append(ip_result)
    if results:
        readable_outputs = tableToMarkdown('Block IP',
                                           results,
                                           ['Result'],
                                           removeNull=True)

        return_results(CommandResults(
            outputs=results, readable_output=readable_outputs,
            outputs_prefix='IP(val.Address === obj.Address).Address'
        ))
    if errors:
        return_error('\n'.join(errors))


@logger
def unblock_ip(ip):
    commands = {
        'command': 'delete_blocklist',
        'ip': ip
    }

    return http_request('/lists', commands)


@logger
def unblock_ip_command(args):
    ip = args.get('ip', None)
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
def blacklist_ip(ip, description):
    commands = {
        'command': 'new_blacklist',
        'entry': {
            'ip': ip,
            'description': description,
            'created': int(time.time())
        }
    }

    return http_request('/lists', commands)


@logger
def blacklist_ip_command(args):
    ips = args.get('ip', None)
    description = args.get('description', 'Added by ThreatX Demisto Integration')
    results = []
    errors = []
    for ip in argToList(ips):
        try:
            ip_result = blacklist_ip(ip, description)
        except Exception as error:
            demisto.error('failed adding ip: {} to balcklist\n{}'.format(ip, traceback.format_exc()))
            errors.append('Failed to add ip: {} to blacklist error: {}'.format(ip, error))
        else:
            results.append(ip_result)

    if results:
        readable_outputs = tableToMarkdown('Blacklist IP',
                                           results,
                                           ['Result'],
                                           removeNull=True)

        return_results(CommandResults(
            outputs=results, readable_output=readable_outputs,
            outputs_prefix='IP(val.Address === obj.Address).Address'
        ))
    if errors:
        return_error('\n'.join(errors))


@logger
def unblacklist_ip(ip):
    commands = {
        'command': 'delete_blacklist',
        'ip': ip
    }

    return http_request('/lists', commands)


@logger
def unblacklist_ip_command(args):
    ip = args.get('ip', None)
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
def whitelist_ip(ip, description):
    commands = {
        'command': 'new_whitelist',
        'entry': {
            'ip': ip,
            'description': description,
            'created': int(time.time())
        }
    }

    return http_request('/lists', commands)


@logger
def whitelist_ip_command(args):
    ip = args.get('ip', None)
    description = args.get('description', 'Added by ThreatX Demisto Integration')
    results = whitelist_ip(ip, description)

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
def unwhitelist_ip_command(args):
    ip = args.get('ip', None)
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
def get_entities_command(args):
    entity_name = args.get('entity_name', None)
    entity_id = args.get('entity_id', None)
    entity_ip = args.get('entity_ip', None)
    timeframe = args.get('timeframe', None)
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
def get_entity_notes_command(args):
    entity_id = args.get('entity_id', None)
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
def add_entity_note_command(args):
    entity_id = args.get('entity_id', None)
    message = args.get('message', None)
    results = add_entity_note(entity_id, message)

    md = tableToMarkdown('New Entity Note',
                         results,
                         ['Result'],
                         removeNull=True)

    return_outputs(md, {}, results)


@logger
def command_test_module():
    results = http_request('/users', {'command': 'list'})

    if not isinstance(results, list):
        raise DemistoException('Unrecognized response from ThreatX.')

    if not results:
        raise DemistoException('Empty response from ThreatX.')

    if 'username' not in results[0]:
        raise DemistoException('Unexpected response from ThreatX.')

    demisto.results('ok')


''' EXECUTION CODE '''


def main():
    global CUSTOMER_NAME, API_KEY, BASE_URL, DBOT_THRESHOLD, USE_SSL
    params = demisto.params()

    url = params.get('url', '').strip('/')
    BASE_URL = url + '/tx_api/v1'

    CUSTOMER_NAME = params.get('customer_name', None)
    API_KEY = params.get('api_key', None)
    DBOT_THRESHOLD = int(params.get('dbot_threshold', 70))
    USE_SSL = not params.get('insecure')

    command = demisto.command()
    demisto.info('command is {}'.format(command))
    args = demisto.args()
    try:
        handle_proxy()
        initialize()
        if command == 'test-module':
            command_test_module()
        elif command == 'threatx-block-ip':
            block_ip_command(args)
        elif command == 'threatx-unblock-ip':
            unblock_ip_command(args)
        elif command == 'threatx-blacklist-ip':
            blacklist_ip_command(args)
        elif command == 'threatx-unblacklist-ip':
            unblacklist_ip_command(args)
        elif command == 'threatx-whitelist-ip':
            whitelist_ip_command(args)
        elif command == 'threatx-unwhitelist-ip':
            unwhitelist_ip_command(args)
        elif command == 'threatx-get-entities':
            get_entities_command(args)
        elif command == 'threatx-get-entity-notes':
            get_entity_notes_command(args)
        elif command == 'threatx-add-entity-note':
            add_entity_note_command(args)

    except Exception as e:
        return_error(str(e), error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
