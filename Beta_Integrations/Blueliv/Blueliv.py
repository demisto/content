import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

from sdk.blueliv_api import BluelivAPI

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
URL = demisto.params()['url'][:-1]
SERVER = URL if URL.endswith('/') else URL

''' HELPER FUNCTIONS '''


def verify_response_code(response):

    if response.status_code != 200:
        return_error(response.error_msg)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():

    response = api.crime_servers.last('all')
    verify_response_code(response)
    demisto.results('ok')


def get_botips_feed_command():

    response = api.bot_ips.recent('full')
    verify_response_code(response)
    human_readable = tableToMarkdown('Bot IP feed', response.items)
    return_outputs(human_readable, {})


def get_crimeservers_feed_command():

    response = api.crime_servers.last('all')
    verify_response_code(response)
    human_readable = tableToMarkdown('Crimeservers feed', response.items)
    return_outputs(human_readable, {})


def get_malware_feed_command():

    response = api.malwares.recent('all')
    verify_response_code(response)
    human_readable = tableToMarkdown('Malware feed', response.items)
    return_outputs(human_readable, {})


def get_attackingips_feed_command():

    response = api.attacking_ips.recent('all')
    verify_response_code(response)
    human_readable = tableToMarkdown('Attacking IPs feed', response.items)
    return_outputs(human_readable, {})


def get_hacktivism_feed_command():

    response = api.hacktivism_ops.last('all')
    verify_response_code(response)
    human_readable = tableToMarkdown('Hacktivism feed', response.items)
    return_outputs(human_readable, {})


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'blueliv-get-botips-feed': get_botips_feed_command,
    'blueliv-get-crimeservers-feed': get_crimeservers_feed_command,
    'blueliv-get-malware-feed': get_malware_feed_command,
    'blueliv-get-attackingips-feed': get_attackingips_feed_command,
    'blueliv-get-hacktivism-feed': get_hacktivism_feed_command
}

try:
    api = BluelivAPI(
        base_url=SERVER,
        token=TOKEN
    )
    LOG('Command being called is {}'.format(demisto.command()))
    command_func = COMMANDS.get(demisto.command())
    if command_func is not None:
        command_func()
except Exception:
    raise
