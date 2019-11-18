import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import xml.etree.ElementTree as ET  # type: ignore
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


"""GLOBAL VARIABLES/CONSTANTS"""
THRESHOLD = int(demisto.params().get('threshold'))
USE_SSL = not demisto.params().get('insecure', False)


"""COMMAND FUNCTIONS"""


def alexa_domain_command():
    domain = demisto.args().get('domain')
    resp = requests.request('GET', 'https://data.alexa.com/data'.format(domain), verify=USE_SSL)
    root = ET.fromstring(str(resp.content))
    try:
        rank = root.find("SD[0]/POPULARITY").attrib['TEXT']  # type: ignore
        if int(rank) > THRESHOLD:
            dbot_score = 2
            dbot_score_text = 'suspicious'
        else:
            dbot_score = 0
            dbot_score_text = 'unknown'
    except AttributeError:
        rank = 'Unknown'
        dbot_score = 2
        dbot_score_text = 'suspicious'
    dom_ec = {'Name': domain}
    dbot_ec = {
        'Score': dbot_score,
        'Vendor': 'Alexa Rank Indicator',
        'Domain': domain,
        'Type': 'domain'
    }
    ec = {
        'Domain(val.Name && val.Name == obj.Name)': dom_ec,
        'DBotScore': dbot_ec,
        'Alexa.Domain(val.Name && val.Name == obj.Domain.Name)': {
            'Name': domain,
            'Rank': rank
        }
    }
    hr_string = ('The Alexa rank of {} is {} and has been marked as {}'
                 ' while the threshold is {}'.format(domain, rank, dbot_score_text, THRESHOLD))
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': xml2json(resp.content),
        'HumanReadable': hr_string,
        'EntryContext': ec
    })


def test_module_command():
    domain = 'google.com'
    resp = requests.request('GET', 'https://data.alexa.com/data'.format(domain), verify=USE_SSL)
    root = ET.fromstring(str(resp.content))
    rank = root.find("SD[0]/POPULARITY").attrib['TEXT']  # type: ignore
    if rank == '1':
        result = 'ok'
    else:
        result = 'An error has occurred'
    return result


"""EXECUTION BLOCK"""
try:
    handle_proxy()
    if demisto.command() == 'test-module':
        test_result = test_module_command()
        demisto.results(test_result)
    if demisto.command() == 'domain':
        alexa_domain_command()
except Exception as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)
