import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import xml.etree.ElementTree as ET  # type: ignore
import requests
import re

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

"""GLOBAL VARIABLES/CONSTANTS"""
THRESHOLD = int(demisto.params().get('threshold'))
BENIGN = int(demisto.params().get('benign'), 0)
USE_SSL = not demisto.params().get('insecure', False)
PROXIES = handle_proxy()

"""COMMAND FUNCTIONS"""


def alexa_fallback_command(domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, '
                      'like Gecko) Chrome/85.0.4183.121 Safari/537.36'
    }
    resp = requests.request('GET', 'https://www.alexa.com/minisiteinfo/{}'.format(domain),
                            headers=headers, verify=USE_SSL, proxies=PROXIES)
    try:
        x = re.search(r"style=\"margin-bottom:-2px;\"\/>\s(\d{0,3},)?(\d{3},)?\d{0,3}<\/a>", resp.content)
        raw_result = x.group()  # type:ignore
        strip_beginning = raw_result.replace('style="margin-bottom:-2px;"/> ', '')
        strip_commas = strip_beginning.replace(',', '')
        formatted_result = strip_commas.replace('</a>', '')
    except:  # noqa
        formatted_result = '-1'
    return formatted_result


def alexa_domain_command():
    domain = demisto.args().get('domain')
    try:
        resp = requests.request('GET',
                                'https://data.alexa.com/data?cli=10&dat=s&url={}'.format(domain),
                                verify=USE_SSL, proxies=PROXIES)
        root = ET.fromstring(str(resp.content))
        rank = root.find(".//POPULARITY").attrib['TEXT']  # type: ignore
    except:  # noqa
        rank = alexa_fallback_command(domain)
    if int(rank) <= BENIGN:
        dbot_score = 1
        dbot_score_text = 'good'
    elif int(rank) > THRESHOLD:
        dbot_score = 2
        dbot_score_text = 'suspicious'
    elif (int(rank) < THRESHOLD) and rank != '-1':
        dbot_score = 0
        dbot_score_text = 'unknown'
    else:
        rank = 'Unknown'
        dbot_score = 2
        dbot_score_text = 'suspicious'
    dom_ec = {'Name': domain}
    ec = {
        'Domain(val.Name && val.Name == obj.Name)': dom_ec,
        'DBotScore': {
            'Score': dbot_score,
            'Vendor': 'Alexa Rank Indicator',
            'Domain': domain,
            'Indicator': domain,
            'Type': 'domain'
        },
        'Alexa.Domain(val.Name && val.Name == obj.Domain.Name)': {
            'Name': domain,
            'Indicator': domain,
            'Rank': rank
        }
    }
    hr_string = ('The Alexa rank of {} is {} and has been marked as {}. '
                 'The benign threshold is {} while the suspicious '
                 'threshold is {}.'.format(domain, rank, dbot_score_text, BENIGN, THRESHOLD))
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': ec,
        'HumanReadable': hr_string,
        'EntryContext': ec
    })


def test_module_command():
    domain = 'google.com'
    try:
        resp = requests.request('GET',
                                'https://data.alexa.com/data?cli=10&dat=s&url={}'.format(domain),
                                verify=USE_SSL, proxies=PROXIES)
        root = ET.fromstring(str(resp.content))
        rank = root.find(".//POPULARITY").attrib['TEXT']  # type: ignore
    except:  # noqa
        rank = alexa_fallback_command(domain)
    if rank == '1':
        result = 'ok'
    else:
        result = 'An error has occurred'
    return result


"""EXECUTION BLOCK"""
try:
    if demisto.command() == 'test-module':
        test_result = test_module_command()
        demisto.results(test_result)
    if demisto.command() == 'domain':
        alexa_domain_command()
except Exception as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)
