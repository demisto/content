import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import xml.etree.ElementTree as ET  # type: ignore
import requests
import re

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

"""COMMAND FUNCTIONS"""


def alexa_fallback_command(domain, use_ssl, proxies):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, '
                      'like Gecko) Chrome/85.0.4183.121 Safari/537.36'
    }
    resp = requests.request('GET', 'https://www.alexa.com/minisiteinfo/{}'.format(domain),
                            headers=headers, verify=use_ssl, proxies=proxies)
    try:
        x = re.search(r"style=\"margin-bottom:-2px;\"\/>\s(\d{0,3},)?(\d{3},)?\d{0,3}<\/a>", resp.content)
        raw_result = x.group()  # type:ignore
        strip_beginning = raw_result.replace('style="margin-bottom:-2px;"/> ', '')
        strip_commas = strip_beginning.replace(',', '')
        formatted_result = strip_commas.replace('</a>', '')
    except:  # noqa
        formatted_result = '-1'
    return formatted_result


def alexa_domain_command(domain, use_ssl, proxies, threshold, benign, reliability):
    try:
        resp = requests.request('GET',
                                'https://data.alexa.com/data?cli=10&dat=s&url={}'.format(domain),
                                verify=use_ssl, proxies=proxies)
        root = ET.fromstring(str(resp.content))
        rank = root.find(".//POPULARITY").attrib['TEXT']  # type: ignore
    except:  # noqa
        rank = alexa_fallback_command(domain, use_ssl, proxies)

    if 0 < int(rank) <= benign:
        dbot_score = 1
        dbot_score_text = 'good'
    elif int(rank) > threshold:
        dbot_score = 2
        dbot_score_text = 'suspicious'
    elif (int(rank) < threshold) and rank != '-1':
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
            'Type': 'domain',
            "Reliability": reliability
        },
        'Alexa.Domain(val.Name && val.Name == obj.Domain.Name)': {
            'Name': domain,
            'Indicator': domain,
            'Rank': rank
        }
    }
    hr_string = ('The Alexa rank of {} is {} and has been marked as {}. '
                 'The benign threshold is {} while the suspicious '
                 'threshold is {}.'.format(domain, rank, dbot_score_text, benign, threshold))
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': ec,
        'HumanReadable': hr_string,
        'EntryContext': ec
    })


def test_module_command(use_ssl, proxies):
    domain = 'google.com'
    try:
        resp = requests.request('GET',
                                'https://data.alexa.com/data?cli=10&dat=s&url={}'.format(domain),
                                verify=use_ssl, proxies=proxies)
        root = ET.fromstring(str(resp.content))
        rank = root.find(".//POPULARITY").attrib['TEXT']  # type: ignore
    except:  # noqa
        rank = alexa_fallback_command(domain, use_ssl, proxies)
    if rank == '1':
        result = 'ok'
    else:
        result = 'An error has occurred'
    return result


"""EXECUTION BLOCK"""
try:
    params = demisto.params()

    instance_params = {
        'threshold': int(params.get('threshold', 2000000)),
        'benign': int(params.get('benign', 0)),
        'use_ssl': not params.get('insecure', False),
        'proxies': handle_proxy()
    }
    reliability = params.get('integrationReliability', DBotScoreReliability.A) or DBotScoreReliability.A

    if DBotScoreReliability.is_valid_type(reliability):
        instance_params['reliability'] = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    if demisto.command() == 'test-module':
        test_result = test_module_command(instance_params['use_ssl'], instance_params['proxies'])
        demisto.results(test_result)
    if demisto.command() == 'domain':
        domain = demisto.args().get('domain')
        alexa_domain_command(domain, **instance_params)
except Exception as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)
