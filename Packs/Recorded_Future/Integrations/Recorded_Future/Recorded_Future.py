import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
import os
import json
import urllib
from datetime import datetime

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
TOKEN = demisto.params()['token']
SERVER = demisto.params()['server'][:-1] if demisto.params()['server'].endswith('/') else demisto.params()['server']
BASE_URL = SERVER + '/v2/'
USE_SSL = not demisto.params().get('unsecure', False)
HEADERS = {
    'X-RFToken': TOKEN,
    'X-RF-User-Agent': 'DemistoIntegrations+v1.0'
}
FILE_THRESHOLD = int(demisto.params()['file_threshold'])
IP_THRESHOLD = int(demisto.params()['ip_threshold'])
DOMAIN_THRESHOLD = int(demisto.params()['domain_threshold'])
URL_THRESHOLD = int(demisto.params()['url_threshold'])
CVE_THRESHOLD = int(demisto.params()['cve_threshold'])
SUSPICIOUS_THRESHOLD = int(demisto.params()['suspicious_threshold'])

FETCH_TIME = demisto.params().get('triggered').strip()
RULE_NAMES = demisto.params().get('rule_names').strip()

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None):
    LOG('running request with url=%s' % (BASE_URL + url_suffix))

    params = params if params is not None else {}

    try:
        res = requests.request(
            method,
            BASE_URL + url_suffix,
            params=params,
            headers=HEADERS,
            verify=USE_SSL
        )
        if res.status_code not in {200, 404}:
            if res.status_code == 401:
                error_str = 'Request failed with status 401 - Authentication error'
            else:
                error_str = 'Request failed, status: ' + str(res.status_code) + ', details: ' + res.text
            return_error(error_str)
    except Exception as e:
        LOG(e.message)
        return_error(e.message)
    return res.text


def translate_score(score, threshold):
    '''
    Translates Recorded Future score to DBot score
    '''
    if score >= threshold:  # Bad
        return 3
    elif score >= SUSPICIOUS_THRESHOLD:  # Suspicious
        return 2
    else:
        return 0  # Unknown


def determine_hash(hash):
    '''
    Determines hash type by length
    '''
    if len(hash) == 128:
        return 'SHA512'
    elif len(hash) == 64:
        return 'SHA256'
    elif len(hash) == 40:
        return 'SHA1'
    elif len(hash) == 32:
        return 'MD5'
    elif len(hash) == 8:
        return 'CRC32'
    else:
        return 'CTPH'


''' FUNCTIONS '''


def domain_command():
    domain = demisto.args().get('domain')
    detailed = False if demisto.args().get('detailed') == 'false' else True
    response = json.loads(domain_lookup(domain))
    if response and ('error' not in response):
        data = response['data']
        timestamps = data['timestamps']
        risk = data['risk']
        rf_score = risk['score']
        sightings = data['sightings']
        hr = '### Recorded Future domain reputation for ' + domain + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += 'First reference collected on: ' + timestamps.get('firstSeen') + '\n'
        hr += 'Latest reference collected on: ' + timestamps.get('lastSeen') + '\n'
        hr += '[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/idn:' + domain + ')' + '\n'
        hr_table = []
        community_notes = []
        publications = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
                community_notes.append({
                    'note': detail.get('evidenceString'),
                    'timestamp': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Evidence Summary', 'Rule Criticality', 'Rule Triggered', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)

            publications.append({
                'timestamp': raw_sighting.get('published'),
                'link': raw_sighting.get('url'),
                'source': raw_sighting.get('source'),
                'title': raw_sighting.get('title')
            })
        if sightings_table:
            hr += tableToMarkdown('References collected for this domain', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['domain']] = {
            'Name': domain,
            'Tags': risk.get('criticalityLabel'),
            'CommunityNotes': community_notes,
            'Publications': publications,
            'RecordedFuture': {
                'Criticality': risk.get('criticalityLabel'),
                'FirstSeen': timestamps.get('firstSeen'),
                'LastSeen': timestamps.get('lastSeen')
            }
        }
        dbot_score = translate_score(rf_score, DOMAIN_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': domain,
            'Type': 'domain',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['domain']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }
    else:
        hr = 'No records found'
        ec = {
            'DBotScore': {
                'Indicator': domain,
                'Type': 'domain',
                'Vendor': 'Recorded Future',
                'Score': 0
            }
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def domain_lookup(domain):
    cmd_url = 'domain/' + domain
    params = {
        'fields': 'sightings,timestamps,risk'
    }

    response = http_request('get', cmd_url, params=params)
    return response


def url_command():
    url = demisto.args().get('url')
    detailed = False if demisto.args().get('detailed') == 'false' else True
    response = json.loads(url_lookup(url))
    if response and ('error' not in response):
        data = response['data']
        timestamps = data['timestamps']
        risk = data['risk']
        rf_score = risk['score']
        sightings = data['sightings']
        encoded_url = urllib.quote_plus(url)
        hr = '### Recorded Future url reputation for ' + url + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += 'First reference collected on: ' + timestamps.get('firstSeen') + '\n'
        hr += 'Latest reference collected on: ' + timestamps.get('lastSeen') + '\n'
        hr += '[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/url:' + encoded_url + ')' + '\n'
        hr_table = []
        community_notes = []
        publications = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
                community_notes.append({
                    'note': detail.get('evidenceString'),
                    'timestamp': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Evidence Summary', 'Rule Criticality', 'Rule Triggered', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
            publications.append({
                'timestamp': raw_sighting.get('published'),
                'link': raw_sighting.get('url'),
                'source': raw_sighting.get('source'),
                'title': raw_sighting.get('title')
            })
        if sightings_table:
            hr += tableToMarkdown('References collected for this URL', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['url']] = {
            'Data': url,
            'Tags': risk.get('criticalityLabel'),
            'CommunityNotes': community_notes,
            'Publications': publications,
            'RecordedFuture': {
                'Criticality': risk.get('criticalityLabel'),
                'FirstSeen': timestamps.get('firstSeen'),
                'LastSeen': timestamps.get('lastSeen')
            }
        }
        dbot_score = translate_score(rf_score, URL_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': url,
            'Type': 'url',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['url']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }
    else:
        hr = 'No records found'
        ec = {
            'DBotScore': {
                'Indicator': url,
                'Type': 'url',
                'Vendor': 'Recorded Future',
                'Score': 0
            }
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def url_lookup(url):
    encoded_url = urllib.quote_plus(url)
    cmd_url = 'url/' + encoded_url
    params = {
        'fields': 'sightings,timestamps,risk'
    }

    response = http_request('get', cmd_url, params=params)
    return response


def ip_command():
    ip = demisto.args().get('ip')
    detailed = False if demisto.args().get('detailed') == 'false' else True
    response = json.loads(ip_lookup(ip))
    if response and ('error' not in response):
        data = response['data']
        timestamps = data['timestamps']
        risk = data['risk']
        rf_score = risk['score']
        sightings = data['sightings']
        hr = '### Recorded Future IP address reputation for ' + ip + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += 'First reference collected on: ' + timestamps.get('firstSeen') + '\n'
        hr += 'Latest reference collected on: ' + timestamps.get('lastSeen') + '\n'
        hr += '[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/ip:' + ip + ')' + '\n'
        evidence_table = []
        community_notes = []
        publications = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                evidence_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
                community_notes.append({
                    'note': detail.get('evidenceString'),
                    'timestamp': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', evidence_table,
                                  ['Evidence Summary', 'Rule Criticality', 'Rule Triggered', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
            publications.append({
                'timestamp': raw_sighting.get('published'),
                'link': raw_sighting.get('url'),
                'source': raw_sighting.get('source'),
                'title': raw_sighting.get('title')
            })
        if sightings_table:
            hr += tableToMarkdown('References collected for this IP', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['ip']] = {
            'Address': ip,
            'Tags': risk.get('criticalityLabel'),
            'CommunityNotes': community_notes,
            'Publications': publications,
            'RecordedFuture': {
                'Criticality': risk.get('criticalityLabel'),
                'FirstSeen': timestamps.get('firstSeen'),
                'LastSeen': timestamps.get('lastSeen')
            }
        }
        dbot_score = translate_score(rf_score, IP_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': ip,
            'Type': 'ip',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['ip']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }

    else:
        hr = 'No records found'
        ec = {
            'DBotScore': {
                'Indicator': ip,
                'Type': 'ip',
                'Vendor': 'Recorded Future',
                'Score': 0
            }
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def ip_lookup(ip):
    cmd_url = 'ip/' + ip

    params = {
        'fields': 'sightings,timestamps,risk'
    }

    response = http_request('get', cmd_url, params=params)
    return response


def file_command():
    file = demisto.args().get('file')
    detailed = False if demisto.args().get('detailed') == 'false' else True
    response = json.loads(file_lookup(file))
    if response and ('error' not in response):
        data = response['data']
        timestamps = data['timestamps']
        risk = data['risk']
        rf_score = risk['score']
        sightings = data['sightings']
        hr = '### Recorded Future file reputation for ' + file + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += 'First reference collected on: ' + timestamps.get('firstSeen') + '\n'
        hr += 'Latest reference collected on: ' + timestamps.get('lastSeen') + '\n'
        hr += '[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/hash:' + file + ')' + '\n'
        hr_table = []
        community_notes = []
        publications = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
                community_notes.append({
                    'note': detail.get('evidenceString'),
                    'timestamp': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Rule Triggered', 'Rule Criticality', 'Evidence Summary', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
            publications.append({
                'timestamp': raw_sighting.get('published'),
                'link': raw_sighting.get('url'),
                'source': raw_sighting.get('source'),
                'title': raw_sighting.get('title')
            })
        if sightings_table:
            hr += tableToMarkdown('References collected for this hash', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        hash_type = determine_hash(file)
        ec = {}
        ec[outputPaths['file']] = {
            hash_type: file,
            'Tags': risk.get('criticalityLabel'),
            'CommunityNotes': community_notes,
            'Publications': publications,
            'RecordedFuture': {
                'Criticality': risk['criticalityLabel'],
                'FirstSeen': timestamps['firstSeen'],
                'LastSeen': timestamps['lastSeen']
            }
        }
        dbot_score = translate_score(rf_score, FILE_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': file,
            'Type': 'file',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['file']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }

    else:
        hr = 'No records found'
        ec = {
            'DBotScore': {
                'Indicator': file,
                'Type': 'file',
                'Vendor': 'Recorded Future',
                'Score': 0
            }
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def file_lookup(file):
    cmd_url = 'hash/' + file

    params = {
        'fields': 'sightings,timestamps,risk'
    }
    response = http_request('get', cmd_url, params=params)
    return response


def get_related_entities_command():
    entity_value = demisto.args().get('entityValue')
    entity_result_type = demisto.args().get('resultEntityType')
    entity_type = demisto.args().get('entityType').lower()
    if entity_type == 'file':
        entity_type = 'hash'
    if entity_type == 'url':
        entity_value = urllib.quote_plus(entity_value)
    response = json.loads(get_related_entities(entity_value, entity_type))

    ec = {}
    if response and ('error' not in response):
        entity_result_type = entity_result_type.split(',')
        entity_types = []  # type: list
        if 'All' in entity_result_type:
            entity_types.extend(['RelatedIpAddress', 'RelatedInternetDomainName', 'RelatedHash', 'RelatedMalware',
                                 'RelatedAttackVector', 'RelatedURL'])
        else:
            if 'IP' in entity_result_type:
                entity_types.append('RelatedIpAddress')
            if 'Hash' in entity_result_type:
                entity_types.append('RelatedHash')
            if 'Domain' in entity_result_type:
                entity_types.append('RelatedInternetDomainName')
            if 'Attacker' in entity_result_type:
                entity_types.append('RelatedAttackVector')
            if 'Malware' in entity_result_type:
                entity_types.append('RelatedMalware')
            if 'URL' in entity_result_type:
                entity_types.append('RelatedURL')
        ip_outputs = []  # type: list
        hash_outputs = []  # type: list
        domain_outputs = []  # type: list
        attacker_outputs = []  # type: list
        malware_outputs = []  # type: list
        url_outputs = []  # type: list

        output_map = {
            'RelatedIpAddress': ip_outputs,
            'RelatedHash': hash_outputs,
            'RelatedInternetDomainName': domain_outputs,
            'RelatedAttackVector': attacker_outputs,
            'RelatedMalware': malware_outputs,
            'RelatedURL': url_outputs
        }
        related_entities = response['data']['relatedEntities']
        for related_entity in related_entities:
            if related_entity['type'] in entity_types:
                entities = related_entity['entities']
                for entity in entities:
                    hr_entity = {
                        'Count': entity['count'],
                        'ID': entity['entity']['id']
                    }

                    if related_entity['type'] == 'RelatedURL':
                        hr_entity['Data'] = entity['entity']['name']
                    else:
                        hr_entity['Name'] = entity['entity']['name']

                    output_map[related_entity['type']].append(hr_entity)
        hr_md = ''

        related_entities_ec = {}
        if ip_outputs:
            hr_md += tableToMarkdown('IP Address', ip_outputs)
            related_entities_ec['IPAddress'] = ip_outputs

        if hash_outputs:
            hr_md += tableToMarkdown('Hash', hash_outputs)
            related_entities_ec['Hash'] = hash_outputs

        if domain_outputs:
            hr_md += tableToMarkdown('Domain', domain_outputs)
            related_entities_ec['Domain'] = domain_outputs

        if attacker_outputs:
            hr_md += tableToMarkdown('Attacker', attacker_outputs)
            related_entities_ec['Attacker'] = attacker_outputs

        if malware_outputs:
            hr_md += tableToMarkdown('Malware', malware_outputs)
            related_entities_ec['Malware'] = malware_outputs

        if url_outputs:
            hr_md += tableToMarkdown('URL', url_outputs)
            related_entities_ec['URL'] = url_outputs

        if hr_md:
            hr_md = '### Recorded Future related entities to ' + entity_value + '\n' + hr_md
            if entity_type == 'ip':
                ec[outputPaths['ip']] = {
                    'Address': entity_value,
                    'RecordedFuture': {
                        'RelatedEntities': related_entities_ec
                    }
                }
            elif entity_type == 'domain':
                ec[outputPaths['domain']] = {
                    'Name': entity_value,
                    'RecordedFuture': {
                        'RelatedEntities': related_entities_ec
                    }
                }
            elif entity_type == 'hash':
                ec[outputPaths['file']] = {
                    determine_hash(entity_value): entity_value,
                    'RecordedFuture': {
                        'RelatedEntities': related_entities_ec
                    }
                }
            elif entity_type == 'url':
                ec[outputPaths['url']] = {
                    'Data': entity_value,
                    'RecordedFuture': {
                        'RelatedEntities': related_entities_ec
                    }
                }
        else:
            hr_md = 'No results found'
    else:
        hr_md = 'No results found'

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr_md,
        'EntryContext': ec
    })


def get_related_entities(entity_value, entity_type):
    cmd_url = entity_type + '/' + entity_value

    params = {
        'fields': 'relatedEntities'
    }
    response = http_request('get', cmd_url, params=params)
    return response


def hashlist_command():
    detailed = False if demisto.args().get('detailed') == 'false' else True
    limit = demisto.args().get('limit')
    risk_lower = demisto.args().get('risk_lower')
    risk_higher = demisto.args().get('risk_higher')
    orderby = demisto.args().get('orderby')
    direction = demisto.args().get('direction')

    response = json.loads(hashlist_lookup(limit, risk_lower, risk_higher, orderby, direction))
    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    resultlist = response['data'].get('results', [])
    if len(resultlist) == 0:
        demisto.results('No results found')
        return

    resultlist = response['data']['results']
    for result in resultlist:
        intelcard = result['intelCard']
        timestamps = result['timestamps']
        file = result['entity']['name']
        risk = result['risk']
        rf_score = risk['score']
        sightings = result['sightings']
        hr = '### Recorded Future file reputation for ' + file + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += '[Intelligence Card](' + intelcard + ')' + '\n'
        hr_table = []
        hash_type = determine_hash(file)
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Rule Triggered', 'Rule Criticality', 'Evidence Summary', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
        if sightings_table:
            hr += tableToMarkdown('References collected for this hash', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['file']] = {
            hash_type: file,
            'RecordedFuture': {
                'Criticality': risk['criticalityLabel'],
                'FirstSeen': timestamps['firstSeen'],
                'LastSeen': timestamps['lastSeen']
            }
        }
        dbot_score = translate_score(rf_score, FILE_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': file,
            'Type': 'file',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['file']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        })


def hashlist_lookup(limit, risk_lower, risk_higher, orderby, direction):
    cmd_url = 'hash/search'

    params = {
        'fields': 'entity,intelCard,risk,sightings,timestamps'
    }

    if limit:
        params['limit'] = limit
    if orderby:
        params['orderby'] = orderby
    if direction:
        params['direction'] = direction
    if risk_lower and risk_higher:
        params['riskScore'] = '[{},{}]'.format(risk_lower, risk_higher)

    response = http_request('get', cmd_url, params=params)
    return response


def iplist_command():
    detailed = False if demisto.args().get('detailed') == 'false' else True
    limit = demisto.args().get('limit')
    risk_lower = demisto.args().get('risk_lower')
    risk_higher = demisto.args().get('risk_higher')
    orderby = demisto.args().get('orderby')
    direction = demisto.args().get('direction')

    response = json.loads(iplist_lookup(limit, risk_lower, risk_higher, orderby, direction))
    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    resultlist = response['data'].get('results', [])
    if len(resultlist) == 0:
        demisto.results('No results found')
        return

    for result in resultlist:
        intelcard = result['intelCard']
        timestamps = result['timestamps']
        ip = result['entity']['name']
        risk = result['risk']
        rf_score = risk['score']
        sightings = result['sightings']
        hr = '### Recorded Future IP reputation for ' + ip + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += '[Intelligence Card](' + intelcard + ')' + '\n'
        hr_table = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Rule Triggered', 'Rule Criticality', 'Evidence Summary', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                raw_sighting['url'] = raw_sighting['url']
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
        if sightings_table:
            hr += tableToMarkdown('References collected for this IP', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['ip']] = {
            'Address': ip,
            'RecordedFuture': {
                'Criticality': risk.get('criticalityLabel'),
                'FirstSeen': timestamps.get('firstSeen'),
                'LastSeen': timestamps.get('lastSeen')
            }
        }
        dbot_score = translate_score(rf_score, IP_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': ip,
            'Type': 'ip',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['ip']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        })


def iplist_lookup(limit, risk_lower, risk_higher, orderby, direction):
    cmd_url = 'ip/search'

    params = {
        'fields': 'entity,intelCard,risk,sightings,timestamps'
    }

    if limit:
        params['limit'] = limit
    if orderby:
        params['orderby'] = orderby
    if direction:
        params['direction'] = direction
    if risk_lower and risk_higher:
        params['riskScore'] = '[{},{}]'.format(risk_lower, risk_higher)

    response = http_request('get', cmd_url, params=params)
    return response


def domainlist_command():
    detailed = False if demisto.args().get('detailed') == 'false' else True
    limit = demisto.args().get('limit')
    risk_lower = demisto.args().get('risk_lower')
    risk_higher = demisto.args().get('risk_higher')
    orderby = demisto.args().get('orderby')
    direction = demisto.args().get('direction')

    response = json.loads(domainlist_lookup(limit, risk_lower, risk_higher, orderby, direction))
    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    resultlist = response['data'].get('results', [])
    if len(resultlist) == 0:
        demisto.results('No results found')
        return

    for result in resultlist:
        timestamps = result['timestamps']
        domain = result['entity']['name']
        risk = result['risk']
        rf_score = risk['score']
        sightings = result['sightings']
        hr = '### Recorded Future Domain reputation for ' + domain + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += '[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/idn:' + domain + ')' + '\n'
        hr_table = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Rule Triggered', 'Rule Criticality', 'Evidence Summary', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
        if sightings_table:
            hr += tableToMarkdown('References collected for this domain', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['domain']] = {
            'Name': domain,
            'RecordedFuture': {
                'Criticality': risk.get('criticalityLabel'),
                'FirstSeen': timestamps.get('firstSeen'),
                'LastSeen': timestamps.get('lastSeen')
            }
        }
        dbot_score = translate_score(rf_score, DOMAIN_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': domain,
            'Type': 'domain',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['domain']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        })


def domainlist_lookup(limit, risk_lower, risk_higher, orderby, direction):
    cmd_url = 'domain/search'

    params = {
        'fields': 'entity,intelCard,risk,sightings,timestamps'
    }

    if limit:
        params['limit'] = limit
    if orderby:
        params['orderby'] = orderby
    if direction:
        params['direction'] = direction
    if risk_lower and risk_higher:
        params['riskScore'] = '[{},{}]'.format(risk_lower, risk_higher)

    response = http_request('get', cmd_url, params=params)
    return response


def urllist_command():
    detailed = False if demisto.args().get('detailed') == 'false' else True
    limit = demisto.args().get('limit')
    risk_lower = demisto.args().get('risk_lower')
    risk_higher = demisto.args().get('risk_higher')
    orderby = demisto.args().get('orderby')
    direction = demisto.args().get('direction')

    response = json.loads(urllist_lookup(limit, risk_lower, risk_higher, orderby, direction))
    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    resultlist = response['data'].get('results', [])
    if len(resultlist) == 0:
        demisto.results('No results found')
        return

    for result in resultlist:
        timestamps = result['timestamps']
        url = result['entity']['name']
        intelcard = urllib.quote_plus(url)
        risk = result['risk']
        rf_score = risk['score']
        sightings = result['sightings']
        hr = '### Recorded Future URL reputation for ' + url + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += '[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/url:' + intelcard + ')' + '\n'
        hr_table = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Rule Triggered', 'Rule Criticality', 'Evidence Summary', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
        if sightings_table:
            hr += tableToMarkdown('References collected for this URL', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['url']] = {
            'Data': url,
            'RecordedFuture': {
                'Criticality': risk.get('criticalityLabel'),
                'FirstSeen': timestamps.get('firstSeen'),
                'LastSeen': timestamps.get('lastSeen')
            }
        }
        dbot_score = translate_score(rf_score, URL_THRESHOLD)
        ec['DBotScore'] = {
            'Indicator': url,
            'Type': 'url',
            'Vendor': 'Recorded Future',
            'Score': dbot_score
        }
        if (dbot_score == 3):
            ec[outputPaths['url']]['Malicious'] = {
                'Vendor': 'Recorded Future',
                'Description': 'Score above ' + str(rf_score)
            }

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': response,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': hr,
            'EntryContext': ec
        })


def urllist_lookup(limit, risk_lower, risk_higher, orderby, direction):
    cmd_url = 'url/search'

    params = {
        'fields': 'entity,intelCard,risk,sightings,timestamps'
    }

    if limit:
        params['limit'] = limit
    if orderby:
        params['orderby'] = orderby
    if direction:
        params['direction'] = direction
    if risk_lower and risk_higher:
        params['riskScore'] = '[{},{}]'.format(risk_lower, risk_higher)

    response = http_request('get', cmd_url, params=params)
    return response


def vulnlist_command():
    detailed = False if demisto.args().get('detailed') == 'false' else True
    limit = demisto.args().get('limit')
    risk_lower = demisto.args().get('risk_lower')
    risk_higher = demisto.args().get('risk_higher')
    orderby = demisto.args().get('orderby')
    direction = demisto.args().get('direction')

    response = json.loads(vulnlist_lookup(limit, risk_lower, risk_higher, orderby, direction))
    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    resultlist = response['data'].get('results', [])
    if len(resultlist) == 0:
        demisto.results('No results found')
        return

    for result in resultlist:
        timestamps = result['timestamps']
        vuln = result['entity']['name']
        entity_id = result['entity']['id']
        risk = result['risk']
        rf_score = risk['score']
        sightings = result['sightings']
        hr = '### Recorded Future Vulnerability info for ' + vuln + '\n'
        hr += 'Risk score: ' + str(rf_score) + ' out of 99\n'
        hr += 'Criticality label: ' + risk.get('criticalityLabel') + '\n'
        hr += 'Summary: ' + risk.get('riskSummary') + '\n'
        hr += 'Total references to this entity: ' + str(len(sightings)) + '\n'
        hr += '[Intelligence Card](https://app.recordedfuture.com/live/sc/entity/' + entity_id + ')' + '\n'
        hr_table = []
        if detailed:
            evidence_details = risk['evidenceDetails']
            for detail in evidence_details:
                hr_table.append({
                    'Rule Criticality': detail.get('criticalityLabel'),
                    'Evidence Summary': detail.get('evidenceString'),
                    'Rule Triggered': detail.get('rule'),
                    'Rule Triggered Time': detail.get('timestamp')
                })
            hr += tableToMarkdown('Triggered Risk Rules', hr_table,
                                  ['Rule Triggered', 'Rule Criticality', 'Evidence Summary', 'Rule Triggered Time'])
        sightings_table = []
        for raw_sighting in sightings:
            sighting = {
                'Published': raw_sighting.get('published'),
                'Type': raw_sighting.get('type'),
                'Fragment': raw_sighting.get('fragment'),
                'Source': raw_sighting.get('source'),
                'Title': raw_sighting.get('title')
            }
            if raw_sighting['url']:
                sighting['URL'] = '[{}]({})'.format(raw_sighting['url'], raw_sighting['url'])
            sightings_table.append(sighting)
        if sightings_table:
            hr += tableToMarkdown('References collected for this vulnerability', sightings_table,
                                  ['Title', 'Source', 'Type', 'URL', 'Fragment', 'Published'])
        ec = {}
        ec[outputPaths['cve']] = {
            'ID': vuln,
            'RecordedFuture': {
                'Criticality': risk.get('criticalityLabel'),
                'FirstSeen': timestamps.get('firstSeen'),
                'LastSeen': timestamps.get('lastSeen')
            }
        }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    })


def vulnlist_lookup(limit, risk_lower, risk_higher, orderby, direction):
    cmd_url = 'vulnerability/search'

    params = {
        'fields': 'entity,intelCard,risk,sightings,timestamps'
    }

    if limit:
        params['limit'] = limit
    if orderby:
        params['orderby'] = orderby
    if direction:
        params['direction'] = direction
    if risk_lower and risk_higher:
        params['riskScore'] = '[{},{}]'.format(risk_lower, risk_higher)

    response = http_request('get', cmd_url, params=params)
    return response


def get_url_risklist_command():
    specific_list = demisto.args().get('list')

    res = get_url_risklist(specific_list)

    if not res:
        return_error('Received empty response')

    demisto.results(
        fileResult(filename='url_risk_list.csv', data=res.encode('utf-8'), file_type=entryTypes['entryInfoFile']))


def get_url_risklist(specific_list):
    cmd_url = 'url/risklist'

    params = {
        'format': 'csv/splunk'
    }

    if specific_list:
        params['list'] = specific_list

    return http_request('get', cmd_url, params=params)


def get_domain_risklist_command():
    specific_list = demisto.args().get('list')

    res = get_domain_risklist(specific_list)

    if not res:
        return_error('Received empty response')

    demisto.results(
        fileResult(filename='domain_risk_list.csv', data=res.encode('utf-8'), file_type=entryTypes['entryInfoFile']))


def get_domain_risklist(specific_list):
    cmd_url = 'domain/risklist'

    params = {
        'format': 'csv/splunk'
    }

    if specific_list:
        params['list'] = specific_list

    return http_request('get', cmd_url, params=params)


def get_ip_risklist_command():
    specific_list = demisto.args().get('list')

    res = get_ip_risklist(specific_list)

    if not res:
        return_error('Received empty response')

    demisto.results(
        fileResult(filename='ip_risk_list.csv', data=res.encode('utf-8'), file_type=entryTypes['entryInfoFile']))


def get_ip_risklist(specific_list):
    cmd_url = 'ip/risklist'

    params = {
        'format': 'csv/splunk'
    }

    if specific_list:
        params['list'] = specific_list

    return http_request('get', cmd_url, params=params)


def get_hash_risklist_command():
    specific_list = demisto.args().get('list')

    res = get_hash_risklist(specific_list)

    if not res:
        return_error('Received empty response')

    demisto.results(
        fileResult(filename='hash_list.csv', data=res.encode('utf-8'), file_type=entryTypes['entryInfoFile']))


def get_hash_risklist(specific_list):
    cmd_url = 'hash/risklist'

    params = {
        'format': 'csv/splunk'
    }

    if specific_list:
        params['list'] = specific_list

    return http_request('get', cmd_url, params=params)


def get_vulnerability_risklist_command():
    specific_list = demisto.args().get('list')

    res = get_vulnerability_risklist(specific_list)

    if not res:
        return_error('Received empty response')

    demisto.results(
        fileResult(filename='cve_risk_list.csv', data=res.encode('utf-8'), file_type=entryTypes['entryInfoFile']))


def get_vulnerability_risklist(specific_list):
    cmd_url = 'vulnerability/risklist'

    params = {
        'format': 'csv/splunk'
    }

    if specific_list:
        params['list'] = specific_list

    return http_request('get', cmd_url, params=params)


def get_domain_riskrules_command():
    response = json.loads(get_hash_riskrules())

    if not response or 'data' not in response:
        'No data found'

    headers = ['Name', 'Description', 'Count', 'Criticality']

    mapped_rules = [{
        'Name': r.get('name'),
        'Description': r.get('description'),
        'Count': r.get('count'),
        'Criticality': r.get('criticalityLabel')
    } for r in response['data'].get('results', [])]

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future Domain risk rules', mapped_rules, headers=headers,
                                         removeNull=True),
        'EntryContext': {
            'RecordedFuture.RiskRule.Domain(val.Name === obj.Name)': createContext(mapped_rules)
        }
    })


def get_domain_riskrules():
    cmd_url = 'domain/riskrules'

    res = http_request('get', cmd_url)

    return res


def get_hash_riskrules_command():
    response = json.loads(get_hash_riskrules())

    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    headers = ['Name', 'Description', 'Count', 'Criticality']

    mapped_rules = [{
        'Name': r.get('name'),
        'Description': r.get('description'),
        'Count': r.get('count'),
        'Criticality': r.get('criticalityLabel')
    } for r in response['data'].get('results', [])]

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future Hash risk rules', mapped_rules, headers=headers,
                                         removeNull=True),
        'EntryContext': {
            'RecordedFuture.RiskRule.Hash(val.Name === obj.Name)': createContext(mapped_rules)
        }
    })


def get_hash_riskrules():
    cmd_url = 'hash/riskrules'

    res = http_request('get', cmd_url)

    return res


def get_ip_riskrules_command():
    response = json.loads(get_ip_riskrules())

    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    headers = ['Name', 'Description', 'Count', 'Criticality']

    mapped_rules = [{
        'Name': r.get('name'),
        'Description': r.get('description'),
        'Count': r.get('count'),
        'Criticality': r.get('criticalityLabel')
    } for r in response['data'].get('results', [])]

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future IP risk rules', mapped_rules, headers=headers,
                                         removeNull=True),
        'EntryContext': {
            'RecordedFuture.RiskRule.IP(val.Name === obj.Name)': createContext(mapped_rules)
        }
    })


def get_ip_riskrules():
    cmd_url = 'ip/riskrules'

    res = http_request('get', cmd_url)

    return res


def get_url_riskrules_command():
    response = json.loads(get_url_riskrules())

    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    headers = ['Name', 'Description', 'Count', 'Criticality']

    mapped_rules = [{
        'Name': r.get('name'),
        'Description': r.get('description'),
        'Count': r.get('count'),
        'Criticality': r.get('criticalityLabel')
    } for r in response['data'].get('results', [])]

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future URL risk rules', mapped_rules, headers=headers,
                                         removeNull=True),
        'EntryContext': {
            'RecordedFuture.RiskRule.URL(val.Name === obj.Name)': createContext(mapped_rules)
        }
    })


def get_url_riskrules():
    cmd_url = 'url/riskrules'

    res = http_request('get', cmd_url)

    return res


def get_vulnerability_riskrules_command():
    response = json.loads(get_vulnerability_riskrules())

    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    headers = ['Name', 'Description', 'Count', 'Criticality']

    mapped_rules = [{
        'Name': r.get('name'),
        'Description': r.get('description'),
        'Count': r.get('count'),
        'Criticality': r.get('criticalityLabel')
    } for r in response['data'].get('results', [])]

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future Vulnerability risk rules', mapped_rules, headers=headers,
                                         removeNull=True),
        'EntryContext': {
            'RecordedFuture.RiskRule.Vulnerability(val.Name === obj.Name)': createContext(mapped_rules)
        }
    })


def get_vulnerability_riskrules():
    cmd_url = 'vulnerability/riskrules'

    res = http_request('get', cmd_url)

    return res


def get_alert_rules_command():
    rule_name = demisto.args().get('rule_name')
    limit = demisto.args().get('limit')

    response = json.loads(get_alert_rules(rule_name, limit))

    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    mapped_rules = [{
        'Name': r['title'],
        'ID': r['id']
    } for r in response['data'].get('results', [])]

    if len(mapped_rules) == 0:
        demisto.results('No results found')
        return

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future Alert rules', mapped_rules, removeNull=True),
        'EntryContext': {
            'RecordedFuture.AlertRule(val.ID === obj.ID)': createContext(mapped_rules)
        }
    })


def get_alert_rules(rule_name=None, limit=None):
    cmd_url = 'alert/rule'

    params = {}

    if rule_name:
        params['freetext'] = rule_name
    if limit:
        params['limit'] = limit

    return http_request('get', cmd_url, params=params)


def get_alerts_command():
    rule_id = demisto.args().get('rule_id')
    limit = demisto.args().get('limit')
    triggered = demisto.args().get('triggered_time')
    assignee = demisto.args().get('assignee')
    status = demisto.args().get('status')
    freetext = demisto.args().get('freetext')
    offset = demisto.args().get('offset')
    orderby = demisto.args().get('orderby')
    direction = demisto.args().get('direction')

    triggered_time = None
    if triggered:
        date, _ = parse_date_range(triggered, date_format='%Y-%m-%d %H:%M:%S')
        triggered_time = '[{},)'.format(date)

    response = json.loads(
        get_alerts(rule_id, triggered_time, limit, assignee, status, freetext, offset, orderby, direction))

    if not response or 'data' not in response:
        demisto.results('No results found')
        return

    headers = ['ID', 'Name', 'Type', 'Triggered', 'Status', 'Assignee', 'Rule']

    mapped_alerts = [{
        'ID': a['id'],
        'Name': a['title'],
        'Type': a['type'],
        'Triggered': a['triggered'],
        'Status': a.get('review', {}).get('status'),
        'Assignee': a.get('review', {}).get('assignee'),
        'Rule': a.get('rule', {}).get('name')
    } for a in response['data'].get('results', [])]

    if len(mapped_alerts) == 0:
        demisto.results('No results found')
        return

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future Alerts', mapped_alerts, headers=headers, removeNull=True),
        'EntryContext': {
            'RecordedFuture.Alert(val.ID === obj.ID)': createContext(mapped_alerts)
        }
    })


def get_alerts(rule_id=None, triggered=None, limit=None, assignee=None, status=None, freetext=None, offset=None,
               orderby=None, direction=None):
    cmd_url = 'alert/search'

    params = {}

    if rule_id:
        params['alertRule'] = rule_id
    if limit:
        params['limit'] = limit
    if triggered:
        params['triggered'] = triggered
    if assignee:
        params['assignee'] = assignee
    if status:
        params['status'] = status
    if freetext:
        params['freetext'] = freetext
    if offset:
        params['from'] = offset
    if orderby:
        params['orderby'] = orderby
    if direction:
        params['direction'] = direction

    return http_request('get', cmd_url, params=params)


def get_alert(alert_id):
    cmd_url = 'alert/' + alert_id

    return http_request('get', cmd_url)


def fetch_incidents():
    if RULE_NAMES:
        rule_names = RULE_NAMES.split(';')
    else:
        rule_names = []

    if FETCH_TIME:
        fetch_time = FETCH_TIME
    else:
        fetch_time = '24 hours'

    last_run = demisto.getLastRun()
    if not last_run:
        last_run = {}
    if 'time' not in last_run:
        time, _ = parse_date_range(fetch_time, date_format='%Y-%m-%dT%H:%M:%S.%fZ')
    else:
        time = last_run['time']

    current_time = datetime.strptime(time, '%Y-%m-%dT%H:%M:%S.%fZ')
    triggered_time = '[{},)'.format(datetime.strftime(current_time, '%Y-%m-%d %H:%M:%S'))
    max_time = current_time

    rule_ids = []  # type: list

    for rule in rule_names:
        rules = json.loads(get_alert_rules(rule))
        if rules and 'data' in rules:
            rule_ids += map(lambda r: r['id'], rules['data'].get('results', []))

    all_alerts = []  # type: list
    if rule_ids:
        for rule_id in rule_ids:
            alerts = json.loads(get_alerts(rule_id, triggered_time))
            if alerts and 'data' in alerts:
                all_alerts += alerts['data'].get('results', [])
    else:
        alerts = json.loads(get_alerts(triggered=triggered_time))
        if alerts and 'data' in alerts:
            all_alerts += alerts['data'].get('results', [])

    incidents = []
    for alert in all_alerts:
        alert_time = datetime.strptime(alert['triggered'], '%Y-%m-%dT%H:%M:%S.%fZ')
        # The API returns also alerts that are triggered in the same time
        if alert_time > current_time:
            alert_data = json.loads(get_alert(alert['id']))
            if alert_data and 'data' in alert_data:
                alert = alert_data['data']
            incidents.append({
                'name': 'Recorded Future Alert - ' + alert['title'],
                'occurred': datetime.strftime(alert_time, '%Y-%m-%dT%H:%M:%SZ'),
                'rawJSON': json.dumps(alert)
            })

            if alert_time > max_time:
                max_time = alert_time

    demisto.incidents(incidents)
    demisto.setLastRun({
        'time': datetime.strftime(max_time, '%Y-%m-%dT%H:%M:%S.%fZ')
    })


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(),))

try:
    if demisto.command() == 'test-module':
        try:
            res = json.loads(ip_lookup('8.8.8.8'))
        except Exception as ex:
            return_error('Failed to get response. The URL might be incorrect.' + str(ex))
        demisto.results('ok')

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

    elif demisto.command() == 'domain':
        domain_command()

    elif demisto.command() == 'url':
        url_command()

    elif demisto.command() == 'ip':
        ip_command()

    elif demisto.command() == 'file':
        file_command()

    elif demisto.command() == 'recorded-future-get-related-entities':
        get_related_entities_command()

    elif demisto.command() == 'recorded-future-get-threats-hash':
        hashlist_command()

    elif demisto.command() == 'recorded-future-get-threats-ip':
        iplist_command()

    elif demisto.command() == 'recorded-future-get-threats-url':
        urllist_command()

    elif demisto.command() == 'recorded-future-get-threats-domain':
        domainlist_command()

    elif demisto.command() == 'recorded-future-get-threats-vulnerabilities':
        vulnlist_command()

    elif demisto.command() == 'recorded-future-get-url-risklist':
        get_url_risklist_command()

    elif demisto.command() == 'recorded-future-get-domain-risklist':
        get_domain_risklist_command()

    elif demisto.command() == 'recorded-future-get-ip-risklist':
        get_ip_risklist_command()

    elif demisto.command() == 'recorded-future-get-vulnerability-risklist':
        get_vulnerability_risklist_command()

    elif demisto.command() == 'recorded-future-get-hash-risklist':
        get_hash_risklist_command()

    elif demisto.command() == 'recorded-future-get-domain-riskrules':
        get_domain_riskrules_command()

    elif demisto.command() == 'recorded-future-get-hash-riskrules':
        get_hash_riskrules_command()

    elif demisto.command() == 'recorded-future-get-ip-riskrules':
        get_ip_riskrules_command()

    elif demisto.command() == 'recorded-future-get-url-riskrules':
        get_url_riskrules_command()

    elif demisto.command() == 'recorded-future-get-vulnerability-riskrules':
        get_vulnerability_riskrules_command()

    elif demisto.command() == 'recorded-future-get-alert-rules':
        get_alert_rules_command()

    elif demisto.command() == 'recorded-future-get-alerts':
        get_alerts_command()

except Exception as e:
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
