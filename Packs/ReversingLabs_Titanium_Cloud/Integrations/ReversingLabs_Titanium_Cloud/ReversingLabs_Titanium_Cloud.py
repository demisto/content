import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
from requests.auth import HTTPBasicAuth
import re
import os


VERSION = "v1.0.1"
USER_AGENT = "ReversingLabs XSOAR TitaniumCloud {version}".format(version=VERSION)
HEADERS = {
        "User-Agent": USER_AGENT
    }

BASE_URL = demisto.params()['base']
if BASE_URL[-1] == '/':
    BASE_URL = BASE_URL[0:-1]
BASE_RL = demisto.params()['baserl']
if BASE_RL[-1] == '/':
    BASE_RL = BASE_RL[0:-1]
AUTH = HTTPBasicAuth(demisto.params()['credentials']['identifier'], demisto.params()['credentials']['password'])
EXTENDED = demisto.params()['extended']

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def get_score(classification):
    score_dict = {
        "UNKNOWN": 0,
        "KNOWN": 1,
        "SUSPICIOUS": 2,
        "MALICIOUS": 3
    }
    return score_dict.get(classification)


def return_error(data):
    """
    Return error as result and exit - filter 404 as non-errors
    """
    if '404' in data:
        demisto.results(
            {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': data
            }
        )
    else:
        demisto.results(
            {
                'Type': entryTypes['error'],
                'ContentsFormat': formats['text'],
                'Contents': data
            }
        )
    sys.exit(0)


def validate_hash(hash_value):
    """
    Validate that the given hash is valid and return the type
    """
    type_dict = {
        32: {
            'type': 'md5',
            'regex': r'([a-fA-F\d]{32})'
        },
        40: {
            'type': 'sha1',
            'regex': r'([a-fA-F\d]{40})'
        },
        64: {
            'type': 'sha256',
            'regex': r'([a-fA-F\d]{64})'
        }
    }
    if len(hash_value) not in type_dict.keys():
        return_error('Provided input string length does not match any hash type')
    if not re.match(type_dict[len(hash_value)]['regex'], hash_value):
        return_error('Provided input string is not as hash due to containing invalid characters')
    return type_dict[len(hash_value)]['type']


def validate_http(r):
    """
    Make sure that the HTTP response is valid and return relevant data if yes
    """
    if r.status_code == 200:
        try:
            return True, r.json()
        except Exception as e:
            return False, 'HTTP response is not JSON [{error}] - {body}'.format(error=e, body=r.text)
    elif r.status_code in (401, 403):
        return False, 'Credential error - The provided TitaniumCloud credentials are either incorrect or lack ' \
                      'API roles [{code}] - {body}'.format(
                        code=r.status_code,
                        body=r.text
                        )
    elif r.status_code == 404:
        return False, 'No reference found - There were no results found for the provided sample ' \
                      '[{code}] - {body}'.format(
                        code=r.status_code,
                        body=r.text
                        )
    else:
        return False, 'An error has occurred [{code}] - {body}'.format(
            code=r.status_code,
            body=r.text
        )


def rldata(hash_type, hash_value):
    """
    Get the extended RL data
    """
    endpoint = '/api/databrowser/rldata/query/{hash_type}/{hash_value}?format=json'.format(
        hash_value=hash_value,
        hash_type=hash_type
    )
    ok, r = validate_http(requests.get(
        BASE_RL + endpoint,
        auth=AUTH,
        headers=HEADERS
    ))
    if not ok:
        return ok, r
    contents = demisto.get(r, 'rl.sample')
    if not contents:
        return False, 'Unexpected JSON reply:\n' + str(r)
    md5 = contents.get('md5')
    sha1 = contents.get('sha1')
    sha256 = contents.get('sha256')
    sha512 = contents.get('sha512')
    ssdeep = contents.get('ssdeep')
    size = contents.get('sample_size')
    ec = {}
    md = '## ReversingLabs extended data\n'
    if md5:
        ec['MD5'] = md5
        md += 'MD5: **' + md5 + '**\n'
    if sha1:
        ec['SHA1'] = sha1
        md += 'SHA1: **' + sha1 + '**\n'
    if sha256:
        ec['SHA256'] = sha256
        md += 'SHA256: **' + sha256 + '**\n'
    if sha512:
        ec['SHA512'] = sha512
        md += 'SHA512: **' + sha512 + '**\n'
    if ssdeep:
        ec['SSDeep'] = ssdeep
        md += 'SSDEEP: **' + ssdeep + '**\n'
    if size:
        ec['Size'] = size
        md += 'Size: **' + str(size) + '**\n'
    scan_entries = demisto.get(contents, 'xref.entries')
    if len(scan_entries) > 0:
        # Sort by latest date
        scan_entries_sorted = sorted(scan_entries, key=lambda entry: entry['record_time'], reverse=True)
        scanners = scan_entries_sorted[0].get('scanners')
        if scanners:
            recent_detections = [item for item in scanners if item['result']]
            if recent_detections:
                md += '***\n'
                md += '#### Recent Detections ({record_time}):\n'.format(record_time=scan_entries_sorted[0].get('record_time'))
                md += "\n".join(['{} -- {}'.format(item['name'], item['result']) for item in recent_detections])
    return True, (md, ec, r)


def mwp(hash_type, hash_value):
    """
    Get the malware presence for the given hash
    """
    endpoint = '/api/databrowser/malware_presence/query/{hash_type}/{hash_value}?extended=true&format=json'.format(
        hash_value=hash_value,
        hash_type=hash_type
    )
    ok, r = validate_http(requests.get(
        BASE_URL + endpoint,
        auth=AUTH,
        headers=HEADERS
    ))
    if not ok:
        return ok, r
    contents = demisto.get(r, 'rl.malware_presence')
    if not contents:
        return False, 'Unexpected JSON reply:\n' + str(r)
    classification = contents["status"]
    md = '## ReversingLabs Malware Presence for {hash_value}\n'.format(hash_value=hash_value)
    md += 'Malware status: **{mwp_status}**\n'.format(mwp_status=contents['status'])
    md += 'First seen: **' + demisto.gets(contents, 'first_seen') + '**\n'
    md += 'Last seen: **' + demisto.gets(contents, 'last_seen') + '**\n'
    md += 'Positives / Total: **' + demisto.gets(contents, 'scanner_match') + ' / ' + demisto.gets(contents, 'scanner_count') + '**\n'
    md += 'Trust factor: **' + demisto.gets(contents, 'trust_factor') + '**\n'
    if contents['status'] == 'MALICIOUS':
        md += 'Threat name: **' + demisto.gets(contents, 'threat_name') + '**\n'
        md += 'Threat level: **' + demisto.gets(contents, 'threat_level') + '**\n'
    score = get_score(classification)
    prop = contents['status'].title()
    ec = {
        outputPaths['file']: {
            hash_type.upper(): hash_value,
            prop: {
                'Vendor': 'ReversingLabs',
                'Detections': demisto.gets(contents, 'scanner_match'),
                'TotalEngines': demisto.gets(contents, 'scanner_count')
            },
            'properties_to_append': prop
        },
        'DBotScore': [
            {
                'Indicator': hash_value,
                'Type': 'hash',
                'Vendor': 'ReversingLabs',
                'Score': score
            },
            {
                'Indicator': hash_value,
                'Type': 'file',
                'Vendor': 'ReversingLabs',
                'Score': score
            }
        ]
    }
    return True, (md, ec, r)


if demisto.command() == 'test-module':
    ok, r = validate_http(requests.get(BASE_URL + '/api/databrowser/malware_presence/query/md5/6a95d3d00267c9fd80bd42122738e726?extended=true&format=json', auth=AUTH))
    if ok:
        demisto.results('ok')
    else:
        return_error(r)
elif demisto.command() == 'file':
    hash_value = demisto.args()['file']
    hash_type = validate_hash(hash_value)
    ok, res = mwp(hash_type, hash_value)
    if not ok:
        return_error(res)
    md, ec, r = res
    if demisto.get(demisto.args(), 'extended'):
        EXTENDED = True if demisto.args()['extended'].lower() == 'true' else False
    if EXTENDED:
        ok, extended_res = rldata(hash_type, hash_value)
        if ok:
            md += '\n' + extended_res[0]
            r['rl']['sample'] = extended_res[2]['rl']['sample']
            # Add all the relevant context data
            score = ec['DBotScore'][0]['Score']
            for k in extended_res[1]:
                ec[outputPaths['file']][k] = extended_res[1][k]
                if k in ('MD5', 'SHA1', 'SHA256') and k.lower() != hash_type:
                    ec['DBotScore'].append({'Indicator': extended_res[1][k], 'Type': 'hash', 'Vendor': 'ReversingLabs', 'Score': score})
                    ec['DBotScore'].append({'Indicator': extended_res[1][k], 'Type': 'file', 'Vendor': 'ReversingLabs', 'Score': score})

    demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['json'], 'Contents': r, 'EntryContext': ec, 'HumanReadable': md})
