import re
import os
import shutil
import requests
from zipfile import ZipFile
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

VERSION = "v1.0.1"
USER_AGENT = "ReversingLabs XSOAR A1000 {version}".format(version=VERSION)

BASE_URL = demisto.getParam('base')
if BASE_URL[-1] == '/':
    BASE_URL = BASE_URL[0:-1]

HEADERS = {
    'Authorization': 'Token ' + demisto.getParam('token'),
    "User-Agent": USER_AGENT
}
EXTENDED = demisto.getParam('extended')
VERIFY_CERT = demisto.getParam('verify')
A1000_FIELDS = ('sha1', 'sha256', 'sha512', 'md5', 'category', 'file_type', 'file_subtype', 'identification_name',
                'identification_version', 'file_size', 'extracted_file_count', 'local_first_seen', 'local_last_seen',
                'classification_origin', 'classification_reason', 'threat_status', 'trust_factor', 'threat_level',
                'threat_name', 'summary', 'ticloud', 'aliases')

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


class NoReferenceFoundError(Exception):
    def __init__(self, message="No reference was found for this input"):
        super(NoReferenceFoundError, self).__init__(message)


no_rerence_object = NoReferenceFoundError()
no_reference_message = "{original_message} - {added_message}".format(
    original_message=str(no_rerence_object),
    added_message="Reply does not contain results"
)


def return_error(data):
    """
    Return error as result and exit - filter 404 as non-errors
    """
    if '404' in data or 'Reply does not contain results' in data:
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
    if 299 >= r.status_code >= 200:
        try:
            return True, r.json()
        except Exception as e:
            return False, 'HTTP response is not JSON [{error}] - {body}'.format(error=e, body=r.text)
    elif r.status_code in (401, 403):
        return False, 'Credential error - The provided A1000 credentials/token are either incorrect or lack ' \
                      'API roles [{code}] - {body}'.format(
                        code=r.status_code,
                        body=r.text
                        )
    elif r.status_code == 404:
        return False, 'No reference found - There were no results found for the provided input ' \
                      '[{code}] - {body}'.format(
                        code=r.status_code,
                        body=r.text
                        )
    else:
        return False, 'An error has occurred [{code}] - {body}'.format(
            code=r.status_code,
            body=r.text
        )


def file(hash_type, hash_value):
    """
    Get the summary data from A1000 with most of the fields except TICORE
    """
    ok, r = validate_http(requests.post(
        url=BASE_URL + '/api/samples/list/',
        headers=HEADERS,
        data={
            'hash_values': hash_value,
            'fields': A1000_FIELDS
        },
        verify=VERIFY_CERT
    ))
    if not ok:
        return_error(r)

    results = r.get('results')
    if not results:
        return_error(no_reference_message)

    res = results[0]
    status = res['threat_status']
    score = {'unknown': 0, 'known': 1, 'suspicious': 2, 'malicious': 3}[status]
    prop = status.title()
    file_data = {
        prop: {
            'Vendor': 'ReversingLabs A1000',
            'Status': status
        },
        'properties_to_append': prop
    }
    md = '## ReversingLabs A1000 reputation for: {}\n'.format(hash_value)
    ec = {'DBotScore': []}

    md5 = res.get('md5')
    sha1 = res.get('sha1')
    sha256 = res.get('sha256')
    sha512 = res.get('sha512')
    file_type = res.get('file_type')
    file_info = res.get('file_subtype')
    file_size = res.get('file_size')
    if md5:
        file_data['MD5'] = md5
        md += 'MD5: **' + md5 + '**\n'
        ec['DBotScore'].append({'Indicator': md5, 'Type': 'hash', 'Vendor': 'ReversingLabs A1000', 'Score': score})
    if sha1:
        file_data['SHA1'] = sha1
        md += 'SHA1: **' + sha1 + '**\n'
        ec['DBotScore'].append({'Indicator': sha1, 'Type': 'hash', 'Vendor': 'ReversingLabs A1000', 'Score': score})
    if sha256:
        file_data['SHA256'] = sha256
        md += 'SHA256: **' + sha256 + '**\n'
        ec['DBotScore'].append({'Indicator': sha256, 'Type': 'hash', 'Vendor': 'ReversingLabs A1000', 'Score': score})
    if sha512:
        file_data['SHA512'] = sha512
        md += 'SHA512: **' + sha512 + '**\n'
    if file_type:
        file_data['Type'] = file_type
    if file_info:
        file_data['Info'] = file_info
    if file_size:
        file_data['Size'] = file_size

    ec[outputPaths['file']] = file_data

    md += 'ID: **{}**\n'.format(demisto.get(res, 'summary.id'))
    md += 'Malware status: **{}**\n'.format(status)
    md += 'Local first seen: **{}**\n'.format(res.get('local_first_seen'))
    md += 'Local last seen: **{}**\n'.format(res.get('local_last_seen'))
    md += 'First seen: **{}**\n'.format(demisto.gets(res, 'ticloud.first_seen'))
    md += 'Last seen: **{}**\n'.format(demisto.gets(res, 'ticloud.last_seen'))
    md += 'Trust factor: **{}**\n'.format(res.get('trust_factor'))
    if status == 'malicious':
        md += 'Threat name: **{}**\n'.format(res.get('threat_name'))
        md += 'Threat level: **{}**\n'.format(res.get('threat_level'))
    md += 'Category: **{}**\n'.format(res.get('category'))
    md += 'Classification origin: **{}**\n'.format(res.get('classification_origin'))
    md += 'Classification reason: **{}**\n'.format(res.get('classification_reason'))
    md += 'Aliases: **{}**\n'.format(','.join(res.get('aliases')))
    md += 'Extracted file count: **{}**\n'.format(res.get('extracted_file_count'))
    md += 'File type: **{}/{}**\n'.format(file_type, file_info)
    md += 'File size: **{}**\n'.format(file_size)
    md += 'Identification name: **{}**\n'.format(res.get('identification_name'))
    md += 'Identification version: **{}**\n'.format(res.get('identification_version'))
    indicators = demisto.get(res, 'summary.indicators')
    if indicators:
        md += tableToMarkdown('Indicators', indicators)

    demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['json'], 'Contents': r, 'EntryContext': ec, 'HumanReadable': md})


def extracted_files():
    """
    Get the list of extracted files for a given sample
    """
    parent = demisto.getArg('hash')
    endpoint = '/api/samples/{}/extracted-files/'.format(parent)
    ok, r = validate_http(
        requests.get(
            url=BASE_URL + endpoint,
            headers=HEADERS,
            verify=VERIFY_CERT
        ))
    if not ok:
        return_error(r)

    results = r.get('results')
    if not results:
        return_error(no_reference_message)

    ec = {'DBotScore': []}
    file_list = []
    file_context_list = []
    for res in results:
        sha1 = demisto.get(res, 'sample.sha1')
        status = demisto.get(res, 'sample.threat_status')
        score = {'unknown': 0, 'known': 1, 'suspicious': 2, 'malicious': 3}[status]
        prop = status.title()
        file_data = {
            'SHA1': sha1,
            'Name': res.get('filename'),
            'Info': demisto.get(res, 'sample.type_display'),
            'Size': demisto.get(res, 'sample.file_size'),
            'Path': res.get('path'),
            'Local First': demisto.get(res, 'sample.local_first_seen'),
            'Local Last': demisto.get(res, 'sample.local_last_seen'),
            'Malware Status': status,
            'Trust': demisto.get(res, 'sample.trust_factor'),
            'Threat Name': demisto.get(res, 'sample.threat_name'),
            'Threat Level': demisto.get(res, 'sample.threat_level')
        }
        file_context = {
            'SHA1': sha1,
            'Type': demisto.get(res, 'sample.file_type'),
            'Name': res.get('filename'),
            'Info': demisto.get(res, 'sample.type_display'),
            'Size': demisto.get(res, 'sample.file_size'),
            prop: {
                'Vendor': 'ReversingLabs A1000',
                'Status': status
            },
            'properties_to_append': prop
        }
        file_list.append(file_data)
        file_context_list.append(file_context)
        ec['DBotScore'].append({'Indicator': sha1, 'Type': 'hash', 'Vendor': 'ReversingLabs A1000', 'Score': score})

    md = tableToMarkdown('ReversingLabs A1000 extracted files for: {}\n'.format(parent), file_data,
        ['SHA1', 'Name', 'Path', 'Info', 'Size', 'Local First', 'Local Last', 'Malware Status', 'Trust', 'Threat Name', 'Threat Level'])
    ec[outputPaths['file']] = file_context_list
    demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['json'], 'Contents': r, 'EntryContext': ec, 'HumanReadable': md})


def upload():
    """
    Upload a file to A1000 for analysis
    """
    data = {}
    if demisto.getArg('comment'):
        data['comment'] = demisto.getArg('comment')
    if demisto.getArg('tags'):
        data['tags'] = demisto.getArg('tags')
    cloud = demisto.getArg('cloud_analyze')
    if cloud and cloud.lower() == 'true':
        data['analysis'] = 'cloud'
    try:
        file_entry = demisto.getFilePath(demisto.getArg('entryId'))
        data['filename'] = file_entry['name']
        with open(file_entry['path'], 'rb') as f:
            ok, r = validate_http(requests.post(
                url=BASE_URL + '/api/uploads/',
                data=data,
                files={'file': f},
                headers=HEADERS,
                verify=VERIFY_CERT
            ))
            if not ok:
                return_error(r)
            md = '## ReversingLabs A1000 file upload\n'
            md += 'Message: **{}**\n'.format(r.get('message'))
            md += 'ID: **{}**\n'.format(demisto.get(r, 'detail.id'))
            md += 'SHA1: **{}**\n'.format(demisto.get(r, 'detail.sha1'))
            md += 'Created: **{}**\n'.format(demisto.get(r, 'detail.created'))
            demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['json'], 'Contents': r, 'HumanReadable': md})
    except:
        return_error('Entry ID {} is not a file'.format(demisto.getArg('entryId')))


def delete_sample():
    """
    Delete a file from A1000
    """
    ok, r = validate_http(requests.delete(
        url=BASE_URL + '/api/samples/{}/'.format(demisto.getArg('hash')),
        headers=HEADERS,
        verify=VERIFY_CERT
    ))
    if not ok:
        return_error(r)
    res = r.get('results')
    if not res:
        return_error('Deleted successfully but got wrong JSON reply')
    md = '## ReversingLabs A1000 file delete\n'
    md += 'Message: **{}**\n'.format(res.get('message'))
    md += 'MD5: **{}**\n'.format(demisto.get(res, 'detail.md5'))
    md += 'SHA1: **{}**\n'.format(demisto.get(res, 'detail.sha1'))
    md += 'SHA256: **{}**\n'.format(demisto.get(res, 'detail.sha256'))
    demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['json'], 'Contents': r, 'HumanReadable': md})


def download():
    """
    Download a sample from A1000
    """
    hash_value = demisto.getArg('hash')
    r = requests.get(
        url=BASE_URL + '/api/samples/{}/download/'.format(hash_value),
        headers=HEADERS,
        stream=True,
        verify=VERIFY_CERT
    )
    if r.status_code < 200 or r.status_code > 299:
        return_error('Bad HTTP response [{code}] - {body}'.format(code=r.status_code, body=r.text))
    filename = hash_value + '.bin'
    with open(filename, 'wb') as f:
        r.raw.decode_content = True
        shutil.copyfileobj(r.raw, f)
    demisto.results(file_result_existing_file(filename))


def reanalyze():
    """
    Re-Analyze a sample already existing on A1000
    """
    ok, r = validate_http(requests.post(
        url=BASE_URL + '/api/samples/{}/analyze/'.format(demisto.getArg('hash')),
        headers=HEADERS,
        data={'analysis': 'cloud'},
        verify=VERIFY_CERT
    ))
    if not ok:
        return_error(r)
    md = '## ReversingLabs A1000 file re-analyze\n'
    md += 'Message: **{}**\n'.format(r.get('message'))
    md += 'MD5: **{}**\n'.format(demisto.get(r, 'detail.md5'))
    md += 'SHA1: **{}**\n'.format(demisto.get(r, 'detail.sha1'))
    md += 'SHA256: **{}**\n'.format(demisto.get(r, 'detail.sha256'))
    demisto.results({'Type': entryTypes['note'], 'ContentsFormat': formats['json'], 'Contents': r, 'HumanReadable': md})


def unpacked():
    """
    Download samples obtained through the unpacking process
    """
    hash_value = demisto.getArg('hash')
    r = requests.get(
        url=BASE_URL + '/api/samples/{}/unpacked/'.format(hash_value),
        headers=HEADERS,
        stream=True,
        verify=VERIFY_CERT
    )
    if r.status_code < 200 or r.status_code > 299:
        return_error('Bad HTTP response [{code}] - {body}'.format(code=r.status_code, body=r.text))
    filename = hash_value + '.zip'
    with open(filename, 'wb') as f:
        r.raw.decode_content = True
        shutil.copyfileobj(r.raw, f)
    demisto.results(file_result_existing_file(filename))


if demisto.command() == 'test-module':
    ok, r = validate_http(requests.get(
        url=BASE_URL + '/api/samples/21841b32c6165b27dddbd4d6eb3a672defe54271/ticloud/',
        headers=HEADERS,
        verify=VERIFY_CERT
    ))
    if ok:
        demisto.results('ok')
    else:
        return_error(r)
elif demisto.command() == 'file':
    hash_value = demisto.args()['file']
    hash_type = validate_hash(hash_value)
    file(hash_type, hash_value)
elif demisto.command() == 'reversinglabs-upload':
    upload()
elif demisto.command() == 'reversinglabs-delete':
    delete_sample()
elif demisto.command() == 'reversinglabs-extracted-files':
    extracted_files()
elif demisto.command() == 'reversinglabs-download':
    download()
elif demisto.command() == 'reversinglabs-analyze':
    reanalyze()
elif demisto.command() == 'reversinglabs-download-unpacked':
    unpacked()
else:
    return_error('Command [{}] not implemented'.format(demisto.command()))
