import demistomock as demisto
from CommonServerPython import *
import re
import sys

from urllib.parse import parse_qs, unquote, urlparse

valid_versions = ['v1', 'v2']


def find_version(url):
    match = re.search(r'https://urldefense.proofpoint.com/(?P<version>v[0-9])/', url)
    return match.group('version')  # type: ignore


def ppdecode(url):
    try:
        version = find_version(url)
    except AttributeError:
        return_error('This does not appear to be a valid proofpoint url: {}'.format(url))
    else:
        if version not in valid_versions:
            return_error('Ppdecode is unprepared to handle this version of proofpoint urls: {}'.format(url))
    parsed_url = urlparse(url)
    query_components = parse_qs(parsed_url.query)  # type: ignore
    if 'u' in query_components:
        if sys.version_info[0] < 3:
            translated_url = query_components['u'][0].translate(str.maketrans('-_', '%/'))
        else:
            translated_url = query_components['u'][0].translate(str.maketrans('-_', '%/'))
    else:
        return_error('A URL was not detected in the query.')
    decoded_url = unquote(translated_url)
    query_components['decoded_url'] = decoded_url  # type: ignore
    query_components['proofpoint_version'] = version
    return query_components


try:
    results = ppdecode(demisto.args()['url'])
    ec = {'URL': {'Data': results['decoded_url']}}
    demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': results,
                     'EntryContext': ec, 'HumanReadable': '#### Decoded URL\n' + results['decoded_url']})


except RuntimeError as e:
    return_error(str(e))
