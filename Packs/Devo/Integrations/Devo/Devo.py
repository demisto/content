import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import hashlib
import hmac
import json
import socket
import struct
import time
from collections import Counter
from datetime import datetime

import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBAL VARS '''
API_KEY = demisto.params()['api_key']
API_SECRET = demisto.params()['api_secret']
VERIFY_SSL = not demisto.params().get('unsecure', False)
SERVER = demisto.params().get('url')[:-1] if demisto.params().get('url').endswith('/') \
    else demisto.params().get('url')

SERVER_URL = SERVER + '/search'

''' HELPER FUNCTIONS '''


def get_api_sign(timestamp, body):
    message = API_KEY
    if body:
        message += json.dumps(body)
    message += str(timestamp)
    sign = hmac.new(API_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256)

    return sign.hexdigest()


def get_headers(body=''):
    headers = {
        'Content-Type': 'application/json'
    }
    timestamp = int(round(time.time() * 1000))

    headers['x-logtrust-apikey'] = API_KEY
    headers['x-logtrust-timestamp'] = str(timestamp)
    headers['x-logtrust-sign'] = get_api_sign(timestamp, body)

    return headers


def send_request(path, headers=get_headers(), method='get', body=None, params=None):
    body = body if body is not None else {}
    params = params if params is not None else {}
    url = '{}/{}'.format(SERVER_URL, path)

    res = requests.request(method, url, headers=headers, data=json.dumps(body), params=params, verify=VERIFY_SSL)

    if res.status_code < 200 or res.status_code >= 300:
        raise Exception('Got status code {} with url {} with body {} with headers {}'.format(
            str(res.status_code), url, res.content, str(res.headers)))

    try:
        return res.json()
    except Exception:
        return res.content


def get_timestamp_in_seconds(timestamp):
    dt = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ').timetuple()
    return int(time.mktime(dt))


''' FUNCTIONS '''


def query_command():
    query = demisto.args().get('query')
    query_id = demisto.args().get('queryId')
    timestamp_from = demisto.args()['from']
    timestamp_to = demisto.args().get('to', datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
    skip = demisto.args().get('skip')
    limit = demisto.args().get('limit')
    write_context = demisto.args()['writeToContext'].lower()

    if (not query and not query_id) or (query and query_id):
        raise ValueError('Query or query id must be specified')

    res = do_query(query, query_id, timestamp_from, timestamp_to, skip, limit)

    entry = {
        'Type': entryTypes['note'],
        'Contents': res,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown']
    }

    if 'object' not in res or not res['object'] or len(res['object']) == 0:
        entry['HumanReadable'] = 'No results found'
        return entry

    results = []
    for result in res['object']:
        if 'eventdate' in result:
            result['eventdate'] = datetime.fromtimestamp(result['eventdate'] / 1000).strftime('%Y-%m-%dT%H:%M:%SZ')
        # temporary
        if 'srcIp' in result:
            try:
                decimal_ip = int(result['srcIp'])
                # Convert decimal IP to IP
                result['srcIp'] = socket.inet_ntoa(struct.pack('!L', int(decimal_ip))) if decimal_ip else ''
            except Exception:
                pass
        results.append(result)

    # remove duplicates and add a count of them instead
    unique_results = [dict(t + (('eventcount', c),)) for t, c in Counter(tuple(r.items()) for r in results).items()]

    headers = res['object'][0].keys()
    if 'eventdate' in headers:
        # set event date as first column
        headers.remove('eventdate')
        headers = ['eventdate'] + headers
    if 'eventcount' not in headers:
        headers.append('eventcount')

    md = tableToMarkdown('Devo query results', unique_results, headers, removeNull=True)

    entry['HumanReadable'] = md
    if write_context == 'true':
        entry['EntryContext'] = {
            'Devo.Results': createContext(unique_results, removeNull=True)
        }

    return entry


def do_query(query, query_id, timestamp_from, timestamp_to, skip, limit):
    query_body = {
        'from': get_timestamp_in_seconds(timestamp_from)
    }

    if query:
        query_body['query'] = query
    elif query_id:
        query_body['queryId'] = query_id

    if timestamp_to:
        query_body['to'] = get_timestamp_in_seconds(timestamp_to)
    if skip:
        query_body['skip'] = skip
    if limit:
        query_body['limit'] = limit

    path = 'query'
    headers = get_headers(query_body)

    return send_request(path, headers, 'post', query_body)


''' EXECUTION CODE '''
try:
    if demisto.command() == 'test-module':
        path = 'system/ping'
        send_request(path)
        demisto.results('ok')
    elif demisto.command() == 'devo-query':
        demisto.results(query_command())
except Exception as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)
