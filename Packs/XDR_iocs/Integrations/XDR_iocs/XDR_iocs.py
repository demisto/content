import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import hashlib
import secrets
import string
import tempfile
from datetime import timezone
from typing import Dict, Optional, List, Tuple
from dateutil.parser import parse
from urllib3 import disable_warnings
from math import ceil


disable_warnings()


class Client:
    severity = ''
    query = 'type:File and (sha256:* or (-sha1:* and md5:*)) or type:Domain or type:IP'
    error_codes = {
        500: 'XDR internal server error.',
        401: 'Unauthorized access. An issue occurred during authentication. This can indicate an ' +    # noqa: W504
             'incorrect key, id, or other invalid authentication parameters.',
        402: 'Unauthorized access. User does not have the required license type to run this API.',
        403: 'Unauthorized access. The provided API key does not have the required RBAC permissions to run this API'
    }

    def __init__(self, params: Dict):
        self._base_url = urljoin(params.get('url'), '/public_api/v1/indicators/')
        self._verify_cert = not params.get('insecure', False)
        self._headers = get_headers(params)
        self._proxy = params.get('proxy', False)
        if self._proxy:
            self._proxy = handle_proxy()

    def http_request(self, url_suffix: str, requests_kwargs):
        url = f'{self._base_url}{url_suffix}'
        res = requests.post(url=url,
                            verify=self._verify_cert,
                            headers=self._headers,
                            **requests_kwargs)

        if res.status_code in self.error_codes:
            raise DemistoException(f'{self.error_codes[res.status_code]}\t({res.content.decode()})')

        return res.json()


def get_headers(params: Dict) -> Dict:
    api_key = params.get('apikey')
    api_key_id = params.get('apikey_id')
    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
    auth_key = "%s%s%s" % (api_key, nonce, timestamp)
    auth_key = auth_key.encode("utf-8")
    api_key_hash = hashlib.sha256(auth_key).hexdigest()

    headers = {
        "x-xdr-timestamp": timestamp,
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash,
        "x-iocs-source": "xsoar"
    }

    return headers


def get_requests_kwargs(_json=None, file_path: Optional[str] = None) -> Dict:
    if _json is not None:
        return {'data': json.dumps({"request_data": _json})}
    elif file_path is not None:
        return {'files': [('file', ('iocs.json', open(file_path, 'rb'), 'application/json'))]}
    else:
        return {}


def prepare_get_changes(time_stamp: int) -> Tuple[str, Dict]:
    url_suffix: str = 'get_changes'
    _json: Dict = {'last_update_ts': time_stamp}
    return url_suffix, _json


def prepare_enable_iocs(iocs: str) -> Tuple[str, List]:
    url_suffix: str = 'enable_iocs'
    _json: List = iocs.split(',')
    return url_suffix, _json


def prepare_disable_iocs(iocs: str) -> Tuple[str, List]:
    url_suffix: str = 'disable_iocs'
    _json: List = iocs.split(',')
    return url_suffix, _json


def create_file_iocs_to_keep(file_path):
    with open(file_path, 'a') as _file:
        total_size = demisto.searchIndicators(query='', page=0, size=1).get('total', 0)
        batch_size = 200
        for i in range(0, ceil(total_size / batch_size)):
            iocs = demisto.searchIndicators(query='', page=i, size=batch_size).get('iocs', [])
            for ios in map(lambda x: x.get('value'), iocs):
                _file.write(ios)
                _file.write('\n')


def create_file_sync(file_path):
    with open(file_path, 'a') as _file:
        total_size = get_iocs_size()
        batch_size = 200
        for i in range(0, ceil(total_size / batch_size)):
            iocs = get_iocs(page=i, size=batch_size)
            for ios in map(lambda x: json.dumps(demisto_ioc_to_xdr(x)), iocs):
                _file.write(ios)
                _file.write('\n')


demisto_score_to_xdr = {
    1: 'GOOD',
    2: 'SUSPICIOUS',
    3: 'BAD'
}


def get_iocs_size(from_date=None, to_date=None):
    return demisto.searchIndicators(query=Client.query, page=0, size=1, fromDate=from_date, toDate=to_date).get('total', 0)


def get_iocs(page=0, size=200, from_date=None, to_date=None):
    return demisto.searchIndicators(query=Client.query, page=page, size=size,
                                    fromDate=from_date, toDate=to_date).get('iocs', [])


def demisto_expiration_to_xdr(expiration):
    if expiration and not expiration.startswith('0001'):
        try:
            return int(parse(expiration).astimezone(timezone.utc).timestamp() * 1000)
        except ValueError:
            pass
    return -1


def demisto_reliability_to_xdr(reliability):
    if reliability:
        return reliability[0]
    else:
        return 'F'


def demisto_vendors_to_xdr(demisto_vendors):
    xdr_vendors = []
    for vendor, data in demisto_vendors.items():
        reliability = demisto_reliability_to_xdr(data.get('reliability'))
        reputation = demisto_score_to_xdr.get(data.get('score'), 'UNKNOWN')
        if vendor and reputation and reliability:
            xdr_vendors.append({
                'vendor_name': vendor,
                'reputation': reputation,
                'reliability': reliability
            })
    return xdr_vendors


def demisto_types_to_xdr(_type: str):
    _type = _type.upper()
    if _type == 'FILE':
        return 'HASH'
    elif _type == 'DOMAIN':
        return 'DOMAIN_NAME'
    else:
        return _type


def demisto_ioc_to_xdr(ioc: Dict) -> Dict:
    xdr_ioc = {
        'indicator': ioc['value'],
        'severity': Client.severity,
        'type': demisto_types_to_xdr(ioc['indicator_type']),
        'reputation': demisto_score_to_xdr.get(ioc.get('score', 0), 'UNKNOWN')
    }
    if 'expiration' in ioc:
        xdr_ioc['expiration_date'] = demisto_expiration_to_xdr(ioc['expiration'])
    if ioc.get('comment'):
        xdr_ioc['comment'] = ioc['comment']
    if ioc.get('aggregatedReliability'):
        xdr_ioc['reliability'] = ioc['aggregatedReliability'][0]
    vendors = demisto_vendors_to_xdr(ioc.get('moduleToFeedMap', {}))
    if vendors:
        xdr_ioc['vendors'] = vendors
    threat_type = ioc.get('CustomFields', {}).get('threattypes', {}).get('threatcategory', False)
    if threat_type:
        xdr_ioc['class'] = threat_type
    return xdr_ioc


def get_temp_file():
    temp_file = tempfile.mkstemp()
    return temp_file[1]


def sync(client: Client):
    temp_file_path = get_temp_file()
    create_file_sync(temp_file_path)
    requests_kwargs = get_requests_kwargs(file_path=temp_file_path)
    path = 'sync_tim_iocs'
    client.http_request(path, requests_kwargs)
    demisto.setIntegrationContext({'ts': int(datetime.now(timezone.utc).timestamp() * 1000),
                                   'time': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')})
    return_outputs('sync with XDR completed.')


def iocs_to_keep(client: Client):
    if not datetime.utcnow().hour in range(1, 3):
        raise DemistoException('iocs_to_keep runs only between 01:00 and 03:00.')
    temp_file_path = get_temp_file()
    create_file_iocs_to_keep(temp_file_path)
    requests_kwargs = get_requests_kwargs(file_path=temp_file_path)
    path = 'iocs_to_keep'
    client.http_request(path, requests_kwargs)
    return_outputs('sync with XDR completed.')


def get_last_iocs():
    current_run = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    last_run = demisto.getIntegrationContext()
    print(last_run['time'])
    total_size = get_iocs_size(from_date=last_run['time'], to_date=current_run)
    batch_size = 200
    iocs = []
    for i in range(0, ceil(total_size / batch_size)):
        iocs.extend(get_iocs(from_date=last_run['time'], to_date=current_run, page=i, size=batch_size))
    last_run['time'] = current_run
    demisto.setIntegrationContext(last_run)
    return iocs


def tim_insert_jsons(client: Client):
    iocs = get_last_iocs()
    path = 'tim_insert_jsons/'
    requests_kwargs = get_requests_kwargs(_json=list(map(lambda ioc: demisto_ioc_to_xdr(ioc), iocs)))
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)


def iocs_command(client: Client):
    command = demisto.command().split('-')[1]
    indicators = demisto.args().get('indicator')
    if command == 'enable':
        path, iocs = prepare_enable_iocs(indicators)
    else:   # command == 'disable'
        path, iocs = prepare_disable_iocs(indicators)
    print(iocs)
    requests_kwargs = get_requests_kwargs(_json=iocs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs(f'indicators {indicators} {command}d.', {}, {})


def xdr_ioc_to_demisto(ioc):
    ioc_time_line = {
        'Value': ioc.get('RULE_INDICATOR'),
        'Message': 'indicator was updated in XDR.',
        'Category': 'Integration Update'
    }
    return ioc_time_line


def filter_inserts(ioc: Dict) -> bool:
    if ioc.get('RULE_MODIFY_TIME', False) and ioc.get('RULE_INSERT_TIME', False):
        if ioc['RULE_MODIFY_TIME'] - ioc['RULE_INSERT_TIME'] < 1000 * 30:   # 0.5 sec
            return False
    return True


def get_changes(client: Client):
    from_time = demisto.getIntegrationContext()
    print(from_time)
    if not from_time:
        raise DemistoException('XDR is not synced.')
    path, requests_kwargs = prepare_get_changes(from_time['ts'])
    requests_kwargs = get_requests_kwargs(_json=requests_kwargs)
    iocs = client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    if iocs:
        from_time['ts'] = iocs[-1].get('RULE_MODIFY_TIME', from_time) + 1
        demisto.setIntegrationContext(from_time)
        iocs = filter(filter_inserts, iocs)
        demisto.results({'IndicatorTimeline': list(map(lambda x: xdr_ioc_to_demisto(x), iocs))})


def main():
    # """
    # Executes an integration command
    # """
    params = demisto.params()
    Client.severity = params.get('severity', '').upper()
    Client.query = params.get('query', Client.query)

    client = Client(params)
    commands = {
        'xdr-iocs-sync': sync,
        'xdr-iocs-iocs-to-keep': iocs_to_keep,
        'xdr-enable-iocs': iocs_command,
        'xdr-disable-iocs': iocs_command,
        'xdr-push-iocs': tim_insert_jsons,
        'fetch-indicators': get_changes,
        'xdr-iocs-get-changes': get_changes
    }

    command = demisto.command()
    try:
        if command in commands:
            commands[command](client)
        else:
            raise NotImplementedError(command)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
