import hashlib
import secrets
import string
import tempfile
from datetime import timezone
from typing import Dict, Optional, List, Tuple
from dateutil.parser import parse

import demistomock as demisto
from CommonServerPython import *


class Client:
    query = 'type:File and (sha256:* or (-sha1:* and md5:*)) or type:Domain or type:IP'
    error_codes = {
        500: 'internal server error.',
        401: 'Unauthorized access. An issue occurred during authentication. This can indicate an incorrect key, id, or other invalid authentication parameters.',
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
            print(res.content)
            raise DemistoException(self.error_codes[res.status_code])

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
        for i in range(4, total_size, batch_size):
            iocs = demisto.searchIndicators(query='', page=i, size=batch_size).get('iocs', [])
            for ios in map(lambda x: x.get('value'), iocs):
                _file.write(ios)
                _file.write('\n')


def create_file_sync(file_path):
    with open(file_path, 'a') as _file:
        total_size = get_iocs_size()
        # total_size = 1
        batch_size = 200
        for i in range(0, total_size, batch_size):
            iocs = get_iocs(page=i, size=batch_size)
            for i in iocs:
                print(i.get('expirationStatus'))
            for ios in map(lambda x: json.dumps(demisto_ioc_to_xdr(x)), iocs):
                _file.write(ios)
                _file.write('\n')


demisto_score_to_xdr = {
    1: 'GOOD',
    2: 'SUSPICIOUS',
    3: 'BAD'
}


def get_iocs_size(_from=None, to=None):
    return demisto.searchIndicators(query=Client.query, page=0, size=1).get('total', 0)


def get_iocs(page=0, size=200, _from=None, to=None):
    return demisto.searchIndicators(query=Client.query, page=page, size=size).get('iocs', [])


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
        'severity': 'INFO',
        'type': demisto_types_to_xdr(ioc['indicator_type']),
        'reputation': demisto_score_to_xdr.get(ioc.get('score'), 'UNKNOWN')
    }
    if 'expiration' in ioc:
        xdr_ioc['expiration_date'] = demisto_expiration_to_xdr(ioc['expiration'])
    if ioc.get('comment'):
        xdr_ioc['comment'] = ioc['comment']
    if ioc.get('aggregatedReliability'):
        xdr_ioc['reliability'] = ioc['aggregatedReliability'][0]
    if vendors := demisto_vendors_to_xdr(ioc.get('moduleToFeedMap', {})):
        xdr_ioc['vendors'] = vendors
    if threat_type := ioc.get('CustomFields', {}).get('threattypes', {}).get('threatcategory', False):
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
    demisto.setLastRun({'next_run': int(datetime.utcnow().timestamp() * 1000)})
    return_outputs('sync with XDR completed.')


def iocs_to_keep(client: Client):
    if datetime.utcnow().hour in range(1, 3):
        raise DemistoException('iocs_to_keep runs only between 01:00 and 03:00.')
    temp_file_path = get_temp_file()
    create_file_iocs_to_keep(temp_file_path)
    requests_kwargs = get_requests_kwargs(file_path=temp_file_path)
    path = 'iocs_to_keep'
    client.http_request(path, requests_kwargs)
    return_outputs('sync with XDR completed.')


def get_last_iocs():
    iocs = get_iocs()
    return iocs


def tim_insert_jsons(client: Client):
    iocs = get_last_iocs()
    path = 'tim_insert_jsons/'
    requests_kwargs = get_requests_kwargs(_json=list(map(lambda ioc: demisto_ioc_to_xdr(ioc), iocs)))
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)


def iocs_command(client: Client):
    command = demisto.command()[4:10]
    if command == 'enable':
        path, iocs = prepare_enable_iocs(demisto.args().get('iocs'))
    else:   # command == 'disable'
        path, iocs = prepare_disable_iocs(demisto.args().get('iocs'))
    requests_kwargs = get_requests_kwargs(_json=iocs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs(f'indicators {iocs} enabled.', {}, {})


def xdr_ioc_to_demisto(ioc):
    return {}


def filter_inserts(ioc: Dict) -> bool:
    return not ioc.get('RULE_MODIFY_TIME', False) or \
           not ioc.get('RULE_INSERT_TIME', False) or \
           ioc['RULE_MODIFY_TIME'] - ioc['RULE_INSERT_TIME'] > 4


def get_changes(client: Client):
    from_time = demisto.getLastRun().get('next_run')
    if not from_time:
        raise DemistoException('xdr never synced.')
    path, requests_kwargs = prepare_get_changes(from_time)
    requests_kwargs = get_requests_kwargs(_json=requests_kwargs)
    iocs = client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    if iocs:
        demisto.setLastRun({'next_run': iocs[-1].get('RULE_MODIFY_TIME', from_time) + 1})
        for i in iocs:
            print(i)
        iocs = filter(filter_inserts, iocs)
        demisto.createIndicators(map(lambda x: xdr_ioc_to_demisto(x), iocs))


def main():
    # """
    # Executes an integration command
    # """
    params = demisto.params()
    client = Client(params)
    sync(client)
    commands = {
        'xdr-iocs-sync': sync,
        'xdr-iocs-iocs_to_keep': iocs_to_keep,
        'xdr-enable-iocs': iocs_command,
        'xdr-disable-iocs': iocs_command,
        'xdr-push-iocs': tim_insert_jsons,
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
