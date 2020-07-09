import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import hashlib
import secrets
import string
import tempfile
from datetime import timezone
from typing import Dict, Optional, List, Tuple, Union
from dateutil.parser import parse
from urllib3 import disable_warnings
from math import ceil


disable_warnings()
DEMISTO_TIME_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'
xdr_types_to_demisto: Dict = {
    "DOMAIN_NAME": 'Domain',
    "HASH": 'File',
    "IP": 'IP'
}
xdr_reputation_to_demisto: Dict = {
    'GOOD': 1,
    'SUSPICIOUS': 2,
    'BAD': 3
}
demisto_score_to_xdr: Dict[int, str] = {
    1: 'GOOD',
    2: 'SUSPICIOUS',
    3: 'BAD'
}


class Client:
    severity: str = ''
    query: str = 'reputation:Bad and (type:File or type:Domain or type:IP)'
    tag = 'Cortex XDR'
    error_codes: Dict[int, str] = {
        500: 'XDR internal server error.',
        401: 'Unauthorized access. An issue occurred during authentication. This can indicate an ' +    # noqa: W504
             'incorrect key, id, or other invalid authentication parameters.',
        402: 'Unauthorized access. User does not have the required license type to run this API.',
        403: 'Unauthorized access. The provided API key does not have the required RBAC permissions to run this API.'
    }

    def __init__(self, params: Dict):
        self._base_url: str = urljoin(params.get('url'), '/public_api/v1/indicators/')
        self._verify_cert: bool = not params.get('insecure', False)
        self._headers: Dict = get_headers(params)
        self._proxy = params.get('proxy', False)
        if self._proxy:
            self._proxy = handle_proxy()

    def http_request(self, url_suffix: str, requests_kwargs) -> Dict:
        url: str = f'{self._base_url}{url_suffix}'
        res = requests.post(url=url,
                            verify=self._verify_cert,
                            headers=self._headers,
                            **requests_kwargs)

        if res.status_code in self.error_codes:
            raise DemistoException(f'{self.error_codes[res.status_code]}\t({res.content.decode()})')
        try:
            return res.json()
        except json.decoder.JSONDecodeError as error:
            demisto.error(str(res.content))
            raise error


def get_headers(params: Dict) -> Dict:
    api_key: str = str(params.get('apikey'))
    api_key_id: str = str(params.get('apikey_id'))
    nonce: str = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    timestamp: str = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
    auth_key = "%s%s%s" % (api_key, nonce, timestamp)
    auth_key = auth_key.encode("utf-8")
    api_key_hash: str = hashlib.sha256(auth_key).hexdigest()

    headers: Dict = {
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
    _json: List = argToList(iocs)
    return url_suffix, _json


def prepare_disable_iocs(iocs: str) -> Tuple[str, List]:
    url_suffix: str = 'disable_iocs'
    _json: List = argToList(iocs)
    return url_suffix, _json


def create_file_iocs_to_keep(file_path, batch_size: int = 200):
    with open(file_path, 'a') as _file:
        total_size: int = get_iocs_size()
        for i in range(0, ceil(total_size / batch_size)):
            iocs: List = get_iocs(page=i, size=batch_size)
            for ios in map(lambda x: x.get('value', ''), iocs):
                _file.write(ios + '\n')


def create_file_sync(file_path, batch_size: int = 200):
    with open(file_path, 'a') as _file:
        total_size: int = get_iocs_size()
        for i in range(0, ceil(total_size / batch_size)):
            iocs: List = get_iocs(page=i, size=batch_size)
            for ioc in map(lambda x: demisto_ioc_to_xdr(x), iocs):
                if ioc:
                    _file.write(json.dumps(ioc) + '\n')


def get_iocs_size(query=None) -> int:
    return demisto.searchIndicators(query=query if query else Client.query, page=0, size=1).get('total', 0)


def get_iocs(page=0, size=200, query=None) -> List:
    return demisto.searchIndicators(query=query if query else Client.query, page=page, size=size).get('iocs', [])


def demisto_expiration_to_xdr(expiration) -> int:
    if expiration and not expiration.startswith('0001'):
        try:
            return int(parse(expiration).astimezone(timezone.utc).timestamp() * 1000)
        except ValueError:
            pass
    return -1


def demisto_reliability_to_xdr(reliability: str) -> str:
    if reliability:
        return reliability[0]
    else:
        return 'F'


def demisto_vendors_to_xdr(demisto_vendors) -> List[Dict]:
    xdr_vendors: List[Dict] = []
    for module_id, data in demisto_vendors.items():
        reliability = demisto_reliability_to_xdr(data.get('reliability'))
        reputation = demisto_score_to_xdr.get(data.get('score'), 'UNKNOWN')
        if module_id and reputation and reliability:
            xdr_vendors.append({
                'vendor_name': data.get('sourceBrand', module_id),
                'reputation': reputation,
                'reliability': reliability
            })
    return xdr_vendors


def demisto_types_to_xdr(_type: str) -> str:
    xdr_type = _type.upper()
    if xdr_type.startswith('FILE'):
        return 'HASH'
    elif xdr_type == 'DOMAIN':
        return 'DOMAIN_NAME'
    else:
        return xdr_type


def demisto_ioc_to_xdr(ioc: Dict) -> Dict:
    try:
        xdr_ioc: Dict = {
            'indicator': ioc['value'],
            'severity': Client.severity,
            'type': demisto_types_to_xdr(str(ioc['indicator_type'])),
            'reputation': demisto_score_to_xdr.get(ioc.get('score', 0), 'UNKNOWN'),
            'expiration_date': demisto_expiration_to_xdr(ioc.get('expiration'))
        }
        # get last 'IndicatorCommentRegular'
        comment: Dict = next(filter(lambda x: x.get('type') == 'IndicatorCommentRegular', reversed(ioc.get('comments', []))), {})
        if comment:
            xdr_ioc['comment'] = comment.get('content')
        if ioc.get('aggregatedReliability'):
            xdr_ioc['reliability'] = ioc['aggregatedReliability'][0]
        vendors = demisto_vendors_to_xdr(ioc.get('moduleToFeedMap', {}))
        if vendors:
            xdr_ioc['vendors'] = vendors
        threat_type = ioc.get('CustomFields', {}).get('threattypes', {}).get('threatcategory')
        if threat_type:
            xdr_ioc['class'] = threat_type
        if ioc.get('CustomFields', {}).get('xdrstatus') == 'disabled':
            xdr_ioc['status'] = 'DISABLED'
        return xdr_ioc
    except KeyError as error:
        demisto.debug(f'unexpected IOC format in key: {str(error)}, {str(ioc)}')
        return {}


def get_temp_file() -> str:
    temp_file = tempfile.mkstemp()
    return temp_file[1]


def sync(client: Client):
    temp_file_path: str = get_temp_file()
    create_file_sync(temp_file_path)
    requests_kwargs: Dict = get_requests_kwargs(file_path=temp_file_path)
    path: str = 'sync_tim_iocs'
    client.http_request(path, requests_kwargs)
    demisto.setIntegrationContext({'ts': int(datetime.now(timezone.utc).timestamp() * 1000),
                                   'time': datetime.now(timezone.utc).strftime(DEMISTO_TIME_FORMAT),
                                   'iocs_to_keep_time': create_iocs_to_keep_time()})
    return_outputs('sync with XDR completed.')


def iocs_to_keep(client: Client):
    if not datetime.utcnow().hour in range(1, 3):
        raise DemistoException('iocs_to_keep runs only between 01:00 and 03:00.')
    temp_file_path: str = get_temp_file()
    create_file_iocs_to_keep(temp_file_path)
    requests_kwargs: Dict = get_requests_kwargs(file_path=temp_file_path)
    path = 'iocs_to_keep'
    client.http_request(path, requests_kwargs)
    return_outputs('sync with XDR completed.')


def create_last_iocs_query(from_date, to_date):
    return f'modified:>={from_date} and modified:<{to_date} and ({Client.query})'


def get_last_iocs(batch_size=200) -> List:
    current_run: str = datetime.utcnow().strftime(DEMISTO_TIME_FORMAT)
    last_run: Dict = demisto.getIntegrationContext()
    query = create_last_iocs_query(from_date=last_run['time'], to_date=current_run)
    total_size = get_iocs_size(query)
    iocs: List = []
    for i in range(0, ceil(total_size / batch_size)):
        iocs.extend(get_iocs(query=query, page=i, size=batch_size))
    last_run['time'] = current_run
    demisto.setIntegrationContext(last_run)
    return iocs


def get_indicators(indicators: str) -> List:
    if indicators:
        iocs = []
        not_found = []
        for indicator in indicators.split(','):
            data = demisto.searchIndicators(value=indicator).get('iocs')
            if data:
                iocs.extend(data)
            else:
                not_found.append(indicator)
        if not_found:
            return_warning('The following indicators were not found: {}'.format(', '.join(not_found)))
        else:
            return iocs
    return []


def tim_insert_jsons(client: Client):
    indicators = demisto.args().get('indicator', '')
    if not indicators:
        iocs = get_last_iocs()
    else:
        iocs = get_indicators(indicators)
    if iocs:
        path = 'tim_insert_jsons/'
        requests_kwargs: Dict = get_requests_kwargs(_json=list(map(lambda ioc: demisto_ioc_to_xdr(ioc), iocs)))
        client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs('push done.')


def iocs_command(client: Client):
    command = demisto.command().split('-')[-1]
    indicators = demisto.args().get('indicator', '')
    if command == 'enable':
        path, iocs = prepare_enable_iocs(indicators)
    else:   # command == 'disable'
        path, iocs = prepare_disable_iocs(indicators)
    requests_kwargs: Dict = get_requests_kwargs(_json=iocs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs(f'indicators {indicators} {command}d.')


def xdr_ioc_to_timeline(iocs: List) -> Dict:
    ioc_time_line = {
        'Value': ','.join(iocs),
        'Message': 'indicator updated in XDR.',
        'Category': 'Integration Update'
    }
    return ioc_time_line


def xdr_expiration_to_demisto(expiration) -> Union[str, None]:
    if expiration:
        if expiration == -1:
            return 'Never'
        return datetime.utcfromtimestamp(expiration / 1000).strftime(DEMISTO_TIME_FORMAT)

    return None


def xdr_ioc_to_demisto(ioc: Dict) -> Dict:
    indicator = ioc.get('RULE_INDICATOR', '')
    xdr_server_score = int(xdr_reputation_to_demisto.get(ioc.get('REPUTATION'), 0))
    score = get_indicator_xdr_score(indicator, xdr_server_score)
    entry: Dict = {
        "value": indicator,
        "type": xdr_types_to_demisto.get(ioc.get('IOC_TYPE')),
        "score": score,
        "fields": {
            "tags": Client.tag,
            "xdrstatus": ioc.get('RULE_STATUS', '').lower(),
            "expirationdate": xdr_expiration_to_demisto(ioc.get('RULE_EXPIRATION_TIME'))
        },
        "rawJSON": ioc
    }
    return entry


def get_changes(client: Client):
    from_time: Dict = demisto.getIntegrationContext()
    if not from_time:
        raise DemistoException('XDR is not synced.')
    path, requests_kwargs = prepare_get_changes(from_time['ts'])
    requests_kwargs: Dict = get_requests_kwargs(_json=requests_kwargs)
    iocs: List = client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    if iocs:
        from_time['ts'] = iocs[-1].get('RULE_MODIFY_TIME', from_time) + 1
        demisto.setIntegrationContext(from_time)
        demisto.createIndicators(list(map(xdr_ioc_to_demisto, iocs)))


def module_test(client: Client):
    ts = int(datetime.now(timezone.utc).timestamp() * 1000) - 1
    path, requests_kwargs = prepare_get_changes(ts)
    requests_kwargs: Dict = get_requests_kwargs(_json=requests_kwargs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    demisto.results('ok')


def fetch_indicators(client: Client, auto_sync: bool = False):
    if not demisto.getIntegrationContext() and auto_sync:
        xdr_iocs_sync_command(client, first_time=True)
    else:
        get_changes(client)
        if auto_sync:
            tim_insert_jsons(client)
            if iocs_to_keep_time():
                # first_time=False will call iocs_to_keep
                xdr_iocs_sync_command(client)


def xdr_iocs_sync_command(client: Client, first_time: bool = False):
    if first_time or not demisto.getIntegrationContext():
        sync(client)
    else:
        iocs_to_keep(client)


def iocs_to_keep_time():
    hour, minute = demisto.getIntegrationContext().get('iocs_to_keep_time', (0, 0))
    time_now = datetime.now(timezone.utc)
    return time_now.hour == hour and time_now.min == minute


def create_iocs_to_keep_time():
    offset = secrets.randbelow(115)
    hour, minute, = divmod(offset, 60)
    hour += 1
    return hour, minute


def is_xdr_data(ioc):
    return ioc.get('sourceBrand') == 'Cortex XDR - IOC'


def get_indicator_xdr_score(indicator: str, xdr_server: int):
    """
    the goal is to avoid reliability changes.
    for example if some feed with reliability 'C' give as the indicator 88.88.88.88 with score 1 (good)
    we dont wont that xdr will also return with 1 and reliability 'A' so the score will be 0 (unknown).
    and we will update only on a case that someone really changed th indicator in xdr.
    :param indicator: the indicator (e.g. 88.88.88.88)
    :param xdr_server: the score in xdr (e.g. GOOD, BAD ...)
    :return: the current score (0 - 3)
    """
    xdr_local: int = 0
    score = 0
    if indicator:
        ioc = demisto.searchIndicators(value=indicator).get('iocs')
        if ioc:
            ioc = ioc[0]
            score = ioc.get('score', 0)
            temp: Dict = next(filter(is_xdr_data, ioc.get('moduleToFeedMap', {}).values()), {})
            xdr_local = temp.get('score', 0)
    if xdr_server != score:
        return xdr_server
    else:
        return xdr_local


def main():
    # """
    # Executes an integration command
    # """
    params = demisto.params()
    Client.severity = params.get('severity', '').upper()
    Client.query = params.get('query', Client.query)
    Client.tag = params.get('tag', Client.tag)
    client = Client(params)
    commands = {
        'test-module': module_test,
        'xdr-iocs-enable': iocs_command,
        'xdr-iocs-disable': iocs_command,
        'xdr-iocs-push': tim_insert_jsons,
    }
    command = demisto.command()
    try:
        if command == 'fetch-indicators':
            fetch_indicators(client, params.get('autoSync', False))
        elif command in commands:
            commands[command](client)
        elif command == 'xdr-iocs-sync':
            xdr_iocs_sync_command(client, demisto.args().get('firstTime') == 'true')
        else:
            raise NotImplementedError(command)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', 'builtins'):
    main()
