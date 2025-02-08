import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import secrets
import tempfile
from datetime import UTC
from dateparser import parse
from urllib3 import disable_warnings
from math import ceil
from google.cloud import storage  # type: ignore[attr-defined]
from CoreIRApiModule import *

disable_warnings()
DEMISTO_TIME_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'

core_types_to_demisto: dict = {
    "DOMAIN_NAME": 'Domain',
    "HASH": 'File',
    "IP": 'IP'
}
core_reputation_to_demisto: dict = {
    'GOOD': 1,
    'SUSPICIOUS': 2,
    'BAD': 3
}
demisto_score_to_core: dict[int, str] = {
    1: 'GOOD',
    2: 'SUSPICIOUS',
    3: 'BAD'
}


class Client(CoreClient):
    severity: str = ''
    query: str = 'reputation:Bad and (type:File or type:Domain or type:IP)'
    tag = 'Cortex Core'
    tlp_color = None
    error_codes: dict[int, str] = {
        500: 'XDR internal server error.',
        401: 'Unauthorized access. An issue occurred during authentication. This can indicate an '    # noqa: W504
             + 'incorrect key, id, or other invalid authentication parameters.',
        402: 'Unauthorized access. User does not have the required license type to run this API.',
        403: 'Unauthorized access. The provided API key does not have the required RBAC permissions to run this API.',
        404: 'XDR Not found: The provided URL may not be of an active XDR server.',
        413: 'Request entity too large. Please reach out to the XDR support team.'
    }

    def __init__(self, params: dict):
        url = "/api/webapp/"
        if not FORWARD_USER_RUN_RBAC:
            url = params.get('url', '')
            if not url:
                url = "http://" + demisto.getLicenseCustomField("Core.ApiHost") + "/api/webapp/"  # type: ignore
        self._base_url: str = urljoin(url, '/public_api/v1/indicators/')
        self._verify_cert: bool = not params.get('insecure', False)
        self._params = params
        handle_proxy()

    def http_request(self, url_suffix: str, requests_kwargs=None) -> dict:
        if FORWARD_USER_RUN_RBAC:
            return CoreClient._http_request(self, method='POST', url_suffix=url_suffix, data=requests_kwargs)
        if requests_kwargs is None:
            requests_kwargs = {}
        res = requests.post(url=self._base_url + url_suffix,
                            verify=self._verify_cert,
                            headers=self._headers,
                            **requests_kwargs)

        if not res.ok:
            status_code = res.status_code
            if status_code in self.error_codes:
                raise DemistoException(self.error_codes[res.status_code], res=res)
            raise DemistoException(f'{status_code}: {res.text}')
        try:
            return res.json()
        except json.decoder.JSONDecodeError as e:
            raise DemistoException(f'Could not parse json out of {res.content.decode()}', exception=e, res=res)

    @property
    def _headers(self):
        # the header should be calculated at most 5 min before the request fired
        return get_headers(self._params)


def get_headers(params: dict) -> dict:
    api_key: str = str(params.get('apikey'))
    api_key_id: str = str(params.get('apikey_id'))
    if not api_key or not api_key_id:
        headers = {
            "HOST": demisto.getLicenseCustomField("Core.ApiHostName"),
            demisto.getLicenseCustomField("Core.ApiHeader"): demisto.getLicenseCustomField("Core.ApiKey"),
            "Content-Type": "application/json"
        }
        add_sensitive_log_strs(demisto.getLicenseCustomField("Core.ApiKey"))
    else:
        headers = {
            "Content-Type": "application/json",
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": api_key
        }
        add_sensitive_log_strs(api_key)

    return headers


def get_requests_kwargs(_json=None) -> dict:
    if _json is not None:
        return {"request_data": _json} if FORWARD_USER_RUN_RBAC else \
            {'data': json.dumps({"request_data": _json})}
    else:
        return {}


def prepare_get_changes(time_stamp: int) -> tuple[str, dict]:
    url_suffix: str = 'get_changes'
    _json: dict = {'last_update_ts': time_stamp}
    return url_suffix, _json


def prepare_enable_iocs(iocs: str) -> tuple[str, list]:
    url_suffix: str = 'enable_iocs'
    _json: list = argToList(iocs)
    return url_suffix, _json


def prepare_disable_iocs(iocs: str) -> tuple[str, list]:
    url_suffix: str = 'disable_iocs'
    _json: list = argToList(iocs)
    return url_suffix, _json


def create_file_iocs_to_keep(file_path, batch_size: int = 200):
    with open(file_path, 'a') as _file:
        total_size: int = get_iocs_size()
        for i in range(0, ceil(total_size / batch_size)):
            iocs: list = get_iocs(page=i, size=batch_size)
            for ios in (x.get('value', '') for x in iocs):
                _file.write(ios + '\n')


def create_file_sync(file_path, batch_size: int = 200):
    with open(file_path, 'a') as _file:
        total_size: int = get_iocs_size()
        for i in range(0, ceil(total_size / batch_size)):
            iocs: list = get_iocs(page=i, size=batch_size)
            for ioc in (demisto_ioc_to_core(x) for x in iocs):
                if ioc:
                    _file.write(json.dumps(ioc) + '\n')


def get_iocs_size(query=None) -> int:
    search_indicators = IndicatorsSearcher()
    query = query if query else Client.query
    query = f'expirationStatus:active AND ({query})'
    return search_indicators.search_indicators_by_version(query=query, size=1)\
        .get('total', 0)


def get_iocs(page=0, size=200, query=None) -> list:
    search_indicators = IndicatorsSearcher(page=page)
    query = query if query else Client.query
    query = f'expirationStatus:active AND ({query})'
    return search_indicators.search_indicators_by_version(query=query, size=size)\
        .get('iocs', [])


def demisto_expiration_to_core(expiration) -> int:
    if expiration and not expiration.startswith('0001'):
        try:
            expiration_date = parse(expiration)
            assert expiration_date is not None, f'could not parse {expiration}'
            return int(expiration_date.astimezone(UTC).timestamp() * 1000)
        except ValueError:
            pass
    return -1


def demisto_reliability_to_core(reliability: str) -> str:
    if reliability:
        return reliability[0]
    else:
        return 'F'


def demisto_vendors_to_core(demisto_vendors) -> list[dict]:
    core_vendors: list[dict] = []
    for module_id, data in demisto_vendors.items():
        reliability = demisto_reliability_to_core(data.get('reliability'))
        reputation = demisto_score_to_core.get(data.get('score'), 'UNKNOWN')
        if module_id and reputation and reliability:
            core_vendors.append({
                'vendor_name': data.get('sourceBrand', module_id),
                'reputation': reputation,
                'reliability': reliability
            })
    return core_vendors


def demisto_types_to_core(_type: str) -> str:
    core_type = _type.upper()
    if core_type.startswith('FILE'):
        return 'HASH'
    elif core_type == 'DOMAIN':
        return 'DOMAIN_NAME'
    else:
        return core_type


def demisto_ioc_to_core(ioc: dict) -> dict:
    try:
        core_ioc: dict = {
            'indicator': ioc['value'],
            'severity': Client.severity,
            'type': demisto_types_to_core(str(ioc['indicator_type'])),
            'reputation': demisto_score_to_core.get(ioc.get('score', 0), 'UNKNOWN'),
            'expiration_date': demisto_expiration_to_core(ioc.get('expiration'))
        }
        # get last 'IndicatorCommentRegular'
        comment: dict = next(filter(lambda x: x.get('type') == 'IndicatorCommentRegular', reversed(ioc.get('comments', []))), {})
        if comment:
            core_ioc['comment'] = comment.get('content')
        if ioc.get('aggregatedReliability'):
            core_ioc['reliability'] = ioc['aggregatedReliability'][0]
        vendors = demisto_vendors_to_core(ioc.get('moduleToFeedMap', {}))
        if vendors:
            core_ioc['vendors'] = vendors

        threat_type = ioc.get('CustomFields', {}).get('threattypes', {})
        if threat_type:
            threat_type = threat_type[0] if isinstance(threat_type, list) else threat_type
            threat_type = threat_type.get('threatcategory')
            if threat_type:
                core_ioc['class'] = threat_type
        if ioc.get('CustomFields', {}).get('corestatus') == 'disabled':
            core_ioc['status'] = 'DISABLED'
        return core_ioc
    except KeyError as error:
        demisto.debug(f'unexpected IOC format in key: {str(error)}, {str(ioc)}')
        return {}


def get_temp_file() -> str:
    temp_file = tempfile.mkstemp()
    return temp_file[1]


def sync(client: Client):
    temp_file_path: str = get_temp_file()
    try:
        create_file_sync(temp_file_path)
        upload_file_to_bucket(temp_file_path)
        requests_kwargs = get_requests_kwargs(_json={"path_to_file": temp_file_path})
        client.http_request(url_suffix='sync_tim_iocs', requests_kwargs=requests_kwargs)
    finally:
        os.remove(temp_file_path)
    set_integration_context({'ts': int(datetime.now(UTC).timestamp() * 1000),
                             'time': datetime.now(UTC).strftime(DEMISTO_TIME_FORMAT),
                             'iocs_to_keep_time': create_iocs_to_keep_time()})
    return_outputs('sync with XDR completed.')


def iocs_to_keep(client: Client):
    if datetime.utcnow().hour not in range(1, 3):
        raise DemistoException('iocs_to_keep runs only between 01:00 and 03:00.')
    temp_file_path: str = get_temp_file()
    try:
        create_file_iocs_to_keep(temp_file_path)
        upload_file_to_bucket(temp_file_path)
        requests_kwargs = get_requests_kwargs(_json={"path_to_file": temp_file_path})
        client.http_request(url_suffix='iocs_to_keep', requests_kwargs=requests_kwargs)
    finally:
        os.remove(temp_file_path)
    return_outputs('sync with XDR completed.')


def create_last_iocs_query(from_date, to_date):
    return f'modified:>={from_date} and modified:<{to_date} and ({Client.query})'


def get_last_iocs(batch_size=200) -> list:
    current_run: str = datetime.utcnow().strftime(DEMISTO_TIME_FORMAT)
    last_run: dict = get_integration_context()
    query = create_last_iocs_query(from_date=last_run['time'], to_date=current_run)
    total_size = get_iocs_size(query)
    iocs: list = []
    for i in range(0, ceil(total_size / batch_size)):
        iocs.extend(get_iocs(query=query, page=i, size=batch_size))
    last_run['time'] = current_run
    set_integration_context(last_run)
    return iocs


def get_indicators(indicators: str) -> list:
    if indicators:
        iocs: list = []
        not_found = []
        for indicator in indicators.split(','):
            search_indicators = IndicatorsSearcher()
            data = search_indicators.search_indicators_by_version(value=indicator).get('iocs')
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
        requests_kwargs: dict = get_requests_kwargs(_json=[demisto_ioc_to_core(ioc) for ioc in iocs])
        client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs('push done.')


def iocs_command(client: Client):
    command = demisto.command().split('-')[-1]
    indicators = demisto.args().get('indicator', '')
    if command == 'enable':
        path, iocs = prepare_enable_iocs(indicators)
    else:   # command == 'disable'
        path, iocs = prepare_disable_iocs(indicators)
    requests_kwargs: dict = get_requests_kwargs(_json=iocs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs(f'indicators {indicators} {command}d.')


def core_ioc_to_timeline(iocs: list) -> dict:
    ioc_time_line = {
        'Value': ','.join(iocs),
        'Message': 'indicator updated in Cortex.',
        'Category': 'Integration Update'
    }
    return ioc_time_line


def core_expiration_to_demisto(expiration) -> str | None:
    if expiration:
        if expiration == -1:
            return 'Never'
        return datetime.utcfromtimestamp(expiration / 1000).strftime(DEMISTO_TIME_FORMAT)

    return None


def module_test(client: Client):
    ts = int(datetime.now(UTC).timestamp() * 1000) - 1
    path, requests_kwargs = prepare_get_changes(ts)
    requests_kwargs: dict = get_requests_kwargs(_json=requests_kwargs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    demisto.results('ok')


def core_iocs_sync_command(client: Client, first_time: bool = False):
    if first_time or not get_integration_context():
        sync(client)
    else:
        iocs_to_keep(client)


def iocs_to_keep_time():
    hour, minute = get_integration_context().get('iocs_to_keep_time', (0, 0))
    time_now = datetime.now(UTC)
    return time_now.hour == hour and time_now.min == minute


def create_iocs_to_keep_time():
    offset = secrets.randbelow(115)
    hour, minute, = divmod(offset, 60)
    hour += 1
    return hour, minute


def is_core_data(ioc):
    return ioc.get('sourceBrand') == 'Cortex Core - IOC'


def get_indicator_core_score(indicator: str, core_server: int):
    """
    the goal is to avoid reliability changes.
    for example if some feed with reliability 'C' give as the indicator 88.88.88.88 with score 1 (good)
    we dont wont that core will also return with 1 and reliability 'A' so the score will be 0 (unknown).
    and we will update only on a case that someone really changed th indicator in core.
    :param indicator: the indicator (e.g. 88.88.88.88)
    :param core_server: the score in core (e.g. GOOD, BAD ...)
    :return: the current score (0 - 3)
    """
    core_local: int = 0
    score = 0
    if indicator:
        search_indicators = IndicatorsSearcher()
        ioc = search_indicators.search_indicators_by_version(value=indicator).get('iocs')
        if ioc:
            ioc = ioc[0]
            score = ioc.get('score', 0)
            temp: dict = next(filter(is_core_data, ioc.get('moduleToFeedMap', {}).values()), {})
            core_local = temp.get('score', 0)
    if core_server != score:
        return core_server
    else:
        return core_local


def set_sync_time(time: str):
    date_time_obj = parse(time, settings={'TIMEZONE': 'UTC'})
    if not date_time_obj:
        raise ValueError('invalid time format.')
    set_integration_context({'ts': int(date_time_obj.timestamp() * 1000),
                             'time': date_time_obj.strftime(DEMISTO_TIME_FORMAT),
                             'iocs_to_keep_time': create_iocs_to_keep_time()})
    return_results(f'set sync time to {time} seccedded.')


def get_sync_file():
    temp_file_path = get_temp_file()
    try:
        create_file_sync(temp_file_path)
        with open(temp_file_path) as _tmpfile:
            return_results(fileResult('core-sync-file', _tmpfile.read()))
    finally:
        os.remove(temp_file_path)


def upload_file_to_bucket(file_path: str) -> None:
    gcpconf_project_id = demisto.getLicenseCustomField("Core.gcpconf_project_id")
    gcpconf_papi_bucket = demisto.getLicenseCustomField("Core.gcpconf_papi_bucket")
    try:
        client = storage.Client(project=gcpconf_project_id)
        bucket = client.get_bucket(gcpconf_papi_bucket)
        blob = bucket.blob(file_path)
        blob.upload_from_filename(file_path)
    except Exception as error:
        raise DemistoException(f'Could not upload to bucket {gcpconf_papi_bucket}', exception=error)


def main():
    # """
    # Executes an integration command
    # """
    params = demisto.params()
    Client.severity = params.get('severity', '').upper()
    Client.query = params.get('query', Client.query)
    Client.tlp_color = params.get('tlp_color')
    client = Client(params)
    commands = {
        'test-module': module_test,
        'core-iocs-enable': iocs_command,
        'core-iocs-disable': iocs_command,
        'core-iocs-push': tim_insert_jsons,
    }
    command = demisto.command()
    try:
        if command == 'core-iocs-set-sync-time':
            set_sync_time(demisto.args()['time'])
        elif command == 'core-iocs-create-sync-file':
            get_sync_file()
        elif command in commands:
            commands[command](client)
        elif command == 'core-iocs-sync':
            core_iocs_sync_command(client, demisto.args().get('firstTime') == 'true')
        else:
            raise NotImplementedError(command)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', 'builtins'):
    main()
