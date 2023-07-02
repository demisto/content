import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import hashlib
import secrets
import string
import tempfile
from datetime import timezone
from typing import Dict, Optional, List, Sequence, Tuple, Union, Iterable
from dateparser import parse
from urllib3 import disable_warnings


disable_warnings()
DEMISTO_TIME_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'
xdr_types_to_demisto: Dict = {
    "DOMAIN_NAME": 'Domain',
    "HASH": 'File',
    "IP": 'IP'
}
xdr_severity_to_demisto: dict[str, str] = {
    'SEV_010_INFO': 'INFO',
    'SEV_020_LOW': 'LOW',
    'SEV_030_MEDIUM': 'MEDIUM',
    'SEV_040_HIGH': 'HIGH',
    'SEV_050_CRITICAL': 'CRITICAL',
    'SEV_090_UNKNOWN': 'UNKNOWN',
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


def batch_iocs(generator, batch_size=200):
    current_batch = []
    for indicator in generator:
        current_batch.append(indicator)
        if len(current_batch) >= batch_size:
            yield current_batch
            current_batch = []

    if current_batch:
        yield current_batch


class Client:
    # All values here are the defaults, which may be changed via params, on main()
    query: str = 'reputation:Bad and (type:File or type:Domain or type:IP)'
    override_severity: bool = True
    severity: str = ''  # used when override_severity is True
    xsoar_severity_field: str = 'sourceoriginalseverity'  # used when override_severity is False
    xsoar_comments_field: str = 'comments'
    comments_as_tags: bool = False
    tag = 'Cortex XDR'
    tlp_color = None
    error_codes: Dict[int, str] = {
        500: 'XDR internal server error.',
        401: 'Unauthorized access. An issue occurred during authentication. '
             'This can indicate an incorrect key, id, or other invalid authentication parameters.',
        402: 'Unauthorized access. User does not have the required license type to run this API.',
        403: 'Unauthorized access. The provided API key does not have the required RBAC permissions to run this API.',
        404: 'XDR Not found: The provided URL may not be of an active XDR server.',
        413: 'Request entity too large. Please reach out to the XDR support team.'
    }

    def __init__(self, params: dict):
        self._base_url: str = urljoin(params.get('url'), '/public_api/v1/indicators/')
        self._verify_cert: bool = not params.get('insecure', False)
        self._params = params
        handle_proxy()

    def http_request(self, url_suffix: str, requests_kwargs=None) -> Dict:
        if requests_kwargs is None:
            requests_kwargs = dict()

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
        # when installing simplejson the type of exception is requests.exceptions.JSONDecodeError when it is not
        # possible to load json.
        except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError) as e:
            raise DemistoException(f'Could not parse json out of {res.content.decode()}', exception=e, res=res)

    @property
    def _headers(self):
        # the header should be calculated at most 5 min before the request fired
        return get_headers(self._params)


def get_headers(params: Dict) -> Dict:
    api_key: str = params.get('apikey_creds', {}).get('password', '') or str(params.get('apikey'))
    api_key_id: str = params.get('apikey_id_creds', {}).get('password', '') or str(params.get('apikey_id'))
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
    with open(file_path, 'w') as _file:
        has_iocs = False
        for ioc in map(lambda x: x.get('value', ''), get_iocs_generator(size=batch_size)):
            has_iocs = True
            _file.write(ioc + '\n')

        if not has_iocs:
            demisto.debug('All indicators that follow the "Sync Query" are expired, adding a space to the iocs_to_keep file.')
            _file.write(' ')


def create_file_sync(file_path, batch_size: int = 200):
    with open(file_path, 'w') as _file:
        for ioc in map(demisto_ioc_to_xdr, get_iocs_generator(size=batch_size)):
            if ioc:
                _file.write(json.dumps(ioc) + '\n')


def get_iocs_generator(size=200, query=None) -> Iterable:
    query = query or Client.query
    query = f'expirationStatus:active AND ({query})'
    try:
        for iocs in map(lambda x: x.get('iocs', []), IndicatorsSearcher(size=size, query=query)):
            for ioc in iocs:
                yield ioc
    except StopIteration:
        pass


def demisto_expiration_to_xdr(expiration) -> int:
    if expiration and not expiration.startswith('0001'):
        try:
            expiration_date = parse(expiration)
            assert expiration_date is not None, f'could not parse {expiration}'
            return int(expiration_date.astimezone(timezone.utc).timestamp() * 1000)
        except (ValueError, AssertionError):
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


def _parse_demisto_comments(ioc: dict, comment_field_name: str, comments_as_tags: bool) -> list[str] | None:
    if comment_field_name == 'comments':
        if comments_as_tags:
            raise DemistoException("When specifying comments_as_tags=True, the xsoar_comment_field cannot be `comments`)."
                                   "Set a different value.")

        # default behavior, take last comment's content value where type==IndicatorCommentRegular
        last_comment_dict: dict = next(
            filter(lambda x: x.get('type') == 'IndicatorCommentRegular', reversed(ioc.get('comments', ()))), {}
        )
        if not last_comment_dict or not (comment := last_comment_dict.get('content')):
            return None
        return [comment]

    else:  # custom comments field
        if not (raw_comment := ioc.get('CustomFields', {}).get(comment_field_name)):
            return None

        if comments_as_tags:
            return raw_comment.split(",")
        else:
            return [raw_comment]


def demisto_ioc_to_xdr(ioc: Dict) -> Dict:
    try:
        demisto.debug(f'Raw outgoing IOC: {ioc}')
        xdr_ioc: Dict = {
            'indicator': ioc['value'],
            'severity': Client.severity,  # default, may be overwritten, see below
            'type': demisto_types_to_xdr(str(ioc['indicator_type'])),
            'reputation': demisto_score_to_xdr.get(ioc.get('score', 0), 'UNKNOWN'),
            'expiration_date': demisto_expiration_to_xdr(ioc.get('expiration'))
        }
        if aggregated_reliability := ioc.get('aggregatedReliability'):
            xdr_ioc['reliability'] = aggregated_reliability[0]
        if vendors := demisto_vendors_to_xdr(ioc.get('moduleToFeedMap', {})):
            xdr_ioc['vendors'] = vendors
        if (comment := _parse_demisto_comments(ioc=ioc, comment_field_name=Client.xsoar_comments_field,
                                               comments_as_tags=Client.comments_as_tags)):
            xdr_ioc['comment'] = comment

        custom_fields = ioc.get('CustomFields', {})

        if threat_type := custom_fields.get('threattypes', {}):
            threat_type = threat_type[0] if isinstance(threat_type, list) else threat_type
            threat_type = threat_type.get('threatcategory')
            if threat_type:
                xdr_ioc['class'] = threat_type

        if custom_fields.get('xdrstatus') == 'disabled':
            xdr_ioc['status'] = 'DISABLED'

        if (not Client.override_severity) and (custom_severity := custom_fields.get(Client.xsoar_severity_field)):
            # Override is True: use Client.severity
            # Override is False: use the value from the xsoar_severity_field, or Client.severity as default
            xdr_ioc['severity'] = custom_severity  # NOTE: these do NOT need translation to XDR's 0x0_xxxx_xxxx format

        xdr_ioc['severity'] = validate_fix_severity_value(xdr_ioc['severity'], ioc['value'])

        demisto.debug(f'Processed outgoing IOC: {xdr_ioc}')
        return xdr_ioc

    except KeyError as error:
        demisto.debug(f'unexpected IOC format in key: {str(error)}, {str(ioc)}')
        return {}


def get_temp_file() -> str:
    temp_file = tempfile.mkstemp()
    return temp_file[1]


def sync(client: Client):
    temp_file_path: str = get_temp_file()
    try:
        create_file_sync(temp_file_path)  # can be empty
        requests_kwargs: Dict = get_requests_kwargs(file_path=temp_file_path)
        path: str = 'sync_tim_iocs'
        client.http_request(path, requests_kwargs)
    finally:
        os.remove(temp_file_path)
    set_integration_context({'ts': int(datetime.now(timezone.utc).timestamp() * 1000),
                             'time': datetime.now(timezone.utc).strftime(DEMISTO_TIME_FORMAT),
                             'iocs_to_keep_time': create_iocs_to_keep_time()})
    return_outputs('sync with XDR completed.')


def iocs_to_keep(client: Client):
    if not datetime.utcnow().hour in range(1, 3):
        raise DemistoException('iocs_to_keep runs only between 01:00 and 03:00.')
    temp_file_path: str = get_temp_file()
    try:
        create_file_iocs_to_keep(temp_file_path)  # can't be empty
        requests_kwargs: Dict = get_requests_kwargs(file_path=temp_file_path)
        path = 'iocs_to_keep'
        client.http_request(path, requests_kwargs)
    finally:
        os.remove(temp_file_path)
    return_outputs('sync with XDR completed.')


def create_last_iocs_query(from_date, to_date):
    return f'modified:>={from_date} and modified:<{to_date} and ({Client.query})'


def get_last_iocs(batch_size=200) -> List:
    current_run: str = datetime.utcnow().strftime(DEMISTO_TIME_FORMAT)
    last_run: Dict = get_integration_context()
    query = create_last_iocs_query(from_date=last_run['time'], to_date=current_run)
    iocs: List = list(get_iocs_generator(query=query, size=batch_size))
    last_run['time'] = current_run
    set_integration_context(last_run)
    return iocs


def get_indicators(indicators: str) -> List:
    if indicators:
        iocs: list = []
        not_found = []
        for indicator in argToList(indicators):
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
        for i, single_batch_iocs in enumerate(batch_iocs(iocs)):
            demisto.debug(f'push batch: {i}')
            requests_kwargs: Dict = get_requests_kwargs(_json=list(
                map(demisto_ioc_to_xdr, single_batch_iocs)))
            client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs('push done.')


def iocs_command(client: Client):
    command = demisto.command().split('-')[-1]
    indicators = demisto.args().get('indicator', '')
    if command == 'enable':
        path, iocs = prepare_enable_iocs(indicators)
    else:  # command == 'disable'
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


def _parse_xdr_comments(raw_comment: str, comments_as_tags: bool) -> list[str]:
    if not raw_comment:
        return []

    if comments_as_tags:
        return raw_comment.split(',')

    return [raw_comment]


def dedupe_keep_order(values: Iterable[str]) -> tuple[str, ...]:
    return tuple({k: None for k in values}.keys())


def list_of_single_to_str(values: Sequence[str]) -> list[str] | str:
    if len(values) == 1:
        return values[0]
    return list(values)


def xdr_ioc_to_demisto(ioc: Dict) -> Dict:
    demisto.debug(f'Raw incoming IOC: {ioc}')
    indicator = ioc.get('RULE_INDICATOR', '')
    xdr_server_score = int(xdr_reputation_to_demisto.get(ioc.get('REPUTATION'), 0))
    score = get_indicator_xdr_score(indicator, xdr_server_score)
    severity = Client.severity if Client.override_severity else xdr_severity_to_demisto[ioc['RULE_SEVERITY']]

    comments = _parse_xdr_comments(raw_comment=ioc.get('RULE_COMMENT', ''),
                                   comments_as_tags=Client.comments_as_tags)

    if Client.xsoar_comments_field == 'tags':
        tag_comment_fields = {"tags": list_of_single_to_str(dedupe_keep_order(filter(None, comments + [Client.tag])))}
    else:
        tag_comment_fields = {
            "tags": Client.tag,
            Client.xsoar_comments_field: list_of_single_to_str(comments)
        }

    tag_comment_fields = {k: v for k, v in tag_comment_fields.items() if v}  # ommits falsey values

    entry: Dict = {
        "value": indicator,
        "type": xdr_types_to_demisto.get(ioc.get('IOC_TYPE')),
        "score": score,
        "fields": {
            "xdrstatus": ioc.get('RULE_STATUS', '').lower(),
            "expirationdate": xdr_expiration_to_demisto(ioc.get('RULE_EXPIRATION_TIME')),
            Client.xsoar_severity_field: severity,
        } | tag_comment_fields,
        "rawJSON": ioc
    }
    if Client.tlp_color:
        entry['fields']['trafficlightprotocol'] = Client.tlp_color

    demisto.debug(f'Processed incoming entry: {entry}')
    return entry


def get_changes(client: Client):
    from_time: Dict = get_integration_context()
    if not from_time:
        raise DemistoException('XDR is not synced.')
    path, requests_kwargs = prepare_get_changes(from_time['ts'])
    requests_kwargs: Dict = get_requests_kwargs(_json=requests_kwargs)
    demisto.debug(f'creating http request to {path} with {str(requests_kwargs)}')
    if iocs := client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', []):
        from_time['ts'] = iocs[-1].get('RULE_MODIFY_TIME', from_time) + 1
        demisto.debug(f'setting integration context with {from_time=}')
        set_integration_context(from_time)
        demisto_indicators = list(map(xdr_ioc_to_demisto, iocs))
        for indicator in demisto_indicators:
            demisto.debug(f'indicator: {indicator}')
        demisto.createIndicators(demisto_indicators)


def module_test(client: Client):
    ts = int(datetime.now(timezone.utc).timestamp() * 1000) - 1
    path, requests_kwargs = prepare_get_changes(ts)
    requests_kwargs: Dict = get_requests_kwargs(_json=requests_kwargs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    demisto.results('ok')


def fetch_indicators(client: Client, auto_sync: bool = False):
    if not get_integration_context() and auto_sync:
        xdr_iocs_sync_command(client, first_time=True)
    else:
        get_changes(client)
        if auto_sync:
            tim_insert_jsons(client)
            if iocs_to_keep_time():
                # first_time=False will call iocs_to_keep
                xdr_iocs_sync_command(client)


def xdr_iocs_sync_command(client: Client, first_time: bool = False):
    if first_time or not get_integration_context():
        sync(client)
    else:
        iocs_to_keep(client)


def iocs_to_keep_time():
    hour, minute = get_integration_context().get('iocs_to_keep_time', (0, 0))
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
        search_indicators = IndicatorsSearcher()
        ioc = search_indicators.search_indicators_by_version(value=indicator).get('iocs')
        if ioc:
            ioc = ioc[0]
            score = ioc.get('score', 0)
            temp: Dict = next(filter(is_xdr_data, ioc.get('moduleToFeedMap', {}).values()), {})
            xdr_local = temp.get('score', 0)
    if xdr_server != score:
        return xdr_server
    else:
        return xdr_local


def set_sync_time(time: str):
    date_time_obj = parse(time, settings={'TIMEZONE': 'UTC'})
    if not date_time_obj:
        raise ValueError('invalid time format.')
    set_integration_context({'ts': int(date_time_obj.timestamp() * 1000),
                             'time': date_time_obj.strftime(DEMISTO_TIME_FORMAT),
                             'iocs_to_keep_time': create_iocs_to_keep_time()})
    return_results(f'set sync time to {time} succeeded.')


def get_sync_file():
    temp_file_path = get_temp_file()
    try:
        create_file_sync(temp_file_path)
        with open(temp_file_path, 'r') as _tmpfile:
            return_results(fileResult('xdr-sync-file', _tmpfile.read()))
    finally:
        os.remove(temp_file_path)


def to_cli_name(field_name: str):
    return field_name.lower().replace(' ', '')


def validate_fix_severity_value(severity: str, indicator_value: Optional[str] = None) -> str:
    """raises error if the value is invalid, returns the value (fixes informational->info)

    Args:
        severity (str): the severity value, must be of INFO,LOW,MEDIUM,HIGH,CRITICAL,UNKNOWN
        indicator_value (Optional[str]): displayed in case of error

    Raises:
        DemistoException: when the value isn't allowed (nor can be fixed automatically)

    Returns:
        _type_: str, validated severity value
    """
    allowed_values = xdr_severity_to_demisto.values()
    severity_upper = severity.upper()

    if severity_upper == "INFORMATIONAL":
        severity_upper = "INFO"

    if severity_upper not in allowed_values:
        prefix = f'indicator {indicator_value}: ' if indicator_value else ''
        raise DemistoException(f"{prefix}the severity value must be one of {', '.join(allowed_values)} (got {severity})")

    return severity_upper


def main():  # pragma: no cover
    params = demisto.params()
    # In this integration, parameters are set in the *class level*, the defaults are in the class definition.
    Client.severity = params.get('severity', '')
    Client.override_severity = argToBoolean(params.get('override_severity', True))
    Client.tlp_color = params.get('tlp_color')
    Client.comments_as_tags = argToBoolean(params.get('comments_as_tags', False))

    if query := params.get('query'):
        Client.query = query
    if tag := (params.get('feedTags') or params.get('tag')):
        Client.tag = tag
    if xsoar_severity_field := params.get('xsoar_severity_field'):
        Client.xsoar_severity_field = to_cli_name(xsoar_severity_field)
    if xsoar_comment_field := params.get('xsoar_comments_field'):
        Client.xsoar_comments_field = xsoar_comment_field

    client = Client(params)
    commands = {
        'test-module': module_test,
        'xdr-iocs-enable': iocs_command,
        'xdr-iocs-disable': iocs_command,
        'xdr-iocs-push': tim_insert_jsons,
    }
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'fetch-indicators':
            fetch_indicators(client, params.get('autoSync', False))
        elif command == 'xdr-iocs-set-sync-time':
            set_sync_time(demisto.args()['time'])
        elif command == 'xdr-iocs-create-sync-file':
            get_sync_file()
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
