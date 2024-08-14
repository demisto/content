import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from pathlib import Path
import hashlib
import secrets
import string
import tempfile
from datetime import timezone
from collections.abc import Sequence, Iterable
from dateparser import parse
from urllib3 import disable_warnings
import zipfile

disable_warnings()
DEMISTO_TIME_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'
xdr_types_to_demisto: dict = {
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

xdr_reputation_to_demisto: dict = {
    'GOOD': 1,
    'SUSPICIOUS': 2,
    'BAD': 3
}
demisto_score_to_xdr: dict[int, str] = {
    1: 'GOOD',
    2: 'SUSPICIOUS',
    3: 'BAD'
}


def create_validation_errors_response(validation_errors):
    if not validation_errors:
        return ''
    response = 'The following IOCs were not pushed due to following errors:\n'
    for item in validation_errors:
        indicator = item.get('indicator')
        error = item.get('error')
        response += f'{indicator}: {error}.\n'
    return response


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
    error_codes: dict[int, str] = {
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

    def http_request(self, url_suffix: str, requests_kwargs=None) -> dict:
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
        # when installing simplejson the type of exception is requests.exceptions.JSONDecodeError when it is not
        # possible to load json.
        except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError) as e:
            raise DemistoException(f'Could not parse json out of {res.content.decode()}', exception=e, res=res)

    @property
    def _headers(self):
        # the header should be calculated at most 5 min before the request fired
        return get_headers(self._params)


def get_headers(params: dict) -> dict:
    api_key: str = params.get('apikey_creds', {}).get('password', '') or str(params.get('apikey'))
    api_key_id: str = params.get('apikey_id_creds', {}).get('password', '') or str(params.get('apikey_id'))
    nonce: str = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    timestamp: str = str(int(datetime.now(timezone.utc).timestamp()) * 1000)  # noqa: UP017
    auth_key = f"{api_key}{nonce}{timestamp}"
    auth_key = auth_key.encode("utf-8")
    api_key_hash: str = hashlib.sha256(auth_key).hexdigest()

    headers: dict = {
        "x-xdr-timestamp": timestamp,
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash,
        "x-iocs-source": "xsoar"
    }

    return headers


def get_requests_kwargs(_json=None, file_path: str | None = None, validate: bool = False) -> dict:
    if _json is not None:
        data = {"request_data": _json}
        if validate:
            data['validate'] = True
        return {'data': json.dumps(data)}
    elif file_path is not None:
        return {'files': [('file', ('iocs.json', open(file_path, 'rb'), 'application/json'))]}
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
    demisto.debug('starting create_file_iocs_to_keep')
    ioc_count = 0
    has_iocs = False
    with open(file_path, 'w') as _file:
        for ioc in (batch.get('value', '') for batch in get_iocs_generator(size=batch_size)):
            _file.write(ioc + '\n')
            has_iocs = True
            ioc_count += 1

        if has_iocs:
            demisto.info(f"created iocs_to_keep file with {ioc_count} IOCs, file size is {_file.tell()} bytes")

        else:
            demisto.info('All IOCs matching the "Sync Query" are expired, only writing a space to the iocs_to_keep file.')
            _file.write(' ')


def create_file_sync(file_path, batch_size: int = 200):
    ioc_count = 0
    with open(file_path, 'w') as _file:
        for ioc in map(demisto_ioc_to_xdr, get_iocs_generator(size=batch_size)):
            if ioc:
                _file.write(json.dumps(ioc) + '\n')
                ioc_count += 1
        if ioc_count:
            demisto.info(f"created sync file with {ioc_count} IOCs. File size is {_file.tell()}")
        else:
            demisto.info("created sync file without any indicators")


def get_iocs_generator(size=200, query=None) -> Iterable:
    query = query or Client.query
    query = f'expirationStatus:active AND ({query})'
    try:
        for iocs in (batch.get('iocs', []) for batch in IndicatorsSearcher(size=size, query=query)):
            for ioc in iocs:
                yield ioc
    except StopIteration:
        pass


def demisto_expiration_to_xdr(expiration) -> int:
    if expiration and not expiration.startswith('0001'):
        try:
            expiration_date = parse(expiration)
            assert expiration_date is not None, f'could not parse {expiration}'
            return int(expiration_date.astimezone(timezone.utc).timestamp() * 1000)  # noqa: UP017
        except (ValueError, AssertionError):
            pass
    return -1


def demisto_reliability_to_xdr(reliability: str) -> str:
    if reliability:
        return reliability[0]
    else:
        return 'F'


def demisto_vendors_to_xdr(demisto_vendors) -> list[dict]:
    xdr_vendors: list[dict] = []
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
    elif xdr_type == 'URL':
        return 'PATH'
    else:
        return xdr_type


def _parse_demisto_comments(ioc: dict, comment_field_name: list[str] | str, comments_as_tags: bool) -> list[Any] | None:
    """"
    Parsing xsoar fields to xdr from multiple fields value or a single value.
    Args:
        ioc (dict): the IOC dict.
        comment_field_name (list[str] | str): the name of the comment field(s) to parse.
        comments_as_tags (bool): whether to return comments as XDR tags rather than notes.

    Returns:
        A list with the parsed comment(s) joined by commas if multiple comment fields were provided,
        otherwise the parsed comment from the single provided field.
        Returns None if no comments were found.
    """
    # parse comments from multiple fields if specified as list
    if isinstance(comment_field_name, list):
        comments = []
        for field in comment_field_name:
            parsing = parse_demisto_single_comments(ioc, field, comments_as_tags)
            if parsing:
                comments.extend(parsing)
        return [', '.join(comments)]

    # else return single field
    return parse_demisto_single_comments(ioc, comment_field_name, comments_as_tags)


def parse_demisto_single_comments(ioc: dict, comment_field_name: list[str] | str, comments_as_tags: bool) -> list[str] | None:
    """"
    Parsing xsoar fields to xdr from a single value.
    Args:
        ioc (dict): the IOC dict.
        comment_field_name (list[str] | str): the name of the comment field(s) to parse.
        comments_as_tags (bool): whether to return comments as XDR tags rather than notes.

    Returns:
        The parsed comment from the single provided field.
        Returns None if no comments were found.
    """
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

    elif comment_field_name == 'indicator_link':
        # parse indicator link into comments field
        if is_xsoar_saas():
            return [f'{demisto.demistoUrls().get("server")}/indicator/{ioc.get("id")}']
        return [f'{demisto.demistoUrls().get("server")}/#/indicator/{ioc.get("id")}']

    else:  # custom comments field
        if not (raw_comment := ioc.get('CustomFields', {}).get(comment_field_name)):
            return None

        if comments_as_tags:
            return raw_comment.split(",")
        else:
            return [raw_comment]


def demisto_ioc_to_xdr(ioc: dict) -> dict:
    try:
        # demisto.debug(f'Raw outgoing IOC: {ioc}') # uncomment to debug, otherwise spams the log
        xdr_ioc: dict = {
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

        if comment := _parse_demisto_comments(ioc=ioc, comment_field_name=Client.xsoar_comments_field,
                                              comments_as_tags=Client.comments_as_tags):
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

        # demisto.debug(f'Processed outgoing IOC: {xdr_ioc}') # uncomment to debug, otherwise spams the log
        return xdr_ioc

    except KeyError as error:
        demisto.debug(f'unexpected IOC format in key: {str(error)}, {str(ioc)}')
        return {}


def get_temp_file() -> str:
    temp_file = tempfile.mkstemp()
    return temp_file[1]


def set_sync_time(timestamp: datetime) -> None:
    value = {
        "ts": int(timestamp.timestamp()) * 1000,
        "time": timestamp.strftime(DEMISTO_TIME_FORMAT),
    }
    demisto.info(f"setting sync time to integration context: {value}")
    set_integration_context(get_integration_context() | value)  # latter value matters when updating a dict


def sync(client: Client):
    """
    Sync command is supposed to run only in first run or the integration context is empty.
    Creates the initial sync between xdr and xsoar iocs.
    """
    demisto.info("executing sync")
    temp_file_path: str = get_temp_file()
    try:
        sync_time = datetime.now(timezone.utc)  # noqa: UP017
        create_file_sync(temp_file_path)  # may end up empty
        requests_kwargs: dict = get_requests_kwargs(file_path=temp_file_path)
        path: str = 'sync_tim_iocs'
        client.http_request(path, requests_kwargs)
    finally:
        os.remove(temp_file_path)

    set_sync_time(sync_time)
    set_new_iocs_to_keep_time()
    return_outputs("sync with XDR completed.")


def iocs_to_keep(client: Client):
    """
    Creats a file of all the indicators from xsoar we want to keep in XDR.
    All the indicators not send to XDR with the file will be deleted from XDR.
    This is to sync the expired/deleted/no more under filter IOC.
    """
    demisto.info("Skipping iocs_to_keep due to an issue with the XDR API")
    return

    demisto.info("executing iocs_to_keep: this will send non-expired IOCs matching the query from XSOAR to XDR")  # noqa: suppress vulture on dead code
    if datetime.utcnow().hour not in range(1, 3):
        raise DemistoException('iocs_to_keep runs only between 01:00 and 03:00.')
    temp_file_path: str = get_temp_file()
    try:
        create_file_iocs_to_keep(temp_file_path)  # can't be empty
        requests_kwargs: dict = get_requests_kwargs(file_path=temp_file_path)
        path = 'iocs_to_keep'
        demisto.debug(f"calling endpoint {path}")
        client.http_request(path, requests_kwargs)
        set_new_iocs_to_keep_time()
    finally:
        os.remove(temp_file_path)
    return_outputs('sync with XDR completed.')


def get_iocs_to_keep_file():
    temp_file_path = Path(get_temp_file())
    try:
        create_file_iocs_to_keep(temp_file_path)
        return_results(fileResult('xdr-ioc-to-keep-file', temp_file_path.read_text()))
    finally:
        os.remove(temp_file_path)


def create_last_iocs_query(from_date, to_date):
    return f'modified:>={from_date} and modified:<{to_date} and ({Client.query})'


def get_last_iocs(batch_size=200) -> list:
    current_run: str = datetime.utcnow().strftime(DEMISTO_TIME_FORMAT)
    last_run: dict = get_integration_context()
    query = create_last_iocs_query(from_date=last_run['time'], to_date=current_run)
    demisto.info(f"querying XSOAR's recently-modified IOCs with {query=}")
    iocs: list = list(get_iocs_generator(query=query, size=batch_size))
    demisto.info(f"querying XSOAR's recently-modified: got {len(iocs)}")
    last_run['time'] = current_run
    demisto.debug(f"querying querying XSOAR's recently-modified IOCs: setting last_run['time']={current_run}")
    set_integration_context(last_run)
    return iocs


def get_indicators(indicators: str) -> list:
    demisto.debug("searching for IOCs in XSOAR")
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
            warning_message = f'{len(not_found)} indicators were not found: {",".join(not_found)}'
            demisto.info(warning_message)
            return_warning(warning_message)
        else:
            demisto.info(f"get_indicators found {len(iocs)} IOCs")
            return iocs
    demisto.debug("get_indicators found 0 IOCs")
    return []


def tim_insert_jsons(client: Client):
    # takes our changes and pushes to XDR
    indicators = demisto.args().get('indicator', '')
    if indicators:
        demisto.info(f"pushing IOCs to XDR: querying with input {indicators}")
        iocs = get_indicators(indicators)
    else:
        demisto.info("pushing IOCs to XDR: did not get indicators, will use recently-modified IOCs")
        iocs = get_last_iocs()

    validation_errors = []
    if iocs:
        path = 'tim_insert_jsons/'
        demisto.info(f"pushing IOCs to XDR: pushing {len(iocs)} IOCs to the {path} endpoint")
        for i, single_batch_iocs in enumerate(batch_iocs(iocs)):
            demisto.debug(f'pushing IOCs to XDR: batch #{i} with {len(single_batch_iocs)} IOCs')
            requests_kwargs: dict = get_requests_kwargs(_json=list(
                map(demisto_ioc_to_xdr, single_batch_iocs)), validate=True)
            response = client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
            validation_errors.extend(response.get('reply', {}).get('validation_errors'))
    else:
        demisto.info("pushing IOCs to XDR: found no matching IOCs")
    if validation_errors:
        errors = create_validation_errors_response(validation_errors)
        demisto.info('pushing IOCs to XDR:' + errors.replace('\n', '. '))
        return_warning(errors)
    return_outputs('pushing IOCs to XDR: complete.')


def iocs_command(client: Client):
    command = demisto.command().split('-')[-1]
    indicators = demisto.args().get('indicator', '')
    if command == 'enable':
        path, iocs = prepare_enable_iocs(indicators)
    else:  # command == 'disable'
        path, iocs = prepare_disable_iocs(indicators)
    demisto.info(f"IOCs command: sending {len(iocs)} IOCs to endpoint {path}")
    requests_kwargs: dict = get_requests_kwargs(_json=iocs)
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    return_outputs(f'IOCs command: {command}d {indicators=}')


def xdr_ioc_to_timeline(iocs: list) -> dict:
    ioc_time_line = {
        'Value': ','.join(iocs),
        'Message': 'indicator updated in XDR.',
        'Category': 'Integration Update'
    }
    return ioc_time_line


def xdr_expiration_to_demisto(expiration) -> str | None:
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


def xdr_ioc_to_demisto(ioc: dict) -> dict:
    # demisto.debug(f'Raw incoming IOC: {ioc}') # uncomment to debug, otherwise spams the log
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

    entry: dict = {
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

    # demisto.debug(f'Processed incoming entry: {entry}') # uncomment to debug, otherwise it spams the log
    return entry


def get_changes(client: Client):
    demisto.debug("pull XDR changes: starting")
    from_time: dict = get_integration_context()
    if not from_time:
        raise DemistoException('XDR is not synced.')
    path, requests_kwargs = prepare_get_changes(from_time['ts'])
    requests_kwargs: dict = get_requests_kwargs(_json=requests_kwargs)
    demisto.debug(f'pull XDR changes: calling endpoint {path}, {requests_kwargs=}')
    if iocs := client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', []):
        from_time['ts'] = iocs[-1].get('RULE_MODIFY_TIME', from_time) + 1
        demisto.info(f'pull XDR changes: got {len(iocs)} IOCs from XDR')
        demisto.info(f'pull XDR changes: setting {from_time} to integration context ')
        set_integration_context(from_time)
        demisto.debug(f"pull XDR changes: converting {len(iocs)} XDR IOCs to demisto format, then creating indicators")
        demisto_indicators = list(map(xdr_ioc_to_demisto, iocs))
        demisto.createIndicators(demisto_indicators)
        demisto.debug("pull XDR changes: done")
    else:
        demisto.info("pull XDR changes:Got 0 IOCs from XDR")


def module_test(client: Client):
    ts = int(datetime.now(timezone.utc).timestamp() * 1000) - 1  # noqa: UP017
    path, requests_kwargs = prepare_get_changes(ts)
    requests_kwargs: dict = get_requests_kwargs(_json=requests_kwargs)
    demisto.debug(f"calling endpoint {path} with {requests_kwargs=}")
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    demisto.results('ok')


def fetch_indicators(client: Client, auto_sync: bool = False):
    demisto.debug("fetching IOCs: starting")
    if not get_integration_context() and auto_sync:
        demisto.debug("fetching IOCs: running sync with first_time=True")
        # this will happen on the first time we run
        xdr_iocs_sync_command(client, first_time=True)
    else:
        # This will happen every fetch time interval as defined in the integration configuration
        demisto.debug("fetching IOCs: running get_changes")
        get_changes(client)
        if auto_sync:
            demisto.debug("fetching IOCs: auto_sync is on")
            tim_insert_jsons(client)
            demisto.debug("checking if iocs_to_keep should run")
            if is_iocs_to_keep_time():
                # first_time=False will call iocs_to_keep
                demisto.debug("running sync with first_time=False")
                xdr_iocs_sync_command(client)


def xdr_iocs_sync_command(client: Client, first_time: bool = False):
    if first_time or not get_integration_context():
        demisto.debug("first time, running sync")
        # the sync is the large operation including the data and the get_integration_context is fill in the sync
        sync(client)
    else:
        iocs_to_keep(client)


def set_new_iocs_to_keep_time():
    offset = secrets.randbelow(115)
    hour, minute = divmod(offset, 60)
    hour += 1
    last_ioc_to_keep = datetime.now(timezone.utc)  # noqa: UP017
    last_ioc_to_keep = last_ioc_to_keep.replace(hour=hour, minute=minute) + timedelta(
        days=1
    )
    next_iocs_to_keep_time = last_ioc_to_keep.strftime(DEMISTO_TIME_FORMAT)
    demisto.debug(f"Setting next iocs to keep time to {next_iocs_to_keep_time}.")
    # This will set the new ioc to keep time in the integration context
    set_integration_context(
        get_integration_context()
        | {"next_iocs_to_keep_time": next_iocs_to_keep_time}
    )


def is_iocs_to_keep_time():
    """
    This function checks if this is the time to run the iocs_to_keep command.
    In order to remove deleted/expired/filtered indicators.
    """
    next_iocs_to_keep_time = get_integration_context().get("next_iocs_to_keep_time")

    if next_iocs_to_keep_time is None:
        # This is supposed to happen only in the case of appliying the fixed version on a running instance.
        set_new_iocs_to_keep_time()
        next_iocs_to_keep_time = get_integration_context().get("next_iocs_to_keep_time")

    time_now = datetime.now(timezone.utc)  # noqa: UP017
    if (
        time_now.hour in range(1, 3)
        and time_now > datetime.strptime(next_iocs_to_keep_time, DEMISTO_TIME_FORMAT).replace(tzinfo=timezone.utc)  # noqa: UP017
    ):
        return True

    return False


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
            temp: dict = next(filter(is_xdr_data, ioc.get('moduleToFeedMap', {}).values()), {})
            xdr_local = temp.get('score', 0)
    if xdr_server != score:
        return xdr_server
    else:
        return xdr_local


def get_sync_file(set_time: bool = False, zip: bool = False) -> None:
    temp_file_path = get_temp_file()

    timestamp = datetime.now(timezone.utc)  # noqa: UP017
    demisto.debug(f"creating sync file with {timestamp=!s}")
    try:
        create_file_sync(temp_file_path)

        if zip:
            with tempfile.NamedTemporaryFile(mode='w+b', suffix=".zip") as temp_zip_file:
                zipfile.ZipFile(temp_zip_file.name, 'w', compression=zipfile.ZIP_DEFLATED).write(temp_file_path, 'xdr-sync-file')
                temp_zip_file.seek(0, os.SEEK_END)
                demisto.info(f"returning a zip, file size is {temp_zip_file.tell()} bytes")
                temp_zip_file.seek(0)
                return_results(fileResult('xdr-sync-file-zipped.zip', temp_zip_file.read()))
        else:
            with open(temp_file_path) as temp_sync_file:
                # raw file size is logged in create_file_sync
                return_results(fileResult('xdr-sync-file', temp_sync_file.read()))

        if set_time:
            set_sync_time(timestamp)
    finally:
        os.remove(temp_file_path)


def to_cli_name(field_name: str):
    return field_name.lower().replace(' ', '')


def validate_fix_severity_value(severity: str, indicator_value: str | None = None) -> str:
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
    args = demisto.args()
    demisto.debug(f'Command being called is {command}, {args=}')
    try:
        if command == "fetch-indicators":
            fetch_indicators(client, params.get("autoSync", False))
        elif command == 'xdr-iocs-set-sync-time':
            return_warning('This command is deprecated and is not relevant anymore.')
        elif command == "xdr-iocs-create-sync-file":
            get_sync_file(set_time=argToBoolean(args['set_time']), zip=argToBoolean(args['zip']))
        elif command == 'xdr-iocs-to-keep-file':
            get_iocs_to_keep_file()
        elif command in commands:
            commands[command](client)
        elif command == 'xdr-iocs-sync':
            xdr_iocs_sync_command(client, args.get('firstTime') == 'true')
        else:
            raise NotImplementedError(command)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', 'builtins'):
    main()
