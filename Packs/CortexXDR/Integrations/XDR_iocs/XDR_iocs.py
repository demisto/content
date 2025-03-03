import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from pathlib import Path
import hashlib
import secrets
import string
import tempfile
from datetime import datetime, UTC
from collections.abc import Sequence, Iterable
from dateparser import parse
from urllib3 import disable_warnings
import zipfile

disable_warnings()
DEMISTO_TIME_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'
MAX_INDICATORS_TO_SYNC: int = 40000
BATCH_SIZE: int = 4000
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


def extensive_log(message):
    if demisto.params().get('extensive_logs', False):
        demisto.debug(message)


def create_validation_errors_response(validation_errors):
    if not validation_errors:
        return ''
    response = f'The following {len(validation_errors)} IOCs were not pushed due to following errors:\n'
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
    add_link_as_a_comment: bool = False
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
    timestamp: str = str(int(datetime.now(UTC).timestamp()) * 1000)
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


def info_log_for_fetch(last_modified_time: str | None,
                       indicator_value: str | None,
                       new_search_after: list[str] | None,
                       ioc_count: int = 1):
    if new_search_after:
        demisto.info(f"Fetched {ioc_count} indicators from xsoar. last modified that was synced "
                     f"{last_modified_time}, with indicator {indicator_value}, "
                     f"search_after {new_search_after}")


def get_iocs_generator(size=200, query=f'expirationStatus:active AND ({Client.query})', stop_iteration=False) -> Iterable:
    full_query = query or Client.query
    ioc_count = 0
    last_fetched = {}
    search_after_array = None
    try:
        filter_fields = ('value,indicator_type,score,expiration,modified,aggregatedReliability,moduleToFeedMap,'
                         'comments,id,CustomFields'
                         if is_xsiam_or_xsoar_saas()
                         else None)
        search_after = get_integration_context().get('search_after', None)
        for batch in IndicatorsSearcher(size=size,
                                        query=full_query,
                                        search_after=search_after,
                                        sort=[{"field": "modified", "asc": True},
                                              {"field": "id", "asc": True}],
                                        filter_fields=filter_fields):
            search_after_array = batch.get('searchAfter', [])
            iocs = batch.get('iocs', [])
            last_fetched = iocs[-1]
            ioc_count += len(iocs)
            for ioc in iocs:
                yield ioc
            if stop_iteration and ioc_count >= MAX_INDICATORS_TO_SYNC:
                # info_log_for_fetch(ioc.get('modified'), ioc.get('value'), search_after_array, ioc_count)
                raise StopIteration
        update_integration_context_override(update_search_after_array=search_after_array)
        info_log_for_fetch(last_fetched.get('modified'), last_fetched.get('value'), search_after_array, ioc_count)
    except StopIteration:
        update_integration_context_override(update_search_after_array=search_after_array)
        info_log_for_fetch(last_fetched.get('modified'), last_fetched.get('value'), search_after_array, ioc_count)
    except Exception as e:
        raise e


def demisto_expiration_to_xdr(expiration) -> int:
    if expiration and not expiration.startswith('0001'):
        try:
            expiration_date = parse(expiration)
            assert expiration_date is not None, f'could not parse {expiration}'
            return int(expiration_date.astimezone(UTC).timestamp() * 1000)
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


def create_an_indicator_link(ioc: dict) -> list[str]:
    """
    Creates an indicator link into comments field.
    Args:
        ioc (dict): the IOC dict.
    Returns:
        A list which contains a string of indicator's link.
    """
    base_url = f'{demisto.demistoUrls().get("server")}'
    path = 'indicator' if is_xsoar_saas() else '#/indicator'
    return [f'{base_url}/{path}/{ioc.get("id")}']


def _parse_demisto_comments(ioc: dict, comment_field_name: str, comments_as_tags: bool) -> list[Any] | None:
    """"
    Parsing xsoar fields to xdr from multiple fields value or a single value.
    Args:
        ioc (dict): the IOC dict.
        comment_field_name (str): the name of the comment field to parse.
        comments_as_tags (bool): whether to return comments as XDR tags rather than notes.

    Returns:
        A list with the parsed comment(s) joined by commas if multiple comment fields were provided,
        otherwise the parsed comment from the single provided field.
        Returns None if no comments were found.
    """

    comments = []
    # a regular comment for the given field name, "comments" as a default
    comment = parse_demisto_single_comment(ioc, comment_field_name, comments_as_tags)
    if comment:
        comments.extend(comment)

    # if the flag is True, add a link as a comment
    if Client.add_link_as_a_comment:
        comments.extend(create_an_indicator_link(ioc))

    if comments_as_tags:
        return comments or ['']

    return [', '.join(comments)]


def parse_demisto_single_comment(ioc: dict, comment_field_name: str, comments_as_tags: bool) -> list[str] | None:
    """"
    Parsing xsoar field to xdr from a single value.
    Args:
        ioc (dict): the IOC dict.
        comment_field_name (str): the name of the comment field to parse.
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

    else:  # custom comments field
        if not (raw_comment := ioc.get('CustomFields', {}).get(comment_field_name)):
            return None

        if comments_as_tags:
            return raw_comment.split(",")
        else:
            return [raw_comment]


def demisto_ioc_to_xdr(ioc: dict) -> dict:
    try:
        extensive_log(f'Raw outgoing IOC: {ioc=}')
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

        extensive_log(f'Processed outgoing IOC: {xdr_ioc}')

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


def update_integration_context_override(update_sync_time_with_datetime: datetime | None = None,
                                        update_is_first_sync_phase: str | None = None,
                                        update_search_after_array: List[Any] | None = None):
    last_run = get_integration_context() or {}
    if update_sync_time_with_datetime:
        last_run['ts'] = int(update_sync_time_with_datetime.timestamp()) * 1000
        last_run['time'] = update_sync_time_with_datetime.strftime(DEMISTO_TIME_FORMAT)
    if update_is_first_sync_phase:
        last_run['is_first_sync_phase'] = argToBoolean(update_is_first_sync_phase)
    if update_search_after_array:
        last_run['search_after'] = update_search_after_array
    set_integration_context(last_run)


def sync(client: Client, batch_size: int = 200):
    """
    Sync command is supposed to run only in first run or the integration context is empty.
    Creates the initial sync between xdr and xsoar iocs.
    """
    demisto.info("executing sync")
    temp_file_path: str = get_temp_file()
    try:
        sync_time = datetime.now(UTC)
        create_file_sync(temp_file_path)  # may end up empty
        requests_kwargs: dict = get_requests_kwargs(file_path=temp_file_path)
        path: str = 'sync_tim_iocs'
        client.http_request(path, requests_kwargs)
    finally:
        os.remove(temp_file_path)

    set_sync_time(sync_time)
    return_outputs("sync with XDR completed.")


def sync_for_fetch(client: Client, batch_size: int = 200):
    """
    Sync command, by default, runs in batches of 4,000 with total of 40,000 indicators in each sync.
    Syncs the data in xsoar to xdr.
    """
    demisto.info("executing sync")
    request_data: List[Any] = []
    try:
        full_query = create_query_with_end_time(to_date=get_integration_context().get('time'))
        request_data = list(map(demisto_ioc_to_xdr, get_iocs_generator(size=batch_size,
                                                                       stop_iteration=True,
                                                                       query=full_query)))
        if request_data:
            response = push_indicators_to_xdr_request(client, request_data)
            if validation_errors := response.get('reply', {}).get('validation_errors'):
                errors = create_validation_errors_response(validation_errors)
                demisto.debug('pushing IOCs to XDR:' + errors.replace('\n', ''))
            if len(request_data) < MAX_INDICATORS_TO_SYNC:
                update_integration_context_override(update_is_first_sync_phase='false')
                demisto.debug(f"updated integration_context to {get_integration_context()=}")
        else:
            demisto.debug("request_data is empty, no indicators to sync")
            update_integration_context_override(update_is_first_sync_phase='false')
    except Exception as e:
        raise DemistoException(f"Failed to sync indicators with error {e}.")


def get_iocs_to_keep_file():
    temp_file_path = Path(get_temp_file())
    try:
        create_file_iocs_to_keep(temp_file_path)
        return_results(fileResult('xdr-ioc-to-keep-file', temp_file_path.read_text()))
    finally:
        os.remove(temp_file_path)


def create_last_iocs_query(from_date: str, to_date: str):
    return f'modified:>={from_date} and modified:<{to_date} and (expirationStatus:active AND ({Client.query}))'


def create_query_with_end_time(to_date: str):
    return f'modified:<{to_date} and (expirationStatus:active AND ({Client.query}))'


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
        if iocs:
            demisto.info(f"get_indicators found {len(iocs)} IOCs")
            return iocs
    demisto.debug("get_indicators found 0 IOCs")
    return []


def push_iocs(client, iocs, path='tim_insert_jsons/'):
    path = 'tim_insert_jsons/'
    validation_errors: list = []
    demisto.info(f"pushing IOCs to XDR: pushing {len(iocs)} IOCs to the {path} endpoint")
    for i, single_batch_iocs in enumerate(batch_iocs(iocs, batch_size=MAX_INDICATORS_TO_SYNC)):
        demisto.debug(f'pushing IOCs to XDR: batch #{i} with {len(single_batch_iocs)} IOCs')
        requests_kwargs: dict = get_requests_kwargs(_json=list(
            map(demisto_ioc_to_xdr, single_batch_iocs)), validate=True)
        response = client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
        validation_errors.extend(response.get('reply', {}).get('validation_errors'))
    return validation_errors


def push_indicators_to_xdr_request(client, indicators):
    path = 'tim_insert_jsons/'
    demisto.debug(f"pushing IOCs to XDR: pushing {len(indicators)} IOCs to the {path} endpoint")
    requests_kwargs: dict = get_requests_kwargs(_json=indicators, validate=True)
    response = client.http_request(url_suffix=path, requests_kwargs=requests_kwargs)
    if response.get('reply', {}).get('success') is not True:
        were_not_pushed = [indicator.get('indicator') for indicator in indicators]
        demisto.debug(f"The following indicators were not pushed: {','.join(were_not_pushed)}")
        raise DemistoException(f"Response status was not success, {response=}")
    return response


def tim_insert_jsons(client: Client):
    try:
        # Retrieve iocs changes from xsoar and pushes to XDR
        indicators = demisto.args().get('indicator', '')
        validation_errors: list = []
        # If tim_insert_jsons is called from xdr-iocs-push is called
        if indicators:
            demisto.info(f"pushing IOCs to XDR: querying with input {indicators}")
            iocs = get_indicators(indicators)
            if iocs:
                validation_errors = push_iocs(client, iocs)
            else:
                demisto.info("pushing IOCs to XDR: found no matching IOCs")
        # If tim_insert_jsons is called from fetch_indicators
        else:
            demisto.info("pushing IOCs to XDR: did not get indicators, will use recently-modified IOCs")
            current_run: str = datetime.utcnow().strftime(DEMISTO_TIME_FORMAT)
            while True:
                last_run: dict = get_integration_context()
                query = (create_query_with_end_time(to_date=current_run)
                         if last_run.get('search_after')
                         else create_last_iocs_query(from_date=last_run.get('time', current_run), to_date=current_run))
                demisto.info(f"pushing IOCs to XDR: querying XSOAR's recently-modified IOCs with {query=}")
                iocs = list(map(demisto_ioc_to_xdr, get_iocs_generator(size=BATCH_SIZE,
                                                                       stop_iteration=True,
                                                                       query=query)))
                if iocs:
                    response = push_indicators_to_xdr_request(client, iocs)
                    current_validation_errors = response.get('reply', {}).get('validation_errors', [])
                    validation_errors.extend(current_validation_errors)
                    demisto.debug(f"Validation errors of the current loop: {current_validation_errors}")
                else:
                    demisto.debug("pushing IOCs to XDR: No more recently modified indicators to push.")
                    break
            demisto.debug("pushing IOCs to XDR: completed.")
        if validation_errors:
            errors = create_validation_errors_response(validation_errors)
            demisto.info('pushing IOCs to XDR:' + errors.replace('\n', '. '))
            return_warning(errors)
        return_outputs('pushing IOCs to XDR: complete.')
    except DemistoException as e:
        raise DemistoException(f"Can not push to xdr with error: {e}")


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
    extensive_log(f'Raw incoming IOC: {ioc=}')
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

    extensive_log(f'Processed incoming entry: {entry}')
    return entry


def get_changes(client: Client):
    try:
        demisto.debug("pull XDR changes: starting")
        last_run: dict = get_integration_context()
        if not last_run:
            raise DemistoException('XDR is not synced.')
        path, requests_kwargs = prepare_get_changes(last_run['ts'])
        requests_kwargs = get_requests_kwargs(_json=requests_kwargs)
        demisto.debug(f'pull XDR changes: calling endpoint {path}, {requests_kwargs=}')
        if iocs := client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', []):
            last_run['ts'] = iocs[-1].get('RULE_MODIFY_TIME', last_run['ts']) + 1
            set_integration_context(last_run)
            demisto.info(f'pull XDR changes: setting {last_run} to integration context ')
            demisto.info(f"pull XDR changes: converting {len(iocs)} XDR IOCs to xsoar format, then creating indicators")
            demisto_indicators = list(map(xdr_ioc_to_demisto, iocs))
            demisto.createIndicators(demisto_indicators)
            demisto.debug("pull XDR changes: done")
        else:
            demisto.info("pull XDR changes:Got 0 IOCs from XDR")
    except DemistoException as e:
        raise DemistoException(f"Can not get changes from xdr with error {e}")


def module_test(client: Client):
    params = demisto.params()
    feed_fetch_interval = arg_to_number(params.get('feedFetchInterval'))
    if (params.get('feed') and feed_fetch_interval and feed_fetch_interval < 15):
        raise DemistoException(f"`Feed Fetch Interval` is set to {feed_fetch_interval}. Setting `Feed Fetch Interval` to less "
                               "then 15 minutes could lead to internal error from xdr side.")
    ts = int(datetime.now(UTC).timestamp() * 1000) - 1
    path, requests_kwargs = prepare_get_changes(ts)
    requests_kwargs: dict = get_requests_kwargs(_json=requests_kwargs)
    demisto.debug(f"calling endpoint {path} with {requests_kwargs=}")
    client.http_request(url_suffix=path, requests_kwargs=requests_kwargs).get('reply', [])
    demisto.results('ok')


def fetch_indicators(client: Client, auto_sync: bool = False):
    demisto.debug("fetching IOCs: starting")
    last_run = get_integration_context()
    demisto.debug(f"The integration context inside fetch_indicators is {last_run=}")
    if (((not last_run) or (last_run.get('is_first_sync_phase', False)))
            and auto_sync):
        if not last_run:
            sync_time = datetime.now(UTC)
            update_integration_context_override(update_sync_time_with_datetime=sync_time, update_is_first_sync_phase='true')
        demisto.debug("fetching IOCs: running sync with is_first_stage_sync=True")
        xdr_iocs_sync_command(client=client, is_first_stage_sync=True, called_from_fetch=True)
    else:
        # This will happen every fetch time interval as defined in the integration configuration and is_first_sync_phase=False
        demisto.debug("fetching IOCs: running get_changes")
        if auto_sync:
            demisto.debug("fetching IOCs from xsoar: auto_sync is on")
            tim_insert_jsons(client)
        get_changes(client)


def xdr_iocs_sync_command(client: Client,
                          first_time: bool = False,
                          is_first_stage_sync: bool = False,
                          called_from_fetch: bool = False):
    if first_time or is_first_stage_sync or not get_integration_context():
        demisto.debug("first time, running sync")
        if called_from_fetch:
            sync_for_fetch(client, batch_size=BATCH_SIZE)
        else:
            # the sync is the large operation including the data and the get_integration_context is fill in the sync
            sync(client, batch_size=BATCH_SIZE)


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

    timestamp = datetime.now(UTC)
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


def parse_xsoar_field_name_and_link(xsoar_comment_field: list[str]) -> tuple[str, bool]:
    """
    Parsing the given list to two elements,
    one is the xsoar field name and the second is the flag if we should add an indicator link as a comment (indicator_link).
    Args:
        xsoar_comment_field: list of fields.
    Returns:
        str: xsoar comment field name.
        bool: whether to append an incident link to the comments.
    """
    if len(xsoar_comment_field) == 1:
        if xsoar_comment_field[0] == "indicator_link":
            return "comments", True
        return xsoar_comment_field[0], False

    if len(xsoar_comment_field) == 2:
        if "indicator_link" not in xsoar_comment_field:
            raise DemistoException(
                f"The parameter {xsoar_comment_field=} should only contain the field name, or the field name with the"
                f" phrase indicator_link, separated by a comma.")

        xsoar_comment_field.remove("indicator_link")
        return xsoar_comment_field[0], True

    raise DemistoException(f"The parameter {xsoar_comment_field=} cannot contain more than two values")


def main():  # pragma: no cover
    params = demisto.params()
    feed_fetch_interval = arg_to_number(params.get('feedFetchInterval'))
    if params.get('feed') and feed_fetch_interval and feed_fetch_interval < 15:
        demisto.info(f"`Feed Fetch Interval` is set to {feed_fetch_interval}. Setting `Feed Fetch Interval` to less then 15 "
                     "minutes could lead to internal error from xdr side.")
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

    if xsoar_comment_param := argToList(params.get('xsoar_comments_field')):
        # in case of xsoar_comment_param is an empty list -> the Client.xsoar_comments_field is defined to "comments" by default
        Client.xsoar_comments_field, Client.add_link_as_a_comment = parse_xsoar_field_name_and_link(xsoar_comment_param)

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
            xdr_iocs_sync_command(client=client, first_time=args.get('firstTime') == 'true')
        else:
            raise NotImplementedError(command)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', 'builtins'):
    main()
