"""
VirusTotal V3 - Premium API
Difference: https://docs.virustotal.com/reference/public-vs-premium-api
"""
import copy
from collections.abc import Iterable

import urllib3
from dateparser import parse

from CommonServerPython import *

# Disable insecure warnings

urllib3.disable_warnings()  # pylint: disable=no-member

# region Globals

INTEGRATION_NAME = "VirusTotal"
COMMAND_PREFIX = "vt-private"
INTEGRATION_ENTRY_CONTEXT = "VirusTotal"


# endregion

# region Helper functions
def convert_epoch_to_readable(
        readable_inputs: dict,
        keys: Iterable[str] = ('start_date', 'creation_date', 'finish_date')
) -> dict:
    """Gets the readable input from a function and converts it times to readable outputs

    Args:
        readable_inputs: a readable output with epoch times in it
        keys: keys to convert

    Returns:
        epoch time in readable output
    """
    for date_ in keys:
        if (creation_date := readable_inputs.get(date_)) and (creation_date := parse(str(creation_date))):
            readable_inputs[date_] = creation_date.replace(microsecond=0).isoformat()
    return readable_inputs


def decrease_data_size(data: Union[dict, list]) -> Union[dict, list]:
    """ Minifying data size.
    Args:
        data: the data object from raw response
    Returns:
        the same data without:
            data['attributes']['last_analysis_results']
            data['attributes']['pe_info']
            data['attributes']['crowdsourced_ids_results']
            data['attributes']['autostart_locations']
            data['attributes']['sandbox_verdicts']
            data['attributes']['sigma_analysis_summary']
            data['attributes']['popular_threat_classification']
            data['attributes']['packers']
            data['attributes']['malware_config']
    """
    attributes_to_remove = [
        'last_analysis_results', 'pe_info', 'crowdsourced_ids_results', 'autostart_locations', 'sandbox_verdicts',
        'sigma_analysis_summary', 'popular_threat_classification', 'packers', 'malware_config'
    ]
    if isinstance(data, list):
        data = [decrease_data_size(item) for item in data]
    else:
        for attribute in attributes_to_remove:
            try:
                del data['attributes'][attribute]
            except KeyError:
                pass
    return data


def arg_to_boolean_can_be_none(arg: Optional[Union[bool, str]]) -> Optional[bool]:
    """A wrapper of argToBool that can return None if arg is None or an empty string"""
    if arg in (None, ''):
        return None
    else:
        return argToBoolean(arg)


def get_last_run_time(params: Optional[dict] = None, last_run: Optional[dict] = None) -> datetime:
    """getting the last run time.
    Args:
        params: Demisto params. Must contain the `first_fetch` key.
        last_run: if exists, should contain the `date` key.

    Returns:
        A datetime object of the fetch time
    """
    if last_run is None:
        last_run = demisto.getLastRun()
    if params is None:
        params = demisto.params()
    if last_run:
        last_run_date = parse(last_run.get('date'))  # type: ignore
    else:  # first run
        first_fetch = params.get('first_fetch')
        try:
            last_run_date = parse(first_fetch)  # type: ignore
            if not last_run_date:
                raise TypeError
        except TypeError:
            raise DemistoException(f'The first fetch time is invalid "{first_fetch=}"')
    assert last_run_date is not None
    return last_run_date


def get_time_range_object(start_time: Optional[str] = None, end_time: Optional[str] = None) -> Dict[str, int]:
    """Gets start and/or end times and converts them to time_range object.

    Args:
        start_time: A string represents time or date range (2018-01-01-18:00Z or 3 days)
        end_time: A string represents time (2018-01-01-18:00Z). if not supplied, will use the current time.

    Returns:
        A dictionary with start and end time.

    Examples:
        >>> get_time_range_object('3 days')
        {'start': 1615199101, 'end': 1615458301}
        >>> get_time_range_object('2018-01-01')
        {'start': 1514757600, 'end': 1615465632}
        >>> get_time_range_object('2018-01-01', '2020-01-01T15:00Z')
    """
    time_range = {}
    start_date: datetime
    end_date: datetime
    if start_time and end_time:
        start_date = parse(start_time)  # type: ignore
        assert start_date, f'Could not parse start_date argument. {start_time=}'
        end_date = parse(end_time)  # type: ignore
        assert end_date, f'Could not parse end_time argument. {end_time=}'

        time_range = {
            'start': int(start_date.timestamp()),
            'end': int(end_date.timestamp())
        }
    elif start_time:
        start_date, end_date = parse(start_time), datetime.now()  # type: ignore
        assert start_date, f'Could not parse start_date argument. {start_time=}'
        assert end_date, f'Could not parse end_time argument. {end_time=}'

        time_range = {
            'start': int(start_date.timestamp()),
            'end': int(end_date.timestamp())
        }
    elif end_time:
        raise AssertionError('Found end_time argument without start_time.')
    return time_range


def arg_to_number_must_int(arg: Any, arg_name: Optional[str] = None, required: bool = False):
    """Wrapper of arg_to_number that must return int
    For mypy fixes.
    """
    arg_num = arg_to_number(arg, arg_name, required)
    assert isinstance(arg_num, int)
    return arg_num


def raise_if_hash_not_valid(
        file_hash: str,
        valid_hashes: Union[tuple, str] = ('sha256', 'sha1', 'md5')
):
    """Raises an error if file_hash is not valid
    Args:
        file_hash: file hash
        valid_hashes: Valid hashes to not raise if file_hash is of its type
    Raises:
        ValueError: if hash is not sha256, sha1, md5
    Examples:
        >>> raise_if_hash_not_valid('not a hash')
        Traceback (most recent call last):
         ...
        ValueError: Hash "not a hash" is not of type sha256, sha1, md5
        >>> raise_if_hash_not_valid('not a hash', valid_hashes='sha1')
        Traceback (most recent call last):
         ...
        ValueError: Hash "not a hash" is not of type sha1
        >>> raise_if_hash_not_valid('7e641f6b9706d860baf09fe418b6cc87')
    """
    if isinstance(valid_hashes, str):
        valid_hashes = (valid_hashes,)
    if get_hash_type(file_hash) not in valid_hashes:
        raise ValueError(f'Hash "{file_hash}" is not of type {", ".join(valid_hashes)}')


def get_file_name(content_disposition: str, ) -> str:
    """Content-Disposition has the filename between the `"`. get it.

    Args:
        content_disposition: the content disposition from download header

    Returns:
        the file name
    """
    if match := re.search(r'"(.*?)"', content_disposition):
        file_name = match.group(1)
    else:
        file_name = demisto.uniqueFile()
    return file_name


# endregion

class Client(BaseClient):
    def __init__(self, params: dict):
        self.api_key = params['credentials']['password']
        super().__init__(
            'https://www.virustotal.com/api/v3/',
            verify=not params.get('insecure'),
            proxy=params.get('proxy'),
            headers={
                'x-apikey': self.api_key,
                'x-tool': 'CortexVirusTotalV3Premium'
            }
        )

    def download_file(self, file: str) -> requests.Response:
        """Download a file.

        See Also:
            https://docs.virustotal.com/reference/files-download
        """
        return self._http_request(
            'GET',
            f'files/{file}/download',
            allow_redirects=True,
            resp_type='response'
        )

    def create_zip(self, hashes: list, password: Optional[str] = None) -> dict:
        """Creates a password-protected ZIP file containing files from VirusTotal.

        See Also:
            https://docs.virustotal.com/reference/zip_files
        """
        body: dict = {
            'hashes': hashes
        }
        if password:
            body['password'] = password
        return self._http_request(
            'POST',
            'intelligence/zip_files',
            json_data={'data': body}
        )

    def get_zip(self, zip_id: str) -> dict:
        """Retrieve information about a ZIP file

        See Also:
            https://docs.virustotal.com/reference/get-zip-file
        """
        return self._http_request(
            'GET',
            f'intelligence/zip_files/{zip_id}'
        )

    def download_zip(self, zip_id: str) -> requests.Response:
        """Download a ZIP file.

        See Also:
            https://docs.virustotal.com/reference/zip-files-download
        """
        return self._http_request(
            'GET',
            f'intelligence/zip_files/{zip_id}/download',
            allow_redirects=True,
            resp_type='request'
        )

    def get_pcap_beaviour(self, report_id) -> dict:
        """Extracted PCAP from a sandbox analysis.

        See Also:
            https://docs.virustotal.com/reference/file_behaviours_pcap
        """
        return self._http_request(
            'GET',
            f'file_behaviours/{report_id}/pcap',
            resp_type='content'
        )

    def search_intelligence(
            self,
            query: str,
            order: Optional[str] = None,
            limit: Optional[int] = None,
            cursor: Optional[str] = None,
            descriptors_only: Optional[bool] = None
    ):
        """Search for files.

        See Also:
            https://docs.virustotal.com/reference/intelligence-search
        """
        return self._http_request(
            'GET',
            'intelligence/search',
            params=assign_params(
                query=query,
                cursor=cursor,
                order=order,
                limit=limit,
                descriptors_only=descriptors_only
            )
        )

    def get_livehunt_rule_by_id(self, id_: str):
        """Retrieve a VT Hunting Livehunt ruleset.

        See Also:
            https://docs.virustotal.com/reference/get-hunting-ruleset
        """
        return self._http_request(
            'GET',
            f'intelligence/hunting_rulesets/{id_}'
        )

    def list_livehunt_rules(
            self,
            /,
            limit: int,
            order: Optional[str] = None,
            name: Optional[str] = None,
            enabled: Optional[bool] = None,
            rule_content: Optional[str] = None,
    ) -> dict:
        """Retrieve a VT Hunting Livehunt rulesets.

        See Also:
            https://docs.virustotal.com/reference/list-hunting-rulesets
        """
        filter_ = ''
        if name:
            filter_ += f'{name} '
        if rule_content:
            filter_ += f'rules:{rule_content} '
        if enabled is not None:
            filter_ += f'enabled:{enabled} '
        return self._http_request(
            'GET',
            'intelligence/hunting_rulesets',
            params=assign_params(
                filter=filter_,
                limit=limit,
                order=order
            )
        )

    def create_livehunt_rule(
            self,
            name: str,
            yara_rule: str,
            enabled: Optional[bool],
            limit: Optional[int],
            notification_emails: Optional[List[str]]
    ) -> dict:
        """Create a new VT Hunting Livehunt ruleset.
        See Also:
            https://docs.virustotal.com/reference/create-hunting-ruleset
        """
        return self._http_request(
            'POST',
            'intelligence/hunting_rulesets',
            json_data={
                'data': {
                    'type': 'hunting_ruleset',
                    'attributes': assign_params(
                        name=name,
                        enabled=enabled,
                        rules=yara_rule,
                        limit=limit,
                        notification_emails=notification_emails
                    )
                }
            }
        )

    def update_livehunt_rule(
            self,
            id_: str,
            yara_rule: Optional[str],
            enabled: Optional[bool],
            limit: Optional[int],
            notification_emails: Optional[List[str]]
    ) -> dict:
        """Update a VT Hunting Livehunt ruleset.

        See Also:
            https://docs.virustotal.com/reference/create-hunting-ruleset
        """
        params = assign_params(
            enabled=enabled,
            rules=yara_rule,
            limit=limit,
            notification_emails=notification_emails
        )
        assert params, 'Found nothing to update'
        return self._http_request(
            'PATCH',
            f'intelligence/hunting_rulesets/{id_}',
            json_data={
                'data': {
                    'type': 'hunting_ruleset',
                    'id': id_,
                    'attributes': params
                }
            }
        )

    def delete_livehunt_rule(self, id_: str):
        """Delete a VT Hunting Livehunt ruleset.

        See Also:
            https://docs.virustotal.com/reference/delete-hunting-ruleset
        """
        self._http_request(
            'DELETE',
            f'intelligence/hunting_rulesets/{id_}',
            resp_type='text'
        )

    def list_notifications(
            self,
            from_time: Optional[datetime] = None,
            to_time: Optional[datetime] = None,
            tag: Optional[str] = None,
            cursor: Optional[str] = None,
            limit: Optional[int] = None
    ) -> dict:
        """Retrieve VT Hunting Livehunt notifications.

        See Also:
            https://docs.virustotal.com/reference/list-hunting-notifications
        """
        time_format = "%Y-%m-%dT%H:%M:%S"
        filter_ = ''
        if tag:
            filter_ += f'{tag} '
        if from_time:
            filter_ += f'date:{from_time.strftime(time_format)}+ '
        if to_time:
            filter_ += f'date:{to_time.strftime(time_format)}- '
        return self._http_request(
            'GET',
            'intelligence/hunting_notifications',
            params=assign_params(
                filter=filter_,
                limit=limit,
                cursor=cursor
            )
        )

    def list_notifications_files(self, filter_: Optional[str], cursor: Optional[str] = None,
                                 limit: Optional[int] = None):
        """Retrieve file objects for VT Hunting Livehunt notifications.

        See Also:
            https://docs.virustotal.com/reference/hunting_notification_files
        """
        return self._http_request(
            'GET',
            'intelligence/hunting_notification_files',
            params=assign_params(
                filter=filter_,
                limit=limit,
                cursor=cursor
            )
        )

    def list_files_by_rule(self, id_: str, cursor: Optional[str] = None, limit: Optional[int] = None) -> dict:
        """Get a VT Hunting Livehunt ruleset by hunting notification files relationship.

        See Also:
            https://docs.virustotal.com/reference/get-hunting-ruleset-relationship
        """
        return self._http_request(
            'GET',
            f'intelligence/hunting_rulesets/{id_}/relationships/hunting_notification_files',
            params=assign_params(
                cursor=cursor,
                limit=limit
            )
        )

    def list_retrohunt_jobs(
            self,
            filter_: Optional[str] = None,
            cursor: Optional[str] = None,
            limit: Optional[int] = None
    ) -> dict:
        """Retrieve retrohunt jobs.

        See Also:
            https://docs.virustotal.com/reference/get-retrohunt-jobs
        """
        return self._http_request(
            'GET',
            'intelligence/retrohunt_jobs',
            params=assign_params(
                filter=filter_,
                limit=limit,
                cursor=cursor
            )
        )

    def create_retrohunt_job(
            self,
            rules: str,
            notification_email: Optional[List[str]] = None,
            corpus: Optional[str] = None,
            time_range: Optional[Dict[str, int]] = None
    ) -> dict:
        """Create a new retrohunt job.

        See Also:
            https://docs.virustotal.com/reference/create-retrohunt-job
        """
        return self._http_request(
            'POST',
            'intelligence/retrohunt_jobs',
            json_data={
                "data": {
                    "type": "retrohunt_job",
                    "attributes": assign_params(
                        rules=rules,
                        notification_email=notification_email,
                        corpus=corpus,
                        time_range=time_range
                    )
                }
            }
        )

    def get_retrohunt_job_by_id(self, id_: str) -> dict:
        """Retrieve a retrohunt job.

        See Also:
            https://docs.virustotal.com/reference/get-retrohunt-job
        """
        return self._http_request(
            'GET',
            f'intelligence/retrohunt_jobs/{id_}'
        )

    def get_retrohunt_job_matching_files(self, id_: str) -> dict:
        """Retrieve matches for a retrohunt job matching file relationship..

        See Also:
            https://docs.virustotal.com/reference/get-retrohunt-job-relationships
        """
        return self._http_request(
            'GET',
            f'intelligence/retrohunt_jobs/{id_}/matching_files'
        )

    def get_quota_limits(self, id_: str) -> dict:
        """Retrieve user's API usage.

        See Also:
            https://docs.virustotal.com/reference/user-api-usage
        """
        return self._http_request(
            'GET',
            f'users/{id_}/overall_quotas'
        )


def test_module(client: Client, params: dict) -> str:
    """Tests API connectivity and authentication'
    A simple call to list_livehunt_rules

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    if argToBoolean(params.get('isFetch')):
        fetch_incidents(client, params, get_last_run_time(last_run={}))
    else:
        client.list_livehunt_rules(limit=1)
    return 'ok'


def download_file(client: Client, args: dict) -> dict:
    """Download a file."""
    file = args['hash']
    raise_if_hash_not_valid(file)
    response = client.download_file(file)
    content = response.content
    content_disposition = response.headers.get('Content-Disposition', '')
    file_name = f'{get_file_name(content_disposition)}-vt-file'
    return fileResult(file_name, content)


def create_zip(client: Client, args: dict) -> CommandResults:
    """Creates a password-protected ZIP file containing files from VirusTotal."""
    hashes = argToList(args['file'])
    for hash_ in hashes:
        raise_if_hash_not_valid(hash_)
    password = args.get('password')
    raw_response = client.create_zip(hashes, password)
    data = raw_response.get('data', {})
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Zip',
        'id',
        outputs=data,
        readable_output=tableToMarkdown(
            'The request to create the ZIP was submitted successfully!',
            {
                **data,
                **data.get('attributes', {})
            },
            headers=['id', 'status']
        )
    )


def get_zip(client: Client, args: dict) -> CommandResults:
    """Retrieve information about a ZIP file"""
    zip_id = args['zip_id']
    raw_response = client.get_zip(zip_id)
    data = raw_response['data']
    status = data.get('attributes', {}).get('status')
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.Zip',
        'id',
        outputs=data,
        readable_output=f'ZIP creation status is "{status}"',
        raw_response=raw_response
    )


def download_zip(client: Client, args: dict) -> dict:
    """Download a ZIP file."""
    zip_id = args['zip_id']
    response = client.download_zip(zip_id)
    content = response.content
    file_name = get_file_name(response.headers.get('Content-Disposition', ''))
    return fileResult(file_name, content)


def get_pcap_behaviour(client: Client, args: dict) -> dict:
    """Extracted PCAP from a sandbox analysis"""
    report_id = args['report_id']
    content = client.get_pcap_beaviour(report_id)
    assert isinstance(content, bytes | str), 'Response from PCAP Behavior is not a bytes-like object.'
    return fileResult(f'{report_id}.pcap', content)


def search_intelligence(client: Client, args: dict) -> CommandResults:
    """Search for files."""
    query = args['query']
    limit = arg_to_number(args.get('limit'))
    order = args.get('order')
    cursor = args.get('cursor')
    descriptors_only = arg_to_boolean_can_be_none(args.get('descriptors_only'))
    raw_response = client.search_intelligence(query, order, limit, cursor, descriptors_only)
    if not arg_to_boolean_can_be_none(args.get('extended_data')):
        raw_response['data'] = decrease_data_size(raw_response.get('data', []))
    data = raw_response['data']
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.IntelligenceSearch',
        'id',
        outputs=data,
        raw_response=raw_response
    )


def get_livehunt_rule(client: Client, args: dict) -> CommandResults:
    """Retrieve a VT Hunting Livehunt ruleset."""
    id_ = args['id']
    raw_response = client.get_livehunt_rule_by_id(id_)
    data = raw_response.get('data', {})
    readable_output = data.get('attributes')
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.LiveHuntRule',
        'id',
        outputs=data,
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            f'Livehunt Ruleset {id_}',
            readable_output,
            headers=['name', 'enabled', 'rule_names']
        )
    )


def list_livehunt_rules(client: Client, args: dict) -> CommandResults:
    """Retrieve a VT Hunting Livehunt rulesets."""
    enabled = None if not args.get('enabled') else arg_to_boolean_can_be_none(args.get('enabled'))
    rule_content = args.get('rule_content')
    name = args.get('name')
    order = args.get('order')
    limit = arg_to_number_must_int(args.get('limit'))
    raw_response = client.list_livehunt_rules(
        limit=limit, name=name, enabled=enabled, rule_content=rule_content, order=order
    )
    data = raw_response.get('data', [])
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.LiveHuntRule',
        'id',
        outputs=data,
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            'VT Hunting Livehunt rulesets',
            [{
                **item.get('attributes', {}),
                'id': item.get('id')
            } for item in data],
            headers=['id', 'name', 'enabled', 'rule_names']
        )
    )


def create_livehunt_rule(client: Client, args: dict) -> CommandResults:
    """Create a new VT Hunting Livehunt ruleset"""
    name = args['name']
    yara_rule = stringUnEscape(args['yara_rule'])
    # optional
    enabled = None if args.get('enabled') == "None" else arg_to_boolean_can_be_none(args.get('enabled'))
    notification_emails = argToList(args.get('notification_emails'))
    limit = arg_to_number(args.get('limit'))
    raw_response = client.create_livehunt_rule(name, yara_rule, enabled, limit, notification_emails)
    outputs = raw_response.get('data', {})
    return CommandResults(
        'VirusTotal.LiveHuntRule',
        'id',
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            f'New rule "{name}" was created successfully',
            {
                **outputs,
                **outputs.get('attributes', {})
            },
            headers=['id', 'name', 'number_of_rules']
        )
    )


def update_livehunt_rules(client: Client, args: dict) -> CommandResults:
    """Create a new VT Hunting Livehunt ruleset"""
    id_ = args['id']
    yara_rule = args.get('yara_rule')
    enabled = arg_to_boolean_can_be_none(args.get('enabled'))
    notification_emails = argToList(args.get('notification_emails'))
    limit = arg_to_number(args.get('limit'))
    raw_response = client.update_livehunt_rule(id_, yara_rule, enabled, limit, notification_emails)
    outputs = raw_response.get('data', {})
    return CommandResults(
        'VirusTotal.LiveHuntRule',
        'id',
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown(
            f'Rule "{id_}" has been updated!',
            {
                **outputs,
                **outputs.get('attributes', {})
            },
            headers=['id', 'name', 'number_of_rules']
        )
    )


def delete_livehunt_rules(client: Client, args: dict) -> CommandResults:
    """Delete a VT Hunting Livehunt ruleset."""
    id_ = args['id']
    client.delete_livehunt_rule(id_)
    return CommandResults(
        readable_output=f'Rule "{id_}" was deleted successfully'
    )


def list_notifications(client: Client, args: dict) -> CommandResults:
    """Retrieve VT Hunting Livehunt notifications."""
    limit = arg_to_number_must_int(args.get('limit'))
    assert limit <= 40, 'limit can\'t be above 40'
    if to_time := args.get('to_time'):
        to_time = parse(to_time)
    if from_time := args.get('from_time'):
        from_time = parse(from_time)
    if from_time and to_time and from_time > to_time:
        raise DemistoException(f'The from_time argument is later then to_time. {from_time} > {to_time}')
    cursor = args.get('cursor')
    tag = args.get('tag')
    outputs = raw_response = client.list_notifications(from_time, to_time, tag, cursor, limit)
    if not arg_to_boolean_can_be_none(args.get('extended_data')):
        outputs = copy.deepcopy(raw_response)
        outputs['data'] = decrease_data_size(outputs.get('data', []))
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.LiveHuntNotification',
        'id',
        readable_output=tableToMarkdown(
            'Notifications found:',
            outputs.get('data', {}),
            headers=['id']
        ),
        outputs=outputs,
        raw_response=raw_response
    )


def list_notifications_files_list(client: Client, args: dict) -> CommandResults:
    """Retrieve file objects for VT Hunting Livehunt notifications"""
    filter_ = args.get('filter')
    limit = arg_to_number(args.get('limit'))
    cursor = args.get('cursor')
    outputs = raw_response = client.list_notifications_files(filter_, cursor, limit)
    if not arg_to_boolean_can_be_none(args.get('extended_data')):
        outputs = copy.deepcopy(raw_response)
        outputs['data'] = decrease_data_size(outputs.get('data', []))
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.LiveHuntFiles',
        'id',
        readable_output=tableToMarkdown(
            'Notifications file listed:',
            [
                {**item.get('attributes', {}), 'id': item.get('id')} for item in raw_response.get('data', [])
            ],
            headers=['id', 'meaningful_name', 'last_analysis_stats']
        ),
        outputs=outputs,
        raw_response=raw_response
    )


def list_notifications_files_list_by_hash(client: Client, args: dict) -> List[CommandResults]:
    """Retrieve file objects for VT Hunting Livehunt notifications by hash."""
    hashes_only = [hash_ for hash_ in argToList(args.get('hash')) if get_hash_type(hash_) != 'Unknown']
    cursor = args.get('cursor')
    results = []
    for hash_ in hashes_only:
        try:
            outputs = raw_response = client.list_notifications_files(hash_, cursor, limit=1)
            if not arg_to_boolean_can_be_none(args.get('extended_data')):
                outputs = copy.deepcopy(raw_response)
                outputs['data'] = decrease_data_size(outputs.get('data', []))
            results.append(CommandResults(
                f'{INTEGRATION_ENTRY_CONTEXT}.LiveHuntFiles',
                'id',
                readable_output=tableToMarkdown(
                    'Notifications file listed:',
                    [
                        {**item.get('attributes', {}), 'id': item.get('id')} for item in raw_response.get('data', [])
                    ],
                    headers=['id', 'meaningful_name', 'last_analysis_stats']
                ),
                outputs=outputs,
                raw_response=raw_response
            ))
        except Exception as exc:
            err = f'Could not process hash "{hash_}"'
            demisto.debug(f'{err}\n{exc}')
            results.append(CommandResults(readable_output=err))
    return results


def list_files_by_rule(client: Client, args: dict) -> CommandResults:
    """Get a VT Hunting Livehunt ruleset by hunting notification files relationship."""
    id_ = args['id']
    limit = arg_to_number(args.get('limit'))
    cursor = args.get(args.get('cursor'))
    raw_response = client.list_files_by_rule(id_, cursor, limit)
    data = raw_response.get('data', [])
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.LiveHuntFiles',
        'id',
        readable_output=tableToMarkdown(
            f'Files found by rule {id_}',
            data
        ),
        outputs=data,
        raw_response=raw_response
    )


def list_retrohunt_jobs(client: Client, args: dict) -> CommandResults:
    """Retrieve retrohunt jobs"""
    limit = arg_to_number(args.get('limit'))
    cursor = args.get('cursor')
    filter_ = args.get('filter')
    raw_response = client.list_retrohunt_jobs(filter_, cursor, limit)
    data = raw_response.get('data', [])
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.RetroHuntJob',
        'id',
        readable_output=tableToMarkdown(
            'Retrohunt jobs listed:',
            [
                {
                    **item.get('attributes', {}),
                    'id': item.get('id')
                } for item in data
            ],
            headers=['id', 'corpus', 'status', 'rules']
        ),
        outputs=data,
        raw_response=raw_response
    )


def create_retrohunt_jobs(client: Client, args: dict) -> CommandResults:
    """Create a new retrohunt job."""
    rules = stringUnEscape(args.get('rules'))
    notification_email = argToList(args.get('notification_email'))
    corpus = args.get('corpus')  # main / goodware
    start_time, end_time = args.get('start_time'), args.get('end_time')
    time_range = get_time_range_object(start_time, end_time)
    raw_response = client.create_retrohunt_job(rules, notification_email, corpus, time_range)
    data = raw_response.get('data', {})
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.RetroHuntJob',
        'id',
        readable_output=tableToMarkdown(
            'Retrohunt job has been successfully created',
            {
                **data,
                **data.get('attributes', {})
            },
            headers=['id', 'corpus', 'status', 'rules']
        ),
        outputs=data,
        raw_response=raw_response
    )


def get_retrohunt_job_by_id(client: Client, args: dict) -> CommandResults:
    """Retrieve a retrohunt job."""
    id_ = args['id']
    raw_response = client.get_retrohunt_job_by_id(id_)
    data = raw_response.get('data', {})
    readable_inputs = {
        **data,
        **data.get('attributes', {})
    }

    readable_inputs.pop('attributes', None)
    readable_inputs = convert_epoch_to_readable(readable_inputs)

    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.RetroHuntJob',
        'id',
        readable_output=tableToMarkdown(
            f'Retrohunt job: {id_}',
            readable_inputs
        ),
        outputs=data,
        raw_response=raw_response
    )


def get_retrohunt_job_matching_files(client: Client, args: dict) -> CommandResults:
    """Retrieve matches for a retrohunt job matching file relationship."""
    id_ = args['id']
    raw_response = client.get_retrohunt_job_matching_files(id_)
    if not arg_to_boolean_can_be_none(args.get('extended_data')):
        raw_response['data'] = decrease_data_size(raw_response['data'])
    data = raw_response.get('data', [])
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.RetroHuntJobFiles',
        'id',
        readable_output=tableToMarkdown(
            f'Files matching id "{id_}"',
            [
                {
                    **item.get('attributes', {}),
                    'id': item.get('id')
                } for item in data
            ],
            headers=['sha256', 'popular_threat_classification', 'reputation']
        ),
        outputs=data,
        raw_response=raw_response
    )


def get_quota_limits(client: Client, args: dict) -> CommandResults:
    """Retrieve user's API usage."""
    id_ = args.get('id', client.api_key)
    raw_response = client.get_quota_limits(id_)
    data = raw_response.get('data', {})
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.QuotaLimits',
        readable_output=tableToMarkdown(
            'Monthly quota data: More data can be found in the Context.',
            {key: value for key, value in data.items() if 'monthly' in key}
        ),
        outputs=data,
        raw_response=raw_response
    )


def fetch_incidents(client: Client, params: dict, last_run_date: datetime) -> tuple[List[dict], datetime]:
    tag = params.get('tag')
    max_fetch = arg_to_number_must_int(params.get('max_fetch', 10))
    raw_response = client.list_notifications(from_time=last_run_date, tag=tag, limit=max_fetch)
    incidents = []
    for notification in raw_response.get('data', []):
        attributes = notification.get('attributes', {})
        date = parse(str(attributes.get('date')))  # epoch int to str
        if not date:
            date = last_run_date
        elif date > last_run_date:
            last_run_date = date
        incidents.append(
            {
                'name': f'VirusTotal Intelligence LiveHunt Notification: {notification.get("id")}',
                'occurred': f'{date.replace(microsecond=0).isoformat()}Z',
                'rawJSON': json.dumps(notification)
            }
        )
    if incidents:
        # To not fetch duplicate notifications. If not incidents - Nothing found. keep going
        last_run_date += timedelta(seconds=1)
    return incidents, last_run_date


def search_file(client: Client, args: dict) -> CommandResults:
    query = args['query']
    limit = 1000 if argToBoolean(args.get('fullResponse')) else 50
    raw_response = client.search_intelligence(query, limit=limit, descriptors_only=True)
    hashes = [item['id'] for item in raw_response.get('data', []) if item.get('id')]
    return CommandResults(
        f'{INTEGRATION_ENTRY_CONTEXT}.SearchFile',
        'Query',
        readable_output=tableToMarkdown(
            f'Found hashes for query: "{query}"',
            hashes,
            headers=['Found hashes']
        ),
        outputs={
            'Query': query,
            'SearchResult': hashes
        },
        raw_response=raw_response
    )


def main():
    """main function, parses params and runs command functions
    """
    results: Union[str, CommandResults, dict, List[CommandResults]]
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {command}')
    try:
        params = demisto.params()
        handle_proxy()
        client = Client(params)
        if command == 'fetch-incidents':
            incidents, new_run_date = fetch_incidents(client, params, get_last_run_time())
            demisto.setLastRun({'date': new_run_date.isoformat()})
            demisto.incidents(incidents)
        else:
            if command == 'test-module':
                results = test_module(client, params)
            elif command == f'{COMMAND_PREFIX}-download-file':
                results = download_file(client, args)
            elif command == f'{COMMAND_PREFIX}-zip-create':
                results = create_zip(client, args)
            elif command == f'{COMMAND_PREFIX}-zip-get':
                results = get_zip(client, args)
            elif command == f'{COMMAND_PREFIX}-zip-download':
                results = download_zip(client, args)
            elif command == f'{COMMAND_PREFIX}-file-sandbox-pcap':
                results = get_pcap_behaviour(client, args)
            elif command == f'{COMMAND_PREFIX}-intelligence-search':
                results = search_intelligence(client, args)
            elif command in (f'{COMMAND_PREFIX}-search-file', 'vt-private-search-file'):
                results = search_file(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-rules-list':
                results = list_livehunt_rules(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-rules-get-by-id':
                results = get_livehunt_rule(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-rules-create':
                results = create_livehunt_rule(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-rules-update':
                results = update_livehunt_rules(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-rules-delete':
                results = delete_livehunt_rules(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-notifications-list':
                results = list_notifications(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-notifications-files-list':
                results = list_notifications_files_list(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-notifications-files-get-by-hash':
                results = list_notifications_files_list_by_hash(client, args)
            elif command == f'{COMMAND_PREFIX}-livehunt-rule-list-files':
                results = list_files_by_rule(client, args)
            elif command == f'{COMMAND_PREFIX}-retrohunt-jobs-list':
                results = list_retrohunt_jobs(client, args)
            elif command == f'{COMMAND_PREFIX}-retrohunt-jobs-get-by-id':
                results = get_retrohunt_job_by_id(client, args)
            elif command == f'{COMMAND_PREFIX}-retrohunt-jobs-create':
                results = create_retrohunt_jobs(client, args)
            elif command == f'{COMMAND_PREFIX}-retrohunt-jobs-get-matching-files':
                results = get_retrohunt_job_matching_files(client, args)
            elif command == f'{COMMAND_PREFIX}-quota-limits-list':
                results = get_quota_limits(client, args)
            else:
                raise NotImplementedError(f'Command "{command}" is not implemented')
            return_results(results)
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
