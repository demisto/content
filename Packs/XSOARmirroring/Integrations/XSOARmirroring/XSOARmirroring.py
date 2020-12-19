import demistomock as demisto
from CommonServerPython import *
import json
import requests
import traceback
import dateparser
from typing import Any, Dict, Tuple, List, Optional, cast, Set

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''


MAX_INCIDENTS_TO_FETCH = 100
FIELDS_TO_COPY_FROM_REMOTE_INCIDENT = [
    'name', 'rawName', 'severity', 'occurred', 'modified', 'roles', 'type', 'rawType', 'status', 'reason', 'created',
    'closed', 'sla', 'labels', 'attachment', 'details', 'openDuration', 'lastOpen', 'owner', 'closeReason',
    'rawCloseReason', 'closeNotes', 'playbookId', 'dueDate', 'reminder', 'runStatus', 'notifyTime', 'phase',
    'rawPhase', 'CustomFields', 'category', 'rawCategory'
]

MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}
''' CLIENT CLASS '''


class Client(BaseClient):
    def search_incidents(self, query: Optional[str], max_results: Optional[int],
                         start_time: Optional[int]) -> List[Dict[str, Any]]:
        data = {
            'filter': {
                'query': query,
                'size': max_results or 10,
                'fromDate': timestamp_to_datestring(start_time)
            }
        }
        return self._http_request(
            method='POST',
            url_suffix='/incidents/search',
            json_data=data
        ).get('data')

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/incident/load/{incident_id}'
        )

    def get_file_entry(self, entry_id: str) -> requests.Response:
        return self._http_request(
            method='GET',
            url_suffix=f'/entry/download/{entry_id}',
            resp_type='content'
        )

    def get_incident_entries(self, incident_id: str, from_date: Optional[int], max_results: Optional[int],
                             categories: Optional[List[str]], tags: Optional[List[str]],
                             tags_and_operator: bool) -> List[Dict[str, Any]]:
        data = {
            'pageSize': max_results or 50,
            'fromTime': timestamp_to_datestring(from_date),
            'categories': categories,
            'tags': tags,
            'tagsAndOperator': tags_and_operator
        }
        inv_with_entries = self._http_request(
            method='POST',
            url_suffix=f'/investigation/{incident_id}',
            json_data=data
        )
        return inv_with_entries.get('entries')

    def get_incident_fields(self) -> List[Dict[str, Any]]:
        return self._http_request(
            method='GET',
            url_suffix='/incidentfields'
        )

    def get_incident_types(self) -> List[Dict[str, Any]]:
        return self._http_request(
            method='GET',
            url_suffix='/incidenttype'
        )

    def update_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/incident',
            json_data=incident
        )

    def close_incident(self, incident_id: str, incident_ver: int, close_reason: Optional[str],
                       close_notes: Optional[str]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/incident/close',
            json_data={
                'id': incident_id,
                'version': incident_ver,
                'closeNotes': close_notes,
                'closeReason': close_reason
            }
        )

    def add_incident_entry(self, incident_id: Optional[str], entry: Dict[str, Any]):
        if entry.get('type') == 3:
            path_res = demisto.getFilePath(entry.get('id'))
            full_file_name = path_res.get('name')

            with open(path_res.get('path'), 'rb') as file_to_send:
                self._http_request(
                    method='POST',
                    url_suffix=f'/entry/upload/{incident_id}',
                    files={
                        "file": (full_file_name, file_to_send, 'application/octet-stream')
                    },
                )

        if not entry.get('note', False):
            demisto.debug(f'the entry has inv_id {incident_id}\nformat {entry.get("format")}\n contents '
                          f'{entry.get("contents")}')
            self._http_request(
                method='POST',
                url_suffix='/entry/formatted',
                json_data={
                    'contents': entry.get('contents'),
                    'format': entry.get('format'),
                    'investigationId': incident_id
                }
            )
        else:
            demisto.debug(f'the entry has inv_id {incident_id}\ndata {entry.get("date")}\n'
                          f'markdown {entry.get("markdown")}')
            entry_format = True if entry.get('format') == 'markdown' else False
            self._http_request(
                method='POST',
                url_suffix='/entry/note',
                json_data={
                    "investigationId": incident_id,
                    "data": entry.get('contents', "False"),
                    "markdown": entry_format
                }
            )


''' HELPER FUNCTIONS '''


def arg_to_timestamp(arg: str, arg_name: str, required: bool = False):
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``-1`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return -1

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: XSOAR client to use

    :type first_fetch_time: ``int``
    :param first_fetch_time: First fetch time parameter value.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.search_incidents(max_results=1, start_time=first_fetch_time, query=None)
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], query: Optional[str], mirror_direction: str,
                    mirror_tag: List[str]) -> Tuple[Dict[str, int], List[dict]]:
    """This function retrieves new incidents every interval (default is 1 minute).

    :type client: ``Client``
    :param client: XSOAR client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type query: ``Optional[str]``
    :param query:
        query to fetch the relevant incidents

    :type mirror_direction: ``str``
    :param mirror_direction:
        Mirror direction for the fetched incidents

    :type mirror_tag: ``List[str]``
    :param mirror_tag:
        The tags that you will mirror out of the incident.

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    last_fetch: int = last_run.get('last_fetch', -1)
    if last_fetch == -1:
        last_fetch = first_fetch_time  # type: ignore
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)
    incidents_result: List[Dict[str, Any]] = []
    last_fetch_milliseconds = last_fetch * 1000
    created_filter = timestamp_to_datestring(last_fetch_milliseconds)

    if query:
        query += f' and created:>="{created_filter}"'
    else:
        query = f'created:>="{created_filter}"'

    demisto.debug(f'Fetching incidents since last fetch: {created_filter}')
    incidents = client.search_incidents(
        query=query,
        max_results=max_results,
        start_time=last_fetch_milliseconds
    )

    for incident in incidents:
        incident_result: Dict[str, Any] = dict()
        incident_result['dbotMirrorDirection'] = MIRROR_DIRECTION[mirror_direction]  # type: ignore
        incident['dbotMirrorInstance'] = demisto.integrationInstance()
        incident_result['dbotMirrorTags'] = mirror_tag if mirror_tag else None  # type: ignore
        incident_result['dbotMirrorId'] = incident['id']

        for key, value in incident.items():
            if key in FIELDS_TO_COPY_FROM_REMOTE_INCIDENT:
                incident_result[key] = value

        incident_result['rawJSON'] = json.dumps(incident)

        file_attachments = []
        if incident.get('attachment') and len(incident.get('attachment', [])) > 0 and incident.get('investigationId'):
            entries = client.get_incident_entries(
                incident_id=incident['investigationId'],  # type: ignore
                from_date=0,
                max_results=10,
                categories=['attachments'],
                tags=None,
                tags_and_operator=False
            )

            for entry in entries:
                if 'file' in entry and entry.get('file'):
                    file_entry_content = client.get_file_entry(entry.get('id'))  # type: ignore
                    file_result = fileResult(entry['file'], file_entry_content)
                    if any(attachment.get('name') == entry['file'] for attachment in incident.get('attachment', [])):
                        if file_result['Type'] == EntryType.ERROR:
                            raise Exception(f"Error getting attachment: {str(file_result.get('Contents', ''))}")

                        file_attachments.append({
                            'path': file_result.get('FileID', ''),
                            'name': file_result.get('File', '')
                        })

        incident_result['attachment'] = file_attachments
        incidents_result.append(incident_result)
        incident_created_time = arg_to_timestamp(
            arg=incident.get('created'),  # type: ignore
            arg_name='created',
            required=True
        )

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time + 1}
    return next_run, incidents_result


def search_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """xsoar-search-incidents command: Search XSOAR incidents

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['query']`` query to search incidents
        ``args['start_time']``  start time as ISO8601 date or seconds since epoch
        ``args['max_results']`` maximum number of results to return
        ``args['columns']`` which columns to display in the table

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains incidents

    :rtype: ``CommandResults``
    """

    query = args.get('query')
    start_date = arg_to_datetime(
        arg=args.get('start_time', '3 days'),
        arg_name='start_time',
        required=False
    )
    max_results = arg_to_number(
        arg=args.get('max_results'),
        arg_name='max_results',
        required=False
    )
    incidents = client.search_incidents(
        query=query,
        start_time=int(start_date.timestamp() * 1000) if start_date else 0,
        max_results=max_results
    )
    if not incidents:
        incidents = []

    return CommandResults(
        outputs_prefix='XSOAR.Incident',
        outputs_key_field='id',
        outputs=incidents
    )


def get_incident_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """xsoar-get-incident command: Returns an incident and all entries with given categories and tags

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['id']`` incident ID to return
        ``args['from_date']`` only return entries after last update
        ``args['categories']`` only return entries with given categories
        ``args['tags']`` only return entries with given tags

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """

    incident_id = args.get('id', None)
    if not incident_id:
        raise ValueError('id not specified')

    from_date_arg = args.get('from_date', '3 days')
    from_date = arg_to_timestamp(
        arg=from_date_arg,
        arg_name='from_date',
        required=False
    )
    max_results = arg_to_number(
        arg=args.get('max_results'),
        arg_name='max_results',
        required=False
    )
    categories = args.get('categories', None)
    if categories:
        categories = categories.split(',')

    tags = args.get('tags', None)
    if tags:
        tags = tags.split(',')

    incident = client.get_incident(incident_id=incident_id)
    incident_title = incident.get('name', incident_id)

    readable_output = tableToMarkdown(f'Incident {incident_title}', incident)

    entries = client.get_incident_entries(
        incident_id=incident_id,
        from_date=from_date * 1000,
        max_results=max_results,
        categories=categories,
        tags=tags,
        tags_and_operator=True,
    )

    readable_output += '\n\n' + tableToMarkdown(f'Last entries since {timestamp_to_datestring(from_date * 1000)}',
                                                entries, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='XSOAR.Incident',
        outputs_key_field='incident_id',
        outputs=incident
    )


def get_mapping_fields_command(client: Client) -> GetMappingFieldsResponse:
    """get-mapping-fields command: Returns the list of fields for an incident type

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['type']`` incident type to retrieve fields for

    :return:
        A ``Dict[str, Any]`` object with keys as field names and description as values

    :rtype: ``Dict[str, Any]``
    """
    all_mappings = GetMappingFieldsResponse()
    incident_fields: List[dict] = client.get_incident_fields()

    types = client.get_incident_types()
    for incident_type_obj in types:
        incident_type_name: str = incident_type_obj.get('name')  # type: ignore
        incident_type_scheme = SchemeTypeMapping(type_name=incident_type_name)
        demisto.debug(f'Collecting incident mapping for incident type - "{incident_type_name}"')

        for field in incident_fields:
            if field.get('group') == 0 and field.get('cliName') is not None and \
                    (field.get('associatedToAll') or incident_type_name in  # type: ignore
                     field.get('associatedTypes')):  # type: ignore
                incident_type_scheme.add_field(name=field.get('cliName'),
                                               description=f"{field.get('name')} - {field.get('type')}")

        all_mappings.add_scheme_type(incident_type_scheme)

    default_scheme = SchemeTypeMapping(type_name="Default Mapping")
    demisto.debug('Collecting the default incident scheme')
    for field in incident_fields:
        if field.get('group') == 0 and field.get('associatedToAll'):
            default_scheme.add_field(name=field.get('cliName'),
                                     description=f"{field.get('name')} - {field.get('type')}")

    all_mappings.add_scheme_type(default_scheme)
    return all_mappings


def demisto_debug(msg):
    if demisto.params().get('debug_mode'):
        demisto.info(msg)
    else:
        demisto.debug(msg)


def get_remote_data_command(client: Client, args: Dict[str, Any], params: Dict[str, Any]) -> GetRemoteDataResponse:
    """get-remote-data command: Returns an updated incident and entries

    :type client: ``Client``
    :param Client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['id']`` incident id to retrieve
        ``args['lastUpdate']`` when was the last time we retrieved data

    :return:
        A ``List[Dict[str, Any]]`` first entry is the incident (which can be completely empty) and others are the new entries

    :rtype: ``List[Dict[str, Any]]``
    """
    demisto_debug(f'##### get-remote-data args: {json.dumps(args, indent=4)}')
    incident = None
    try:
        args['lastUpdate'] = arg_to_timestamp(
            arg=args.get('lastUpdate'),  # type: ignore
            arg_name='lastUpdate',
            required=True
        )
        remote_args = GetRemoteDataArgs(args)
        demisto_debug(f'Getting update for remote [{remote_args.remote_incident_id}]')

        categories = params.get('categories', None)
        if categories:
            categories = categories.split(',')
        else:
            categories = None
        tags = params.get('tags', None)
        if tags:
            tags = tags.split(',')
        else:
            tags = None

        incident = client.get_incident(incident_id=remote_args.remote_incident_id)  # type: ignore
        # If incident was modified before we last updated, no need to return it
        modified = arg_to_timestamp(
            arg=incident.get('modified'),  # type: ignore
            arg_name='modified',
            required=False
        )
        occurred = arg_to_timestamp(
            arg=incident.get('occurred'),  # type: ignore
            arg_name='occurred',
            required=False
        )

        if (datetime.fromtimestamp(modified) - datetime.fromtimestamp(occurred) < timedelta(minutes=1)
                and datetime.fromtimestamp(remote_args.last_update) - datetime.fromtimestamp(modified)
                < timedelta(minutes=1)):
            remote_args.last_update = occurred + 1
            # in case new entries created less than a minute after incident creation

        demisto_debug(f'tags: {tags}')
        demisto_debug(f'tags: {categories}')
        entries = client.get_incident_entries(
            incident_id=remote_args.remote_incident_id,  # type: ignore
            from_date=remote_args.last_update * 1000,
            max_results=100,
            categories=categories,
            tags=tags,
            tags_and_operator=True
        )

        formatted_entries = []
        # file_attachments = []

        if entries:
            for entry in entries:
                if 'file' in entry and entry.get('file'):
                    file_entry_content = client.get_file_entry(entry.get('id'))  # type: ignore
                    file_result = fileResult(entry['file'], file_entry_content)

                    formatted_entries.append(file_result)
                else:
                    formatted_entries.append({
                        'Type': entry.get('type'),
                        'Category': entry.get('category'),
                        'Contents': entry.get('contents'),
                        'ContentsFormat': entry.get('format'),
                        'Tags': entry.get('tags'),  # the list of tags to add to the entry
                        'Note': entry.get('note')  # boolean, True for Note, False otherwise
                    })

        # Handle if the incident closed remotely
        if incident.get('status') == IncidentStatus.DONE:
            formatted_entries.append({
                'Type': EntryType.NOTE,
                'Contents': {
                    'dbotIncidentClose': True,
                    'closeReason': incident.get('closeReason'),
                    'closeNotes': incident.get('closeNotes')
                },
                'ContentsFormat': EntryFormat.JSON
            })

        incident['in_mirror_error'] = ''

        if remote_args.last_update >= modified and not formatted_entries:
            demisto.debug(f'Nothing new in the incident, incident id {remote_args.remote_incident_id}')
            incident = {}  # this empties out the incident, which will result in not updating the local one

        incident['dbotMirrorInstance'] = demisto.integrationInstance()
        incident['id'] = remote_args.remote_incident_id
        # incident['attachment'] = file_attachments
        mirror_data = GetRemoteDataResponse(
            mirrored_object=incident,
            entries=formatted_entries
        )
        return mirror_data

    except Exception as e:
        demisto.error(f"Error in XSOAR incoming mirror for incident {args['id']} \nError message: {str(e)}")
        incident = {
            'id': args['id'],
            'in_mirror_error': str(e)
        }

        return GetRemoteDataResponse(
            mirrored_object=incident,
            entries=[]
        )


def update_remote_system_command(client: Client, args: Dict[str, Any], mirror_tags: Set[str]) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :type mirror_tags: ``Optional[str]``
    :param mirror_tags:
        The tag that you will mirror out of the incident.

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    if parsed_args.delta:
        demisto.debug(f'Got the following delta keys {str(list(parsed_args.delta.keys()))}')

    demisto.debug(f'Sending incident with remote ID [{parsed_args.remote_incident_id}] to remote system\n')

    new_incident_id: str = parsed_args.remote_incident_id  # type: ignore
    updated_incident = {}
    if not parsed_args.remote_incident_id or parsed_args.incident_changed:
        if parsed_args.remote_incident_id:
            # First, get the incident as we need the version
            old_incident = client.get_incident(incident_id=parsed_args.remote_incident_id)
            for changed_key in parsed_args.delta.keys():
                old_incident[changed_key] = parsed_args.delta[changed_key]  # type: ignore

            parsed_args.data = old_incident

        else:
            parsed_args.data['createInvestigation'] = True
            # This is used to identify the custom field, so that we will know the source of the incident
            # and will not mirror it in afterwards
            parsed_args.data['CustomFields'] = {
                'frompong': 'true'
            }

        updated_incident = client.update_incident(incident=parsed_args.data)
        new_incident_id = updated_incident['id']
        demisto.debug(f'Got back ID [{new_incident_id}]')

    else:
        demisto.debug(f'Skipping updating remote incident fields [{parsed_args.remote_incident_id}] as it is '
                      f'not new nor changed.')

    if parsed_args.entries:
        for entry in parsed_args.entries:
            demisto.info(f"this is the tag {entry.get('tags', [])}")
            if mirror_tags.intersection(set(entry.get('tags', []))):
                demisto.debug(f'Sending entry {entry.get("id")}')
                client.add_incident_entry(incident_id=new_incident_id, entry=entry)

    # Close incident if relevant
    if updated_incident and parsed_args.inc_status == IncidentStatus.DONE:
        demisto.debug(f'Closing remote incident {new_incident_id}')
        client.close_incident(
            new_incident_id,
            updated_incident.get('version'),  # type: ignore
            parsed_args.data.get('closeReason'),
            parsed_args.data.get('closeNotes')
        )

    return new_incident_id


def main() -> None:
    api_key = demisto.params().get('apikey')
    base_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    proxy = demisto.params().get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    mirror_tags = set(demisto.params().get('mirror_tag', '').split(',')) \
        if demisto.params().get('mirror_tag') else set([])

    query = demisto.params().get('query', '') or ''
    disable_from_same_integration = demisto.params().get('disable_from_same_integration')
    if disable_from_same_integration:
        query += ' -sourceBrand:"XSOAR Mirroring"'

    max_results = arg_to_number(
        arg=demisto.params().get('max_fetch'),
        arg_name='max_fetch'
    )
    if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    try:
        headers = {
            'Authorization': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            if demisto.params().get('isFetch'):
                fetch_incidents(
                    client=client,
                    max_results=max_results,
                    last_run=demisto.getLastRun(),
                    first_fetch_time=first_fetch_time,
                    query=query,
                    mirror_direction=demisto.params().get('mirror_direction'),
                    mirror_tag=list(mirror_tags)
                )

            return_results(test_module(client, first_fetch_time))

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                query=query,
                mirror_direction=demisto.params().get('mirror_direction'),
                mirror_tag=list(mirror_tags)
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'xsoar-search-incidents':
            return_results(search_incidents_command(client, demisto.args()))

        elif demisto.command() == 'xsoar-get-incident':
            return_results(get_incident_command(client, demisto.args()))

        elif demisto.command() == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))

        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(client, demisto.args(), demisto.params()))

        elif demisto.command() == 'update-remote-system':
            return_results(update_remote_system_command(client, demisto.args(), mirror_tags))

        else:
            raise NotImplementedError('Command not implemented')

    except NotImplementedError:
        raise
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
