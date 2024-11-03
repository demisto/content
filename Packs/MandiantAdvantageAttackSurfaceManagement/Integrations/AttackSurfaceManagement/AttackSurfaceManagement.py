from datetime import datetime
import typing
import urllib.parse
from dateutil import parser

import dateutil

# import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
XSOAR_TO_ASM_STATUS_MAP = {
    0: "open_new",
    1: "open_in_progress",
    2: "closed",
    3: "closed"
}


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self,
                 access_key: str,
                 secret_key: str,
                 base_url: str,
                 verify: bool,
                 proxy: bool,
                 timeout: int,
                 limit: int,
                 project_id: int | None,
                 collection_ids: list[str] | None):
        self._access_key: str = access_key
        self._secret_key: str = secret_key
        self.base_url: str = base_url

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200,))

        self.timeout: int = timeout
        self.limit: int = limit

        self.project_id: Optional[int] = project_id
        self.collection_ids: list[str] = collection_ids or []

    def get_projects_list(self) -> list:
        endpoint = 'projects'
        response = self._http_request('GET', endpoint, headers=self.get_headers(include_project=False))

        if not isinstance(response, dict) or not response.get('success'):
            raise DemistoException('The ASM API was unable to return'
                                   'a list of projects')

        return response.get('result') or []

    def get_collections_list(self, project_id: int) -> list:
        endpoint = 'user_collections'

        response = self._http_request('GET', endpoint,
                                      headers=self.get_headers(project_id=project_id))

        if not isinstance(response, dict) or not response.get('success'):
            raise DemistoException('The ASM API was unable to return'
                                   'a list of collections')

        return response.get('result') or []

    def get_issues_since_time(self,
                              since: Optional[datetime],
                              until: Optional[datetime] = None,
                              severity: int = 1) -> typing.Generator[dict, None, None]:
        if not until:
            until = datetime.utcnow()

        endpoint = 'search/issues/'
        collections_query = 'collection:' + ' collection:'.join(self.collection_ids)
        severity_query = f' severity_gte:{severity}'

        # Datetime format - 2022-10-07T17:36:37.000Z
        datetime_query = f' last_seen_before:{until.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}'
        if since:
            datetime_query = datetime_query + f' last_seen_after:{since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}'

        search_query = collections_query + datetime_query + severity_query
        endpoint = endpoint + urllib.parse.quote(search_query)

        params = {'page': 0}

        while True:
            response = self._http_request('GET', endpoint, params=params,
                                          headers=self.get_headers())

            if not isinstance(response, dict) or not response.get('success'):
                raise RuntimeError(f'Failed to retrieve issues from ASM {response} {search_query}')

            yield from response.get('result', {}).get('hits')

            if response.get('result', {}).get('more'):
                params['page'] = params['page'] + 1
            else:
                break

    def get_issue_details(self,
                          issue_id: str) -> dict:
        endpoint = f'issues/{issue_id}'

        response = self._http_request('GET', endpoint,
                                      headers=self.get_headers())

        if not isinstance(response, dict) or not response.get('success'):
            raise DemistoException('The ASM API was unable to return details for'
                                   f'issue {issue_id} in project {self.project_id}')

        return response.get('result') or {}

    def get_notes(self,
                  resource_type: str,
                  resource_id: str) -> list:
        endpoint = f'notes/{resource_type}/{resource_id}'

        response = self._http_request('GET', endpoint,
                                      headers=self.get_headers())

        if not isinstance(response, dict) or not response.get('success'):
            raise DemistoException('The ASM API was unable to return notes for'
                                   f'{resource_type} {resource_id} in project {self.project_id}')

        return response.get('result') or []

    def update_issue_status(self,
                            indicator_id: str,
                            indicator_status: int):
        endpoint = f'/issues/{indicator_id}/status'
        request_body = {
            'status': XSOAR_TO_ASM_STATUS_MAP[indicator_status]
        }

        response = self._http_request('POST', endpoint, json_data=request_body, headers=self.get_headers())

        if not isinstance(response, dict) or not response.get('success'):
            raise DemistoException('The ASM API was unable to update'
                                   'the status of the issue')

        return response.get('result') or False

    def get_headers(self, include_project: bool = True, project_id=None):
        if not project_id:
            project_id = self.project_id
        headers = {
            "INTRIGUE_ACCESS_KEY": self._access_key,
            "INTRIGUE_SECRET_KEY": self._secret_key
        }
        if include_project:
            headers['PROJECT_ID'] = str(project_id)

        return headers


''' HELPER FUNCTIONS '''


def helper_create_incident(issue: dict, project_id: int) -> dict:
    severity_map = {1: 4, 2: 3, 3: 2, 4: 1, 5: 0.5}

    raw_json = issue
    raw_json['mirror_direction'] = 'Both'
    raw_json['mirror_instance'] = demisto.integrationInstance()

    issue = {
        'name': issue.get('summary', {}).get('pretty_name'),
        'details': json.dumps(issue, indent=4),
        'severity': severity_map.get(issue.get('summary', {}).get('severity'),),
        'rawJSON': json.dumps(raw_json),
        'dbotMirrorId': issue.get('id', issue.get('uid')),
        'CustomFields': {
            'masmcollection': issue.get('collection'),
            'masmproject': str(project_id),
            'masmconfirmed': issue.get('summary', {}).get('confidence') == 'confirmed',
            'masmentityname': issue.get('entity_name'),
            'masmcategory': issue.get('summary', {}).get('category')
        }
    }

    occurred = raw_json.get('first_seen')
    if isinstance(occurred, str):
        issue['occurred'] = parser.parse(occurred).isoformat()

    return issue


def fetch_incident_helper(client: Client, last_run: dict) -> tuple[dict, list]:
    last_start_time: datetime

    params = demisto.params()

    if not client.project_id:
        raise DemistoException('Must configure a Project ID to fetch incidents from Mandiant ASM')

    last_run_time = last_run.get('time')

    if last_run_time and isinstance(last_run_time, str):
        last_start_time = parser.parse(last_run_time)
    else:
        parsed_time = dateparser.parse(params.get("first_fetch"), settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})
        if not parsed_time:
            parsed_time = datetime.now()
        last_start_time = parsed_time

    issues = client.get_issues_since_time(last_start_time, severity=params.get('minimum_severity'))
    most_recent_update = None

    parsed_issues = []

    for issue in issues:
        incident_details = client.get_issue_details(issue["id"])
        new_incident = helper_create_incident(incident_details, client.project_id)
        new_incident['dbotMirrorLastSync'] = datetime.fromtimestamp(0).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_incident['lastupdatetime'] = new_incident['dbotMirrorLastSync']

        parsed_issues.append(new_incident)

        # If removed, far more issues can be pulled than will be ingested during an ingestion run, resulting
        # in timeouts or apparent freezing
        if len(parsed_issues) >= client.limit:
            break

    parsed_issues = filter_incidents_by_duplicates_and_limit(
        incidents_res=parsed_issues, last_run=last_run, fetch_limit=client.limit, id_field='dbotMirrorId'
    )
    if parsed_issues:
        most_recent_update = parsed_issues[-1].get('last_seen')

    new_issues = [json.loads(i['rawJSON'])['uid'] for i in parsed_issues]

    last_run = {
        'time': most_recent_update,
        'found_incident_ids': list(set(new_issues + last_run.get('found_incident_ids', [])))
    }

    return last_run, parsed_issues,


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        client.get_projects_list()

        if demisto.params().get('isFetch', False):

            last_run = demisto.getLastRun()
            fetch_incident_helper(client, last_run)

        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure Access Key and Secret Key is correctly set'
        else:
            raise e
    return message


def get_projects(client: Client, args: dict = None) -> CommandResults:
    args = args if args else {}

    response = client.get_projects_list()

    output = [{'Name': proj.get('name'),
               'ID': proj.get('id'),
               'Owner': proj.get('owner_email')} for proj in response]

    return CommandResults(
        outputs_prefix='MandiantAdvantageASM.Projects',
        outputs=output,
        ignore_auto_extract=True
    )


def get_collections(client: Client, args: dict = None) -> CommandResults:
    args = args or {}

    project_id: int = args.get('project_id', client.project_id)

    response = client.get_collections_list(project_id)

    output = [{'Name': collection.get('printable_name'),
               'ID': collection.get('name'),
               'Owner': collection.get('owner_name')} for collection in response]

    return CommandResults(
        outputs_prefix='MandiantAdvantageASM.Collections',
        outputs=output,
        ignore_auto_extract=True
    )


def fetch_incidents(client: Client):
    last_run = demisto.getLastRun()

    last_run, new_issues = fetch_incident_helper(client, last_run)

    demisto.setLastRun(last_run)
    return new_issues


def get_remote_data_command(client: Client, args: dict):
    parsed_args = GetRemoteDataArgs(args)
    if parsed_args.last_update:
        parsed_date = arg_to_datetime(parsed_args.last_update)
    if not parsed_date:
        parsed_date = datetime.now()
    last_updated = parsed_date

    if not client.project_id:
        raise DemistoException('Must configure a Project ID to fetch incidents from Mandiant ASM')

    try:
        masm_id = parsed_args.remote_incident_id

        issue_details = client.get_issue_details(masm_id)

        new_incident_data = helper_create_incident(issue_details, client.project_id)

        notes = client.get_notes('issue', masm_id)
        notes_entries = []
        for note in notes:
            timestamp: datetime = dateutil.parser.parse(note.get('created_at'))
            if timestamp.timestamp() > last_updated.timestamp():
                new_note = {
                    'Type': EntryType.NOTE,
                    'Contents': f"{note['note']}\n"
                                f"{note['created_by_user']['printable_name']}",
                    'ContentsFormat': EntryFormat.MARKDOWN,
                    'Note': True,
                    'Tags': ['note_from_ma_asm']
                }
                notes_entries.append(new_note)

        if issue_details.get("status", "").lower().startswith("closed"):
            notes_entries.append({
                'Type': EntryType.NOTE,
                'Contents': {
                    'dbotIncidentClose': True,
                    'closeNotes': "Closed in Mandiant Advantage ASM",
                    'closeReason': "Closed in Mandiant Advantage ASM"
                },
                'ContentsFormat': EntryFormat.JSON
            })

        new_incident_data['id'] = masm_id

        return GetRemoteDataResponse(new_incident_data, notes_entries)
    except Exception as e:
        raise e


def update_remote_system_command(client: Client, args: dict):
    parsed_args = UpdateRemoteSystemArgs(args)

    remote_incident_id = parsed_args.remote_incident_id

    issue_status = parsed_args.delta.get("runStatus")
    if issue_status is not None:
        client.update_issue_status(remote_incident_id, parsed_args.inc_status)

    if not parsed_args.remote_incident_id or parsed_args.incident_changed:
        if parsed_args.remote_incident_id:
            old_incident = client.get_issue_details(remote_incident_id)

            old_incident.update(parsed_args.delta)

            parsed_args.data = old_incident
        else:
            parsed_args.data['createInvestigation'] = True

    return remote_incident_id


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    # get the service API url
    base_url = urljoin(params['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    access_key = params.get('credentials', {}).get('identifier')
    secret_key = params.get('credentials', {}).get('password')
    project_id = params.get('project_id')
    collections = argToList(params.get('collection_ids', []))

    limit = arg_to_number(params.get("max_fetch", 50)) or 50
    timeout = arg_to_number(params.get("timeout", 60)) or 60

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        client = Client(
            access_key=access_key,
            secret_key=secret_key,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            timeout=timeout,
            limit=limit,
            project_id=project_id,
            collection_ids=collections
        )

        commands_with_args: dict[str, typing.Callable] = {
            'get-remote-data': get_remote_data_command,
            'update-remote-system': update_remote_system_command,
            'attacksurfacemanagement-get-projects': get_projects,
            'attacksurfacemanagement-get-collections': get_collections
        }
        commands_no_args: dict[str, typing.Callable] = {
            'test-module': test_module
        }

        command = demisto.command()

        if command in commands_no_args:
            # This is the call made when pressing the integration Test button.
            result = commands_no_args[command](client)
            return_results(result)

        elif command in commands_with_args:
            args = demisto.args()
            results = commands_with_args[command](client, args)
            return_results(results)

        elif command == 'fetch-incidents':
            results = fetch_incidents(client)
            demisto.incidents(results)

        # TODO: ADD command cases for the commands you will implement
        else:
            raise NotImplementedError('The command you tried to run doens\'t exist')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
