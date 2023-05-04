"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
from datetime import datetime
import typing
import urllib.parse

import dateutil
import requests

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

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
                 project_id: typing.Optional[int],
                 collection_ids: typing.Optional[typing.List[str]]):
        self._access_key: str = access_key
        self._secret_key: str = secret_key
        self.base_url: str = base_url

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=(200,))

        self.timeout: int = timeout
        self.limit: int = limit
        if project_id:
            self.project_id: int = project_id
        else:
            self.project_id = None

        if collection_ids:
            self.collection_ids: typing.List[str] = collection_ids
        else:
            self.collection_ids = None

    def make_request(self, method: str, endpoint: str, **kwargs) -> typing.Union[str, dict, bytes]:
        headers = {
            "INTRIGUE_ACCESS_KEY": self._access_key,
            "INTRIGUE_SECRET_KEY": self._secret_key
        }
        if kwargs.get('headers') is not None:
            headers.update(kwargs.pop('headers'))

        url = urljoin(self.base_url, endpoint)

        response = requests.request(method, url, headers=headers, **kwargs)

        response.raise_for_status()

        response_type = response.headers.get("content-type")
        if "application/json" in response_type:
            return response.json()
        elif "text/html" in response_type:
            return response.text
        else:
            return response.content

    def get_projects_list(self) -> typing.List:
        endpoint = 'projects'
        response = self.make_request('GET', endpoint)

        if not response.get('success'):
            raise DemistoException('The ASM API was unable to return'
                                   'a list of projects')

        return response.get('result', [])

    def get_collections_list(self, project_id: int) -> typing.List:
        endpoint = 'user_collections'

        response = self.make_request('GET', endpoint,
                                     headers={'PROJECT_ID': project_id})

        if not response.get('success'):
            raise DemistoException('The ASM API was unable to return'
                                   'a list of collections')

        return response.get('result', [])

    def get_issues_since_time(self,
                              since: Optional[datetime],
                              until: Optional[datetime] = None) -> typing.Generator[dict, None, None]:
        if not until:
            until = datetime.utcnow()

        endpoint = 'search/issues/'
        collections_query = 'collection:' + ' collection:'.join(self.collection_ids)

        # Datetime format - 2022-10-07T17:36:37.000Z
        datetime_query = f' last_seen_before:{until.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}'
        if since:
            datetime_query = datetime_query + f' last_seen_after:{since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}'

        search_query = collections_query + datetime_query
        endpoint = endpoint + urllib.parse.quote(search_query)

        params = {'page': 0}

        while True:
            response = self.make_request('GET', endpoint, params=params,
                                         headers={'PROJECT_ID': self.project_id})

            if not response.get('success'):
                raise RuntimeError('Failed to retrieve issues from ASM')

            yield from response.get('result', {}).get('hits')

            if response.get('result', {}).get('more'):
                params['page'] = params['page'] + 1
            else:
                break

    def get_issue_details(self,
                          issue_id: str) -> dict:
        endpoint = f'issues/{issue_id}'

        response = self.make_request('GET', endpoint,
                                     headers={'PROJECT_ID': self.project_id})

        if not response.get('success'):
            raise DemistoException('The ASM API was unable to return details for'
                                   f'issue {issue_id} in project {self.project_id}')

        return response['result']

    def get_notes(self,
                  resource_type: str,
                  resource_id: str) -> dict:
        endpoint = f'notes/{resource_type}/{resource_id}'

        response = self.make_request('GET', endpoint,
                                     headers={'PROJECT_ID': self.project_id})

        if not response.get('success'):
            raise DemistoException('The ASM API was unable to return notes for'
                                   f'{resource_type} {resource_id} in project {self.project_id}')

        return response['result']

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}
    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)
def helper_create_incident(issue: dict, project_id: str) -> dict:
    severity_map = {1: 4, 2: 3, 3: 2, 4: 1, 5: 0.5}

    raw_json = issue
    raw_json['mirror_direction'] = 'Both'
    raw_json['mirror_instance'] = demisto.integrationInstance()

    issue = {
        'name': issue['summary']['pretty_name'],
        'details': json.dumps(issue, indent=4),
        'occurred': dateutil.parser.parse(issue['first_seen']).isoformat(),
        'severity': severity_map.get(issue['summary']['severity']),
        'rawJSON': json.dumps(raw_json),
        'dbotMirrorId': issue.get('id', issue.get('uid')),
        'CustomFields': {
            'masmcollection': issue['collection'],
            'masmproject': project_id,
            'masmconfirmed': issue['summary']['confidence'] == 'confirmed',
            'masmentityname': issue['entity_name'],
            'masmcategory': issue['summary']['category']
        }
    }

    return issue

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

        fetch_incidents(client)

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

    output = [{'Name': proj['name'],
               'ID': proj['id'],
               'Owner': proj['owner_email']} for proj in response]

    return CommandResults(
        outputs_prefix='MandiantAdvantageASM.Projects',
        outputs=output,
        ignore_auto_extract=True
    )


def get_collections(client: Client, args: dict = None) -> CommandResults:
    args = args if args else {}

    project_id: int = client.project_id

    if 'project_id' in args:
        project_id = args.get('project_id')

    response = client.get_collections_list(project_id)

    output = [{'Name': collection['printable_name'],
               'ID': collection['name'],
               'Owner': collection['owner_name']} for collection in response]

    return CommandResults(
        outputs_prefix='MandiantAdvantageASM.Collections',
        outputs=output,
        ignore_auto_extract=True
    )


def fetch_incidents(client: Client):
    last_run = demisto.getLastRun()
    last_start_time: datetime

    params = demisto.params()

    if last_run and 'start_time' in last_run and last_run['start_time']:
        last_start_time = dateutil.parser.parse(last_run.get('start_time'))
    else:
        last_start_time = dateparser.parse(params.get("first_fetch"), settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})

    issues = client.get_issues_since_time(last_start_time)
    most_recent_update = None

    parsed_issues = []

    for issue in issues:
        incident_details = client.get_issue_details(issue["id"])
        new_incident = helper_create_incident(incident_details, client.project_id)
        new_incident['dbotMirrorLastSync'] = datetime.fromtimestamp(0).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_incident['lastupdatetime'] = new_incident['dbotMirrorLastSync']

        parsed_issues.append(new_incident)
        most_recent_update = issue['last_seen']

        if len(parsed_issues) >= client.limit:
            break

    parsed_issues = filter_incidents_by_duplicates_and_limit(
        incidents_res=parsed_issues, last_run=last_run, fetch_limit=client.limit, id_field='dbotMirrorId'
    )

    new_issues = [json.loads(i['rawJSON'])['uid'] for i in parsed_issues]

    last_run = {
        'start_time': most_recent_update,
        'found_incident_ids': list(set(new_issues + last_run.get('found_incident_ids', [])))
    }

    demisto.setLastRun(last_run)
    demisto.incidents(parsed_issues)


def get_remote_data_command(client: Client, args: dict):
    parsed_args = GetRemoteDataArgs(args)
    last_updated: datetime = arg_to_datetime(parsed_args.last_update)

    demisto.debug(f'get-remote-data {parsed_args.last_update} {parsed_args.remote_incident_id}')

    try:
        masm_id = parsed_args.remote_incident_id

        new_incident_data = helper_create_incident(client.get_issue_details(masm_id), client.project_id)
        new_incident_data['dbotMirrorLastSync'] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        new_incident_data['lastupdatedtime'] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        notes = client.get_notes('issue', masm_id)
        demisto.debug(notes)
        notes_entries = []
        for note in notes:
            timestamp: datetime = dateutil.parser.parse(note['created_at'])
            if timestamp.timestamp() > last_updated.timestamp():
                new_note = {
                    'Type': EntryType.NOTE,
                    'Contents': f"{note['note']}\n"
                                f"{note['created_by_user']['printable_name']}",
                    'ContentsFormat': EntryFormat.MARKDOWN,
                    'Note': True,
                }
                notes_entries.append(new_note)

        new_incident_data['id'] = masm_id
        new_incident_data['in_mirror_error'] = ''

        return GetRemoteDataResponse(new_incident_data, notes_entries)
    except Exception as e:
        print(e)

def update_remote_system_command(client: Client, args: dict):
    parsed_args = UpdateRemoteSystemArgs(args)

    if parsed_args.delta:
        demisto.debug(f'Detected following delta keys: {str(list(parsed_args.delta.keys()))}')

    demisto.debug(parsed_args.inc_status)

    remote_incident_id = parsed_args.remote_incident_id

    updated_incident = {}

    if not parsed_args.remote_incident_id or parsed_args.incident_changed:
        if parsed_args.remote_incident_id:
            old_incident = client.get_issue_details(remote_incident_id)
            old_incident.update(parsed_args.delta)

            parsed_args.data = old_incident
        else:
            parsed_args.data['createInvestigation'] = True

        demisto.debug(json.dumps(parsed_args.data))

    issue_status = parsed_args.delta.get("runStatus")
    if issue_status:
        demisto.debug(f"New issue status: {XSOAR_TO_ASM_STATUS_MAP[issue_status]}")
        # TODO: Push update to XSOAR

    warroom_entries = parsed_args.entries
    for entry in warroom_entries:
        # TODO: Identify if entry originated from ASM or XSOAR
        demisto.debug(entry)


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    dummy = args.get('dummy', None)
    if not dummy:
        raise ValueError('dummy not specified')

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


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
    collections_raw = params.get('collection_ids', '').split(',')
    collections = [c.strip() for c in collections_raw]

    limit = int(params.get("max_fetch", 50))
    timeout = int(params.get("timeout", 60))

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
            'test-module': test_module,
            'fetch-incidents': fetch_incidents
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

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement
        else:
            raise NotImplementedError('The command you tried to run doens\'t exist')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
