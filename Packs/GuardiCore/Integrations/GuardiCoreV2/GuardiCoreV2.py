import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any
import base64
import json
from dateparser import parse
from pytz import utc

# Disable insecure warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
INCIDENT_COLUMNS = ['id', 'incident_type', 'severity', 'start_time', 'end_time',
                    'ended', 'affected_assets']
ASSET_COLUMNS = ['asset_id', 'name', 'status', 'last_seen', 'ip_addresses',
                 'tenant_name']
''' CLIENT CLASS '''

INTEGRATION_CONTEXT_NAME = 'Guardicore'
INTEGRATION_NAME = 'GuardiCore v2'
GLOBAL_TIMEOUT = 10


class Client(BaseClient):
    """
       Client for GuardiCoreV2

       Args:
          username (str): The GuardiCore username for API access.
          password (str): The GuardiCore password for API access.
          base_url (str): The GuardiCore API server URL.
    """

    def __init__(self, proxy: bool, verify: bool, base_url: str, username: str,
                 password: str):
        super().__init__(proxy=proxy, verify=verify, base_url=base_url)
        self.username = username
        self.password = password
        self.base_url = base_url
        self.access_token = ""
        self._headers = {}

        self.login()

    def login(self):
        integration_context = get_integration_context()

        if self._is_access_token_valid(integration_context):
            access_token = integration_context.get('access_token')
            self._save_access_token(access_token)
        else:
            demisto.debug(
                f"{INTEGRATION_NAME} - Generating a new token (old one isn't valid anymore).")
            self.generate_new_token()

    def _save_access_token(self, access_token: str):
        self.access_token = access_token
        self._headers = {
            "Authorization": f'Bearer {access_token}'}

    def _is_access_token_valid(self, integration_context: dict) -> bool:
        access_token_expiration = integration_context.get('expires_in')
        access_token = integration_context.get('access_token')
        demisto.debug(
            f'{INTEGRATION_NAME} - Checking if context has valid access token...'
            + f'expiration: {access_token_expiration}, access_token: {access_token}')
        if access_token and access_token_expiration:
            access_token_expiration_datetime = datetime.strptime(
                access_token_expiration, DATE_FORMAT)
            return access_token_expiration_datetime > datetime.now()
        return False

    def generate_new_token(self):
        token = self.authenticate()
        self.save_jwt_token(token)
        self._save_access_token(token)

    def save_jwt_token(self, access_token: str):
        expiration = get_jwt_expiration(access_token)
        expiration_timestamp = datetime.fromtimestamp(expiration)
        context = {"access_token": access_token,
                   "expires_in": expiration_timestamp.strftime(DATE_FORMAT)}
        set_integration_context(context)
        demisto.debug(
            f"New access token that expires in : {expiration_timestamp.strftime(DATE_FORMAT)}"
            f" was set to integration_context.")

    def authenticate(self):
        body = {
            'username': self.username,
            'password': self.password
        }
        new_token = self._http_request(
            method='POST',
            url_suffix='/authenticate',
            json_data=body)

        if not new_token or not new_token.get('access_token'):
            raise DemistoException(
                f"{INTEGRATION_NAME} error: The client credentials are invalid.")

        new_token = new_token.get('access_token')
        return new_token

    def get_assets(self, url_params: dict):
        data = self._http_request(
            method='GET',
            url_suffix='/assets',
            params=url_params,
            timeout=GLOBAL_TIMEOUT
        )
        return data

    def get_incident(self, url_params: str):
        data = self._http_request(
            method='GET',
            url_suffix=f'/incidents/{url_params}',
            timeout=GLOBAL_TIMEOUT
        )
        return data

    def get_incidents(self, url_params: dict):
        data = self._http_request(
            method='GET',
            url_suffix='/incidents',
            params=url_params,
            timeout=GLOBAL_TIMEOUT
        )
        return data


''' HELPER FUNCTIONS '''


def get_jwt_expiration(token: str):
    if "." not in token:
        return 0
    jwt_token = base64.b64decode(token.split(".")[1] + '==')
    jwt_token = json.loads(jwt_token)
    return jwt_token.get("exp")


def calculate_fetch_start_time(last_fetch: Optional[str],
                               first_fetch: Optional[str]):
    # Taken from the MicrosoftCloudAppSecurity Integration
    if last_fetch is None:
        if not first_fetch:
            first_fetch = '3 days'
        first_fetch_dt = parse(first_fetch).replace(tzinfo=utc)  # type:ignore
        # Changing 10-digits timestamp to 13-digits by padding with zeroes,
        # since API supports 13-digits
        first_fetch_time = int(first_fetch_dt.timestamp()) * 1000
        return first_fetch_time
    else:
        return int(last_fetch)


def filter_human_readable(results: dict, human_columns: List[str]) -> dict:
    # Takes in results dict and filters out relevant human_columns.
    filtered = {}
    for hc in human_columns:
        if hc in results:
            filtered[hc] = results[hc]
    return filtered


def incident_severity_to_dbot_score(severity: int) -> int:
    if not isinstance(severity, int):
        return 0

    if severity <= 30:
        return 1  # low
    elif severity >= 50:
        return 3  # high
    return 2  # medium


def map_guardicore_os(os: int) -> str:
    if not isinstance(os, int):
        return 'Unknown'

    return {
        0: 'Unknown',
        1: 'Windows',
        2: 'Linux',
    }.get(os, 'Unknown')


''' COMMAND FUNCTIONS '''


def test_module(client: Client, is_fetch: bool = False) -> str:
    message: str = ''
    try:
        one_day = parse("1 days")
        assert one_day is not None
        from_time = int(
            one_day.replace(tzinfo=utc).timestamp()) * 1000
        now = parse("now")
        assert now is not None
        to_time = int(
            now.replace(tzinfo=utc).timestamp()) * 1000
        client.get_incidents({"from_time": from_time, "to_time": to_time})

        if is_fetch:
            fetch_incidents(client, {
                'limit': 10,
            })

        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(
                e):
            message = 'Authorization Error: make sure your username and password are correctly set.'
        else:
            raise e

    return message


def get_incidents(client: Client, args: dict[str, Any]):
    from_time = args.get('from_time', None)
    to_time = args.get('to_time', None)

    if not from_time or not to_time:
        raise DemistoException(
            f"{INTEGRATION_NAME} - get incidents needs from_time and to_time.")

    # Convert time format to epoch
    try:
        from_time = date_to_timestamp(from_time, DATE_FORMAT)
    except ValueError:
        from_time_date = parse(from_time)
        assert from_time_date is not None
        from_time = int(from_time_date.replace(tzinfo=utc).timestamp()) * 1000

    try:
        to_time = date_to_timestamp(to_time, DATE_FORMAT)
    except ValueError:
        to_time_date = parse(to_time)
        assert to_time_date is not None
        to_time = int(to_time_date.replace(tzinfo=utc).timestamp()) * 1000

    limit = int(args.get('limit', 50))
    offset = int(args.get('offset', 0))
    severity = args.get('severity', [])
    source = args.get('source', None)
    destination = args.get('destination', None)
    tag = args.get('tag', None)
    incident_type = args.get('incident_type', None)

    if incident_type == 'false' or incident_type == 'All':
        incident_type = None
    elif incident_type:
        incident_type = ",".join(incident_type).lower()

    result = client.get_incidents({
        "from_time": from_time,  # Epoch with ms
        "to_time": to_time,
        "limit": limit,
        "offset": offset,
        "severity": severity,
        "source": source,
        "destination": destination,
        "tag": tag,
        "incident_type": incident_type
    })

    raw_results = result.get("objects")

    results: List[dict[str, Any]] = []
    for res in raw_results:
        row = filter_human_readable(res, human_columns=INCIDENT_COLUMNS)

        # Make the values more readable
        row['start_time'] = timestamp_to_datestring(row['start_time'])
        row['end_time'] = timestamp_to_datestring(row['end_time'])

        results.append(row)

    md = tableToMarkdown(f'{INTEGRATION_NAME} - Incidents: {len(results)}',
                         results, headers=INCIDENT_COLUMNS)

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Incident',
        outputs_key_field="_id",
        readable_output=md,
        outputs=results,
        raw_response=raw_results
    )


def fetch_incidents(client: Client, args: dict[str, Any]) -> \
        tuple[List[dict], int, List[str]]:
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("last_fetch")
    last_ids = last_run.get("last_ids", [])
    first_fetch = args.get('first_fetch', None)
    demisto.debug(
        f'{INTEGRATION_NAME} - Fetch incidents last fetch: {last_fetch}, first fetch: {first_fetch}')

    fetch_start_time = calculate_fetch_start_time(last_fetch, first_fetch)

    now_time = int(datetime.now().timestamp()) * 1000
    fetch_params = {
        "from_time": fetch_start_time,
        "to_time": now_time,
        "severity": args.get('severity'),
        "source": args.get('source'),
        "destination": args.get('destination'),
        "tag": args.get('tag'),
        "limit": args.get('limit'),
        "incident_type": args.get('incident_type'),
        "sort": "start_time",
    }
    remove_nulls_from_dictionary(fetch_params)
    demisto.debug(f"{fetch_params=}")

    results = client.get_incidents(fetch_params)
    raw_incidents = sorted(  # the API's built-in sort isn't perfect
        results.get("objects") or [],
        key=lambda x: x.get("start_time") or 0,
    )
    demisto.debug(f'Returned {len(raw_incidents)} incidents from API')

    incidents = []
    next_fetch_start_time = fetch_start_time
    for inc in raw_incidents:
        id = inc.get('_id')
        start_time = inc.get('start_time')
        severity = inc.get('severity')
        if not id or "-" not in id or not start_time:
            demisto.debug(f"Skipped fetching incident because no start_time or id. {inc=}")
            continue
        demisto.debug(f"Current incident: {id=}, {start_time=}")
        if id in last_ids:
            demisto.debug(f"Skipping incident with {id=} as it was already fetched.")
            continue
        demisto.debug(f"Fetching incident with {id=}")
        incident = {
            'name': f"{INTEGRATION_CONTEXT_NAME} Incident (INC-{id.split('-')[0].upper()})",
            'occurred': timestamp_to_datestring(start_time, DATE_FORMAT),
            'severity': incident_severity_to_dbot_score(severity),
            'rawJSON': json.dumps(inc)
        }
        incidents.append(incident)

        if next_fetch_start_time == start_time:
            last_ids.append(id)
        elif next_fetch_start_time < start_time:
            next_fetch_start_time = start_time
            last_ids = [id]

    demisto.debug(f"{next_fetch_start_time=}, {last_ids=}")
    return incidents, next_fetch_start_time, last_ids


def get_indicent(client: Client, args: dict[str, Any]) -> CommandResults:
    incident_id = args.get('id', None)
    if not incident_id:
        raise DemistoException(
            f"{INTEGRATION_NAME} - get incident needs an id parameter.")

    # Call the Client function and get the raw response
    result = client.get_incident(incident_id)

    hr = filter_human_readable(result, human_columns=INCIDENT_COLUMNS)

    # Make the values more readable
    hr['start_time'] = timestamp_to_datestring(hr['start_time'])
    hr['end_time'] = timestamp_to_datestring(hr['end_time'])

    md = tableToMarkdown(f'{INTEGRATION_NAME} - Incident: {incident_id}', hr,
                         headers=INCIDENT_COLUMNS)

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Incident',
        outputs_key_field=incident_id,
        readable_output=md,
        raw_response=result,
        outputs=result,
    )


def get_assets(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    ip_address = args.get('ip_address', None)
    name = args.get('name', None)
    asset_id = args.get('asset_id', None)
    limit = int(args.get('limit', 50))
    offset = int(args.get('offset', 0))

    if not ip_address and not name and not asset_id:
        raise DemistoException(
            f"{INTEGRATION_NAME} - Endpoint search must have ip, name or asset_id defined.")

    params = {
        "asset_id": asset_id,
        "limit": limit,
        "offset": offset
    }

    if ip_address:
        params['search'] = ip_address
    elif name:
        params['search'] = name

    results = client.get_assets(params)

    endpoints = []
    for res in results.get("objects"):
        hostname = res.get("guest_agent_details", {}).get("hostname", "")

        res = filter_human_readable(res, human_columns=ASSET_COLUMNS)
        md = tableToMarkdown(f'{INTEGRATION_NAME} - Asset: {hostname}',
                             res, headers=ASSET_COLUMNS)

        endpoints.append(CommandResults(
            readable_output=md,
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Endpoint',
            outputs_key_field="_id",
            raw_response=res,
            outputs=res,
        ))

    return endpoints


def endpoint_command(client: Client, args: dict[str, Any]) -> \
        List[CommandResults]:
    id = args.get("id", None)
    ip_address = args.get("ip", None)
    hostname = args.get("hostname", None)
    if not id and not ip_address and not hostname:
        raise DemistoException(
            f'{INTEGRATION_NAME} - In order to run this command, please provide valid id, ip or hostname')

    params = {}
    if id:
        params['search'] = id
    elif ip_address:
        params['search'] = ip_address
    elif hostname:
        params['search'] = hostname

    results = client.get_assets(params)

    endpoints = []
    for res in results.get("objects"):
        hostname = res.get("guest_agent_details", {}).get("hostname", "")
        endpoint = Common.Endpoint(
            hostname=hostname,
            id=res.get("_id"),
            os_version=res.get("guest_agent_details", {}).get(
                "os_details", {}).get("os_display_name"),
            ip_address=res.get("ip_addresses", [])[0],  # Get only the ipv4
            mac_address=", ".join(res.get("mac_addresses", [])),
            os=map_guardicore_os(res.get("guest_agent_details", {}).get("os")),
            status='Online' if res.get('status') == "on" else 'Offline',
            vendor=f'{INTEGRATION_NAME} Response')

        endpoint_context = endpoint.to_context().get(
            Common.Endpoint.CONTEXT_PATH)
        md = tableToMarkdown(f'{INTEGRATION_NAME} - Endpoint: {hostname}',
                             endpoint_context)

        endpoints.append(CommandResults(
            readable_output=md,
            outputs_prefix='',
            raw_response=res,
            outputs_key_field="_id",
            indicator=endpoint
        ))

    return endpoints


def main() -> None:
    global GLOBAL_TIMEOUT
    params = demisto.params()
    base_url = params.get('base_url')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    proxy = params.get('proxy', False)
    insecure = params.get('insecure', False)
    client = Client(username=username, password=password,
                    base_url=base_url, proxy=proxy, verify=(not insecure))
    demisto.debug(f'Command being called is {demisto.command()}')

    # fetch incidents params
    severity = params.get('severity', None)
    if "All" in severity:
        severity = None
    elif severity:
        severity = ",".join(severity)
    source = params.get('source', None)
    destination = params.get('destination', None)
    incident_type = params.get('incident_type', None)
    if "All" in incident_type:
        incident_type = None
    elif incident_type:
        incident_type = ",".join(incident_type).lower()
    tag = params.get('tag', None)
    first_fetch = params.get('first_fetch', '7 days')
    limit = int(params.get("max_fetch", 50))
    GLOBAL_TIMEOUT = int(params.get("timeout", 10))

    try:
        args = demisto.args()
        command = demisto.command()
        if command == 'test-module':
            return_results(test_module(client, demisto.params().get('isFetch')))
        elif command == 'fetch-incidents':
            incidents, last_fetch, last_ids = fetch_incidents(client, {
                'severity': severity,
                'incident_type': incident_type,
                'first_fetch': first_fetch,
                'limit': limit,
                'source': source,
                'destination': destination,
                'tag': tag
            })
            demisto.setLastRun({"last_fetch": last_fetch, "last_ids": last_ids})
            demisto.incidents(incidents)
        elif command == 'guardicore-get-incident':
            return_results(get_indicent(client, args))
        elif command == 'guardicore-get-incidents':
            return_results(get_incidents(client, args))
        elif command == 'guardicore-search-asset':
            return_results(get_assets(client, args))
        elif command == 'endpoint':
            return_results(endpoint_command(client, args))
        else:
            raise NotImplementedError(
                f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
