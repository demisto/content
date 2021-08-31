import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


'''IMPORTS'''
import json
import urllib3
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

# Validators
MAX_INCIDENTS_TO_FETCH = 1000
SUPPORTED_SUB_TYPES = [2, 3, 12, 16, 17, 18, 19, 23]
SUPPORTED_SUB_TYPES_FOR_PURCHASE = [16, 18]
# Mappers
TYPE_MAPPER = {
    'leaked_credentials': 'Leaked Credentials',
    'reports': 'Intelligence Reports',
    'botnets': 'Compromised Accounts'
}
# URLs
RADARK_URL = 'https://radark2.ke-la.com'
BASE_URL = RADARK_URL + '/api'
INCIDENT_URL = RADARK_URL + '/#/incident?monitorId={MONITOR_ID}&feedPropertyId={item_id}'
FETCH_ITEMS_API = 'incidents/feedProperty/{incident_id}?apiToken={API_KEY}&monitor_id={MONITOR_ID}'
FETCH_INCIDENTS_API = 'aggregations?monitor_id={MONITOR_ID}&apiToken={API_KEY}&limit={max_results}'
EMAIL_ENRICHMENT_API = 'incidents/all?monitor_id={MONITOR_ID}&apiToken={API_KEY}'
INCIDENT_ACTION_API = 'incidents/{item_id}/{action}?apiToken={API_KEY}'
FETCH_AN_ITEM_API = 'monitor_id/{MONITOR_ID}/incidents/{item_id}?apiToken={API_KEY}'
MESSAGE_API = 'messages/message?apiToken={API_KEY}'
MENTIONS_LIST_API = 'messages/mentionsList?monitorId={MONITOR_ID}&apiToken={API_KEY}'
# Default values
DEFAULT_MAX_FETCH = 10
DEFAULT_INCIDENT_TYPES = ['Leaked Credentials', 'Intelligence Reports', 'Compromised Accounts']  # All types allowed
DEFAULT_FIRST_TIME_TO_FETCH = '45 days'
# Get from instance
API_KEY = demisto.params().get('api_key')
MONITOR_ID = demisto.params().get('monitor_id')

''' CLIENT CLASS '''


class Client(BaseClient):
    def search_alerts(self, start_time: Optional[int], max_results: int, incident_types: List[str]):  # \
        # -> List[Dict[str, Any]]:
        # Base filter
        params: Dict[str, Dict] = {
            "filters": {
                "and": {
                    "start_date": start_time
                }
            },
            "sort": {
                "by": "incident_date",
                "order": "asc"
            }
        }

        # Add indices to fetch to the filter
        if len(incident_types) > 0:
            indices = []
            for incident_type in incident_types:
                identifier = get_type(incident_type)
                if identifier != "":
                    indices.append({"identifier": identifier})
            params["filters"]["and"]["indices"] = indices

        headers = {'Content-Type': 'application/json'}
        max_results = str(max_results)
        try:
            return self._http_request(
                method='POST',
                url_suffix=FETCH_INCIDENTS_API.format(MONITOR_ID=MONITOR_ID, API_KEY=API_KEY, max_results=max_results),
                json_data=params,
                headers=headers)
        except Exception as e:
            return_error(str(e))

    def incident_get_items(self, incident_id: str) -> Union[Dict[str, Any], None]:
        try:
            return self._http_request(
                method='GET',
                url_suffix=FETCH_ITEMS_API.format(incident_id=incident_id, API_KEY=API_KEY, MONITOR_ID=MONITOR_ID)
            )
        except Exception as e:
            return_error(str(e))
            return None

    def email_enrich_data(self, email: str) -> Union[Dict[str, Any], None]:
        # filter
        params = {
            "index": "leaked_credentials",
            "getAll": False,
            "filters": {
                "and": {
                    "emails": [email],
                    "indices": [{"identifier": "leaked_credentials"}]
                }
            }
        }
        headers = {'Content-Type': 'application/json'}
        try:
            return self._http_request(
                method='POST',
                url_suffix=EMAIL_ENRICHMENT_API.format(MONITOR_ID=MONITOR_ID, API_KEY=API_KEY),
                json_data=params,
                headers=headers
            )
        except Exception as e:
            return_error(str(e))
            return None

    def action_on_item(self, item_id: str, action: str) -> Union[Dict[str, Any], None]:
        params = {'monitor_id': MONITOR_ID, 'value': True, 'force': False}
        headers = {'Content-Type': 'application/json'}
        try:
            return self._http_request(
                method='POST',
                url_suffix=INCIDENT_ACTION_API.format(item_id=item_id, action=action, API_KEY=API_KEY),
                json_data=params,
                headers=headers
            )
        except Exception as e:
            return_error(str(e))
            return None

    def get_item(self, item_id: str) -> Union[Dict[str, Any], None]:
        try:
            return self._http_request(
                method='GET',
                url_suffix=FETCH_AN_ITEM_API.format(item_id=item_id, API_KEY=API_KEY, MONITOR_ID=MONITOR_ID)
            )
        except Exception as e:
            return_error(str(e))
            return None

    def message_on_incident(self, message: Dict[str, Any], room: Dict[str, str]) -> Union[Dict[str, Any], None]:
        params = {'monitorId': MONITOR_ID, 'message': message, 'room': room}
        headers = {'Content-Type': 'application/json'}
        try:
            return self._http_request(
                method='POST',
                url_suffix=MESSAGE_API.format(API_KEY=API_KEY),
                json_data=params,
                headers=headers
            )
        except Exception as e:
            return_error(str(e))
            return None

    def get_mention_list(self) -> Union[Dict[str, Any], None]:
        try:
            return self._http_request(
                method='GET',
                url_suffix=MENTIONS_LIST_API.format(API_KEY=API_KEY, MONITOR_ID=MONITOR_ID)
            )
        except Exception as e:
            return_error(str(e))
            return None


''' HELPER FUNCTIONS '''


def parse_email_enrichment_markdown_table(data: dict):
    items = data['incidents']
    table = []
    # Set headers. Important for order.
    headers = ['Email', 'Domain', 'Password Type', 'Password', 'Service', 'Source', 'Date']
    # Parse each item.
    for item in items:
        email = item.get('email', '')
        domain = item.get('domain', '')
        password_type = item.get('password_type', '')
        password = item.get('password', '')
        service = item.get('service', '')
        source = item.get('source', '')
        date = item.get('posted_date', '')
        row = {
            'Email': email if email else '-',
            'Domain': domain if domain else '-',
            'Password Type': password_type if password_type else '-',
            'Password': password if password else '-',
            'Service': service if service else '-',
            'Source': source if source else '-',
            'Date': formatEpochDate(date) if date else '-'
        }
        table.append(row)
    # Return the items as Markdown
    return table, tableToMarkdown(name="", t=table, headers=headers)


def parse_incident_markdown_table(data: dict, item_id: str):
    items = data['incidents']
    aggr_type = data['aggregation']['type']
    sub_type = data['aggregation']['sub_type']
    if aggr_type == 'reports':
        url = INCIDENT_URL.format(MONITOR_ID=MONITOR_ID, item_id=item_id)
        return [{'URL': url, 'Item ID': item_id}], '#### Report available here: <' + url + '>'
    elif aggr_type == 'botnets':
        headers, table = parse_botnets_markdown_table(items, sub_type)
    elif aggr_type == 'leaked_credentials':
        headers, table = parse_leaked_credentials_markdown_table(items, sub_type)
    else:
        return None, f'No data found for item ID: {item_id}'
    # Return the items as Markdown
    return table, tableToMarkdown(name="", t=table, headers=headers)


def parse_leaked_credentials_markdown_table(items: List[Dict[str, Any]], sub_type: int):
    table = []
    # Set headers. Important for order.
    headers = ['Item ID', 'Email', 'Domain', 'Password', 'Password Type']
    if sub_type == 2 or sub_type == 23:
        headers.append('Source')
        headers.append('Date')
    elif sub_type == 3:
        headers.append('Service')
    elif sub_type == 19:
        headers.append('Dump Post Date')
        headers.append('Compromised Website')
    # Parse each item base on subtype
    for item in items:
        item_id = item.get('id', '')
        email = item.get('email', '')
        domain = item.get('domain', '')
        password = item.get('password', '')
        password_type = item.get('password_type', '')
        row = {
            'Item ID': item_id if item_id else '-',
            'Email': email if email else '-',
            'Domain': domain if domain else '-',
            'Password': password if password else '-',
            'Password Type': password_type if password_type else '-'
        }
        if sub_type == 2 or sub_type == 23:
            source = item.get('source', '')
            row['Source'] = source if source else '-'
            date = item.get('posted_date', '')
            row['Date'] = formatEpochDate(date) if date else '-'
        elif sub_type == 3:
            service = item.get('service', '')
            row['Service'] = service if service else '-'
        elif sub_type == 19:
            date = item.get('dump_post_date', '')
            row['Dump Post Date'] = formatEpochDate(date) if date else '-'
            compromised_website = item.get('compromised_website', '')
            row['Compromised Website'] = compromised_website if compromised_website else '-'
        table.append(row)
    return headers, table


def parse_botnets_markdown_table(items: List[Dict[str, Any]], sub_type: int):
    table = []
    # Set headers. Important for order.
    headers = ['Item ID', 'Bot ID', 'Updated Date', 'Resource', 'Country', 'Source IP', 'Infection Type']
    if sub_type == 17:
        headers.insert(3, 'Username')
        headers.insert(4, 'Password')
    elif sub_type == 16 or sub_type == 18:
        headers.insert(3, 'Username')
        headers.insert(4, 'Password')
        headers.insert(5, 'Available Data')
        headers.append('Price')
    # Parse each item base on subtype
    for item in items:
        item_id = item.get('id', '')
        bot_id = item.get('bot_id', '')
        resource = item.get('resource', '')
        country = item.get('country', '')
        isp = item.get('isp', '')
        infection_type = item.get('infection_type', '')
        updated_date = item.get('updated_date', '')
        row = {
            'Item ID': item_id if item_id else '-',
            'Bot ID': bot_id if bot_id else '-',
            'Resource': resource if resource else '-',
            'Country': country if country else '-',
            'Source IP': isp if isp else '-',
            'Infection Type': infection_type if infection_type else '-',
            'Updated Date': formatEpochDate(updated_date) if updated_date else '-'
        }
        if sub_type == 17:
            username = item.get('username', '')
            password = item.get('password', '')
            row['Username'] = username if username else '-'
            row['Password'] = password if password else '-'
        elif sub_type == 16 or sub_type == 18:
            available_data_res = ''
            available_data = item.get('available_data', {'-': ''})
            for key in available_data:
                available_data_res += key + '(' + available_data[key] + '),' if available_data[key] else key + ','
            if available_data_res[-1] == ',':
                available_data_res = available_data_res[0:-1]
            username = available_data.get('username', '')
            if not username:
                username = available_data.get('login', '')
                if not username:
                    username = available_data.get('email', '')
            password = available_data.get('password', '')
            row['Username'] = username if username else '-'
            row['Password'] = password if password else '-'
            row['Available Data'] = available_data_res
            price = item.get('price', '')
            row['Price'] = str(price) + '$' if price else price
        table.append(row)
    return headers, table


def get_first_time_fetch(first_fetch: str) -> Union[int, None]:
    first_fetch_time = arg_to_datetime(
        arg=first_fetch if first_fetch else DEFAULT_FIRST_TIME_TO_FETCH,
        arg_name='First fetch time',
        required=True)
    return int(first_fetch_time.timestamp()) if first_fetch_time else None


def get_max_fetch(max_results: str) -> int:
    if max_results.isnumeric():
        max_fetch = int(max_results)
        if max_fetch < 0:
            max_fetch = DEFAULT_MAX_FETCH
    else:  # Default value
        max_fetch = DEFAULT_MAX_FETCH
    if not max_fetch or max_fetch > MAX_INCIDENTS_TO_FETCH:
        max_fetch = MAX_INCIDENTS_TO_FETCH
    return max_fetch


def get_type(incident_type: str) -> str:
    for key in TYPE_MAPPER:
        if TYPE_MAPPER[key] == incident_type:
            return key
    return ""


def get_name(incident_type: str) -> str:
    return TYPE_MAPPER.get(incident_type, "Unknown Incident Type")


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: Optional[int]) -> str:
    try:
        client.search_alerts(start_time=first_fetch_time, max_results=1, incident_types=DEFAULT_INCIDENT_TYPES)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def fetch_incidents(
        client: Client,
        max_results: int,
        last_run: Dict[str, int],
        first_fetch_time: Optional[int],
        incident_types: List[str]) -> Tuple[Dict[str, int], List[dict]]:
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:  # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:  # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    # Fetch alerts from RaDark.
    alerts = client.search_alerts(
        start_time=last_fetch,
        max_results=max_results,
        incident_types=incident_types)['data']['aggregations']

    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the HelloWorld API response
        incident_created_time = int(alert.get('incident_date', '0'))

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch and incident_created_time <= last_fetch:
            continue

        # Prevent unsupported sub type to fetch incidents
        sub_type = alert['sub_type']
        if sub_type in SUPPORTED_SUB_TYPES:
            alert['type_description'] = get_name(alert['type'])
            alert['incident_url'] = INCIDENT_URL.format(MONITOR_ID=MONITOR_ID, item_id=alert['feed_property_id'])
            alert.pop('title', None)

            # Add monitor ID to the incident.
            alert['monitor_id'] = MONITOR_ID

            # Parse incident
            incident = {
                'name': get_name(alert['type']),
                'occurred': timestamp_to_datestring(incident_created_time * 1000),  # timestamp in ms
                'rawJSON': json.dumps(alert)
            }
            incidents.append(incident)

        # Update last run if needed
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def incident_get_items_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, None]:
    try:
        incident_id = str(args.get('incident_id'))
        incident_data = client.incident_get_items(incident_id=incident_id)
        if isinstance(incident_data, dict) and isinstance(incident_data.get('data'), dict) and \
                isinstance(incident_data['data'].get('incidents'), list) and len(incident_data['data']['incidents']) > 0:
            parsed_data, readable_output = parse_incident_markdown_table(incident_data['data'], incident_id)
        else:
            readable_output = f'No data found for item ID: {incident_id}'
            parsed_data = None
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Radark.itemDetails',
            outputs_key_field='items',
            outputs={'items': parsed_data, "items_markdown": readable_output})
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute command.\nError:\n {str(e)} {incident_data}')
        return None


def email_enrich_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, None]:
    try:
        email = str(args.get('email'))
        email_data = client.email_enrich_data(email=email)
        if isinstance(email_data, dict) and isinstance(email_data.get('data'), dict) and \
                isinstance(email_data['data'].get('incidents'), list) and len(email_data['data']['incidents']) > 0:
            parsed_data, readable_output = parse_email_enrichment_markdown_table(email_data['data'])
        else:
            readable_output = f'No data found for email: {email}'
            parsed_data = None
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Radark.emailDetails',
            outputs_key_field='emails',
            outputs={'items': parsed_data, "items_markdown": readable_output})
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute command.\nError:\n {str(e)} {email}')
        return None


def item_handle_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, None]:
    try:
        item_id = str(args.get('item_id'))
        action_res = client.action_on_item(item_id=item_id, action="handled")
        if isinstance(action_res, dict) and isinstance(action_res.get('data'), dict) \
                and action_res['data'].get('value'):
            readable_output = 'Item marked as handled'
            return CommandResults(readable_output=readable_output)
        else:
            raise Exception("Action failed!")
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute command on {item_id}.\nError:\n {str(e)}')
        return None


def item_purchase_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, None]:
    try:
        item_id = str(args.get('item_id'))
        bot_id = ''
        room_id = ''

        # Get mentions list:
        mentions_list_res = client.get_mention_list()
        if isinstance(mentions_list_res, dict) and isinstance(mentions_list_res.get('data', ''), list) \
                and len(mentions_list_res['data']) > 0 and isinstance(mentions_list_res['data'][0], dict) \
                and 'id' in mentions_list_res['data'][0] and 'alias' in mentions_list_res['data'][0]:

            mentions_list = mentions_list_res['data']

            # Fetch some important item data.
            item_res = client.get_item(item_id=item_id)
            if isinstance(item_res, dict) and isinstance(item_res.get('data', ''), dict):
                # Prevent execution on unsupported sub types.
                if item_res['data'].get('sub_type', -1) not in SUPPORTED_SUB_TYPES_FOR_PURCHASE:
                    raise Exception("Sub type not supported for purchasing!")

                # Extract bot ID and incident ID.
                incident_id = item_res['data'].get('feed_property_id', '')
                if not incident_id:
                    raise Exception("Item ID doesn't found!")
                bot_id = item_res['data'].get('bot_id', '')
                if not bot_id:
                    raise Exception("Bot ID doesn't found!")

                # Check if chat room already exists.
                incident_res = client.incident_get_items(incident_id=incident_id)
                if isinstance(incident_res, dict) and isinstance(incident_res.get('data', ''), dict) and \
                        isinstance(incident_res['data'].get('chat', ''), dict) and \
                        isinstance(incident_res['data']['chat'].get('room', ''), dict):
                    room_id = incident_res['data']['chat']['room'].get('id', '')

                # Send the action status.
                action_res = client.action_on_item(item_id=item_id, action="request")
                if isinstance(action_res, dict) and isinstance(action_res.get('data', ''), dict) \
                        and action_res['data'].get('value', ''):

                    # Send the chat request.
                    message = {
                        "text": "Hi <b>@KELA</b> , I would like to acquire further details about bot: " + bot_id,
                        "mentionsList": mentions_list
                    }
                    room = {"itemId": incident_id, "itemType": "FEED_PROPERTY"}
                    if room_id:
                        room['id'] = room_id

                    # Send message.
                    message_res = client.message_on_incident(message=message, room=room)
                    if isinstance(message_res, dict) and isinstance(message_res.get('data', ''), dict) \
                            and message_res['data'].get('roomId', ''):
                        # readable_output = 'Item marked for purchasing'
                        readable_output = 'Bot ID (' + bot_id + ') marked for purchasing'
                    else:
                        raise Exception("Action failed!")
                else:
                    raise Exception("Action failed!")
            else:
                readable_output = f'No data found for item ID: {incident_id}'
        else:
            raise Exception("Mentions list doesn't found!")
        return CommandResults(readable_output=readable_output)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute command on {item_id}.\nError:\n {str(e)}')
        return None


''' MAIN FUNCTION '''


def main() -> None:
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_timestamp = get_first_time_fetch(demisto.params().get('first_fetch'))

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # Initialize Client
        client = Client(base_url=BASE_URL, verify=verify_certificate, headers={}, proxy=proxy)

        # Run the requested command
        if demisto.command() == 'test-module':
            return_results(test_module(client, first_fetch_timestamp))
        elif demisto.command() == 'fetch-incidents':
            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = get_max_fetch(demisto.params().get('max_fetch'))
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_timestamp,
                incident_types=demisto.params().get('incident_types', DEFAULT_INCIDENT_TYPES)
            )
            # Set last run and create incidents in XSOAR
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif demisto.command() == 'radark-incident-get-items':
            return_results(incident_get_items_command(client, demisto.args()))
        elif demisto.command() == 'radark-email-enrich':
            return_results(email_enrich_command(client, demisto.args()))
        elif demisto.command() == 'radark-item-handle':
            return_results(item_handle_command(client, demisto.args()))
        elif demisto.command() == 'radark-item-purchase':
            return_results(item_purchase_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
