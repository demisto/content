import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


'''IMPORTS'''
import json
import urllib3
import traceback
from typing import Any, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

# Validators
MAX_INCIDENTS_TO_FETCH = 1000
SUPPORTED_SUB_TYPES = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 23, 24, 26]
SUPPORTED_SUB_TYPES_FOR_PURCHASE = [16, 18, 26]
# Mappers And Formatters
TYPE_MAPPER = {
    'leaked_credentials': 'Leaked Credentials',
    'reports': 'Intelligence Reports',
    'botnets': 'Compromised Accounts',
    'network_vulnerabilities': 'Network Vulnerabilities',
    'credit_cards': 'Credit Cards',
    'hacking_discussions': 'Hacking Discussions'
}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
HACKING_DISCUSSIONS_LINES_SNIPPET = 5
# URLs
RADARK_URL = 'https://radark2.ke-la.com'
BASE_URL = RADARK_URL + '/api'
INCIDENT_URL = RADARK_URL + '/#/incident?monitorId={MONITOR_ID}&feedPropertyId={incident_id}'
FETCH_ITEMS_API = 'incidents/feedProperty/{incident_id}?apiToken={API_KEY}&monitor_id={MONITOR_ID}&include_original_text=true'
FETCH_INCIDENTS_API = 'aggregations?monitor_id={MONITOR_ID}&apiToken={API_KEY}&limit={max_results}'
EMAIL_ENRICHMENT_API = 'incidents/all?monitor_id={MONITOR_ID}&apiToken={API_KEY}'
INCIDENT_ACTION_API = 'incidents/{item_id}/{action}?apiToken={API_KEY}'
FETCH_AN_ITEM_API = 'monitor_id/{MONITOR_ID}/incidents/{item_id}?apiToken={API_KEY}'
MESSAGE_API = 'messages/message?apiToken={API_KEY}'
MENTIONS_LIST_API = 'messages/mentionsList?monitorId={MONITOR_ID}&apiToken={API_KEY}'
# Default values
DEFAULT_MAX_FETCH = 10
DEFAULT_INCIDENT_TYPES = [
    'Leaked Credentials',
    'Intelligence Reports',
    'Compromised Accounts',
    'Network Vulnerabilities',
    'Credit Cards',
    'Hacking Discussions'
]  # All types allowed
DEFAULT_FIRST_TIME_TO_FETCH = '45 days'
# Get from instance
API_KEY = demisto.params().get('api_key')
MONITOR_ID = demisto.params().get('monitor_id')

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self,
                 base_url: str,
                 verify: bool,
                 headers: dict[str, str],
                 proxy: bool,
                 api_key: str,
                 monitor_id: str):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)
        self.api_key = api_key
        self.monitor_id = monitor_id

    def search_alerts(self, start_time: int | None, max_results: int, incident_types: list[str]):
        # Base filter
        params: dict[str, dict] = {
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
                url_suffix=FETCH_INCIDENTS_API.format(
                    MONITOR_ID=self.monitor_id,
                    API_KEY=self.api_key,
                    max_results=max_results),
                json_data=params,
                headers=headers)
        except Exception as e:
            return_error(str(e))

    def incident_get_items(self, incident_id: str) -> dict[str, Any] | None:
        try:
            return self._http_request(
                method='GET',
                url_suffix=FETCH_ITEMS_API.format(
                    incident_id=incident_id,
                    API_KEY=self.api_key,
                    MONITOR_ID=self.monitor_id)
            )
        except Exception as e:
            return_error(str(e))
            return None

    def email_enrich_data(self, email: str) -> dict[str, Any] | None:
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
                url_suffix=EMAIL_ENRICHMENT_API.format(MONITOR_ID=self.monitor_id, API_KEY=self.api_key),
                json_data=params,
                headers=headers
            )
        except Exception as e:
            return_error(str(e))
            return None

    def action_on_item(self, item_id: str, action: str) -> dict[str, Any] | None:
        params = {'monitor_id': self.monitor_id, 'value': True, 'force': False}
        headers = {'Content-Type': 'application/json'}
        try:
            return self._http_request(
                method='POST',
                url_suffix=INCIDENT_ACTION_API.format(item_id=item_id, action=action, API_KEY=self.api_key),
                json_data=params,
                headers=headers
            )
        except Exception as e:
            return_error(str(e))
            return None

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        try:
            return self._http_request(
                method='GET',
                url_suffix=FETCH_AN_ITEM_API.format(item_id=item_id, API_KEY=self.api_key, MONITOR_ID=self.monitor_id)
            )
        except Exception as e:
            return_error(str(e))
            return None

    def message_on_incident(self, message: dict[str, Any], room: dict[str, str]) -> dict[str, Any] | None:
        params = {'monitorId': self.monitor_id, 'message': message, 'room': room}
        headers = {'Content-Type': 'application/json'}
        try:
            return self._http_request(
                method='POST',
                url_suffix=MESSAGE_API.format(API_KEY=self.api_key),
                json_data=params,
                headers=headers
            )
        except Exception as e:
            return_error(str(e))
            return None

    def get_mention_list(self) -> dict[str, Any] | None:
        try:
            return self._http_request(
                method='GET',
                url_suffix=MENTIONS_LIST_API.format(API_KEY=self.api_key, MONITOR_ID=self.monitor_id)
            )
        except Exception as e:
            return_error(str(e))
            return None


''' HELPER FUNCTIONS '''


def parse_email_enrichment_markdown_table(data: dict):
    items = data['incidents']
    table = []
    # Set headers. Important for order.
    headers = ['email', 'domain', 'password_type', 'password', 'service', 'source', 'date']
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
            'email': email if email else '-',
            'domain': domain if domain else '-',
            'password_type': password_type if password_type else '-',
            'password': password if password else '-',
            'service': service if service else '-',
            'source': source if source else '-',
            'date': timestamp_to_datestring(date * 1000, DATE_FORMAT) if date else '-'
        }
        table.append(row)
    # Return the items as Markdown
    return table, tableToMarkdown(name='', t=table, headers=headers, headerTransform=lambda s: s.replace('_', ' ').title())


def parse_incident_markdown_table(data: dict, incident_id: str):
    items = data.get('incidents', '')
    aggr = data.get('aggregation', '')
    if not aggr or not items or not isinstance(items, list) or len(items) < 1:
        raise Exception('RaDark Error: Response is missing!')
    aggr_type = aggr.get('type', '')
    sub_type = aggr.get('sub_type', '')
    if not aggr_type or not sub_type:
        raise Exception('RaDark Error: Response is missing!')
    if aggr_type == 'reports':
        details = 'The Intelligence report is available on your RaDark monitor.'
        table = []
    elif aggr_type == 'botnets':
        count = len(items)
        many_suffix = "s" if count > 1 else ""
        details = f'Incident contains {count} item{many_suffix}. Full details can be found on "items" tab.'
        table = parse_botnets_markdown_table(items, sub_type)
    elif aggr_type == 'leaked_credentials':
        count = len(items)
        many_suffix = "s" if count > 1 else ""
        details = f'Incident contains {count} item{many_suffix}. Full details can be found on "items" tab.'
        table = parse_leaked_credentials_markdown_table(items, sub_type)
    elif aggr_type == 'network_vulnerabilities':
        count = len(items)
        many_suffix = "s" if count > 1 else ""
        details = f'Incident contains {count} item{many_suffix}. Full details can be found on "items" tab.'
        table = parse_network_vulnerabilities_markdown_table(items, sub_type)
    elif aggr_type == 'credit_cards':
        count = len(items)
        many_suffix = "s" if count > 1 else ""
        details = f'Incident contains {count} item{many_suffix}. Full details can be found on "items" tab.'
        table = parse_credit_cards_markdown_table(items, sub_type)
    elif aggr_type == 'hacking_discussions':
        details = ('incident may contain textual context or screenshots that include the company\'s assets. '
                   'More details can be found on "items" tab.')
        table = parse_hacking_discussions_markdown_table(items, aggr)
    else:
        details = f'No data found for item ID: {incident_id}'
        table = []
    return table, details


def parse_leaked_credentials_markdown_table(items: list[dict[str, Any]], sub_type: int):
    table = []
    # Parse each item base on subtype
    for item in items:
        item_id = item.get('id', '')
        email = item.get('email', '')
        domain = item.get('domain', '')
        password = item.get('password', '')
        password_type = item.get('password_type', '')
        row = {
            'item_id': item_id if item_id else '-',
            'email': email if email else '-',
            'domain': domain if domain else '-',
            'password': password if password else '-',
            'password_type': password_type if password_type else '-'
        }
        if sub_type in [2, 23]:
            source = item.get('source', '')
            date = item.get('posted_date', '')
            row['source'] = source if source else '-'
            row['date'] = timestamp_to_datestring(date * 1000, DATE_FORMAT) if date else '-'
        elif sub_type in [3]:
            pass
        elif sub_type in [19]:
            date = item.get('dump_post_date', '')
            compromised_website = item.get('compromised_website', '')
            row['dump_post_date'] = timestamp_to_datestring(date * 1000, DATE_FORMAT) if date else '-'
            row['compromised_website'] = compromised_website if compromised_website else '-'
        table.append(row)
    return table


def parse_botnets_markdown_table(items: list[dict[str, Any]], sub_type: int):
    table = []
    # Parse each item base on subtype
    for item in items:
        item_id = item.get('id', '')
        bot_id = item.get('bot_id', '')
        resource = item.get('resource', '')
        country = item.get('country', '')
        updated_date = item.get('updated_date', '')
        row = {
            'item_id': item_id if item_id else '-',
            'bot_id': bot_id if bot_id else '-',
            'resource': resource if resource else '-',
            'country': country if country else '-',
            'updated_date': timestamp_to_datestring(updated_date * 1000, DATE_FORMAT) if updated_date else '-'
        }
        if sub_type in [16]:
            additional_data, username, password = extract_available_data_from_item(item)
            source_ip = item.get('source_ip', '')
            price = item.get('price', '')
            row['username'] = username if username else '-'
            row['password'] = password if password else '-'
            row['additional_data'] = additional_data
            row['source_ip'] = source_ip if source_ip else '-'
            row['price'] = str(price) + '$' if price else price
        elif sub_type in [17]:
            username = item.get('username', '')
            password = item.get('password', '')
            source_ip = item.get('source_ip', '')
            infection_type = item.get('infection_type', '')
            row['username'] = username if username else '-'
            row['password'] = password if password else '-'
            row['source_ip'] = source_ip if source_ip else '-'
            row['infection_type'] = infection_type if infection_type else '-'
        elif sub_type in [18]:
            additional_data, username, password = extract_available_data_from_item(item)
            isp = item.get('isp', '')
            infection_type = item.get('infection_type', '')
            price = item.get('price', '')
            row['username'] = username if username else '-'
            row['password'] = password if password else '-'
            row['additional_data'] = additional_data
            row['isp'] = isp if isp else '-'
            row['infection_type'] = infection_type if infection_type else '-'
            row['price'] = str(price) + '$' if price else price
        elif sub_type in [26]:
            additional_data, username, password = extract_available_data_from_item(item)
            tags = item.get('tags', '')
            price = item.get('price', '')
            row['username'] = username if username else '-'
            row['password'] = password if password else '-'
            row['tags'] = tags if tags else '-'
            row['price'] = str(price) + '$' if price else price
        table.append(row)
    return table


def parse_network_vulnerabilities_markdown_table(items: list[dict[str, Any]], sub_type: int):
    table = []
    # Parse each item base on subtype
    for item in items:
        item_id = item.get('id', '')
        hostname = item.get('hostname', '')
        row = {
            'item_id': item_id if item_id else '-',
            'hostname': hostname if hostname else '-',
        }
        if sub_type in [4, 5, 6, 7, 8, 14]:
            ip = item.get('ip', '')
            port = item.get('port', '')
            service = item.get('service', '')
            isp = item.get('isp', '')
            row['ip'] = ip if ip else '-'
            row['port'] = port if port else '-'
            row['service'] = service if service else '-'
            row['isp'] = isp if isp else '-'
        elif sub_type in [9]:
            technology = item.get('technology', '')
            cve_details = item.get('cve_details', '')
            row['technology'] = technology if technology else '-'
            row['cve_details'] = cve_details if cve_details else '-'
        elif sub_type in [10, 11]:
            nv_type = item.get('type', '')
            details = item.get('details', '')
            row['type'] = nv_type if nv_type else '-'
            row['details'] = details if details else '-'
        elif sub_type in [20]:
            ip = item.get('ip', '')
            isp = item.get('isp', '')
            description = item.get('description', '')
            row['ip'] = ip if ip else '-'
            row['isp'] = isp if isp else '-'
            row['description'] = description if description else '-'
        table.append(row)
    return table


def parse_credit_cards_markdown_table(items: list[dict[str, Any]], sub_type: int):
    table = []
    # Parse each item base on subtype
    # Include both 13 and 24
    for item in items:
        item_id = item.get('id', '')
        bin = item.get('bin', '')
        number = item.get('number', '')
        source = item.get('source', '')
        date = item.get('posted_date', '')
        row = {
            'item_id': item_id if item_id else '-',
            'bin': bin if bin else '-',
            'number': number if number else '-',
            'source': source if source else '-',
            'date': timestamp_to_datestring(date * 1000, DATE_FORMAT) if date else '-'
        }
        table.append(row)
    return table


def parse_hacking_discussions_markdown_table(items: list[dict[str, Any]], aggr: dict[str, Any]):
    table = []
    aggr_media = aggr.get('media', [])
    aggr_tags = aggr.get('tags', [])
    if not isinstance(aggr_media, list) or not isinstance(aggr_tags, list):
        raise Exception('RaDark Error: Response is missing!')
    aggr_tags = list(map(lambda t: t.lower(), aggr_tags))
    # Image items handler
    for media_item in aggr_media:
        if not isinstance(media_item, dict):
            raise Exception('RaDark Error: Incorrect media_item type!')
        media_item_tags = media_item.get('tags', [])
        if not isinstance(media_item_tags, list):
            raise Exception('RaDark Error: Incorrect media_item_tags type!')
        for tag in media_item_tags:
            if not isinstance(tag, str):
                raise Exception('RaDark Error: Incorrect tag type!')
        if media_item_tags:
            media_item_url = media_item.get('url', '')
            if not isinstance(media_item_url, str):
                raise Exception('RaDark Error: Incorrect media_item_url type!')
            item_type = 'image'
            tags = ', '.join(media_item_tags)
            link = media_item_url
            row = {
                'type': item_type if item_type else '-',
                'tags': tags if tags else '-',
                'link': link if link else '-',
                'context': '-'
            }
            table.append(row)

    # Snippet items handler
    item = items[0]
    if not isinstance(item, dict):
        raise Exception('RaDark Error: Incorrect item type!')
    text = item.get('text', {})
    if not isinstance(text, str):
        raise Exception('RaDark Error: Incorrect text type!')
    lines = text.splitlines()
    for i in range(len(lines)):
        tag_catched = []
        for tag in aggr_tags:
            if tag in lines[i].lower():
                tag_catched.append(tag)
        if len(tag_catched) > 0:
            snippet_lines = []
            for j in range(
                    max(0, i - HACKING_DISCUSSIONS_LINES_SNIPPET),
                    min(len(lines), i + 1 + HACKING_DISCUSSIONS_LINES_SNIPPET)):
                snippet_lines.append(lines[j])
            item_type = 'text'
            tags = ', '.join(tag_catched)
            context = '\n'.join(snippet_lines)
            row = {
                'type': item_type if item_type else '-',
                'tags': tags if tags else '-',
                'link': '-',
                'context': context if context else '-'
            }
            table.append(row)
    return table


def extract_available_data_from_item(item: dict) -> tuple[str, str, str]:
    additional_data = ''
    available_data = item.get('available_data', '')
    if not available_data:
        available_data = {'-': ''}
    for key in available_data:
        additional_data += key + '(' + available_data[key] + '),' if available_data[key] else key + ','
    if additional_data[-1] == ',':
        additional_data = additional_data[0:-1]
    username = available_data.get('username', '')
    if not username:
        username = available_data.get('login', '')
        if not username:
            username = available_data.get('email', '')
    password = available_data.get('password', '')
    return additional_data, username, password


def get_first_time_fetch(first_fetch: str) -> int | None:
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


def test_module(client: Client, first_fetch_time: int | None) -> str:
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
        last_run: dict[str, int],
        first_fetch_time: int | None,
        incident_types: list[str]) -> tuple[dict[str, int], list[dict]]:
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch', None)
    if not last_fetch:  # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:  # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

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
            alert['incident_url'] = INCIDENT_URL.format(
                MONITOR_ID=client.monitor_id,
                incident_id=alert['feed_property_id'])
            alert.pop('title', None)

            # Add monitor ID to the incident.
            alert['monitor_id'] = client.monitor_id

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


def incident_get_items_command(client: Client, args: dict[str, Any]) -> CommandResults:
    try:
        incident_id = str(args.get('incident_id', ''))
        incident_data = client.incident_get_items(incident_id=incident_id)
        if isinstance(incident_data, dict) and isinstance(incident_data.get('data'), dict) and \
                isinstance(incident_data['data'].get('incidents'), list) and len(incident_data['data']['incidents']) > 0:
            parsed_data, readable_output = parse_incident_markdown_table(incident_data['data'], incident_id)
        else:
            readable_output = f'No data found for item ID: {incident_id}.'
            parsed_data = []
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Radark.itemDetails',
            outputs_key_field='items',
            outputs={'items': parsed_data, "details": readable_output})
    except Exception as e:
        raise Exception(f'RaDark Error: Failed to execute command.\nError:\n {str(e)} {incident_data}')


def email_enrich_command(client: Client, args: dict[str, Any]) -> CommandResults:
    try:
        email = str(args.get('email', ''))
        email_data = client.email_enrich_data(email=email)
        if isinstance(email_data, dict) and isinstance(email_data.get('data'), dict) and \
                isinstance(email_data['data'].get('incidents'), list) and len(email_data['data']['incidents']) > 0:
            parsed_data, readable_output = parse_email_enrichment_markdown_table(email_data['data'])
        else:
            readable_output = f'No data found for email: {email}.'
            parsed_data = None
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='Radark.emailDetails',
            outputs_key_field='emails',
            outputs={'emails': parsed_data})
    except Exception as e:
        raise Exception(f'RaDark Error: Failed to execute command.\nError:\n {str(e)} {email}')


def item_handle_command(client: Client, args: dict[str, Any]) -> CommandResults:
    try:
        item_id = str(args.get('item_id', ''))
        action_res = client.action_on_item(item_id=item_id, action="handled")
        if isinstance(action_res, dict) and isinstance(action_res.get('data'), dict) \
                and action_res['data'].get('value'):
            readable_output = f'Item ID ({item_id}) marked as handled.'
            return CommandResults(readable_output=readable_output)
        else:
            raise Exception("RaDark Error: Mark item action failed!")
    except Exception as e:
        raise Exception(f'RaDark Error: Failed to execute command on {item_id}.\nError:\n {str(e)}')


def item_purchase_command(client: Client, args: dict[str, Any]) -> CommandResults:
    try:
        item_id = str(args.get('item_id', ''))
        bot_id = ''
        room_id = ''

        # Get mentions list:
        mentions_list_res = client.get_mention_list()
        if isinstance(mentions_list_res, dict) and isinstance(mentions_list_res.get('data', ''), list) \
                and len(mentions_list_res['data']) > 0 and isinstance(mentions_list_res['data'][0], dict) \
                and 'id' in mentions_list_res['data'][0]:

            mentions_list = mentions_list_res['data']

            # Fetch some important item data.
            item_res = client.get_item(item_id=item_id)
            if isinstance(item_res, dict) and isinstance(item_res.get('data', ''), dict):
                # Prevent execution on unsupported sub types.
                if item_res['data'].get('sub_type', -1) not in SUPPORTED_SUB_TYPES_FOR_PURCHASE:
                    raise Exception("RaDark Error: Sub type not supported for purchasing!")

                # Extract bot ID and incident ID.
                incident_id = item_res['data'].get('feed_property_id', '')
                if not incident_id:
                    raise Exception("RaDark Error: Item ID was not found!")
                bot_id = item_res['data'].get('bot_id', '')
                if not bot_id:
                    raise Exception("RaDark Error: Bot ID was not found!")

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
                        "text": f"Hi <b>@KELA</b> , I would like to acquire further details about bot: {bot_id}",
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
                        readable_output = f"Bot ID ('{bot_id}') marked for purchasing."
                    else:
                        raise Exception("RaDark Error: Purchase message was not created!")
                else:
                    raise Exception("RaDark Error: Item was not marked for purchase!")
            else:
                readable_output = f'No data found for item ID: {item_id}'
        else:
            raise Exception("RaDark Error: Mentions list was not found!")
        return CommandResults(readable_output=readable_output)
    except Exception as e:
        raise Exception(f'RaDark Error: Failed to execute command on {item_id}.\nError:\n {str(e)}')


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_timestamp = get_first_time_fetch(demisto.params().get('first_fetch'))

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # Initialize Client
        client = Client(base_url=BASE_URL,
                        verify=verify_certificate,
                        headers={},
                        proxy=proxy,
                        api_key=API_KEY,
                        monitor_id=MONITOR_ID)

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
