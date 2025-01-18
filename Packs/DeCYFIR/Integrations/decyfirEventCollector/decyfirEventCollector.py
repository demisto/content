import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

import uuid

urllib3.disable_warnings()

''' CONSTANTS '''
LABEL_DECYFIR = "DeCYFIR"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'Cyfirma'
PRODUCT = LABEL_DECYFIR
MAX_EVENT_TO_FETCH = 100

VAR_EVENT_API_PATH_SUFFIX: str = '/org/api-ua/v1/event-logs/'

VAR_ACCESS_LOGS = "access-logs"
VAR_ASSETS_LOGS = "assets-logs"
VAR_DR_KEYWORDS_LOGS = "dr-keywords-logs"

EVENT_TYPES = [VAR_ACCESS_LOGS, VAR_ASSETS_LOGS, VAR_DR_KEYWORDS_LOGS]


class Client(BaseClient):

    def request_decyfir_api(self, event_type, request_params: dict) -> list[dict]:
        response = self._http_request(
            url_suffix=f"{VAR_EVENT_API_PATH_SUFFIX}/{event_type}", params=request_params,
            resp_type='response',
            method='GET')

        if response.status_code == 200 and response.content:
            return response.json()

        return []

    def get_event_format(self, events_raw_data, event_type: str):
        final_data = []
        if events_raw_data:
            if event_type == VAR_ACCESS_LOGS:
                for raw_data1 in events_raw_data:
                    data = {
                    #    "id": uuid.uuid4(),
                        "event_type": "Access Logs",
                        "principal": raw_data1.get("principal", ""),
                        "action_type": raw_data1.get("event_type", ""),
                        "IP": raw_data1.get("ip", ""),
                        "event_date": raw_data1.get("event_date", "")
                    }
                    final_data.append(data)
            elif event_type == VAR_ACCESS_LOGS or event_type == VAR_DR_KEYWORDS_LOGS:
                for raw_data2 in events_raw_data:
                    event_type1 = "Asset Logs" if event_type == VAR_ACCESS_LOGS else "Digital Risk Keywards Logs"
                    data = {
                        # "id": str(uuid.uuid4()),
                        "event_type": event_type1,
                        "action_type": raw_data2.get("event_action", ""),
                        "asset_comments": raw_data2.get("asset_comments", ""),
                        "vendor": raw_data2.get("vendor", ""),
                        "asset_type": raw_data2.get("asset_comments", ""),
                        "asset_name": raw_data2.get("asset_name", ""),
                        "modified_by": raw_data2.get("modified_by", ""),
                        "event_date": raw_data2.get("modified_date", ""),
                        "version": raw_data2.get("version", "")
                    }
                    final_data.append(data)
        return final_data

    def get_decyfir_event_logs(self, after_val: int, decyfir_api_key: str, max_fetch):
        size = max_fetch if max_fetch else MAX_EVENT_TO_FETCH
        return_data = []
        for event_type in EVENT_TYPES:
            current_page = 0
            # while True:
            request_params = {
                "key": decyfir_api_key,
                "size": size,
                "after": after_val,
                # "page": current_page
            }
            response_data = self.request_decyfir_api(event_type, request_params)
            if response_data:
                return_data = return_data + self.get_event_format(response_data, event_type)
        return return_data


def test_event_logs_command(client, decyfir_api_key):
    url = VAR_EVENT_API_PATH_SUFFIX + "/" + VAR_ACCESS_LOGS + "?key=" + decyfir_api_key
    response = client._http_request(url_suffix=url, method='GET', resp_type='response')
    if response.status_code == 200:
        return 'ok'
    elif response.status_code in [401, 403]:
        return 'Not Authorized'
    else:
        return f"Error_code: {response.status_code}, Please contact the DeCYFIR team to assist you further on this."


def fetch_events(client: Client, decyfir_api_key: str, last_run, max_fetch, first_fetch):
    start_fetch = dateparser.parse(last_run.get("last_fetch")) if last_run else dateparser.parse(first_fetch)
    start_fetch_timestamp_val: float = start_fetch.timestamp() if isinstance(start_fetch, datetime) else 0.0
    start_fetch_timestamp: int = int(start_fetch_timestamp_val * 1000)

    events = client.get_decyfir_event_logs(
        after_val=start_fetch_timestamp,
        max_fetch=max_fetch,
        decyfir_api_key=decyfir_api_key
    )

    last_fetch_time = datetime.now().strftime(DATE_FORMAT)
    last_fetch = {"last_fetch": last_fetch_time}
    demisto.debug(f'Setting next run {last_fetch}.')
    return last_fetch, events


def add_time_to_events(events: List[Dict] | None):
    """
    Adds the _time key to the events.
    Args:
        events: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            create_time = arg_to_datetime(arg=event.get('event_date'))
            event['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    decyfir_url = params['url'].rstrip('/')
    decyfir_api_key = params.get('api_key').get("password")
    verify_certificate = not params.get('insecure', False)
    first_fetch = params.get('first_fetch', '30 days').strip()
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(args.get('limit') or params.get('max_fetch', 500))

    try:
        client = Client(base_url=decyfir_url, verify=verify_certificate, proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_event_logs_command(client, decyfir_api_key)
            demisto.results(result)

        elif demisto.command() in ['fetch-events', 'decyfir-get-events']:
            next_run, events = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                decyfir_api_key=decyfir_api_key,
                max_fetch=max_fetch
            )

            add_time_to_events(events)
            demisto.results(events)
            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

        else:
            raise NotImplementedError('DeCYFIR Events error: ' + f'command {demisto.command()} is not implemented')

    # Log exceptions
    except Exception as e:
        err = f'Failed to execute {demisto.command()} command. DeCYFIR events error: {str(e)}'
        return_error(err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
