
import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
VENDOR = 'orca'
PRODUCT = 'security'
MAX_ALLOWED_ENTRY_SIZE = 5 * (10 ** 6)  # 5 MB, this is the maximum allowed size of a single entry.
''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, server_url: str, headers: dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_alerts_request(self, max_fetch: int, last_fetch: str, next_page_token: Optional[str]) -> dict:
        """ Retrieve information about alerts.
            Args:
                max_fetch: int - Limit number of returned records.
                last_fetch: str - the date and time of the last fetch
                next_page_token: Optional[str] - the token to the next page
            Returns:
                A dictionary with the alerts details.
        """
        params = {
            'limit': max_fetch,
            'dsl_filter': "{\n\"filter\":\n[\n{\n\"field\": \"state.created_at\",\n\"range\": {\n\""
                          "gt\": \"" + last_fetch + "\"\n}\n}\n],\n\"sort\":\n[\n{\"field\":"
                                                    "\"state.created_at\",\n\"order\":\"asc\"\n}\n]}",
            'show_all_statuses_alerts': True,
            'show_informational_alerts': True,
        }
        if next_page_token:
            params['next_page_token'] = next_page_token

        demisto.info(f'In get_alerts request {params=}')
        return self._http_request(method='GET', url_suffix='/query/alerts', params=params)


''' HELPER FUNCTIONS '''


def add_time_key_to_alerts(alerts: List[dict]) -> List[dict]:
    """
    Adds the _time key to the alerts.
    Args:
        alerts: List[Dict] - list of events to add the _time key to.
    Returns:
        list: The events with the _time key.
    """
    if alerts:
        for alert in alerts:
            create_time = arg_to_datetime(arg=alert.get('state', {}).get('created_at'))
            alert['_time'] = create_time.strftime(DATE_FORMAT) if create_time else None
            demisto.debug(f'{alert.get("state", {}).get("alert_id")=} , {alert.get("_time")=}')
    return alerts


''' COMMAND FUNCTIONS '''


def test_module(client: Client, last_fetch: str, max_fetch: int) -> str:
    """ Test the connection to Orca Security.
    Args:
        client: client - An Orca client.
        last_fetch: str - The time and date of the last fetch alert
        max_fetch: int - The maximum number of events per fetch
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_alerts_request(max_fetch, last_fetch, None)
        return 'ok'
    except DemistoException as e:
        if 'Error in API call [404] - Not Found' in e.message:
            raise Exception('Error in API call [404] - Not Found\n{"error": "URL is invalid"}')
        else:
            raise Exception(e.message)


def get_alerts(client: Client, max_fetch: int, last_fetch: str, next_page_token: str = None) -> tuple:
    """ Retrieve information about alerts.
    Args:
        client: client - An Orca client.
        max_fetch: int - The maximum number of events per fetch
        last_fetch: str - The time and date of the last fetch alert
        next_page_token: str - The token to the next page.
    Returns:
        - list of alerts
        - next_page_token if exist
    """
    response = client.get_alerts_request(max_fetch, last_fetch, next_page_token)
    next_page_token = response.get('next_page_token')
    alerts = response.get('data', [])
    demisto.debug(f'Get Alerts Response {next_page_token=} , {len(alerts)=}\n {alerts=}')
    return alerts, next_page_token


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    api_token = demisto.params().get('credentials', {}).get('password')
    server_url = f"{demisto.params().get('server_url')}/api"
    first_fetch = demisto.params().get('first_fetch') or '3 days'
    max_fetch = arg_to_number(demisto.params().get('max_fetch')) or 1000
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=first_fetch,
        arg_name='First fetch time',
        required=True
    )
    first_fetch_time = first_fetch_time.strftime(DATE_FORMAT) if first_fetch_time else ''
    demisto.debug(f'{first_fetch_time=}')
    demisto.info(f'Orca Security. Command being called is {command}')
    try:

        headers: dict = {
            "Authorization": f'Token {api_token}'
        }

        client = Client(
            server_url=server_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        last_run = demisto.getLastRun()
        if not last_run:
            demisto.debug(f'first run {last_run=}')
            last_fetch = first_fetch_time
        else:
            last_fetch = last_run.get('lastRun')
            demisto.debug(f"Isn't the first run {last_fetch}")
        next_page_token = last_run.get('next_page_token')

        if command == 'test-module':
            return_results(test_module(client, last_fetch, max_fetch))
        elif command in ('fetch-events', 'orca-security-get-events'):
            alerts, next_page_token = get_alerts(client, max_fetch, last_fetch, next_page_token)

            if command == 'fetch-events':
                should_push_events = True

            else:  # command == 'orca-security-get-events'
                should_push_events = argToBoolean(demisto.args().get('should_push_events', False))
                return_results(CommandResults(
                    readable_output=tableToMarkdown(t=alerts,
                                                    name=f'{VENDOR} - {PRODUCT} events',
                                                    removeNull=True),
                    raw_response=alerts
                ))

            if should_push_events:
                alerts = add_time_key_to_alerts(alerts)
                demisto.debug(f'before send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}')
                send_events_to_xsiam_mod(alerts, VENDOR, PRODUCT)
                demisto.debug(f'after send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}')

            current_last_run = {
                'next_page_token': next_page_token
            }
            if next_page_token:
                current_last_run['lastRun'] = last_fetch
            else:
                last_updated = arg_to_datetime(arg=alerts[-1].get('state', {}).get('created_at')) if alerts else None
                current_last_run['lastRun'] = last_updated.strftime(DATE_FORMAT) if last_updated else last_fetch

            demisto.setLastRun(current_last_run)
            demisto.debug(f'{current_last_run=}')

        else:
            raise NotImplementedError('This command is not implemented yet.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


""" Orca changes """


def send_events_to_xsiam_mod(
    events,
    vendor,
    product,
    data_format=None,
    url_key="url",
    num_of_attempts=3,
    chunk_size=XSIAM_EVENT_CHUNK_SIZE,
    should_update_health_module=True,
    add_proxy_to_request=False,
    multiple_threads=False,
):
    """
    Send the fetched events into the XDR data-collector private api.

    :type events: ``Union[str, list]``
    :param events: The events to send to XSIAM server. Should be of the following:
        1. List of strings or dicts where each string or dict represents an event.
        2. String containing raw events separated by a new line.

    :type vendor: ``str``
    :param vendor: The vendor corresponding to the integration that originated the events.

    :type product: ``str``
    :param product: The product corresponding to the integration that originated the events.

    :type data_format: ``str``
    :param data_format: Should only be filled in case the 'events' parameter contains a string of raw
        events in the format of 'leef' or 'cef'. In other cases the data_format will be set automatically.

    :type url_key: ``str``
    :param url_key: The param dict key where the integration url is located at. the default is 'url'.

    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes)

    :type chunk_size: ``int``
    :param chunk_size: Advanced - The maximal size of each chunk size we send to API. Limit of 9 MB will be inforced.

    :type should_update_health_module: ``bool``
    :param should_update_health_module: whether to trigger the health module showing how many events were sent to xsiam

    :type add_proxy_to_request :``bool``
    :param add_proxy_to_request: whether to add proxy to the send evnets request.

    :type multiple_threads: ``bool``
    :param multiple_threads: whether to use multiple threads to send the events to xsiam or not.

    :return: Either None if running in a single thread or a list of future objects if running in multiple threads.
    In case of running with multiple threads, the list of futures will hold the number of events sent and can be accessed by:
    for future in concurrent.futures.as_completed(futures):
        data_size += future.result()
    :rtype: ``List[Future]`` or ``None``
    """
    return send_data_to_xsiam_mod(
        events,
        vendor,
        product,
        data_format,
        url_key,
        num_of_attempts,
        chunk_size,
        data_type="events",
        should_update_health_module=should_update_health_module,
        add_proxy_to_request=add_proxy_to_request,
        multiple_threads=multiple_threads,
    )


def send_data_to_xsiam_mod(
    data,
    vendor,
    product,
    data_format=None,
    url_key="url",
    num_of_attempts=3,
    chunk_size=XSIAM_EVENT_CHUNK_SIZE,
    data_type=EVENTS,
    should_update_health_module=True,
    add_proxy_to_request=False,
    snapshot_id="",
    items_count=None,
    multiple_threads=False,
):
    """
    Send the supported fetched data types into the XDR data-collector private api.

    :type data: ``Union[str, list]``
    :param data: The data to send to XSIAM server. Should be of the following:
        1. List of strings or dicts where each string or dict represents an event or asset.
        2. String containing raw events separated by a new line.

    :type vendor: ``str``
    :param vendor: The vendor corresponding to the integration that originated the data.

    :type product: ``str``
    :param product: The product corresponding to the integration that originated the data.

    :type data_format: ``str``
    :param data_format: Should only be filled in case the 'events' parameter contains a string of raw
        events in the format of 'leef' or 'cef'. In other cases the data_format will be set automatically.

    :type url_key: ``str``
    :param url_key: The param dict key where the integration url is located at. the default is 'url'.

    :type num_of_attempts: ``int``
    :param num_of_attempts: The num of attempts to do in case there is an api limit (429 error codes)

    :type chunk_size: ``int``
    :param chunk_size: Advanced - The maximal size of each chunk size we send to API. Limit of 9 MB will be inforced.

    :type data_type: ``str``
    :param data_type: Type of data to send to Xsiam, events or assets.

    :type should_update_health_module: ``bool``
    :param should_update_health_module: whether to trigger the health module showing how many events were sent to xsiam
        This can be useful when using send_data_to_xsiam in batches for the same fetch.

    :type add_proxy_to_request: ``bool``
    :param add_proxy_to_request: whether to add proxy to the send evnets request.

    :type snapshot_id: ``str``
    :param snapshot_id: the snapshot id.

    :type items_count: ``str``
    :param items_count: the asset snapshot items count.

    :type multiple_threads: ``bool``
    :param multiple_threads: whether to use multiple threads to send the events to xsiam or not.
    Note that when set to True, the updateModuleHealth should be done from the itnegration itself.

    :return: Either None if running in a single thread or a list of future objects if running in multiple threads.
    In case of running with multiple threads, the list of futures will hold the number of events sent and can be accessed by:
    for future in concurrent.futures.as_completed(futures):
        data_size += future.result()
    :rtype: ``List[Future]`` or ``None```
    """
    data_size = 0
    params = demisto.params()
    url = params.get(url_key)
    calling_context = demisto.callingContext.get("context", {})
    instance_name = calling_context.get("IntegrationInstance", "")
    collector_name = calling_context.get("IntegrationBrand", "")
    if not items_count:
        items_count = len(data) if isinstance(data, list) else 1
    if data_type not in DATA_TYPES:
        demisto.debug(f"data type must be one of these values: {DATA_TYPES}")
        return None

    if not data:
        demisto.debug(
            f"send_data_to_xsiam function received no {data_type}, skipping the API call to send {data_type} to XSIAM"
        )
        demisto.updateModuleHealth({f"{data_type}Pulled": data_size})
        return None

    # only in case we have data to send to XSIAM we continue with this flow.
    # Correspond to case 1: List of strings or dicts where each string or dict represents an one event or asset or snapshot.
    if isinstance(data, list):
        # In case we have list of dicts we set the data_format to json and parse each dict to a stringify each dict.
        demisto.debug(f"Sending {len(data)} {data_type} to XSIAM")
        if isinstance(data[0], dict):
            data = [json.dumps(item) for item in data]
            data_format = "json"
        # Separating each event with a new line
        data = "\n".join(data)
    elif not isinstance(data, str):
        raise DemistoException(
            f"Unsupported type: {type(data)} for the {data_type} parameter. Should be a string or list."
        )
    if not data_format:
        data_format = "text"

    xsiam_api_token = demisto.getLicenseCustomField("Http_Connector.token")
    xsiam_domain = demisto.getLicenseCustomField("Http_Connector.url")
    xsiam_url = f"https://api-{xsiam_domain}"
    headers = {
        "authorization": xsiam_api_token,
        "format": data_format,
        "product": product,
        "vendor": vendor,
        "content-encoding": "gzip",
        "collector-name": collector_name,
        "instance-name": instance_name,
        "final-reporting-device": url,
        "collector-type": ASSETS if data_type == ASSETS else EVENTS,
    }
    if data_type == ASSETS:
        if not snapshot_id:
            snapshot_id = str(round(time.time() * 1000))

        # We are setting a time stamp ahead of the instance name since snapshot-ids must be configured in ascending
        # alphabetical order such that first_snapshot < second_snapshot etc.
        headers["snapshot-id"] = snapshot_id + instance_name
        headers["total-items-count"] = str(items_count)

    header_msg = f"Error sending new {data_type} into XSIAM.\n"

    def data_error_handler(res):
        """
        Internal function to parse the XSIAM API errors
        """
        try:
            response = res.json()
            error = res.reason
            if response.get("error").lower() == "false":
                xsiam_server_err_msg = response.get("error")
                error += ": " + xsiam_server_err_msg

        except ValueError:
            if res.text:
                error = f"\n{res.text}"
            else:
                error = "Received empty response from the server"

        api_call_info = (
            "Parameters used:\n"
            f"\tURL: {xsiam_url}\n"
            f"\tHeaders: {json.dumps(headers, indent=8)}\n\n"
            f"Response status code: {res.status_code}\n"
            f"Error received:\n\t{error}"
        )

        demisto.error(header_msg + api_call_info)
        raise DemistoException(header_msg + error, DemistoException)

    client = BaseClient(base_url=xsiam_url, proxy=add_proxy_to_request)
    data_chunks = split_data_to_chunks_mod(data, chunk_size)

    def send_events(data_chunk):
        chunk_size = len(data_chunk)
        data_chunk = "\n".join(data_chunk)
        zipped_data = gzip.compress(data_chunk.encode("utf-8"))  # type: ignore[AttributeError,attr-defined]
        xsiam_api_call_with_retries(
            client=client,
            events_error_handler=data_error_handler,
            error_msg=header_msg,
            headers=headers,
            num_of_attempts=num_of_attempts,
            xsiam_url=xsiam_url,
            zipped_data=zipped_data,
            is_json_response=True,
            data_type=data_type,
        )
        return chunk_size

    if multiple_threads:
        demisto.info("Sending events to xsiam with multiple threads.")
        all_chunks = [chunk for chunk in data_chunks]
        demisto.info("Finished appending all data_chunks to a list.")
        support_multithreading()
        futures = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=NUM_OF_WORKERS)
        for chunk in all_chunks:
            future = executor.submit(send_events, chunk)
            futures.append(future)

        demisto.info(f"Finished submiting {len(futures)} Futures.")
        return futures
    else:
        demisto.info("Sending events to xsiam with a single thread.")
        for chunk in data_chunks:
            data_size += send_events(chunk)

        if should_update_health_module:
            demisto.updateModuleHealth({f"{data_type}Pulled": data_size})
    return None


def split_data_to_chunks_mod(data, target_chunk_size):
    """
    Splits a string of data into chunks of an approximately specified size.
    The actual size can be lower.

    :type data: ``list`` or a ``string``
    :param data: A list of data or a string delimited with \n  to split to chunks.
    :type target_chunk_size: ``int``
    :param target_chunk_size: The maximum size of each chunk. The maximal size allowed is 9MB.

    :return: An iterable of lists where each list contains events with approx size of chunk size.
    :rtype: ``collections.Iterable[list]``
    """
    target_chunk_size = min(target_chunk_size, XSIAM_EVENT_CHUNK_SIZE_LIMIT)
    chunk = []  # type: ignore[var-annotated]
    chunk_size = 0
    large_entry_cnt = 0
    if isinstance(data, str):
        data = data.split("\n")
    for data_part in data:
        if chunk_size >= target_chunk_size:
            demisto.debug(f"reached max chunk size, sending chunk with size: {chunk_size}")
            yield chunk
            chunk = []

        data_part_size = sys.getsizeof(data_part)
        if data_part_size >= MAX_ALLOWED_ENTRY_SIZE:
            large_entry_cnt += 1
            demisto.error(
                f"######### entry size {data_part_size} is larger than the maximum allowed entry size {MAX_ALLOWED_ENTRY_SIZE}, skipping this entry."
            )
            demisto.error(f"{target_chunk_size=}, {data=}")
            continue
        chunk.append(data_part)
        chunk_size += sys.getsizeof(data_part)
    demisto.debug(f'######### {large_entry_cnt=}')
    if chunk_size != 0:
        demisto.debug(f"sending the remaining chunk with size: {chunk_size}")
        yield chunk


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
