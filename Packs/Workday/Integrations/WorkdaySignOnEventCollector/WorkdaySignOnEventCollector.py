import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3
from typing import Tuple

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = 'workday'
PRODUCT = 'sign_on'
API_VERSION = 'v40.0'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def get_from_time(seconds_ago):
    current_time = datetime.now(tz=timezone.utc)
    from_time = current_time - timedelta(seconds=seconds_ago)
    return from_time.strftime(DATE_FORMAT)


def fletcher16(data: bytes) -> int:
    """
    Compute the Fletcher-16 checksum for the given data.

    The Fletcher-16 checksum is a simple and fast checksum algorithm that provides
    a checksum value based on the input data. It's not as collision-resistant as
    cryptographic hashes but is faster and can be suitable for non-security-critical
    applications.

    Parameters:
    - data (bytes): The input data for which the checksum is to be computed.

    Returns:
    - int: The computed Fletcher-16 checksum value.
    """
    sum1, sum2 = 0, 0
    for byte in data:
        sum1 = (sum1 + byte) % 256
        sum2 = (sum2 + sum1) % 256
    return (sum2 << 8) | sum1


def generate_checksum(short_session_id: str, user_name: int, successful: int, signon_datetime: str) -> int:
    """
    Compute a checksum for the given inputs using the Fletcher-16 algorithm.

    This function takes in several parameters, converts them to bytes, and then computes
    a Fletcher-16 checksum for the concatenated byte data. The checksum provides a way to
    verify the integrity of the data, ensuring that it has not been altered.

    Parameters:
    - short_session_id (str): A GUID not longer than 6 characters.
    - user_name (int): An integer representing the user's name.
    - successful (int): A boolean represented as 0 (False) or 1 (True).
    - signon_datetime (str): A string representing the sign-on date and time in ISO 8601 format.

    Returns:
    - int: The computed Fletcher-16 checksum value.
    """
    data = (short_session_id + signon_datetime).encode() + user_name.to_bytes(4, 'little') + bytes([successful])
    checksum = fletcher16(data)
    return checksum


def check_events_against_checksums(events: list, checksums: set) -> list:
    """
    Check if events exist in the list of checksums.

    Parameters:
    - events (list): A list of events, where each event is a tuple containing the arguments for the generate_checksum function.
    - checksums (list): A list of checksums.

    Returns:
    - list: A list of events that do not exist in the list of checksums.
    """

    new_events = []

    for event in events:
        short_session_id, user_name, successful, signon_datetime = event
        event_checksum = generate_checksum(short_session_id, user_name, successful, signon_datetime)

        if event_checksum not in checksums:
            new_events.append(event)

    return new_events


def filter_and_check_events(events: list, target_datetime_str: str, checksums: set) -> list:
    """
    Filter events based on the proximity of their Signon_DateTime to a target datetime and then check against checksums.

    Parameters:
    - events (list): A list of events, where each event is a dictionary containing keys used for checksum generation.
    - target_datetime_str (str): A datetime string in the format 'YYYY-MM-DDTHH:MM:SS'.
    - checksums (set): A set of checksums to check against.

    Returns:
    - list: A refined list of non-duplicate events.
    """
    target_datetime = datetime.fromisoformat(target_datetime_str)

    start_time = target_datetime - timedelta(seconds=1)
    end_time = target_datetime + timedelta(seconds=1)

    potential_duplicates = [event for event in events if
                            start_time <= datetime.fromisoformat(event['Signon_DateTime']) <= end_time]

    formatted_events = [(event['Short_Session_ID'], event['User_Name'], event['Successful'], event['Signon_DateTime'])
                        for event in potential_duplicates]

    non_duplicates = check_events_against_checksums(formatted_events, checksums)

    return non_duplicates


def get_future_duplicates_within_timeframe(events: list, to_time: str) -> list:
    """
    Filter events based on a timeframe of one second before and up to the given to_time.

    Parameters:
    - events (list): A list of events, where each event is a dictionary containing keys used for checksum generation.
    - to_time (str): A datetime string in the format 'YYYY-MM-DDTHH:MM:SS' which represents the end of the timeframe.

    Returns:
    - list: A list of events within the specified timeframe which could be a duplicate for the next fetch.
    """
    # Convert the to_time string to a datetime object
    end_time = datetime.fromisoformat(to_time)

    # Define the start time for the timeframe
    start_time = end_time - timedelta(seconds=1)

    # Filter events based on the timeframe
    future_duplicates = [event for event in events if
                         start_time <= datetime.fromisoformat(event['Signon_DateTime']) <= end_time]

    return future_duplicates


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url: str, verify_certificate: bool, proxy: bool, tenant_name: str, token: str,
                 username: str, password: str):
        headers = {"content-type": "text/xml;charset=UTF-8"}

        super().__init__(base_url=base_url, verify=verify_certificate, proxy=proxy, headers=headers)
        self.tenant_name = tenant_name
        self.token = token
        self.username = username
        self.password = password

    def generate_workday_account_signons_body(self, page: int, count: int, to_time: Optional[str] = None,
                                              from_time: Optional[str] = None) -> str:
        """
        Generates XML body for Workday Account Signons Request.

        :type page: ``int``
        :param page: Page number.

        :type count: ``int``
        :param count: Number of results per page.

        :type to_time: ``Optional[str]``
        :param to_time: End time for fetching events.

        :type from_time: ``Optional[str]``
        :param from_time: Start time for fetching events.

        :return: XML body as string.
        :rtype: ``str``
        """

        return f"""
            <soapenv:Envelope xmlns:bsvc="urn:com.workday/bsvc" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                <soapenv:Header>
                    <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                        <wsse:UsernameToken wsu:Id="UsernameToken-BF23D830F28697AA1614674076904673">
                            <wsse:Username>{self.username}</wsse:Username>
                            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{self.password}</wsse:Password>
                        </wsse:UsernameToken>
                    </wsse:Security>
                </soapenv:Header>
                <soapenv:Body>
                    <bsvc:Get_Workday_Account_Signons_Request xmlns:bsvc="urn:com.workday/bsvc" bsvc:version="v37.0">
                        <!-- Optional: -->
                        <bsvc:Request_Criteria>
                            <!-- Optional: -->
                            <bsvc:From_DateTime>{from_time}</bsvc:From_DateTime>
                            <!-- Optional: -->
                            <bsvc:To_DateTime>{to_time}</bsvc:To_DateTime>
                        </bsvc:Request_Criteria>
                        <!-- Optional: -->
                        <bsvc:Response_Filter>
                            <bsvc:Page>{page}</bsvc:Page>
                            <!-- Optional: -->
                            <bsvc:Count>{count}</bsvc:Count>
                            <bsvc:As_Of_Entry_DateTime>{from_time}</bsvc:As_Of_Entry_DateTime>
                        </bsvc:Response_Filter>
                    </bsvc:Get_Workday_Account_Signons_Request>
                </soapenv:Body>
            </soapenv:Envelope>

            """

    def generate_test_payload(self, from_time, to_time):
        return  f"""
            <soapenv:Envelope xmlns:bsvc="urn:com.workday/bsvc" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                <soapenv:Header>
                    <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                        <wsse:UsernameToken wsu:Id="UsernameToken-BF23D830F28697AA1614674076904673">
                            <wsse:Username>{self.username}</wsse:Username>
                            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{self.password}</wsse:Password>
                        </wsse:UsernameToken>
                    </wsse:Security>
                </soapenv:Header>
                <soapenv:Body>
                    <bsvc:Get_Workday_Account_Signons_Request xmlns:bsvc="urn:com.workday/bsvc" bsvc:version="v37.0">
                        <!-- Optional: -->
                        <bsvc:Request_Criteria>
                            <!-- Optional: -->
                            <bsvc:From_DateTime>{from_time}</bsvc:From_DateTime>
                            <!-- Optional: -->
                            <bsvc:To_DateTime>{to_time}</bsvc:To_DateTime>
                        </bsvc:Request_Criteria>
                        <!-- Optional: -->
                        <bsvc:Response_Filter>
                            <bsvc:Page>1</bsvc:Page>
                            <!-- Optional: -->
                            <bsvc:Count>1</bsvc:Count>
                        </bsvc:Response_Filter>
                    </bsvc:Get_Workday_Account_Signons_Request>
                </soapenv:Body>
            </soapenv:Envelope>
    
            """

    def retrieve_events(self, page: int, count: int, to_time: Optional[str] = None,
                        from_time: Optional[str] = None) -> Tuple:
        """
        Retrieves events from Workday.

        :type page: ``int``
        :param page: Page number.

        :type count: ``int``
        :param count: Number of results per page.

        :type to_time: ``Optional[str]``
        :param to_time: End time for fetching events.

        :type from_time: ``Optional[str]``
        :param from_time: Start time for fetching events.

        :return: Tuple containing raw JSON response and account sign-on data.
        :rtype: ``Tuple``
        """

        body = self.generate_workday_account_signons_body(page=page, count=count, to_time=to_time, from_time=from_time)
        raw_response = self._http_request(method="POST", url_suffix="", data=body, resp_type='text', timeout=120)
        raw_json_response, account_signon_data = convert_to_json(raw_response)
        response_results = raw_json_response.get('Envelope', {}).get('Body', {}).get(
            'Get_Workday_Account_Signons_Response',
            {}).get('Response_Results', {})
        total_pages = response_results.get('Total_Pages', '1')
        return account_signon_data, int(total_pages)

    def test_connectivity(self) -> str:
        """
        Tests API connectivity and authentication.

        :return: 'ok' if test passed, else exception.
        :rtype: ``str``
        """
        seconds_ago = 5
        from_time = get_from_time(seconds_ago)
        to_time = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)

        payload = self.generate_test_payload(from_time=from_time, to_time=to_time)

        self._http_request(method="POST", url_suffix="", data=payload, resp_type='text', timeout=120)

        return "ok"


''' HELPER FUNCTIONS '''


def convert_to_json(response: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Convert an XML response to a JSON object and extract the 'Workday_Account_Signons' data.

    :param response: XML response to be converted
    :return: Tuple containing the full converted response and the extracted 'Workday_Account_Signons' data.
    :raises ValueError: If the expected data cannot be found in the response.
    """
    if type(response) == dict:
        raw_json_response = response
    else:
        try:
            raw_json_response = json.loads(xml2json(response))
        except Exception as e:
            raise ValueError(f"Error parsing XML to JSON: {e}")

    # Get the 'Get_Workday_Account_Signons_Response' dictionary safely
    response_data = raw_json_response.get('Envelope', {}).get('Body', {}).get('Get_Workday_Account_Signons_Response', {})

    if not response_data:
        response_data = raw_json_response.get(
            'Get_Workday_Account_Signons_Response', {})

    account_signon_data = response_data.get('Response_Data', {})

    return raw_json_response, account_signon_data


def process_events(events: List[Dict[str, Any]]) -> None:
    """
    Update each event in the provided list with a '_time' key set to the value of 'Signon_DateTime'.

    :param events: List of event dictionaries.
    """
    [_event.update({'_time': _event.get('Signon_DateTime')}) for _event in events]


def fetch_sign_on_logs(client: Client, limit_to_fetch: int, from_date: str, to_date: str):
    """
    Fetches Sign On logs from workday.
    Args:
        client: Client object.
        limit_to_fetch: limit of logs to fetch from Workday.
        from_date: Events from time.
        to_date: Events to time.

    Returns:
        Sign On Events fetched from Workday.
    """
    sign_on_logs: list = []
    page = 1  # We assume that we will need to make one call at least
    res, total_pages = client.retrieve_events(from_time=from_date, to_time=to_date, page=1, count=limit_to_fetch)
    sign_on_logs.extend(res.get('Workday_Account_Signon', []))
    demisto.debug(f"Request indicates a total of {total_pages} pages to paginate.")
    pages_remaining = total_pages - 1

    while page <= total_pages and pages_remaining != 0:
        page += 1
        res, _ = client.retrieve_events(from_time=from_date, to_time=to_date, page=page, count=limit_to_fetch)
        pages_remaining -= 1
        demisto.debug(f'Fetched {len(res)} sign on logs.')
        sign_on_logs.extend(res.get('Workday_Account_Signon'))
        if not res:
            break
        demisto.debug(f'{pages_remaining} pages left to fetch.')
    return sign_on_logs


''' COMMAND FUNCTIONS '''


def get_sign_on_events_command(client: Client, from_date: str, to_date: str, limit: Optional[int]) -> Tuple[
    list, CommandResults]:
    """

    Args:
        limit: The maximum number of logs to return.
        to_date: date to fetch events from.
        from_date: date to fetch events to.
        client: Client object.

    Returns:
        Sign on logs from Workday.
    """

    sign_on_events = fetch_sign_on_logs(client=client, limit_to_fetch=limit, from_date=from_date, to_date=to_date)
    process_events(sign_on_events)
    demisto.results(f"Got a total of {len(sign_on_events)} events between the time {from_date} to {to_date} - {sign_on_events}")
    readable_output = tableToMarkdown('Sign On Events List:', sign_on_events,
                                      removeNull=True,
                                      headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)))

    return sign_on_events, CommandResults(readable_output=readable_output)


def fetch_sign_on_events_command(client: Client, max_fetch: int, first_fetch: datetime, last_run: dict):
    """
    Fetches sign on logs from Workday.
    Args:
        first_fetch: first fetch date.
        client: Client object.
        max_fetch: max logs to fetch set by customer.
        last_run: last run object.

    Returns:
        Sign on logs from Workday.

    """
    from_date = last_run.get('last_fetch_time', first_fetch.strftime(DATE_FORMAT))
    previous_run_checksums = last_run.get('previous_run_checksums', set())
    to_date = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
    demisto.debug(f'Getting Sign On Events {from_date=}, {to_date=}.')
    sign_on_events = fetch_sign_on_logs(client=client, limit_to_fetch=max_fetch, from_date=from_date, to_date=to_date)

    if sign_on_events:
        demisto.debug("Got sign_on_events. Begin processing.")
        non_duplicates = filter_and_check_events(events=sign_on_events, target_datetime_str=from_date, checksums=previous_run_checksums)
        sign_on_events.extend(non_duplicates)
        process_events(sign_on_events)

        future_potential_duplicates = get_future_duplicates_within_timeframe(events=sign_on_events, to_time=to_date)
        checksums_for_next_iteration = {
            generate_checksum(
                event['Short_Session_ID'],
                event['User_Name'],
                event['Successful'],
                event['Signon_DateTime']
            ) for event in future_potential_duplicates}

        demisto.debug(f"Done processing {len(sign_on_events)} sign_on_events.")
        last_run = {'last_fetch_time': to_date, 'previous_run_checksums': checksums_for_next_iteration}
        demisto.debug(f"Saving last run as {last_run}")

    return sign_on_events, last_run


def module_of_testing(client: Client) -> str:  # pragma: no cover
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    return client.test_connectivity()


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    tenant_name = params.get('tenant_name')
    url = params.get('base_url')
    # url = r'https://services1.myworkday.com/ccx/service/cnx/Identity_Management/v37.0'
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    token = params.get('token', {}).get('password')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000
    first_fetch = arg_to_datetime(arg=params.get('first_fetch', '3 days'),
                                  arg_name='First fetch time',
                                  required=True)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=url,
            tenant_name=tenant_name,
            token=token,
            username=username,
            password=password,
            verify_certificate=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            return_results(module_of_testing(client))
        elif command == 'workday-get-sign-on-events':
            sign_on_events, results = get_sign_on_events_command(client=client,
                                                                 from_date=args.get('from_date'),
                                                                 to_date=args.get('to_date'),
                                                                 limit=arg_to_number(args.get('limit')))
            return_results(results)
            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    sign_on_events,
                    vendor=VENDOR,
                    product=PRODUCT
                )
        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            demisto.debug(f'Starting new fetch with last_run as {last_run}')
            sign_on_events, new_last_run = fetch_sign_on_events_command(client=client,
                                                                        max_fetch=max_fetch,
                                                                        first_fetch=first_fetch,  # type: ignore
                                                                        last_run=last_run)
            demisto.debug("Done fetching events, sending to XSIAM.")
            send_events_to_xsiam(
                sign_on_events,
                vendor=VENDOR,
                product=PRODUCT
            )
            if new_last_run:
                # saves next_run for the time fetch-events is invoked
                demisto.info(f'Setting new last_run to {new_last_run}')
                demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
