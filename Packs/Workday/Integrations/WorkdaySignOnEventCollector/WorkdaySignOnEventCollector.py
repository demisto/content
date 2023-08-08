import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import urllib3
from typing import Tuple

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = 'workday'
PRODUCT = 'sign_on'
API_VERSION = 'v40.0'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

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

        body = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:bsvc="urn:com.workday/bsvc">
            <soapenv:Header>
                <wsse:Security soapenv:mustUnderstand="1"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                    <wsse:UsernameToken wsu:Id="UsernameToken-{token}">
                        <wsse:Username>{username}</wsse:Username>
                        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0
                        #PasswordText">{password}</wsse:Password>
                    </wsse:UsernameToken>
                </wsse:Security>
            </soapenv:Header>
            <soapenv:Body>
                <bsvc:Response_Filter>
                    <bsvc:Page>{page}</bsvc:Page>
                    <bsvc:Count>{count}</bsvc:Count>
                </bsvc:Response_Filter>
                <bsvc:Get_Workday_Account_Signons_Request bsvc:version="v40.0">        
                    <bsvc:Request_Criteria>         
                        <bsvc:From_DateTime>{from_time}</bsvc:From_DateTime>
                        <bsvc:To_DateTime>{to_time}</bsvc:To_DateTime>           
                    </bsvc:Request_Criteria>        
                </bsvc:Get_Workday_Account_Signons_Request>
            </soapenv:Body>
        </soapenv:Envelope>
        """

        return body.format(
            token=self.token, username=self.username, password=self.password, api_version=API_VERSION,
            to_time=to_time, from_time=from_time, page=page, count=count)

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
        total_pages = response_results.get('Total_Pages', 1)
        return account_signon_data, total_pages

    def test_connectivity(self) -> str:
        """
        Tests API connectivity and authentication.

        :return: 'ok' if test passed, else exception.
        :rtype: ``str``
        """

        def get_from_time():
            current_time = datetime.now(tz=timezone.utc)
            five_seconds_ago = current_time - timedelta(seconds=5)
            from_time = five_seconds_ago.strftime(DATE_FORMAT)
            return from_time

        to_time = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
        body = self.generate_workday_account_signons_body(page=1, count=1, to_time=to_time, from_time=get_from_time())
        self._http_request(method="POST", url_suffix="", data=body, resp_type='text', timeout=120)
        return 'ok'


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

    # Get 'Response_Data' and 'Workday_Account_Signon' safely
    account_signon_data = response_data.get('Response_Data', {}).get('Workday_Account_Signon') if response_data.get(
        'Response_Data') else None

    if not account_signon_data:
        raise ValueError("'Workday_Account_Signon' not found in the 'Response_Data'")

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
    sign_on_logs.extend(res)
    demisto.debug(f"Request indicates a total of {total_pages} pages to paginate.")
    pages_remaining = total_pages - 1

    while page <= total_pages and pages_remaining != 0:
        page += 1
        res, _ = client.retrieve_events(from_time=from_date, to_time=to_date, page=page, count=limit_to_fetch)
        pages_remaining -= 1
        demisto.debug(f'Fetched {len(res)} sign on logs.')
        sign_on_logs.extend(res)
        if not res:
            break
        demisto.debug(f'{pages_remaining} pages left to fetch.')
    demisto.debug(f'Found {len(sign_on_logs)} Sign On Logs.')
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
    to_date = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
    demisto.debug(f'Getting Sign On Events {from_date=}, {to_date=}.')
    sign_on_events = fetch_sign_on_logs(client=client, limit_to_fetch=max_fetch, from_date=from_date, to_date=to_date)

    if sign_on_events:
        demisto.debug("Got sign_on_events. Begin processing.")
        last_event = sign_on_events[-1]
        process_events(sign_on_events)
        demisto.debug(f"Done processing {len(sign_on_events)} sign_on_events.")
        last_run = {'last_fetch_time': to_date, 'last_event': last_event}
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
    base_url = params.get('base_url')
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
            base_url=base_url,
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
            should_push_events = argToBoolean(args.pop('should_push_events'))
            sign_on_events, results = get_sign_on_events_command(client=client,
                                                                 from_date=args.get('from_date'),
                                                                 to_date=args.get('to_date'),
                                                                 limit=arg_to_number(args.get('limit')))
            return_results(results)
            if should_push_events:
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
