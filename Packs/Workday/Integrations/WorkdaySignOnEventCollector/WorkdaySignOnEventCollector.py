
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from xml.sax.saxutils import escape

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = "workday"
PRODUCT = "signon"
API_VERSION = "v40.0"
REQUEST_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # Old format for making requests
EVENT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"  # New format for processing events
TIMEDELTA = 1


def get_from_time(seconds_ago: int) -> str:
    current_time = datetime.now(tz=timezone.utc)
    from_time = current_time - timedelta(seconds=seconds_ago)
    return from_time.strftime(REQUEST_DATE_FORMAT)


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


def generate_pseudo_id(event: dict) -> str:
    """
    Compute a checksum for the given event using the Fletcher-16 algorithm.

    This function takes the entire event, serializes it to a JSON string,
    converts that string to bytes, and then computes a Fletcher-16 checksum
    for the byte data.

    Parameters:
    - event (dict): The entire event dictionary.

    Returns:
    - str: The unique ID, which is the computed Fletcher-16 checksum value concatenated with the event's Signon_DateTime.
    """
    # Serialize the entire event to a JSON string and encode that to bytes
    event_str = json.dumps(event, sort_keys=True)
    data = event_str.encode()

    # Calculate the checksum
    checksum = fletcher16(data)

    # Create a unique ID by concatenating the checksum with the Signon_DateTime
    try:
        unique_id = f"{checksum}_{event['Signon_DateTime']}"
    except KeyError as e:
        raise DemistoException(f"While calculating the pseudo ID for an event, an event without a Signon_DateTime was "
                               f"found.\nError: {e}")

    return unique_id


""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(
        self,
        base_url: str,
        verify_certificate: bool,
        proxy: bool,
        tenant_name: str,
        username: str,
        password: str,
    ):
        headers = {"content-type": "text/xml;charset=UTF-8"}

        super().__init__(
            base_url=base_url, verify=verify_certificate, proxy=proxy, headers=headers
        )

        self.tenant_name = tenant_name
        self.username = escape(username)
        self.password = escape(password)

    def generate_workday_account_signons_body(
        self,
        page: int,
        count: int,
        to_time: Optional[str] = None,
        from_time: Optional[str] = None,
    ) -> str:
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

            """  # noqa:E501

    def generate_test_payload(self, from_time: str, to_time: str) -> str:
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
                            <bsvc:Page>1</bsvc:Page>
                            <!-- Optional: -->
                            <bsvc:Count>1</bsvc:Count>
                        </bsvc:Response_Filter>
                    </bsvc:Get_Workday_Account_Signons_Request>
                </soapenv:Body>
            </soapenv:Envelope>
            """  # noqa:E501

    def retrieve_events(
            self,
            page: int,
            count: int,
            to_time: Optional[str] = None,
            from_time: Optional[str] = None,
    ) -> tuple:
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

        # Make the HTTP request.
        raw_response = self._http_request(
            method="POST",
            url_suffix="",
            data=self.generate_workday_account_signons_body(page, count, to_time, from_time),
            resp_type="text",
            timeout=120
        )

        raw_json_response, account_signon_data = convert_to_json(raw_response)

        total_pages = int(demisto.get(
            obj=raw_json_response, field="Envelope.Body.Get_Workday_Account_Signons_Response.Response_Results",
            defaultParam={}
        ).get("Total_Pages", "1"))

        return account_signon_data, total_pages

    def test_connectivity(self) -> str:
        """
        Tests API connectivity and authentication.

        :return: 'ok' if test passed, else exception.
        :rtype: ``str``
        """
        seconds_ago = 5
        from_time = get_from_time(seconds_ago)
        to_time = datetime.now(tz=timezone.utc).strftime(REQUEST_DATE_FORMAT)

        payload = self.generate_test_payload(from_time=from_time, to_time=to_time)

        self._http_request(
            method="POST", url_suffix="", data=payload, resp_type="text", timeout=120
        )

        return "ok"


""" HELPER FUNCTIONS """


def convert_to_json(response: str | dict) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Convert an XML response to a JSON object and extract the 'Workday_Account_Signons' data.

    :param response: XML response to be converted
    :return: Tuple containing the full converted response and the extracted 'Workday_Account_Signons' data.
    :raises ValueError: If the expected data cannot be found in the response.
    """
    if type(response) is dict:
        raw_json_response = response
    else:
        try:
            raw_json_response = json.loads(xml2json(response))
        except Exception as e:
            raise ValueError(f"Error parsing XML to JSON: {e}")

    # Get the 'Get_Workday_Account_Signons_Response' dictionary safely
    response_data = demisto.get(raw_json_response, "Envelope.Body.Get_Workday_Account_Signons_Response")

    if not response_data:
        response_data = raw_json_response.get(
            "Get_Workday_Account_Signons_Response", {}
        )

    account_signon_data = response_data.get("Response_Data", {})

    # Ensure 'Workday_Account_Signon' is a list
    workday_account_signons = account_signon_data.get("Workday_Account_Signon")
    if isinstance(workday_account_signons, dict):
        account_signon_data["Workday_Account_Signon"] = [workday_account_signons]

    return raw_json_response, account_signon_data


def process_and_filter_events(events: list, from_time: str, previous_run_pseudo_ids: set) -> tuple:
    non_duplicates = []
    duplicates = []
    pseudo_ids_for_next_iteration = set()

    try:
        from_datetime = datetime.strptime(from_time, EVENT_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        # On first run, the from_time is in UTC since that is what's sent in the request, this covers this scenario
        from_datetime = datetime.strptime(from_time, REQUEST_DATE_FORMAT).replace(tzinfo=timezone.utc)
    most_recent_event_time = datetime.min.replace(tzinfo=timezone.utc)

    for event in events:
        event_datetime = datetime.strptime(event["Signon_DateTime"], EVENT_DATE_FORMAT).replace(tzinfo=timezone.utc)

        # Add '_time' key to each event
        event["_time"] = event.get("Signon_DateTime")

        # Update the most recent event time
        if event_datetime > most_recent_event_time:
            most_recent_event_time = event_datetime

        # Check for duplicates within ±1 second of from_time
        if abs((event_datetime - from_datetime).total_seconds()) <= 1:
            event_pseudo_id = generate_pseudo_id(event)
            if event_pseudo_id not in previous_run_pseudo_ids:
                non_duplicates.append(event)
            else:
                duplicates.append(event_pseudo_id)
        else:
            non_duplicates.append(event)
    # Generate pseudo IDs for events within the last second of the most recent event
    last_second_start_time = most_recent_event_time - timedelta(seconds=TIMEDELTA)

    if duplicates:
        demisto.debug(f"Found {len(duplicates)} duplicate events: {duplicates}")

    for event in non_duplicates:
        event_datetime = datetime.strptime(event["_time"], EVENT_DATE_FORMAT).replace(tzinfo=timezone.utc)

        if event_datetime >= last_second_start_time:
            event_pseudo_id = generate_pseudo_id(event)
            pseudo_ids_for_next_iteration.add(event_pseudo_id)

    return non_duplicates, pseudo_ids_for_next_iteration


def fetch_sign_on_logs(
    client: Client, limit_to_fetch: int, from_date: str, to_date: str
):
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
    total_fetched = 0  # Keep track of the total number of events fetched
    res, total_pages = client.retrieve_events(
        from_time=from_date, to_time=to_date, page=1, count=999
    )
    sign_on_events_from_api = res.get("Workday_Account_Signon", [])
    sign_on_logs.extend(sign_on_events_from_api)
    demisto.debug(f"Request indicates a total of {total_pages} pages to paginate.")
    pages_remaining = total_pages - 1

    while (page <= total_pages and pages_remaining != 0) and res:
        page += 1
        # Calculate the remaining number of events to fetch
        remaining_to_fetch = limit_to_fetch - total_fetched
        if remaining_to_fetch <= 0:
            break
        res, _ = client.retrieve_events(
            from_time=from_date, to_time=to_date, page=page, count=limit_to_fetch
        )
        pages_remaining -= 1
        fetched_count = len(sign_on_events_from_api)
        total_fetched += fetched_count

        demisto.debug(f"Fetched {len(sign_on_events_from_api)} sign on logs.")
        sign_on_logs.extend(sign_on_events_from_api)
        demisto.debug(f"{pages_remaining} pages left to fetch.")
    return sign_on_logs


""" COMMAND FUNCTIONS """


def get_sign_on_events_command(
    client: Client, from_date: str, to_date: str, limit: int
) -> tuple[list, CommandResults]:
    """

    Args:
        limit: The maximum number of logs to return.
        to_date: date to fetch events from.
        from_date: date to fetch events to.
        client: Client object.

    Returns:
        Sign on logs from Workday.
    """

    sign_on_events = fetch_sign_on_logs(
        client=client, limit_to_fetch=limit, from_date=from_date, to_date=to_date
    )

    [_event.update({"_time": _event.get("Signon_DateTime")}) for _event in sign_on_events]

    demisto.info(
        f"Got a total of {len(sign_on_events)} events between the time {from_date} to {to_date}"
    )
    readable_output = tableToMarkdown(
        "Sign On Events List:",
        sign_on_events,
        removeNull=True,
        headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)),
    )

    return sign_on_events, CommandResults(readable_output=readable_output)


def fetch_sign_on_events_command(client: Client, max_fetch: int, last_run: dict):
    """
    Fetches sign on logs from Workday.
    Args:
        client: Client object.
        max_fetch: max logs to fetch set by customer.
        last_run: last run object.

    Returns:
        Sign on logs from Workday.

    """
    current_time = datetime.utcnow()
    if "last_fetch_time" not in last_run:
        first_fetch_time = current_time - timedelta(minutes=1)
        first_fetch_str = first_fetch_time.strftime(REQUEST_DATE_FORMAT)
        from_date = last_run.get("last_fetch_time", first_fetch_str)
    else:
        from_date = last_run.get("last_fetch_time")
    # Checksums in this context is used as an ID since none is provided directly from Workday.
    # This is to prevent duplicates.
    previous_run_pseudo_ids = last_run.get("previous_run_pseudo_ids", {})
    to_date = datetime.now(tz=timezone.utc).strftime(REQUEST_DATE_FORMAT)
    demisto.debug(f"Getting Sign On Events {from_date=}, {to_date=}.")
    sign_on_events = fetch_sign_on_logs(
        client=client, limit_to_fetch=max_fetch, from_date=from_date, to_date=to_date
    )

    if sign_on_events:
        demisto.debug(f"Got {len(sign_on_events)} sign_on_events. Begin processing.")
        non_duplicates, pseudo_ids_for_next_iteration = process_and_filter_events(
            events=sign_on_events,
            previous_run_pseudo_ids=previous_run_pseudo_ids,
            from_time=from_date
        )

        demisto.debug(f"Done processing {len(non_duplicates)} sign_on_events.")
        last_event = non_duplicates[-1]
        last_run = {
            "last_fetch_time": last_event.get('Signon_DateTime'),
            "previous_run_pseudo_ids": pseudo_ids_for_next_iteration,
        }
        demisto.debug(f"Saving last run as {last_run}")
    else:
        # Handle the case where no events were retrieved
        last_run["last_fetch_time"] = current_time
        non_duplicates = []

    return non_duplicates, last_run


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


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    tenant_name = params.get("tenant_name")
    base_url = params.get("base_url")

    if not base_url.startswith("https://"):
        raise ValueError("Invalid base URL. Should begin with https://")
    url = f"{base_url}/ccx/service/{tenant_name}/Identity_Management/{API_VERSION}"

    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    max_fetch = arg_to_number(params.get("max_fetch")) or 10000

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=url,
            tenant_name=tenant_name,
            username=username,
            password=password,
            verify_certificate=verify_certificate,
            proxy=proxy,
        )

        if command == "test-module":
            return_results(module_of_testing(client))
        elif command == "workday-get-sign-on-events":
            if args.get("relative_from_date", None):
                from_time = arg_to_datetime(  # type:ignore
                    arg=args.get('relative_from_date'),
                    arg_name='Relative datetime',
                    required=False
                ).strftime(REQUEST_DATE_FORMAT)
                to_time = datetime.utcnow().strftime(REQUEST_DATE_FORMAT)
            else:
                from_time = args.get("from_date")
                to_time = args.get("to_date")

            sign_on_events, results = get_sign_on_events_command(
                client=client,
                from_date=from_time,
                to_date=to_time,
                limit=arg_to_number(args.get("limit", "100"), required=True),  # type: ignore
            )
            return_results(results)
            if argToBoolean(args.get("should_push_events", "true")):
                send_events_to_xsiam(sign_on_events, vendor=VENDOR, product=PRODUCT)
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Starting new fetch with last_run as {last_run}")
            sign_on_events, new_last_run = fetch_sign_on_events_command(
                client=client, max_fetch=max_fetch, last_run=last_run
            )
            demisto.debug(f"Done fetching events, sending to XSIAM. - {sign_on_events}")
            send_events_to_xsiam(sign_on_events, vendor=VENDOR, product=PRODUCT)
            if new_last_run:
                # saves next_run for the time fetch-events is invoked
                demisto.info(f"Setting new last_run to {new_last_run}")
                demisto.setLastRun(new_last_run)
        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
