import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any, Tuple

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC
DEFAULT_MAX_LIMIT = 1000
OAT_DETECTION_LOGS_TIME = 'oat_detection_logs_time'
WORKBENCH_LOGS_TIME = 'workbench_logs_time'
SEARCH_DETECTION_LOGS_TIME = 'search_detection_logs_time'
''' CLIENT CLASS '''


class Client(BaseClient):

    API_VERSION = 'v3.0'

    def __init__(self, base_url: str, api_key: str, proxy: bool, verify: bool):
        self.base_url = base_url
        self.api_key = api_key

        super().__init__(base_url=base_url, proxy=proxy, verify=verify)

    def http_request(
        self,
        url_suffix: str | None = None,
        method: str = 'GET',
        params: Dict | None = None,
        headers: Dict | None = None,
        next_link: str | None = None
    ) -> Any:
        """
        Implements a generic http request to Trend Micro Vision One api.

        Args:
            url_suffix (str): The URL suffix for the api endpoint.
            method (str): the method of the api endpoint.
            params (dict): query parameters for the api request.
            headers (dict): any custom headers for the api request.
            next_link (str): the next link for the api request (used mainly for pagination)
        """
        request_headers = headers or {
            "Authorization": f"Bearer {self.api_key}"
        }

        url = next_link or f"{self.base_url}{url_suffix}"
        demisto.debug(f'Sending the http request with {url=}, {params=}')

        return self._http_request(
                method=method,
                full_url=url,
                params=params,
                headers=request_headers,
            )

    def get_events(
        self,
        url_suffix: str,
        method: str = 'GET',
        params: Dict | None = None,
        headers: Dict | None = None,
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[Dict]:
        """
        Implements a generic method with pagination to retrieve logs from trend micro vision one.

        Args:
            url_suffix (str): the URL suffix for the api endpoint.
            method (str): the method of the api endpoint.
            params (dict): query parameters for the api request.
            headers (dict): any custom headers for the api request.
            limit (str): the maximum number of events to retrieve.

        Returns:
            List[Dict]: a list of the requested logs.
        """
        events = []

        response = self.http_request(url_suffix=url_suffix, method=method, params=params, headers=headers)
        current_items = response.get('items') or []
        demisto.debug(f'Received {current_items=} with {url_suffix=}')
        events.extend(current_items)

        while (next_link := response.get('nextLink')) and len(events) < limit:
            response = self.http_request(method=method, params=params, headers=headers, next_link=next_link)
            current_items = response.get('items') or []
            demisto.debug(f'Received {current_items=} with {next_link=}')
            events.extend(current_items)

        return events[:limit]

    def get_workbench_logs(
        self,
        start_datetime: str,
        end_datetime: str | None = None,
        order_by: str | None = None,
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[Dict]:
        """
        Get the workbench logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Observed-Attack-Techniques/paths/~1v3.0~1oat~1detections/get

        Args:
            start_datetime (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the start
                                  of the data retrieval time range.
            end_datetime (str): Datetime in ISO 8601 format (yyyy-MM-ddThh:mm:ssZ in UTC) that indicates the end
                                of the data retrieval time range.
            order_by (str): Parameter to be used for sorting records. Records are returned in descending
                            order by default.
            limit (int): the maximum number of workbench events to retrieve.

        Returns:
            List[Dict]: The workbench events that were found.
        """
        # will retrieve all the events that are more or equal to start_datetime, does not support miliseconds
        params = {'startDateTime': start_datetime}

        if end_datetime:
            params['endDateTime'] = end_datetime
        if order_by:
            params['orderBy'] = order_by

        return self.get_events(
            url_suffix=f'/{self.API_VERSION}/workbench/alerts',
            params=params,
            limit=limit
        )

    def get_observed_attack_techniques_logs(
        self,
        detected_start_datetime: str,
        detected_end_datetime: str,
        top: int = DEFAULT_MAX_LIMIT,
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[Dict]:
        """
        Get the observed attack techniques logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Observed-Attack-Techniques/paths/~1v3.0~1oat~1detections/get

        Note: The data retrieval time range cannot be greater than 365 days.

        Args:
            detected_start_datetime (str): Timestamp in ISO 8601 format that indicates the start of the event detection
                                           data retrieval time range. If no value is specified, detectedStartDateTime
                                           defaults to 1 hour before the time the request is made.
            detected_end_datetime (str): Timestamp in ISO 8601 format that indicates the end of the event
                                         detection data retrieval time range. If no value is specified,
                                         detectedEndDateTime defaults to the time the request is made.
            top (int): Number of records displayed on a single page.
            limit (int): the maximum number of observed attack techniques logs to retrieve.

        Returns:
            List[Dict]: The observe attack techniques that were found.
        """
        # will retrieve all the events that are more or equal to detected_start_datetime, does not support miliseconds
        # The data retrieval time range cannot be greater than 365 days.
        return self.get_events(
            url_suffix=f'/{self.API_VERSION}/oat/detections',
            params={
                'detectedStartDateTime': detected_start_datetime,
                'detectedEndDateTime': detected_end_datetime,
                'top': top
            },
            limit=limit
        )

    def get_search_detection_logs(
        self,
        start_datetime: str,
        end_datetime: str | None = None,
        top: int = DEFAULT_MAX_LIMIT,
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[Dict]:
        """
        Get the search detection logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Search/paths/~1v3.0~1search~1endpointActivities/get

        Args:
            start_datetime (str): Timestamp in ISO 8601 format that indicates the start of the data retrieval range.
            end_datetime (str): Timestamp in ISO 8601 format that indicates the end of the data retrieval time range.
                                If no value is specified, 'endDateTime' defaults to the time the request is made.
            top (int): Number of records displayed on a page.
            limit (int): the maximum number of search detection logs to retrieve.

        Returns:
            List[Dict]: The search detection logs that were found.
        """
        # will retrieve all the events that are more or equal to detected_start_datetime, does not support miliseconds
        params = {'startDateTime': start_datetime, 'top': top}

        if end_datetime:
            params['endDateTime'] = end_datetime

        return self.get_events(
            url_suffix=f'/{self.API_VERSION}/search/detections',
            params=params,
            limit=limit
        )

    def get_audit_logs(
        self,
        start_datetime: str,
        end_datetime: str | None = None,
        order_by: str | None = None,
        top: int = 200,
        limit: int = DEFAULT_MAX_LIMIT
    ) -> List[Dict]:
        """
        Get the audit logs.

        docs:
        https://automation.trendmicro.com/xdr/api-v3#tag/Audit-Logs

        Args:
            start_datetime (str): Timestamp in ISO 8601 format that indicates the start of the data retrieval range.
            end_datetime (str): Timestamp in ISO 8601 format that indicates the end of the data retrieval time range.
                                If no value is specified, 'endDateTime' defaults to the time the request is made.
            order_by (str): Parameter that allows you to sort the retrieved search results in ascending or
                            descending order. If no order is specified, the results are shown in ascending order.
            top (int): Number of records displayed on a page.
            limit (int): the maximum number of audit logs to retrieve.

        Returns:
            List[Dict]: The audit logs that were found.
        """
        # will retrieve all the events that are only more than detected_start_datetime, does not support miliseconds
        params = {'startDateTime': start_datetime, 'top': top}

        if end_datetime:
            params['endDateTime'] = end_datetime

        if order_by:
            params['orderBy'] = order_by

        return self.get_events(
            url_suffix=f'/{self.API_VERSION}/audit/logs',
            params=params,
            limit=limit
        )


''' HELPER FUNCTIONS '''


def get_datetime_range(
    last_run: Dict,
    first_fetch: str,
    log_type_time: str,
    date_format: str = DATE_FORMAT
) -> Tuple[str, str]:
    """
    Get a datetime range for any log type.

    Args:
        last_run (dict): The last run object.
        first_fetch (str): First fetch time.
        log_type_time (str): the name of the field in the last run for a specific log type.
        date_format (str): The date format.

    Returns:
        Tuple[str, str]: start time and end time
    """
    last_run_time = last_run and log_type_time in last_run and last_run[log_type_time]
    now = get_current_time()

    if last_run_time:
        last_run_time = dateparser.parse(last_run_time, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})
    else:
        last_run_time = dateparser.parse(first_fetch, settings={'TIMEZONE': 'UTC', 'RETURN_AS_TIMEZONE_AWARE': True})

    if log_type_time == OAT_DETECTION_LOGS_TIME:
        # Note: The data retrieval time range cannot be greater than 365 days for oat logs,
        # it cannot exceed datetime.now, otherwise the api will return 400
        one_year_from_last_run_time = last_run_time + timedelta(days=365)
        if one_year_from_last_run_time > now:
            end_time_datetime = now
        else:
            end_time_datetime = one_year_from_last_run_time
    else:
        end_time_datetime = now

    start_time, end_time = last_run_time.strftime(date_format), end_time_datetime.strftime(date_format)
    demisto.debug(f'{start_time=} and {end_time=} for {log_type_time=}')
    return start_time, end_time


def get_latest_log_created_time(
    logs: List[Dict],
    created_time_field: str,
    log_type: str,
    date_format: str = DATE_FORMAT,
    increase_latest_log: bool = False
) -> str:
    """
    Get the latest occurred time of a log from a list of logs.

    Args:
        logs (list[dict]): a list of logs.
        created_time_field (str): The created time field for the logs.
        log_type (str): the log type for debugging purposes.
        date_format (str): the date format.
        increase_latest_log (bool): Whether to increase the latest time of the log by a single second.

    Returns:
        str: latest occurred time of a log, empty string in case there aren't any logs.
    """
    if logs:
        latest_log_time_datetime = datetime.strptime(logs[0][created_time_field], date_format)

        for log in logs:
            log_time = datetime.strptime(log[created_time_field], date_format)
            if log_time > latest_log_time_datetime:
                latest_log_time_datetime = log_time

        if increase_latest_log:
            latest_log_time_datetime = latest_log_time_datetime + timedelta(seconds=1)

        latest_log_time = latest_log_time_datetime.strftime(date_format)
        demisto.debug(f'{latest_log_time=} for {log_type=}')
        return latest_log_time_datetime.strftime(date_format)

    demisto.debug(f'No new logs for {log_type=}')
    return ''


def get_workbench_logs(
    client: Client,
    last_run: Dict,
    first_fetch: str,
    date_format: str = DATE_FORMAT,
    limit: int = DEFAULT_MAX_LIMIT
) -> Tuple[List[Dict], str]:
    """
    Get the workbench logs.

    Args:
        client (Client): the client object
        last_run (dict): The last run object
        first_fetch (str): the first fetch time
        date_format (str): the date format.
        limit (int): the maximum number of workbench logs to return.

    Returns:
        Tuple[List[Dict], str]: workbench logs & latest time of the workbench log that was created.
    """
    start_time, end_time = get_datetime_range(
        last_run=last_run, first_fetch=first_fetch, log_type_time=WORKBENCH_LOGS_TIME, date_format=date_format
    )
    workbench_logs = client.get_workbench_logs(start_datetime=start_time, limit=limit)
    latest_workbench_log_time = get_latest_log_created_time(
        logs=workbench_logs,
        created_time_field='createdDateTime',
        log_type='workbench',
        date_format=date_format,
        increase_latest_log=True
    )

    return workbench_logs, latest_workbench_log_time or end_time


def get_observed_attack_techniques_logs(
    client: Client,
    last_run: Dict,
    first_fetch: str,
    date_format: str = DATE_FORMAT,
    limit: int = DEFAULT_MAX_LIMIT
) -> Tuple[List[Dict], str]:
    """
    Get the observed attack techniques logs.

    Args:
        client (Client): the client object
        last_run (dict): The last run object
        first_fetch (str): the first fetch time
        date_format (str): the date format.
        limit (int): the maximum number of observed attack techniques logs to return.

    Returns:
        Tuple[List[Dict], str]: observed attack techniques logs & latest time of the technique log that was created.
    """
    start_time, end_time = get_datetime_range(
        last_run=last_run, first_fetch=first_fetch, log_type_time=OAT_DETECTION_LOGS_TIME, date_format=date_format
    )
    observed_attack_techniques_logs = client.get_observed_attack_techniques_logs(
        detected_start_datetime=start_time, detected_end_datetime=end_time, top=limit, limit=limit
    )
    latest_observed_attack_technique_log_time = get_latest_log_created_time(
        logs=observed_attack_techniques_logs,
        created_time_field='detectedDateTime',
        log_type='observed attack techniques',
        date_format=date_format,
        increase_latest_log=True
    )

    return observed_attack_techniques_logs, latest_observed_attack_technique_log_time or end_time


def get_search_detection_logs(
    client: Client,
    last_run: Dict,
    first_fetch: str,
    date_format: str = DATE_FORMAT,
    limit: int = DEFAULT_MAX_LIMIT
):
    """
    Get the search detection logs.

    Args:
        client (Client): the client object
        last_run (dict): The last run object
        first_fetch (str): the first fetch time
        date_format (str): the date format.
        limit (int): the maximum number of search detection logs to return.

    Returns:
        Tuple[List[Dict], str]: search detection logs & latest time of the search detection log that was created.
    """
    start_time, end_time = get_datetime_range(
        last_run=last_run, first_fetch=first_fetch, log_type_time=SEARCH_DETECTION_LOGS_TIME, date_format=date_format
    )
    search_detection_logs = client.get_search_detection_logs(
        start_datetime=start_time, end_datetime=end_time, top=limit, limit=limit
    )
    for log in search_detection_logs:
        if event_time := log.get('eventTime'):
            log['eventTime'] = timestamp_to_datestring(timestamp=event_time, date_format=date_format, is_utc=True)

    latest_search_detection_log_time = get_latest_log_created_time(
        logs=search_detection_logs,
        created_time_field='eventTime',
        log_type='search detection',
        date_format=date_format,
        increase_latest_log=True
    )

    return search_detection_logs, latest_search_detection_log_time or end_time

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
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


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

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        # TODO: REMOVE the following dummy command case:
        elif demisto.command() == 'baseintegration-dummy':
            return_results(baseintegration_dummy_command(client, demisto.args()))
        # TODO: ADD command cases for the commands you will implement

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
