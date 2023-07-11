import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import time
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union

import dateparser
import urllib3
from requests import Response

# Disable insecure warnings
urllib3.disable_warnings()


''' Global Variables '''
INTEGRATION_NAME = 'ThousandEyes'
INTEGRATION_COMMAND_NAME = 'thousandeyes'
INTEGRATION_CONTEXT_NAME = 'ThousandEyes'
API_VERSION_ENDPOINT = '/v6'
THOUSAND_EYES_DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
MAX_INCIDENTS_TO_FETCH = 200


class Client(BaseClient):
    def handle_rate_lmiit_and_make_request(
        self,
        method: str,
        url_suffix: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        timeout: float = 10,
        resp_type: str = "response",
        test_module: bool = False
    ) -> Union[Response, Dict]:
        """
            Handles the reached rate limit, performs API request to the specified endpoint and reutrns the full Response object

        Args:
            method (str) required: The HTTP method, for example, GET, POST, and so on.
            url_suffix (str) required: The API endpoint.
            params (dict): URL parameters to specify the query. Default is None.
            data (dict): The data to send in a 'POST' request. Default is None.
            json_data (dict): The dictionary to send in a 'POST' request. Default is None.
            timeout: (float): Time (in seconds) for the client to wait to establish a connection before a timeout occurs.
                                Default is 10.
            resp_type (str): Determines which data format to return from the HTTP request. Other options are 'text',
                             'content', 'xml' or 'response'. Use 'response' to return the full response object.
                             Default is response.
            test_module (bool): Boolean flag to check if function is called from test-module or not

        Returns:
            Either a Response Object or Dictionary, depending on the resp_type value
        """

        if test_module:
            response = self._http_request(
                method=method,
                url_suffix=url_suffix,
                resp_type=resp_type
            )

            return response

        try:
            while True:
                response = self._http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    data=data,
                    json_data=json_data,
                    timeout=timeout,
                    resp_type=resp_type,
                )

                response_headers = response.headers
                org_rate_limit_remaining = response_headers.get('x-organization-rate-limit-remaining')
                org_rate_limit_reset = response_headers.get('x-organization-rate-limit-reset')

                if response.status_code == 200 and int(org_rate_limit_remaining) > 0:
                    return response

                elif org_rate_limit_remaining == 0:
                    current_timestamp = int(time.time())
                    time.sleep(org_rate_limit_reset - current_timestamp)
                    continue

                else:
                    status_code = response.status_code
                    msg = response.text
                    err_response = {
                        "Status Code": status_code,
                        "Err Message": msg
                    }
                    return err_response

        except Exception as e:
            raise Exception(e)


def test_module_command(client: Client, *_) -> str:
    """
        Checks to see if the connection is working as expected or not

    Args:
        client (Client Object): Client object with request.

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """

    endpoint: str = '/tests.json'
    method: str = 'GET'

    response = client.handle_rate_lmiit_and_make_request(
        method=method,
        url_suffix=endpoint,
        test_module=True
    )

    if response.status_code == 200:  # type: ignore
        return "ok"

    raise DemistoException(f'Test module failed, {response.text}')  # type: ignore


''' Helper Functions '''


def fetch_all_aids(client: Client) -> Union[List, Dict]:
    """
        Fetches all AIDs configured in ThousandEyes

    Args:
        client (Client Object): Client object with request.

    Returns:
        List of Group AIDs
    """

    endpoint = '/account-groups.json'
    method = 'GET'
    # Hits the API in loop case the rate limit is reached.
    response = client.handle_rate_lmiit_and_make_request(
        method,
        endpoint
    )

    # If Response is an error, return the error
    if isinstance(response, dict):
        return response

    group_list = response.json().get("accountGroups")
    group_aid_list = [sub["aid"] for sub in group_list]
    return group_aid_list


def parse_agent_response_helper(raw_response: Dict) -> Tuple[List, List]:
    """
        Prepare the context and human readable data for Agents
    Args:
        raw_response (dict): Raw API response

    Returns:
        Tuple of Context Data and Human Readable Data.
    """

    entry_context = []
    human_readable = []
    if raw_response:
        agents_list: Union[List, None] = raw_response.get("agents")

        if agents_list:
            for items in agents_list:
                item = assign_params(
                    **{
                        "Agent ID": items.get('agentId'),
                        "Agent Name": items.get('agentName'),
                        "Agent Type": items.get('agentType'),
                        "Country ID": items.get('countryId'),
                        "Enabled": items.get('enabled'),
                        "Keep Browser Cache": items.get('keepBrowserCache'),
                        "Verify SSL Certificates": items.get('verifySslCertificates'),
                        "Ip Adresses": items.get('ipAdresses'),
                        "Last Seen": items.get('lastSeen'),
                        "Location": items.get('location'),
                        "Network": items.get('network'),
                        "Prefix": items.get('prefix'),
                        "Public IP Addresses": items.get('publicIpAddresses'),
                        "Target For Tests": items.get('targetForTests'),
                        "Agent State": items.get('agentState'),
                        "Utilization": items.get('utilization'),
                        "IPv6 Policy": items.get('ipv6Policy'),
                        "Hostname": items.get('hostname'),
                        "Created Date": items.get('createdDate'),
                        "Error Details": items.get('errorDetails')
                    }
                )

                human_readable.append(
                    item
                )

                entry_context.append(
                    item
                )
    return (entry_context, human_readable)


def get_alerts_helper(alert_info: Dict, aid: Optional[int], human_readable: bool) -> Tuple[Dict, Dict]:
    """
        Prepare the context and human readable data for Alerts
    Args:
        alert_info (Dict): Dict information of an Active Alert
        aid (int (Optional)): AID to prepare data for
        human_readable (boolean): Flag to prepare human readable data or not

    Returns:
        Tuple of Context Data and Human Readable Data.
    """
    entry_context = {}
    human_readable_data = {}
    if alert_info:
        prepared_alert_info = {
            "Active": alert_info.get('active'),
            "Agents": alert_info.get('agents'),
            "AID": aid,
            "AlertID": alert_info.get('alertId'),
            "DateStart": alert_info.get('dateStart'),
            "ApiLinks": alert_info.get('apiLinks'),
            "PermaLink": alert_info.get('permalink'),
            "RuleExpression": alert_info.get('ruleExpression'),
            "RuleID": alert_info.get('ruleId'),
            "RuleName": alert_info.get('ruleName'),
            "TestID": alert_info.get('testId'),
            "TestName": alert_info.get('testName'),
            "ViolationCount": alert_info.get('violationCount'),
            "Type": alert_info.get('type'),
            "Severity": alert_info.get('severity')
        }
        if human_readable:
            human_readable_data = assign_params(
                **prepared_alert_info
            )

        entry_context = assign_params(
            **prepared_alert_info
        )

    return (entry_context, human_readable_data)


def parse_alerts_response(
    client: Client,
    method: str,
    response: Union[Response, Dict],
    aid: Optional[int],
    human_readable: bool = False
) -> Tuple[bool, List, List, List]:
    """
        Parses the fetched alerts and looks for information in additional pages (if any)
    Args:
        client (Client): Client object with the request.
        method (str): HTTP method to use
        response (Response, Dict): Response Object/Error Dict returned from first call for fetching alert of respective AID
        aid (int (Optional)): Group AID of which we are fetching the active alerts
        human_readable (bool): Flag to switch the parsing of human_readable data ON/OFF

    Returns:
        Tuple of (alerts_found (bool), raw_response (List[Dict]), entry_context (List[Dict]), human_readable_data (List[Dict]))
    """

    raw_response: List[Dict] = []
    entry_context: List[Dict] = []
    human_readable_data: List[Dict] = []

    # Handle parsing results from multiple pages if any
    if isinstance(response, requests.models.Response):
        result = response.json()
        page_info = result.get("pages")
        next_url = page_info.get("next")
        alerts_list = result.get("alert")
        alerts_found = True if alerts_list else False

        while True:
            if alerts_found:

                for alert in alerts_list:
                    raw_response.append(alert)
                    entry_context_temp, human_readable_data_temp = get_alerts_helper(
                        alert,
                        aid,
                        human_readable
                    )
                    entry_context.append(entry_context_temp)
                    human_readable_data.append(human_readable_data_temp)

            if not next_url:
                break

            response = client.handle_rate_lmiit_and_make_request(
                method,
                next_url
            )

            # Raise exception if error is returned
            if isinstance(response, dict):
                raise Exception(response)

            # Untested parsing
            # Need to see actual API response
            # Made based on the assumption that response returned on next page is same as previous
            result = response.json()
            page_info = result.get("pages")
            next_url = page_info.get("next")
            alerts_list = result.get("alert")
            alerts_found = True if alerts_list else False

    alerts_found = True if entry_context else False

    return (alerts_found, raw_response, entry_context, human_readable_data)


def parse_agent_response(response: Response):
    """
        Set the fetched agent details to context and parse the results to warroom

    Args:
        response (Response): Response object from the API call

    Returns:
        CommandResults object containing required details to send to warroom

    """

    if response:
        result = response.json()

        if result.get("agents"):
            title: str = f'{INTEGRATION_NAME} - Agents Output'
            entry_context, human_readable = parse_agent_response_helper(result)

            if entry_context:
                results = CommandResults(
                    readable_output=tableToMarkdown(title, t=human_readable),
                    outputs_prefix='ThousandEyes.Agents',
                    outputs_key_field='AgentId',
                    outputs=entry_context,
                    raw_response=result
                )
                return results

            else:
                message = f'{INTEGRATION_NAME} - No Agent information found'
                results = CommandResults(
                    readable_output=message
                )
                return results

    err_message = f'{INTEGRATION_NAME} - Could not find any results for the given query'
    results = CommandResults(
        readable_output=err_message
    )
    return results


def filter_out_alerts_above_minimum_severity(raw_response_list: List, minimum_severity: str) -> List:
    """
        Filters out alerts which are equal and below the provided minimum severity value

    Args:
        raw_response_list (List): List of Alert objects from the API response
        minimum_severity (str): Minimum severity value above which alerts need to be returned

    Returns:
        List of events/raw responses (meeting the filter criteria) to create
    """

    severity_to_rank_mapping = {
        "INFO": 1,
        "MINOR": 2,
        "MAJOR": 3,
        "CRITICAL": 4
    }

    rank_to_severity_mapping = {
        1: "INFO",
        2: "MINOR",
        3: "MAJOR",
        4: "CRITICAL"
    }

    minimum_severity_ranking: Optional[int] = severity_to_rank_mapping.get(minimum_severity)

    # Can return None in case of Severity classes are modified by Thousand Eyes API
    if not minimum_severity_ranking:
        raise KeyError("Severity classes are modified by ThousandEyes API, "
                       "please modify the filter_out_alerts_above_minimum_severity() function accordingly")

    whitelisted_severity_ranks: List = [i for i in rank_to_severity_mapping.keys() if i >= minimum_severity_ranking]

    events_to_create = []

    for raw_response in raw_response_list:
        severity_in_response: str = raw_response.get("severity")

        severity_ranking: Optional[int] = severity_to_rank_mapping.get(severity_in_response)

        if severity_ranking in whitelisted_severity_ranks:
            events_to_create.append(raw_response)

    return events_to_create


''' Command Functions '''


def fetch_incidents_command(
    client: Client,
    max_results: int,
    last_run: Dict,
    first_fetch_time: str,
    minimum_severity: str
) -> Tuple[Dict, List]:
    """
        Fetches the events and returns the incidents list.

    Args:
        client (Client): Client object with the request.
        max_results (int): maximum number of events to fetch.
        last_run (Dict[str, str]): The latest incident creation time.
        first_fetch_time (Optional[str]): If last_run is None then fetch all incidents since first_fetch_time
        minimum_severity (str): Flag to filter out data based on severity of the alert

    Returns:
        Tuple of next run time dict and the list of incident objects
    """

    # Handling First fetch time
    if isinstance(last_run, dict) and last_run.get("start_time"):
        # Should return datetime str representation in %Y-%m-%dT%H:%M:%S format
        last_fetch = last_run.get("start_time")

    else:
        last_fetch = dateparser.parse(first_fetch_time).strftime(THOUSAND_EYES_DATE_TIME_FORMAT)  # type: ignore[union-attr]

    incidents_to_create: List = []
    incident_created_time: str = ""
    events_to_create: List = get_alerts_command(client=client, from_date=last_fetch, fetch_for_incident=True)
    events_to_create: List = filter_out_alerts_above_minimum_severity(events_to_create, minimum_severity)

    for event in events_to_create:

        incident_created_time = datetime.utcnow().strftime(THOUSAND_EYES_DATE_TIME_FORMAT + "Z")
        incident = {
            "name": f"ThousandEyes Incident - {event.get('ruleName')} - {event.get('dateStart')}",
            "occured": incident_created_time,
            "rawJSON": json.dumps(event)
        }

        incidents_to_create.append(incident)

    # Update last run and remove the last 'Z' from datetime string
    last_fetch = incident_created_time[:-1]

    next_run = {"start_time": last_fetch}
    return next_run, incidents_to_create


def get_alerts_command(
    client: Client,
    aid: Optional[int] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    fetch_for_incident: bool = False
):
    """
        Fetches live alerts

    Args:
        client (Client Object): Client object with request.
        aid (int) (Optional): Fetch Active Alerts for a specific AID.
        from_date (str) (Optional): Explicit start date to fetch Alerts from.
        to_date (str) (Optional): Explicit end date to fetch Alerts to.
        fetch_for_incident (Boolean) (Default - False): Boolean flag to specify if the alerts are fetched for incidents or not

    Returns:
        Results of CommandResults type or List of raw_response (if called from fetch_incidents_command() function)

    """

    endpoint = '/alerts.json'
    method = 'GET'
    raw_response_list: List[Dict] = []
    entry_context: List[Dict] = []
    human_readable_data: List[Dict] = []

    params: Dict = {}
    if aid and not from_date and not to_date:
        params = {
            "aid": aid
        }

    elif aid and from_date and not to_date:
        params = {
            "aid": aid,
            "from": from_date
        }

    elif aid and from_date and to_date:
        params = {
            "aid": aid,
            "from": from_date,
            "to": to_date
        }

    if fetch_for_incident:
        params = {
            "from": from_date
        }
        group_aid_list = fetch_all_aids(client)

        if isinstance(group_aid_list, dict):
            err_msg = group_aid_list
            raise Exception(err_msg)

        for group_aid in group_aid_list:
            response = client.handle_rate_lmiit_and_make_request(
                method,
                endpoint,
                params=params
            )

            alerts_found, raw_response_temp_list, entry_context_temp, human_readable_data_temp = parse_alerts_response(
                client=client,
                method=method,
                response=response,
                aid=group_aid,
                human_readable=False
            )

            for raw_response_temp in raw_response_temp_list:
                raw_response_list.append(raw_response_temp)

        return raw_response_list

    # Fetch results for non-incident calls made (From Warroom)
    response = client.handle_rate_lmiit_and_make_request(
        method,
        endpoint,
        params=params
    )

    alerts_found, raw_response_temp_list, entry_context_temp, human_readable_data_temp = parse_alerts_response(
        client=client,
        method=method,
        response=response,
        aid=aid,
        human_readable=True
    )

    raw_response_list = raw_response_temp_list

    entry_context = entry_context_temp

    human_readable_data = human_readable_data_temp

    if alerts_found:
        if aid:
            title = f'{INTEGRATION_NAME} - Active Alerts found for AID: {aid}'

        else:
            title = f'{INTEGRATION_NAME} - Active Alerts found for AID: Default'

    else:
        if aid:
            title = f'{INTEGRATION_NAME} - No Active Alerts Found for AID: {aid}'

        else:
            title = f'{INTEGRATION_NAME} - No Active Alerts found for AID: Default'

    results = CommandResults(
        readable_output=tableToMarkdown(title, t=human_readable_data),
        outputs_prefix='ThousandEyes.Alerts',
        outputs_key_field='AlertId',
        outputs=entry_context,
        raw_response=raw_response_list
    )

    return results


def get_alert_command(client: Client, alert_id: int):
    """
        Fetch a given alert.

    Args:
        client (Client Object): Client object with request.
        alert_id (int): Alert ID to fetch.

    Returns:
        Tuple of Context Data and Human Readable Data.

    """

    endpoint = f'/alerts/{alert_id}.json'
    method = 'GET'

    response = client.handle_rate_lmiit_and_make_request(
        method,
        endpoint
    )

    # If Response is an error, return the error
    if isinstance(response, dict):
        return response

    return response.json()


def get_agents_command(client: Client):
    """
        Fetches all agents

    Args:
        client (Client Object): Client object with request.

    Returns:
        Tuple of Context Data and Human Readable Data.
    """

    endpoint = '/agents.json'
    method = 'GET'

    response = client.handle_rate_lmiit_and_make_request(
        method,
        endpoint
    )

    # If Response is an error, return the error
    if isinstance(response, dict):
        return response

    return parse_agent_response(response)


def get_agent_command(client: Client, agent_id: int):
    """
        Fetches a given agent.

    Args:
        client (Client Object): Client object with request.
        agent_id (int): Agent ID to fetch.

    Returns:
        Tuple of Context Data and Human Readable Data.
    """

    endpoint = f'/agents/{agent_id}.json'
    method = 'GET'

    response = client.handle_rate_lmiit_and_make_request(
        method,
        endpoint
    )

    # If Response is an error, return the error
    if isinstance(response, dict):
        return response

    return response.json()


def main():
    # Fetching required parameters
    params = demisto.params()
    base_url = params.get('base_url') + API_VERSION_ENDPOINT
    bearer_token = params.get('credentials').get('password')
    headers = {
        'Authorization': f'Bearer {bearer_token}',
        'Accept': 'application/json'
    }
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')

    # Initializing the Client Object with required configuration
    client = Client(
        base_url=base_url,
        verify=verify_ssl,
        proxy=proxy,
        headers=headers
    )

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-get-alerts': get_alerts_command,
        f'{INTEGRATION_COMMAND_NAME}-get-alert': get_alert_command,
        f'{INTEGRATION_COMMAND_NAME}-get-agents': get_agents_command,
        f'{INTEGRATION_COMMAND_NAME}-get-agent': get_agent_command
    }

    try:
        if command in commands:
            results = commands[command](client=client, **demisto.args())  # type: ignore
            return_results(results)

        elif command == 'fetch-incidents':
            max_results = arg_to_number(arg=demisto.params().get("max_fetch"), arg_name="max_fetch", required=False)
            first_fetch_timestamp = params.get("fetch_time", "3 days").strip()
            minimum_severity = params.get("severity")

            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents_to_create = fetch_incidents_command(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_timestamp,
                minimum_severity=minimum_severity
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents_to_create)

        else:
            raise NotImplementedError(f"{command} is not an existing ThousandEyes command")

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
