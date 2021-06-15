import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Lookout CASB Integration for Cortex XSOAR (aka Demisto)
    Last updated: 2020-10-27

"""

# import demistomock as demisto
# from CommonServerPython import *
# from CommonServerUserPython import *

import datetime
import json
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dateparser
import requests

# Disable insecure warnings
DEFAULT_FETCH_DAYS_FOR_FIRST_TIME = '3 days'
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

EVENT_TYPE_VIOLATION = 'Violation'
EVENT_TYPE_ANOMALY = 'Anomaly'
EVENT_TYPE_ACTIVITY = 'Activity'
EVENT_TYPE_ALL = 'All'

AUTH_TOKEN_CONST = 'auth_token'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
EPOCH_STRING = '1970-01-01T00:00:01.000Z'  # OR 2020-11-01T01:35:00.000-00:00
EXPIRES_IN = 'expires_in'
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
MAX_INCIDENTS_TO_FETCH = 500
NOT_FOUND = 'NOT_FOUND'
TOKEN_TTL_IN_SECONDS = 3600
VERIFY_SSL = not demisto.params().get('insecure', False)  # TODO: Review and fix

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """


''' HELPER FUNCTIONS '''


def epoch_to_iso(epoch: int) -> str:
    """Converts epoch seconds to ISO 8601 format

    :type epoch: ``int``
    :param epoch: epoch seconds. For example: 1603582551

    :return: time in string ISO 8601 format. For example: 2020-10-24T23:35:51+00:00.
    :rtype: ``str``
    """

    dt = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return dt.isoformat()


def current_time() -> str:
    """Returns current time in string: For example: 2020-11-06T20:08:17+00:00.

    :return: Returns current time in string: For example: 2020-11-06T20:08:17+00:00.
    :rtype: ``str``
    """

    return datetime.datetime.utcnow().replace(microsecond=0).replace(tzinfo=datetime.timezone.utc).isoformat()


def epoch_seconds() -> int:
    """ Returns epoch seconds. For example: 1604722185.

    :return: Epoch seconds
    :rtype: ``int``
    """

    return int(datetime.datetime.utcnow().timestamp())


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def get_argument_str(args, param, default: str) -> str:
    if param in args:
        return args[param]
    else:
        return default


def get_argument_int(args, param: str, default: int) -> int:
    if param in args:
        return args[param]
    else:
        return default


''' AUTHENTICATION FUNCTIONS '''


def get_authentication_token(base_url: str, client_id: str, client_secret: str) -> str:
    """Requests API Token from CASB API Gateway using client_id and client_sercret.

    :type base_url: ``str``
    :param base_url: Base URL for integration

    :type client_id: ``str``
    :param client_id: Client ID for CipherCloud CASB Integration

    :type client_secret: ``str``
    :param client_secret: Client Secret for CipherCloud CASB Integration

    :return access token
    """

    integration_context = demisto.getIntegrationContext()
    auth_token = integration_context.get(AUTH_TOKEN_CONST)
    expires_in = integration_context.get(EXPIRES_IN)

    time_now = epoch_seconds()
    demisto.debug(f'epoch:{time_now}, expires_in:{expires_in}')
    if auth_token and expires_in and time_now < expires_in:
        demisto.debug(f'Returning stored access_token. epoch:{time_now}, expires_in:{expires_in}')
        return auth_token

    demisto.debug(f'No stored token found or token expired - will send token request for client_id:{client_id}')
    request_body = {
        'clientId': client_id,
        'clientSecret': client_secret
    }

    full_url = base_url + '/apigw/v1/authenticate'
    res = requests.post(
        full_url,
        verify=VERIFY_SSL,
        json=request_body
    )

    json_response = json.loads(res.text)

    if "id_token" not in json_response:
        demisto.debug(f'res : {res}')
        demisto.debug(f'{json_response}')
        err_msg = 'Failed to get authentication. Response: {}'.format(res)
        raise DemistoException(err_msg)

    auth_token = json_response['id_token']
    demisto.debug(f'auth: {auth_token}')

    new_expires_in = time_now + TOKEN_TTL_IN_SECONDS

    integration_context = {
        AUTH_TOKEN_CONST: auth_token,
        EXPIRES_IN: new_expires_in
    }

    demisto.setIntegrationContext(integration_context)
    return auth_token


''' COMMAND FUNCTIONS '''


def test_module(client: Client, event_type: str) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    test_results = fetch_events(client, event_type, None, None, 1)
    demisto.info(f'test_module result: {test_results}')
    return 'ok'


def fetch_events(client: Client,
                 event_type: str,
                 start_time: str,
                 end_time: str,
                 max_results: int
                 ) -> List:
    """ Fetched given event occurred betnween start_time and end_time limited by max_results.

    :param client: client to use
    :param event_type: One of the event types: Violation, Anomaly, Activity. All will fetch Violation and Anomaly.
    :param start_time: Start time in ISO 8601 format.
    :param end_time: End time is ISO 8601 format.
    :param max_results: Maximum results to fetch.
    :return: List of events
    """
    request_params = {
        'eventType': event_type
    }

    if start_time is not None:
        request_params['startTime'] = start_time

    if end_time is not None:
        request_params['endTime'] = end_time

    if max_results is not None:
        request_params['maxResults'] = max_results

    records = client._http_request(
        method='GET',
        url_suffix='/apigw/v1/events',
        params=request_params
    )

    demisto.debug(f'RECORDS {records}')

    violations = []

    if 'data' not in records:
        demisto.results(f'NO {event_type} FOUND')
        return violations

    violations = records['data']

    if violations:
        demisto.results(f'Fetch incidents completed - {len(violations)} {event_type} FOUND')
    else:
        demisto.results("NO {event_type} FOUND")

    return violations


def incidents_api_call(client: Client,
                       event_type: str,
                       start_time: str,
                       end_time: str,
                       max_results: int
                       ) -> str:
    """ Fetches given event occurred between start_time and end_time limited by max_results.

    :param client: client to use
    :param event_type: One of the event types: Violation, Anomaly, Activity. All will fetch Violation and Anomaly.
    :param start_time: Start time in ISO 8601 format.
    :param end_time: End time is ISO 8601 format.
    :param max_results: Maximum results to fetch.
    :return: List of events
    """

    violations = []

    request_params = {
        'eventType': event_type
    }

    if start_time is not None:
        request_params['startTime'] = start_time

    if end_time is not None:
        request_params['endTime'] = end_time

    if max_results is not None:
        request_params['maxResults'] = max_results

    records = client._http_request(
        method='GET',
        url_suffix='/apigw/v1/events',
        params=request_params
    )

    demisto.debug(f'RECORDS {records}')

    if 'data' not in records:
        demisto.debug(f'NO {event_type} FOUND')
    else:
        violations = records['data']

    return violations


def get_information(client: Client,
                    entity_id: str,
                    entity_type: str,
                    result_type: str,
                    start_time: str,
                    end_time: str
                    ) -> str:
    """ Fetches given event occurred between start_time and end_time limited by max_results.

    :param client: client to use
    :param entity_id: entity value to seatch for
    :param entity_type: One of the entity types: User, Content, Location, Device, Application
    :param start_time: Start time in ISO 8601 format.
    :param end_time: End time is ISO 8601 format.
    :param result_type:
    :return: Returns
            {'status': 'Success', 'statusCode': 200, 'message': 'Success', 'data': {'userRiskRating': 'Low', 'Location': [{'name': 'Brooklyn', 'count': '6060', 'percentage': '82.832149'},
            {'name': 'Raipur', 'count': '483', 'percentage': '6.601968'}}]}}
    """

    request_params = {
        'entityId': entity_id,
        'entityType': entity_type,
        'resultType': result_type
    }

    if start_time is not None:
        request_params['startTime'] = start_time

    if end_time is not None:
        request_params['endTime'] = end_time

    records = client._http_request(
        method='GET',
        url_suffix='/apigw/v1/insights',
        params=request_params
    )

    demisto.debug(f'RECORDS {records}')

    if 'data' not in records:    # data will exist even when user/entity is not found.
        err_msg = 'Failed to get information. Response: {}'.format(records)
        raise DemistoException(err_msg)

    return records['data']


def user_profile(client: Client,
                 user_email: str,
                 user_risk_rating: str,
                 action: str
                 ) -> str:
    """Manages used user profile. You can get, add/update, delete user profile.

    :param client: client to use
    :param user_email: User email
    :param user_risk_rating: User risk rating - High, Medium, Low
    :param action: will be one of 'Get', 'Update', 'Delete'
    :return: 'Get' returns json with userEmail and userRiskRating
            'Update' returns {"status": "Success","statusCode": 200,"message": "Success"} on success
            'Delete' returns {"status": "Success","statusCode": 200,"message": "Success"} on success
    """
    method = action.upper()
    request_params = {
        'userEmail': user_email
    }

    if action == 'Update':
        method = 'POST'
        request_params['userRiskRating'] = user_risk_rating

    records = client._http_request(
        method=method,
        url_suffix='/apigw/v1/userprofile',
        params=request_params
    )

    demisto.debug(f'{records}')

    if action == 'Update' or action == 'Delete':
        if records['status'] == 'Success':
            return records
        else:
            demisto.results(f'Error in User {action} action for user: {user_email}.')
            err_msg = 'Failed update/delete user profile. Response: {}'.format(records)
            raise DemistoException(err_msg)

    if action == 'Get':
        if records['status'] == 'Success':
            data = records['data']
            return data
        else:
            err_msg = 'Error in fetching user profile. Response: {}'.format(records)
            raise DemistoException(err_msg)


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int]
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """Fetches Violation and Anomaly incidents based based on last fetch time. Records are limited by max_results.

    :param client: client to use
    :param max_results: maximum results to fetch.
    :param last_run: last run time
    :param first_fetch_time: first fetch time
    :return: next run details and list of incidents
    """

    demisto.info("Start -> fetch_incidents")

    last_fetch = last_run.get('last_fetch', None)

    if last_fetch is None:
        demisto.debug("last_fetch is None")
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)
        demisto.debug(f'last_fetch: {last_fetch}')

    latest_created_time = cast(int, last_fetch)

    incidents: List[Dict[str, Any]] = []

    last_fetch_str = epoch_to_iso(last_fetch)

    alerts = incidents_api_call(
        client=client,
        event_type=EVENT_TYPE_ALL,
        start_time=last_fetch_str,
        end_time=current_time(),
        max_results=max_results
    )

    demisto.debug(f'# of alerts:{len(alerts)}')

    for alert in alerts:
        demisto.debug("Pocessing alerts")
        date1 = dateparser.parse(alert.get('timeStamp', EPOCH_STRING))
        demisto.debug(f'alert timeStamp: {date1}')
        incident_created_time = date1.timestamp()
        incident_created_time_ms = incident_created_time * 1000
        demisto.debug(f'incident_created_time_ms: {incident_created_time_ms}')

        demisto.debug(f'alert: {alert}')
        incident_name = alert.get('eventId')
        demisto.debug(f'Incident_name: {incident_name}')

        if last_fetch and incident_created_time <= last_fetch:
            demisto.info("incident_created_time <= last_fetch so skipping this alert")
            continue

        incident_name = alert.get('eventId')
        demisto.debug(f'Incident_name: {incident_name}')

        demisto.debug(f'Creating incident: {incident_name}, {date1.isoformat()}')
        incident = {
            'name': incident_name,
            'occurred': date1.isoformat(),
            'rawJSON': json.dumps(alert)
        }

        incidents.append(incident)

        if incident_created_time > latest_created_time:
            demisto.debug(f'incident_created_time:{incident_created_time}, latest_created_time:{latest_created_time}')
            latest_created_time = incident_created_time

    demisto.debug(f'Saving last_fetch -> {latest_created_time}')
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """ Main method to process all commands

    :return: None
    """

    demisto.info("START: Processing")
    client_id = demisto.params().get('client_id')
    client_secret = demisto.params().get('client_secret')
    base_url = demisto.params()['url']
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    args = demisto.args()
    demisto.info(f'ARGS: {args}')

    entity_id = get_argument_str(args, 'entity_id', 'NA')
    entity_type = get_argument_str(args, 'entity_type', 'NA')
    result_type = get_argument_str(args, 'result_type', 'User')
    user_email = get_argument_str(args, 'email', 'Content')
    user_risk_rating = get_argument_str(args, 'risk_rating', 'NA')
    action = get_argument_str(args, 'action', 'Get')
    start_time = get_argument_str(args, 'start_time', None)
    end_time = get_argument_str(args, 'end_time', None)
    max_results = get_argument_int(args, 'max_results', MAX_INCIDENTS_TO_FETCH)

    if max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    demisto.info(f'base_url: {base_url}, Max Results:{max_results}, start_time: {start_time}, end_time: {end_time}')

    demisto.info(f'Command:{demisto.command()}')

    try:
        api_key = get_authentication_token(base_url, client_id, client_secret)

        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module(client, EVENT_TYPE_VIOLATION)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            demisto.info("START: fetch_incidents")

            first_fetch_time = arg_to_timestamp(
                arg=demisto.params().get('first_fetch', DEFAULT_FETCH_DAYS_FOR_FIRST_TIME),
                arg_name='First fetch time',
                required=True
            )

            demisto.info(f'first_fetch_time: {first_fetch_time}')

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time
            )

            demisto.info("END: fetch_incidents")

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'lookout-get-violations':
            violations = fetch_events(
                client=client,
                event_type=EVENT_TYPE_VIOLATION,
                start_time=start_time,
                end_time=end_time,
                max_results=max_results
            )

            cmd_result = CommandResults(
                outputs_prefix='CipherCloud.Violation',
                outputs_key_field=['eventId'],
                outputs=violations
            )

            return_results(cmd_result)
            demisto.debug("lookout-get-violations Completed")

        elif demisto.command() == 'lookout-get-anomalies':
            anomalies = fetch_events(
                client=client,
                event_type=EVENT_TYPE_ANOMALY,
                start_time=start_time,
                end_time=end_time,
                max_results=max_results
            )
            cmd_result = CommandResults(
                outputs_prefix='CipherCloud.Anomaly',
                outputs_key_field=['currEventId'],
                outputs=anomalies
            )

            return_results(cmd_result)
            demisto.debug("lookout-get-violations Completed")

        elif demisto.command() == 'lookout-get-events':
            activities = fetch_events(
                client=client,
                event_type=EVENT_TYPE_ACTIVITY,
                start_time=start_time,
                end_time=end_time,
                max_results=max_results
            )
            cmd_result = CommandResults(
                outputs_prefix='CipherCloud.Activity',
                outputs_key_field=['eventId'],
                outputs=activities
            )

            return_results(cmd_result)

        elif demisto.command() == 'lookout-get-information':
            information = get_information(
                client=client,
                entity_id=entity_id,
                entity_type=entity_type,
                result_type=result_type,
                start_time=start_time,
                end_time=end_time
            )

            cmd_result = CommandResults(
                outputs_prefix='CipherCloud.Info',
                outputs_key_field=[entity_type],
                outputs=information
            )
            return_results(cmd_result)

        elif demisto.command() == 'lookout-profile-user':
            res = user_profile(
                client=client,
                user_email=user_email,
                user_risk_rating=user_risk_rating,
                action=action
            )
            cmd_result = CommandResults(
                outputs_prefix='CipherCloud.UserProfile',
                outputs_key_field=['userEmail'],
                outputs=res
            )
            return_results(cmd_result)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
