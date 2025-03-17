import demistomock as demisto
from CommonServerPython import *
import urllib3
import json
import dateparser
import traceback
import urllib.parse
from typing import Any, cast

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def xm_get_user(self, user: str):
        """Retrieves a user in xMatters. Good for testing authentication
        :type user: ``str``
        :param user: The user to retrieve

        :return: Result from getting the user
        :rtype: ``Dict[str, Any]``
        """
        res = self._http_request(
            method='GET',
            url_suffix='/api/xm/1/people?webLogin=' + urllib.parse.quote(user)
        )

        return res

    def xm_trigger_workflow(self, recipients: str | None = None,
                            subject: str | None = None, body: str | None = None,
                            incident_id: str | None = None,
                            close_task_id: str | None = None) -> dict[str, Any]:
        """Triggers a workflow in xMatters.

        :type recipients: ``Optional[str]``
        :param recipients: recipients for the xMatters alert.

        :type subject: ``Optional[str]``
        :param subject: Subject for the message in xMatters.

        :type body: ``Optional[str]``
        :param body: Body for the message in xMatters.

        :type incident_id: ``Optional[str]``
        :param incident_id: ID of incident that the message is related to.

        :type close_task_id: ``Optional[str]``
        :param close_task_id: Task ID from playbook to close.

        :return: result of the http request
        :rtype: ``Dict[str, Any]``
        """

        request_params: dict[str, Any] = {
        }

        if recipients:
            request_params['recipients'] = recipients

        if subject:
            request_params['subject'] = subject

        if body:
            request_params['body'] = body

        if incident_id:
            request_params['incident_id'] = incident_id

        if close_task_id:
            request_params['close_task_id'] = close_task_id

        res = self._http_request(
            method='POST',
            url_suffix='',
            params=request_params,
        )

        return res

    def search_alerts(self, max_fetch: int = 100, alert_status: str | None = None, priority: str | None = None,
                      start_time: int | None = None, property_name: str | None = None,
                      property_value: str | None = None, request_id: str | None = None,
                      from_time: str | None = None, to_time: str | None = None,
                      workflow: str | None = None, form: str | None = None) -> list[dict[str, Any]]:
        """Searches for xMatters alerts using the '/events' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type max_fetch: ``str``
        :param max_fetch: The maximum number of events or incidents to retrieve

        :type alert_status: ``Optional[str]``
        :param alert_status: status of the alert to search for. Options are: 'ACTIVE' or 'SUSPENDED'

        :type priority: ``Optional[str]``
        :param priority:
            severity of the alert to search for. Comma-separated values.
            Options are: "LOW", "MEDIUM", "HIGH"

        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search

        :type property_name: ``Optional[str]``
        :param property_name: Name of property to match when searching for alerts.

        :type property_value: ``Optional[str]``
        :param property_value: Value of property to match when searching for alerts.

        :type request_id: ``Optional[str]``
        :param request_id: Matches requestId in xMatters.

        :type from_time: ``Optional[str]``
        :param from_time: UTC time of the beginning time to search for events.

        :type to_time: ``Optional[str]``
        :param to_time: UTC time of the end time to search for events.

        :type workflow: ``Optional[str]``
        :param workflow: Workflow that events are from in xMatters.

        :type form: ``Optional[str]``
        :param form: Form that events are from in xMatters.

        :return: list containing the found xMatters events as dicts
        :rtype: ``List[Dict[str, Any]]``
        """

        request_params: dict[str, Any] = {}

        request_params['limit'] = max_fetch

        if alert_status:
            request_params['status'] = alert_status

        if priority:
            request_params['priority'] = priority

        if from_time:
            request_params['from'] = from_time
        elif start_time:
            request_params['from'] = start_time

        if to_time:
            request_params['to'] = to_time

        if property_value and property_name:
            request_params['propertyName'] = property_name
            request_params['propertyValue'] = property_value

        if request_id:
            request_params['requestId'] = request_id

        if workflow:
            request_params['plan'] = workflow

        if form:
            request_params['form'] = form

        res = self._http_request(
            method='GET',
            url_suffix='/api/xm/1/events',
            params=request_params
        )

        data = res.get('data')

        has_next = True

        while has_next:
            if 'links' in res and 'next' in res['links']:

                res = self._http_request(
                    method='GET',
                    url_suffix=res.get('links').get('next')
                )

                for val in res.get('data'):
                    data.append(val)
            else:
                has_next = False

        return data

    def search_alert(self, event_id: str):
        """Searches for xMatters alerts using the '/events' API endpoint

        The event_id is passed as a parameter to the API call.

        :type event_id: ``Required[str]``
        :param event_id: The event ID or UUID of the event to retrieve
        """

        res = self._http_request(
            method='GET',
            url_suffix='/api/xm/1/events/' + event_id,
            ok_codes=(200, 404)
        )
        return res


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: str) -> int:
    """Maps xMatters severity to Cortex XSOAR severity

    Converts the xMatters alert severity level ('Low', 'Medium',
    'High') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the HelloWorld API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'low': 1,  # low severity
        'medium': 2,  # medium severity
        'high': 3,  # high severity
    }[severity.lower()]


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int | None:
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


''' COMMAND FUNCTIONS '''


def fetch_incidents(client: Client,
                    max_fetch: int = 100,
                    last_run: dict[str, int] = {},
                    first_fetch_time: int | None = None,
                    alert_status: str | None = None,
                    priority: str | None = None,
                    property_name: str | None = None,
                    property_value: str | None = None
                    ) -> tuple[dict[str, int], list[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch_time to determine when to start fetching
    the first time.

    :type client: ``Client``
    :param Client: xMatters client to use

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type alert_status: ``Optional[str]``
    :param alert_status:
        status of the alert to search for. Options are: 'ACTIVE',
        'SUSPENDED', or 'TERMINATED'

    :type max_fetch: ``str``
    :param max_fetch:
        The maximum number of events or incidents to fetch.

    :type priority: ``str``
    :param priority:
        Comma-separated list of the priority to search for.
        Options are: "LOW", "MEDIUM", "HIGH"

    :type property_name: ``Optional[str]``
    :param property_name: Property name to match with events.

    :type property_value: ``Optional[str]``
    :param property_value: Property value to match with events.

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

    if last_fetch is not None:
        start_time = timestamp_to_datestring(last_fetch * 1000)
    else:
        start_time = None

    # demisto.info("This is the current timestamp: " + str(start_time))
    # demisto.info("MS - last_fetch: " + str(last_fetch))

    alerts = client.search_alerts(
        max_fetch=max_fetch,
        alert_status=alert_status,
        start_time=start_time,
        priority=priority,
        property_name=property_name,
        property_value=property_value
    )

    for alert in alerts:
        try:
            # If no created_time set is as epoch (0). We use time in ms so we must
            # convert it from the HelloWorld API response
            incident_created_time = alert.get('created')

            # If no name is present it will throw an exception
            if "name" in alert:
                incident_name = alert['name']
            else:
                incident_name = "No Message Subject"

            datetimeformat = '%Y-%m-%dT%H:%M:%S.000Z'

            if isinstance(incident_created_time, str):
                parseddate = dateparser.parse(incident_created_time)
                if isinstance(parseddate, datetime):
                    occurred = parseddate.strftime(datetimeformat)
                    date = dateparser.parse(occurred, settings={'TIMEZONE': 'UTC'})
                    if isinstance(date, datetime):
                        incident_created_time = int(date.timestamp())
                        incident_created_time_ms = incident_created_time * 1000
                    else:
                        incident_created_time = 0
                        incident_created_time_ms = 0
                else:
                    date = None
                    incident_created_time = 0
                    incident_created_time_ms = 0
            else:
                date = None
                incident_created_time = 0
                incident_created_time_ms = 0

            demisto.info("MS - incident_created_time: " + str(last_fetch))
            # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
            if last_fetch:
                if incident_created_time <= last_fetch:
                    continue

            details = ""

            if 'plan' in alert:
                details = details + alert['plan']['name'] + " - "

            if 'form' in alert:
                details = details + alert['form']['name']

            incident = {
                'name': incident_name,
                'details': details,
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'rawJSON': json.dumps(alert),
                'type': 'xMatters Alert',  # Map to a specific XSOAR incident Type
                'severity': convert_to_demisto_severity(alert.get('priority', 'Low')),
            }

            incidents.append(incident)

            # Update last run and add incident if the incident is newer than last fetch
            if isinstance(date, datetime) and date.timestamp() > latest_created_time:
                latest_created_time = incident_created_time
        except Exception as e:
            demisto.info("Issue with event")
            demisto.info(str(alert))
            demisto.info(str(e))

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}

    return next_run, incidents


def event_reduce(e):
    return {"Created": e.get('created'),
            "Terminated": e.get('terminated'),
            "ID": e.get('id'),
            "EventID": e.get('eventId'),
            "Name": e.get('name'),
            "PlanName": e.get('plan').get('name'),
            "FormName": e.get('form').get('name'),
            "Status": e.get('status'),
            "Priority": e.get('priority'),
            "Properties": e.get('properties'),
            "SubmitterName": e.get('submitter').get('targetName')}


def xm_trigger_workflow_command(client: Client, recipients: str,
                                subject: str, body: str, incident_id: str,
                                close_task_id: str) -> CommandResults:
    out = client.xm_trigger_workflow(
        recipients=recipients,
        subject=subject,
        body=body,
        incident_id=incident_id,
        close_task_id=close_task_id
    )
    """
    This function runs when the xm-trigger-workflow command is run.

    :type client: ``Client``
    :param Client: xMatters client to use

    :type recipients: ``str``
    :param recipients: Recipients to alert from xMatters.

    :type subject: ``str``
    :param subject: Subject of the alert in xMatters.

    :type body: ``str``
    :param body: Body of the alert in xMatters.

    :type incident_id: ``str``
    :param incident_id: Incident ID of the event in XSOAR.

    :type close_task_id: ``str``
    :param close_task_id: ID of task to close in a playbook.

    :return: Output of xm-trigger-workflow command being run.

    :rtype: ``CommandResults``
    """

    outputs = {}

    outputs['requestId'] = out['requestId']

    return CommandResults(
        readable_output="Successfully sent a message to xMatters.",
        outputs=outputs,
        outputs_prefix='xMatters.Workflow',
        outputs_key_field='requestId'
    )


def xm_get_events_command(client: Client, request_id: str | None = None, status: str | None = None,
                          priority: str | None = None, from_time: str | None = None,
                          to_time: str | None = None, workflow: str | None = None,
                          form: str | None = None, property_name: str | None = None,
                          property_value: str | None = None) -> CommandResults:
    """
    This function runs when the xm-get-events command is run.


        :type client: ``Client``
    :param Client: xMatters client to use

    :type request_id: ``Optional[str]```
    :param request_id: The the request ID associated with the events.

    :type status: ``Optional[str]``
    :param status:
        status of the alert to search for. Options are: 'ACTIVE',
        'SUSPENDED', or 'TERMINATED'

    :type priority: ``Optional[str]``
    :param priority:
        Comma-separated list of the priority to search for.
        Options are: "LOW", "MEDIUM", "HIGH"

    :type from_time: ``Optional[str]``
    :param from_time: UTC time for the start of the search.

    :type to_time: ``Optional[str]``
    :param to_time: UTC time for the end of the search.

    :type workflow: ``Optional[str]``
    :param workflow: Name of workflow to match the search.

    :type form: ``Optional[str]``
    :param form: Name of form to match in the search.

    :type property_name: ``Optional[str]``
    :param property_name: Property name to match with events.

    :type property_value: ``Optional[str]``
    :param property_value: Property value to match with events.

    :return: Events from the search.

    :rtype: ``CommandResults``
    """
    out = client.search_alerts(
        request_id=request_id,
        alert_status=status,
        priority=priority,
        from_time=from_time,
        to_time=to_time,
        workflow=workflow,
        form=form,
        property_name=property_name,
        property_value=property_value
    )

    reduced_out: dict[str, list[Any]]
    if len(out) == 0:
        reduced_out = {"xMatters.GetEvent.Event": []}
        readable_output = "Could not find Events with given criteria in xMatters"
    else:
        reduced_out = {"xMatters.GetEvents.Events": [event_reduce(event) for event in out]}
        readable_output = f'Retrieved Events from xMatters: {reduced_out}'

    return CommandResults(
        readable_output=readable_output,
        outputs=reduced_out,
        outputs_prefix='xMatters.GetEvents',
        outputs_key_field='event_id'
    )


def xm_get_event_command(client: Client, event_id: str) -> CommandResults:
    """
    This function is run when the xm-get-event command is run.

    :type client: ``Client``
    :param Client: xMatters client to use

    :type event_id: ``str``
    :param event_id: Event ID to search for in xMatters

    :return: Output of xm-get-event command

    :rtype: ``CommandResults``
    """
    out = client.search_alert(event_id=event_id)

    reduced_out: dict[str, Any]
    if out.get('code') == 404:
        reduced_out = {"xMatters.GetEvent.Event": {}}
        readable_output = f'Could not find Event "{event_id}" from xMatters'
    else:
        reduced = event_reduce(out)
        reduced_out = {"xMatters.GetEvent.Event": reduced}
        readable_output = f'Retrieved Event "{event_id}" from xMatters:\nEventID: {reduced.get("EventID")}\n' \
                          f'Created: {reduced.get("Created")}\nTerminated: {reduced.get("Terminated")}\n' \
                          f'Name: {reduced.get("Name")}\nStatus: {reduced.get("Status")}'

    return CommandResults(
        readable_output=readable_output,
        outputs=reduced_out,
        outputs_prefix='xMatters.GetEvent',
        outputs_key_field='event_id'
    )


def test_module(from_xm: Client, to_xm: Client, user: str, max_fetch: int) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type from_xm: ``Client``
    :param Client: xMatters client to use to pull events from

    :type to_xm: ``Client``
    :param Client: xMatters client to use to post an event to.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error

    max_fetch_int = int(max_fetch)
    try:
        if max_fetch_int <= 0 or max_fetch_int > 200:
            raise ValueError
    except ValueError:
        raise ValueError("Max Fetch must be between 0 and 201")

    try:
        to_xm.xm_trigger_workflow(
            recipients='nobody',
            subject='Test - please ignore',
            body='Test - please ignore'
        )
        # return f'RequestId: {res["requestId"]}'

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: Check the URL of an HTTP trigger in a flow'
        else:
            raise e

    try:
        from_xm.xm_get_user(user=user)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: Username and Password fields and verify the user exists'
        else:
            raise e

    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    instance = demisto.params().get('instance')
    username = demisto.params().get('username')
    password = demisto.params().get('password')
    property_name = demisto.params().get('property_name')
    property_value = demisto.params().get('property_value')
    base_url = demisto.params().get('url')
    max_fetch = demisto.params().get('max_fetch', 20)

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_timestamp(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_time, int)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        to_xm_client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        from_xm_client = Client(
            base_url="https://" + instance,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'xm-trigger-workflow':
            return_results(xm_trigger_workflow_command(
                to_xm_client,
                demisto.args().get('recipients'),
                demisto.args().get('subject'),
                demisto.args().get('body'),
                demisto.args().get('incident_id'),
                demisto.args().get('close_task_id')
            ))
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get('status', None)
            priority = demisto.params().get('priority', None)

            next_run, incidents = fetch_incidents(
                client=from_xm_client,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                max_fetch=max_fetch,
                alert_status=alert_status,
                priority=priority,
                property_name=property_name,
                property_value=property_value
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to crate
            demisto.incidents(incidents)
        elif demisto.command() == 'xm-get-events':
            return_results(xm_get_events_command(
                client=from_xm_client,
                request_id=demisto.args().get('request_id'),
                status=demisto.args().get('status'),
                priority=demisto.args().get('priority'),
                from_time=demisto.args().get('from'),
                to_time=demisto.args().get('to'),
                workflow=demisto.args().get('workflow'),
                form=demisto.args().get('form'),
                property_name=demisto.args().get('property_name'),
                property_value=demisto.args().get('property_value')
            ))
        elif demisto.command() == 'xm-get-event':
            return_results(xm_get_event_command(
                client=from_xm_client,
                event_id=demisto.args().get('event_id')
            ))
        elif demisto.command() == 'test-module':
            return_results(test_module(
                from_xm=from_xm_client,
                to_xm=to_xm_client,
                user=username,
                max_fetch=max_fetch
            ))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
