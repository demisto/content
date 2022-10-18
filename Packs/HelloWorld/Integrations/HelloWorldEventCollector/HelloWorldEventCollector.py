"""HelloWorld Event Collector for Cortex XSIAM

This integration is a good example on you can build a Cortex XSIAM Integration
using Python 3. Please follow the documentation links below and make sure that
your integration follows the Code Conventions and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

When building a Cortex XSIAM integration that is reusable, a lot of effort
must be placed in the design. We recommend to fill a Design Document template,
that allows you to capture Use Cases, Requirements and Inputs/Outputs.

Example Design document for the this Integration (HelloWorld):
https://docs.google.com/document/d/1wETtBEKg37PHNU8tYeB56M1LE314ux086z3HFeF_cX0


HelloWorld API
--------------

The HelloWorld API is a simple API that shows a realistic use case for an XSIAM
integration. It's actually a real API that is available to the following URL:
https://soar.mastersofhack.com - if you need an API Key to test it out please
reach out to your Cortex XSIAM contacts.

This API has a few basic functions:
- Alerts: the endpoint returns mocked alerts and allows you to search based on
a number of parameters, such as state (ACTIVE or CLOSED), type, timestamp. It
can also return a single alert by ID. This is used to create new events in
XSIAM by using the ``fetch-events`` command, which is by default invoked
every minute.
There is also an endpoint that allows to retrieve additional details about a
specific alert by ID, and one to change the alert status to "CLOSED" once
it has been resolved.

- Reputation (ip and domain): these endpoints return, for an IP and
domain respectively, a WHOIS lookup of the entity as well as a reputation score
(from 0 to 100) that is used to determine whether the entity is malicious. This
endpoint is called by XSIAM reputation commands ``ip`` and ``domain`` that
are run automatically every time an indicator is extracted in XSIAM. As a best
practice of design, it is important to map and document the mapping between
a score in the original API format (0 to 100 in this case) to a score in XSIAM
format (0 to 3). This score is called ``DBotScore``, and is returned in the
context to allow automated handling of indicators based on their reputation.
More information: https://xsoar.pan.dev/docs/integrations/dbot


- Scan: to demonstrate how to run commands that are not returning instant data,
the API provides a scan endpoint that simulates scanning a host and generating
a report after the scan is completed. The API has endpoints to start a scan,
which returns a job ID, poll for the scan status and, if the scan is completed,
retrieved the job results.
This function is used in conjunction of the HelloWorld Scan playbook that uses
the GenericPolling mechanism to implement the job polling loop. The results
can be returned in JSON or attachment file format.
Info on GenericPolling: https://xsoar.pan.dev/docs/playbooks/generic-polling

Please check the HelloWorld Design Document referenced above for details about
the raw API responsens as well as the design details for this integration.

This integration also has a ``say-hello`` command for backward compatibility,
that doesn't connect to an API and just returns a ``Hello {name}`` string,
where name is the input value provided.


Integration File Structure
--------------------------

An integration usually consists of the following parts:
- Imports
- Constants
- Client Class
- Helper Functions
- Command Functions
- Main Function
- Entry Point


Imports
-------

Here you can import Python module you need for your integration. If you need
a module that is not part of the default XSIAM Docker images, you can add
a custom one. More details: https://xsoar.pan.dev/docs/integrations/docker

There are also internal imports that are used by XSIAM:
- demistomock (imported as demisto): allows your code to work offline for
testing. The actual ``demisto`` module is provided at runtime when the
code runs in XSIAM.
- CommonServerPython.py: contains a set of helper functions, base classes
and other useful components that will make your integration code easier
to maintain.
- CommonServerUserPython.py: includes a set of user defined commands that
are specific to an XSIAM installation. Do not use it for integrations that
are meant to be shared externally.

These imports are automatically loaded at runtime within the XSIAM script
runner, so you shouldn't modify them

Constants
---------

Usually some constants that do not require user parameters or inputs, such
as the default API entry point for your service, or the maximum numbers of
events to fetch every time.


Client Class
------------

We recommend to use a Client class to wrap all the code that needs to interact
with your API. Moreover, we recommend, when possible, to inherit from the
BaseClient class, defined in CommonServerPython.py. This class already handles
a lot of the work, such as system proxy settings, SSL certificate verification
and exception handling for HTTP errors.

Note that the Client class should NOT contain any Cortex XSIAM specific code,
i.e. it shouldn't use anything in the ``demisto`` class (functions such as
``demisto.args()`` or ``demisto.results()`` or even ``return_results`` and
``return_error``.
You will use the Command Functions to handle XSIAM inputs and outputs.

When calling an API, you should use the ``_http.request()`` method and you
can return the raw data to the calling function (usually a Command function).

You should usually have one function for each API endpoint.

Look at the code and the commends of this specific class to better understand
the implementation details.


Helper Functions
----------------

Helper functions are usually used as utility functions that are used by several
command functions throughout your code. For example they map arguments to types
or convert severity formats from integration-specific to XSIAM.
Many helper functions are already defined in ``CommonServerPython.py`` and are
often very handy.


Command Functions
-----------------

Command functions perform the mapping between XSIAM inputs and outputs to the
Client class functions inputs and outputs. As a best practice, they shouldn't
contain calls to ``demisto.args()``, ``demisto.results()``, ``return_error``
and ``demisto.command()`` as those should be handled through the ``main()``
function.
However, in command functions, use ``demisto`` or ``CommonServerPython.py``
artifacts, such as ``demisto.debug()`` or the ``CommandResults`` class and the
``Common.*`` classes.
Usually you will have one command function for every specific XSIAM command
you want to implement in your integration, plus ``test-module``,
``fetch-events`` and ``fetch-indicators``(if the latter two are supported
by your integration). Each command function should invoke one specific function
of the Client class.

Command functions, when invoked through an XSIAM command usually return data
using the ``CommandResults`` class, that is then passed to ``return_results()``
in the ``main()`` function.
``return_results()`` is defined in ``CommonServerPython.py`` to return
the data to XSIAM. ``return_results()`` actually wraps ``demisto.results()``.
You should never use ``demisto.results()`` directly.

Sometimes you will need to return values in a format that is not compatible
with ``CommandResults`` (for example files): in that case you must return a
data structure that is then pass passed to ``return.results()``. (i.e.
check the ``scan_results_command`` function in this file that has the option
to return a file to Cortex XSIAM).

In any case you should never call ``return_results()`` directly from the
command functions.

When you use create the CommandResults object in command functions, you
usually pass some types of data:

- Human Readable: usually in Markdown format. This is what is presented to the
analyst in the War Room. You can use ``tableToMarkdown()``, defined in
``CommonServerPython.py``, to convert lists and dicts in Markdown and pass it
to ``return_results()`` using the ``readable_output`` argument, or the
``return_results()`` function will call ``tableToMarkdown()`` automatically for
you.

- Context Output: this is the machine readable data, JSON based, that XSIAM can
parse and manage in the Playbooks or event's War Room. The Context Output
fields should be defined in your integration YML file and is important during
the design phase. Make sure you define the format and follow best practices.
You can use ``demisto-sdk json-to-outputs`` to autogenerate the YML file
outputs section. Context output is passed as the ``outputs`` argument in ``demisto_results()``,
and the prefix (i.e. ``HelloWorld.Alert``) is passed via the ``outputs_prefix``
argument.

More information on Context Outputs, Standards, DBotScore and demisto-sdk:
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/context-standards
https://xsoar.pan.dev/docs/integrations/dbot
https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/json_to_outputs/README.md

Also, when you write data in the Context, you want to make sure that if you
return updated information for an entity, to update it and not append to
the list of entities (i.e. in HelloWorld you want to update the status of an
existing ``HelloWorld.Alert`` in the context when you retrieve it, rather than
adding a new one if you already retrieved it). To update data in the Context,
you can define which is the key attribute to use, such as (using the example):
``outputs_key_field='alert_id'``. This means that you are using the ``alert_id``
key to determine whether adding a new entry in the context or updating an
existing one that has the same ID. You can look at the examples to understand
how it works.
More information here:
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/dt

- Raw Output: this is usually the raw result from your API and is used for
troubleshooting purposes or for invoking your command from Automation Scripts.
If not specified, ``return_results()`` will use the same data as ``outputs``.


Main Function
-------------

The ``main()`` function takes care of reading the integration parameters via
the ``demisto.params()`` function, initializes the Client class and checks the
different options provided to ``demisto.commands()``, to invoke the correct
command function passing to it ``demisto.args()`` and returning the data to
``return_results()``. If implemented, ``main()`` also invokes the function
``fetch_events()``with the right parameters and passes the outputs to the
``demisto.events()`` function. ``main()`` also catches exceptions and
returns an error message via ``return_error()``.


Entry Point
-----------

This is the integration code entry point. It checks whether the ``__name__``
variable is ``__main__`` , ``__builtin__`` (for Python 2) or ``builtins`` (for
Python 3) and then calls the ``main()`` function. Just keep this convention.

"""
from requests import Response

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
VENDOR = 'hello'
PRODUCT = 'worlds'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def search_alerts(self, alert_status: Optional[str],
                      alert_type: Optional[str], max_results: Optional[int],
                      start_time: Optional[int]) -> Union[dict, str, Response]:
        """
        Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'
            alert_type (str): type of alerts to search for. There is no list of predefined types.
            max_results (int): maximum number of results to return.
            start_time (int): start timestamp (epoch in seconds) for the alert search.

        Returns:
            list: list of HelloWorld alerts as dicts.
        """

        request_params: Dict[str, Any] = {}

        if alert_status:
            request_params['alert_status'] = alert_status

        if alert_type:
            request_params['alert_type'] = alert_type

        if max_results:
            request_params['max_results'] = max_results

        if start_time:
            request_params['start_time'] = start_time

        return self._http_request(
            method='GET',
            url_suffix='/get_alerts',
            params=request_params
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: Dict[str, Any], first_fetch_time: int) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): HelloWorld client to use.
        params (Dict): Integration parameters.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSIAM UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSIAM will print everything you return different than 'ok' as
    # an error
    try:
        alert_status = params.get('alert_status', None)
        alert_type = params.get('alert_type', None)

        fetch_events(
            client=client,
            max_results=1,
            last_run={},
            first_fetch_time=first_fetch_time,
            alert_status=alert_status,
            alert_type=alert_type
        )

    except Exception as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def fetch_events(client: Client, max_results: int, last_run: Dict[str, int],
                 first_fetch_time: Optional[int], alert_status: Optional[str], alert_type: Optional[str]
                 ) -> Tuple[Dict[str, int], List[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that events are fetched only onces and no events are missed.
    By default it's invoked by XSIAM every minute. It will use last_run to save the timestamp of the last event it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): HelloWorld client to use.
        max_results (int): Maximum numbers of events per fetch.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching events.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        alert_type (str): type of alerts to search for. There is no list of predefined types.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
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

    # Initialize an empty list of events to return
    # Each event is a dict with a string as a key
    events: List[Dict[str, Any]] = []

    # Get the CSV list of severities from min_severity

    alerts = client.search_alerts(
        alert_type=alert_type,
        alert_status=alert_status,
        max_results=max_results,
        start_time=last_fetch,
    )

    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the HelloWorld API response
        event_created_time = int(alert.get('created', '0'))
        event_created_time_ms = event_created_time * 1000

        # to prevent duplicates, we are only adding events with creation_time > last fetched event
        if last_fetch:
            if event_created_time <= last_fetch:
                continue

        # If no name is present it will throw an exception
        event_name = alert['name']

        # INTEGRATION DEVELOPER TIP
        # The event dict is initialized with a few mandatory fields:
        # name: the event name
        # occurred: the time on when the event occurred, in ISO8601 format
        # we use timestamp_to_datestring() from CommonServerPython.py to
        # handle the conversion.
        # rawJSON: everything else is packed in a string via json.dumps()
        # and is included in rawJSON. It will be used later for classification
        # and mapping inside XSIAM.
        # severity: it's not mandatory, but is recommended. It must be
        # converted to XSIAM specific severity (int 1 to 4)
        # Note that there are other fields commented out here. You can do some
        # mapping of fields (either out of the box fields, like "details" and
        # "type") or custom fields (like "helloworldid") directly here in the
        # code, or they can be handled in the classification and mapping phase.
        # In either case customers can override them. We leave the values
        # commented out here, but you can use them if you want.
        event = {
            'name': event_name,
            # 'details': alert['name'],
            'occurred': timestamp_to_datestring(event_created_time_ms),
            'rawJSON': json.dumps(alert),
            # 'CustomFields': {  # Map specific XSIAM Custom Fields
            #     'helloworldid': alert.get('alert_id'),
            #     'helloworldstatus': alert.get('alert_status'),
            #     'helloworldtype': alert.get('alert_type')
            # }
        }

        events.append(event)

        # Update last run and add event if the event is newer than last fetch
        if event_created_time > latest_created_time:
            latest_created_time = event_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, events


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey')

    # get the service API url
    base_url = urljoin(params.get('url'), '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params, first_fetch_timestamp)
            return_results(result)

        elif command in ('hello-world-get-events', 'fetch-events'):
            if command == 'hello-world-get-events':
                pass
                # events, results = todo
                # return_results(results)

            else:  # command == 'fetch-events':
                # Set and define the fetch events command to run after activated via integration settings.
                alert_status = params.get('alert_status', None)
                alert_type = params.get('alert_type', None)

                # Convert the argument to an int using helper function
                max_results = arg_to_number(arg=params.get('max_fetch'))

                next_run, events = fetch_events(
                    client=client,
                    max_results=max_results,
                    last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                    first_fetch_time=first_fetch_timestamp,
                    alert_status=alert_status,
                    alert_type=alert_type
                )

                # saves next_run for the time fetch-events is invoked
                demisto.setLastRun(next_run)

            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(
                    events,
                    vendor=VENDOR,
                    product=PRODUCT
                )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
