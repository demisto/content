import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""HelloWorld Integration for Cortex XSOAR (aka Demisto)

This integration is a good example on you can build a Cortex XSOAR Integration
using Python 3. Please follow the documentation links below and make sure that
your integration follows the Code Conventions and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

When building a Cortex XSOAR integration that is reusable, a lot of effort
must be placed in the design. We recommend to fill a Design Document template,
that allows you to capture Use Cases, Requirements and Inputs/Outputs.

Example Design document for the this Integration (HelloWorld):
https://docs.google.com/document/d/1wETtBEKg37PHNU8tYeB56M1LE314ux086z3HFeF_cX0


HelloWorld API
--------------

The HelloWorld API is a simple API that shows a realistic use case for an XSOAR
integration. It's actually a real API that is available to the following URL:
https://soar.mastersofhack.com - if you need an API Key to test it out please
reach out to your Cortex XSOAR contacts.

This API has a few basic functions:
- Alerts: the endpoint returns mocked alerts and allows you to search based on
a number of parameters, such as state (ACTIVE or CLOSED), type, timestamp. It
can also return a single alert by ID. This is used to create new Incidents in
XSOAR by using the ``fetch-incidents`` command, which is by default invoked
every minute.
There is also an endpoint that allows to retrieve additional details about a
specific alert by ID, and one to change the alert status to "CLOSED" once
it has been resolved.

- Reputation (ip and domain): these endpoints return, for an IP and
domain respectively, a WHOIS lookup of the entity as well as a reputation score
(from 0 to 100) that is used to determine whether the entity is malicious. This
endpoint is called by XSOAR reputation commands ``ip`` and ``domain`` that
are run automatically every time an indicator is extracted in XSOAR. As a best
practice of design, it is important to map and document the mapping between
a score in the original API format (0 to 100 in this case) to a score in XSOAR
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
a module that is not part of the default XSOAR Docker images, you can add
a custom one. More details: https://xsoar.pan.dev/docs/integrations/docker

There are also internal imports that are used by XSOAR:
- demistomock (imported as demisto): allows your code to work offline for
testing. The actual ``demisto`` module is provided at runtime when the
code runs in XSOAR.
- CommonServerPython.py: contains a set of helper functions, base classes
and other useful components that will make your integration code easier
to maintain.
- CommonServerUserPython.py: includes a set of user defined commands that
are specific to an XSOAR installation. Do not use it for integrations that
are meant to be shared externally.

These imports are automatically loaded at runtime within the XSOAR script
runner, so you shouldn't modify them

Constants
---------

Usually some constants that do not require user parameters or inputs, such
as the default API entry point for your service, or the maximum numbers of
incidents to fetch every time.


Client Class
------------

We recommend to use a Client class to wrap all the code that needs to interact
with your API. Moreover, we recommend, when possible, to inherit from the
BaseClient class, defined in CommonServerPython.py. This class already handles
a lot of the work, such as system proxy settings, SSL certificate verification
and exception handling for HTTP errors.

Note that the Client class should NOT contain any Cortex XSOAR specific code,
i.e. it shouldn't use anything in the ``demisto`` class (functions such as
``demisto.args()`` or ``demisto.results()`` or even ``return_results`` and
``return_error``.
You will use the Command Functions to handle XSOAR inputs and outputs.

When calling an API, you should use the ``_http.request()`` method and you
can return the raw data to the calling function (usually a Command function).

You should usually have one function for each API endpoint.

Look at the code and the commends of this specific class to better understand
the implementation details.


Helper Functions
----------------

Helper functions are usually used as utility functions that are used by several
command functions throughout your code. For example they map arguments to types
or convert severity formats from integration-specific to XSOAR.
Many helper functions are already defined in ``CommonServerPython.py`` and are
often very handy.


Command Functions
-----------------

Command functions perform the mapping between XSOAR inputs and outputs to the
Client class functions inputs and outputs. As a best practice, they shouldn't
contain calls to ``demisto.args()``, ``demisto.results()``, ``return_error``
and ``demisto.command()`` as those should be handled through the ``main()``
function.
However, in command functions, use ``demisto`` or ``CommonServerPython.py``
artifacts, such as ``demisto.debug()`` or the ``CommandResults`` class and the
``Common.*`` classes.
Usually you will have one command function for every specific XSOAR command
you want to implement in your integration, plus ``test-module``,
``fetch-incidents`` and ``fetch-indicators``(if the latter two are supported
by your integration). Each command function should invoke one specific function
of the Client class.

Command functions, when invoked through an XSOAR command usually return data
using the ``CommandResults`` class, that is then passed to ``return_results()``
in the ``main()`` function.
``return_results()`` is defined in ``CommonServerPython.py`` to return
the data to XSOAR. ``return_results()`` actually wraps ``demisto.results()``.
You should never use ``demisto.results()`` directly.

Sometimes you will need to return values in a format that is not compatible
with ``CommandResults`` (for example files): in that case you must return a
data structure that is then pass passed to ``return.results()``. (i.e.
check the ``scan_results_command`` function in this file that has the option
to return a file to Cortex XSOAR).

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

- Context Output: this is the machine readable data, JSON based, that XSOAR can
parse and manage in the Playbooks or Incident's War Room. The Context Output
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
``fetch_incidents()``with the right parameters and passes the outputs to the
``demisto.incidents()`` function. ``main()`` also catches exceptions and
returns an error message via ``return_error()``.


Entry Point
-----------

This is the integration code entry point. It checks whether the ``__name__``
variable is ``__main__`` , ``__builtin__`` (for Python 2) or ``builtins`` (for
Python 3) and then calls the ``main()`` function. Just keep this convention.

"""
import json
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dateparser
import urllib3

from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
DEFAULT_INDICATORS_THRESHOLD = 65
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
LIMIT = 10

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

#     def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
#         """Gets the IP reputation using the '/ip' API endpoint
#
#         Args:
#             ip (str): IP address to get the reputation for.
#
#         Returns:
#             dict: dict containing the IP reputation as returned from the API
#         """
#         mocked_response = {}
#         return mocked_response
#
#     def search_alerts(self, alert_status: Optional[str], severity: Optional[str],
#                       alert_type: Optional[str], max_results: Optional[int],
#                       start_time: Optional[int]) -> List[Dict[str, Any]]:
#         """
#         Searches for HelloWorld alerts using the '/get_alerts' API endpoint.
#         All the parameters are passed directly to the API as HTTP POST parameters in the request
#
#         Args:
#             alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'
#             severity (str): severity of the alert to search for. Comma-separated values. Options are: "Low", "Medium",
#                 "High", "Critical".
#             alert_type (str): type of alerts to search for. There is no list of predefined types.
#             max_results (int): maximum number of results to return.
#             start_time (int): start timestamp (epoch in seconds) for the alert search.
#
#         Returns:
#             list: list of HelloWorld alerts as dicts.
#         """
#
#         request_params: Dict[str, Any] = {}
#
#         if alert_status:
#             request_params['alert_status'] = alert_status
#
#         if alert_type:
#             request_params['alert_type'] = alert_type
#
#         if severity:
#             request_params['severity'] = severity
#
#         if max_results:
#             request_params['max_results'] = max_results
#
#         if start_time:
#             request_params['start_time'] = start_time
#
#         return self._http_request(
#             method='GET',
#             url_suffix='/get_alerts',
#             params=request_params
#         )
#
#         """Gets the results of a HelloWorld scan
#
#         Args:
#             scan_id (str): ID of the scan to retrieve results for.
#
#         Returns:
#             dict: dict containing the scan results as returned from the API.
#         """
#
#         return self._http_request(
#             method='GET',
#             url_suffix='/get_scan_results',
#             params={
#                 'scan_id': scan_id
#             }
#         )

    def say_hello(self, name: str) -> str:
        """
        Returns a string: 'Hello {name}'

        Args:
            name (str): name to append to the 'Hello' string.

        Returns:
            str: string containing 'Hello {name}'
        """

        return f'Hello {name}'

    def get_incident_list(self, page_size, cursor: str = None) -> dict:
        params = {"per_page": page_size}
        if cursor:
            params['cursor'] = cursor

        return self._http_request(
            method='GET',
            url_suffix='v1/incidents/secrets',
            params=params
        )

    def get_incident(self, incident_id: int) -> dict:
        return self._http_request(
            method='GET',
            url_suffix=f'v1/incidents/secrets/{incident_id}'
        )


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: str) -> int:
    """
    Maps HelloWorld severity to Cortex XSOAR severity.
    Converts the HelloWorld alert severity level ('Low', 'Medium', 'High', 'Critical') to Cortex XSOAR incident
    severity (1 to 4).

    Args:
        severity (str): severity as returned from the HelloWorld API.
        first_fetch_time (int): The first fetch time as configured in the integration params.

    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH,
        'Critical': IncidentSeverity.CRITICAL
    }[severity]


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
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        if params.get('isFetch'):  # Tests fetch incident:
            alert_status = params.get('alert_status', None)
            alert_type = params.get('alert_type', None)
            min_severity = params.get('min_severity', None)

            fetch_incidents(
                client=client,
                max_results=1,
                last_run={},
                first_fetch_time=first_fetch_time,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )
        else:
            client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None,
                                 severity=None)

    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


# def say_hello_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    helloworld-say-hello command: Returns Hello {somename}

    Args:
        client (Client): HelloWorld client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['name']`` is used as input name.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that hello world message.
    """

    # INTEGRATION DEVELOPER TIP
    # In this case 'name' is an argument set in the HelloWorld.yml file as mandatory,
    # so the null check here as XSOAR will always check it before your code is called.
    # Although it's not mandatory to check, you are welcome to do so.

    name = args.get('name', None)
    if not name:
        raise ValueError('name not specified')

    # Call the Client function and get the raw response
    result = client.say_hello(name)

    # Create the human readable output.
    # It will  be in markdown format - https://www.markdownguide.org/basic-syntax/
    # More complex output can be formatted using ``tableToMarkDown()`` defined
    # in ``CommonServerPython.py``
    readable_output = f'## {result}'

    # More information about Context:
    # https://xsoar.pan.dev/docs/integrations/context-and-outputs
    # We return a ``CommandResults`` object, and we want to pass a custom
    # markdown here, so the argument ``readable_output`` is explicit. If not
    # passed, ``CommandResults``` will do a ``tableToMarkdown()`` do the data
    # to generate the readable output.
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='hello',
        outputs_key_field='',
        outputs=result
    )


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], alert_status: Optional[str],
                    min_severity: str, alert_type: Optional[str]
                    ) -> Tuple[Dict[str, int], List[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that incidents are fetched only onces and no incidents are missed.
    By default it's invoked by XSOAR every minute. It will use last_run to save the timestamp of the last incident it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): HelloWorld client to use.
        max_results (int): Maximum numbers of incidents per fetch.
        last_run (dict): A dict with a key containing the latest incident created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching incidents.
        alert_status (str): status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'.
        min_severity (str): minimum severity of the alert to search for. Options are: "Low", "Medium", "High" and
            "Critical".
        alert_type (str): type of alerts to search for. There is no list of predefined types.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of incidents that will be created in XSOAR.
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
    incidents: List[Dict[str, Any]] = []

    # Get the CSV list of severities from min_severity
    severity = ','.join(HELLOWORLD_SEVERITIES[HELLOWORLD_SEVERITIES.index(min_severity):])

    alerts = client.search_alerts(
        alert_type=alert_type,
        alert_status=alert_status,
        max_results=max_results,
        start_time=last_fetch,
        severity=severity
    )

    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the HelloWorld API response
        incident_created_time = int(alert.get('created', '0'))
        incident_created_time_ms = incident_created_time * 1000

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue

        # If no name is present it will throw an exception
        incident_name = alert['name']

        # INTEGRATION DEVELOPER TIP
        # The incident dict is initialized with a few mandatory fields:
        # name: the incident name
        # occurred: the time on when the incident occurred, in ISO8601 format
        # we use timestamp_to_datestring() from CommonServerPython.py to
        # handle the conversion.
        # rawJSON: everything else is packed in a string via json.dumps()
        # and is included in rawJSON. It will be used later for classification
        # and mapping inside XSOAR.
        # severity: it's not mandatory, but is recommended. It must be
        # converted to XSOAR specific severity (int 1 to 4)
        # Note that there are other fields commented out here. You can do some
        # mapping of fields (either out of the box fields, like "details" and
        # "type") or custom fields (like "helloworldid") directly here in the
        # code, or they can be handled in the classification and mapping phase.
        # In either case customers can override them. We leave the values
        # commented out here, but you can use them if you want.
        incident = {
            'name': incident_name,
            # 'details': alert['name'],
            'occurred': timestamp_to_datestring(incident_created_time_ms),
            'rawJSON': json.dumps(alert),
            # 'type': 'Hello World Alert',  # Map to a specific XSOAR incident Type
            'severity': convert_to_demisto_severity(alert.get('severity', 'Low')),
            # 'CustomFields': {  # Map specific XSOAR Custom Fields
            #     'helloworldid': alert.get('alert_id'),
            #     'helloworldstatus': alert.get('alert_status'),
            #     'helloworldtype': alert.get('alert_type')
            # }
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def ip_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int,
                          reliability: DBotScoreReliability) -> List[CommandResults]:
    """
    ip command: Returns IP reputation for a list of IPs

    Args:
        client (Client): HelloWorld client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['ip']`` is a list of IPs or a single IP.
            ``args['threshold']`` threshold to determine whether an IP is malicious.
        default_threshold (int): default threshold to determine whether an IP is malicious if threshold is not
            specified in the XSOAR arguments.
        reliability (DBotScoreReliability): reliability of the source providing the intelligence data.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains IPs.
    """

    # INTEGRATION DEVELOPER TIP
    # Reputation commands usually support multiple inputs (i.e. arrays), so
    # they can be invoked once in XSOAR. In this case the API supports a single
    # IP at a time, so we will cycle this for all the members of the array.
    # We use argToList(), implemented in CommonServerPython.py to automatically
    # return a list of a single element even if the provided input is a scalar.

    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    # It's a good practice to document the threshold you use to determine
    # if a score is malicious in your integration documentation.
    # Thresholds should also be possible to override, as in this case,
    # where threshold is an actual argument of the command.
    threshold = int(args.get('threshold', default_threshold))

    # Initialize an empty list of CommandResults to return
    # each CommandResult will contain context standard for IP
    command_results: List[CommandResults] = []

    for ip in ips:
        if not is_ip_valid(ip, accept_v6_ips=True):  # check IP's validity
            raise ValueError(f'IP "{ip}" is not valid')
        ip_data = client.get_ip_reputation(ip)
        ip_data['ip'] = ip

        # This is an example of creating relationships in reputation commands.
        # We will create relationships between indicators only in case that the API returns information about
        # the relationship between two indicators.
        # See https://xsoar.pan.dev/docs/integrations/generic-commands-reputation#relationships

        relationships_list = []
        links = ip_data.get('network', {}).get('links', [])
        for link in links:
            relationships_list.append(EntityRelationship(
                entity_a=ip,
                entity_a_type=FeedIndicatorType.IP,
                name='related-to',
                entity_b=link,
                entity_b_type=FeedIndicatorType.URL,
                brand='HelloWorld'))

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        reputation = int(ip_data.get('score', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        # The context is bigger here than other commands, as it consists in 3
        # parts: the vendor-specific context (HelloWorld), the standard-context
        # (IP) and the DBotScore.
        # More information:
        # https://xsoar.pan.dev/docs/integrations/context-and-outputs
        # https://xsoar.pan.dev/docs/integrations/context-standards
        # https://xsoar.pan.dev/docs/integrations/dbot
        # Also check the HelloWorld Design Document

        # Create the DBotScore structure first using the Common.DBotScore class.
        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name='HelloWorld',
            score=score,
            malicious_description=f'Hello World returned reputation {reputation}',
            reliability=reliability
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(
            ip=ip,
            asn=ip_data.get('asn'),
            dbot_score=dbot_score,
            relationships=relationships_list
        )

        # INTEGRATION DEVELOPER TIP
        # In the integration specific Context output (HelloWorld.IP) in this
        # example you want to provide a lot of information as it can be used
        # programmatically from within Cortex XSOAR in playbooks and commands.
        # On the other hand, this API is way to verbose, so we want to select
        # only certain keys to be returned in order not to clog the context
        # with useless information. What to actually return in the context and
        # to define as a command output is subject to design considerations.

        # INTEGRATION DEVELOPER TIP
        # To generate the Context Outputs on the YML use ``demisto-sdk``'s
        # ``json-to-outputs`` option.

        # Define which fields we want to exclude from the context output as
        # they are too verbose.
        ip_context_excluded_fields = ['objects', 'nir']
        ip_data = {k: ip_data[k] for k in ip_data if k not in ip_context_excluded_fields}

        # In this case we want to use an custom markdown to specify the table title,
        # but otherwise ``CommandResults()`` will call ``tableToMarkdown()``
        #  automatically
        readable_output = tableToMarkdown('IP', ip_data)

        # INTEGRATION DEVELOPER TIP
        # The output key will be ``HelloWorld.IP``, using ``ip`` as the key field.
        # ``indicator`` is used to provide the context standard (IP)
        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='HelloWorld.IP',
            outputs_key_field='ip',
            outputs=ip_data,
            indicator=ip_standard_context,
            relationships=relationships_list
        ))
    return command_results


# def search_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    helloworld-search-alerts command: Search alerts in HelloWorld

    Args:
        client (Client): HelloWorld client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['status']`` alert status. Options are 'ACTIVE' or 'CLOSED'.
            ``args['severity']`` alert severity CSV.
            ``args['alert_type']`` alert type.
            ``args['start_time']``  start time as ISO8601 date or seconds since epoch.
            ``args['max_results']`` maximum number of results to return.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains an alerts.
    """

    status = args.get('status')

    # Check if severity contains allowed values, use all if default
    severities: List[str] = HELLOWORLD_SEVERITIES
    severity = args.get('severity', None)
    if severity:
        severities = severity.split(',')
        if not all(s in HELLOWORLD_SEVERITIES for s in severities):
            raise ValueError(
                f'severity must be a comma-separated value '
                f'with the following options: {",".join(HELLOWORLD_SEVERITIES)}')

    alert_type = args.get('alert_type')

    # Convert the argument to a timestamp using helper function
    start_time = arg_to_datetime(
        arg=args.get('start_time'),
        arg_name='start_time',
        required=False
    )

    # Convert the argument to an int using helper function
    max_results = arg_to_number(
        arg=args.get('max_results'),
        arg_name='max_results',
        required=False
    )

    # Severity is passed to the API as a CSV
    alerts = client.search_alerts(
        severity=','.join(severities),
        alert_status=status,
        alert_type=alert_type,
        start_time=int(start_time.timestamp()) if start_time else None,
        max_results=max_results
    )

    # INTEGRATION DEVELOPER TIP
    # We want to convert the "created" time from timestamp(s) to ISO8601 as
    # Cortex XSOAR customers and integrations use this format by default
    for alert in alerts:
        if 'created' not in alert:
            continue
        created_time_ms = int(alert.get('created', '0')) * 1000
        alert['created'] = timestamp_to_datestring(created_time_ms)

    # in this example we are not providing a custom markdown, we will
    # let ``CommandResults`` generate it by default.
    return CommandResults(
        outputs_prefix='HelloWorld.Alert',
        outputs_key_field='alert_id',
        outputs=alerts
    )


def incident_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_id = arg_to_number(args.get("incident_id"))
    page_size = arg_to_number(args.get("limit") or LIMIT)
    cursor = args.get("next_token")

    if incident_id:
        res = client.get_incident(incident_id)
    else:
        res = client.get_incident_list(page_size=page_size, cursor=cursor)
    if not isinstance(res, list):
        res = [res]
    readable_output = tableToMarkdown('Incident List', res)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Incident',
        outputs_key_field='id',
        outputs=res
    )


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('credentials', {}).get('password')

    # get the service API url
    base_url = params.get('url')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # How much time before the first fetch to retrieve incidents
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

    # Integration that implements reputation commands (e.g. url, ip, domain,..., etc) must have
    # a reliability score of the source providing the intelligence data.
    reliability = params.get('integrationReliability', DBotScoreReliability.C)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'Authorization': f'Token {api_key}'
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

        elif command == 'ip':
            default_threshold_ip = arg_to_number(params.get('threshold_ip')) or DEFAULT_INDICATORS_THRESHOLD
            return_results(dummy_ip_reputation_command(client, args, default_threshold_ip, reliability))

        elif command == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = params.get('alert_status', None)
            alert_type = params.get('alert_type', None)
            min_severity = params.get('min_severity', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=params.get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif command == 'helloworld-incident-list':
            return_results(incident_list_command(client, args))

#         elif command == 'helloworld-incident-note-list':
#             return_results(incident_note_list_command(client, args))
#
#         elif command == 'helloworld-incident-note-create':
#             return_results(incident - note - create_command(client, args))
#
#         elif command == 'helloworld-file-scan-start':
            return_results(file - scan - start_command(client, args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
