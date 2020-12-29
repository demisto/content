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
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Gets the IP reputation using the '/ip' API endpoint

        :type ip: ``str``
        :param ip: IP address to get the reputation for

        :return: dict containing the IP reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/ip',
            params={
                'ip': ip
            }
        )

    def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Gets the Domain reputation using the '/domain' API endpoint

        :type domain: ``str``
        :param domain: domain name to get the reputation for

        :return: dict containing the domain reputation as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/domain',
            params={
                'domain': domain
            }
        )

    def search_alerts(self, alert_status: Optional[str], severity: Optional[str],
                      alert_type: Optional[str], max_results: Optional[int],
                      start_time: Optional[int]) -> List[Dict[str, Any]]:
        """Searches for HelloWorld alerts using the '/get_alerts' API endpoint

        All the parameters are passed directly to the API as HTTP POST parameters in the request

        :type alert_status: ``Optional[str]``
        :param alert_status: status of the alert to search for. Options are: 'ACTIVE' or 'CLOSED'

        :type severity: ``Optional[str]``
        :param severity:
            severity of the alert to search for. Comma-separated values.
            Options are: "Low", "Medium", "High", "Critical"

        :type alert_type: ``Optional[str]``
        :param alert_type: type of alerts to search for. There is no list of predefined types

        :type max_results: ``Optional[int]``
        :param max_results: maximum number of results to return

        :type start_time: ``Optional[int]``
        :param start_time: start timestamp (epoch in seconds) for the alert search

        :return: list containing the found HelloWorld alerts as dicts
        :rtype: ``List[Dict[str, Any]]``
        """

        request_params: Dict[str, Any] = {}

        if alert_status:
            request_params['alert_status'] = alert_status

        if alert_type:
            request_params['alert_type'] = alert_type

        if severity:
            request_params['severity'] = severity

        if max_results:
            request_params['max_results'] = max_results

        if start_time:
            request_params['start_time'] = start_time

        return self._http_request(
            method='GET',
            url_suffix='/get_alerts',
            params=request_params
        )

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Gets a specific HelloWorld alert by id

        :type alert_id: ``str``
        :param alert_id: id of the alert to return

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/get_alert_details',
            params={
                'alert_id': alert_id
            }
        )

    def update_alert_status(self, alert_id: str, alert_status: str) -> Dict[str, Any]:
        """Changes the status of a specific HelloWorld alert

        :type alert_id: ``str``
        :param alert_id: id of the alert to return

        :type alert_status: ``str``
        :param alert_status: new alert status. Options are: 'ACTIVE' or 'CLOSED'

        :return: dict containing the alert as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/change_alert_status',
            params={
                'alert_id': alert_id,
                'alert_status': alert_status
            }
        )

    def scan_start(self, hostname: str) -> Dict[str, Any]:
        """Starts a HelloWorld scan on a specific hostname

        :type hostname: ``str``
        :param hostname: hostname of the machine to scan

        :return: dict containing the scan status as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/start_scan',
            params={
                'hostname': hostname
            }
        )

    def scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Gets the status of a HelloWorld scan

        :type scan_id: ``str``
        :param scan_id: ID of the scan to retrieve status for

        :return: dict containing the scan status as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/check_scan',
            params={
                'scan_id': scan_id
            }
        )

    def scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Gets the results of a HelloWorld scan

        :type scan_id: ``str``
        :param scan_id: ID of the scan to retrieve results for

        :return: dict containing the scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """

        return self._http_request(
            method='GET',
            url_suffix='/get_scan_results',
            params={
                'scan_id': scan_id
            }
        )

    def say_hello(self, name: str) -> str:
        """Returns 'Hello {name}'

        :type name: ``str``
        :param name: name to append to the 'Hello' string

        :return: string containing 'Hello {name}'
        :rtype: ``str``
        """

        return f'Hello {name}'


''' HELPER FUNCTIONS '''


def parse_domain_date(domain_date: Union[List[str], str], date_format: str = '%Y-%m-%dT%H:%M:%S.000Z') -> Optional[str]:
    """Converts whois date format to an ISO8601 string

    Converts the HelloWorld domain WHOIS date (YYYY-mm-dd HH:MM:SS) format
    in a datetime. If a list is returned with multiple elements, takes only
    the first one.

    :type domain_date: ``Union[List[str],str]``
    :param date_format:
        a string or list of strings with the format 'YYYY-mm-DD HH:MM:SS'

    :return: Parsed time in ISO8601 format
    :rtype: ``Optional[str]``
    """

    if isinstance(domain_date, str):
        # if str parse the value
        domain_date_dt = dateparser.parse(domain_date)
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    elif isinstance(domain_date, list) and len(domain_date) > 0 and isinstance(domain_date[0], str):
        # if list with at least one element, parse the first element
        domain_date_dt = dateparser.parse(domain_date[0])
        if domain_date_dt:
            return domain_date_dt.strftime(date_format)
    # in any other case return nothing
    return None


def convert_to_demisto_severity(severity: str) -> int:
    """Maps HelloWorld severity to Cortex XSOAR severity

    Converts the HelloWorld alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
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
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH,
        'Critical': IncidentSeverity.CRITICAL
    }[severity]


''' COMMAND FUNCTIONS '''


def test_module(client: Client, first_fetch_time: int) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type name: ``str``
    :param name: name to append to the 'Hello' string

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
    try:
        client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None,
                             severity=None)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def say_hello_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-say-hello command: Returns Hello {somename}

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``str``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['name']`` is used as input name

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the hello world message

    :rtype: ``CommandResults``
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
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch_time to determine when to start fetching
    the first time.

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

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
        status of the alert to search for. Options are: 'ACTIVE'
        or 'CLOSED'

    :type min_severity: ``str``
    :param min_severity:
        minimum severity of the alert to search for.
        Options are: "Low", "Medium", "High", "Critical"

    :type alert_type: ``Optional[str]``
    :param alert_type:
        type of alerts to search for. There is no list of predefined types

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


def ip_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> List[CommandResults]:
    """ip command: Returns IP reputation for a list of IPs

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['ip']`` is a list of IPs or a single IP
        ``args['threshold']`` threshold to determine whether an IP is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an IP is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains IPs

    :rtype: ``CommandResults``
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
        ip_data = client.get_ip_reputation(ip)
        ip_data['ip'] = ip

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        score = 0
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
            malicious_description=f'Hello World returned reputation {reputation}'
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(
            ip=ip,
            asn=ip_data.get('asn'),
            dbot_score=dbot_score
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
            indicator=ip_standard_context
        ))
    return command_results


def domain_reputation_command(client: Client, args: Dict[str, Any], default_threshold: int) -> List[CommandResults]:
    """domain command: Returns domain reputation for a list of domains

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['domain']`` list of domains or a single domain
        ``args['threshold']`` threshold to determine whether a domain is malicious

    :type default_threshold: ``int``
    :param default_threshold:
        default threshold to determine whether an domain is malicious
        if threshold is not specified in the XSOAR arguments

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Domains

    :rtype: ``CommandResults``
    """

    # INTEGRATION DEVELOPER TIP
    # Reputation commands usually support multiple inputs (i.e. arrays), so
    # they can be invoked once in XSOAR. In this case the API supports a single
    # IP at a time, so we will cycle this for all the members of the array.
    # We use argToList(), implemented in CommonServerPython.py to automatically
    # return a list of a single element even if the provided input is a scalar.

    domains = argToList(args.get('domain'))
    if len(domains) == 0:
        raise ValueError('domain(s) not specified')

    threshold = int(args.get('threshold', default_threshold))

    # Initialize an empty list of CommandResults to return,
    # each CommandResult will contain context standard for Domain
    command_results: List[CommandResults] = []

    for domain in domains:
        domain_data = client.get_domain_reputation(domain)
        domain_data['domain'] = domain

        # INTEGRATION DEVELOPER TIP
        # We want to convert the dates to ISO8601 as
        # Cortex XSOAR customers and integrations use this format by default
        if 'creation_date' in domain_data:
            domain_data['creation_date'] = parse_domain_date(domain_data['creation_date'])
        if 'expiration_date' in domain_data:
            domain_data['expiration_date'] = parse_domain_date(domain_data['expiration_date'])
        if 'updated_date' in domain_data:
            domain_data['updated_date'] = parse_domain_date(domain_data['updated_date'])

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        score = 0
        reputation = int(domain_data.get('score', 0))
        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation >= threshold:
            score = Common.DBotScore.BAD  # bad
        elif reputation >= threshold / 2:
            score = Common.DBotScore.SUSPICIOUS  # suspicious
        else:
            score = Common.DBotScore.GOOD  # good

        # INTEGRATION DEVELOPER TIP
        # The context is bigger here than other commands, as it consists in 3
        # parts: the vendor-specific context (HelloWorld), the standard-context
        # (Domain) and the DBotScore.
        # More information:
        # https://xsoar.pan.dev/docs/integrations/context-and-outputs
        # https://xsoar.pan.dev/docs/integrations/context-standards
        # https://xsoar.pan.dev/docs/integrations/dbot
        # Also check the sample Design Document

        dbot_score = Common.DBotScore(
            indicator=domain,
            integration_name='HelloWorld',
            indicator_type=DBotScoreType.DOMAIN,
            score=score,
            malicious_description=f'Hello World returned reputation {reputation}'
        )

        # Create the Domain Standard Context structure using Common.Domain and
        # add dbot_score to it.
        domain_standard_context = Common.Domain(
            domain=domain,
            creation_date=domain_data.get('creation_date', None),
            expiration_date=domain_data.get('expiration_date', None),
            updated_date=domain_data.get('updated_date', None),
            organization=domain_data.get('org', None),
            name_servers=domain_data.get('name_servers', None),
            registrant_name=domain_data.get('name', None),
            registrant_country=domain_data.get('country', None),
            registrar_name=domain_data.get('registrar', None),
            dbot_score=dbot_score
        )

        # In this case we want to use an custom markdown to specify the table title,
        # but otherwise ``CommandResults()`` will call ``tableToMarkdown()``
        #  automatically
        readable_output = tableToMarkdown('Domain', domain_data)

        # INTEGRATION DEVELOPER TIP
        # The output key will be ``HelloWorld.Domain``, using ``domain`` as the key
        # field.
        # ``indicator`` is used to provide the context standard (Domain)
        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='HelloWorld.Domain',
            outputs_key_field='domain',
            outputs=domain_data,
            indicator=domain_standard_context
        ))
    return command_results


def search_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-search-alerts command: Search alerts in HelloWorld

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['status']`` alert status. Options are 'ACTIVE' or 'CLOSED'
        ``args['severity']`` alert severity CSV
        ``args['alert_type']`` alert type
        ``args['start_time']``  start time as ISO8601 date or seconds since epoch
        ``args['max_results']`` maximum number of results to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains alerts

    :rtype: ``CommandResults``
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


def get_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-get-alert command: Returns a HelloWorld alert

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to return

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an alert

    :rtype: ``CommandResults``
    """

    alert_id = args.get('alert_id', None)
    if not alert_id:
        raise ValueError('alert_id not specified')

    alert = client.get_alert(alert_id=alert_id)

    # INTEGRATION DEVELOPER TIP
    # We want to convert the "created" time from timestamp(s) to ISO8601 as
    # Cortex XSOAR customers and integrations use this format by default
    if 'created' in alert:
        created_time_ms = int(alert.get('created', '0')) * 1000
        alert['created'] = timestamp_to_datestring(created_time_ms)

    # tableToMarkdown() is defined is CommonServerPython.py and is used very
    # often to convert lists and dicts into a human readable format in markdown
    readable_output = tableToMarkdown(f'HelloWorld Alert {alert_id}', alert)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Alert',
        outputs_key_field='alert_id',
        outputs=alert
    )


def update_alert_status_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-update-alert-status command: Changes the status of an alert

    Changes the status of a HelloWorld alert and returns the updated alert info

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['alert_id']`` alert ID to update
        ``args['status']`` new status, either ACTIVE or CLOSED

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an updated alert

    :rtype: ``CommandResults``
    """

    alert_id = args.get('alert_id', None)
    if not alert_id:
        raise ValueError('alert_id not specified')

    status = args.get('status', None)
    if status not in ('ACTIVE', 'CLOSED'):
        raise ValueError('status must be either ACTIVE or CLOSED')

    alert = client.update_alert_status(alert_id, status)

    # INTEGRATION DEVELOPER TIP
    # We want to convert the "updated" time from timestamp(s) to ISO8601 as
    # Cortex XSOAR customers and integrations use this format by default
    if 'updated' in alert:
        updated_time_ms = int(alert.get('updated', '0')) * 1000
        alert['updated'] = timestamp_to_datestring(updated_time_ms)

    # tableToMarkdown() is defined is CommonServerPython.py and is used very
    # often to convert lists and dicts into a human readable format in markdown
    readable_output = tableToMarkdown(f'HelloWorld Alert {alert_id}', alert)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Alert',
        outputs_key_field='alert_id',
        outputs=alert
    )


def scan_start_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-start-scan command: Starts a HelloWorld scan

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['hostname']`` hostname to run the scan on

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan job

    :rtype: ``CommandResults``
    """

    hostname = args.get('hostname', None)
    if not hostname:
        raise ValueError('hostname not specified')

    scan = client.scan_start(hostname=hostname)

    # INTEGRATION DEVELOPER TIP
    # The API doesn't return the hostname of the scan it was called against,
    # which is the input. It could be useful to have that information in the
    # XSOAR context, so we are adding it manually here, based on the command
    # input argument.
    scan['hostname'] = hostname

    scan_id = scan.get('scan_id')

    readable_output = f'Started scan {scan_id}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Scan',
        outputs_key_field='scan_id',
        outputs=scan
    )


def scan_status_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """helloworld-scan-status command: Returns status for HelloWorld scans

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['scan_id']`` list of scan IDs or single scan ID

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``
    """

    scan_id_list = argToList(args.get('scan_id', []))
    if len(scan_id_list) == 0:
        raise ValueError('scan_id(s) not specified')

    scan_list: List[Dict[str, Any]] = []
    for scan_id in scan_id_list:
        scan = client.scan_status(scan_id=scan_id)
        scan_list.append(scan)

    readable_output = tableToMarkdown('Scan status', scan_list)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='HelloWorld.Scan',
        outputs_key_field='scan_id',
        outputs=scan_list
    )


def scan_results_command(client: Client, args: Dict[str, Any]) -> Union[Dict[str, Any], CommandResults, List[CommandResults]]:
    """helloworld-scan-results command: Returns results for a HelloWorld scan

    :type client: ``Client``
    :param Client: HelloWorld client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['scan_id']`` scan ID to retrieve results
        ``args['format']`` format of the results. Options are 'file' or 'json'

    :return:
        A ``CommandResults`` compatible to return ``return_results()``,
        that contains a scan result when json format is selected, or
        A Dict of entries also compatible to ``return_results()`` that
        contains the output file when file format is selected.

    :rtype: ``Union[Dict[str, Any],CommandResults]``
    """

    scan_id = args.get('scan_id', None)
    if not scan_id:
        raise ValueError('scan_id not specified')

    scan_format = args.get('format', 'file')

    # INTEGRATION DEVELOPER TIP
    # This function supports returning data in multiple formats, either in a json
    # format that is then mapped to a table, or as a file attachment.
    # In this case, if the format is "file", the return value is different and
    # uses a raw format  and ``fileResult()`` directly instead of
    # ``CommandResults``. In either case you should return data to main and
    # call ``return_results()`` from there.
    # Always use ``CommandResults`` when possible but, if you need to return
    # anything special like a file, you can use this raw format.

    results = client.scan_results(scan_id=scan_id)
    if scan_format == 'file':
        return (
            fileResult(
                filename=f'{scan_id}.json',
                data=json.dumps(results, indent=4),
                file_type=entryTypes['entryInfoFile']
            )
        )
    elif scan_format == 'json':
        # This scan returns CVE information. CVE is also part of the XSOAR
        # context standard, so we must extract CVE IDs and return them also.
        # See: https://xsoar.pan.dev/docs/integrations/context-standards#cve
        cves: List[Common.CVE] = []
        command_results: List[CommandResults] = []
        entities = results.get('entities', [])
        for e in entities:
            if 'vulns' in e.keys() and isinstance(e['vulns'], list):
                cves.extend([Common.CVE(id=c, cvss=None, published=None, modified=None, description=None) for c in e['vulns']])

        # INTEGRATION DEVELOPER TIP
        # We want to provide a unique result for every CVE indicator.
        # Since every entity may contain several CVE indicators,
        # we will split the entities result and CVE indicator results.
        readable_output = tableToMarkdown(f'Scan {scan_id} results', entities)
        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='HelloWorld.Scan',
            outputs_key_field='scan_id',
            outputs=results
        ))

        cves = list(set(cves))  # make the indicator list unique
        for cve in cves:
            command_results.append(CommandResults(
                readable_output=f"CVE {cve}",
                indicator=cve
            ))
        return command_results
    else:
        raise ValueError('Incorrect format, must be "json" or "file"')


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

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
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, first_fetch_timestamp)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get('alert_status', None)
            alert_type = demisto.params().get('alert_type', None)
            min_severity = demisto.params().get('min_severity', None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=demisto.params().get('max_fetch'),
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
            # of incidents to crate
            demisto.incidents(incidents)

        elif demisto.command() == 'ip':
            default_threshold_ip = int(demisto.params().get('threshold_ip', '65'))
            return_results(ip_reputation_command(client, demisto.args(), default_threshold_ip))

        elif demisto.command() == 'domain':
            default_threshold_domain = int(demisto.params().get('threshold_domain', '65'))
            return_results(domain_reputation_command(client, demisto.args(), default_threshold_domain))

        elif demisto.command() == 'helloworld-say-hello':
            return_results(say_hello_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-search-alerts':
            return_results(search_alerts_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-get-alert':
            return_results(get_alert_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-update-alert-status':
            return_results(update_alert_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-start':
            return_results(scan_start_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-status':
            return_results(scan_status_command(client, demisto.args()))

        elif demisto.command() == 'helloworld-scan-results':
            return_results(scan_results_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
