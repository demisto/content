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
integration.

This API has a few basic functions:
- Alerts: the endpoint returns mocked alerts and allows you to search based on
a number of parameters, such as severity. It
can also return a single alert by ID. This is used to create new alerts in
XSOAR by using the ``fetch-incidents`` command, which is by default invoked
every minute.

- Reputation (ip): this endpoint return a WHOIS lookup of the ip given as well as a reputation score
(from 0 to 100) that is used to determine whether the entity is malicious. This
endpoint is called by XSOAR reputation command ``ip`` that
is run automatically every time an indicator is extracted in XSOAR. As a best
practice of design, it is important to map and document the mapping between
a score in the original API format (0 to 100 in this case) to a score in XSOAR
format (0 to 3). This score is called ``DBotScore``, and is returned in the
context to allow automated handling of indicators based on their reputation.
More information: https://xsoar.pan.dev/docs/integrations/dbot

- Create Note: to demonstrate how to run commands that are not returning instant data,
the API provides a command simulates creating a new entity in the API.
This can be used for endpoints that take longer than a few seconds to complete with the
GenericPolling mechanism to implement the job polling loop. The results
can be returned in JSON or attachment file format.
Info on GenericPolling: https://xsoar.pan.dev/docs/playbooks/generic-polling

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
alerts to fetch every time.


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
data structure that is then pass passed to ``return.results()``.

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
from typing import Any

import dateparser

from CommonServerUserPython import *


""" CONSTANTS """
LOG_LINE = "HelloWorldDebugLog: "  # Make sure to use a line easily to search and read in logs.
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_ALERTS_TO_FETCH = 50
DEFAULT_INDICATORS_THRESHOLD = 65
HELLOWORLD_SEVERITIES = ["Low", "Medium", "High", "Critical"]
LIMIT = 10
DEFAULT_PAGE_SIZE = 5
DUMMY_API_KEY = "dummy-key"
ITEM_TEMPLATE = '"id": {id}, "name": "XSOAR Test Alert #{id}", "severity": "{severity}", "date": "{date}", "status": "{status}"'
""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def specific_api_endpoint_call_example(self, param1, param2):
        """Example of calling a real specific API endpoint"""
        # INTEGRATION DEVELOPER TIP
        # 1. The assign_params function (Found in CommonServerPython) can easily create a None-free dictionary.
        #   Use it to send the ``json_data`` argument to ``self._http_request`` method (request body).
        #   When the request body is complex, best practice is to build the dictionary outside (pass as argument).
        # 2. It's possible to get the whole response and not just the data part, using the ``resp_type`` argument.
        # 3. It's possible to get responses for statuses other than 200 by using the ``ok_codes`` argument-
        #   otherwise, the ``self._http_request method`` will fail when parsing it.
        # 4. If the URL parameters are complex (filters, etc.) -
        #   it is possible to pass them using the ``params`` argument.

        url = f"/api/endpoint/{param1}/{param2}"
        response = self._http_request(method="GET", url=url)

        return response

    def get_ip_reputation(self, ip: str) -> dict[str, Any]:
        """For developing walkthrough purposes, this is a dummy response.
        For real API calls, see the specific_api_endpoint_call_example method.

        Args:
            ip (str): IP address to get the reputation for.

        Returns:
            dict: dict containing the dummy IP reputation for an example ip as it should be returned from the API.
        """
        mocked_response = {
            "attributes": {
                "as_owner": "EMERALD-ONION",
                "asn": 396507,
                "continent": "NA",
                "country": "US",
                "jarm": ":jarm:",
                "last_analysis_stats": {"harmless": 72, "malicious": 5, "suspicious": 2, "timeout": 0, "undetected": 8},
                "last_modification_date": 1613300914,
                "network": ":cidr:",
                "regional_internet_registry": "ARIN",
                "reputation": -4,
                "tags": [],
                "total_votes": {"harmless": 0, "malicious": 1},
                "whois_date": 1611870274,
            },
            "id": "x.x.x.x",
            "links": {"self": "https://www.virustotal.com/api/v3/ip_addresses/x.x.x.x"},
            "type": "ip_address",
        }

        return mocked_response

    def say_hello(self, name: str) -> str:
        """
        Returns a string: 'Hello {name}'

        Args:
            name (str): name to append to the 'Hello' string.

        Returns:
            str: string containing 'Hello {name}'
        """

        return f"Hello {name}"

    def get_alert_list(self, limit: int, severity: str = None, last_id: int = 0) -> list[dict]:
        """For developing walkthrough purposes, this is a dummy response.
           For real API calls, see the specific_api_endpoint_call_example method.

        Args:
            limit (int): The number of item to generate.
            severity (str) : The severity value of the items returned.

        Returns:
            list[dict]: Dummy data of items as it would return from API.
        """
        mock_response: list[dict] = []
        for i in range(limit):
            item = ITEM_TEMPLATE.format(
                id=last_id + i + 1,
                severity=severity if severity else "",
                date=datetime(2023, 9, 14, 11, 30, 39, 882955).isoformat(),
                status="Testing",
            )
            dict_item = json.loads("{" + item + "}")
            mock_response.append(dict_item)

        return mock_response

    def get_alert(self, alert_id: int) -> list[dict]:
        """For developing walkthrough purposes, this is a dummy response.
        For real API calls, see the specific_api_endpoint_call_example method.

        Args:
            alert_id (int) : An alert to retrieve.

        Returns:
            dict: Dummy data of alert as it would return from API.
        """
        item = ITEM_TEMPLATE.format(
            id=alert_id, severity="low", date=datetime(2023, 9, 14, 11, 30, 39, 882955).isoformat(), status="Testing"
        )
        return json.loads("{" + item + "}")

    def create_note(self, alert_id: int, comment: str) -> dict:
        """
        This function calls the API to create a new note in an alert.
        For real API calls, see the specific_api_endpoint_call_example method.

        Args:
            alert_id (int): a number represent an alert.
            comment (str): A text comment to add to the alert as a note.

        Returns:
            dict: The summary of the newly created note from the API response.
        """

        return {"status": "success", "msg": f"Note was created for alert #{alert_id} successfully with {comment=}"}

    def get_alert_list_for_fetch(self, limit, start_time: datetime, last_id: int = 0, severity: str = "low") -> list[dict]:
        """This function return dummy events for fetch.

        Args:
            limit (int): The number of alert to fetch.
            start_time (str, optional): The time to start fetch alerts from. Defaults to None.
            severity (str, optional): The severity of the alerts fetched. Defaults to None.
        """

        def mock_time(item):
            item["id"] = last_id + 1
            item["date"] = datetime.strftime(start_time + timedelta(minutes=1), DATE_FORMAT)

        incidents = self.get_alert_list(limit=limit, severity=severity, last_id=last_id)
        demisto.debug("Setting alerts time to now.")
        for item in incidents:
            mock_time(item)
            last_id += 1
        return incidents


""" HELPER FUNCTIONS """


def validate_api_key(api_key: str) -> None:
    """
    This is a validation that the api-key is valid. It is not needed when dealing with a real API.
    But we wanted to give you a full experience.
    Some APIs handle invalid credentials with an invalid status code with an unclear message, which users will not understand.
    It can be handled in the commands or in the main function when the status code implies incorrect credentials.

    Args:
        api_key (str): api to connect to the API.

    Raises:
        DemistoException: Exception with a nicer error when credential are invalid.
    """
    if api_key != DUMMY_API_KEY:
        raise DemistoException("Invalid Credentials. Please Verify your Connection parameters.")


def convert_to_demisto_severity(severity: str) -> int:
    """
    Maps HelloWorld severity to Cortex XSOAR severity.
    Converts the HelloWorld alert severity level ('Low', 'Medium', 'High', 'Critical') to Cortex XSOAR alert
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
        "low": IncidentSeverity.LOW,
        "medium": IncidentSeverity.MEDIUM,
        "high": IncidentSeverity.HIGH,
        "critical": IncidentSeverity.CRITICAL,
        "unknown": IncidentSeverity.UNKNOWN,
    }[severity]


def dedup_by_ids(alerts: list[dict], ids_to_compare: list[int]) -> tuple[list[dict], int]:
    """Gets a list of new IDs and a list of existing IDs,
    and returns a list with only alerts with id not found in ids_to_compare.
    For example, if alerts=[{'a':2},{'b': 3}] and ids_to_compare=[1,2], [3] is returned.

    Args:
        new_ids (list[dict]): A list of alerts to compare. Assuming the existence of "id" key.
        ids_to_compare (list[str]): A list of existing strings

    Returns:
        list[dict]: A list of only new unique alerts.
        int: The number of duplicates found.
    """
    dups = []
    dedup = []
    for alert in alerts:
        if id := alert["id"] in ids_to_compare:
            dups.append(id)
        else:
            dedup.append(alert)
    return dedup, len(dups)


""" COMMAND FUNCTIONS """


def test_module(client: Client, params: dict[str, Any]) -> str:
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
        time = dateparser.parse("1 minute")
        assert time
        severity = params.get("severity", None)
        if params.get("isFetch"):  # Tests fetch alert:
            fetch_incidents(client=client, max_results=1, last_run={}, first_fetch_time=time.isoformat(), severity=severity)
        else:
            client.get_alert_list(limit=1, severity=params.get("severity"))

    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def say_hello_command(client: Client, args: dict[str, Any]) -> CommandResults:
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

    name = args.get("name", None)
    if not name:
        raise ValueError("name not specified")

    # Call the Client function and get the raw response
    result = client.say_hello(name)

    # Create the human readable output.
    # It will  be in markdown format - https://www.markdownguide.org/basic-syntax/
    # More complex output can be formatted using ``tableToMarkDown()`` defined
    # in ``CommonServerPython.py``
    readable_output = f"## {result}"

    # More information about Context:
    # https://xsoar.pan.dev/docs/integrations/context-and-outputs
    # We return a ``CommandResults`` object, and we want to pass a custom
    # markdown here, so the argument ``readable_output`` is explicit. If not
    # passed, ``CommandResults``` will do a ``tableToMarkdown()`` do the data
    # to generate the readable output.
    return CommandResults(readable_output=readable_output, outputs_prefix="hello", outputs_key_field="", outputs=result)


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: dict,
    first_fetch_time: str,
    severity: str = "low",
    _page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[dict, list[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that alerts are fetched only once and no alerts are missed.
    By default it's invoked by Cortex XSOAR every minute. It will use last_run to save the timestamp of the last alert it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): HelloWorld client to use.
        max_results (int): Maximum numbers of alerts per fetch.
        last_run (dict): A dict with a key containing the latest alert created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching alerts.
        severity (str): severity of the alert to search for.
        page_size (int): number of alerts to retrieve per page from the API. This should be standard when dealing with pagination.
            It contains `_` here since we are not using it in an API call.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of alerts that will be created in Cortex XSOAR.
    """
    # INTEGRATION DEVELOPER TIP
    # You can use the last_run to save important information between fetches (For example, the last fetched alert's IDs).
    # Note that the last_run can store only small amounts of data, abusing it might cause unexpected behavior.

    # INTEGRATION DEVELOPER TIP
    # The fetch-incident function is usually *very* hard to debug in a client's environment.
    # Logging the steps correctly can save a lot of time and effort.
    # Make sure to use demisto.debug() to avoid flooding the general log.

    # Get the last fetch time, if exists
    last_fetch = last_run.get("last_fetch", None)
    last_ids: list[int] = last_run.get("last_ids", []) or []

    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = last_fetch

    assert last_fetch

    # Initialize an empty list of alerts to return. Incidents are processed alerts.
    incidents: list[dict[str, Any]] = []
    last_dummy_id = max(last_ids) if last_ids else 0
    demisto.debug(f"Running API query with {last_fetch=}, {severity=}")

    # Calling the relevant client method. Note that sometimes pagination is in order.
    # For pagination related information, see:
    # https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands.
    alerts = client.get_alert_list_for_fetch(
        limit=max_results,
        start_time=dateparser.parse(last_fetch),  # type: ignore
        severity=severity,
        last_id=last_dummy_id,
    )
    demisto.debug(f"Received {len(alerts)} alerts from server.")

    # INTEGRATION DEVELOPER TIP
    # alerts might be duplicated in some cases:
    # 1. Pagination done without next page's token -
    #   The exact time of the last alert is queried again so the same alert will be fetched again.
    # 2. Limit is exceeded but there are more alert in the same time to fetch in the next run-
    #   (Mostly happens when API does not support milliseconds).

    alerts, number_of_dups = dedup_by_ids(alerts, last_ids)
    demisto.debug(f"recieved {number_of_dups} duplicates alerts to skip.")

    # Get the last alert time.
    # We assume asc order so we can get all the alerts fetched with the exact same time and avoid it in the next run.
    # If no results returned from API, we use the last alert fetched from last_run.
    last_fetched_time = alerts[-1]["date"] if alerts else last_fetch
    last_ids = []
    demisto.debug(f"{alerts=}")
    for alert in alerts:
        # To prevent duplicates, we are only adding alerts with creation_time > last_fetched.
        # When we cannot assume alerts order in the response, we can use this code:

        # if last_fetch:
        # if alert_created_time <= last_fetch:
        #     continue

        # Update last run and add alert if the alert is newer than last fetch
        # if alert_created_time > latest_created_time:
        #     latest_created_time = alert_created_time

        # Otherwise, we might need to add the alert ID to the last_ids so it will be avoided in the next run.
        if alert["date"] == last_fetched_time:
            last_ids.append(alert["id"])

        # Formatting the alerts as needed (Adding fields, Removing sensitive ones, etc.)
        alert["name"] = alert.get("name") or "Hello World Alert"

        # INTEGRATION DEVELOPER TIP
        # The incident dict is initialized with a few mandatory fields:
        # name: the incident name
        # occurred: the time on when the incident occurred, in ISO8601 format, which matches the API response in this case.
        # we can use timestamp_to_datestring() from CommonServerPython.py to handle the conversion when dealing with timestamps.
        # rawJSON: everything else is packed in a string via json.dumps() and is included in rawJSON.
        # It will be used later for classification and mapping inside Cortex XSOAR.
        # severity: it's not mandatory, but is recommended. It must be
        # converted to XSOAR specific severity (int 1 to 4)
        # Note that there are other fields commented out here. You can do some
        # mapping of fields (either out of the box fields, like "details" and
        # "type") or custom fields (like "helloworldid") directly here in the
        # code, or they can be handled in the classification and mapping phase (Most Recommended).
        # In either case customers can override them. We leave the values commented out here, but you can use them if you want.
        incident = {
            "name": alert["name"],
            # 'details': alert['name'],
            "occurred": alert["date"],
            "rawJSON": json.dumps(alert),
            # 'type': 'Hello World Alert',  # Map to a specific XSOAR alert Type
            "severity": convert_to_demisto_severity(alert.get("severity", "low")),
            # 'CustomFields': {  # Map specific XSOAR Custom Fields
            #     'helloworldid': alert.get('id'),
            #     'helloworldstatus': alert.get('status'),
            #     'helloworldvalidity': alert.get('validity')
            # }
        }

        incidents.append(incident)

    # Save the next_run as a dict with the last_fetch key to be stored.
    # When we reached the limit but there are still alerts to get from this run,
    # the leftovers will be returned in the next run by time.
    demisto.debug(f"setting next run- {last_fetched_time=}")
    next_run = {"last_fetch": last_fetched_time, "last_ids": last_ids}
    return next_run, incidents


def ip_reputation_command(
    client: Client, args: dict[str, Any], default_threshold: int, reliability: DBotScoreReliability | str
) -> list[CommandResults]:
    """
    ip command: Returns IP reputation for a list of IPs

    Args:
        client (Client): HelloWorld client to use.
        args (dict): all command arguments, usually passed from ``demisto.args()``.
            ``args['ip']`` is a list of IPs or a single IP. We are providing a dummy response for the ip 8.8.8.8.
            ``args['threshold']`` threshold to determine whether an IP is malicious.
        default_threshold (int): default threshold to determine whether an IP is malicious if threshold is not
            specified in the XSOAR arguments.
        reliability (DBotScoreReliability): reliability of the source providing the intelligence data.

    Returns:
        CommandResults: A ``CommandResults`` object that is then passed to ``return_results``, that contains IPs.
    """

    # INTEGRATION DEVELOPER TIP
    # Reputation commands usually support multiple inputs (i.e. arrays), so
    # they can be invoked once in Cortex XSOAR. In case the API supports a single
    # IP at a time, we will cycle this for all the members of the array.
    # We use argToList(), implemented in CommonServerPython.py to automatically
    # return a list of a single element even if the provided input is a scalar.

    ips = argToList(args.get("ip"))
    if not ips:
        raise ValueError("IP(s) not specified")

    # It's a good practice to document the threshold you use to determine
    # if a score is malicious in your integration documentation.
    # Thresholds should also be possible to override, as in this case,
    # where threshold is an actual argument of the command.
    threshold = int(args.get("threshold", default_threshold))

    # Initialize an empty list of CommandResults to return
    # each CommandResult will contain context standard for IP
    command_results: list[CommandResults] = []

    for ip in ips:
        if not is_ip_valid(ip, accept_v6_ips=True):  # check IP's validity
            raise ValueError(f'IP "{ip}" is not valid')
        ip_data = client.get_ip_reputation(ip)
        ip_data["ip"] = ip

        # This is an example of creating relationships in reputation commands.
        # We will create relationships between indicators only in case that the API returns information about
        # the relationship between two indicators.
        # See https://xsoar.pan.dev/docs/integrations/generic-commands-reputation#relationships

        relationships_list = []
        links = ip_data.get("links", {}).get("self", "")
        for link in links:
            relationships_list.append(
                EntityRelationship(
                    entity_a=ip,
                    entity_a_type=FeedIndicatorType.IP,
                    name="related-to",
                    entity_b=link,
                    entity_b_type=FeedIndicatorType.URL,
                    brand="HelloWorld",
                )
            )

        # We can use demisto.get to get nested values from dict.
        reputation = int(demisto.get(ip_data, "attributes.reputation", defaultParam=0))

        # HelloWorld score to XSOAR reputation mapping
        # See: https://xsoar.pan.dev/docs/integrations/dbot
        # We are using Common.DBotScore as macros to simplify
        # the mapping.

        if reputation == 0:
            score = Common.DBotScore.NONE  # unknown
        elif reputation < threshold / 2:
            score = Common.DBotScore.BAD  # bad
        elif reputation < threshold:
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
            integration_name="HelloWorld",
            score=score,
            malicious_description=f"Hello World returned reputation {reputation}",
            reliability=reliability,
        )

        # Create the IP Standard Context structure using Common.IP and add
        # dbot_score to it.
        ip_standard_context = Common.IP(ip=ip, asn=ip_data.get("asn"), dbot_score=dbot_score, relationships=relationships_list)

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

        # Define which fields we want to exclude from the context output as they are too verbose.
        # We will use attributes key separately. Just make sure to keep the whole response somewhere.
        ip_context_excluded_fields = ["whois", "attributes"]
        ip_data_outputs = {k: ip_data[k] for k in ip_data if k not in ip_context_excluded_fields}

        # In this case we want to use an custom markdown to specify the table title,
        # but otherwise ``CommandResults()`` will call ``tableToMarkdown()``
        #  automatically.

        readable_attributes = tableToMarkdown("Attributes", ip_data["attributes"], is_auto_json_transform=True)
        readable_output = tableToMarkdown("IP (Sample Data)", ip_data_outputs)
        readable_output += readable_attributes

        # INTEGRATION DEVELOPER TIP
        # The output key will be ``HelloWorld.IP``, using ``ip`` as the key field.
        # ``indicator`` is used to provide the context standard (IP)
        command_results.append(
            CommandResults(
                readable_output=readable_output,
                raw_response=ip_data,
                outputs_prefix="HelloWorld.IP",
                outputs_key_field="ip",
                outputs=ip_data_outputs,
                indicator=ip_standard_context,
                relationships=relationships_list,
            )
        )
    return command_results


def alert_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    alert_id = arg_to_number(args.get("alert_id"))
    severity = args.get("severity")
    if not severity and not alert_id:
        raise DemistoException("Severity is a required parameter.")

    # Pagination params. See https://xsoar.pan.dev/docs/integrations/code-conventions#pagination-in-integration-commands
    limit = arg_to_number(args.get("limit")) or LIMIT

    if alert_id:  # If alert_id is provided, we only need one call to API and pagination is not needed.
        full_res = client.get_alert(alert_id)
        if isinstance(full_res, dict):
            full_res = [full_res]

    else:
        full_res = client.get_alert_list(limit=limit, severity=severity)

    readable_output = tableToMarkdown("Items List (Sample Data)", full_res)
    return CommandResults(
        readable_output=readable_output, outputs_prefix="HelloWorld.Alert", outputs_key_field="id", outputs=full_res
    )


def alert_note_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    alert_id = arg_to_number(args["alert_id"], required=True)
    note = args["note_text"]

    if not alert_id:
        raise DemistoException("Please provide alert id.")

    res_data = client.create_note(alert_id=alert_id, comment=note)

    return CommandResults(
        readable_output="Note was created successfully.",
        outputs_prefix="HelloWorld.Note",
        outputs_key_field="id",
        outputs=res_data,
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("credentials", {}).get("password")

    validate_api_key(api_key)

    # get the service API url
    base_url = params.get("url")

    # If your Client class inherits from BaseClient, SSL verification is handled out-of-the-box by it.
    # Just pass ``verify_certificate`` to the Client constructor
    verify_certificate = not params.get("insecure", False)

    # How much time before the first fetch to retrieve alerts
    first_fetch_time = arg_to_datetime(arg=params.get("first_fetch", "3 days"), arg_name="First fetch time", required=True)
    assert first_fetch_time
    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get("proxy", False)

    # Integration that implements reputation commands (e.g. url, ip, domain,..., etc) must have
    # a reliability score of the source providing the intelligence data.
    reliability = params.get("integrationReliability") or DBotScoreReliability.C

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Token {api_key}"}
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        elif command == "ip":
            default_threshold_ip = arg_to_number(params.get("threshold_ip")) or DEFAULT_INDICATORS_THRESHOLD
            return_results(ip_reputation_command(client, args, default_threshold_ip, reliability))

        elif command == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            severity = params.get("severity", "low")

            # Convert the argument to an int using helper function or set to MAX_ALERTS_TO_FETCH
            max_results = arg_to_number(arg=params.get("max_fetch"), arg_name="max_fetch", required=False)
            if not max_results or max_results > MAX_ALERTS_TO_FETCH:
                max_results = MAX_ALERTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=datetime.strftime(first_fetch_time, DATE_FORMAT),
                severity=severity,
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif command == "helloworld-alert-list":
            return_results(alert_list_command(client, args))

        elif command == "helloworld-alert-note-create":
            return_results(alert_note_create_command(client, args))

        elif command == "helloworld-say-hello":
            return_results(say_hello_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
