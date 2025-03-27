import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""HelloWorld Feed Integration for Cortex XSOAR (aka Demisto)

This feed integration is a good example on you can build a Cortex XSOAR feed
using Python 3. Please follow the documentation links below and make sure that
your feed integration follows the Code Conventions and required parameters, and passes the Linting phase.

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Feed Required Parameters: https://xsoar.pan.dev/docs/integrations/feeds#required-parameters
Linting: https://xsoar.pan.dev/docs/integrations/linting


The API
--------------

For this template, the feed used as API is OpenPhish, supplying a feed of URLs.
This API's output is of type freetext, and the suitable handling for this type can be seen in the function
'fetch_indicators'. Other APIs may have different formats, so when using this template for other feed APIs
make sure you handle the output properly according to its format.


Feed Integration File Structure
--------------------------

A feed integration usually consists of the following parts:
- Imports
- Constants
- Client Class
- Helper Functions
- Command Functions
- Main Function
- Entry Point


Imports
-------

Here you can import Python module you need for your feed integration. If you need
a module that is not part of the default XSOAR Docker images, you can add
a custom one. More details: https://xsoar.pan.dev/docs/integrations/docker

There are also internal imports that are used by XSOAR:
- demistomock (imported as demisto): allows your code to work offline for
testing. The actual ``demisto`` module is provided at runtime when the
code runs in XSOAR.
- CommonServerPython.py: contains a set of helper functions, base classes
and other useful components that will make your feed integration code easier
to maintain.
- CommonServerUserPython.py: includes a set of user defined commands that
are specific to an XSOAR installation. Do not use it for feed integrations that
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

Look at the code and the commands of this specific class to better understand
the implementation details.


Helper Functions
----------------

Helper functions are usually used as utility functions that are used by several
command functions throughout your code. For example they map arguments to types
or convert severity formats from feed integration-specific to XSOAR.
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

Every feed integration should have these three base commands:
``<product-prefix>-get-indicators`` - where <product-prefix> is replaced by the name
of the Product or Vendor source providing the feed. So for example, if you were
developing a feed integration for Microsoft Intune this command might be called
msintune-get-indicators. This command should fetch a limited number of indicators
from the feed source and display them in the war room.
``fetch-indicators`` - this command will initiate a request to the feed endpoint, format
the data fetched from the endpoint to conform to Cortex XSOAR's expected input format
and create new indicators. If the integration instance is configured to Fetch indicators,
then this is the command that will be executed at the specified Feed Fetch Interval.
``test-module`` - this is the command that is run when the Test button in the configuration
 panel of a feed integration is clicked.

More information on Context Outputs, Standards, DBotScore and demisto-sdk:
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/context-standards
https://xsoar.pan.dev/docs/integrations/dbot
https://github.com/demisto/demisto-sdk/blob/master/demisto_sdk/commands/json_to_outputs/README.md
https://xsoar.pan.dev/docs/integrations/context-and-outputs
https://xsoar.pan.dev/docs/integrations/code-conventions#outputs
https://xsoar.pan.dev/docs/integrations/dt


Main Function
-------------

The ``main()`` function takes care of reading the feed integration parameters via
the ``demisto.params()`` function, initializes the Client class and checks the
different options provided to ``demisto.commands()``, to invoke the correct
command function passing to it ``demisto.args()`` and returning the data to
``return_results()``. ``main()`` also catches exceptions and
returns an error message via ``return_error()``.


Entry Point
-----------

This is the integration code entry point. It checks whether the ``__name__``
variable is ``__main__`` , ``__builtin__`` (for Python 2) or ``builtins`` (for
Python 3) and then calls the ``main()`` function. Just keep this convention.

"""


import urllib3
from urllib.parse import urlparse


# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld Feed implementation, no special attributes defined
    """

    def build_iterator(self) -> list:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        res = self._http_request(
            "GET",
            url_suffix="",
            full_url=self._base_url,
            resp_type="text",
        )

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            indicators = res.split("\n")

            for indicator in indicators:
                # Infer the type of the indicator using 'auto_detect_indicator_type(indicator)' function
                # (defined in CommonServerPython).
                if indicator_type := auto_detect_indicator_type(indicator):
                    related_indicator = {}

                    # Adding domain related to url indicator.
                    # This is an example of creating relationships in Feeds.
                    # We will create relationships between indicators only in case that the API returns information
                    # about the relationship between two indicators.
                    if indicator_type == FeedIndicatorType.URL:
                        domain = urlparse(indicator).netloc
                        related_indicator = {"value": domain, "type": FeedIndicatorType.Domain, "relationType": "hosted-on"}

                    result.append(
                        {"value": indicator, "type": indicator_type, "FeedURL": self._base_url, "relations": [related_indicator]}
                    )

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f"Could not parse returned data as indicator. \n\nError massage: {err}")
        return result


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    # INTEGRATION FEED DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error

    fetch_indicators(client, limit=1)
    return "ok"


def fetch_indicators(
    client: Client, tlp_color: str | None = None, feed_tags: list = [], limit: int = -1, create_relationships: bool = False
) -> list[dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
        create_relationships (bool): create related indicators entries
    Returns:
        Indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item.get("value")
        type_ = item.get("type")
        raw_data = {
            "value": value_,
            "type": type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})
        indicator_obj = {
            # The indicator value.
            "value": value_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            "type": type_,
            # The name of the service supplying this feed.
            "service": "HelloWorld",
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            "fields": {},
            # A dictionary of the raw data returned from the feed source about the indicator.
            "rawJSON": raw_data,
        }

        if feed_tags:
            indicator_obj["fields"]["tags"] = feed_tags

        if tlp_color:
            indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

        # Example of creating indicator relationships.
        # For more information see: https://xsoar.pan.dev/docs/integrations/feeds#indicator-objects
        if (relations := item.get("relations")) and create_relationships:
            relationships = []
            for relation in relations:
                if relation:
                    entity_relation = EntityRelationship(
                        name=relation.get("relationType"),
                        entity_a=value_,
                        entity_a_type=type_,
                        entity_b=relation.get("value"),
                        entity_b_type=relation.get("type"),
                    )
                    relationships.append(entity_relation.to_indicator())

            indicator_obj["relationships"] = relationships

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client, params: dict[str, str], args: dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    limit = int(args.get("limit", "10"))
    tlp_color = params.get("tlp_color")
    feed_tags = argToList(params.get("feedTags", ""))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown(
        "Indicators from HelloWorld Feed:",
        indicators,
        headers=["value", "type"],
        headerTransform=string_to_table_header,
        removeNull=True,
    )
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="",
        outputs_key_field="",
        raw_response=indicators,
        outputs={},
    )


def fetch_indicators_command(client: Client, params: dict[str, str]) -> list[dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get("tlp_color")
    create_relationships = argToBoolean(params.get("create_relationships", True))

    indicators = fetch_indicators(client, tlp_color, feed_tags, create_relationships=create_relationships)
    return indicators


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # Get the service API url
    base_url = params.get("url")

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get("insecure", False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get("proxy", False)

    command = demisto.command()
    args = demisto.args()

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging
    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == "helloworld-get-indicators":
            # This is the command that fetches a limited number of indicators from the feed source
            # and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == "fetch-indicators":
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
