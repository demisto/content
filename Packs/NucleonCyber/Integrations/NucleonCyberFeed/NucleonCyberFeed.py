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

from typing import Dict, List, Optional
# from datetime import date
import urllib3
import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


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

    def build_iterator(self) -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []

        res = self._http_request('GET',
                                 url_suffix='',
                                 full_url=self._base_url,
                                 resp_type='text',
                                 )

        # In this case the feed output is in text format, so extracting the indicators from the response requires
        # iterating over it's lines solely. Other feeds could be in other kinds of formats (CSV, MISP, etc.), or might
        # require additional processing as well.
        try:
            indicators = res.split('\n')

            for indicator in indicators:
                # Infer the type of the indicator using 'auto_detect_indicator_type(indicator)' function
                # (defined in CommonServerPython).
                if auto_detect_indicator_type(indicator):
                    result.append({
                        'value': indicator,
                        'type': auto_detect_indicator_type(indicator),
                        'FeedURL': self._base_url
                    })

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError massage: {err}')
        return result

    def get_hashes(self, params: Dict[str, str], limit: int) -> List:
        res = self._http_request(
            'GET',
            url_suffix='',
            full_url="http://api.cybercure.ai/feed/get_hash",
            resp_type='text',
        )

        json_payload = json.loads(res)
        result = []
        # all_data = json_payload.get("data")
        all_urls = json_payload.get("data").get("hash")
        for data in all_urls:
            result.append(
                {
                    'value': data,
                    "type": "File",
                    # "reputation":"Bad",
                }
            )
        return result

    """
    """

    def get_urls(self, limit: int) -> List:
        res = self._http_request('GET',
                                 url_suffix='',
                                 full_url="http://api.cybercure.ai/feed/get_url",
                                 resp_type='text',
                                 )

        json_payload = json.loads(res)
        result = []
        # all_data = json_payload.get("data")
        all_urls = json_payload.get("data").get("urls")
        for data in all_urls:
            result.append(
                {
                    'value': data,
                    "type": "URL",
                    # "reputation":"Bad",

                }
            )
        return result

    """
    """

    def fix_segment(self, segment) -> str:
        if segment is None:
            return "other"
        else:
            return segment

    """
    """

    def get_ips(self, params: Dict[str, str], limit: int) -> List:
        global_username = params.get('username')
        global_password = params.get('password')
        global_usrn = params.get('usrn')
        global_client_id = params.get('clientid')
        # ips_indicators_url = params.get('ips')
        body = {'usrn': global_usrn, 'clientID': global_client_id, 'limit': limit}
        res = self._http_request('POST',
                                 url_suffix='',
                                 full_url="https://api.nucleoncyber.com/feed/activethreats",
                                 auth=(global_username, global_password),
                                 data=body,
                                 resp_type='text',
                                 )
        json_payload = json.loads(res)
        result = []
        all_data = json_payload.get("data")

        demisto.info(all_data)
        for data in all_data:
            result.append(
                {
                    'value': data.get("ip"),
                    # 'value': "40.22.22.22",
                    "exp": data.get("exp"),
                    # "exp":1677535200000,
                    'type': "IP",
                    'segment': self.fix_segment(data.get("attackDetails").get("segment")),
                    'targetCountry': data.get("attackDetails").get("targetCountry"),
                    'os': data.get("attackDetails").get("remote").get("os"),
                    'osVersion': data.get("attackDetails").get("remote").get("osVersion"),
                    'governments': data.get("attackMeta").get("governments"),
                    'port': data.get("attackMeta").get("port"),
                    'darknet': data.get("attackMeta").get("darknet"),
                    'bot': data.get("attackMeta").get("bot"),
                    'cnc': data.get("attackMeta").get("cnc"),
                    'proxy': data.get("attackMeta").get("proxy"),
                    'automated': data.get("attackMeta").get("automated"),
                    'bruteForce': data.get("attackMeta").get("bruteForce"),
                    'sourceCountry': data.get("attackMeta").get("sourceCountry"),
                    # "reputation":"Bad",

                }
            )
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

    client.build_iterator()
    return 'ok'


def fetch_indicators(client: Client, tlp_color: Optional[str] = None, feed_tags: List = [], limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    # iterator = client.build_iterator()
    params = demisto.params()
    iterator = client.get_ips(params, limit)

    indicators = []
    # if limit > 0:
    #     iterator = iterator[:limit]

    # extract values from iterator

    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        segment_ = item.get('segment')
        targetCountry_ = item.get('targetCountry')
        os_ = item.get('os')
        osVersion_ = item.get('osVersion')
        governments_ = item.get('governments')
        port_ = item.get('port')
        darknet_ = item.get('darknet')
        bot_ = item.get('bot')
        cnc_ = item.get('cnc')
        proxy_ = item.get('proxy')
        automated_ = item.get('automated')
        bruteForce_ = item.get('bruteForce')
        sourceCountry_ = item.get('sourceCountry')

        # exp = item.get('exp')
        # exp_= timestamp_to_datestring(exp_ms)

        raw_data = {
            'value': value_,
            'type': type_,
            # 'exp':exp_,
            'segment': segment_,
            'targetCountry': targetCountry_,
            'os': os_,
            'osVersion': osVersion_,
            'governments': governments_,
            'port': port_,
            'darknet': darknet_,
            'botnet': bot_,
            'cnc': cnc_,
            'proxy': proxy_,
            'automated': automated_,
            'bruteForce': bruteForce_,
            'sourceCountry': sourceCountry_,

        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})

        indicator_obj = {
            # The indicator value.
            'value': value_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            'type': type_,
            'segment': segment_,
            'targetCountry': targetCountry_,
            'os': os_,
            'osVersion': osVersion_,
            'governments': governments_,
            'port': port_,
            'darknet': darknet_,
            'botnet': bot_,
            'cnc': cnc_,
            'proxy': proxy_,
            'automated': automated_,
            'bruteForce': bruteForce_,
            'sourceCountry': sourceCountry_,
            # 'exp':exp_,



            # The name of the service supplying this feed.
            'service': 'NucleonCyberFeed',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {
                'osversion': osVersion_,
                'os': os_,
                'port': port_,
                'nucleonsegment': segment_,
                #    'expiration':exp_,
            },
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
        }

        # if feed_tags:
        #     indicator_obj['fields']['tags'] = feed_tags

        # if tlp_color:
        #     indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)

    return indicators


"""
"""


def fetch_hashes(client: Client, limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        limit (int): limit the results
    Returns:
        Indicators.
    """
    # iterator = client.build_iterator()
    params = demisto.params()
    iterator = client.get_hashes(params, limit)

    indicators = []

    if limit > 0:
        iterator = iterator[:limit]
    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})

        indicator_obj = {
            # The indicator value.
            'value': value_,
            'type': type_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            # 'exp':exp_,
            # "port":port_,
            # The name of the service supplying this feed.
            'service': 'NucleonCyberFeed',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {
            },
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
        }
        indicators.append(indicator_obj)

    return indicators


"""
"""


def fetch_urls(client: Client, limit: int = -1) \
        -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        limit (int): limit the results
    Returns:
        Indicators.
    """
    # iterator = client.build_iterator()
    # params = demisto.params()
    iterator = client.get_urls(limit)

    indicators = []

    if limit > 0:
        iterator = iterator[:limit]
    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})

        indicator_obj = {
            # The indicator value.
            'value': value_,
            'type': type_,
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            # 'exp':exp_,
            # "port":port_,
            # The name of the service supplying this feed.
            'service': 'NucleonCyberFeed',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {
            },
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data
        }
        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]
                           ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
        IP indicators
    """
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown('IP indicators from NucleonCyberFeed:', indicators,
                                     headers=['value', 'type', 'exp'], headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='NucleonCyber.Indicators',
        outputs_key_field='',
        raw_response=indicators,
        # outputs={},
        outputs=indicators,
    )


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        All indicators type (ip,url,hash(file)).
    """
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = params.get('tlp_color')
    ips = fetch_indicators(client, tlp_color, feed_tags)
    urls = fetch_urls(client)
    hashes = fetch_hashes(client)
    return [ips, urls, hashes]


"""
"""


def get_hashes_command(client: Client,
                       params: Dict[str, str],
                       args: Dict[str, Any]
                       ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
        Hash indicators
    """
    limit = int(args.get('limit', '10'))
    hashes = fetch_hashes(client, limit)
    human_readable = tableToMarkdown('Hash indicators from NucleonCyberFeed:', hashes,
                                     headers=['value', 'type'], headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='NucleonCyber.Indicators.hash',
        outputs_key_field='',  # in Xsoar it helps to update exist instead of adding new
        raw_response=hashes,
        outputs=hashes,
    )


"""
"""


def get_urls_command(client: Client,
                     params: Dict[str, str],
                     args: Dict[str, Any]
                     ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
        url indicators
    """
    limit = int(args.get('limit', '10'))
    urls = fetch_urls(client, limit)
    human_readable = tableToMarkdown('URL indicators from NucleonCyberFeed:', urls,
                                     headers=['value', 'type'], headerTransform=string_to_table_header, removeNull=True)

    # res = client.get_urls()
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='NucleonCyber.Indicators.url',
        outputs_key_field='',  # in Xsoar it helps to update exist instead of adding new
        raw_response=urls,
        outputs=urls,
    )


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # Get the service API url
    base_url = params.get('url')

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'nucleoncyber-get-ips':
            # This is the command that fetches a limited number of indicators from the feed source
            # and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == 'nucleoncyber-get-urls':
            return_results(get_urls_command(client, params, args))

        elif command == 'nucleoncyber-get-hashes':
            return_results(get_hashes_command(client, params, args))

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint and create new indicators objects from
            # the data fetched. If the integration instance is configured to fetch indicators, then this is the command
            # that will be executed at the specified feed fetch interval.
            ips, urls, hashes = fetch_indicators_command(client, params)
            for iter_ in batch(ips, batch_size=2000):
                demisto.createIndicators(iter_)
            for iter_ in batch(urls, batch_size=2000):
                demisto.createIndicators(iter_)
            for iter_ in batch(hashes, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
