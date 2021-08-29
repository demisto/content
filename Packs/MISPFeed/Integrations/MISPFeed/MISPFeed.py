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

import urllib3, json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS

indicator_to_galaxy_relation_dict: Dict[str, Any] = {
    ThreatIntel.ObjectsNames.ATTACK_PATTERN: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.USES,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.USES,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    },
    ThreatIntel.ObjectsNames.MALWARE: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.USES,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    },
    ThreatIntel.ObjectsNames.TOOL: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.USES,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.USES,
    },
    ThreatIntel.ObjectsNames.INTRUSION_SET: {
        FeedIndicatorType.File: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.IP: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.URL: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Email: EntityRelationship.Relationships.INDICATOR_OF,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.RELATED_TO,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.ATTRIBUTED_TO,
    },
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION: {
        FeedIndicatorType.File: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.IP: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Domain: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.URL: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Email: EntityRelationship.Relationships.RELATED_TO,
        FeedIndicatorType.Registry: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.THREAT_ACTOR: EntityRelationship.Relationships.RELATED_TO,
        DBotScoreType.CRYPTOCURRENCY: EntityRelationship.Relationships.RELATED_TO,
        ThreatIntel.ObjectsNames.MALWARE: EntityRelationship.Relationships.MITIGATED_BY,
        ThreatIntel.ObjectsNames.CAMPAIGN: EntityRelationship.Relationships.RELATED_TO,
    }
}


class Client(BaseClient):
    def search_query(self, body: Dict[str, Any]) -> List:
        result = []
        headers = {
            'Authorization': demisto.params().get('apikey'),
            "Accept": "application/json",
            'Content-Type': 'application/json'
        }
        response = requests.request("POST",
                                    url=self._base_url + "attributes/restSearch",
                                    headers=headers,
                                    data=json.dumps(body),
                                    verify=False)
        try:
            attributes = json.loads(response.content)['response']['Attribute']
            for attribute in attributes:
                if get_attribute_indicator_type(attribute):
                    result.append({
                        'value': attribute,
                        'type': get_attribute_indicator_type(attribute),
                        'raw_type': attribute['type'],
                        'FeedURL': self._base_url,
                    })
        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError massage: {err}')
        return result


def get_attribute_indicator_type(attribute: Dict[str, Any]) -> Optional[str]:
    attribute_type = attribute['type']
    indicator_map = {
        'sha256': FeedIndicatorType.File,
        'md5': FeedIndicatorType.File,
        'sha1': FeedIndicatorType.File,
        'filename|md5': FeedIndicatorType.File,
        'filename|sha1': FeedIndicatorType.File,
        'filename|sha256': FeedIndicatorType.File,
        'ip-src': FeedIndicatorType.IP,
        'ip-dst': FeedIndicatorType.IP,
        'domain': FeedIndicatorType.Domain,
        'email': FeedIndicatorType.Email,
        'email-src': FeedIndicatorType.Email,
        'email-dst': FeedIndicatorType.Email,
        'url': FeedIndicatorType.URL,
        'regkey': FeedIndicatorType.Registry,
        'threat-actor': ThreatIntel.ObjectsNames.THREAT_ACTOR,
        'btc': DBotScoreType.CRYPTOCURRENCY,
        'campaign-name': ThreatIntel.ObjectsNames.CAMPAIGN,
        'campaign-id': ThreatIntel.ObjectsNames.CAMPAIGN,
        'malware-type': ThreatIntel.ObjectsNames.MALWARE

    }
    return indicator_map.get(attribute_type, None)


def get_galaxy_indicator_type(galaxy_tag_name: str) -> Optional[str]:
    if 'galaxy' in galaxy_tag_name:
        galaxy_name = galaxy_tag_name[0:galaxy_tag_name.index("=")]
        galaxy_map = {
            'misp-galaxy:mitre-attack-pattern': ThreatIntel.ObjectsNames.ATTACK_PATTERN,
            'misp-galaxy:mitre-malware': ThreatIntel.ObjectsNames.MALWARE,
            'misp-galaxy:mitre-tool': ThreatIntel.ObjectsNames.TOOL,
            'misp-galaxy:mitre-intrusion-set': ThreatIntel.ObjectsNames.INTRUSION_SET,
            'misp-galaxy:mitre-course-of-action': ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
        }
        return galaxy_map.get(galaxy_name, None)
    return None


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

    client.search_query(build_params_dict([], []))
    return 'ok'


def fetch_indicators(client: Client,
                     tags: List[str],
                     attribute_type: List[str],
                     query: Optional[str],
                     tlp_color: Optional[str],
                     limit: int = -1) -> List[Dict]:
    if query:
        params_dict = clean_user_query(query)
    else:
        params_dict = build_params_dict(tags, attribute_type)

    indicators_iterator = client.search_query(params_dict)
    indicators = []

    if limit > 0:
        indicators_iterator = indicators_iterator[:limit]

    for indicator in indicators_iterator:
        value_ = indicator.get('value').get('value')
        type_ = indicator.get('type')
        raw_type = indicator.pop('raw_type')
        raw_data = {
            'value': value_,
            'type': type_,
        }
        for key, value in indicator.items():
            raw_data.update({key: value})

        indicator_obj = build_indicator(value_, type_, raw_data)

        update_indicator_fields(indicator_obj, tlp_color, raw_type)
        galaxy_indicators = build_indicators_from_galaxies(indicator_obj)
        indicators.extend(galaxy_indicators)
        create_and_add_relationships(indicator_obj, galaxy_indicators)

        indicators.append(indicator_obj)

    return indicators


def build_indicator(value_: str, type_: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
    indicator_obj = {
        'value': value_,
        'type': type_,
        'service': 'MISP',
        'fields': {},
        'rawJSON': raw_data
    }
    return indicator_obj


def build_indicators_from_galaxies(indicator_obj: Dict[str, Any]) -> List[Dict[str,Any]]:
    tags = indicator_obj['rawJSON']['value'].get('Tag', None)
    galaxy_indicators = []
    for tag in tags:
        tag_name = tag.get('name', None)
        if tag_name and get_galaxy_indicator_type(tag_name):
            value_ = tag_name[tag_name.index('=\"') + 1: tag_name.index("-") - 1]
            type_ = get_galaxy_indicator_type(tag_name)
            raw_data = {
                'value': value_,
                'type': type_,
            }
            for key, value in tag.items():
                raw_data.update({key: value})

            galaxy_indicators.append(build_indicator(value_, type_, raw_data))

    return galaxy_indicators


def create_and_add_relationships(indicator_obj: Dict[str, Any], galaxy_indicators: List[Dict[str,Any]]) -> None:
    indicator_obj_type = indicator_obj['type']
    relationships_indicators = []
    for galaxy_indicator in galaxy_indicators:
        galaxy_indicator_type = galaxy_indicator['type']

        indicator_to_galaxy_relation = indicator_to_galaxy_relation_dict[galaxy_indicator_type][indicator_obj_type]
        galaxy_to_indicator_relation = EntityRelationship.Relationships.\
            RELATIONSHIPS_NAMES[indicator_to_galaxy_relation]

        indicator_relation = EntityRelationship(
            name=indicator_to_galaxy_relation,
            entity_a=indicator_obj['value'],
            entity_a_type=indicator_obj_type,
            entity_b=galaxy_indicator['value'],
            entity_b_type=galaxy_indicator_type,
            ).to_indicator()
        galaxy_relation = EntityRelationship(
            name=galaxy_to_indicator_relation,
            entity_a=galaxy_indicator['value'],
            entity_a_type=galaxy_indicator_type,
            entity_b=indicator_obj['value'],
            entity_b_type=indicator_obj_type,
        ).to_indicator()

        relationships_indicators.append(indicator_relation)
        galaxy_indicator['relationship'] = galaxy_relation

    if relationships_indicators:
        indicator_obj['relationship'] = relationships_indicators


def update_indicator_fields(indicator_obj: Dict[str, Any], tlp_color: Optional[str], raw_type: str) -> None:
    first_seen = indicator_obj['rawJSON']['value'].get('first_seen', None)
    last_seen = indicator_obj['rawJSON']['value'].get('last_seen', None)
    timestamp = indicator_obj['rawJSON']['value'].get('timestamp', None)
    category = indicator_obj['rawJSON']['value'].get('category', None)
    comment = indicator_obj['rawJSON']['value'].get('comment', None)
    tags = indicator_obj['rawJSON']['value'].get('Tag', None)

    if first_seen:
        indicator_obj['fields']['First Seen By Source'] = first_seen

    if last_seen:
        indicator_obj['fields']['Last Seen By Source'] = last_seen

    if timestamp:
        indicator_obj['fields']['Updated Date'] = timestamp

    if category:
        indicator_obj['fields']['Category'] = category

    if comment:
        indicator_obj['fields']['Description'] = comment

    if tlp_color:
        indicator_obj['fields']['trafficlightprotocol'] = tlp_color

    if tags:
        handle_tags_fields(indicator_obj, tags)

    if 'md5' in raw_type or 'sha1' in raw_type or 'sha256' in raw_type:
        handle_file_type_fields(raw_type, indicator_obj)


def get_attributes_command(client: Client, args: Dict[str, str], params: Dict[str, str]) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        args: demisto.args()
        params: demisto.params()
    Returns:
        Outputs.
    """
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    tags = argToList(args.get('tags', ''))
    query = args.get('query', None)

    attribute_type = argToList(args.get('attribute_type', ''))
    indicators = fetch_indicators(client, tags, attribute_type, query, tlp_color, limit)
    human_readable = "Retrieved " + str(len(indicators)) + " indicators."
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='Indicators',
        outputs_key_field='',
        raw_response=indicators,
        outputs=indicators,
    )


def fetch_attributes_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Outputs.
    """
    tlp_color = params.get('tlp_color')
    tags = argToList(params.get('attribute_tags', ''))
    attribute_types = argToList(params.get('attribute_types', ''))
    query = params.get('query', None)

    indicators = fetch_indicators(client, tags, attribute_types, query, tlp_color)
    return indicators


def handle_tags_fields(indicator_obj: Dict[str, Any], tags: List[Any]) -> None:
    indicator_obj['fields']['Tags'] = []
    for tag in tags:
        tag_name = tag.get('name', None)
        if tag_name and not get_galaxy_indicator_type(tag_name):
            indicator_obj['fields']['Tags'].append(tag_name)


def handle_file_type_fields(raw_type: str, indicator_obj: Dict[str, Any]) -> None:
    hash_value = indicator_obj['value']
    if 'filename|' in raw_type:
        pipe_index = hash_value.index("|")
        filename = hash_value[0:pipe_index]
        hash_value = hash_value[pipe_index + 1:]

        indicator_obj['fields']['Associated File Names'] = filename
        indicator_obj['value'] = hash_value
        raw_type = raw_type[raw_type.index("|") + 1:]

    indicator_obj['fields'][raw_type.upper()] = hash_value


def build_params_dict(tags: List[str], attribute_type: List[str]) -> Dict[Any, str]:
    params = {
        'returnFormat': 'json',
        'type': {
                'OR': []
        },
        'tags': {
            'OR': []
        }
    }
    if attribute_type:
        params["type"]["OR"] = attribute_type
    if tags:
        params["tags"]["OR"] = tags
    return params


def clean_user_query(query: str):
    try:
        params = json.loads(query)
        params["returnFormat"] = "json"
        params.pop("timestamp", None)
    except Exception as err:
        demisto.debug(str(err))
        raise DemistoException(f'Could not parse user query. \n\nError massage: {err}')

    return params


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
            return_results(test_module(client))
        elif command == 'misp-feed-get-indicators':
            return_results(get_attributes_command(client, args, params))
        elif command == 'fetch-indicators':
            indicators = fetch_attributes_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
