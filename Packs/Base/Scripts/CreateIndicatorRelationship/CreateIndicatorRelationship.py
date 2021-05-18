from typing import Tuple

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback

BRAND = "XSOAR"
PAGE_SIZE = 2000


# --------------------------------------------------- Helper functions---------------------------------------------


def find_indicators_by_query(query: str) -> List[dict]:
    """
    Search indicators in the system using a query.

    :type query: ``str``
    :param query: A query for the searchIndicators command.

    :return: A list of indicators that exist in the system.
    :rtype: ``list``
    """
    indicators: List[dict] = []
    search_indicators = IndicatorsSearcher()

    # last_found_len should be PAGE_SIZE (or PAGE_SIZE - 1, as observed for some users) for full pages
    fetched_indicators = search_indicators.search_indicators_by_version(query=query, size=PAGE_SIZE).get('iocs')
    while fetched_indicators:
        # In case the result from searchIndicators includes the key `iocs` but it's value is None
        fetched_indicators = fetched_indicators or []

        # save only the value and type of each indicator
        indicators.extend({'entity_b': ioc.get('value'), 'entity_b_type': ioc.get('indicator_type')}
                          for ioc in fetched_indicators)
        fetched_indicators = search_indicators.search_indicators_by_version(query=query, size=PAGE_SIZE).get('iocs')

    return indicators


def remove_existing_entity_b_indicators(entity_b_list: list, entity_b_query: str = '') -> list:
    """
    We would like to send to the createNewIndicator command only unexisting indicators, as a result this function
    checks for existing indicator in the system and removed from entity_b the existing indicators.

    :type entity_b_list: ``list``
    :param entity_b_list: A list of entity_b's arguments to the command.

    :type entity_b_query: ``str``
    :param entity_b_query: A query that has been given to the command.

    :return: A list of entity_b's that do not exist in the system that we will need to add.
    :rtype: ``list``
    """
    if entity_b_query:
        return []
    else:
        query = f'value:{entity_b_list[0]}'
        for entity_b in entity_b_list[1:]:
            query += f' or value:{entity_b}'
    result_indicators_by_query = find_indicators_by_query(query)
    for indicator in result_indicators_by_query:
        if indicator.get('entity_b') in entity_b_list:
            entity_b_list.remove(indicator.get('entity_b'))
    return entity_b_list


def create_relation_command_using_query(args: dict) -> List[EntityRelationship]:
    relationships = []
    indicators = find_indicators_by_query(args.get('entity_b_query', ''))
    for indicator in indicators:
        relationships.append(create_relationship(name=args.get('relationship', ''), entity_a=args.get('entity_a', ''),
                                                 entity_a_type=args.get('entity_a_type', ''),
                                                 entity_b=indicator.get('entity_b', ''),
                                                 entity_b_type=indicator.get('entity_b_type', ''),
                                                 source_reliability=args.get('source_reliability', ''),
                                                 reverse_name=args.get('reverse_relationship', ''),
                                                 first_seen=args.get('first_seen', ''),
                                                 description=args.get('description', '')
                                                 ))
    return relationships


def create_relationships_with_args(args: dict) -> List[EntityRelationship]:
    relationships = []
    entity_b_list = argToList(args.get('entity_b'))
    for entity_b in entity_b_list:
        relationships.append(create_relationship(name=args.get('relationship', ''), entity_a=args.get('entity_a', ''),
                                                 entity_a_type=args.get('entity_a_type', ''),
                                                 entity_b=entity_b,
                                                 entity_b_type=args.get('entity_b_type', ''),
                                                 source_reliability=args.get('source_reliability', ''),
                                                 reverse_name=args.get('reverse_relationship', ''),
                                                 first_seen=args.get('first_seen', ''),
                                                 description=args.get('description', '')))
    return relationships


def create_relationship(name: str, entity_a: str, entity_a_type: str, entity_b: str, entity_b_type: str,
                        source_reliability: str = '', reverse_name: str = '', first_seen: str = '',
                        description: str = '') -> EntityRelationship:
    return EntityRelationship(
        name=name,
        reverse_name=reverse_name,
        entity_a=entity_a,
        entity_a_type=entity_a_type,
        entity_b=entity_b,
        entity_b_type=entity_b_type,
        source_reliability=source_reliability,
        brand=BRAND,
        fields={
            "firstSeenBySource": first_seen or datetime.now().isoformat('T'),
            "lastSeenBySource": datetime.now().isoformat('T'),
            "description": description
        }
    )


# --------------------------------------------------- Main functions---------------------------------------------


def validate_arguments(args: dict) -> Dict[str, str]:
    """Get the args of the command and validate the arguments.

    :return: raise an error if one of the validations fail.
    :rtype: ``None``
    """
    if len(argToList(args.get('entity_a'))) > 1:
        raise Exception("entity_a is a list, Please insert a single entity_a to create the relationship")
    if len(argToList(args.get('entity_b_type'))) > 1:
        raise Exception("entity_b_type is a list, Please insert a single type to create the relationship")
    if len(argToList(args.get('entity_a_type'))) > 1:
        raise Exception("entity_a_type is a list, Please insert a single type to create the relationship")
    if args.get('entity_b') and args.get('entity_b_type') and args.get('entity_b_query'):
        raise Exception("entity_b_query can not be used with entity_b and/or entity_b_type")
    if not args.get('entity_b_query') and not args.get('entity_b'):
        raise Exception("Missing entity_b in the create relationships")
    if args.get('entity_b') and not args.get('entity_b_type'):
        raise Exception("Missing entity_b_type in the create relationships")
    return args


def create_indicators(args: dict):
    """
    When the create_indicator argument is set to True, create the new indicator first.

    :type args: ``dict``
    :param args: dict of arguments of the command.

    :return: return a list of errors, empty if no errors.
    :rtype: ``None``
    """
    entity_b_to_create = remove_existing_entity_b_indicators(argToList(args.get('entity_b')),
                                                             args.get('entity_b_query', ''))
    indicators = []
    for entity_b in entity_b_to_create:
        indicator = {
            'value': entity_b,
            'type': args.get('entity_b_type'),
        }
        indicators.append(indicator)
    errors = list()
    for indicator in indicators:
        res = demisto.executeCommand("createNewIndicator", indicator)
        if is_error(res[0]):
            errors.append("Error creating indicator - {}".format(res[0]["Contents"]))
    demisto.debug(
        f"Create Indicators From CreateIndicatorRelationship automation: {len(indicators) - len(errors)}"
        f" indicators were created with values {str(indicators)}"
    )
    if errors:
        demisto.debug(f'Errors were found while creating indicators from CreateIndicatorRelationships automation:'
                      f' {json.dumps(errors, indent=4)}')


def create_relationships(args: dict) -> Tuple[List[EntityRelationship], str]:
    """
    Create relationships from given arguments.

    :type args: ``dict``
    :param args: dict of arguments of the command.

    :return: relationships object with human readable output.
    :rtype: ``tuple``
    """
    if args.get('entity_b_query'):
        relationships = create_relation_command_using_query(args)
    else:
        relationships = create_relationships_with_args(args)

    if len(relationships) == 1:
        human_readable = f"Relationship for {args.get('entity_a')} was created successfully."
    elif len(relationships) > 1:
        human_readable = f"{str(len(relationships))} Relationships for {args.get('entity_a')} were created successfully."
    else:
        human_readable = f"Relationships were not created for {args.get('entity_a')}."
    return relationships, human_readable


''' MAIN FUNCTION '''


def main():
    try:
        args = validate_arguments(demisto.args())
        if argToBoolean(args.get('create_indicator')):
            create_indicators(args)
        relationships, human_readable = create_relationships(args)
        return_results(CommandResults(readable_output=human_readable, relationships=relationships))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute CreateIndicatorRelationships automation. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
