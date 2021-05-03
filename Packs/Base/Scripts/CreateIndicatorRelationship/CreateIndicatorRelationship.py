import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback

''' STANDALONE FUNCTION '''

BRAND = "XSOAR"
PAGE_SIZE = 2000


def build_create_relationships_result(relationships, human_readable):
    if relationships:
        relationships = [relation.to_entry() for relation in relationships]
    return {
        'Type': 1,
        'ContentsFormat': 'json',
        'Contents': None,
        'HumanReadable': human_readable,
        'EntryContext': {},
        'IndicatorTimeline': [],
        'IgnoreAutoExtract': False,
        'Relationships': relationships,
        'Note': False
    }


def find_indicators_by_query(query):
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


def create_relationships(args):
    if args.get('entity_b_query'):
        relationships = create_relation_command_using_query(args)
    else:
        relationships = create_relationships_with_args(args)

    if len(relationships) == 1:
        human_readable = f"Relationship for {args.get('entity_a')} was created successfully."
    elif len(relationships) > 1:
        human_readable = f"Relationships for {args.get('entity_a')} were created successfully."
    else:
        human_readable = f"Relationships were not created for {args.get('entity_a')}."
    return relationships, human_readable


def remove_existing_entity_b_indicators(args):
    entity_b_list = argToList(args.get('entity_b'))
    if args.get('entity_b_query'):
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


def create_indicators(args):
    entity_b_to_create = remove_existing_entity_b_indicators(args)
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
    return_outputs(
        "Create Indicators From CreateIndicatorRelationship automation: {} indicators were created.".format(
            len(indicators) - len(errors)
        )
    )
    if errors:
        return_error(json.dumps(errors, indent=4))


def create_relation_command_using_query(args):
    relationships = []
    indicators = find_indicators_by_query(args.get('entity_b_query'))
    for indicator in indicators:
        relationships.append(create_relationship(name=args.get('relationship'), entity_a=args.get('entity_a'),
                                                 entity_a_type=args.get('entity_a_type'),
                                                 entity_b=indicator.get('entity_b'),
                                                 entity_b_type=indicator.get('entity_b_type'),
                                                 source_reliability=args.get('source_reliability', ''),
                                                 reverse_name=args.get('reverse_relationship', ''),
                                                 first_seen=args.get('first_seen'),
                                                 description=args.get('description')
                                                 ))
    return relationships


def create_relationships_with_args(args):
    relationships = []
    entity_b_list = argToList(args.get('entity_b'))
    for entity_b in entity_b_list:
        relationships.append(create_relationship(name=args.get('relationship'), entity_a=args.get('entity_a'),
                                                 entity_a_type=args.get('entity_a_type'),
                                                 entity_b=entity_b, entity_b_type=args.get('entity_b_type'),
                                                 source_reliability=args.get('source_reliability', ''),
                                                 reverse_name=args.get('reverse_relationship', ''),
                                                 first_seen=args.get('first_seen', ''),
                                                 description=args.get('description', '')))
    return relationships


def create_relationship(name, entity_a, entity_a_type, entity_b, entity_b_type, source_reliability='', reverse_name='',
                        first_seen='', description=''):
    return EntityRelation(
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


def validate_arguments() -> Dict[str, str]:
    """Get the args of the command and validate the arguments.

    :return: raise an error if one of the validations fail.
    :rtype: ``None``
    """
    args = demisto.args()
    if len(argToList(args.get('entity_a'))) > 1:
        raise Exception("entity_a is a list, Please insert a single entity_a to create the relationship")
    if len(argToList(args.get('entity_b_type'))) > 1:
        raise Exception("entity_b_type is a list, Please insert a single type to create the relationship")
    if args.get('entity_b') and args.get('entity_b_type') and args.get('entity_b_query'):
        raise Exception("entity_b_query can not be used with entity_b and/or entity_b_type")
    if not args.get('entity_b_query') and not args.get('entity_b'):
        raise Exception("Missing entity_b in the create relationships")
    if args.get('entity_b') and not args.get('entity_b_type'):
        raise Exception("Missing entity_b_type in the create relationships")
    return args

''' MAIN FUNCTION '''


def main():
    try:
        args = validate_arguments()
        if argToBoolean(args.get('create_indicator')):
            create_indicators(args)
        relationships, human_readable = create_relationships(args)
        demisto.results(build_create_relationships_result(relationships, human_readable))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute CreateIndicatorRelationships automation. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
