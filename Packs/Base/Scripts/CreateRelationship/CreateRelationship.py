import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import traceback

''' STANDALONE FUNCTION '''


def build_create_relationships_result(relationships, human_readable):
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


def validate_arguments() -> Dict[str, str]:
    """Returns a simple python dict with the information provided
    in the input (dummy).

    :type dummy: ``str``
    :param dummy: string to add in the dummy dict that is returned

    :return: dict of all relevant arguments for the relationship.
    :rtype: ``dict``
    """
    args = demisto.args()
    indicators = []
    if args.get('entity_b') and args.get('entity_b_type') and args.get('entity_b_query'):
        raise Exception("entity_b_query can not be used with entity_b and/or entity_b_type")
    if args.get('entity_b') and args.get('entity_b_query') or args.get('entity_b_type') and args.get('entity_b_query'):
        raise Exception("entity_b_query can not be used with entity_b and/or entity_b_type")

    if args.get('entity_b_query'):
        args['entity_b'] = find_indicators_to_limit_loop(query) # ????????????????

    if argToBoolean(args.get('create_indicator')):
        # entityb_b = search for all indicators, check that do not exists and create. ???????????????
        entityb_b_list = []
        for entity_b in entityb_b_list:
            indicator = {
                'value': entity_b,
                'type': args.get('entity_b_type'),
            }
            indicators.append(indicator)

    return args


''' COMMAND FUNCTION '''


def create_relation_command(args):
    relationships = []
    entity_b_list = argToList(args.get('entity_b', []))
    for entity_b in entity_b_list:
        relationships.append(EntityRelation(
            name=args.get("name"),
            reverse_name=args.get("reverse_name", ''),
            entity_a=args.get("entity_a"),
            entity_a_type=args.get("object_type_a"),
            entity_b=entity_b,
            entity_b_type=args.get("object_type_b"),
            source_reliability=args.get("source_reliability"),
            brand="XSOAR",
            fields={
                "revoked": bool(demisto.getArg("revoked")),
                "firstSeenBySource": demisto.getArg("first_seen_by_source") or datetime.now().isoformat('T'),
                "lastSeenBySource": demisto.getArg("last_seen_by_source") or datetime.now().isoformat('T'),
                "description": demisto.getArg('description')
                }
            )
        )

    if len(relationships) == 1:
        human_readable = f"Relationship for {args.get('entity_a')} was created successfully."
    elif len(relationships) > 1 :
        human_readable = f"Relationships for {args.get('entity_a')} were created successfully."
    else:
        human_readable = f"Relationships were not created for {args.get('entity_a')}. "
    return relationships, human_readable


''' MAIN FUNCTION '''


def main():
    try:
        args = validate_arguments()
        relationships, human_readable = create_relation_command(args)
        demisto.results(build_create_relationships_result(relationships, human_readable))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute create-relation automation. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
