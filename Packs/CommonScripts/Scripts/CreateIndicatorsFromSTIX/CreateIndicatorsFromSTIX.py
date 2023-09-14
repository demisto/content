import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def parse_indicators_using_stix_parser(entry_id):
    """ Parse Indicators using StixParserV2.

    :param entry_id: the uploaded file for the script
    :return: parsed indicators in stix Parser
    """
    if not entry_id:
        return_error(f"Could not find file for entry id {entry_id}.")
    comm_output = demisto.executeCommand("StixParser", {"entry_id": entry_id})
    indicators = comm_output[0].get("Contents")
    if is_error(comm_output[0]):
        return_error(indicators)
    return json.loads(indicators)


def create_relationships_from_entity(indicator_relationships):
    if not indicator_relationships:
        return None
    entity_relationships = list()
    for relationship in indicator_relationships:
        relationship_object = EntityRelationship(name=relationship.get('name'),
                                                 entity_a=relationship.get('entityA'),
                                                 entity_b=relationship.get('entityB'),
                                                 entity_a_type=relationship.get('entityAType'),
                                                 entity_b_type=relationship.get('entityBType'),
                                                 relationship_type=relationship.get('type'))
        entity_relationships.append(relationship_object)

    return entity_relationships


def create_indicators_loop(indicators):
    """ Create indicators using createNewIndicator automation

    :param indicators: parsed indicators
    :return: errors if exist
    """
    relationships_objects = list()
    errors = list()
    for indicator in indicators:
        indicator['type'] = indicator.get('indicator_type')
        relationship_object = create_relationships_from_entity(indicator.get('relationships'))
        if relationship_object:
            relationships_objects.extend(relationship_object)
        res = demisto.executeCommand("createNewIndicator", indicator)
        if is_error(res[0]):
            errors.append(f'Error creating indicator - {(res[0]["Contents"])}')
    result = CommandResults(
        readable_output=f"Create Indicators From STIX: {len(indicators) - len(errors)} indicators were created.",
        relationships=relationships_objects
    )
    return result, errors


def main():  # pragma: no cover
    args = demisto.args()
    entry_id = args.get("entry_id", "")
    indicators = parse_indicators_using_stix_parser(entry_id)
    results, errors = create_indicators_loop(indicators)
    return_results(results)
    if errors:
        return_error(json.dumps(errors, indent=4))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
