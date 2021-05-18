import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re

import traceback


# --------------------------------------------------- Helper functions---------------------------------------------


def to_context(relationships: list, verbose: bool) -> List[dict]:
    """
    Create context entries from the relationships returned from the searchRelationships command.

    :type relationships: ``list``
    :param relationships: list of dict of relationships from the searchRelationships command.

    :type verbose: ``bool``
    :param verbose: True if extended context should return, False for basic.

    :return: list of context for each relationship.
    :rtype: ``list``
    """
    context_list = []
    for relationship in relationships:
        relationships_context = {'EntityA': relationship['entityA'],
                                 'EntityAType': relationship['entityAType'],
                                 'EntityB': relationship['entityB'],
                                 'EntityBType': relationship['entityBType'],
                                 'Relationship': relationship['name'],
                                 'Reverse': relationship['reverseName'],
                                 'ID': relationship['id']}
        if verbose:
            relationships_context['Type'] = relationship.get('type', '')

            sources = relationship.get('sources')
            if sources:
                relationships_context['Reliability'] = sources[0].get('reliability', '')
                relationships_context['Brand'] = sources[0].get('brand', '')

            custom_fields = relationship.get('CustomFields', {})
            if custom_fields:
                relationships_context['Revoked'] = custom_fields.get('revoked', '')
                relationships_context['FirstSeenBySource'] = custom_fields.get('firstseenbysource', '')
                relationships_context['LastSeenBySource'] = custom_fields.get('lastseenbysource', '')
                relationships_context['Description'] = custom_fields.get('description', '')

        context_list.append(relationships_context)

    return context_list


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        entities = args.get('entities', '')
        entities_types = args.get('entities_types', '')
        relationships = args.get('relationships', '')
        limit = int(args.get('limit'))
        verbose = argToBoolean(args.get('verbose', 'false'))
        revoked = argToBoolean(args.get('revoked', 'false'))
        query = 'revoked:T' if revoked else 'revoked:F'

        res = demisto.executeCommand("searchRelationships", {'entities': entities, 'entityTypes': entities_types,
                                                             'relationshipNames': relationships,
                                                             'size': limit, 'query': query})
        if is_error(res[0]):
            raise Exception("Error in searchRelationships command - {}".format(res[0]["Contents"]))

        relationships = res[0].get('Contents', {}).get('data', [])
        if relationships:
            context = to_context(relationships, verbose)
        else:
            context = []
        hr = tableToMarkdown('Relationships', context,
                             headers=['EntityA', 'EntityAType', 'EntityB', 'EntityBType', 'Relationship'],
                             headerTransform=lambda header: re.sub(r"\B([A-Z])", r" \1", header))
        return_results(
            CommandResults(readable_output=hr, outputs_prefix='Relationships', outputs=context, outputs_key_field='ID'))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute SearchIndicatorRelationships automation. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
