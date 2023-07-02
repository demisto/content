import demistomock as demisto
from CommonServerPython import *
from itertools import chain


def format_relation(relation: dict) -> dict:
    """
    Converts a relation to a dictionary with the relevant fields.
    """
    return {
        'name': relation.get('name'),
        'relatedResourceKind': relation.get('properties', {}).get('relatedResourceKind'),
        'relatedResourceType': relation.get('properties', {}).get('relatedResourceType'),
        'relatedResourceName': relation.get('properties', {}).get('relatedResourceName'),
        'relatedResourceId': relation.get('properties', {}).get('relatedResourceId')
    }


def convert_to_table(context_results: str) -> CommandResults:
    """
    Args:
        context_results (str): String representing a list of dicts

    Returns:
        CommandResults: CommandResults object containing only readable_output
    """
    context_results = json.loads(context_results)

    context_formatted = [
        format_relation(relation) for relation in context_results
    ]

    md = tableToMarkdown(
        '',
        context_formatted,
        headers=[*dict.fromkeys(chain.from_iterable(context_formatted))],
        removeNull=True,
        sort_headers=False,
        headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=md
    )


def main():  # pragma: no cover
    context = dict_safe_get(
        demisto.callingContext,
        ['context', 'Incidents', 0, 'CustomFields', 'microsoftsentinelrelations'],
        {}
    )

    if not context:
        return_error('No data to present')

    return_results(convert_to_table(context))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
