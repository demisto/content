import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any


def check_components(components: list, context: Any):
    """
    Args:
        components(list): list of components related to one field to search
        context: context to check the fields in
    """
    for idx, component in enumerate(components):
        if isinstance(context, list) and context:
            for x in context:
                check_components(components[idx:], x)
                return
        else:
            context = context[component]
            if not context:
                raise KeyError


def check_fields(fields_to_search_array: list, context_json) -> tuple[bool, Any]:
    """
    Args:
        fields_to_search_array(list): list of fields to search
        context_json: context to check the fields in

    Returns: True if all fields are in context_json, else false.
    """
    non_found_field = None
    try:
        for fields in fields_to_search_array:
            components = fields.split('.')
            new_context = context_json
            non_found_field = fields
            check_components(components, new_context)

    except KeyError:
        return False, non_found_field
    return True, None


def check_fields_command(args: dict[str, Any]) -> CommandResults:
    """
    Args:
        args(dict): args from demisto

    Returns: Command Results with context and human readable output
    """
    fields_to_search = argToList(args.get('fields_to_search'))
    context = args.get('object', '{}')

    # Call the standalone function and get the raw response
    result, non_found_field = check_fields(fields_to_search, context)
    readable_output = f'Fields {",".join(fields_to_search)} are in given context.' if result \
        else f'Field "{non_found_field}" is not in context.'

    return CommandResults(
        outputs_prefix='CheckIfFieldsExists.FieldsExists',
        outputs_key_field='',
        outputs=result,
        readable_output=readable_output
    )


def main():
    try:
        return_results(check_fields_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute VerifyObjectFieldsList. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
