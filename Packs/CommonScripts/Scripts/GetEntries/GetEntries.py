import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()

        filter_args = assign_params(tags=argToList(args.get('tags')),
                                    categories=argToList(args.get('categories')))

        ents = execute_command('getEntries', {'filter': filter_args}, extract_contents=False)
        if not ents:
            return_results('No matching entries')
        else:
            outputs = [assign_params(
                ID=demisto.get(ent, 'ID'),
                Type=demisto.get(ent, 'Type'),
                Tags=demisto.get(ent, 'Metadata.tags'),
                Category=demisto.get(ent, 'Metadata.category'),
                Created=demisto.get(ent, 'Metadata.created'),
                Modified=demisto.get(ent, 'Metadata.modified')) for ent in ents]
            return_results(CommandResults(outputs_prefix='Entry', outputs=outputs, readable_output='Done.', raw_response=ents))
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GetEntries.\nError:\n{type(e)}, {str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
