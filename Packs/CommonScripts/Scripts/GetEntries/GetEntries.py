import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()

        params = assign_params(id=args.get('id'),
                               filter=assign_params(
                                   tags=argToList(args.get('tags')),
                                   categories=argToList(args.get('categories')),
                                   pageSize=arg_to_number(args.get('page_size')),
                                   lastId=args.get('last_id'),
                                   firstID=args.get('first_id'),
                                   selectedEntryID=args.get('selected_entry_id'),
                                   users=argToList(args.get('users')),
                                   tagsAndOperator=argToBoolean(args.get('tags_and_operator', False)),
                                   fromTime=args.get('from_time'),
                                   parentID=args.get('parent_id')
        ))

        ents = demisto.executeCommand('getEntries', params)
        if not ents:
            return_results('No matching entries')
        else:
            ents = ents if isinstance(ents, list) else [ents]
            if is_error(ents) and not demisto.get(ents[0], 'ID'):
                error_message = get_error(ents)
                raise DemistoException(f'Failed to execute getEntries. Error details:\n{error_message}')

            outputs = [assign_params(
                ID=demisto.get(ent, 'ID'),
                Type=demisto.get(ent, 'Type'),
                Tags=demisto.get(ent, 'Metadata.tags'),
                Category=demisto.get(ent, 'Metadata.category'),
                Created=demisto.get(ent, 'Metadata.created'),
                Modified=demisto.get(ent, 'Metadata.modified')) for ent in ents]
            return_results(CommandResults(outputs_prefix='Entry',
                                          outputs=outputs,
                                          readable_output=f'Found {len(ents)} entries.',
                                          raw_response=ents))
    except Exception as e:
        demisto.debug(traceback.format_exc())
        return_error(f'Failed to execute GetEntries.\nError:\n{type(e)}, {str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
