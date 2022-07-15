import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' COMMAND FUNCTION '''


def mapper_command(args: Dict[str, Any]) -> CommandResults:
    format = str(args.get('format', '{1}-{2}'))
    list1 = argToList(args.get('list1', []))
    list2 = argToList(args.get('list2', []))

    res = [format.replace('{1}', x).replace('{2}', y) for x, y in zip(list1, list2)]

    return CommandResults(outputs={
        'zipped_list': res
    })


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    try:
        return_results(mapper_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
