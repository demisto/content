import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import demistomock as demisto

ATTEMPS = 10


def find_available_branch(pack_name, command_get_branch):

    branch_name = pack_name
    for i in range(ATTEMPS):
        if i > 0:
            branch_name = f'{pack_name}_{i}'
        try:
            print("*** in try ***")
            status, get_branch_res = execute_command(command_get_branch, {'branch_name': branch_name},
                                                     fail_on_error=False)
        except Exception as ex:
            print("*** in except ***")
            return branch_name
        if not status:
            if 'Branch not found' in get_branch_res:
                return branch_name
            else:
                raise DemistoException(get_branch_res)


''' MAIN FUNCTION '''


def main():

    try:
        pack_name = demisto.getArg('pack')
        command_get_branch = demisto.getArg('command_get_branch')
        branch_name = find_available_branch(pack_name, command_get_branch)

        return_results(CommandResults(
            readable_output=branch_name,
            outputs_prefix='AvailableBranch',
            outputs=branch_name
        ))

    except Exception as ex:
        demisto.error(str(ex))  # print the traceback
        return_error(f'Failed to execute script. Error: {ex}', error=ex)


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
