import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ATTEMPS = 10


def find_available_branch_azure_devops(pack_name: str, command_get_branch: str):
    response = demisto.executeCommand(command_get_branch, args={})
    branch_name = pack_name
    for i in range(ATTEMPS):
        branch_exists = False
        if i > 0:
            branch_name = f'{pack_name}_{i}'
        for branch in response[0].get("Contents", {}).get("value", []):
            if branch.get("name", "").endswith(branch_name):
                print(f'{branch.get("name")=} {branch_name=}')
                branch_exists = True
                break
        if not branch_exists:
            return f'refs/heads/{branch_name}'
    raise DemistoException('Please enter a branch name.')

def find_available_branch(pack_name: str, command_get_branch: str):
    branch_name = pack_name
    for i in range(ATTEMPS):
        if i > 0:
            branch_name = f'{pack_name}_{i}'
        status, get_branch_res = execute_command(command_get_branch, {'branch_name': branch_name}, fail_on_error=False)
        if (not status) and ('Bad Request' or 'Branch not found' or 'Not Found' in get_branch_res):
            return branch_name
    raise DemistoException('Please enter a branch name.')


''' MAIN FUNCTION '''


def main():  # pragma: no cover

    try:
        pack_name = demisto.getArg('pack')
        command_get_branch = demisto.getArg('use_command')

        if command_get_branch == 'azure-devops-branch-list':
            branch_name = find_available_branch_azure_devops(pack_name, command_get_branch)
            print(f"{branch_name=}")
        else:
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
