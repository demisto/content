import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ERROR_MESSAGE = ()


def execute_ssh_command():
    """Execute the `ssh` command to get the server logs and return the result to the war room."""
    file = "/var/log/demisto/server.log"
    res = demisto.executeCommand("ssh", {"cmd": f"tail {file}"})

    contents = res[0].get('Contents')
    if isinstance(contents, list):
        contents = contents[0]

    if contents.get('error'):
        raise Exception(contents.get('error'))

    output = f"File: {file}\n"
    output += contents.get("output")
    output = re.sub(r" \(source: .*\)", "", output)

    return_results(output)


def check_remote_access_integration_enable():
    found_module = False
    for module in demisto.getModules().values():
        if "RemoteAccess v2" in module.get('brand') and module.get("state") == "active":
            demisto.debug('RemoteAccess v2 is enabled.')
            found_module = True

    if not found_module:
        return_error("The script could not execute the `ssh` command. Please create an instance of the "
                     "`RemoteAccess v2` integration and try to run the script again.")


def main():  # pragma: no cover
    check_remote_access_integration_enable()
    try:
        execute_ssh_command()
    except ValueError as e:
        demisto.error(str(e))
        return_error("The script could not execute the `ssh` command. Please create an instance of the "
                     "`RemoteAccess v2` integration and try to run the script again.")


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
