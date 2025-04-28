import demistomock as demisto
from CommonServerPython import *


def check_remote_access_integration_enable():
    found_module = False
    for module in demisto.getModules().values():
        if "RemoteAccess v2" in module.get('brand') and module.get("state") == "active":
            demisto.debug('RemoteAccess v2 is enabled.')
            found_module = True

    if not found_module:
        return_error("The script could not execute the `ssh` command. Please create an instance of the "
                     "`RemoteAccess v2` integration and try to run the script again.")


def main():
    check_remote_access_integration_enable()
    file = "/var/log/demisto/docker.log"
    res = demisto.executeCommand("ssh", {"cmd": f"cat {file}"})

    contents = res[0].get('Contents')
    if isinstance(contents, list):
        contents = contents[0]

    if contents.get('error'):
        raise Exception(contents.get('error'))

    output = f"File: {file}\n"
    output += contents.get("output")

    return_results(output)


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
