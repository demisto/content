import demistomock as demisto
from CommonServerPython import *


def main():
    try:
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

    except ValueError as e:
        demisto.error(str(e))
        return_error(
            "The script could not execute the `ssh` command. Please create an instance of the "
            "`RemoteAccess v2` integration and try to run the script again."
        )


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
