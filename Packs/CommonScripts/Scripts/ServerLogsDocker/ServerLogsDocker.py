import demistomock as demisto
from CommonServerPython import *

def main():
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
