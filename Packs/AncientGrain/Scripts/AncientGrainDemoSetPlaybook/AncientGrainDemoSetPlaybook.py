import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' MAIN FUNCTION '''


def main():

    demisto.executeCommand("setPlaybook", {"name":"RH - ChatGPT Ancient Grain Recipes"})


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
