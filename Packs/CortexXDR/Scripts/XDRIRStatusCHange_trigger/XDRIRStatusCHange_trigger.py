import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *
from typing import Dict, Any


''' STANDALONE FUNCTION '''


def trigger_playbook():
    playbook_to_run = "my_test_playbook"
    demisto.executeCommand("setPlaybook", {"name": playbook_to_run})
    


''' MAIN FUNCTION '''


def main():
    try:
        trigger_playbook()
    except Exception as ex:
        return_error(f'Failed to execute XDRIRStatusCHange_trigger. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
