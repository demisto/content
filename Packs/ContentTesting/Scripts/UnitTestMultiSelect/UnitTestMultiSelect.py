import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# CONSTANT for task ID to add new task after since no arguments are passed
# Would need to change if adding tasks to a playbook other than UnitTestingTopLevel
MULTISELECT = "10"


def main():
    try:
        args = demisto.args()
        if args.get("new", "") == "":
            return
        playbooks = args.get("new")
        demisto.executeCommand("UnitTest", {'playbook': playbooks, 'addAfter': MULTISELECT, 'testType': "Multiselect"})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestingMultiSelect: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
