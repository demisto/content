import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io


def main():
    args = demisto.args()
    testName = args.get("testName", "")
    listName = args.get("listName", "")
    addAfter = args.get("addAfter", "")
    try:
        if listName != "":
            listlines = demisto.executeCommand("getList", {'listName': listName})[0]['Contents']
            buf = io.StringIO(listlines)
        else:
            raise DemistoException("No test case list provided")

        line = buf.readline()
        while line != "":
            words = line.split("|", 1)
            testType = words[0].strip()
            # Process commands
            if testType == "Automation" or testType == "Subplaybook" or testType == "Playbook":
                if testType == "Playbook":
                    testList = ""
                    playbooks = words[1].strip()
                else:
                    testList = words[1].strip()
                    playbooks = ""
                args = {
                    'playbook': playbooks,
                    'addAfter': addAfter,
                    'testType': testType,
                    'listName': testList
                }
                demisto.executeCommand("UnitTest", args)
            line = buf.readline()

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestCase: {testName} Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
