import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io


def main():
    args = demisto.args()
    testName = args.get("testName", "")
    listName = args.get("listName", "")
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
            datalist = words[1].strip().replace("\n", "")
            # Process commands to load fields or context
            if testType == "LoadFields":
                demisto.executeCommand("UnitTestLoadFieldsList", {'list': datalist})
            elif testType == "LoadContext":
                demisto.executeCommand("UnitTestLoadContextList", {'list': datalist})
            line = buf.readline()

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestCasePrep: {testName} Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
