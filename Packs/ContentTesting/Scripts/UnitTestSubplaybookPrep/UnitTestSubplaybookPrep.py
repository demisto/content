import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io


def main():
    try:
        listName = demisto.args().get("listName", "").strip()
        if listName != "":
            listlines = demisto.executeCommand("getList", {'listName': listName})[0]['Contents']
            buf = io.StringIO(listlines)
            line = buf.readline()

            while line != "":
                words = line.split(",", 1)
                inputs = json.loads(words[1].strip())
                # Set context values in prep for running the subplaybook
                for key, val in inputs.items():
                    demisto.setContext(key, val)
                line = buf.readline()

    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestSubplaybookPrep: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
