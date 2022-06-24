import random
import traceback
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():
    try:
        targetList = demisto.args().get("list")
        engagement_list = demisto.executeCommand("getList", {"listName": targetList})[0]["Contents"].split(",")
        random.shuffle(engagement_list)
        buffer_list = ""
        for token in engagement_list:
            buffer_list = buffer_list + token.replace('"', '') + ","
        buffer_list = buffer_list[:-1]
        demisto.executeCommand("setList", {"listName": targetList, "listData": buffer_list})
        return_results("List " + targetList + " successfully shuffled!")
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
