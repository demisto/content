import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

''' MAIN FUNCTION '''


def main():

    item = argToList(demisto.args().get('UserToDelete'))
    print('Item: ' + str(item))
    body = {"ids": item}

    print('\nBody: ' + str(body) + '\n')
    tojson = json.dumps(body)
    print(type(tojson))

    try:
        execute_command("core-api-post", {"uri": "/users/delete", "body": tojson})

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
