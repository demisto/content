import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import traceback

def get_index(json_data,array_val):
    element_index=json_data.index(array_val)
    return element_index

''' MAIN FUNCTION '''
def main():
    args = demisto.args()
    json_data = argToList(args.get('value'))
    array_val = args.get('item_to_find')
    try:
        return_results(get_index(json_data,array_val))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

