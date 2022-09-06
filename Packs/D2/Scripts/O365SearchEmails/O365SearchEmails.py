import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

REGEX_RESULTS = r"Search results\: \{([^}]*)\}"


def main():
    res = []
    d_args = demisto.args()
    d_args['using'] = d_args['system']


    del_arg = demisto.get(d_args, 'delete')
    if type(del_arg) in [str, str] and del_arg.lower() == 'true':
        demisto.info('[*] Script set to also delete found emails.')
        res_cmd_name = demisto.executeCommand("D2O365SearchAndDelete", d_args)
    else:
        res_cmd_name = demisto.executeCommand("D2O365ComplianceSearch", d_args)
    try:
        for entry in res_cmd_name:
            if isError(entry):
                res = res_cmd_name
                break
            else:
                if result := get_search_results_from_entry(entry):
                    res.append(result)
    except Exception as ex:
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Error occurred while parsing output from command. Exception info:\n" + str(ex)
                                + "\n\nInvalid output:\n" + str(res_cmd_name)})
    demisto.results(res)


def get_search_results_from_entry(entry):
    my_data = demisto.get(entry, 'Contents')
    match = re.search(REGEX_RESULTS, my_data)
    if match and match.groups():
        search_results = match.groups()[0]
        return {"Type": entryTypes["note"],
                    "ContentsFormat": formats["text"], "Contents": search_results}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
