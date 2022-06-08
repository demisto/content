import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# #### Variables #####
use_case_list_arg = demisto.args().get('list')
use_case_title = demisto.args().get('title')
use_case_date = demisto.args().get('review_date')

# #### Logic #####
use_case_list_raw = demisto.executeCommand("getList", {"listName": use_case_list_arg})
use_case_list = safe_load_json(use_case_list_raw[0]['Contents'])

if use_case_title in use_case_list:
    old_value = use_case_list[use_case_title]
else:
    old_value = ""

use_case_list[use_case_title] = use_case_date

demisto.executeCommand("setList", {"listName": use_case_list_arg, "listData": use_case_list})

results = {
    "old_value": old_value,
    "new_value": use_case_date
}

return_results(results)
