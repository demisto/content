import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

# Get arguments
search_string = demisto.args().get("searchString")
list_name = demisto.args().get("listName")
case_insensitive = demisto.args().get("caseInsensitive", "false").lower() == "true"
use_wildcard = demisto.args().get("useWildcard", "false").lower() == "true"

# Retrieve the list content
res = demisto.executeCommand("getList", {"listName": list_name})[0]
list_contents = res.get("Contents", "")

# Normalize list to lines
if isinstance(list_contents, str):
    list_items = list_contents.splitlines()
else:
    list_items = list_contents

# Prepare search pattern
if search_string and list_items:
    if use_wildcard:
        # Convert wildcard to regex: * → .*, ? → .
        pattern = re.escape(search_string).replace(r'\*', '.*').replace(r'\?', '.')
        flags = re.IGNORECASE if case_insensitive else 0
        regex = re.compile(f"^{pattern}$", flags)
        match_found = any(regex.match(item) for item in list_items)
    else:
        if case_insensitive:
            match_found = any(search_string.lower() == item.lower() for item in list_items)
        else:
            match_found = search_string in list_items

    demisto.results("yes" if match_found else "no")
else:
    demisto.results("no")
