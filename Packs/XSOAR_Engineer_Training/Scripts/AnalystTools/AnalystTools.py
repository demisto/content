import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# requires an xsoar list with the following format example format
#[{"Name":"Google","Link":"https://www.google.ca"},{"Name":"Cortex XSOAR Admin Guide","Link":"https://docs.paloaltonetworks.com/cortex/cortex-xsoar.html"}]

# get the list
tools = demisto.executeCommand("getList", {"listName": "Analyst Tools"})[0]['Contents']

# default tools list if there is no list from above.
default_tools = [
    {"Name": "Google", "Link": "https://www.google.ca"},
    {"Name": "Cortex XSOAR Admin Guide", "Link": "https://docs.paloaltonetworks.com/cortex/cortex-xsoar.html"},
    {"Name": "Cortex XSOAR Developer Guide", "Link": "https://xsoar.pan.dev/"},
    {"Name": "Cortex XSOAR Integration Documentation Reference", "Link": "https://xsoar.pan.dev/docs/reference/index"},
    {"Name": "Cortex XSOAR Feature Request Portal", "Link": "https://xsoar.ideas.aha.io/"},
    {"Name": "Cortex XSOAR Webinars", "Link": "https://event.on24.com/wcc/r/2947927/BB6BF4B437CD3534B314909D4E3C8BE3/1064499"},
    {"Name": "Palo Alto Networks Live Community", "Link": "https://live.paloaltonetworks.com/"},
    {"Name": "Palo Alto Networks Support Portal", "Link": "https://https://support.paloaltonetworks.com/"},
    {"Name": "Palo Alto Networks URL Filtering", "Link": "https://urlfiltering.paloaltonetworks.com/"}
]

# check if the list exists, if not create it:
if "Item not found" in tools:
    demisto.executeCommand("createList", {"listName": "Analyst Tools", "listData": default_tools})
    tools = json.loads(demisto.executeCommand("getList", {"listName": "Analyst Tools"})[0]["Contents"])
else:
    tools = json.loads(tools)

# add the markdown for the link
for tool in tools:
    tool['Link'] = f"[{tool.get('Name')}]({tool.get('Link')})"

# return a MD entry for the dynamic section
results = CommandResults(readable_output=tableToMarkdown('Analyst Tools', tools, ['Link']))
return_results(results)
