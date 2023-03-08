import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
links = [
    {"Name": "Cortex XSOAR Documentation", "Link": "https://docs-cortex.paloaltonetworks.com/p/XSOAR"},
    {"Name": "Cortex XSOAR Developer Guide", "Link": "https://xsoar.pan.dev/"},
    {"Name": "Cortex XSOAR Integration Documentation Reference", "Link": "https://xsoar.pan.dev/docs/reference/index"},
    {"Name": "XSOAR Engineer Training Series", "Link": "https://www.youtube.com/watch?v=BhpkZA9t1HA&list=PLD6FJ8WNiIqUVEA2e5LZhmqNnwFcFhDTZ"},
    {"Name": "Palo Alto Networks Live Community", "Link": "https://live.paloaltonetworks.com/"}
]

# add the markdown for the link
for l in links:
    l['Link'] = f"[{l.get('Name')}]({l.get('Link')})"

# return a MD entry for the dynamic section
results = CommandResults(readable_output=tableToMarkdown('Reference Links', links, ['Link']))
return_results(results)
