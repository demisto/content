import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# requires an XSOAR list that contains a markdown table with links to important Analyst Tools (wikis, google, etc)

# get the Case Management Analyst Tools list
tools = demisto.executeCommand("getList", {"listName": "Case Management Analyst Tools"})[0]['Contents']

# default tools, if the above list does not exist.
default_tools = """
| Link | Description |
| --- | --- |
| [Palo Alto Networks URL Filtering](https://urlfiltering.paloaltonetworks.com/) | Check a URL Category via Palo Altos Test a Site utility |
| [Cortex XSOAR Admin Guide](https://docs-cortex.paloaltonetworks.com/p/XSOAR) | Cortex XSOAR Admin Guide |
| [Cortex XSOAR Developer Guide](https://xsoar.pan.dev/) | The XSOAR Developer Guide |
| [Cortex XSOAR Integration Reference](https://xsoar.pan.dev/docs/reference/index) | Reference documentation for Cortex XSOAR Integrations |
| [Palo Alto Networks Live Community](https://live.paloaltonetworks.com/) | Palo Alto Networks Live Community, which includes training and how-to blog posts! |
| [Palo Alto Networks Support Portal](https://support.paloaltonetworks.com/) | Palo Alto Networks Support Portal |

**To create your own list, create an XSOAR list called "+Case Management Analyst Tools+", and add a Markdown Table with your own list.**
"""  # noqa: E501

# check if the list exists, if not, display the default_tools
if "Item not found" in tools:
    tools = default_tools

# return markdown in results.
result = CommandResults(readable_output=tools, ignore_auto_extract=True)
return_results(result)
