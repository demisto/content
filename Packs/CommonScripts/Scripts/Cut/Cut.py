import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()

value = args.get("value")
fields = args.get("fields")
delim = args.get("delimiter")
if delim == "''":
    delim = ""

data = value.split(delim)
fields = [int(_) for _ in fields.split(",")]

max_index = max(fields)
if len(data) < max_index:
    return_error("Invalid field index {}, should be between 1 to {}.".format(max_index, len(data)))

demisto.results(delim.join([str(data[i - 1]) for i in fields]))
