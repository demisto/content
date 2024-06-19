import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

file_id = demisto.args().get("entryID")
context_key = demisto.args().get("contextKey")

# get the file path, for the above file.
res = demisto.getFilePath(file_id)
if not res:
    return_error(f"Entry {file_id} not found")

file_path = res.get('path')

# open the file, and try and load the JSON, error if it's invalid.
with open(file_path) as f:
    try:
        data = json.load(f)
    except ValueError as e:
        return_error(f"File is not valid JSON: {e}")
    except Exception:
        return_error("Something else went wrong...")

# return the results to context
results = CommandResults(
    readable_output=f"Loaded JSON to context key: {context_key} from file.",
    outputs_prefix=context_key,
    outputs=data,
    ignore_auto_extract=True)

return_results(results)
