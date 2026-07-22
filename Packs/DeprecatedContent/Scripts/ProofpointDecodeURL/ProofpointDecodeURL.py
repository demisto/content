import demistomock as demisto
from CommonServerPython import *

args = {
    "input": demisto.args().get("url")
}
res = demisto.executeCommand("UnEscapeURLs", args)

if is_error(res):
    return_error("Error: An error returned, could not parse URL.")
else:
    decoded_url = res[0].get("Contents")
    entry_context = {
        "Data": decoded_url
    }
    return_outputs(
        readable_output="Decoded URL is: {0}".format(decoded_url),
        raw_response=decoded_url,
        outputs={
            'URL(val.Data && val.Data == obj.Data)': entry_context
        }
    )
