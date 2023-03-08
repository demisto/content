import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
result = demisto.executeCommand("demisto-api-post", {"uri": "/automation/search",
                                "body": {"query": "tags:training AND system:F"}})
scripts = [{"Name": x["name"], "Description":x["comment"], "Tags":x["tags"]}
           for x in result[0]["Contents"]["response"]["scripts"]]

# remove the Training tag
for script in scripts:
    tags = script["Tags"]
    tags.remove("training")
    script["Tags"] = tags

# return a MD entry for the dynamic section
results = CommandResults(readable_output=tableToMarkdown(
    'Training Automation Scripts', scripts, headers=["Name", "Description", "Tags"]))
return_results(results)
