import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
field = demisto.args()['field']
formType = demisto.args()['formType']
# You can create a condition for the incident, which is served as a JSON object.
# You can view the original field settings and take necessary action - such as validate that the options are part of the global set in the field definition.
# You can view the current form type (new, edit, close) and take necessary action - such as show fields only in the close form.
if incident["id"] == "":
    # This is a new incident, hide the field
    demisto.results({"hidden": True, "options": []})
else:
    # This is an existing incident, we want to show the field, to know which values to display
    # we will take them from the field definition
    options = []
    if "Select" in demisto.get(field, "type"):
        options = demisto.get(field, "selectValues")
    demisto.results({"hidden": False, "options": options})
