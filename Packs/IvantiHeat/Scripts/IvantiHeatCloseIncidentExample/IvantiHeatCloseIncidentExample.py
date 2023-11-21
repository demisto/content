import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


"""
Use the IvantiHeatCloseIncidentExample script to close incident object in Ivanti Heat.
The script gets the record Id as argumet to create the "close incident" action payload(JSON)
and sets it inside the IvantiHeat.CloseIncidentJSON context path.
To close incident in Ivanti, execute the script and call the “ivanti-heat-object-perform-action” command where the
request-data argument value equals the script output and action equals Close_Incident:
!ivanti-heat-object-perform-action action=Close_Incident object-id=1
object-type=incidents request-data=${ivantiHeat.CloseIncidentJSON} .
See the Ivanti documentation for more information on quick actions:
*tenant-url*/help/admin/Content/Configure/QuickActions/Using_Quick_Actions.htm
"""


def main():
    rec_id = demisto.args().get('rec_id')
    data = {
        "ActionId": "3492dbcc-e502-44fd-9790-e3e45cb26c45",
        "ShouldSave": True,
        "ActionParams": {
            "FormParams": {
                "actionId": "3492dbcc-e502-44fd-9790-e3e45cb26c45",
                "actualObjectType": "Incident#",
                "objectId": rec_id
            },
            "GridParams": None
        },
        "PromptParams": [
            {
                "Value": "Closed",
                "FieldName": "Status"
            },
            {
                "__type": "DataLayer.PromptData",
                "Label": "Select Cause Code",
                "ActionId": "3492dbcc-e502-44fd-9790-e3e45cb26c45",
                "ActionObjectId": "CAA8B29A4D24464FA68DBF281D7505B9",
                "PromptObjectId": "CAA8B29A4D24464FA68DBF281D7505B9",
                "ActionObjectType": "Incident#",
                "PromptObjectType": "Incident#",
                "Value": "Documentation Request",

                "FieldName": "CauseCode"
            },
            {
                "__type": "DataLayer.PromptData",
                "Label": "Is first call resolution?",
                "ActionId": "3492dbcc-e502-44fd-9790-e3e45cb26c45",
                "ActionObjectId": "CAA8B29A4D24464FA68DBF281D7505B9",
                "PromptObjectId": "CAA8B29A4D24464FA68DBF281D7505B9",
                "ActionObjectType": "Incident#",
                "PromptObjectType": "Incident#",
                "Value": None,
                "ValidList": "",
                "FieldName": "FirstCallResolution",
                "FieldType": "boolean",
                "FieldLength": 0,
                "Precision": 0,
                "FieldAreaWidth": 0,
                "FieldAreaHeight": 0,
                "Password": False,
                "Required": False,
                "DefaultValue": None,
                "Hidden": False,
                "IsNewPrompt": True
            },
            {
                "__type": "DataLayer.PromptData",
                "Label": "Resolution",
                "ActionId": "3492dbcc-e502-44fd-9790-e3e45cb26c45",
                "ActionObjectId": "CAA8B29A4D24464FA68DBF281D7505B9",
                "PromptObjectId": "CAA8B29A4D24464FA68DBF281D7505B9",
                "ActionObjectType": "Incident#",
                "PromptObjectType": "Incident#",
                "Value": "test",
                "FieldName": "Resolution"

            }
        ]
    }
    return_outputs(json.dumps(data, indent=4), {'IvantiHeat.CloseIncidentJSON': json.dumps(data)}, data)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
