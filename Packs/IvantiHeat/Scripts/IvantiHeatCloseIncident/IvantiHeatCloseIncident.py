import json

import demistomock as demisto
from CommonServerPython import *


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
