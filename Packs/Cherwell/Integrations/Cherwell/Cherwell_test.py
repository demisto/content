from datetime import datetime, timedelta
from CommonServerPython import date_to_timestamp
import demistomock as demisto
from Cherwell import (
    cherwell_get_business_object_summary_command,
    cherwell_get_one_step_actions_command,
    get_one_step_actions_recursive,
)
from unittest.mock import patch


BO_SUMMARY_RES = {
    "firstRecIdField": "fa03d51b709e4a6eb2d52885b2ef7e04",
    "groupSummaries": [],
    "recIdFields": "fa03d51b709e4a6eb2d52885b2ef7e04",
    "stateFieldId": "5eb3234ae1344c64a19819eda437f18d",
    "states": "Pending,Closed,Reopened,New,In Progress,Resolved,Assigned",
    "busObId": "6dd53665c0c24cab86870a21cf6434ae",
    "displayName": "Incident",
    "group": False,
    "lookup": False,
    "major": False,
    "name": "Incident",
    "supporting": False,
}

ONE_STEP_ACTIONS_RES = {
    "root": {
        "childFolders": [
            {
                "name": "Config Item Tasks",
                "childItems": [
                    {
                        "description": "Launches Skype to contact the Customer.",
                        "displayName": "Call Contact",
                        "id": "9389e70ed88b993cff6c66",
                        "name": "Call Contact",
                        "association": "6dd536621cf6434ae",
                        "standInKey": "DefType:OneStepDef#Scope:Global#Id:9389e70ed88b73a6b1393434ae",
                    }
                ],
            },
            {
                "childFolders": [
                    {
                        "name": "Buttons",
                        "childItems": [
                            {
                                "description": "Abandons the incident and opens the default dashboard",
                                "displayName": "Cancel Incident",
                                "id": "944414556c072e6e430",
                                "name": "Cancel Incident",
                                "association": "6dd53665ccf6434ae",
                                "standInKey": "DefType:OneStepDef#Scope:Global#Id:944434ae",
                            }
                        ],
                    }
                ]
            },
        ]
    }
}

ONE_STEP_ACTIONS_OUTPUTS = {
    "BusinessObjectId": "6dd53665",
    "Actions": {
        "Config Item Tasks": [
            {
                "description": "Launches Skype to contact the Customer.",
                "displayName": "Call Contact",
                "id": "9389e70ed88b993cff6c66",
                "name": "Call Contact",
                "association": "6dd536621cf6434ae",
                "standInKey": "DefType:OneStepDef#Scope:Global#Id:9389e70ed88b73a6b1393434ae",
            }
        ],
        "Buttons": [
            {
                "description": "Abandons the incident and opens the default dashboard",
                "displayName": "Cancel Incident",
                "id": "944414556c072e6e430",
                "name": "Cancel Incident",
                "association": "6dd53665ccf6434ae",
                "standInKey": "DefType:OneStepDef#Scope:Global#Id:944434ae",
            }
        ],
    },
}

BU_SUMMARY_HR = (
    "### Business Object Summary:\n"
    "|Bus Ob Id|Display Name|First Rec Id Field|Group|Group Summaries|Lookup|Major|Name|"
    "Rec Id Fields|State Field Id|States|Supporting|\n"
    "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
    "| 6dd53665c0c24cab86870a21cf6434ae | Incident | fa03d51b709e4a6eb2d52885b2ef7e04 | false |  |"
    " false | false | Incident | fa03d51b709e4a6eb2d52885b2ef7e04 | 5eb3234ae1344c64a19819eda437f18d |"
    " Pending,Closed,Reopened,New,In Progress,Resolved,Assigned | false |\n"
)

ONE_TEP_ACTIONS_HR = (
    "### Config Item Tasks one-step actions:\n"
    "|Name|Display Name|Description|Id|Association|Stand In Key|\n"
    "|---|---|---|---|---|---|\n"
    "| Call Contact | Call Contact | Launches Skype to contact the Customer. | 9389e70ed88b993cff6c66"
    " | 6dd536621cf6434ae | DefType:OneStepDef#Scope:Global#Id:9389e70ed88b73a6b1393434ae |\n"
    "### Buttons one-step actions:\n"
    "|Name|Display Name|Description|Id|Association|Stand In Key|\n"
    "|---|---|---|---|---|---|\n"
    "| Cancel Incident | Cancel Incident | Abandons the incident and opens the default dashboard |"
    " 944414556c072e6e430 | 6dd53665ccf6434ae | DefType:OneStepDef#Scope:Global#Id:944434ae |\n"
)

INTEGRATION_CONTEXT = {"token_expiration_time": date_to_timestamp(datetime.now() + timedelta(days=1)), "access_token": "TOKEN"}


@patch("Cherwell.BASE_URL", "https://demisto.experiencecherwell.com/CherwellAPI/")
def test_cherwell_get_business_object_summary_command(mocker, requests_mock):
    """
    When:
        Execute cherwell-get-business-object-summary command.
    Then:
        Validate the command results is correct.
    """
    mocker.patch.object(demisto, "args", return_value={"name": "incident"})
    mocker.patch.object(demisto, "getIntegrationContext", return_value=INTEGRATION_CONTEXT)
    requests_mock.get(
        "https://demisto.experiencecherwell.com/CherwellAPI/api/V1/getbusinessobjectsummary/busobname/incident",
        json=BO_SUMMARY_RES,
    )
    command_res = cherwell_get_business_object_summary_command()

    assert command_res.readable_output == BU_SUMMARY_HR
    assert command_res.outputs == BO_SUMMARY_RES
    assert command_res.outputs_prefix == "Cherwell.BusinessObjectSummary"


@patch("Cherwell.BASE_URL", "https://demisto.experiencecherwell.com/CherwellAPI/")
def test_cherwell_get_one_step_actions_command(mocker, requests_mock):
    """
    When:
        Execute cherwell-get-one-step-actions-for-business-object.
    Then:
        Validate the command results is correct.
    """
    mocker.patch.object(demisto, "args", return_value={"busobjectid": "6dd53665"})
    mocker.patch.object(demisto, "getIntegrationContext", return_value=INTEGRATION_CONTEXT)
    requests_mock.get(
        "https://demisto.experiencecherwell.com/CherwellAPI/api/V1/getonestepactions/association/6dd53665",
        json=ONE_STEP_ACTIONS_RES,
    )
    command_res = cherwell_get_one_step_actions_command()

    assert command_res.readable_output == ONE_TEP_ACTIONS_HR
    assert command_res.outputs == ONE_STEP_ACTIONS_OUTPUTS
    assert command_res.outputs_prefix == "Cherwell.OneStepActions"


def test_get_one_step_actions_recursive_one_folder():
    """
    Given:
        A dict object with one child folder with the name folder1 and 3 items inside it.
    When:
        Execute get_one_step_actions_recursive method.
    Then:
        Check that the dict result contains one key with the name folder1 and array with the child items.
    """
    actions = {}
    root_obj = {"childFolders": [{"name": "folder1", "childItems": [1, 2, 3]}]}
    get_one_step_actions_recursive(root_obj, actions)
    assert actions == {"folder1": [1, 2, 3]}


def test_get_one_step_actions_recursive_3_folders():
    """
    Given:
        A dict object with 2 child folders: folder1 and folder 2, both of them contains 3 items,
        folder1 have a child folder with the name folder1_child that contains 3 items.
    When:
        Execute get_one_step_actions_recursive method.
    Then:
        Check that the dict result contains 3 keys folder1, folder1_child and folder2
        Check that the items inside the folders are correct.
    """
    actions = {}
    root_obj = {
        "childFolders": [
            {"name": "folder1", "childItems": [1, 2, 3], "childFolders": [{"name": "folder1_child", "childItems": [4, 5, 6]}]},
            {"name": "folder2", "childItems": [10, 20, 30]},
        ]
    }

    get_one_step_actions_recursive(root_obj, actions)
    assert actions == {"folder1": [1, 2, 3], "folder1_child": [4, 5, 6], "folder2": [10, 20, 30]}
