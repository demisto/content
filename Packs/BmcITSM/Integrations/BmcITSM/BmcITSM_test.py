import json
import os
from datetime import datetime, timedelta, UTC
from unittest.mock import MagicMock, patch

import pytest
from CommonServerPython import *

"""MOCK PARAMETERS """
CREDENTIALS = "credentials"
ACCOUNT_ID = "account_id"
ZONE_ID = "zone_id"
"""CONSTANTS"""
BASE_URL = "https://example.com:443"
RSSO_URL = "https://rsso-server.example.com:8443/rsso"
USERNAME = "MOCK_USER"
PASSWORD = "XXX"
TOKEN = "XXX-XXXX"
""" MOCK CLIENT"""


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(os.path.join("test_data", file_name), encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


def mock_jwt_token(self):
    return TOKEN


@pytest.fixture(autouse=True)
@patch("BmcITSM.AuthClient.retrieve_jwt_token", mock_jwt_token)
def mock_client():
    """
    Mock client
    """
    from BmcITSM import AuthClient, Client

    auth_client = AuthClient(server_url=BASE_URL, verify=False, proxy=False, username=USERNAME, password=PASSWORD)
    auth_header = auth_client.get_authorization_header()
    return Client(server_url=BASE_URL, auth_header=auth_header, verify=False, proxy=False)


""" TESTING INTEGRATION COMMANDS"""


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_name",
    [
        (
            "list_users.json",
            {
                "limit": "2",
            },
            2,
            "App",
        ),
        (
            "list_users.json",
            {"page": "2", "page_size": "1"},
            1,
            "Qmasters",
        ),
        (
            "list_users_filter.json",
            {"limit": "2", "first_name": "Allen"},
            1,
            "Allen",
        ),
    ],
)
def test_user_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_name,
    requests_mock,
    mock_client,
):
    """
    Scenario: List Users.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-user-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import user_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/CTM:People"
    requests_mock.get(url=url, json=mock_response)

    result = user_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.User"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["FirstName"] == expected_name


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_name",
    [
        (
            "list_company.json",
            {
                "limit": "2",
            },
            2,
            "Alienware",
        ),
        (
            "list_company.json",
            {"page": "2", "page_size": "1"},
            1,
            "Best IT, Inc.",
        ),
        (
            "list_company_filter.json",
            {"limit": "2", "company": "TestSoft, Inc."},
            1,
            "TestSoft, Inc.",
        ),
    ],
)
def test_company_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_name,
    requests_mock,
    mock_client,
):
    """
    Scenario: List Companies.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-company-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import company_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/COM:Company"
    requests_mock.get(url=url, json=mock_response)

    result = company_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.Company"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["Name"] == expected_name


@pytest.mark.parametrize(
    "response_file_name,command_arguments,ticket_form,expected_outputs_len,expected_name",
    [
        (
            "list_tickets.json",
            {"limit": "2", "ticket_type": "service request"},
            "SRM:Request",
            2,
            "000000000000402",
        ),
        (
            "list_tickets.json",
            {"page": "2", "page_size": "1", "ticket_type": "service request"},
            "SRM:Request",
            1,
            "000000000000403",
        ),
        (
            "list_tickets_filter.json",
            {
                "limit": "2",
                "ticket_ids": "000000000000404",
                "ticket_type": "service request",
            },
            "SRM:Request",
            1,
            "000000000000404",
        ),
    ],
)
def test_ticket_list_command(
    response_file_name,
    command_arguments,
    ticket_form,
    expected_outputs_len,
    expected_name,
    requests_mock,
    mock_client,
):
    """
    Scenario: List tickets.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-ticket-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import ticket_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/{ticket_form}"
    requests_mock.get(url=url, json=mock_response)

    result = ticket_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.Ticket"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["RequestID"] == expected_name


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_desc",
    [
        (
            "list_srd.json",
            {
                "limit": "2",
            },
            2,
            "Use this for all issues related to Skype for Business",
        ),
        (
            "list_srd.json",
            {"page": "2", "page_size": "1"},
            1,
            "To request new  Corporate Wireless Plan or mobile Device",
        ),
        (
            "list_srd_filter.json",
            {"limit": "2", "description": "mobile device"},
            1,
            "Submit the Access and Waiver form to request for your mobile device.",
        ),
    ],
)
def test_service_request_definition_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_desc,
    requests_mock,
    mock_client,
):
    """
    Scenario: List service request definition.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-service-request-definiton-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import service_request_definition_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/SRD:ServiceRequestDefinition"
    requests_mock.get(url=url, json=mock_response)

    result = service_request_definition_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.ServiceRequestDefinition"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["Description"] == expected_desc


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_desc",
    [
        (
            "list_change_template.json",
            {
                "limit": "2",
            },
            2,
            "AG00123F73CF5EK3sTSQq73rAAefQA",
        ),
        (
            "list_change_template.json",
            {"page": "2", "page_size": "1"},
            1,
            "ID005056B51438UcCcSgrxGYGQ5QwI",
        ),
        (
            "list_change_template_filter.json",
            {"limit": "2", "description": "Provision"},
            1,
            "AG00123F73CF5EK3sTSQnL3rAAd_QA",
        ),
    ],
)
def test_change_request_template_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_desc,
    requests_mock,
    mock_client,
):
    """
    Scenario: List change request template.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-change-request-template-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import change_request_template_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/CHG:Template"
    requests_mock.get(url=url, json=mock_response)

    result = change_request_template_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.ChangeRequestTemplate"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["InstanceID"] == expected_desc


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_desc",
    [
        (
            "list_incident_template.json",
            {
                "limit": "2",
            },
            2,
            "AG00123F73CF5EKnsTSQSrvrAAYvQA",
        ),
        (
            "list_incident_template.json",
            {"page": "2", "page_size": "1"},
            1,
            "AG00123F73CF5EKnsTSQ5rvrAAZfQA",
        ),
    ],
)
def test_incident_template_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_desc,
    requests_mock,
    mock_client,
):
    """
    Scenario: List incident template.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-incident-template-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import incident_template_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/HPD:Template"
    requests_mock.get(url=url, json=mock_response)

    result = incident_template_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.IncidentTemplate"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["InstanceID"] == expected_desc


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_desc",
    [
        (
            "list_task_template.json",
            {
                "limit": "2",
            },
            2,
            "TM00123F73CF5EK3sTSQ877rAAhfQA",
        ),
        (
            "list_task_template.json",
            {"page": "2", "page_size": "1"},
            1,
            "TM001143D417CBD_bDQwojSFAA9qQA",
        ),
        (
            "list_task_template_filter.json",
            {"limit": "2", "description": "mobile device"},
            1,
            "TM001143D417CBESuBQwqsp9BAMtkA",
        ),
    ],
)
def test_task_template_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_desc,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create service request.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-service-request-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import task_template_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/TMS:TaskTemplate"
    requests_mock.get(url=url, json=mock_response)

    result = task_template_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.TaskTemplate"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["InstanceID"] == expected_desc


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_id",
    [
        (
            "service_request_create.json",
            {
                "srd_instance_id": "SRGAA5V0GENAWAO6ZQWYO6EBWDOUAU",
            },
            3,
            "000000000000118",
        )
    ],
)
def test_service_request_create_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_id,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create service request
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-service-request-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import service_request_create_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/SRM:RequestInterface_Create?fields=values(SysRequestID,Request Number,Submit Date)"
    requests_mock.post(url=url, json=mock_response)

    result = service_request_create_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.ServiceRequest"
    assert len(outputs) == expected_outputs_len
    assert outputs["RequestID"] == expected_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_id",
    [
        (
            "create_change_request.json",
            {
                "template_id": "AG00123F73CF5EK3sTSQTb3rAAbfQA",
                "first_name": "Allen",
                "last_name": "Allbrook",
                "summary": "test",
            },
            3,
            "CRQ000000000109",
        )
    ],
)
def test_change_request_create_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_id,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create change request
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-change-request-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import change_request_create_command

    mock_response = load_mock_response(response_file_name)
    fields = "values(Change_Entry_ID,Infrastructure Change Id,Create Date)"
    url = f"{BASE_URL}/api/arsys/v1/entry/CHG:ChangeInterface_Create?fields={fields}"
    requests_mock.post(url=url, json=mock_response)

    result = change_request_create_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.ChangeRequest"
    assert len(outputs) == expected_outputs_len
    assert outputs["RequestID"] == expected_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_id",
    [
        (
            "incident_create.json",
            {
                "template_instance_id": "AG00123F73CF5EKnsTSQ5rvrAAZfQA",
                "first_name": "Allen",
                "last_name": "Allbrook",
                "summary": "test",
                "impact": "1-Extensive/Widespread",
                "status": "Assigned",
                "urgency": "1-Critical",
                "details": "details",
            },
            3,
            "INC000000000527",
        )
    ],
)
def test_incident_create_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_id,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create incident.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-incident-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import incident_create_command

    mock_response = load_mock_response(response_file_name)
    fields = "values(Incident_Entry_ID,Incident Number,Create Date)"
    url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface_Create?fields={fields}"
    requests_mock.post(url=url, json=mock_response)

    url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface"
    requests_mock.get(url=url, json=load_mock_response("get_incident.json"))

    result = incident_create_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.Incident"
    assert len(outputs) == expected_outputs_len
    assert outputs["RequestID"] == expected_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_id",
    [
        (
            "create_task.json",
            {
                "location_company": "Calbro Services",
                "priority": "Critical",
                "root_request_id": "PKE000000000227",
                "root_ticket_type": "known error",
                "summary": "test",
                "status": "Assigned",
                "details": "details",
            },
            3,
            "TAS000000000409",
        )
    ],
)
def test_task_create_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_id,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create Task.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-task-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import task_create_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/TMS:Task?fields=values(Task ID,Create Date)"
    requests_mock.post(url=url, json=mock_response)
    query = "('Request ID' = \"PKE000000000227\")"
    url = f"{BASE_URL}/api/arsys/v1/entry/PBM:KnownErrorInterface?q={query}"
    requests_mock.get(url=url, json=load_mock_response("get_known_error.json"))

    result = task_create_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.Task"
    assert len(outputs) == expected_outputs_len
    assert outputs["RequestID"] == expected_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_id",
    [
        (
            "create_prob.json",
            {
                "template_instance_id": "AG00123F73CF5EKnsTSQ5rvrAAZfQA",
                "first_name": "Allen",
                "last_name": "Allbrook",
                "summary": "test",
                "impact": "1-Extensive/Widespread",
                "status": "Assigned",
                "urgency": "1-Critical",
                "details": "details",
                "target_resolution_date": "in 3 days",
            },
            3,
            "PBI000000000402",
        ),
    ],
)
def test_problem_investigation_create_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_id,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create problem investigation.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-problem-investigation-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import problem_investigation_create_command

    mock_response = load_mock_response(response_file_name)
    fields = "values(Request ID,Problem Investigation ID,Create Date)"
    url = f"{BASE_URL}/api/arsys/v1/entry/PBM:ProblemInterface_Create?fields={fields}"
    requests_mock.post(url=url, json=mock_response)

    url = f"{BASE_URL}/api/arsys/v1/entry/PBM:ProblemInterface"
    requests_mock.get(url=url, json=load_mock_response("get_prob.json"))

    result = problem_investigation_create_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.ProblemInvestigation"
    assert len(outputs) == expected_outputs_len
    assert outputs["RequestID"] == expected_id


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_id",
    [
        (
            "create_known_error.json",
            {
                "template_instance_id": "AG00123F73CF5EKnsTSQ5rvrAAZfQA",
                "first_name": "Allen",
                "last_name": "Allbrook",
                "summary": "test",
                "impact": "1-Extensive/Widespread",
                "status": "Assigned",
                "urgency": "1-Critical",
                "details": "details",
                "target_resolution_date": "in 3 days",
            },
            3,
            "PKE000000000230",
        ),
    ],
)
def test_known_error_create_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_id,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create Known error.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-known-error-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import known_error_create_command

    mock_response = load_mock_response(response_file_name)
    fields = "values(Request ID,Known Error ID,Create Date)"
    url = f"{BASE_URL}/api/arsys/v1/entry/PBM:ProblemInterface_Create?fields={fields}"
    requests_mock.post(url=url, json=mock_response)

    url = f"{BASE_URL}/api/arsys/v1/entry/PBM:KnownErrorInterface"
    requests_mock.get(url=url, json=load_mock_response("get_known_error.json"))

    result = known_error_create_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.KnownError"
    assert len(outputs) == expected_outputs_len
    assert outputs["RequestID"] == expected_id


@pytest.mark.parametrize(
    "ticket_request_id,command_arguments,expected_msg",
    [
        (
            "PKE000000000220",
            {
                "ticket_request_id": "PKE000000000220",
                "summary": "Updated summary",
                "impact": "1-Extensive/Widespread",
                "urgency": "1-Critical",
                "details": "UPDATED KNOWN ERROR DETAILS",
                "target_resolution_date": "in 3 days",
            },
            "Known Error: PKE000000000220 was successfully updated.",
        ),
    ],
)
def test_known_error_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock, mock_client):
    """
    Scenario: Update Known error.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-known-error-update command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from BmcITSM import known_error_update_command

    url = f"{BASE_URL}/api/arsys/v1/entry/PBM:KnownErrorInterface/{ticket_request_id}|{ticket_request_id}"
    requests_mock.put(url=url, text="")

    result = known_error_update_command(mock_client, command_arguments)
    readable_output = result.readable_output

    assert readable_output == expected_msg


@pytest.mark.parametrize(
    "ticket_request_id,command_arguments,expected_msg",
    [
        (
            "PBI000000000402",
            {
                "ticket_request_id": "PBI000000000402",
                "summary": "Updated summary",
                "impact": "1-Extensive/Widespread",
                "urgency": "1-Critical",
                "details": "UPDATED DETAILS",
            },
            "Problem Investigation: PBI000000000402 was successfully updated.",
        ),
    ],
)
def test_problem_investigation_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock, mock_client):
    """
    Scenario: Update problem investigation.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-problem-investigation-update command called.
    Then:
     - Ensure the human readable message is correct.

    """
    from BmcITSM import problem_investigation_update_command

    url = f"{BASE_URL}/api/arsys/v1/entry/PBM:ProblemInterface/{ticket_request_id}|{ticket_request_id}"
    requests_mock.put(url=url, text="")

    result = problem_investigation_update_command(mock_client, command_arguments)
    readable_output = result.readable_output

    assert readable_output == expected_msg


@pytest.mark.parametrize(
    "ticket_request_id,command_arguments,expected_msg",
    [
        (
            "TAS000000000409",
            {
                "ticket_request_id": "TAS000000000409",
                "summary": "Updated summary",
                "details": "UPDATED DETAILS",
            },
            "Task: TAS000000000409 was successfully updated.",
        ),
    ],
)
def test_task_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock, mock_client):
    """
    Scenario: Update task.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-task-update command called.
    Then:
     - Ensure the human readable message is correct.

    """
    from BmcITSM import task_update_command

    url = f"{BASE_URL}/api/arsys/v1/entry/TMS:TaskInterface/{ticket_request_id}|{ticket_request_id}"
    requests_mock.put(url=url, text="")

    result = task_update_command(mock_client, command_arguments)
    readable_output = result.readable_output

    assert readable_output == expected_msg


@pytest.mark.parametrize(
    "ticket_request_id,command_arguments,expected_msg",
    [
        (
            "INC000000000532",
            {
                "ticket_request_id": "INC000000000532",
                "summary": "Updated summary",
                "details": "UPDATED DETAILS",
            },
            "Incident: INC000000000532 was successfully updated.",
        ),
    ],
)
def test_incident_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock, mock_client):
    """
    Scenario: Update incident.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-incident-update command called.
    Then:
     - Ensure the human readable message is correct.

    """
    from BmcITSM import incident_update_command

    url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface/{ticket_request_id}|{ticket_request_id}"
    requests_mock.put(url=url, text="")

    result = incident_update_command(mock_client, command_arguments)
    readable_output = result.readable_output

    assert readable_output == expected_msg


@pytest.mark.parametrize(
    "ticket_request_id,command_arguments,expected_msg",
    [
        (
            "CRQ000000000532",
            {
                "ticket_request_id": "CRQ000000000532",
                "summary": "Updated summary",
                "details": "UPDATED DETAILS",
            },
            "Change Request: CRQ000000000532 was successfully updated.",
        ),
    ],
)
def test_change_request_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock, mock_client):
    """
    Scenario: Update change request.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-change-request-update command called.
    Then:
     - Ensure the human readable message is correct.

    """
    from BmcITSM import change_request_update_command

    url = f"{BASE_URL}/api/arsys/v1/entry/CHG:ChangeInterface/{ticket_request_id}|{ticket_request_id}"
    requests_mock.put(url=url, text="")

    result = change_request_update_command(mock_client, command_arguments)
    readable_output = result.readable_output

    assert readable_output == expected_msg


@pytest.mark.parametrize(
    "ticket_request_id,command_arguments,expected_msg",
    [
        (
            "000000000000259",
            {
                "ticket_request_id": "000000000000259",
                "summary": "Updated summary",
                "details": "UPDATED DETAILS",
            },
            "Service Request: 000000000000259 was successfully updated.",
        ),
    ],
)
def test_service_request_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock, mock_client):
    """
    Scenario: Update service request.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-service-request-update command called.
    Then:
     - Ensure the human readable message is correct.

    """
    from BmcITSM import service_request_update_command

    url = f"{BASE_URL}/api/arsys/v1/entry/SRM:RequestInterface/{ticket_request_id}|{ticket_request_id}"
    requests_mock.put(url=url, text="")

    result = service_request_update_command(mock_client, command_arguments)
    readable_output = result.readable_output

    assert readable_output == expected_msg


@pytest.mark.parametrize(
    "ticket_request_id,ticket_form,command_arguments,expected_msg",
    [
        (
            "INC000000000532",
            "HPD:Help Desk",
            {"ticket_type": "incident", "ticket_ids": "INC000000000532"},
            "incident INC000000000532 was deleted successfully.",
        ),
    ],
)
def test_ticket_delete_command(
    ticket_request_id,
    ticket_form,
    command_arguments,
    expected_msg,
    requests_mock,
    mock_client,
):
    """
    Scenario: Delete ticket.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-ticket-delete command called.
    Then:
     - Ensure the human readable message is correct.

    """
    from BmcITSM import ticket_delete_command

    url = f"{BASE_URL}/api/arsys/v1/entry/{ticket_form}/{ticket_request_id}"
    requests_mock.delete(url=url, text="")

    result = ticket_delete_command(mock_client, command_arguments)
    readable_output = result[0].readable_output

    assert expected_msg == readable_output


""" TESTING HELPER FUNCTIONS"""


def test_format_command_output():
    """
    Scenario: Format record retrieved from BmcITSM API.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-ticket-list command called.
    Then:
     - Ensure the human readable message is correct.

    """
    from BmcITSM import (
        SERVICE_REQUEST_CONTEXT_MAPPER,
        arrange_ticket_context_data,
        format_command_output,
    )

    mapper = SERVICE_REQUEST_CONTEXT_MAPPER
    arranger = arrange_ticket_context_data
    mock_records = load_mock_response("service_request_records.json")
    formatted_outputs = format_command_output(mock_records, mapper, "service_request", arranger)
    first_record = formatted_outputs[0]
    assert first_record["RequestID"] == "000000000000402"
    assert first_record["DisplayID"] == "REQ000000000401"

    assert first_record["CreateDate"] == "2022-06-29T14:38:36"
    assert first_record["Type"] == "service request"


def test_gen_fetch_incidents_query():
    """
    Scenario: Format record retrieved from BmcITSM API.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-ticket-list command called.
    Then:
     - Ensure the generated fetch query is as expected.

    """
    from BmcITSM import gen_fetch_incidents_query

    ticket_type = "change request"
    t_epoch_from = 1657032797
    t_epoch_to = 1657032797
    stauts_filter = []
    impact_filter = []
    urgency_filter = ["4-Low"]
    custom_query = None
    query = gen_fetch_incidents_query(
        ticket_type,
        t_epoch_from,
        t_epoch_to,
        stauts_filter,
        impact_filter,
        urgency_filter,
        custom_query,
    )
    assert query == "('Submit Date' <= \"1657032797\" AND 'Submit Date' >\"1657032797\") AND ('Urgency' = \"4-Low\")"


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_desc",
    [
        (
            "list_support_group.json",
            {
                "limit": "2",
            },
            2,
            "APX990000000029",
        ),
        (
            "list_support_group.json",
            {"page": "2", "page_size": "1"},
            1,
            "SGP000000000110",
        ),
        (
            "list_support_group_filter.json",
            {"limit": "2", "company": "Apex"},
            1,
            "APX990000000029",
        ),
    ],
)
def test_list_support_group_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_desc,
    requests_mock,
    mock_client,
):
    """
    Scenario: List support groups.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may provided filtering arguments.
     - User may provided query arguments.
    When:
     - bmc-itsm-support-group-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import support_group_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/CTM:Support Group"
    requests_mock.get(url=url, json=mock_response)

    result = support_group_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.SupportGroup"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["SupportGroupID"] == expected_desc


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_desc",
    [
        (
            "list_work_order_template.json",
            {
                "limit": "2",
            },
            2,
            "IDGCWH5RDMNSBARVRM5ERVRM5EKP11",
        ),
        (
            "list_work_order_template.json",
            {"page": "2", "page_size": "1"},
            1,
            "IDGCWH5RDMNSBARVRNNGRVRNNGKY0X",
        ),
        (
            "list_work_order_template_filter.json",
            {"limit": "2", "template_name": "UNIX User"},
            1,
            "IDGCWH5RDMNSBARWFDYBRWFDYBB8NV",
        ),
        (
            "list_work_order_template.json",
            {"limit": 2, "template_ids": "IDGCWH5RDMNSBARVRM5ERVRM5EKP11,IDGCWH5RDMNSBARVRNNGRVRNNGKY0X"},
            2,
            "IDGCWH5RDMNSBARVRM5ERVRM5EKP11",
        ),
        (
            "list_work_order_template_filter.json",
            {"limit": 2, "query": 'Summary like "%UNIX%"'},
            1,
            "IDGCWH5RDMNSBARWFDYBRWFDYBB8NV",
        ),
    ],
)
def test_list_work_order_template_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_desc,
    requests_mock,
    mock_client,
):
    """
    Scenario: List work order templates.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may provided filtering arguments.
     - User may provided query arguments.
    When:
     - bmc-itsm-work-order-template-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import work_order_template_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/WOI:Template"
    requests_mock.get(url=url, json=mock_response)

    result = work_order_template_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.WorkOrderTemplate"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["GUID"] == expected_desc


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len,expected_id",
    [
        (
            "create_work_order.json",
            {
                "customer_first_name": "Scully",
                "customer_last_name": "Agent",
                "customer_company": "Calbro Services",
                "summary": "Sample WO 20240205",
                "detailed_description": "Sample WO 20240205",
                "status": "Assigned",
                "priority": "Low",
                "location_company": "Calbro Services",
            },
            3,
            "WO0000000000701",
        ),
    ],
)
def test_work_order_create_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    expected_id,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create Work order.
    Given:
     - User has provided valid credentials.
    When:
     - bmc-itsm-work-order-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import work_order_create_command

    mock_response = load_mock_response(response_file_name)
    fields = "values(Request ID,WorkOrder_ID,Create Date)"
    url = f"{BASE_URL}/api/arsys/v1/entry/WOI:WorkOrderInterface_Create?fields={fields}"
    requests_mock.post(url=url, json=mock_response)

    request_id = "WO0000000000701"
    url = f"{BASE_URL}/api/arsys/v1/entry/WOI:WorkOrderInterface/{request_id}"
    requests_mock.get(url=url, json=load_mock_response("get_work_order.json"))

    result = work_order_create_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.WorkOrder"
    assert len(outputs) == expected_outputs_len
    assert outputs["RequestID"] == expected_id


@pytest.mark.parametrize(
    "request_id,command_arguments,expected_msg",
    [
        (
            "WO0000000000701",
            {"request_id": "WO0000000000701", "status": "In Progress", "summary": "Updated Summary"},
            "Work Order: WO0000000000701 was successfully updated.",
        ),
    ],
)
def test_work_order_update_command(request_id, command_arguments, expected_msg, requests_mock, mock_client):
    """
    Scenario: Update Work error.
    Given:
     - User has provided valid credentials.
     - User has provided updated values
    When:
     - bmc-itsm-work-order-update command called.
    Then:
     - Ensure the human readable message is correct.
    """
    from BmcITSM import work_order_update_command

    url = f"{BASE_URL}/api/arsys/v1/entry/WOI:WorkOrder/{request_id}"
    requests_mock.put(url=url, text="")

    result = work_order_update_command(mock_client, command_arguments)
    readable_output = result.readable_output

    assert readable_output == expected_msg


@pytest.mark.parametrize(
    "response_file_name,command_arguments,ticket_form,expected_outputs_len,expected_name",
    [
        (
            "list_tickets_work_order.json",
            {
                "limit": "2",
                "ticket_ids": "WO0000000000009",
                "ticket_type": "work order",
            },
            "WOI:WorkOrderInterface",
            1,
            "WO0000000000009",
        ),
    ],
)
def test_ticket_list_work_order_command(
    response_file_name,
    command_arguments,
    ticket_form,
    expected_outputs_len,
    expected_name,
    requests_mock,
    mock_client,
):
    """
    Scenario: List work order tickets.
    Given:
     - User has provided valid credentials.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-ticket-list command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import ticket_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/api/arsys/v1/entry/{ticket_form}"
    requests_mock.get(url=url, json=mock_response)

    result = ticket_list_command(mock_client, command_arguments)
    outputs = result.outputs

    assert result.outputs_prefix == "BmcITSM.Ticket"
    assert len(outputs) == expected_outputs_len
    assert outputs[0]["DisplayID"] == expected_name


def test_fetch_command(mocker):
    """
    Given:
     - List tickets.
    When:
     - fetch_incidents command called.
    Then:
     - Ensure that the *last_create_time* in *last_run_result* is the last between all incidents.
    """
    import BmcITSM

    mock_response = load_mock_response("list_tickets_not_sorted.json")
    expected_result = 1719671916
    mocker.patch.object(demisto, "getLastRun", return_value={"SRM:Request": {"last_create_time": "2021-06-29T14:38:36.000+0000"}})
    mocker.patch.object(BmcITSM, "fetch_relevant_tickets_by_ticket_type", return_value=mock_response)
    _, last_run_result = BmcITSM.fetch_incidents(
        mock_client,
        max_fetch=2,
        first_fetch="2022-06-29T14:38:36.000+0000",
        last_run={"SRM:Request": {"last_create_time": "2021-06-29T14:38:36.000+0000"}},
        ticket_type_filter=["SRM:Request"],
        status_filter=[],
        impact_filter=[],
        urgency_filter=[],
        custom_query=("('Submit Date' <= \"1657032797\" AND 'Submit Date'" '>"1657032797") AND (\'Urgency\' = "4-Low")'),  # noqa: ISC001
        mirror_direction="both",
    )
    assert last_run_result["SRM:Request"]["last_create_time"] == expected_result


@pytest.mark.parametrize(
    "command_arguments,",
    [
        {
            "incident_number": "INC000010381028",
            "detailed_description": "Description TEST",
            "view_access": "Public",
            "worklog_type": "Chat",
        },
    ],
)
def test_worklog_add_command(
    command_arguments,
    requests_mock,
    mock_client,
):
    """
    Scenario: Create incident.
    Given:
     - User has provided valid credentials.
     - User may provided pagination args.
     - User may Provided filtering arguments.
    When:
     - bmc-itsm-incident-create command called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure number of items is correct.
     - Validate outputs' fields.
    """
    from BmcITSM import worklog_add_command

    url = f"{BASE_URL}/api/arsys/v1/entry/HPD:WorkLog/"
    requests_mock.post(url=url, status_code=201)

    result = worklog_add_command(mock_client, command_arguments)
    assert result.readable_output == "Worklog is successfully added"


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len",
    [
        (
            "list_worklogs.json",
            {
                "ticket_ids": "INC000010381027",
                "limit": 50,
            },
            1,
        ),
    ],
)
def test_worklog_list(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    requests_mock,
    mock_client,
):
    """ """
    from BmcITSM import worklog_list_command

    ticket_id = command_arguments.get("ticket_ids")

    mock_response = load_mock_response(response_file_name)
    expected_worklog_id = mock_response.get("entries")[0].get("values").get("Work Log ID")

    query = f"('Incident Number' = \"{ticket_id}\")"
    url = f"{BASE_URL}/api/arsys/v1/entry/HPD:WorkLog?q={query}"
    requests_mock.get(url=url, json=mock_response)

    result = worklog_list_command(mock_client, command_arguments)

    assert len(result.outputs) == expected_outputs_len
    assert result.outputs_prefix == "BmcITSM.WorkLog"
    assert result.outputs[0].get("WorkLogID") == expected_worklog_id


@pytest.mark.parametrize(
    "command_arguments",
    [
        {
            "association_type": "Caused",
            "first_form_name": "incident",
            "first_request_id": "INC000002405276",
            "second_form_name": "incident",
            "second_request_id": "INC000002405278",
            "request_description": "Creating relationship",
            "request_type": "Incident",
            "bidirectional": True,
        },
    ],
)
def test_ticket_create_relationship(
    command_arguments,
    requests_mock,
    mock_client,
):
    from BmcITSM import ticket_create_relationship_command

    url = f"{BASE_URL}/api/arsys/v1/entry/HPD:Associations"
    requests_mock.post(url=url, status_code=201, text="")

    first_request_id = command_arguments.get("first_request_id")
    second_request_id = command_arguments.get("second_request_id")
    expected = f"Created relationship between {first_request_id} and {second_request_id}."

    result = ticket_create_relationship_command(mock_client, command_arguments)
    assert result.readable_output == expected


@pytest.mark.parametrize(
    "command_arguments",
    [
        {
            "worklog_id": "WLG000002437503",
        },
    ],
)
def test_worklog_attachment_get(
    command_arguments,
    requests_mock,
    mock_client,
):
    from BmcITSM import worklog_attachment_get_command

    file_name = "attachment.txt"
    file_contents = "FILE_BODY"
    worklog_id = command_arguments.get("worklog_id")

    base = f"{BASE_URL}/api/arsys/v1/entry/HPD:WorkLog/{worklog_id}/attach/z2AF Work Log"
    first_url = f"{base}01"
    requests_mock.get(
        url=first_url, status_code=200, text=file_contents, headers={"Content-Disposition": f"attachment ;filename={file_name}"}
    )

    for suffix in ("02", "03"):
        requests_mock.get(url=f"{base}{suffix}", status_code=200, text="")

    result = worklog_attachment_get_command(mock_client, command_arguments)
    assert result[0].get("File") == file_name


""" TESTING OAUTH FUNCTIONS """


class TestGenerateLoginUrlCommand:
    """Tests for the generate_login_url_command function."""

    def test_generate_login_url_command_success(self):
        """
        Given:
            - A valid RSSO URL, client ID, and redirect URI.
        When:
            - generate_login_url_command is called.
        Then:
            - The returned CommandResults contains the correct authorization URL.
        """
        from BmcITSM import generate_login_url_command

        result = generate_login_url_command(
            rsso_url="https://rsso-server.example.com:8443/rsso",
            client_id="my-client-id",
            redirect_uri="https://oauth.pstmn.io/v1/callback",
        )

        assert "oauth2/authorize" in result.readable_output
        assert "client_id=my-client-id" in result.readable_output
        assert "redirect_uri=https://oauth.pstmn.io/v1/callback" in result.readable_output
        assert "response_type=code" in result.readable_output

    def test_generate_login_url_command_missing_client_id(self):
        """
        Given:
            - No client ID is provided.
        When:
            - generate_login_url_command is called.
        Then:
            - A DemistoException is raised.
        """
        from BmcITSM import generate_login_url_command

        with pytest.raises(DemistoException, match="Client ID"):
            generate_login_url_command(
                rsso_url="https://rsso-server.example.com:8443/rsso",
                client_id="",
                redirect_uri="https://oauth.pstmn.io/v1/callback",
            )

    def test_generate_login_url_command_missing_redirect_uri(self):
        """
        Given:
            - No redirect URI is provided.
        When:
            - generate_login_url_command is called.
        Then:
            - A DemistoException is raised.
        """
        from BmcITSM import generate_login_url_command

        with pytest.raises(DemistoException, match="Redirect URI"):
            generate_login_url_command(
                rsso_url="https://rsso-server.example.com:8443/rsso",
                client_id="my-client-id",
                redirect_uri="",
            )

    def test_generate_login_url_command_invalid_rsso_url(self):
        """
        Given:
            - An RSSO URL that doesn't end with /rsso.
        When:
            - generate_login_url_command is called.
        Then:
            - A DemistoException is raised about invalid URL format.
        """
        from BmcITSM import generate_login_url_command

        with pytest.raises(DemistoException, match="must end with"):
            generate_login_url_command(
                rsso_url="https://rsso-server.example.com:8443/invalid",
                client_id="my-client-id",
                redirect_uri="https://oauth.pstmn.io/v1/callback",
            )


class TestIsTokenExpired:
    """Tests for the AuthClient.is_token_expired static method."""

    def test_token_not_expired(self):
        """
        Given:
            - A token expiration time 10 minutes in the future.
        When:
            - AuthClient.is_token_expired is called.
        Then:
            - Returns False (token is still valid).
        """
        from BmcITSM import AuthClient

        future_time = (datetime.now(UTC) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert AuthClient.is_token_expired(future_time) is False

    def test_token_expired(self):
        """
        Given:
            - A token expiration time 10 minutes in the past.
        When:
            - AuthClient.is_token_expired is called.
        Then:
            - Returns True (token is expired).
        """
        from BmcITSM import AuthClient

        past_time = (datetime.now(UTC) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert AuthClient.is_token_expired(past_time) is True

    def test_token_expires_within_buffer(self):
        """
        Given:
            - A token expiration time 30 seconds in the future (within 1-minute buffer).
        When:
            - AuthClient.is_token_expired is called.
        Then:
            - Returns True (token is considered expired due to buffer).
        """
        from BmcITSM import AuthClient

        near_future = (datetime.now(UTC) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert AuthClient.is_token_expired(near_future) is True

    def test_token_empty_string(self):
        """
        Given:
            - An empty string for expiration time.
        When:
            - AuthClient.is_token_expired is called.
        Then:
            - Returns True (treated as expired).
        """
        from BmcITSM import AuthClient

        assert AuthClient.is_token_expired("") is True

    def test_token_malformed_date(self):
        """
        Given:
            - A malformed date string.
        When:
            - AuthClient.is_token_expired is called.
        Then:
            - Returns True (treated as expired).
        """
        from BmcITSM import AuthClient

        assert AuthClient.is_token_expired("not-a-date") is True


class TestGetOAuthToken:
    """Tests for the Client.get_oauth_token method."""

    @staticmethod
    def _create_oauth_auth_client_instance():
        """Helper to create a bare AuthClient instance for OAuth testing."""
        from BmcITSM import AuthClient

        auth_client = AuthClient.__new__(AuthClient)
        auth_client._use_oauth = True
        auth_client._rsso_url = RSSO_URL
        auth_client._client_id = "test-client-id"
        auth_client._redirect_uri = "https://oauth.pstmn.io/v1/callback"
        auth_client._auth_code = "test-auth-code"
        auth_client._verify = False
        return auth_client

    def test_get_oauth_token_uses_cached_token(self):
        """
        Given:
            - A valid, non-expired access token in integration context.
        When:
            - get_oauth_token is called.
        Then:
            - Returns the cached access token without making API calls.
        """
        future_time = (datetime.now(UTC) + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        mock_context = {
            "oauth_access_token": "cached-access-token",
            "oauth_access_token_expires_in": future_time,
            "oauth_refresh_token": "cached-refresh-token",
            "oauth_refresh_token_expires_in": future_time,
        }

        auth_client = self._create_oauth_auth_client_instance()

        with patch("BmcITSM.get_integration_context", return_value=mock_context), patch("BmcITSM.set_integration_context"):
            token = auth_client.get_oauth_token()

        assert token == "cached-access-token"

    def test_get_oauth_token_refresh_flow(self):
        """
        Given:
            - An expired access token but a valid refresh token in integration context.
        When:
            - get_oauth_token is called.
        Then:
            - Uses the refresh token to get a new access token.
        """
        past_time = (datetime.now(UTC) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future_time = (datetime.now(UTC) + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_context = {
            "oauth_access_token": "expired-access-token",
            "oauth_access_token_expires_in": past_time,
            "oauth_refresh_token": "valid-refresh-token",
            "oauth_refresh_token_expires_in": future_time,
        }

        token_response = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
        }

        auth_client = self._create_oauth_auth_client_instance()
        auth_client._auth_code = ""

        mock_set_ctx = MagicMock()
        with (
            patch("BmcITSM.get_integration_context", return_value=mock_context),
            patch("BmcITSM.set_integration_context", mock_set_ctx),
            patch.object(auth_client, "_http_request", return_value=token_response),
        ):
            token = auth_client.get_oauth_token()

        assert token == "new-access-token"
        # Verify the context was updated
        stored_ctx = mock_set_ctx.call_args[0][0]
        assert stored_ctx["oauth_access_token"] == "new-access-token"
        assert stored_ctx["oauth_refresh_token"] == "new-refresh-token"

    def test_get_oauth_token_auth_code_exchange(self):
        """
        Given:
            - No valid tokens in integration context, but an authorization code is provided.
        When:
            - get_oauth_token is called.
        Then:
            - Exchanges the authorization code for tokens.
        """
        token_response = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
        }

        auth_client = self._create_oauth_auth_client_instance()

        mock_http = MagicMock(return_value=token_response)
        with (
            patch("BmcITSM.get_integration_context", return_value={}),
            patch("BmcITSM.set_integration_context"),
            patch.object(auth_client, "_http_request", mock_http),
        ):
            token = auth_client.get_oauth_token()

        assert token == "new-access-token"

        # Verify the _http_request was called with correct data
        call_kwargs = mock_http.call_args
        post_data = call_kwargs[1].get("data")
        assert post_data["grant_type"] == "authorization_code"
        assert post_data["code"] == "test-auth-code"
        assert post_data["client_id"] == "test-client-id"

    def test_get_oauth_token_no_tokens_no_code(self):
        """
        Given:
            - No valid tokens in integration context and no authorization code.
        When:
            - get_oauth_token is called.
        Then:
            - Raises DemistoException with instructions to run generate-login-url.
        """
        auth_client = self._create_oauth_auth_client_instance()
        auth_client._auth_code = ""

        with (
            patch("BmcITSM.get_integration_context", return_value={}),
            patch("BmcITSM.set_integration_context"),
            pytest.raises(DemistoException, match="bmc-itsm-generate-login-url"),
        ):
            auth_client.get_oauth_token()

    def test_get_oauth_token_auth_code_exchange_failure(self):
        """
        Given:
            - No valid tokens and an authorization code that fails to exchange.
        When:
            - get_oauth_token is called.
        Then:
            - Raises DemistoException with the error details.
        """
        auth_client = self._create_oauth_auth_client_instance()
        auth_client._auth_code = "expired-auth-code"

        with (
            patch("BmcITSM.get_integration_context", return_value={}),
            patch("BmcITSM.set_integration_context"),
            patch.object(auth_client, "_http_request", side_effect=DemistoException("invalid_grant")),
            pytest.raises(DemistoException, match="Failed to exchange authorization code"),
        ):
            auth_client.get_oauth_token()


class TestClientOAuthInit:
    """Tests for Client initialization with OAuth."""

    def test_auth_client_oauth_sets_bearer_header(self):
        """
        Given:
            - OAuth is enabled with valid tokens in integration context.
        When:
            - AuthClient.get_authorization_header() is called.
        Then:
            - The returned header uses Bearer token format.
        """
        from BmcITSM import AuthClient

        future_time = (datetime.now(UTC) + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        mock_context = {
            "oauth_access_token": "my-oauth-token",
            "oauth_access_token_expires_in": future_time,
            "oauth_refresh_token": "my-refresh-token",
            "oauth_refresh_token_expires_in": future_time,
        }

        with patch("BmcITSM.get_integration_context", return_value=mock_context), patch("BmcITSM.set_integration_context"):
            auth_client = AuthClient(
                server_url=BASE_URL,
                verify=False,
                proxy=False,
                use_oauth=True,
                client_id="test-client-id",
                redirect_uri="https://oauth.pstmn.io/v1/callback",
                auth_code="test-auth-code",
                rsso_url=RSSO_URL,
            )
            auth_header = auth_client.get_authorization_header()

        assert auth_header["Authorization"] == "Bearer my-oauth-token"

    @patch("BmcITSM.AuthClient.retrieve_jwt_token", mock_jwt_token)
    def test_auth_client_jwt_sets_arjwt_header(self):
        """
        Given:
            - OAuth is not enabled (default behavior).
        When:
            - AuthClient.get_authorization_header() is called.
        Then:
            - The returned header uses AR-JWT token format.
        """
        from BmcITSM import AuthClient

        auth_client = AuthClient(
            server_url=BASE_URL,
            verify=False,
            proxy=False,
            username=USERNAME,
            password=PASSWORD,
        )
        auth_header = auth_client.get_authorization_header()

        assert auth_header["Authorization"] == f"AR-JWT {TOKEN}"


class TestFullUrlFix:
    """Tests that AuthClient uses full_url (not url_suffix) to avoid the leading '/' bug.

    The custom urljoin in CommonServerPython concatenates base_url + suffix.
    When base_url="" (as in AuthClient), it becomes "/" + suffix = "/https://..."
    which causes: 'No connection adapters were found for /https://...'
    Using full_url= bypasses base_url concatenation entirely.
    """

    def test_retrieve_jwt_token_uses_full_url(self, requests_mock):
        """
        Given:
            - An AuthClient configured with a server URL (JWT mode, use_oauth=False).
        When:
            - retrieve_jwt_token is called.
        Then:
            - The HTTP request is made to the correct full URL (https://example.com:443/api/jwt/login)
              without a leading '/' prefix that would cause InvalidSchema.
        """
        from BmcITSM import AuthClient

        expected_url = f"{BASE_URL}/api/jwt/login"
        requests_mock.post(expected_url, text="mock-jwt-token-123")

        auth_client = AuthClient(
            server_url=BASE_URL,
            verify=False,
            proxy=False,
            username=USERNAME,
            password=PASSWORD,
        )

        with patch("BmcITSM.get_integration_context", return_value={}), patch("BmcITSM.set_integration_context"):
            token = auth_client.retrieve_jwt_token()

        assert token == "mock-jwt-token-123"
        assert requests_mock.called
        # Verify the actual URL does NOT start with '/' (the original bug)
        actual_url = requests_mock.last_request.url
        assert not actual_url.startswith("/"), f"URL should not start with '/': {actual_url}"
        assert actual_url == expected_url

    def test_get_oauth_token_uses_full_url_for_auth_code_exchange(self, requests_mock):
        """
        Given:
            - An AuthClient configured for OAuth with an authorization code.
        When:
            - get_oauth_token is called and exchanges the auth code.
        Then:
            - The HTTP request is made to the correct full URL (rsso_url/oauth2/token)
              without a leading '/' prefix.
        """
        from BmcITSM import AuthClient

        expected_url = f"{RSSO_URL}/oauth2/token"
        token_response = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
        }
        requests_mock.post(expected_url, json=token_response)

        auth_client = AuthClient(
            server_url=BASE_URL,
            verify=False,
            proxy=False,
            use_oauth=True,
            client_id="test-client-id",
            redirect_uri="https://oauth.pstmn.io/v1/callback",
            auth_code="test-auth-code",
            rsso_url=RSSO_URL,
        )

        with patch("BmcITSM.get_integration_context", return_value={}), patch("BmcITSM.set_integration_context"):
            token = auth_client.get_oauth_token()

        assert token == "new-access-token"
        assert requests_mock.called
        actual_url = requests_mock.last_request.url
        assert not actual_url.startswith("/"), f"URL should not start with '/': {actual_url}"
        assert actual_url == expected_url

    def test_get_oauth_token_uses_full_url_for_refresh_flow(self, requests_mock):
        """
        Given:
            - An AuthClient configured for OAuth with an expired access token but valid refresh token.
        When:
            - get_oauth_token is called and uses the refresh token.
        Then:
            - The HTTP request is made to the correct full URL (rsso_url/oauth2/token)
              without a leading '/' prefix.
        """
        from BmcITSM import AuthClient

        expected_url = f"{RSSO_URL}/oauth2/token"
        token_response = {
            "access_token": "refreshed-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
        }
        requests_mock.post(expected_url, json=token_response)

        past_time = (datetime.now(UTC) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future_time = (datetime.now(UTC) + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
        mock_context = {
            "oauth_access_token": "expired-access-token",
            "oauth_access_token_expires_in": past_time,
            "oauth_refresh_token": "valid-refresh-token",
            "oauth_refresh_token_expires_in": future_time,
        }

        auth_client = AuthClient(
            server_url=BASE_URL,
            verify=False,
            proxy=False,
            use_oauth=True,
            client_id="test-client-id",
            redirect_uri="https://oauth.pstmn.io/v1/callback",
            auth_code="",
            rsso_url=RSSO_URL,
        )

        with patch("BmcITSM.get_integration_context", return_value=mock_context), patch("BmcITSM.set_integration_context"):
            token = auth_client.get_oauth_token()

        assert token == "refreshed-access-token"
        assert requests_mock.called
        actual_url = requests_mock.last_request.url
        assert not actual_url.startswith("/"), f"URL should not start with '/': {actual_url}"
        assert actual_url == expected_url


class TestAddAttachmentCommand:
    """Tests for the bmc-itsm-add-attachment command (add_attachment_command)."""

    @pytest.mark.parametrize(
        "entry_type",
        [
            "incident",
            "change request",
            "service request",
            "task",
            "problem investigation",
            "known error",
            "work order",
        ],
    )
    def test_add_single_attachment_success(self, entry_type, requests_mock, mock_client, tmp_path, mocker):
        """
        Given:
            - A valid entry_id pointing to a file in the War Room.
            - A valid field_name for the attachment field.
            - A valid entry_type and request_id.
        When:
            - add_attachment_command is called with a single attachment.
        Then:
            - The command sends a PUT request to the correct form endpoint.
            - The readable output confirms the attachment was added.
        """
        from BmcITSM import TICKET_TYPE_TO_ATTACHMENT_FORM, add_attachment_command

        form_name = TICKET_TYPE_TO_ATTACHMENT_FORM[entry_type]
        request_id = "INC000000000123"
        # Create a temporary file to simulate a War Room file
        test_file = tmp_path / "test_report.txt"
        test_file.write_text("test file content")

        url = f"{BASE_URL}/api/arsys/v1/entry/{form_name}/{request_id}"
        requests_mock.put(url=url, status_code=204)

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(test_file), "name": "test_report.txt"})

        result = add_attachment_command(
            mock_client,
            {
                "entry_ids": "12@34",
                "field_names": "z2AF_Attachment1",
                "entry_type": entry_type,
                "request_id": request_id,
            },
        )

        assert result.readable_output == f"Attachment was successfully added to {entry_type} {request_id}."

    def test_add_multiple_attachments_success(self, requests_mock, mock_client, tmp_path, mocker):
        """
        Given:
            - Two valid entry_ids pointing to files in the War Room.
            - Two corresponding field_names for the attachment fields.
        When:
            - add_attachment_command is called with multiple attachments.
        Then:
            - The command sends a PUT request with all attachments.
            - The readable output uses plural form ("Attachments were").
        """
        from BmcITSM import add_attachment_command

        request_id = "INC000000000456"
        # Create temporary files
        file1 = tmp_path / "report.pdf"
        file1.write_bytes(b"pdf content")
        file2 = tmp_path / "screenshot.png"
        file2.write_bytes(b"png content")

        url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface/{request_id}"
        requests_mock.put(url=url, status_code=204)

        mocker.patch.object(
            demisto,
            "getFilePath",
            side_effect=[
                {"path": str(file1), "name": "report.pdf"},
                {"path": str(file2), "name": "screenshot.png"},
            ],
        )

        result = add_attachment_command(
            mock_client,
            {
                "entry_ids": "12@34,56@78",
                "field_names": "z2AF_Attachment1,z2AF_Attachment2",
                "entry_type": "incident",
                "request_id": request_id,
            },
        )

        assert result.readable_output == f"Attachments were successfully added to incident {request_id}."

    def test_add_attachment_with_entry_json(self, requests_mock, mock_client, tmp_path, mocker):
        """
        Given:
            - A valid attachment and an optional entry JSON with additional field values.
        When:
            - add_attachment_command is called with the entry argument.
        Then:
            - The command succeeds and includes the additional fields in the request.
        """
        from BmcITSM import add_attachment_command

        request_id = "INC000000000789"
        test_file = tmp_path / "evidence.txt"
        test_file.write_text("evidence content")

        url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface/{request_id}"
        requests_mock.put(url=url, status_code=204)

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(test_file), "name": "evidence.txt"})

        result = add_attachment_command(
            mock_client,
            {
                "entry_ids": "12@34",
                "field_names": "z2AF_Attachment1",
                "entry_type": "incident",
                "request_id": request_id,
                "entry": '{"Status": "In Progress", "Description": "Evidence from XSOAR"}',
            },
        )

        assert result.readable_output == f"Attachment was successfully added to incident {request_id}."
        # Verify the request body contains the entry JSON with both additional fields and attachment mapping
        request_body = requests_mock.last_request.body
        assert b"evidence.txt" in request_body
        assert b"In Progress" in request_body

    def test_add_attachment_mismatched_ids_and_fields(self, mock_client):
        """
        Given:
            - entry_ids has 2 items but field_names has 3 items.
        When:
            - add_attachment_command is called.
        Then:
            - A ValueError is raised indicating the mismatch.
        """
        from BmcITSM import add_attachment_command

        with pytest.raises(ValueError, match="Number of entry_ids .* must match number of field_names"):
            add_attachment_command(
                mock_client,
                {
                    "entry_ids": "12@34,56@78",
                    "field_names": "z2AF_Attachment1,z2AF_Attachment2,z2AF_Attachment3",
                    "entry_type": "incident",
                    "request_id": "INC000000000123",
                },
            )

    def test_add_attachment_invalid_entry_json(self, mock_client):
        """
        Given:
            - The entry argument contains invalid JSON.
        When:
            - add_attachment_command is called.
        Then:
            - A ValueError is raised indicating invalid JSON format.
        """
        from BmcITSM import add_attachment_command

        with pytest.raises(ValueError, match="Invalid JSON format provided in the 'entry' argument"):
            add_attachment_command(
                mock_client,
                {
                    "entry_ids": "12@34",
                    "field_names": "z2AF_Attachment1",
                    "entry_type": "incident",
                    "request_id": "INC000000000123",
                    "entry": "{invalid json}",
                },
            )

    def test_add_attachment_strips_attach_prefix(self, requests_mock, mock_client, tmp_path, mocker):
        """
        Given:
            - The user accidentally includes the 'attach-' prefix in field_names.
        When:
            - add_attachment_command is called.
        Then:
            - The prefix is stripped to prevent double-prefixing (attach-attach-).
            - The command succeeds.
        """
        from BmcITSM import add_attachment_command

        request_id = "INC000000000321"
        test_file = tmp_path / "log.txt"
        test_file.write_text("log content")

        url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface/{request_id}"
        requests_mock.put(url=url, status_code=204)

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(test_file), "name": "log.txt"})

        result = add_attachment_command(
            mock_client,
            {
                "entry_ids": "12@34",
                "field_names": "attach-z2AF_Attachment1",
                "entry_type": "incident",
                "request_id": request_id,
            },
        )

        assert result.readable_output == f"Attachment was successfully added to incident {request_id}."
        # Verify the multipart body uses 'attach-z2AF_Attachment1' (not 'attach-attach-z2AF_Attachment1')
        request_body = requests_mock.last_request.body
        assert b"attach-z2AF_Attachment1" in request_body
        assert b"attach-attach-" not in request_body

    def test_add_attachment_invalid_entry_id(self, mock_client, mocker):
        """
        Given:
            - An entry_id that does not exist in the War Room.
        When:
            - add_attachment_command is called.
        Then:
            - A DemistoException is raised indicating the failure.
        """
        from BmcITSM import add_attachment_command

        mocker.patch.object(demisto, "getFilePath", side_effect=Exception("Entry not found"))

        with pytest.raises(DemistoException, match="Could not find file for entry ID"):
            add_attachment_command(
                mock_client,
                {
                    "entry_ids": "invalid@id",
                    "field_names": "z2AF_Attachment1",
                    "entry_type": "incident",
                    "request_id": "INC000000000123",
                },
            )

    def test_add_attachment_api_failure(self, requests_mock, mock_client, tmp_path, mocker):
        """
        Given:
            - A valid attachment but the API returns a non-204 status code.
        When:
            - add_attachment_command is called.
        Then:
            - A DemistoException is raised with the error details.
        """
        from BmcITSM import add_attachment_command

        request_id = "INC000000000999"
        test_file = tmp_path / "data.csv"
        test_file.write_text("csv content")

        url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface/{request_id}"
        requests_mock.put(url=url, status_code=400, text="Bad Request: Invalid field name")

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(test_file), "name": "data.csv"})

        with pytest.raises(DemistoException, match="Failed to add attachment"):
            add_attachment_command(
                mock_client,
                {
                    "entry_ids": "12@34",
                    "field_names": "z2AF_Attachment1",
                    "entry_type": "incident",
                    "request_id": request_id,
                },
            )

    def test_add_attachment_files_closed_on_success(self, requests_mock, mock_client, tmp_path, mocker):
        """
        Given:
            - A valid attachment file.
        When:
            - add_attachment_command completes successfully.
        Then:
            - All opened file handles are properly closed.
        """
        from BmcITSM import add_attachment_command

        request_id = "INC000000000111"
        test_file = tmp_path / "cleanup_test.txt"
        test_file.write_text("cleanup test content")

        url = f"{BASE_URL}/api/arsys/v1/entry/HPD:IncidentInterface/{request_id}"
        requests_mock.put(url=url, status_code=204)

        mock_file = MagicMock()
        mock_file.read.return_value = b"file content"

        mocker.patch.object(demisto, "getFilePath", return_value={"path": str(test_file), "name": "cleanup_test.txt"})
        mocker.patch("builtins.open", return_value=mock_file)

        add_attachment_command(
            mock_client,
            {
                "entry_ids": "12@34",
                "field_names": "z2AF_Attachment1",
                "entry_type": "incident",
                "request_id": request_id,
            },
        )

        mock_file.close.assert_called_once()

    def test_add_attachment_files_closed_on_failure(self, mock_client, tmp_path, mocker):
        """
        Given:
            - Two entry_ids where the second one is invalid.
        When:
            - add_attachment_command fails during file processing.
        Then:
            - All previously opened file handles are properly closed.
        """
        from BmcITSM import add_attachment_command

        test_file = tmp_path / "valid_file.txt"
        test_file.write_text("valid content")

        mock_file = MagicMock()

        mocker.patch.object(
            demisto,
            "getFilePath",
            side_effect=[
                {"path": str(test_file), "name": "valid_file.txt"},
                Exception("Second file not found"),
            ],
        )
        mocker.patch("builtins.open", return_value=mock_file)

        with pytest.raises(DemistoException, match="Could not find file for entry ID"):
            add_attachment_command(
                mock_client,
                {
                    "entry_ids": "12@34,56@78",
                    "field_names": "z2AF_Attachment1,z2AF_Attachment2",
                    "entry_type": "incident",
                    "request_id": "INC000000000123",
                },
            )

        # The first file was opened and should be closed even though the second failed
        mock_file.close.assert_called_once()
