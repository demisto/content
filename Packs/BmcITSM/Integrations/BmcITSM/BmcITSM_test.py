import json
import os
import pytest
from unittest.mock import patch
"""MOCK PARAMETERS """
CREDENTIALS = "credentials"
ACCOUNT_ID = "account_id"
ZONE_ID = "zone_id"
"""CONSTANTS"""
BASE_URL = "https://example.com:443"
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
    with open(os.path.join("test_data", file_name), mode="r", encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


def mock_access_token(client, username: str, password: str):
    return TOKEN


@pytest.fixture(autouse=True)
@patch("BmcITSM.Client.retrieve_access_token", mock_access_token)
def mock_client():
    """
    Mock client
    """
    from BmcITSM import Client

    return Client(BASE_URL, USERNAME, PASSWORD, verify=False, proxy=False)


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
            {
                "page": "2",
                "page_size": "1"
            },
            1,
            "Qmasters",
        ),
        (
            "list_users_filter.json",
            {
                "limit": "2",
                "first_name": "Allen"
            },
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
            {
                "page": "2",
                "page_size": "1"
            },
            1,
            "Best IT, Inc.",
        ),
        (
            "list_company_filter.json",
            {
                "limit": "2",
                "company": "BMC Software, Inc."
            },
            1,
            "BMC Software, Inc.",
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
            {
                "limit": "2",
                "ticket_type": "service request"
            },
            "SRM:Request",
            2,
            "000000000000402",
        ),
        (
            "list_tickets.json",
            {
                "page": "2",
                "page_size": "1",
                "ticket_type": "service request"
            },
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
            {
                "page": "2",
                "page_size": "1"
            },
            1,
            "To request new  Corporate Wireless Plan or mobile Device",
        ),
        (
            "list_srd_filter.json",
            {
                "limit": "2",
                "description": "mobile device"
            },
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
            {
                "page": "2",
                "page_size": "1"
            },
            1,
            "ID005056B51438UcCcSgrxGYGQ5QwI",
        ),
        (
            "list_change_template_filter.json",
            {
                "limit": "2",
                "description": "Provision"
            },
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
            {
                "page": "2",
                "page_size": "1"
            },
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
            {
                "page": "2",
                "page_size": "1"
            },
            1,
            "TM001143D417CBD_bDQwojSFAA9qQA",
        ),
        (
            "list_task_template_filter.json",
            {
                "limit": "2",
                "description": "mobile device"
            },
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
    [(
        "service_request_create.json",
        {
            "srd_instance_id": "SRGAA5V0GENAWAO6ZQWYO6EBWDOUAU",
        },
        3,
        "000000000000118",
    )],
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
    [(
        "create_change_request.json",
        {
            "template_id": "AG00123F73CF5EK3sTSQTb3rAAbfQA",
            "first_name": "Allen",
            "last_name": "Allbrook",
            "summary": "test",
        },
        3,
        "CRQ000000000109",
    )],
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
    [(
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
    )],
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
    [(
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
    )],
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
    query = "'Request ID' = \"PKE000000000227\""
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
def test_known_error_update_command(ticket_request_id, command_arguments, expected_msg,
                                    requests_mock, mock_client):
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
def test_problem_investigation_update_command(ticket_request_id, command_arguments, expected_msg,
                                              requests_mock, mock_client):
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
def test_task_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock,
                             mock_client):
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
def test_incident_update_command(ticket_request_id, command_arguments, expected_msg, requests_mock,
                                 mock_client):
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
def test_change_request_update_command(ticket_request_id, command_arguments, expected_msg,
                                       requests_mock, mock_client):
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
def test_service_request_update_command(ticket_request_id, command_arguments, expected_msg,
                                        requests_mock, mock_client):
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
            {
                "ticket_type": "incident",
                "ticket_ids": "INC000000000532"
            },
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
        format_command_output,
        arrange_ticket_context_data,
    )

    mapper = SERVICE_REQUEST_CONTEXT_MAPPER
    arranger = arrange_ticket_context_data
    mock_records = load_mock_response("service_request_records.json")
    formatted_outputs = format_command_output(mock_records, mapper, arranger)
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
    assert query == "'Submit Date' <= \"1657032797\" AND 'Submit Date' >\"1657032797\" AND 'Urgency' = \"4-Low\""
