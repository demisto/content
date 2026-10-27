import json

import pytest
from CommonServerPython import CommandResults
from Workday import Client, convert_to_json, create_worker_context, list_workers_command, main

client = Client(
    tenant_url="https://test.workday.com/XSOAR",
    verify_certificate=False,
    proxy=False,
    tenant_name="tenant_name",
    token="token",
    username="username",
    password="password",
)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_read_file(path):
    with open(path) as _file:
        return _file.read()


@pytest.mark.parametrize("args", [({"page": "1", "count": "1", "managers": "2"}), ({"employee_id": "123456", "managers": "2"})])
def test_list_workers_command(mocker, args):
    """Tests list_workers_command command function.

    Configures mocker instance and patches the client's http_request to generate the appropriate
    list_workers API response, loaded from a local JSON file.
    Checks the output of the command function with the expected output.

    This Test run 2 times for each use case (with employee Id and without)
    """
    XML_RAW_RESPONSE = util_read_file("test_data/xml_raw_response.txt")
    mocker.patch.object(client, "_http_request", return_value=XML_RAW_RESPONSE)
    results: CommandResults = list_workers_command(client, args)
    assert results.outputs == WORKER_CONTEXT_DATA
    assert results.outputs_key_field == "Worker_ID"
    assert results.outputs_prefix == "Workday.Worker"


def test_create_worker_context():
    """Tests create_worker_context function.

    Checks the output of the function with the expected output.
    Checks the boolean representation for `Primary` Field under `Emails`. expected - True
    Checks the boolean representation for `Active` Field. expected - True
    Checks the context contains the specified managers number(2)

    No mock is needed here.
    """
    WORKER_DATA = util_load_json("test_data/worker_data.json")
    context = create_worker_context(WORKER_DATA, num_of_managers=2)
    assert context == WORKER_CONTEXT_DATA
    assert len(context[0].get("Managers")) == 2
    if context[0]["Emails"][0]["Primary"]:
        assert True
    if context[0]["Active"]:
        assert True


def _worker_with_status_data(worker_status_data: dict) -> dict:
    """Returns a copy of the sample worker with Worker_Status_Data replaced."""
    import copy

    worker = copy.deepcopy(util_load_json("test_data/worker_data.json"))
    worker["Worker_Data"]["Employment_Data"]["Worker_Status_Data"] = worker_status_data
    return worker


def test_create_worker_context_without_hire_reason():
    """
    Given:
    - A worker whose Worker_Status_Data has no Hire_Reason_Reference (seen on real tenants).
    When:
    - Calling create_worker_context.
    Then:
    - Ensure no exception is raised and Hire_Reason is None, while other status fields are still parsed.
    """
    worker = _worker_with_status_data({"Active": "1", "Hire_Date": "2020-03-25"})

    context = create_worker_context(worker, num_of_managers=2)

    assert context[0]["Hire_Reason"] is None
    assert context[0]["Hire_Date"] == "2020-03-25"
    assert context[0]["Active"] is True


def test_create_worker_context_reference_with_single_id():
    """
    Given:
    - A worker whose Hire_Reason_Reference has a single ID (a dict, not a list) - how xml2json renders one element.
    When:
    - Calling create_worker_context.
    Then:
    - Ensure no exception is raised and Hire_Reason is None (the expected ID type is not present).
    """
    worker = _worker_with_status_data(
        {
            "Active": "1",
            "Hire_Reason_Reference": {"ID": {"@{urn:com.workday/bsvc}type": "WID", "#text": "abc"}},
        }
    )

    context = create_worker_context(worker, num_of_managers=2)

    assert context[0]["Hire_Reason"] is None


def test_create_worker_context_terminated_without_termination_references():
    """
    Given:
    - A terminated worker with no termination reason/category references.
    When:
    - Calling create_worker_context.
    Then:
    - Ensure no exception is raised and the termination fields that exist are still returned.
    """
    worker = _worker_with_status_data({"Active": "0", "Terminated": "1", "Termination_Date": "2026-01-01"})

    context = create_worker_context(worker, num_of_managers=2)

    assert context[0]["Terminated"] is True
    assert context[0]["Termination_Date"] == "2026-01-01"
    assert context[0]["Primary_Termination_Reason"] is None
    assert context[0]["Primary_Termination_Category"] is None


def test_create_worker_context_minimal_worker():
    """
    Given:
    - A worker with only IDs and no personal, employment, contact or management data.
    When:
    - Calling create_worker_context.
    Then:
    - Ensure no exception is raised and the IDs are returned.
    """
    worker = {"Worker_Data": {"Worker_ID": "1", "User_ID": "user@example.com"}}

    context = create_worker_context(worker, num_of_managers=2)

    assert context[0]["Worker_ID"] == "1"
    assert context[0]["User_ID"] == "user@example.com"
    assert context[0]["Country"] is None


def test_convert_to_json():
    """Tests convert_to_json function.

    Checks the output of the function with the expected output.

    No mock is needed here.
    """
    XML_RAW_RESPONSE = util_read_file("test_data/xml_raw_response.txt")
    JSON_RAW_RESPONSE = util_load_json("test_data/json_raw_respose.json")
    raw_response, worker_data = convert_to_json(XML_RAW_RESPONSE)
    assert raw_response == JSON_RAW_RESPONSE
    assert worker_data == worker_data


WORKER_CONTEXT_DATA = [
    {
        "Worker_ID": "123456",
        "User_ID": "jdoe@example.com",
        "Country": "AE",
        "Legal_First_Name": "John Wick",
        "Legal_Last_Name": "Doe",
        "Preferred_First_Name": "John Wick",
        "Preferred_Last_Name": "Doe",
        "Position_ID": "POS-114061",
        "Position_Title": "Regional Sales Manager",
        "Business_Title": "Regional Sales Manager",
        "Start_Date": "2020-03-25",
        "End_Employment_Reason_Reference": "",
        "Worker_Type": "Regular",
        "Position_Time_Type": "Full_time",
        "Scheduled_Weekly_Hours": "40",
        "Default_Weekly_Hours": "40",
        "Full_Time_Equivalent_Percentage": "100",
        "Exclude_from_Headcount": "0",
        "Pay_Rate_Type": "Salary",
        "Job_Profile_Name": "Regional Sales Manager (DQC)",
        "Work_Shift_Required": "0",
        "Critical_Job": "0",
        "Business_Site_id": "3010",
        "Business_Site_Name": "Office - Saudi Arabia - Narnia",
        "Business_Site_Type": "Office",
        "Business_Site_Address": {
            "Address_ID": "ADDRESS_REFERENCE-3-3415",
            "Formatted_Address": "Eye Tower&#xa;P.O Box: 230 888, Floor 28&#xa;Offices 1, "
            "2&#xa;Narnia 11111&#xa;Narnia&#xa;Saudi Arabia",
            "Country": "SA",
            "Postal_Code": "11111",
        },
        "End_Date": None,
        "Pay_Through_Date": None,
        "Active": True,
        "Hire_Date": "2020-03-25",
        "Hire_Reason": "Hire_Employee_Hire_Employee_Rehire",
        "First_Day_of_Work": "2020-03-25",
        "Retired": "0",
        "Days_Unemployed": "0",
        "Terminated": False,
        "Rehire": "1",
        "Resignation_Date": "2018-06-14",
        "Has_International_Assignment": "0",
        "Home_Country_Reference": "SA",
        "Photo": "image_in_base64",
        "Addresses": [
            {
                "Address_ID": "ADDRESS_REFERENCE-3-3415",
                "Formatted_Address": "Eye Tower&#xa;P.O Box: 230 888, Floor 28&#xa;Offices 1, 2&#xa;Narnia "
                "11111&#xa;Narnia&#xa;Saudi Arabia",
                "Country": "SA",
                "Region": "01",
                "Region_Descriptor": "Narnia",
                "Postal_Code": "11111",
                "Type": "WORK",
            },
            {
                "Address_ID": "ADDRESS_REFERENCE-6-107",
                "Formatted_Address": "King Testname District&#xa;Narnia 13215&#xa;Saudi Arabia",
                "Country": "SA",
                "Region": "",
                "Region_Descriptor": "",
                "Postal_Code": "13215",
                "Type": "HOME",
            },
        ],
        "Emails": [
            {"Email_Address": "John@hotmail.com", "Type": "HOME", "Primary": True, "Public": False},
            {"Email_Address": "jdoe@example.com", "Type": "WORK", "Primary": True, "Public": True},
        ],
        "Phones": [
            {"ID": "PHONE_REFERENCE-3-4210", "Phone_Number": "+966555055555", "Type": "Mobile", "Usage": "WORK"},
            {"ID": "PHONE_REFERENCE-3-14614", "Phone_Number": "+966555055555", "Type": "Mobile", "Usage": "HOME"},
        ],
        "Managers": [
            {"Manager_ID": "100700", "Manager_Name": "Manager 700"},
            {"Manager_ID": "100600", "Manager_Name": "Manager 600"},
        ],
    }
]


def test_api_request_returns_expected_data(mocker):
    """
    Given:
    - Valid input parameters.
    - A successful API request that returns expected data.
    When:
    - Calling the main function.
    Then:
    - Ensure the function properly handles the API request and returns the expected data.
    """
    import demistomock as demisto
    import Workday

    params = {
        "credentials": {"identifier": "user", "password": "pass"},
        "base_url": "https://test.com",
        "cred_tenant_name": {"password": "tenant"},
        "insecure": False,
        "proxy": False,
        "cred_token": {"password": "token"},
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="workday-list-workers")
    mocker.patch.object(demisto, "args", return_value={"page": "1", "count": "1"})
    mocker.patch.object(Client, "list_workers", return_value=({}, [{"Worker_Data": {"Worker_ID": "123"}}]))
    XML_RAW_RESPONSE = util_read_file("test_data/xml_raw_response.txt")
    mocker.patch.object(client, "_http_request", return_value=XML_RAW_RESPONSE)
    mocker.patch.object(Workday, "create_worker_context", return_value=None)
    main()


def _sent_request_body(mocker, list_workers_kwargs: dict) -> str:
    """Runs Client.list_workers with a mocked _http_request and returns the SOAP body that was sent."""
    soap_client = Client(
        tenant_url="https://test.workday.com/XSOAR",
        verify_certificate=False,
        proxy=False,
        tenant_name="tenant_name",
        token="token",
        username="username",
        password="password",
    )
    http_request = mocker.patch.object(
        soap_client, "_http_request", return_value=util_read_file("test_data/xml_raw_response.txt")
    )
    soap_client.list_workers(**list_workers_kwargs)
    return http_request.call_args.kwargs["data"]


LIST_WORKERS_VARIANTS = [
    pytest.param({"page": "1", "count": "1"}, id="all_workers"),
    pytest.param({"page": "1", "count": "1", "employee_id": "123456"}, id="by_employee_id"),
]


@pytest.mark.parametrize("list_workers_kwargs", LIST_WORKERS_VARIANTS)
def test_list_workers_response_group_follows_schema_order(mocker, list_workers_kwargs):
    """
    Given:
    - A Workday client.
    When:
    - Calling list_workers (with and without an employee ID).
    Then:
    - Ensure the Response_Group elements are sent in the order defined by the Workday schema
      (Include_Reference first). Workday rejects out-of-order elements with
      'Client.validationError - Invalid request'.
    """
    import xml.etree.ElementTree as ET

    body = _sent_request_body(mocker, list_workers_kwargs)

    response_group = ET.fromstring(body.strip()).find(".//{urn:com.workday/bsvc}Response_Group")
    assert response_group is not None
    sent_order = [element.tag.split("}")[1] for element in response_group]
    assert sent_order == [
        "Include_Reference",
        "Include_Personal_Information",
        "Include_Employment_Information",
        "Include_Management_Chain_Data",
        "Include_Photo",
    ]


@pytest.mark.parametrize(
    "params, expected",
    [
        pytest.param({}, "v47.0", id="default"),
        pytest.param({"api_version": ""}, "v47.0", id="empty"),
        pytest.param({"api_version": "v34.0"}, "v34.0", id="custom"),
        pytest.param({"api_version": " v45.1 "}, "v45.1", id="whitespace"),
    ],
)
def test_get_api_version(params, expected):
    """
    Given:
    - Instance parameters with or without an api_version.
    When:
    - Calling get_api_version.
    Then:
    - Ensure the configured version is returned, or the default when not set.
    """
    from Workday import get_api_version

    assert get_api_version(params) == expected


@pytest.mark.parametrize("api_version", ["47.0", "v47", "version47", "v47.0/"])
def test_get_api_version_invalid(api_version):
    """
    Given:
    - A malformed api_version parameter.
    When:
    - Calling get_api_version.
    Then:
    - Ensure a DemistoException is raised.
    """
    from CommonServerPython import DemistoException
    from Workday import get_api_version

    with pytest.raises(DemistoException, match="Invalid API version"):
        get_api_version({"api_version": api_version})


@pytest.mark.parametrize("list_workers_kwargs", LIST_WORKERS_VARIANTS)
def test_list_workers_sends_configured_api_version(mocker, list_workers_kwargs):
    """
    Given:
    - A Workday client configured with a custom API version.
    When:
    - Calling list_workers (with and without an employee ID).
    Then:
    - Ensure the Get_Workers_Request is sent with the configured version.
    """
    import xml.etree.ElementTree as ET

    soap_client = Client(
        tenant_url="https://test.workday.com/XSOAR",
        verify_certificate=False,
        proxy=False,
        tenant_name="tenant_name",
        token="token",
        username="username",
        password="password",
        api_version="v34.0",
    )
    raw_response = util_read_file("test_data/xml_raw_response.txt")
    http_request = mocker.patch.object(soap_client, "_http_request", return_value=raw_response)
    soap_client.list_workers(**list_workers_kwargs)

    body = http_request.call_args.kwargs["data"]
    request = ET.fromstring(body.strip()).find(".//{urn:com.workday/bsvc}Get_Workers_Request")
    assert request.get("{urn:com.workday/bsvc}version") == "v34.0"
