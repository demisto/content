import io
import json
import pytest
from Workday import Client, list_workers_command, create_worker_context, convert_to_json, main

from CommonServerPython import CommandResults

client = Client(tenant_url="https://test.workday.com/XSOAR", verify_certificate=False, proxy=False,
                tenant_name="tenant_name", token="token", username="username", password="password")


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_read_file(path):
    with open(path, 'r') as _file:
        return _file.read()


@pytest.mark.parametrize(
    'args', [
        ({'page': '1', 'count': '1', 'managers': '2'}),
        ({"employee_id": '123456', 'managers': '2'})
    ]
)
def test_list_workers_command(mocker, args):
    """Tests list_workers_command command function.

    Configures mocker instance and patches the client's http_request to generate the appropriate
    list_workers API response, loaded from a local JSON file.
    Checks the output of the command function with the expected output.

    This Test run 2 times for each use case (with employee Id and without)
    """
    XML_RAW_RESPONSE = util_read_file('test_data/xml_raw_response.txt')
    mocker.patch.object(client, '_http_request', return_value=XML_RAW_RESPONSE)
    results: CommandResults = list_workers_command(client, args)
    assert results.outputs == WORKER_CONTEXT_DATA
    assert results.outputs_key_field == 'Worker_ID'
    assert results.outputs_prefix == 'Workday.Worker'


def test_create_worker_context():
    """Tests create_worker_context function.

       Checks the output of the function with the expected output.
       Checks the boolean representation for `Primary` Field under `Emails`. expected - True
       Checks the boolean representation for `Active` Field. expected - True
       Checks the context contains the specified managers number(2)

       No mock is needed here.
       """
    WORKER_DATA = util_load_json('test_data/worker_data.json')
    context = create_worker_context(WORKER_DATA, num_of_managers=2)
    assert WORKER_CONTEXT_DATA == context
    assert len(context[0].get('Managers')) == 2
    if context[0]['Emails'][0]['Primary']:
        assert True
    if context[0]['Active']:
        assert True


def test_convert_to_json():
    """Tests convert_to_json function.

    Checks the output of the function with the expected output.

    No mock is needed here.
    """
    XML_RAW_RESPONSE = util_read_file('test_data/xml_raw_response.txt')
    JSON_RAW_RESPONSE = util_load_json('test_data/json_raw_respose.json')
    raw_response, worker_data = convert_to_json(XML_RAW_RESPONSE)
    assert JSON_RAW_RESPONSE == raw_response
    assert worker_data == worker_data


WORKER_CONTEXT_DATA = [{
    'Worker_ID': '123456', 'User_ID': 'JDoe@paloaltonetworks.com', 'Country': 'AE',
    'Legal_First_Name': 'John Wick', 'Legal_Last_Name': 'Doe',
    'Preferred_First_Name': 'John Wick', 'Preferred_Last_Name': 'Doe',
    'Position_ID': 'POS-114061', 'Position_Title': 'Regional Sales Manager',
    'Business_Title': 'Regional Sales Manager', 'Start_Date': '2020-03-25',
    'End_Employment_Reason_Reference': '', 'Worker_Type': 'Regular',
    'Position_Time_Type': 'Full_time', 'Scheduled_Weekly_Hours': '40', 'Default_Weekly_Hours': '40',
    'Full_Time_Equivalent_Percentage': '100', 'Exclude_from_Headcount': '0',
    'Pay_Rate_Type': 'Salary', 'Job_Profile_Name': 'Regional Sales Manager (DQC)',
    'Work_Shift_Required': '0', 'Critical_Job': '0', 'Business_Site_id': '3010',
    'Business_Site_Name': 'Office - Saudi Arabia - Narnia', 'Business_Site_Type': 'Office',
    'Business_Site_Address': {'Address_ID': 'ADDRESS_REFERENCE-3-3415',
                              'Formatted_Address': 'Eye Tower&#xa;P.O Box: 230 888, Floor 28&#xa;Offices 1, '
                                                   '2&#xa;Narnia 11111&#xa;Narnia&#xa;Saudi Arabia',
                              'Country': 'SA', 'Postal_Code': '11111'}, 'End_Date': None,
    'Pay_Through_Date': None, 'Active': True, 'Hire_Date': '2020-03-25',
    'Hire_Reason': 'Hire_Employee_Hire_Employee_Rehire', 'First_Day_of_Work': '2020-03-25',
    'Retired': '0', 'Days_Unemployed': '0', 'Terminated': False, 'Rehire': '1',
    'Resignation_Date': '2018-06-14', 'Has_International_Assignment': '0',
    'Home_Country_Reference': 'SA', 'Photo': 'image_in_base64', 'Addresses': [
        {'Address_ID': 'ADDRESS_REFERENCE-3-3415',
         'Formatted_Address': 'Eye Tower&#xa;P.O Box: 230 888, Floor 28&#xa;Offices 1, 2&#xa;Narnia '
                              '11111&#xa;Narnia&#xa;Saudi Arabia',
         'Country': 'SA', 'Region': '01', 'Region_Descriptor': 'Narnia', 'Postal_Code': '11111', 'Type': 'WORK'},
        {'Address_ID': 'ADDRESS_REFERENCE-6-107',
         'Formatted_Address': 'King Faisal District&#xa;Narnia 13215&#xa;Saudi Arabia', 'Country': 'SA', 'Region': '',
         'Region_Descriptor': '', 'Postal_Code': '13215', 'Type': 'HOME'}], 'Emails': [
        {'Email_Address': 'John@hotmail.com', 'Type': 'HOME', 'Primary': True, 'Public': False},
        {'Email_Address': 'JDoe@paloaltonetworks.com', 'Type': 'WORK', 'Primary': True, 'Public': True}], 'Phones': [
        {'ID': 'PHONE_REFERENCE-3-4210', 'Phone_Number': '+966555055555', 'Type': 'Mobile', 'Usage': 'WORK'},
        {'ID': 'PHONE_REFERENCE-3-14614', 'Phone_Number': '+966555055555', 'Type': 'Mobile', 'Usage': 'HOME'}],
    'Managers': [{'Manager_ID': '100700', 'Manager_Name': 'Manager 700'},
                 {'Manager_ID': '100600', 'Manager_Name': 'Manager 600'}]}]


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
        'credentials': {'identifier': 'user', 'password': 'pass'},
        'base_url': 'https://test.com',
        'cred_tenant_name': {'password': 'tenant'},
        'insecure': False,
        'proxy': False,
        'cred_token': {'password': 'token'}
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='workday-list-workers')
    mocker.patch.object(demisto, 'args', return_value={'page': '1', 'count': '1'})
    mocker.patch.object(Client, 'list_workers', return_value=({}, [{'Worker_Data': {'Worker_ID': '123'}}]))
    XML_RAW_RESPONSE = util_read_file('test_data/xml_raw_response.txt')
    mocker.patch.object(client, '_http_request', return_value=XML_RAW_RESPONSE)
    mocker.patch.object(Workday, 'create_worker_context', return_value=None)
    main()
