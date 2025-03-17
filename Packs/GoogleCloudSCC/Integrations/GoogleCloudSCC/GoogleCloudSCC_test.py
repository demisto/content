import json
import os
from unittest.mock import patch, Mock

import pytest

from GoogleCloudSCC import ERROR_MESSAGES, GoogleSccClient, BaseGoogleClient, GooglePubSubClient, \
    GoogleCloudAssetClient, GoogleNameParser

with open("test_data/service_account_json.txt") as f:
    TEST_JSON = f.read()


@pytest.fixture
def client():
    with patch.object(GoogleSccClient, "__init__", lambda x: None):
        mocked_client = GoogleSccClient()
        mocked_client.organization_id = "organization_id"
        mocked_client.service = Mock()
        mocked_client.execute_request = Mock()
    return mocked_client


@pytest.fixture
def pubsub_client():
    with patch.object(GooglePubSubClient, "__init__", lambda x: None):
        mocked_client = GooglePubSubClient()
        mocked_client.project_id = "project_id"
        mocked_client.subscription_id = "subscription_id"
        mocked_client.service = Mock()
        mocked_client.execute_request = Mock()
    return mocked_client


@pytest.fixture
def cloud_asset_client():
    with patch.object(GoogleCloudAssetClient, "__init__", lambda x: None):
        mocked_client = GoogleCloudAssetClient()
        mocked_client.organization_id = "organization_id"
        mocked_client.service = Mock()
        mocked_client.execute_request = Mock()
    return mocked_client


@pytest.fixture
def base_client():
    with patch.object(BaseGoogleClient, "__init__", lambda x: None):
        mocked_client = BaseGoogleClient()
        mocked_client.service = "service"
    return mocked_client


def test_safe_load_non_strict_json():
    """
    Scenario: Dictionary should be prepared from json string.

    Given:
    - json as string.

    When:
    - Preparing dictionary from string.

    Then:
    - Ensure valid json should be loaded successfully.
    """
    from GoogleCloudSCC import safe_load_non_strict_json

    excepted_json = json.loads(TEST_JSON, strict=False)
    assert safe_load_non_strict_json(TEST_JSON) == excepted_json


def test_safe_load_non_strict_json_parse_error():
    """
     Scenario: Failed to load json when invalid json string is given.

     Given:
     - Empty json string.

     When:
     - Preparing dictionary from string.

     Then:
     - Ensure Exception is raised with proper error message.
     """
    from GoogleCloudSCC import safe_load_non_strict_json

    with pytest.raises(ValueError, match=ERROR_MESSAGES['JSON_PARSE_ERROR'].format('Service Account JSON')):
        safe_load_non_strict_json('Invalid json')


def test_safe_load_non_strict_json_empty():
    """
    Scenario: Returns {}(blank) dictionary when empty json string is given.

    Given:
    - Invalid json as string.

    When:
    - Preparing dictionary from string.

    Then:
    - Ensure {}(blank) dictionary should be returned.
    """
    from GoogleCloudSCC import safe_load_non_strict_json
    assert safe_load_non_strict_json('') == {}


def test_get_source_path(mocker):
    """
    Scenario: Return a fully-qualified source string.

    Given:
    - valid string parameters.

    When:
    - Preparing source string.

    Then:
    - Ensure a fully-qualified source string should be returned.
    """
    from GoogleCloudSCC import GoogleNameParser, demisto
    mocker.patch.object(demisto, "params", return_value={"organization_id": "organization_id"})
    assert GoogleNameParser.get_source_path("source_id") == "organizations/organization_id/sources/source_id"


@patch('GoogleCloudSCC.init_google_scc_client')
def test_validate_service_account_and_organization_name(mock1, client):
    """
    Scenario:Validate organization by making "Organization settings" API call.

    Given:
    - Empty Dictionary.

    When:
    - Validating parameters.

    Then:
    - Ensure {}(blank) dictionary returns error.
    """
    from GoogleCloudSCC import validate_service_account_and_organization_name

    mock1.return_value = client
    client.get_findings = Mock(return_value={})
    validate_service_account_and_organization_name({"service_account_json": '{"test": "test"}'})
    assert client.get_findings.call_count == 1

    param = {"service_account_json": "123"}
    with pytest.raises(ValueError, match=ERROR_MESSAGES["INVALID_SERVICE_ACCOUNT"].format("Service Account JSON")):
        validate_service_account_and_organization_name(param)


def test_prepare_markdown_fields_for_fetch_incidents():
    """
    Scenario:Prepares markdown fields for incident.

    Given:
    -  Dictionary of fields received in response of fetch incident.

    When:
    - Validating parameters.

    Then:
    - Proper table format of given parameters.
    """
    from GoogleCloudSCC import prepare_markdown_fields_for_fetch_incidents, tableToMarkdown
    data = {
        "finding": {
            "securityMarks": {"marks": {"A": 1, "B": 2}},
            "sourceProperties": {"MfaDetails": {"C": 3, "D": 4}}
        }
    }

    actual_output = prepare_markdown_fields_for_fetch_incidents(data)

    expected_output = {
        "MfaDetails": tableToMarkdown('', {"C": 3, "D": 4}),
        "securityMarks": tableToMarkdown('', {"A": 1, "B": 2})
    }
    assert actual_output == expected_output


def test_create_filter_list_findings():
    """
    Scenario : Creating common filter query string for "list findings" API based on various filter parameter.

    Given:
    -  List of filter parameters.

    When:
    - Preparing a filter query based on convention of API.

    Then:
    - A filter query with all parameters in proper format.
    """
    from GoogleCloudSCC import create_filter_list_findings
    output = create_filter_list_findings("A, B ,C", "ABC = X", ["HIGH", "LOW"], ["ACTIVE"])
    assert output == 'ABC = X AND (Severity="HIGH" OR Severity="LOW") AND (State="ACTIVE") AND ' \
                     '(Category="A" OR Category="B" OR Category="C")'

    output = create_filter_list_findings("A, B ,C", "", ["HIGH", "LOW"], ["ACTIVE"])
    assert output == '(Severity="HIGH" OR Severity="LOW") AND (State="ACTIVE") AND ' \
                     '(Category="A" OR Category="B" OR Category="C")'


def test_fetch_incidents(pubsub_client):
    """
    Scenario : Prepares incidents from past activity in Google Drive.

    Given:
    -  List of parameters.

    When:
    - Preparing a incident according to given parameters.

    Then:
    - An incident made according to parameters and last_run is returned.
    """
    from GoogleCloudSCC import fetch_incidents
    with open('test_data/fetch_incidents_data.json') as file:
        mock_data = json.load(file)

    pubsub_client.pull_messages = Mock(return_value=mock_data)
    pubsub_client.acknowledge_messages = Mock(return_value={})

    param = {"organization_id": "123"}

    incidents = fetch_incidents(pubsub_client, param)

    assert len(incidents) == 4


def test_execute_request(base_client):
    """
    Scenario : Execute the request and handle error scenario.

    Given:
    - Request object.

    When:
    -  Handling error scenarios.

    Then:
    - Checks if correct Error message is there or not.
    """
    from GoogleCloudSCC import HttpError, httplib2
    from httplib2 import Response, socks
    mock_request = Mock()
    mock_request.execute = Mock(side_effect=[
        HttpError(Response({"status": 404}), b'{}'),
        HttpError(Response({"status": 501}), b'{}'),
        socks.HTTPError("Proxy Error"),
        httplib2.ServerNotFoundError("Not Found.")
    ])
    errors = [
        ERROR_MESSAGES["NOT_FOUND_ERROR"].format("Ok"),
        ERROR_MESSAGES["UNKNOWN_ERROR"].format(501, "Ok"),
        ERROR_MESSAGES["PROXY_ERROR"],
        ERROR_MESSAGES["TIMEOUT_ERROR"].format("Not Found.")
    ]

    for error in errors:
        with pytest.raises(ValueError, match=error):
            base_client.execute_request(mock_request)


def test_google_name_parser():
    """
    Scenario: Validates static method of GoogleNameParser

    Given:
    - argument given

    Then:
    - Ensure static method should return proper outputs.
    """
    from GoogleCloudSCC import GoogleNameParser
    assert GoogleNameParser.get_finding_path("-", "123") == "organizations//sources/-/findings/123"
    assert GoogleNameParser.get_project_path("123") == "projects/123"
    assert GoogleNameParser.get_subscription_path("123", "456") == "projects/123/subscriptions/456"


def test_main(mocker, client):
    """
        Scenario : Parse and validate integration params and commands.
    """
    from GoogleCloudSCC import demisto
    import GoogleCloudSCC

    params = {
        "service_account_json": TEST_JSON,
        "organization_id": "organization_id"
    }
    mocker.patch.object(demisto, "params", return_value=params)

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(GoogleCloudSCC, "init_google_scc_client")
    mocker.patch.object(GoogleCloudSCC, "init_google_pubsub_client")
    mocker.patch.object(GoogleCloudSCC, "test_module", return_value="ok")
    GoogleCloudSCC.main()
    assert GoogleCloudSCC.test_module.called

    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    mocker.patch.object(GoogleCloudSCC, "fetch_incidents", return_value=([], []))
    GoogleCloudSCC.main()
    assert GoogleCloudSCC.fetch_incidents.called

    mocker.patch.object(GoogleCloudSCC, "fetch_incidents", side_effect=[Exception("test")])
    with pytest.raises(Exception, match="Failed to execute {} command. Error: {}".format("fetch-incidents", "test")):
        GoogleCloudSCC.main()


@patch('GoogleCloudSCC.init_google_scc_client')
def test_test_module(mock1, client, mocker):
    """
        Scenario : Test authentication using service json.
    """
    from GoogleCloudSCC import test_module, demisto
    mocker.patch.object(demisto, "results")
    mock1.return_value = client
    client.get_findings = Mock(return_value={})
    test_module({"organization_id": "organization_id", "service_account_json": '{"test": "test"}'})
    assert demisto.results.called
    demisto.results.assert_called_with('ok')


def test_validate_get_int_success():
    """
    Scenario: Validate and convert string max_results to integer.

    Given:
    - valid page size.

    When:
    - Validating max_results.

    Then:
    - Ensure if max_results is valid.
    """
    from GoogleCloudSCC import validate_get_int

    max_results = "9"

    return_value = validate_get_int(max_results, ERROR_MESSAGES["MAX_INCIDENT_ERROR"])
    assert return_value == 9


@pytest.mark.parametrize("string_input", ["invalid_int", "10000000", "-700"])
def test_validate_get_int_max_incident_error(string_input):
    """
    Scenario: Validate and convert string max_results to integer.

    Given:
    - Invalid page size.

    When:
    - Validating max_results at a time of fetched incident

    Then:
    - Ensure if page_size is not in range it returns error.
    """
    from GoogleCloudSCC import validate_get_int, MAX_PAGE_SIZE

    with pytest.raises(ValueError, match=ERROR_MESSAGES["MAX_INCIDENT_ERROR"]):
        validate_get_int(string_input, ERROR_MESSAGES["MAX_INCIDENT_ERROR"], MAX_PAGE_SIZE)


def test_prepare_hr_and_ec_for_list_findings():
    """
    Scenario: Validates human readable and entry context for list findings

    Given:
    - finding response given

    Then:
    - Ensure finding HR and EC.
    """
    from GoogleCloudSCC import prepare_hr_and_ec_for_list_findings
    with open('./test_data/list_finding_response.json') as f:
        finding_response = json.load(f)
    with open('./test_data/list_finding_ec.json') as f:
        finding_ec = json.load(f)

    _, context = prepare_hr_and_ec_for_list_findings(finding_response)
    assert context == finding_ec


def test_prepare_hr_and_ec_for_list_findings_no_record():
    """
    Scenario: Validates human readable and entry context for list findings

    Given:
    - finding response given

    When:
    - Zero records found

    Then:
    - Ensure finding HR and EC.
    """
    from GoogleCloudSCC import prepare_hr_and_ec_for_list_findings
    finding_response = {"listFindingsResults": []}
    hr, context = prepare_hr_and_ec_for_list_findings(finding_response)
    assert context == {}
    assert hr == ERROR_MESSAGES["NO_RECORDS_FOUND"].format("finding")


def test_findings_list_command(client):
    """
    Scenario: Validates command result for list-finding command.

    Given:
    - command arguments given for list finding command

    Then:
    - Ensure command should return proper outputs.
    """
    from GoogleCloudSCC import finding_list_command
    with open('test_data/list_finding_response.json') as file:
        mock_data = json.load(file)
    with open('./test_data/list_finding_ec.json') as f:
        finding_ec = json.load(f)
    with open('test_data/list_finding_hr.md') as f:
        hr_output = f.read()
    GoogleNameParser.get_organization_id = Mock(return_value='123')
    client.get_findings = Mock(return_value=mock_data)

    arguments = {
        "category": "A, B",
        "status": "ACTIVE"
    }
    command_output = finding_list_command(client, arguments)

    assert command_output.outputs == finding_ec
    assert command_output.raw_response == mock_data
    assert command_output.readable_output == hr_output


def test_create_filter_list_assets():
    """
    Scenario : Creating common filter query string for "list assets" API based on various filter parameter.

    Given:
    - List of filter parameters.

    When:
    - Preparing a filter query based on convention of API.

    Then:
    - A filter query with all parameters in proper format.
    """
    from GoogleCloudSCC import create_filter_list_assets
    output = create_filter_list_assets("X, Y ,Z", "A, B, C", "ABC = XYZ", "true")

    assert output == 'ABC = XYZ AND (resourceProperties.name="A" OR resourceProperties.name="B" OR' \
                     ' resourceProperties.name="C") AND (securityCenterProperties.resourceType="X" OR ' \
                     'securityCenterProperties.resourceType="Y" OR securityCenterProperties.resourceType="Z") AND ' \
                     '(resourceProperties.lifecycleState="ACTIVE")'

    output = create_filter_list_assets("X, Y ,Z", "A, B, C", "ABC = XYZ", "")
    assert output == 'ABC = XYZ AND (resourceProperties.name="A" OR resourceProperties.name="B" OR' \
                     ' resourceProperties.name="C") AND (securityCenterProperties.resourceType="X" OR ' \
                     'securityCenterProperties.resourceType="Y" OR securityCenterProperties.resourceType="Z")'


def test_prepare_hr_and_ec_for_list_assets():
    """
    Scenario: Validates human readable and entry context for list assets

    Given:
    - assets response given

    Then:
    - Ensure finding HR and EC.
    """
    from GoogleCloudSCC import prepare_outputs_for_list_assets
    with open('./test_data/list_asset_response.json') as f:
        asset_response = json.load(f)
    with open('./test_data/list_asset_ec.json') as f:
        asset_ec = json.load(f)

    context, _ = prepare_outputs_for_list_assets(asset_response)
    assert context == asset_ec


def test_prepare_hr_and_ec_for_list_assets_no_record():
    """
    Scenario: Validates human readable and entry context for list assets

    Given:
    - asset response given

    When:
    - Zero records found

    Then:
    - Ensure finding HR and EC.
    """
    from GoogleCloudSCC import prepare_outputs_for_list_assets
    response = {"listAssetsResults": []}
    context, hr = prepare_outputs_for_list_assets(response)
    assert context == {}
    assert hr == ERROR_MESSAGES["NO_RECORDS_FOUND"].format("asset")


def test_asset_list_command(client):
    """
    Scenario: Validates command result for list-asset command.

    Given:
    - command arguments given for list asset command

    Then:
    - Ensure command should return proper outputs.
    """
    from GoogleCloudSCC import asset_list_command
    with open('test_data/list_asset_response.json') as file:
        mock_data = json.load(file)
    with open('./test_data/list_asset_ec.json') as f:
        asset_ec = json.load(f)
    with open('test_data/list_asset_hr.md') as f:
        hr_output = f.read()
    GoogleNameParser.get_organization_id = Mock(return_value='123')
    client.get_assets = Mock(return_value=mock_data)

    arguments = {
        "resourceType": "A",
        "filter": "test"
    }
    command_output = asset_list_command(client, arguments)

    assert command_output.outputs == asset_ec
    assert command_output.raw_response == mock_data
    assert command_output.readable_output == hr_output


def test_split():
    """
    Scenario: Validates that string should split properly.

    Given:
    - string which contains delimiter

    Then:
    - Ensure result should split by delimiter and not split by escaped delimeter
    """
    from GoogleCloudSCC import split_and_escape
    assert split_and_escape(r"abc,ss,ssa,sc\,aa", ",") == ['abc', 'ss', 'ssa', 'sc,aa']
    assert split_and_escape(r"ab;cd ;xy\;ad", ";") == ['ab', 'cd', 'xy;ad']


def test_get_and_validate_args_finding_update():
    """
    Scenario: Get and validates argument of update finding command

    Given:
    - raw argument of update finding command

    Then:
    - Ensure all argument should be in valid format.
    """
    from GoogleCloudSCC import get_and_validate_args_finding_update

    # Invalid severity
    args = {"severity": "INVALID"}
    with pytest.raises(ValueError, match=ERROR_MESSAGES["INVALID_SEVERITY_ERROR"]):
        get_and_validate_args_finding_update(args)

    args = {"sourceProperties": "A=B,  C=D\\,X\\=Y"}
    assert get_and_validate_args_finding_update(args)[4] == {"A": "B", "C": "D,X=Y"}

    args = {"sourceProperties": "INVALID"}
    with pytest.raises(ValueError):
        get_and_validate_args_finding_update(args)

    args = {"severity": "HIGH", "updateMask": "A,B,C"}
    _, _, severity, _, _, update_mask = get_and_validate_args_finding_update(args)
    assert severity == "HIGH"
    assert update_mask == ["A", "B", "C"]


def test_get_update_mask_for_update_finding():
    """
    Scenario: Validates updateMask field construct Properly

    Given:
    - update finding command arguments

    Then:
    - Ensure updateMask field construct properly
    """
    from GoogleCloudSCC import get_update_mask_for_update_finding
    body = {
        "severity": "HIGH",
        "state": "ACTIVE",
        "eventTime": "REQUIRED",
        "sourceProperties": {"A": "1"}
    }
    update_mask = ["state", "severity"]

    assert get_update_mask_for_update_finding(body, update_mask).split(",") == ["state", "severity", "eventTime",
                                                                                "sourceProperties.A"]


def test_prepare_hr_and_ec_for_update_finding():
    """
    Scenario: Validates human readable and entry context for update finding

    Given:
    - update finding response given

    Then:
    - Ensure finding HR is correct
    """
    from GoogleCloudSCC import prepare_hr_and_ec_for_update_finding
    with open('./test_data/update_finding_response.json') as f:
        finding_response = json.load(f)

    hr, _ = prepare_hr_and_ec_for_update_finding(finding_response)
    assert "Name" in hr
    assert "State" in hr
    assert "Category" in hr
    assert "Severity" not in hr


def test_prepare_hr_and_ec_for_cloud_assets_list():
    """
    Scenario: Validates human readable and entry context for cloud assets list

    Given:
    - asset list response given

    Then:
    - Ensure HR and entry context is correct
    """
    from GoogleCloudSCC import prepare_hr_and_ec_for_cloud_asset_list
    with open('./test_data/cloud_assets_list_response.json') as f:
        cloud_assets_response = json.load(f)

    with open('./test_data/cloud_assets_list_ec.json') as f:
        cloud_assets_ec = json.load(f)

    hr, ec = prepare_hr_and_ec_for_cloud_asset_list(cloud_assets_response)

    assert cloud_assets_ec == ec
    assert "Asset Name" in hr
    assert "Asset Type" in hr
    assert "Parent" in hr
    assert "Discovery Name" in hr
    assert "Ancestors" in hr
    assert "Update Time (In UTC)" in hr


def test_prepare_hr_and_ec_for_cloud_assets_list_no_record():
    """
    Scenario: Validates human readable and entry context for cloud assets list

    Given:
    - cloud asset response given

    When:
    - Zero records found

    Then:
    - Ensure finding HR and EC.
    """
    from GoogleCloudSCC import prepare_hr_and_ec_for_cloud_asset_list
    response = {"assets": []}
    hr, context = prepare_hr_and_ec_for_cloud_asset_list(response)
    assert context == {}
    assert hr == ERROR_MESSAGES["NO_RECORDS_FOUND"].format("resource")


def test_cloud_asset_list_command(cloud_asset_client):
    """
    Scenario: Validates command result for cloud asset-resource-list command.

    Given:
    - command arguments given for cloud asset resource list command

    Then:
    - Ensure command should return proper outputs.
    """
    from GoogleCloudSCC import cloud_asset_list_command
    with open('test_data/cloud_assets_list_response.json') as file:
        mock_data = json.load(file)
    with open('./test_data/cloud_assets_list_ec.json') as f:
        asset_ec = json.load(f)
    with open('test_data/cloud_assets_list_hr.md') as f:
        hr_output = f.read()
    GoogleNameParser.get_organization_id = Mock(return_value='123')
    cloud_asset_client.get_assets = Mock(return_value=mock_data)

    arguments = {
        "parent": "project/123456789000"
    }
    command_output = cloud_asset_list_command(cloud_asset_client, arguments)

    assert command_output.outputs == asset_ec
    assert command_output.raw_response == mock_data
    assert command_output.readable_output == hr_output


@pytest.mark.parametrize("test_case, project_names, max_iterations, call_count",
                         [("one-iteration-one-found", "projects/123456789", 2, 1),
                          ("two-iteration-two-found", "projects/123456789,projects/234567890", 2, 2),
                          ("two-iteration-one-only-found-no-token", "projects/123456789,projects/234567890", 2, 1),
                          ("two-iteration-one-only-found-max-iteration-reached",
                           "projects/123456789,projects/234567890",
                           1, 1)])
def test_cloud_asset_owner_get_command(cloud_asset_client, test_case, project_names, max_iterations, call_count):
    """
    Scenario: Validates command result for cloud asset-owner-get command.

    Given:
    - command arguments given for cloud asset owner get command

    Then:
    - Ensure command should call the API expected times and return appropriate outputs.
    """
    from GoogleCloudSCC import cloud_asset_owner_get_command
    with open('test_data/cloud_assets_owners_get_response.json') as file:
        mock_data = json.load(file)['test-cases'][test_case]
    with open('test_data/cloud_assets_owners_get_hr.json') as file:
        hr_output = json.load(file)['test-cases'][test_case]
    GoogleNameParser.get_organization_id = Mock(return_value='123')
    cloud_asset_client.get_assets = Mock(side_effect=mock_data['responses'])

    arguments = {
        "projectName": project_names,
        "maxIteration": max_iterations
    }

    command_output = cloud_asset_owner_get_command(cloud_asset_client, arguments)

    assert command_output.outputs == mock_data['outputs']
    assert cloud_asset_client.get_assets.call_count == call_count
    assert command_output.raw_response == mock_data['outputs']
    assert command_output.readable_output == hr_output


def test_finding_update_command(client, mocker):
    """
    Scenario: Validates command result for update-finding command.

    Given:
    - command arguments given for update finding command

    Then:
    - Ensure command should return proper outputs.
    """
    from GoogleCloudSCC import finding_update_command, demisto
    with open('test_data/update_finding_response.json') as file:
        mock_data = json.load(file)
    with open('./test_data/update_finding_ec.json') as f:
        finding_ec = json.load(f)
    with open('./test_data/update_finding_hr.md') as f:
        hr_output = f.read()
    client.update_finding = Mock(return_value=mock_data)
    params = {
        "organization_id": "123",
    }
    mocker.patch.object(demisto, "params", return_value=params)

    arguments = {
        "status": "ACTIVE"
    }
    command_output = finding_update_command(client, arguments)

    assert command_output.outputs_key_field == "name"
    assert command_output.raw_response == mock_data
    assert command_output.to_context()["EntryContext"] == finding_ec
    assert command_output.readable_output == hr_output


def test_prepare_hr_and_ec_for_cloud_asset_owners_get():
    """
    Scenario: Validates human readable and entry context for cloud assets owners get

    Given:
    - project asset response given

    Then:
    - Ensure HR and entry context is correct
    """
    from GoogleCloudSCC import prepare_hr_and_ec_for_cloud_asset_owners_get
    with open('./test_data/cloud_assets_owners_get_assets.json') as f:
        cloud_assets_response = json.load(f)

    with open('./test_data/cloud_assets_owners_get_ec.json') as f:
        cloud_assets_ec = json.load(f)

    hr, ec = prepare_hr_and_ec_for_cloud_asset_owners_get(cloud_assets_response['assets'],
                                                          cloud_assets_response['readTime'])

    assert cloud_assets_ec == ec
    assert "Project Name" in hr
    assert "Project Owner" in hr
    assert "Ancestors" in hr
    assert "Update Time (In UTC)" in hr


def test_prepare_hr_and_ec_for_cloud_asset_owners_get_no_record():
    """
    Scenario: Validates human readable and entry context for cloud assets owners get

    Given:
    - project asset response given

    When:
    - Zero records found

    Then:
    - Ensure finding HR and EC.
    """
    from GoogleCloudSCC import prepare_hr_and_ec_for_cloud_asset_owners_get

    hr, context = prepare_hr_and_ec_for_cloud_asset_owners_get([], "")
    assert context == []
    assert hr == ERROR_MESSAGES["NO_RECORDS_FOUND"].format("project")


@patch('GoogleCloudSCC.init_google_pubsub_client')
def test_validate_project_and_subscription_id(mock1, pubsub_client):
    """
    Scenario: Validates project ID and subscription ID

    Given:
    - configuration parameter

    When:
    - correct argument provided

    Then:
    - Ensure command should return proper outputs.
    """
    from GoogleCloudSCC import validate_project_and_subscription_id
    mock1.return_value = pubsub_client
    params = {
        "project_id": "project_id",
        "subscription_id": "subscription_id"
    }
    pubsub_client.pull_messages = Mock(return_value={})
    validate_project_and_subscription_id(params)
    assert pubsub_client.pull_messages.call_count == 1


def test_get_http_client_with_proxy(mocker, client):
    """
    Scenario: Validate that proxy is set in http object

    Given:
    - proxy
      insecure
      path to custom certificate

    When:
    - correct proxy, insecure and certificate path arguments provided

    Then:
    - Ensure command that proxy, insecure and certificate path should set in Http object
    """
    mocker.patch('GoogleCloudSCC.handle_proxy', return_value={"https": "admin:password@127.0.0.1:3128"})
    mocker.patch.dict(os.environ, {"REQUESTS_CA_BUNDLE": "path/to/cert"})
    http_obj = client.get_http_client_with_proxy(True, True)

    assert http_obj.proxy_info.proxy_host == "127.0.0.1"
    assert http_obj.proxy_info.proxy_port == 3128
    assert http_obj.proxy_info.proxy_user == "admin"
    assert http_obj.proxy_info.proxy_pass == "password"
    assert http_obj.disable_ssl_certificate_validation
    assert http_obj.ca_certs == "path/to/cert"


def test_google_scc_class_wrapper_methods(client):
    """
    Scenario: Validates helper method of GoogleSccClient

    Given:
    - configuration parameter

    Then:
    - Ensure wrapper method should return proper outputs.
    """
    client.execute_request = Mock(return_value={"A": 123})
    assert client.get_findings(parent="123") == {"A": 123}
    assert client.get_assets("parent", "duration", "mask", "filter", "order", "size", "token", "readtime") == {"A": 123}
    assert client.get_source("name") == {"A": 123}
    assert client.update_finding("name", "time", "severity", "url", None, []) == {"A": 123}


def test_google_pubsub_wrapper_methods(pubsub_client):
    """
    Scenario: Validates helper method of GooglePubSubClient

    Given:
    - configuration parameter

    Then:
    - Ensure wrapper method should return proper outputs.
    """
    pubsub_client.execute_request = Mock(return_value={"B": 123})
    assert pubsub_client.pull_messages("123") == {"B": 123}
    assert pubsub_client.acknowledge_messages(["123"]) == {"B": 123}


def test_google_cloud_assets_class_wrapper_methods(cloud_asset_client):
    """
    Scenario: Validates helper method of GoogleCloudAssetClient

    Given:
    - configuration parameter

    Then:
    - Ensure wrapper method should return proper outputs.
    """
    cloud_asset_client.execute_request = Mock(return_value={"A": 123})
    assert cloud_asset_client.get_assets("parent", "asset_types", "content_type", "10", "page_token",
                                         "read_time") == {"A": 123}


def test_validate_state_and_severity_list():
    """
    Scenario: Validates state and severity.

    Given:
    - state and severity is given

    When:
    - incorrect state and severity given

    Then:
    - Ensure proper error message should raised.
    """
    from GoogleCloudSCC import validate_state_and_severity_list
    with pytest.raises(ValueError, match=ERROR_MESSAGES["INVALID_STATE_ERROR"]):
        validate_state_and_severity_list(["INVALID"], [])
    with pytest.raises(ValueError, match=ERROR_MESSAGES["INVALID_SEVERITY_ERROR"]):
        validate_state_and_severity_list(["ACTIVE"], ["INVALID"])


def test_flatten_keys_to_root_negative():
    """
    Scenario: Validates dictionary

    Given:
    - nested dict given

    Then:
    - Ensure proper dict should returned.
    """
    from GoogleCloudSCC import flatten_keys_to_root
    input_dict = {
        "A": {"AA": 1},
        "B": ["C"]
    }

    flatten_keys_to_root(input_dict, ["C"], {})
    assert input_dict == {"A": {"AA": 1}, "B": ["C"], "C": None}

    flatten_keys_to_root(input_dict, ["A"], {})
    assert input_dict == {"AA": 1, "B": ["C"], "C": None}


def test_find_asset_owners():
    """
    Scenario: Validates find_asset_owners function

    Given:
    - minimized cloud asset

    Then:
    - Ensure that owners list is returned.
    """
    from GoogleCloudSCC import find_asset_owners

    input_asset = {
        "iamPolicy": {
            "bindings": [
                {'members': ['serviceAccount:service-12345'],
                 'role': 'roles/cloudfunctions.serviceAgent'},
                {'members': ['cloudservices.gserviceaccount.com',
                             'serviceAccount.gserviceaccount.com'],
                 'role': 'roles/owner'},
                {'members': ['serviceAccount:firebase-dummy-account'],
                 'role': 'roles/firebase.managementServiceAgent'}
            ]
        }
    }
    expected_owners = ['cloudservices.gserviceaccount.com',
                       'serviceAccount.gserviceaccount.com']
    assert expected_owners == find_asset_owners(input_asset)


def test_find_asset_owners_no_record():
    """
    Scenario: Validates find_asset_owners function

    Given:
    - minimized asset without owners
    - empty input

    Then:
    - Ensure that empty list is returned.
    """
    from GoogleCloudSCC import find_asset_owners

    input_asset = {
        "iamPolicy": {
            "bindings": [
                {'members': ['serviceAccount:service-12345'],
                 'role': 'roles/cloudfunctions.serviceAgent'},
                {'members': ['serviceAccount:firebase-dummy-account'],
                 'role': 'roles/firebase.managementServiceAgent'}
            ]
        }
    }
    assert find_asset_owners(input_asset) == []
    assert find_asset_owners({}) == []


def test_validate_with_regex():
    """
    Scenario: Validates validate_with_regex function

    Given:
    - pattern
    - string
    - validation_message

    When:
    - pattern matches
    - pattern does not match

    Then:
    - Ensure ValueError with provided message is raised when pattern does not match.
    """
    from GoogleCloudSCC import validate_with_regex

    validate_with_regex("validation error", r"^\d{1,4}$", "123")

    with pytest.raises(ValueError) as e:
        validate_with_regex("validation error", r"^\d{1,4}$", "12345")

    assert str(e.value) == "validation error"


def test_finding_state_update_command(client):
    """
    Scenario: Validates command result for update-finding command.

    Given:
    - command arguments given for update finding command

    Then:
    - Ensure command should return proper outputs.
    """
    from GoogleCloudSCC import finding_state_update_command
    with open('test_data/update_finding_response.json') as file:
        mock_data = json.load(file)
    with open('./test_data/update_finding_ec.json') as f:
        finding_ec = json.load(f)
    with open('test_data/update_finding_hr.md') as f:
        hr_output = f.read()
    GoogleNameParser.get_organization_id = Mock(return_value='123')
    client.update_state = Mock(return_value=mock_data)

    arguments = {
        "state": "ACTIVE",
        "name": "name"
    }
    command_output = finding_state_update_command(client, arguments)

    assert command_output.outputs_key_field == "name"
    assert command_output.raw_response == mock_data
    assert command_output.to_context()["EntryContext"] == finding_ec
    assert command_output.readable_output == hr_output


def test_finding_state_update_command_invalid_args(client):
    """
    Scenario: Validates command result for update-finding command.

    Given:
    - command arguments given for update finding command

    Then:
    - Ensure command should return proper outputs.
    """
    from GoogleCloudSCC import finding_state_update_command

    arguments = {
        "state": "dummy",
        "name": "name"
    }

    with pytest.raises(ValueError) as err:
        finding_state_update_command(client, arguments)

    assert str(err.value) == ERROR_MESSAGES["INVALID_STATE_ERROR"]
