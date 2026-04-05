import pytest
from pytest_mock import MockerFixture
import json
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from MagnetAutomate import MagnetAutomateClient


def load_mock_response(file_name: str) -> dict:
    """
    Helper function to load mock response data from a JSON file.

    Args:
        file_name (str): The name of the JSON file to load from the test_data directory.

    Returns:
        dict: The parsed JSON content as a dictionary.
    """
    with open(f"test_data/{file_name}") as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture) -> None:
    """Mock support_multithreading to prevent demistomock attribute errors.

    This fixture automatically runs before each test to mock the support_multithreading
    function which is called during ContentClient initialization. Without this mock,
    tests fail with: AttributeError: module 'demistomock' has no attribute '_Demisto__do'
    """
    mocker.patch("ContentClientApiModule.support_multithreading")


@pytest.fixture
def client() -> "MagnetAutomateClient":
    """
    Pytest fixture that initializes and returns a MagnetAutomateClient instance for testing.

    Returns:
        MagnetAutomateClient: An instance of the Magnet Automate API client.
    """
    from pydantic import SecretStr
    from MagnetAutomate import MagnetAutomateClient, MagnetAutomateParams

    params = MagnetAutomateParams(
        url="https://test.com",  # type: ignore[arg-type]
        api_key=SecretStr("test-key"),
    )
    return MagnetAutomateClient(params)


# region helpers


@pytest.mark.parametrize(
    "results, page, page_size, expected",
    [
        pytest.param([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 2, 5, [6, 7, 8, 9, 10], id="standard_pagination"),
        pytest.param([1, 2, 3], None, None, [1, 2, 3], id="default_behavior_no_page_no_size"),
        pytest.param([1, 2, 3], 1, None, [1, 2, 3], id="default_behavior_page_1_no_size"),
        pytest.param([1, 2, 3], None, 10, [1, 2, 3], id="default_behavior_no_page_with_size"),
        pytest.param([1, 2, 3], 2, 5, [], id="page_exceeds_total_results"),
        pytest.param([], 1, 5, [], id="empty_input_list"),
        pytest.param([1, 2, 3, 4, 5, 6, 7], 2, 5, [6, 7], id="partial_last_page"),
    ],
)
def test_paginate(results: list, page: int | None, page_size: int | None, expected: list) -> None:
    """
    Given:
        - A list of results and pagination parameters (page and page_size).
    When:
        - Calling the paginate helper function.
    Then:
        - Assert the list is sliced correctly according to the page and page_size.
    """
    from MagnetAutomate import paginate

    assert paginate(results, page, page_size) == expected


@pytest.mark.parametrize(
    "results, limit, all_results, expected",
    [
        pytest.param([1, 2, 3, 4, 5], 2, True, [1, 2, 3, 4, 5], id="all_results_true"),
        pytest.param([1, 2, 3, 4, 5], 2, False, [1, 2], id="all_results_false_exceeds_limit"),
        pytest.param([1, 2, 3], 5, False, [1, 2, 3], id="all_results_false_within_limit"),
        pytest.param([], 5, False, [], id="empty_list"),
    ],
)
def test_truncate_results(results: list, limit: int | None, all_results: bool, expected: list) -> None:
    """
    Given:
        - A list of results, a limit, and a flag to return all results.
    When:
        - Calling the truncate_results helper function.
    Then:
        - Assert the list is truncated correctly based on the limit and all_results flag.
    """
    from MagnetAutomate import truncate_results

    assert truncate_results(results, limit, all_results) == expected


# endregion


# region ma-forensics-custom-fields-list


def test_custom_fields_list_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A workflow ID.
    When:
        - Calling the custom_fields_list_command.
    Then:
        - Assert the client's custom_fields_list method is called.
        - Assert the response is correctly processed into CommandResults with expected outputs and prefix.
    """
    from MagnetAutomate import custom_fields_list_command, CustomFieldsListArgs

    mock_response = load_mock_response("custom_fields_list.json")
    mocker.patch.object(client, "custom_fields_list", return_value=mock_response)

    args = CustomFieldsListArgs(workflow_id=1)

    response = custom_fields_list_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.CustomFields"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 0
    assert outputs[1].get("id") == 1
    assert "Custom Fields" in response.readable_output


# endregion

# region ma-forensic-case-create


def test_case_create_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Case creation arguments including case number and custom field values.
    When:
        - Calling the case_create_command.
    Then:
        - Assert the client's case_create method is called with the provided arguments.
        - Assert the response is correctly processed into CommandResults with expected case details.
    """
    from MagnetAutomate import case_create_command, CaseCreateArgs

    mock_response = load_mock_response("case_create.json")
    mocker.patch.object(client, "case_create", return_value=mock_response)

    args = CaseCreateArgs(case_number="CASE-001", custom_field_values={"field1": "value1", "field2": 2})

    response = case_create_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.Case"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 10
    assert outputs.get("caseNumber") == "CASE-001"
    assert "Case Created" in response.readable_output


# endregion

# region ma-forensic-cases-list


def test_cases_list_command_all(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - No specific case ID (requesting all cases).
    When:
        - Calling the cases_list_command.
    Then:
        - Assert the client's cases_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of cases.
    """
    from MagnetAutomate import cases_list_command, CasesListArgs

    mock_response = load_mock_response("cases_list.json")
    mocker.patch.object(client, "cases_list", return_value=mock_response)

    args = CasesListArgs(case_id=None)

    response = cases_list_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.Case"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 1
    assert outputs[1].get("id") == 2
    assert "Cases List" in response.readable_output


def test_cases_list_command_single(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A specific case ID.
    When:
        - Calling the cases_list_command.
    Then:
        - Assert the client's cases_list method is called for the specific case.
        - Assert the response is correctly processed into CommandResults with detailed case information.
    """
    from MagnetAutomate import cases_list_command, CasesListArgs

    mock_response = load_mock_response("case_get.json")
    mocker.patch.object(client, "cases_list", return_value=mock_response)

    args = CasesListArgs(case_id="1")

    response = cases_list_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.Case"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 10
    assert outputs.get("caseNumber") == "CASE-001"
    assert "Case 1 Details" in response.readable_output


# endregion

# region ma-forensic-case-delete


def test_case_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID to delete.
    When:
        - Calling the case_delete_command.
    Then:
        - Assert the client's case_delete method is called with the correct case ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import case_delete_command, CaseDeleteArgs

    mocker.patch.object(client, "case_delete", return_value=None)

    args = CaseDeleteArgs(case_id="123")

    response = case_delete_command(client, args)

    assert response.readable_output == "Case 123 deleted successfully"
    client.case_delete.assert_called_once_with(case_id="123")  # type: ignore


# endregion

# region ma-forensic-case-cancel


def test_case_cancel_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID to cancel.
    When:
        - Calling the case_cancel_command.
    Then:
        - Assert the client's case_cancel method is called with the correct case ID.
        - Assert the readable output indicates successful cancellation.
    """
    from MagnetAutomate import case_cancel_command, CaseCancelArgs

    mocker.patch.object(client, "case_cancel", return_value=None)

    args = CaseCancelArgs(case_id="123")

    response = case_cancel_command(client, args)

    assert response.readable_output == "Case 123 cancelled successfully"
    client.case_cancel.assert_called_once_with(case_id="123")  # type: ignore


# endregion

# region ma-forensics-workflow-run-start


def test_workflow_run_start_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Workflow run arguments including case ID, evidence details, and decryption parameters.
    When:
        - Calling the workflow_run_start_command.
    Then:
        - Assert the client's workflow_run_start method is called with all provided arguments.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from MagnetAutomate import workflow_run_start_command, WorkflowRunStartArgs

    mock_response = load_mock_response("workflow_run_start.json")
    mocker.patch.object(client, "workflow_run_start", return_value=mock_response)

    args = WorkflowRunStartArgs(
        case_id="10",
        evidence_number="ExhibitA",
        type={"ImageSource": {"path": "C:\\testdata\\image\\image123.001"}},
        workflow_id=3,
        output_path="C:\\testdata\\output",
        platform="windows",
        decryption_type="password",
        decryption_value="MySecretPassword",
        continue_on_decryption_fail=False,
        custom_field_values={"5": "Evidence Value A"},
        assigned_node_name="AGENT1",
    )

    response = workflow_run_start_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.WorkflowRun"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 1
    assert outputs[0].get("id") == 11
    assert outputs[0].get("caseId") == 10
    assert "Workflow Run Started" in response.readable_output

    client.workflow_run_start.assert_called_once_with(  # type: ignore
        case_id="10",
        evidence_number="ExhibitA",
        evidence_type={"ImageSource": {"path": "C:\\testdata\\image\\image123.001"}},
        workflow_id=3,
        output_path="C:\\testdata\\output",
        platform="windows",
        decryption={"type": "password", "value": "MySecretPassword", "continueOnDecryptionFail": False},
        custom_field_values={"5": "Evidence Value A"},
        assigned_node_name="AGENT1",
    )


# endregion

# region ma-forensics-workflow-run-list


def test_workflow_run_list_command_specific(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID.
        - A run ID.
    When:
        - Calling the workflow_run_list_command.
    Then:
        - Assert the client's workflow_run_list method is called with the correct case and run IDs.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from MagnetAutomate import workflow_run_list_command, WorkflowRunListArgs

    mock_response = load_mock_response("workflow_run_list_specific.json")
    mocker.patch.object(client, "workflow_run_list_specific", return_value=mock_response)

    args = WorkflowRunListArgs(case_id="10", run_id="23")

    response = workflow_run_list_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.WorkflowRun"
    assert response.outputs_key_field == "id"

    output: dict[str, Any] = response.outputs  # type: ignore

    assert output.get("id") == 23
    assert "Workflow Run 23 Details" in response.readable_output
    client.workflow_run_list_specific.assert_called_once_with(case_id="10", run_id="23")  # type: ignore


def test_workflow_run_list_command_all(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID.
    When:
        - Calling the workflow_run_list_command.
    Then:
        - Assert the client's workflow_run_list method is called with the correct case ID.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from MagnetAutomate import workflow_run_list_command, WorkflowRunListArgs

    mock_response = load_mock_response("workflow_run_list_all.json")
    mocker.patch.object(client, "workflow_run_list_all", return_value=mock_response)

    args = WorkflowRunListArgs(case_id="10", run_id=None)

    response = workflow_run_list_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.WorkflowRun"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 23
    assert outputs[1].get("id") == 42
    assert "Workflow Runs for Case 10" in response.readable_output
    client.workflow_run_list_all.assert_called_once_with(case_id="10")  # type: ignore


# endregion


# region ma-forensics-workflow-run-delete


def test_workflow_run_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID and a workflow run ID to delete.
    When:
        - Calling the workflow_run_delete_command.
    Then:
        - Assert the client's workflow_run_delete method is called with the correct case ID and run ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import workflow_run_delete_command, WorkflowRunDeleteArgs

    mocker.patch.object(client, "workflow_run_delete", return_value=None)

    args = WorkflowRunDeleteArgs(case_id="123", run_id="456")

    response = workflow_run_delete_command(client, args)

    assert response.readable_output == "Workflow run 456 for case 123 deleted successfully"
    client.workflow_run_delete.assert_called_once_with(case_id="123", run_id="456")  # type: ignore


# endregion

# region ma-forensics-workflow-run-cancel


def test_workflow_run_cancel_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A case ID and a workflow run ID to cancel.
    When:
        - Calling the workflow_run_cancel_command.
    Then:
        - Assert the client's workflow_run_cancel method is called with the correct case ID and run ID.
        - Assert the readable output indicates successful cancellation.
    """
    from MagnetAutomate import workflow_run_cancel_command, WorkflowRunCancelArgs

    mocker.patch.object(client, "workflow_run_cancel", return_value=None)

    args = WorkflowRunCancelArgs(case_id="123", run_id="456")

    response = workflow_run_cancel_command(client, args)

    assert response.readable_output == "Workflow run 456 for case 123 cancelled successfully"
    client.workflow_run_cancel.assert_called_once_with(case_id="123", run_id="456")  # type: ignore


# endregion


# region ma-forensics-merge-workflow-run-start


def test_merge_workflow_run_start_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Merge workflow run arguments including case ID, run IDs, and workflow ID.
    When:
        - Calling the merge_workflow_run_start_command.
    Then:
        - Assert the client's merge_workflow_run_start method is called with all provided arguments.
        - Assert the response is correctly processed into CommandResults with expected workflow run details.
    """
    from MagnetAutomate import merge_workflow_run_start_command, MergeWorkflowRunStartArgs

    mock_response = load_mock_response("merge_workflow_run_start.json")
    mocker.patch.object(client, "merge_workflow_run_start", return_value=mock_response)

    args = MergeWorkflowRunStartArgs(
        case_id="10",
        run_ids=["11", "12"],
        workflow_id=5,
        output_path="C:\\testdata\\output",
        assigned_node_name="AGENT1",
    )

    response = merge_workflow_run_start_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.WorkflowRun"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 14
    assert outputs.get("caseId") == 10
    assert "Merge Workflow Run Started" in response.readable_output

    client.merge_workflow_run_start.assert_called_once_with(  # type: ignore
        case_id="10",
        run_ids=["11", "12"],
        workflow_id=5,
        output_path="C:\\testdata\\output",
        assigned_node_name="AGENT1",
    )


# endregion


# region ma-forensics-workflow-list


def test_workflow_list_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - No specific arguments (requesting all workflows).
    When:
        - Calling the workflow_list_command.
    Then:
        - Assert the client's workflows_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of workflows.
    """
    from MagnetAutomate import workflow_list_command, WorkflowListArgs

    mock_response = load_mock_response("workflows_list.json")
    mocker.patch.object(client, "workflows_list", return_value=mock_response)

    args = WorkflowListArgs()

    response = workflow_list_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.Workflow"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 2
    assert outputs[0].get("id") == 9
    assert outputs[1].get("id") == 17
    assert "Workflows" in response.readable_output
    client.workflows_list.assert_called_once()  # type: ignore


# endregion


# region ma-forensics-workflow-delete


def test_workflow_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A workflow ID to delete.
    When:
        - Calling the workflow_delete_command.
    Then:
        - Assert the client's workflow_delete method is called with the correct workflow ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import workflow_delete_command, WorkflowDeleteArgs

    mocker.patch.object(client, "workflow_delete", return_value=None)

    args = WorkflowDeleteArgs(workflow_id="9")

    response = workflow_delete_command(client, args)

    assert response.readable_output == "Workflow 9 deleted successfully"
    client.workflow_delete.assert_called_once_with(workflow_id="9")  # type: ignore


# endregion


# region ma-forensics-workflow-get


def test_workflow_get_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A workflow ID to export.
    When:
        - Calling the workflow_get_command.
    Then:
        - Assert the client's workflow_get method is called with the correct workflow ID.
        - Assert the response is correctly processed into CommandResults with expected workflow export details.
    """
    from MagnetAutomate import workflow_get_command, WorkflowGetArgs

    mock_response = load_mock_response("workflow_get.json")
    mocker.patch.object(client, "workflow_get", return_value=mock_response)

    args = WorkflowGetArgs(workflow_id="1")

    response = workflow_get_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.Workflow"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("name") == "Process - Image"
    assert outputs.get("automateVersion") == "1.2.3.0000"
    assert outputs.get("id") == "1"
    assert "Workflow 1 Export" in response.readable_output
    client.workflow_get.assert_called_once_with(workflow_id="1")  # type: ignore


# endregion


# region ma-forensics-node-create


def test_node_create_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Node creation arguments including name, address, and working directory.
    When:
        - Calling the node_create_command.
    Then:
        - Assert the client's node_create method is called with the provided arguments.
        - Assert the response is correctly processed into CommandResults with expected node details.
    """
    from MagnetAutomate import node_create_command, NodeCreateArgs

    mock_response = load_mock_response("node_create.json")
    mocker.patch.object(client, "node_create", return_value=mock_response)

    args = NodeCreateArgs(
        name="NODE-002",
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications_json='[{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0", "applicationPath": "C:\\\\Program Files\\\\Magnet Forensics\\\\Magnet AUTOMATE\\\\agent\\\\AXIOM Process\\\\AXIOMProcess.CLI.exe"}]',  # noqa: E501
    )

    response = node_create_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.Node"
    assert response.outputs_key_field == "id"

    outputs: dict[str, Any] = response.outputs  # type: ignore

    assert outputs.get("id") == 1
    assert outputs.get("name") == "NODE-002"
    assert "The node 'NODE-002' was created successfully" in response.readable_output

    client.node_create.assert_called_once_with(  # type: ignore
        name="NODE-002",
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications=[
            {
                "applicationName": "AXIOM Process",
                "applicationVersion": "7.0.0",
                "applicationPath": "C:\\Program Files\\Magnet Forensics\\Magnet AUTOMATE\\agent\\AXIOM Process\\AXIOMProcess.CLI.exe",  # noqa: E501
            }
        ],
    )


# endregion


# region ma-forensics-nodes-list


def test_nodes_list_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - No specific arguments (requesting all nodes).
    When:
        - Calling the nodes_list_command.
    Then:
        - Assert the client's nodes_list method is called.
        - Assert the response is correctly processed into CommandResults containing a list of nodes.
    """
    from MagnetAutomate import nodes_list_command, NodesListArgs

    mock_response = load_mock_response("nodes_list.json")
    mocker.patch.object(client, "nodes_list", return_value=mock_response)

    args = NodesListArgs()

    response = nodes_list_command(client, args)

    assert response.outputs_prefix == "MagnetForensics.Node"
    assert response.outputs_key_field == "id"

    outputs: list[dict[str, Any]] = response.outputs  # type: ignore

    assert len(outputs) == 3
    assert outputs[0].get("id") == 1
    assert outputs[1].get("id") == 2
    assert outputs[2].get("id") == 3
    assert "Nodes List" in response.readable_output
    client.nodes_list.assert_called_once()  # type: ignore


# endregion


# region ma-forensics-node-update


def test_node_update_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - Node update arguments including node ID, address, and working directory.
    When:
        - Calling the node_update_command.
    Then:
        - Assert the client's node_update method is called with the provided arguments.
    """
    from MagnetAutomate import node_update_command, NodeUpdateArgs

    mocker.patch.object(client, "node_update", return_value=None)

    args = NodeUpdateArgs(
        node_id="1",
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications_json='[{"applicationName": "AXIOM Process", "applicationVersion": "7.0.0", "applicationPath": "C:\\\\Program Files\\\\Magnet Forensics\\\\Magnet AUTOMATE\\\\agent\\\\AXIOM Process\\\\AXIOMProcess.CLI.exe"}]',  # noqa: E501
    )

    response = node_update_command(client, args)

    assert "Node 1 was updated successfully" in response.readable_output

    client.node_update.assert_called_once_with(  # type: ignore
        node_id="1",
        address="automate-node-2",
        working_directory="C:\\automate\\updatedTemp",
        applications=[
            {
                "applicationName": "AXIOM Process",
                "applicationVersion": "7.0.0",
                "applicationPath": "C:\\Program Files\\Magnet Forensics\\Magnet AUTOMATE\\agent\\AXIOM Process\\AXIOMProcess.CLI.exe",  # noqa: E501
            }
        ],
    )


# endregion


# region ma-forensics-node-delete


def test_node_delete_command(mocker: MockerFixture, client: "MagnetAutomateClient") -> None:
    """
    Given:
        - A node ID to delete.
    When:
        - Calling the node_delete_command.
    Then:
        - Assert the client's node_delete method is called with the correct node ID.
        - Assert the readable output indicates successful deletion.
    """
    from MagnetAutomate import node_delete_command, NodeDeleteArgs

    mocker.patch.object(client, "node_delete", return_value=None)

    args = NodeDeleteArgs(node_id="123")

    response = node_delete_command(client, args)

    assert response.readable_output == "The Node 123 was deleted successfully"
    client.node_delete.assert_called_once_with(node_id="123")  # type: ignore


# endregion
