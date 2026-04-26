# ruff: noqa: F403, F405
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any
from pydantic import AnyUrl, Field, SecretStr, validator  # pylint: disable=no-name-in-module

from ContentClientApiModule import *
from BaseContentApiModule import *

# region Constants

BASE_CONTEXT_OUTPUT_PREFIX = "MagnetAutomate"

# endregion

# region Helpers


def truncate_results(results: list[Any], limit: int | None = None, all_results: bool = False) -> list[Any]:
    """
    Truncates a list of results based on a limit or an override flag.

    Args:
        results (list[Any]): The list of results to truncate.
        limit (int | None): The maximum number of results to return.
        all_results (bool): If True, returns the full list regardless of the limit.

    Returns:
        list[Any]: The truncated slice of results.
    """
    if all_results:
        return results

    if limit is not None:
        return results[:limit]

    return results


def validate_json(value):
    if isinstance(value, str) and value:
        try:
            return json.loads(value)
        except json.JSONDecodeError as e:
            # not logging json value as it might contain sensitive information
            demisto.debug(f"[VALIDATION FAILED] Could not parse json from provided value with exception {e.msg}.")
            return value
    return value


# endregion

# region Parameters


class Credentials(ContentBaseModel):
    """Credentials model for API authentication."""

    # username field omitted because `hiddenusername: true` in YML
    password: SecretStr


class MagnetAutomateParams(BaseParams):
    """Integration parameters for Magnet Automate."""

    url: AnyUrl
    credentials: Credentials

    @property
    def api_key(self):
        return self.credentials.password


# endregion

# region Auth & Client


class MagnetAutomateAuthHandler(APIKeyAuthHandler):
    """Custom authentication handler for Magnet Automate."""

    def __init__(self, api_key: SecretStr):
        super().__init__(key=api_key.get_secret_value(), header_name="X-API-KEY")


class MagnetAutomateClient(ContentClient):
    """Client for Magnet Automate API."""

    def __init__(self, params: MagnetAutomateParams):
        auth_handler = MagnetAutomateAuthHandler(params.api_key)
        super().__init__(
            base_url=params.url,
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=auth_handler,
            client_name="MagnetAutomateClient",
        )

    def custom_fields_list(self) -> list[dict[str, Any]]:
        """
        Gets custom fields for cases and evidence sources.

        Returns:
            list[dict[str, Any]]: A list of custom fields.
        """

        demisto.debug("Sending a GET Request to /customFields.")

        return self.get(
            url_suffix="/customFields",
        )

    def case_create(self, case_number: str, custom_field_values: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Creates a new case.

        Args:
            case_number (str): The case number.
            custom_field_values (dict[str, Any] | None): Optional custom field values.

        Returns:
            dict[str, Any]: The created case.
        """
        json_data: dict[str, Any] = assign_params(caseNumber=case_number, customFieldValues=custom_field_values)

        demisto.debug(f"Sending a POST Request to /cases with {json_data=}.")

        return self.post(
            url_suffix="/cases",
            json=json_data,
        )

    def cases_list(self, case_id: int | None = None) -> list[dict[str, Any]] | dict[str, Any]:
        """
        Gets a list of all cases or information about a specific case.

        Args:
            case_id (int | None): The ID of the case to get.

        Returns:
            list[dict[str, Any]] | dict[str, Any]: A list of cases or a specific case.
        """
        url_suffix = "/cases"
        if case_id:
            url_suffix += f"/{case_id}"

        demisto.debug(f"Sending a GET Request to {url_suffix}.")

        return self.get(
            url_suffix=url_suffix,
        )

    def case_delete(self, case_id: int) -> None:
        """
        Deletes a case.

        Args:
            case_id (int): The ID of the case to delete.
        """
        demisto.debug(f"Sending a DELETE Request to /cases/{case_id}.")

        self.delete(
            url_suffix=f"/cases/{case_id}",
            resp_type="text",
        )

    def case_cancel(self, case_id: int) -> None:
        """
        Cancels a case.

        Args:
            case_id (int): The ID of the case to cancel.
        """
        demisto.debug(f"Sending a PUT Request to /cases/{case_id}/cancel.")

        self.put(
            url_suffix=f"/cases/{case_id}/cancel",
            resp_type="text",
        )

    def workflow_run_start(
        self,
        case_id: int,
        evidence_number: str,
        evidence_type: dict[str, Any],
        workflow_id: int,
        output_path: str | None = None,
        platform: str | None = None,
        decryption: dict[str, Any] | None = None,
        custom_field_values: dict[str, Any] | None = None,
        assigned_node_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Starts a workflow run and assigns it to a case.

        Args:
            case_id (int): The ID of the case to associate the workflow run with.
            evidence_number (str): An evidence number to apply to the evidence source.
            evidence_type (dict[str, Any]): The evidence type (e.g., {"ImageSource": {"path": "..."}}).
            workflow_id (int): The ID of the workflow to run.
            output_path (str | None): Optional output path.
            platform (str | None): Optional platform.
            decryption (dict[str, Any] | None): Optional decryption options.
            custom_field_values (dict[str, Any] | None): Optional custom field values.
            assigned_node_name (str | None): Optional assigned node name.

        Returns:
            list[dict[str, Any]]: The started workflow runs.
        """
        evidence_source: dict[str, Any] = assign_params(
            evidenceNumber=evidence_number,
            type=evidence_type,
            workflowId=workflow_id,
            outputPath=output_path,
            platform=platform,
            decryption=decryption,
            customFieldValues=custom_field_values,
            assignedNodeName=assigned_node_name,
        )

        json_data = {"evidenceSources": [evidence_source]}

        demisto.debug(f"Sending a POST Request to /cases/{case_id}/runs with {json_data=}.")

        if decryption and "value" in decryption and hasattr(decryption["value"], "get_secret_value"):
            # remove obfuscation from payload before http post method
            raw_decryption_dict = decryption.copy()
            raw_decryption_dict["value"] = decryption["value"].get_secret_value()
            evidence_source["decryption"] = raw_decryption_dict

        return self.post(
            url_suffix=f"/cases/{case_id}/runs",
            json=json_data,
        )

    def workflow_run_delete(self, case_id: int, run_id: int) -> None:
        """
        Deletes a workflow run.

        Args:
            case_id (int): The ID of the case.
            run_id (int): The ID of the workflow run to delete.
        """
        demisto.debug(f"Sending a DELETE Request to /cases/{case_id}/runs/{run_id}.")

        self.delete(
            url_suffix=f"/cases/{case_id}/runs/{run_id}",
            resp_type="text",
        )

    def workflow_run_cancel(self, case_id: int, run_id: int) -> None:
        """
        Cancels a workflow run.

        Args:
            case_id (int): The ID of the case.
            run_id (int): The ID of the workflow run to cancel.
        """
        demisto.debug(f"Sending a PUT Request to /cases/{case_id}/runs/{run_id}/cancel.")

        self.put(
            url_suffix=f"/cases/{case_id}/runs/{run_id}/cancel",
            resp_type="text",
        )

    def workflow_run_list_specific(self, case_id: int, run_id: int) -> dict[str, Any]:
        """
        Gets a specific workflow run from a specific case.

        Args:
            case_id (int): The ID of the case to get workflow runs for.
            run_id (int): The ID of the specific workflow run.

        Returns:
            dict[str, Any]: A workflow run object.
        """
        demisto.debug(f"Sending a GET Request to /cases/{case_id}/runs/{run_id}.")

        return self.get(
            url_suffix=f"/cases/{case_id}/runs/{run_id}",
        )

    def workflow_run_list_all(self, case_id: int) -> list[dict[str, Any]]:
        """
        Gets a list of all workflow runs for a specific case.

        Args:
            case_id (int): The ID of the case to get workflow runs for.

        Returns:
            list[dict[str, Any]]: A list of workflow runs.
        """
        demisto.debug(f"Sending a GET Request to /cases/{case_id}/runs.")

        return self.get(
            url_suffix=f"/cases/{case_id}/runs",
        )

    def merge_workflow_run_start(
        self,
        case_id: int,
        run_ids: list[int],
        workflow_id: int,
        output_path: str | None = None,
        assigned_node_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Starts a merge workflow run for multiple existing workflow runs.

        Args:
            case_id (int): The ID of the case.
            run_ids (list[int]): The IDs of the workflow runs to merge.
            workflow_id (int): The ID of the workflow to run.
            output_path (str | None): Optional output path.
            assigned_node_name (str | None): Optional assigned node name.

        Returns:
            dict[str, Any]: The started merge workflow run.
        """
        json_data: dict[str, Any] = assign_params(
            runIds=run_ids, workflowId=workflow_id, outputPath=output_path, assignedNodeName=assigned_node_name
        )

        demisto.debug(f"Sending a POST Request to /cases/{case_id}/merge with {json_data=}.")

        return self.post(
            url_suffix=f"/cases/{case_id}/merge",
            json=json_data,
        )

    def workflows_list(self) -> list[dict[str, Any]]:
        """
        Gets a list of all workflows.

        Returns:
            list[dict[str, Any]]: A list of workflows.
        """
        demisto.debug("Sending a GET Request to /workflows.")

        return self.get(
            url_suffix="/workflows",
        )

    def workflow_delete(self, workflow_id: int) -> None:
        """
        Deletes a workflow.

        Args:
            workflow_id (int): The ID of the workflow to delete.
        """
        demisto.debug(f"Sending a DELETE Request to /workflows/{workflow_id}.")

        self.delete(
            url_suffix=f"/workflows/{workflow_id}",
            resp_type="text",
        )

    def workflow_get(self, workflow_id: int) -> dict[str, Any]:
        """
        Gets workflow export.

        Args:
            workflow_id (int): The ID of the workflow to export.

        Returns:
            dict[str, Any]: The exported workflow.
        """
        demisto.debug(f"Sending a GET Request to /workflows/{workflow_id}/generate-export.")

        return self.get(
            url_suffix=f"/workflows/{workflow_id}/generate-export",
        )

    def node_create(
        self,
        name: str | None = None,
        address: str | None = None,
        working_directory: str | None = None,
        applications: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Creates a new node.

        Args:
            name (str | None): The name of the node.
            address (str | None): The address of the node.
            working_directory (str | None): The working directory of the node.
            applications (list[dict[str, Any]] | None): Information about the applications installed on the node.

        Returns:
            dict[str, Any]: The created node.
        """
        json_data: dict[str, Any] = assign_params(
            name=name, address=address, workingDirectory=working_directory, applications=applications
        )

        demisto.debug(f"Sending a POST Request to /nodes with {json_data=}.")

        return self.post(
            url_suffix="/nodes",
            json=json_data,
        )

    def nodes_list(self) -> list[dict[str, Any]]:
        """
        Gets a list of all the available nodes.

        Returns:
            list[dict[str, Any]]: A list of nodes.
        """
        demisto.debug("Sending a GET Request to /nodes.")

        return self.get(
            url_suffix="/nodes",
        )

    def node_update(
        self,
        node_id: int,
        address: str | None = None,
        working_directory: str | None = None,
        applications: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Updates an existing node.

        Args:
            node_id (int): The ID of the node to update.
            address (str | None): The address of the node.
            working_directory (str | None): The working directory of the node.
            applications (list[dict[str, Any]] | None): Information about the applications installed on the node.

        Returns:
            dict[str, Any]: The updated node.
        """
        json_data: dict[str, Any] = assign_params(address=address, workingDirectory=working_directory, applications=applications)

        demisto.debug(f"Sending a PUT Request to /nodes/{node_id} with {json_data=}.")

        return self.put(
            url_suffix=f"/nodes/{node_id}",
            json=json_data,
        )

    def node_delete(self, node_id: int) -> None:
        """
        Deletes an existing node.

        Args:
            node_id (int): The ID of the node to delete.
        """
        demisto.debug(f"Sending a DELETE Request to /nodes/{node_id}.")

        self.delete(
            url_suffix=f"/nodes/{node_id}",
            resp_type="text",
        )


# endregion

# region test-module


def test_module(client: MagnetAutomateClient) -> str:
    """
    Verifies the connectivity with the Magnet Automate API.

    This function attempts to list custom fields with a limit of 1 to ensure
    that the provided API key and Server URL are valid and reachable.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.

    Returns:
        str: Returns "ok" if the connection is successful, otherwise an error message.
    """
    try:
        demisto.debug("[Testing] Testing API connectivity")
        args = CustomFieldsListArgs(limit=1, all_results=False)
        custom_fields_list_command(client, args)
        demisto.debug("[Testing] API connectivity test passed")

    except Exception as e:
        return f"AuthenticationError: Connection failed. Make sure Server URL and API Key are correctly set. {str(e)}"

    demisto.debug("[Testing] All tests passed.")
    return "ok"


# endregion


# region mf-automate-custom-fields-list
class CustomFieldsListArgs(ContentBaseModel):
    limit: int | None = Field(50, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def custom_fields_list_command(client: MagnetAutomateClient, args: CustomFieldsListArgs) -> CommandResults:
    """
    Executes the mf-automate-custom-fields-list command.

    Retrieves a list of custom fields for cases and evidence sources from Magnet Automate,
    optionally filtered by a workflow ID.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (CustomFieldsListArgs): The command arguments including workflow_id, limit, and all_results.

    Returns:
        CommandResults: The results of the command execution, including the list of custom fields.
    """
    results = client.custom_fields_list()
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)

    readable_output = tableToMarkdown(
        "Custom Fields",
        paginated_results,
        headers=[
            "id",
            "name",
            "type",
            "elementType",
            "description",
            "required",
            "exposeInWorkflow",
            "variableName",
        ],
        headerTransform=lambda x: {
            "id": "Field Id",
            "name": "Name",
            "type": "Type",
            "elementType": "Element Type",
            "description": "Description",
            "required": "Required",
            "exposeInWorkflow": "Expose In Workflow",
            "variableName": "Variable Name",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.CustomFields",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-case-create


class CaseCreateArgs(ContentBaseModel):
    case_number: str = Field(alias="case_number")
    custom_field_values: dict[str, Any] | None = Field(None, alias="custom_field_values")

    @validator("custom_field_values", pre=True, allow_reuse=True)
    @classmethod
    def validate_custom_field_values(cls, v):
        return validate_json(v)


def case_create_command(client: MagnetAutomateClient, args: CaseCreateArgs) -> CommandResults:
    """
    Executes the mf-automate-case-create command.

    Creates a new case in Magnet Automate with the specified case number and optional custom field values.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (CaseCreateArgs): The command arguments including case_number and custom_field_values.

    Returns:
        CommandResults: The results of the command execution, including the created case details.
    """
    results = client.case_create(case_number=args.case_number, custom_field_values=args.custom_field_values)

    readable_output = tableToMarkdown(
        "Case Created",
        results,
        headers=["id", "caseNumber", "customFieldValues"],
        headerTransform=lambda x: {
            "id": "Case Id",
            "caseNumber": "Case Number",
            "customFieldValues": "Custom Fields",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Case",
        outputs_key_field="id",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-cases-list


class CasesListArgs(ContentBaseModel):
    case_id: int | None = Field(None, alias="case_id")
    limit: int | None = Field(50, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v)

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def cases_list_command(client: MagnetAutomateClient, args: CasesListArgs) -> CommandResults:
    """
    Executes the mf-automate-cases-list command.

    Retrieves a list of all cases or detailed information about a specific case from Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (CasesListArgs): The command arguments including case_id, limit, and all_results.

    Returns:
        CommandResults: The results of the command execution, including the case(s) information.
    """
    results = client.cases_list(case_id=args.case_id)

    if args.case_id:
        # Single case result
        case = results if isinstance(results, dict) else results[0] if results else {}

        readable_output = tableToMarkdown(
            f"Case {args.case_id} Details",
            case,
            headers=[
                "id",
                "caseNumber",
                "status",
                "startDateTime",
                "endDateTime",
                "duration",
                "caseRunDetails",
            ],
            headerTransform=lambda x: {
                "id": "Case Id",
                "caseNumber": "Case Number",
                "status": "Status",
                "startDateTime": "Start Date Time",
                "endDateTime": "End Date Time",
                "duration": "Duration",
                "caseRunDetails": "Case Run Details",
            }.get(x, x),
            removeNull=True,
        )
        return CommandResults(
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Case",
            outputs_key_field="id",
            outputs=case,
            readable_output=readable_output,
            raw_response=results,
        )

    # List of cases
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)  # type: ignore
    readable_output = tableToMarkdown(
        "Cases List",
        paginated_results,
        headers=["id", "caseNumber"],
        headerTransform=lambda x: {"id": "Case Id", "caseNumber": "Case Number"}.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Case",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-case-delete


class CaseDeleteArgs(ContentBaseModel):
    case_id: int = Field(alias="case_id")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v, required=True)


def case_delete_command(client: MagnetAutomateClient, args: CaseDeleteArgs) -> CommandResults:
    """
    Executes the mf-automate-case-delete command.

    Deletes a specific case from Magnet Automate using its unique identifier.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (CaseDeleteArgs): The command arguments including the case_id to delete.

    Returns:
        CommandResults: A message indicating the successful deletion of the case.
    """
    client.case_delete(case_id=args.case_id)

    return CommandResults(readable_output=f"Case {args.case_id} deleted successfully")


# endregion

# region mf-automate-case-cancel


class CaseCancelArgs(ContentBaseModel):
    case_id: int = Field(alias="case_id")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v, required=True)


def case_cancel_command(client: MagnetAutomateClient, args: CaseCancelArgs) -> CommandResults:
    """
    Executes the mf-automate-case-cancel command.

    Cancels an ongoing case in Magnet Automate using its unique identifier.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (CaseCancelArgs): The command arguments including the case_id to cancel.

    Returns:
        CommandResults: A message indicating the successful cancellation of the case.
    """
    client.case_cancel(case_id=args.case_id)

    return CommandResults(readable_output=f"Case {args.case_id} cancelled successfully")


# endregion

# region mf-automate-workflow-run-start


class WorkflowRunStartArgs(ContentBaseModel):
    case_id: int = Field(alias="case_id")
    evidence_number: str = Field(alias="evidence_number")
    evidence_type: dict[str, Any] = Field(alias="type")
    workflow_id: int = Field(alias="workflow_id")
    output_path: str | None = Field(None, alias="output_path")
    platform: str | None = Field(None, alias="platform")
    decryption_type: str | None = Field(None, alias="decryption_type")
    decryption_value: SecretStr | None = Field(None, alias="decryption_value")
    continue_on_decryption_fail: bool | None = Field(None, alias="continue_on_decryption_fail")
    custom_field_values: dict[str, Any] | None = Field(None, alias="custom_field_values")
    assigned_node_name: str | None = Field(None, alias="assigned_node_name")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v, required=True)

    @validator("evidence_type", pre=True, allow_reuse=True)
    @classmethod
    def validate_evidence_type(cls, v):
        return validate_json(v)

    @validator("workflow_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_workflow_id(cls, v):
        return arg_to_number(v, required=True)

    @validator("continue_on_decryption_fail", pre=True, allow_reuse=True)
    @classmethod
    def validate_continue_on_decryption_fail(cls, v):
        return arg_to_bool_or_none(v)

    @validator("custom_field_values", pre=True, allow_reuse=True)
    @classmethod
    def validate_custom_field_values(cls, v):
        return validate_json(v)


def workflow_run_start_command(client: MagnetAutomateClient, args: WorkflowRunStartArgs) -> CommandResults:
    """
    Executes the mf-automate-workflow-run-start command.

    Starts a new workflow run in Magnet Automate and associates it with a specific case.
    Supports various options such as evidence type, decryption, and custom fields.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (WorkflowRunStartArgs): The command arguments including case_id, evidence details, and workflow_id.

    Returns:
        CommandResults: The results of the command execution, including the started workflow run details.
    """
    decryption = None
    if args.decryption_type:
        decryption = {
            "type": args.decryption_type,
            "value": args.decryption_value,
            "continueOnDecryptionFail": args.continue_on_decryption_fail or False,
        }

    results = client.workflow_run_start(
        case_id=args.case_id,
        evidence_number=args.evidence_number,
        evidence_type=args.evidence_type,
        workflow_id=args.workflow_id,
        output_path=args.output_path,
        platform=args.platform,
        decryption=decryption,
        custom_field_values=args.custom_field_values,
        assigned_node_name=args.assigned_node_name,
    )

    readable_output = tableToMarkdown(
        "Workflow Run Started",
        results,
        headers=[
            "id",
            "path",
            "version",
            "caseId",
            "caseTypeId",
            "basePath",
            "automateVersion",
        ],
        headerTransform=lambda x: {
            "id": "Run Id",
            "path": "Path",
            "version": "Version",
            "caseId": "Case Id",
            "caseTypeId": "Case Type Id",
            "basePath": "Base Path",
            "automateVersion": "Automate Version",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.WorkflowRun",
        outputs_key_field="id",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-workflow-run-list


class WorkflowRunListArgs(ContentBaseModel):
    case_id: int = Field(alias="case_id")
    run_id: int | None = Field(None, alias="run_id")
    limit: int | None = Field(50, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v, required=True)

    @validator("run_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_run_id(cls, v):
        return arg_to_number(v)

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def workflow_run_list_markdown(results: list[dict[str, Any]], title: str) -> str:
    """
    Converts workflow run results into a markdown table.

    Args:
        results (list[dict[str, Any]]): A list of workflow run objects to format.
        title (str): The title for the markdown table.

    Returns:
        str: A markdown table representing the workflow runs, including details about evidence,
            status, workflow, and current stage.
    """
    table_data = []
    for run in results:
        evidence = run.get("evidence", {}) or {}
        current_stage = run.get("currentStage", {}) or {}
        created_by = run.get("createdBy", {}) or {}

        table_data.append(
            {
                "Run Id": run.get("id"),
                "Evidence Id": evidence.get("id"),
                "Evidence Path": evidence.get("path"),
                "Evidence Type": evidence.get("evidenceType"),
                "Evidence Number": evidence.get("evidenceNumber"),
                "Selected Platform": evidence.get("selectedPlatform"),
                "Status": run.get("status"),
                "Workflow Id": run.get("workflowId"),
                "Workflow Name": run.get("workflowName"),
                "Start DateTime": run.get("startDateTime"),
                "Current Stage Application Display Name": current_stage.get("applicationDisplayName"),
                "Current Stage Status": current_stage.get("status"),
                "End DateTime": run.get("endDateTime"),
                "Created By": created_by.get("name"),
            }
        )

    headers = list(table_data[0].keys()) if table_data else None

    return tableToMarkdown(
        title,
        table_data,
        headers=headers,
        removeNull=True,
    )


def workflow_run_list_command(client: MagnetAutomateClient, args: WorkflowRunListArgs) -> CommandResults:
    """
    Executes the mf-automate-workflow-run-list command.

    Retrieves a list or a specific workflow run associated with a specific case.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (WorkflowRunListArgs): The command arguments including case_id and optional run_id, limit, and all_results.

    Returns:
        CommandResults: The results of the command execution, including the list of workflow runs.
    """
    if args.run_id:
        # single run
        result = client.workflow_run_list_specific(case_id=args.case_id, run_id=args.run_id)
        readable_output = workflow_run_list_markdown(
            [result],
            f"Workflow Run {args.run_id} Details",
        )

        return CommandResults(
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.WorkflowRun",
            outputs_key_field="id",
            outputs=result,
            readable_output=readable_output,
            raw_response=result,
        )

    # all runs
    results = client.workflow_run_list_all(case_id=args.case_id)
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)
    readable_output = workflow_run_list_markdown(
        paginated_results,
        f"Workflow Runs for Case {args.case_id}",
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.WorkflowRun",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-workflow-run-delete


class WorkflowRunDeleteArgs(ContentBaseModel):
    case_id: int = Field(alias="case_id")
    run_id: int = Field(alias="run_id")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v, required=True)

    @validator("run_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_run_id(cls, v):
        return arg_to_number(v, required=True)


def workflow_run_delete_command(client: MagnetAutomateClient, args: WorkflowRunDeleteArgs) -> CommandResults:
    """
    Executes the mf-automate-workflow-run-delete command.

    Deletes a specific workflow run from a case in Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (WorkflowRunDeleteArgs): The command arguments including case_id and run_id.

    Returns:
        CommandResults: The results of the command execution.
    """
    client.workflow_run_delete(case_id=args.case_id, run_id=args.run_id)

    return CommandResults(readable_output=f"Workflow run {args.run_id} for case {args.case_id} deleted successfully")


# endregion

# region mf-automate-workflow-run-cancel


class WorkflowRunCancelArgs(ContentBaseModel):
    case_id: int = Field(alias="case_id")
    run_id: int = Field(alias="run_id")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v, required=True)

    @validator("run_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_run_id(cls, v):
        return arg_to_number(v, required=True)


def workflow_run_cancel_command(client: MagnetAutomateClient, args: WorkflowRunCancelArgs) -> CommandResults:
    """
    Executes the mf-automate-workflow-run-cancel command.

    Cancels a specific workflow run in Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (WorkflowRunCancelArgs): The command arguments including case_id and run_id.

    Returns:
        CommandResults: The results of the command execution.
    """
    client.workflow_run_cancel(case_id=args.case_id, run_id=args.run_id)

    return CommandResults(readable_output=f"Workflow run {args.run_id} for case {args.case_id} cancelled successfully")


# endregion

# region mf-automate-merge-workflow-run-start


class MergeWorkflowRunStartArgs(ContentBaseModel):
    case_id: int = Field(alias="case_id")
    run_ids: list[int] = Field(alias="run_ids")
    workflow_id: int = Field(alias="workflow_id")
    output_path: str | None = Field(None, alias="output_path")
    assigned_node_name: str | None = Field(None, alias="assigned_node_name")

    @validator("case_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_case_id(cls, v):
        return arg_to_number(v, required=True)

    @validator("run_ids", pre=True, allow_reuse=True)
    @classmethod
    def validate_run_ids(cls, v):
        return argToList(v, transform=lambda x: arg_to_number(x, required=True))

    @validator("workflow_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_workflow_id(cls, v):
        return arg_to_number(v, required=True)


def merge_workflow_run_start_command(client: MagnetAutomateClient, args: MergeWorkflowRunStartArgs) -> CommandResults:
    """
    Executes the mf-automate-merge-workflow-run-start command.

    Starts a merge workflow run for multiple existing workflow runs in Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (MergeWorkflowRunStartArgs): The command arguments including case_id, run_ids, and workflow_id.

    Returns:
        CommandResults: The results of the command execution, including the started merge workflow run details.
    """
    results = client.merge_workflow_run_start(
        case_id=args.case_id,
        run_ids=args.run_ids,
        workflow_id=args.workflow_id,
        output_path=args.output_path,
        assigned_node_name=args.assigned_node_name,
    )

    readable_output = tableToMarkdown(
        "Merge Workflow Run Started",
        results,
        headers=[
            "id",
            "path",
            "version",
            "caseId",
            "caseTypeId",
            "basePath",
            "automateVersion",
        ],
        headerTransform=lambda x: {
            "id": "Run Id",
            "path": "Path",
            "version": "Version",
            "caseId": "Case Id",
            "caseTypeId": "Case Type Id",
            "basePath": "Base Path",
            "automateVersion": "Automate Version",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.WorkflowRun",
        outputs_key_field="id",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-workflow-list


class WorkflowListArgs(ContentBaseModel):
    limit: int | None = Field(50, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def workflow_list_markdown(results: list[dict[str, Any]]) -> str:
    """
    Converts workflow list results into a markdown table.

    Args:
        results (list[dict[str, Any]]): A list of workflow objects to format.

    Returns:
        str: A markdown table representing the workflows, including ID, Name, Type,
            Description, and Output Path.
    """
    table_data = []
    for workflow in results:
        workflow_type = workflow.get("type", {}) or {}

        table_data.append(
            {
                "Id": workflow.get("id"),
                "Name": workflow.get("name"),
                "Type Name": workflow_type.get("name"),
                "Description": workflow.get("description"),
                "Output Path": workflow.get("outputPath"),
            }
        )

    return tableToMarkdown(
        "Workflows",
        table_data,
        headers=["Id", "Name", "Type Name", "Description", "Output Path"],
        removeNull=True,
    )


def workflow_list_command(client: MagnetAutomateClient, args: WorkflowListArgs) -> CommandResults:
    """
    Executes the mf-automate-workflow-list command.

    Retrieves a list of available workflows from Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (WorkflowListArgs): The command arguments including limit and all_results.

    Returns:
        CommandResults: The results of the command execution, including the list of workflows.
    """
    results = client.workflows_list()
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)

    readable_output = workflow_list_markdown(paginated_results)

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Workflow",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-workflow-delete


class WorkflowDeleteArgs(ContentBaseModel):
    workflow_id: int = Field(alias="workflow_id")

    @validator("workflow_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_workflow_id(cls, v):
        return arg_to_number(v, required=True)


def workflow_delete_command(client: MagnetAutomateClient, args: WorkflowDeleteArgs) -> CommandResults:
    """
    Executes the mf-automate-workflow-delete command.

    Deletes a specific workflow from Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (WorkflowDeleteArgs): The command arguments including the workflow_id to delete.

    Returns:
        CommandResults: The results of the command execution.
    """
    client.workflow_delete(workflow_id=args.workflow_id)

    return CommandResults(readable_output=f"Workflow {args.workflow_id} deleted successfully")


# endregion

# region mf-automate-workflow-get


class WorkflowGetArgs(ContentBaseModel):
    workflow_id: int = Field(alias="workflow_id")

    @validator("workflow_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_workflow_id(cls, v):
        return arg_to_number(v, required=True)


def workflow_get_markdown(results: dict[str, Any], workflow_id: int) -> str:
    """
    Converts a workflow export object into a markdown table.

    Args:
        results (dict[str, Any]): The workflow export data.
        workflow_id (int): The ID of the workflow being exported.

    Returns:
        str: A markdown table representing the workflow export details, including version,
            name, description, source configuration, and paths.
    """
    source_config = results.get("sourceConfig", {}) or {}

    table_data = {
        "Automate Version": results.get("automateVersion"),
        "Name": results.get("name"),
        "Description": results.get("description"),
        "Source Type": results.get("sourceType"),
        "Source Config Image": source_config.get("image"),
        "Output Path": results.get("outputPath"),
        "Key List Path": results.get("keylistPath"),
        "Password List Path": results.get("passwordListPath"),
        "Distribution": results.get("distribution"),
        "Local Mode": results.get("localMode"),
    }

    return tableToMarkdown(
        f"Workflow {workflow_id} Export",
        table_data,
        headers=[
            "Automate Version",
            "Name",
            "Description",
            "Source Type",
            "Source Config Image",
            "Output Path",
            "Key List Path",
            "Password List Path",
            "Distribution",
            "Local Mode",
        ],
        removeNull=True,
    )


def workflow_get_command(client: MagnetAutomateClient, args: WorkflowGetArgs) -> CommandResults:
    """
    Executes the mf-automate-workflow-get command.

    Retrieves detailed information about a specific workflow from Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (WorkflowGetArgs): The command arguments including the workflow_id.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.workflow_get(workflow_id=args.workflow_id)

    readable_output = workflow_get_markdown(results, args.workflow_id)

    # extend the response with the workflow id
    context_output = results.copy()
    context_output["id"] = args.workflow_id

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Workflow",
        outputs_key_field="id",
        outputs=context_output,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-node-create


class NodeCreateArgs(ContentBaseModel):
    name: str | None = Field(None, alias="name")
    address: str | None = Field(None, alias="address")
    working_directory: str | None = Field(None, alias="working_directory")
    applications_json: Any | None = Field(None, alias="applications_json")

    @validator("applications_json", pre=True, allow_reuse=True)
    @classmethod
    def validate_applications_json(cls, v):
        return validate_json(v)


def node_create_command(client: MagnetAutomateClient, args: NodeCreateArgs) -> CommandResults:
    """
    Executes the mf-automate-node-create command.

    Creates a new node (agent) in Magnet Automate with the specified configuration.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (NodeCreateArgs): The command arguments including name, address, and working directory.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.node_create(
        name=args.name,
        address=args.address,
        working_directory=args.working_directory,
        applications=args.applications_json,  # type: ignore
    )

    node_name = results.get("name", "Unknown")
    readable_output = f"The node '{node_name}' was created successfully"

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Node",
        outputs_key_field="id",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-nodes-list


class NodesListArgs(ContentBaseModel):
    limit: int | None = Field(50, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def nodes_list_command(client: MagnetAutomateClient, args: NodesListArgs) -> CommandResults:
    """
    Executes the mf-automate-nodes-list command.

    Retrieves a list of all nodes (agents) configured in Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (NodesListArgs): The command arguments including limit and all_results.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.nodes_list()
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)

    readable_output = tableToMarkdown(
        "Nodes List",
        paginated_results,
        headers=["id", "name", "status", "workingDirectory", "address"],
        headerTransform=lambda x: {
            "id": "Node Id",
            "name": "Name",
            "status": "Status",
            "workingDirectory": "Working Directory",
            "address": "Address",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Node",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region mf-automate-node-update


class NodeUpdateArgs(ContentBaseModel):
    node_id: int = Field(alias="node_id")
    address: str | None = Field(None, alias="address")
    working_directory: str | None = Field(None, alias="working_directory")
    applications_json: Any | None = Field(None, alias="applications_json")

    @validator("node_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_node_id(cls, v):
        return arg_to_number(v, required=True)

    @validator("applications_json", pre=True, allow_reuse=True)
    @classmethod
    def validate_applications_json(cls, v):
        return validate_json(v)


def node_update_command(client: MagnetAutomateClient, args: NodeUpdateArgs) -> CommandResults:
    """
    Executes the mf-automate-node-update command.

    Updates the configuration of an existing node in Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (NodeUpdateArgs): The command arguments including node_id and fields to update.

    Returns:
        CommandResults: The results of the command execution.
    """
    client.node_update(
        node_id=args.node_id,
        address=args.address,
        working_directory=args.working_directory,
        applications=args.applications_json,  # type: ignore
    )

    return CommandResults(readable_output=f"Node {args.node_id} was updated successfully")


# endregion

# region mf-automate-node-delete


class NodeDeleteArgs(ContentBaseModel):
    node_id: int = Field(alias="node_id")

    @validator("node_id", pre=True, allow_reuse=True)
    @classmethod
    def validate_node_id(cls, v):
        return arg_to_number(v, required=True)


def node_delete_command(client: MagnetAutomateClient, args: NodeDeleteArgs) -> CommandResults:
    """
    Executes the mf-automate-node-delete command.

    Deletes a specific node from Magnet Automate.

    Args:
        client (MagnetAutomateClient): The Magnet Automate API client.
        args (NodeDeleteArgs): The command arguments including the node_id to delete.

    Returns:
        CommandResults: The results of the command execution.
    """
    client.node_delete(node_id=args.node_id)

    return CommandResults(readable_output=f"The Node {args.node_id} was deleted successfully")


# endregion

# region ExecutionConfig


class MagnetAutomateExecutionConfig(BaseExecutionConfig):
    """Execution configuration for Magnet Automate."""

    @property
    def params(self) -> MagnetAutomateParams:
        return MagnetAutomateParams(**self._raw_params)

    @property
    def custom_fields_list_args(self) -> CustomFieldsListArgs:
        return CustomFieldsListArgs(**self._raw_args)

    @property
    def case_create_args(self) -> CaseCreateArgs:
        return CaseCreateArgs(**self._raw_args)

    @property
    def cases_list_args(self) -> CasesListArgs:
        return CasesListArgs(**self._raw_args)

    @property
    def case_delete_args(self) -> CaseDeleteArgs:
        return CaseDeleteArgs(**self._raw_args)

    @property
    def case_cancel_args(self) -> CaseCancelArgs:
        return CaseCancelArgs(**self._raw_args)

    @property
    def workflow_run_start_args(self) -> WorkflowRunStartArgs:
        return WorkflowRunStartArgs(**self._raw_args)

    @property
    def workflow_run_delete_args(self) -> WorkflowRunDeleteArgs:
        return WorkflowRunDeleteArgs(**self._raw_args)

    @property
    def workflow_run_cancel_args(self) -> WorkflowRunCancelArgs:
        return WorkflowRunCancelArgs(**self._raw_args)

    @property
    def workflow_run_list_args(self) -> WorkflowRunListArgs:
        return WorkflowRunListArgs(**self._raw_args)

    @property
    def merge_workflow_run_start_args(self) -> MergeWorkflowRunStartArgs:
        return MergeWorkflowRunStartArgs(**self._raw_args)

    @property
    def workflow_list_args(self) -> WorkflowListArgs:
        return WorkflowListArgs(**self._raw_args)

    @property
    def workflow_delete_args(self) -> WorkflowDeleteArgs:
        return WorkflowDeleteArgs(**self._raw_args)

    @property
    def workflow_get_args(self) -> WorkflowGetArgs:
        return WorkflowGetArgs(**self._raw_args)

    @property
    def node_create_args(self) -> NodeCreateArgs:
        return NodeCreateArgs(**self._raw_args)

    @property
    def nodes_list_args(self) -> NodesListArgs:
        return NodesListArgs(**self._raw_args)

    @property
    def node_update_args(self) -> NodeUpdateArgs:
        return NodeUpdateArgs(**self._raw_args)

    @property
    def node_delete_args(self) -> NodeDeleteArgs:
        return NodeDeleteArgs(**self._raw_args)


# endregion

# region Main


def main() -> None:
    """
    Main entry point for the Magnet Automate integration.

    Initializes the execution configuration, client, and dispatches the command
    to the appropriate command function.
    """
    execution = MagnetAutomateExecutionConfig()
    command = execution.command
    demisto.debug(f"[Main] Starting to execute {command=}.")

    try:
        params = execution.params
        client = MagnetAutomateClient(params)

        match command:
            case "test-module":
                return_results(test_module(client))

            case "mf-automate-custom-fields-list":
                return_results(custom_fields_list_command(client, execution.custom_fields_list_args))

            case "mf-automate-case-create":
                return_results(case_create_command(client, execution.case_create_args))

            case "mf-automate-cases-list":
                return_results(cases_list_command(client, execution.cases_list_args))

            case "mf-automate-case-delete":
                return_results(case_delete_command(client, execution.case_delete_args))

            case "mf-automate-case-cancel":
                return_results(case_cancel_command(client, execution.case_cancel_args))

            case "mf-automate-workflow-run-start":
                return_results(workflow_run_start_command(client, execution.workflow_run_start_args))

            case "mf-automate-workflow-run-list":
                return_results(workflow_run_list_command(client, execution.workflow_run_list_args))

            case "mf-automate-workflow-run-delete":
                return_results(workflow_run_delete_command(client, execution.workflow_run_delete_args))

            case "mf-automate-workflow-run-cancel":
                return_results(workflow_run_cancel_command(client, execution.workflow_run_cancel_args))

            case "mf-automate-merge-workflow-run-start":
                return_results(merge_workflow_run_start_command(client, execution.merge_workflow_run_start_args))

            case "mf-automate-workflow-list":
                return_results(workflow_list_command(client, execution.workflow_list_args))

            case "mf-automate-workflow-delete":
                return_results(workflow_delete_command(client, execution.workflow_delete_args))

            case "mf-automate-workflow-get":
                return_results(workflow_get_command(client, execution.workflow_get_args))

            case "mf-automate-node-create":
                return_results(node_create_command(client, execution.node_create_args))

            case "mf-automate-nodes-list":
                return_results(nodes_list_command(client, execution.nodes_list_args))

            case "mf-automate-node-update":
                return_results(node_update_command(client, execution.node_update_args))

            case "mf-automate-node-delete":
                return_results(node_delete_command(client, execution.node_delete_args))

            case _:
                raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
