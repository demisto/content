from dataclasses import dataclass, asdict
from enum import StrEnum
from abc import ABC, abstractmethod
from collections import defaultdict

from CommonServerPython import *

""" CONSTANTS """
DEFAULT_TIMEOUT = 300


class Brands(StrEnum):
    """
    Enum representing different integration brands.
    """

    CORTEX_XDR_IR = "Cortex XDR - IR"
    CORTEX_CORE_IR = "Cortex Core - IR"
    MDE = "Microsoft Defender Advanced Threat Protection"

    @classmethod
    def values(cls):
        return [b.value for b in cls]

    @classmethod
    def normalize(cls, value: str):
        _ALIASES = {
            "Microsoft Defender ATP": "Microsoft Defender Advanced Threat Protection",
        }
        """Normalize a brand string (alias → canonical enum)."""
        canonical = _ALIASES.get(value, value)
        return canonical


""" DATA STRUCTURES """


class QuarantineException(Exception):
    """Custom exception for QuarantineFile errors."""


@dataclass
class QuarantineResult:
    """A structured object to hold the result of a quarantine action for a single endpoint."""

    EndpointID: str
    Status: str
    Message: str
    Brand: str
    FilePath: str
    FileHash: str

    class Statuses(StrEnum):
        SUCCESS = "Success"
        FAILED = "Failed"

    class Messages(StrEnum):
        """A namespace for standardized human-readable messages."""

        GENERAL_FAILURE = "Failed to quarantine file. See logs for more details."
        ALREADY_QUARANTINED = "Already quarantined."
        SUCCESS = "File successfully quarantined."
        ENDPOINT_OFFLINE = "Failed to quarantine file. The endpoint is offline or unreachable, please try again later."
        ENDPOINT_STATUS_UNKNOWN = "Failed to quarantine file. Endpoint status is '{status}'."
        ENDPOINT_NOT_FOUND = "Endpoint not found by any active integration, or the hash type does not match the integration."
        FAILED_WITH_REASON = "Failed to quarantine file. {reason}"

    @staticmethod
    def create(endpoint_id: str, status: str, message: str, brand: str, script_args: dict) -> "QuarantineResult":
        """
        Creates a QuarantineResult instance from script arguments and result data.

        This helper method simplifies the creation of result objects by populating
        common fields from the main script arguments.

        Args:
            endpoint_id (str): The unique identifier of the endpoint.
            status (str): The final status of the action (e.g., "Success", "Failed").
            message (str): A human-readable message describing the result.
            brand (str): The integration brand that performed the action.
            script_args (dict): The original arguments passed to the script.

        Returns:
            QuarantineResult: A new instance of the QuarantineResult class.
        """
        return QuarantineResult(
            EndpointID=endpoint_id,
            Status=status,
            Message=message,
            Brand=brand,
            FilePath=script_args.get(QuarantineOrchestrator.FILE_PATH_ARG, ""),
            FileHash=script_args.get(QuarantineOrchestrator.FILE_HASH_ARG, ""),
        )

    @staticmethod
    def to_context_entry(results_list: list) -> list[dict]:
        """
        Converts a list of QuarantineResult objects into a list of dictionaries.

        This is used to prepare the final results for storage in the incident context,
        which requires simple, serializable data types.

        Args:
            results_list (list): A list containing QuarantineResult objects and potentially dicts.

        Returns:
            list[dict]: A clean list of dictionaries.
        """
        context_ready_list = []
        for item in results_list:
            if isinstance(item, QuarantineResult):
                context_ready_list.append(asdict(item))
            elif isinstance(item, dict):
                context_ready_list.append(item)
        return context_ready_list


""" HELPER CLASSES & FUNCTIONS """


class Command:
    """Helper class for executing XSOAR commands and parsing their results."""

    def __init__(self, name: str, args: dict, brand: str | None = None) -> None:
        """
        Initializes a Command object.

        Args:
            name (str): The name of the command to execute (e.g., 'xdr-get-endpoint-details').
            args (dict): The arguments to pass to the command.
            brand (str | None): The specific integration brand to use for execution.
                                If None, uses the default or first available integration.
        """
        self.brand: str | None = brand
        self.name: str = name
        self.args: dict = args

    def execute(self) -> tuple[list, list[CommandResults]]:
        """
        Executes the command via demisto.executeCommand and handles the response.

        This method wraps the command execution, checks for errors in the response,
        and separates the raw API response from the verbose, human-readable results.

        Returns:
            tuple[list, list[CommandResults]]: A tuple containing:
                - The raw response list from demisto.executeCommand.
                - A list of CommandResults objects for verbose output.

        Raises:
            QuarantineException: If the command execution returns an error entry.
        """
        demisto.debug(f"[Command] Executing: '{self.name}' with args: {self.args} for brand: {self.brand}")
        raw_response = demisto.executeCommand(self.name, self.args)

        verbose_results = []
        for result in raw_response:
            if is_error(result):
                demisto.error(f"Error executing {self.name}:\n{get_error(result)}")
                hr = f"Error executing {self.name}:\n{get_error(result)}"
            else:
                hr = result.get("HumanReadable", f"Successfully executed {self.name}")
            verbose_results.append(CommandResults(readable_output=hr))

        return raw_response, verbose_results

    @staticmethod
    def get_entry_contexts(raw_response: list) -> list[dict]:
        """
        Safely extracts all EntryContext objects from a raw command response.

        It iterates through all entries in a command's raw response and collects
        any populated EntryContext objects into a single list.

        Args:
            raw_response (list): The raw list of results from a command execution.

        Returns:
            list[dict]: A list containing all non-empty entry context objects from the response.
        """
        entry_contexts: list[dict] = []
        for result in raw_response:
            if is_error(result):
                continue

            # The EntryContext can be None or an empty dict/list. We only want populated ones.
            if entry_context_item := result.get("EntryContext"):
                if not entry_context_item:
                    continue

                entry_contexts.append(entry_context_item)

        return entry_contexts

    @staticmethod
    def get_entry_context_object_containing_key(raw_response: list, key: str) -> Any:
        """
        Get the first EntryContext object containing a specific key.

        It iterates through all entries in a command's raw response and collects
        any populated EntryContext objects into a single list.

        Args:
            raw_response (list): The raw list of results from a command execution.
            key (str): The key to look for in the EntryContext.

        Returns:
            dict/list/None: The object containing the key, or None if not found.
        """

        entry_contexts = Command.get_entry_contexts(raw_response)
        demisto.debug(
            f"[Command] Getting entry context object containing key '{key}'. From {len(entry_contexts)} entry contexts."
        )

        for entry_context in entry_contexts:
            for entry_context_key, entry_context_value in entry_context.items():
                if key in entry_context_key:
                    return entry_context_value

        demisto.debug(f"[Command] Key '{key}' not found in any entry context.")
        return None


class EndpointBrandMapper:
    """
    Handles the discovery and grouping of endpoints by their managing brand.

    This class runs 'get-endpoint-data' to determine which security product
    (e.g., 'Cortex XDR - IR') is responsible for each target endpoint. It also
    filters out offline or undiscoverable endpoints.
    """

    def __init__(self, script_args: dict, orchestrator):
        """
        Initializes the EndpointBrandMapper.

        Args:
            script_args (dict): The original arguments passed to the script.
            orchestrator (QuarantineOrchestrator): The orchestrator instance for accessing shared properties.
        """
        self.script_args = script_args
        self.orchestrator = orchestrator
        self.endpoint_ids_to_map = argToList(script_args.get(QuarantineOrchestrator.ENDPOINT_IDS_ARG))
        self.initial_results: list[QuarantineResult] = []

    def group_by_brand(self) -> dict[str, list]:
        """
        Groups online endpoints by their managing brand using 'get-endpoint-data'.

        This is the main public method of the class. It orchestrates the fetching
        and filtering of endpoint data to produce a clean mapping of brands to the
        online endpoints they manage.

        Returns:
            dict[str, list]: A dictionary mapping each brand name to a list of its
                             online endpoint IDs. Example: {'Cortex XDR - IR': ['id1', 'id2']}.

                             An empty dictionary is returned if no online endpoints are found.

        Raises:
            QuarantineException: If get-endpoint-data fails to retrieve endpoint data.
        """

        endpoint_data = self._fetch_endpoint_data()
        if not endpoint_data:
            demisto.debug("[EndpointBrandMapper] No endpoint data found, will not quarantine.")
            for endpoint_id in self.endpoint_ids_to_map:
                self.initial_results.append(
                    QuarantineResult.create(
                        endpoint_id=endpoint_id,
                        status=QuarantineResult.Statuses.FAILED,
                        message=QuarantineResult.Messages.ENDPOINT_NOT_FOUND,
                        brand="Unknown",
                        script_args=self.script_args,
                    )
                )
            raise QuarantineException("Could not retrieve endpoint data.")

        online_endpoints = self._filter_endpoint_data(endpoint_data)
        if not online_endpoints:
            demisto.debug("[EndpointBrandMapper] No online endpoints found. Not running quarantine.")
            return {}

        grouped_endpoints: dict[str, list] = defaultdict(list)
        for endpoint_id, brand in online_endpoints.items():
            grouped_endpoints[brand].append(endpoint_id)

        return grouped_endpoints

    def _fetch_endpoint_data(self) -> list:
        """
        Makes a single, efficient call to 'get-endpoint-data' for all target endpoints.

        Returns:
            list: The list of endpoint data objects from the command's entry context.
                  Returns an empty list if no data is found.
        """

        demisto.debug(
            f"[EndpointBrandMapper] Querying get-endpoint-data limited to brands: "
            f"{self.script_args.get(QuarantineOrchestrator.BRANDS_ARG)}"
        )
        command_args = {
            "endpoint_id": self.endpoint_ids_to_map,
            "brands": self.script_args.get(QuarantineOrchestrator.BRANDS_ARG),
        }

        cmd = Command(name="get-endpoint-data", args=command_args)
        raw_response, verbose_res = cmd.execute()

        if self.orchestrator.verbose:
            self.orchestrator.verbose_results.extend(verbose_res)

        endpoint_data: list = Command.get_entry_context_object_containing_key(raw_response, "EndpointData")

        return endpoint_data

    def _filter_endpoint_data(self, endpoint_data: list) -> dict:
        """
        Parses endpoint data to identify online endpoints and create failure results for others.

        This method processes the raw data from `_fetch_endpoint_data`. It prioritizes
        'Online' endpoints and handles duplicates. For any endpoint that is found but is
        not online, or not found at all, it generates an appropriate `QuarantineResult`
        and adds it to `self.initial_results`.

        Args:
            endpoint_data (list): A list of endpoint data objects from the API.

        Returns:
            dict: A dictionary mapping online endpoint IDs to their brand.
        """
        online_endpoints = {}
        all_found_ids = set()
        demisto.debug(f"[EndpointBrandMapper] Filtering data: {endpoint_data}")

        # First pass: find all successful, online endpoints. These take precedence.
        for result in endpoint_data:
            if not (endpoint_id := result.get("ID")) or endpoint_id in online_endpoints:
                continue

            if result.get("Message") == "Command successful" and result.get("Status") == "Online":
                online_endpoints[endpoint_id] = Brands.normalize(result.get("Brand"))

        # Second pass: Create failure results for any endpoint that was not found or offline.
        for result in endpoint_data:
            if not (endpoint_id := result.get("ID")) or endpoint_id in all_found_ids:
                continue

            all_found_ids.add(endpoint_id)

            # Skip endpoints that were found as 'Online'
            if endpoint_id in online_endpoints:
                continue

            if result.get("Message") == "Command successful":
                message = QuarantineResult.Messages.ENDPOINT_STATUS_UNKNOWN.format(status=result.get("Status", "Unknown"))
            else:  # Message is not 'Command successful', i.e. "Command failed - no endpoint found"
                get_endpoint_status_message = result.get("Message", QuarantineResult.Messages.ENDPOINT_OFFLINE)
                message = QuarantineResult.Messages.FAILED_WITH_REASON.format(reason=get_endpoint_status_message)

            self.initial_results.append(
                QuarantineResult.create(
                    endpoint_id=endpoint_id,
                    status=QuarantineResult.Statuses.FAILED,
                    message=message,
                    brand=Brands.normalize(result.get("Brand", "Unknown")),
                    script_args=self.script_args,
                )
            )

        unprocessed_ids = [eid for eid in self.endpoint_ids_to_map if eid not in all_found_ids]
        if unprocessed_ids:
            demisto.error(
                f"[EndpointBrandMapper] Error in get-endpoint-data command. "
                f"Endpoints not found in any the response: {unprocessed_ids}"
            )
            for endpoint_id in unprocessed_ids:
                self.initial_results.append(
                    QuarantineResult.create(
                        endpoint_id=endpoint_id,
                        status=QuarantineResult.Statuses.FAILED,
                        message=QuarantineResult.Messages.ENDPOINT_NOT_FOUND,
                        brand="Unknown",
                        script_args=self.script_args,
                    )
                )

        demisto.debug(f"[EndpointBrandMapper] Processing complete. Found {len(online_endpoints)} online endpoints.")
        return online_endpoints


""" BRAND HANDLER INTERFACE & FACTORY """


class BrandHandler(ABC):
    """Abstract base class (Interface) for all brand-specific handlers."""

    def __init__(self, brand: str, orchestrator):
        """
        Initializes the BrandHandler.

        Args:
            brand (str): The name of the brand this handler is responsible for.
            orchestrator (QuarantineOrchestrator): The orchestrator instance.
        """
        self.brand = brand
        self.orchestrator = orchestrator

    @abstractmethod
    def validate_args(self, args: dict) -> None:
        """
        Validates that all required arguments for this brand are present.
        """

    @abstractmethod
    def initiate_quarantine(self, args: dict) -> dict:
        """
        Initiates the quarantine action for the brand and returns a polling job object.
        """

    @abstractmethod
    def finalize(self, last_poll_response: list) -> list[QuarantineResult]:
        """
        Processes the final results of a completed polling job for the brand.
        """


class XDRHandler(BrandHandler):
    """Concrete handler for Cortex XDR and Cortex Core quarantine actions."""

    CORE_COMMAND_PREFIX = "core"
    XDR_COMMAND_PREFIX = "xdr"
    QUARANTINE_STATUS_COMMAND = "get-quarantine-status"
    QUARANTINE_STATUS_SUCCESS = "COMPLETED_SUCCESSFULLY"

    def __init__(self, brand: str, orchestrator):
        """
        Initializes the XDRHandler.

        Args:
            brand (str): The brand name ('Cortex XDR - IR' or 'Cortex Core - IR').
            orchestrator (QuarantineOrchestrator): The main orchestrator instance.
        """
        super().__init__(brand, orchestrator)
        self.command_prefix = self.CORE_COMMAND_PREFIX if self.brand == Brands.CORTEX_CORE_IR else self.XDR_COMMAND_PREFIX
        self.quarantine_command = (
            "core-quarantine-files" if self.command_prefix == self.CORE_COMMAND_PREFIX else "xdr-file-quarantine"
        )

    def validate_args(self, args: dict) -> None:
        """
        Validates that the 'file_path' argument is provided for XDR actions.

        Args:
            args (dict): The script arguments.

        Raises:
            ValueError: If the 'file_path' argument is missing.
        """
        demisto.debug(f"[{self.brand} Handler] Validating args.")
        if not args.get(QuarantineOrchestrator.FILE_PATH_ARG):
            raise QuarantineException(
                f"The '{QuarantineOrchestrator.FILE_PATH_ARG}' argument is required for brand {self.brand}."
            )

    def _execute_quarantine_status_command(self, endpoint_id: str, file_hash: str, file_path: str) -> dict:
        """
        Checks if a file is already quarantined on a specific endpoint.

        Args:
            endpoint_id (str): The ID of the endpoint to check.
            file_hash (str): The SHA256 hash of the file.
            file_path (str): The path of the file on the endpoint.

        Returns:
            dict: The response from the 'get-quarantine-status' command.
                  Example:
                      {
                          'endpointId': 'EP_ID',
                          'fileHash': 'sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256',
                          'filePath': '/PATH/TO/FILE/ON/ENDPOINT/TO/QUARANTINE',
                          'status': False if not quarantined, True if quarantined
                      }
        """
        demisto.debug(f"[{self.brand} Handler] Checking quarantine status for endpoint {endpoint_id}.")
        status_cmd = Command(
            name=f"{self.command_prefix}-{XDRHandler.QUARANTINE_STATUS_COMMAND}",
            args={"endpoint_id": endpoint_id, "file_hash": file_hash, "file_path": file_path},
            brand=self.brand,
        )
        raw_response, verbose_res = status_cmd.execute()
        if self.orchestrator.verbose:
            self.orchestrator.verbose_results.extend(verbose_res)

        status_context = Command.get_entry_contexts(raw_response)
        if not status_context or not isinstance(status_context[0], dict):
            return {}

        return list(status_context[0].values())[0]

    def _process_final_endpoint_status(self, endpoint_result: dict) -> QuarantineResult:
        """
        Processes the final result for a single endpoint from a completed polling job.

        If the initial quarantine action was successful, this method makes a second,
        separate call to 'get-quarantine-status' to get the true final result.

        Args:
            endpoint_result (dict): The result object for a single endpoint from the polling command.
                                    Example: {'action_id': 123, 'endpoint_id': 'EP_ID', 'status': 'COMPLETED_SUCCESSFULLY'}

        Returns:
            QuarantineResult: A structured result object for the endpoint.
        """
        endpoint_id = str(endpoint_result.get("endpoint_id"))
        demisto.debug(f"[{self.brand} Handler] Processing final status for endpoint {endpoint_id}.")

        if endpoint_result.get("status") == XDRHandler.QUARANTINE_STATUS_SUCCESS:
            quarantine_status_data = self._execute_quarantine_status_command(
                endpoint_id,
                self.orchestrator.args.get(QuarantineOrchestrator.FILE_HASH_ARG),
                self.orchestrator.args.get(QuarantineOrchestrator.FILE_PATH_ARG),
            )
            quarantine_status = quarantine_status_data.get("status")

            message = (
                QuarantineResult.Messages.SUCCESS
                if quarantine_status
                else QuarantineResult.Messages.FAILED_WITH_REASON.format(
                    reason=quarantine_status_data.get("error_description", "")
                )
            )
            status = QuarantineResult.Statuses.SUCCESS if quarantine_status else QuarantineResult.Statuses.FAILED
            demisto.debug(f"[{self.brand} Handler] Final status for {endpoint_id}: {status}")
        else:
            message = QuarantineResult.Messages.FAILED_WITH_REASON.format(reason=endpoint_result.get("error_description", ""))
            status = QuarantineResult.Statuses.FAILED
            demisto.debug(f"[{self.brand} Handler] Quarantine action failed for {endpoint_id}. Reason: {message}")

        return QuarantineResult.create(
            endpoint_id=endpoint_id, status=status, message=message, brand=self.brand, script_args=self.orchestrator.args
        )

    def initiate_quarantine(self, args: dict) -> dict:
        """
        Initiates the quarantine action for a list of XDR endpoints.

        This method calls the appropriate quarantine command ('core-quarantine-files' or
        'xdr-file-quarantine') and constructs a job object for polling.

        Args:
            args (dict): The script arguments, including the list of endpoint IDs to action.

        Returns:
            dict: A job object containing metadata required for polling.
                  The poll_command and poll_args fields are populated based on the Metadata returned from the PollResult response.
                  Examples:
                      {
                          "brand": "Cortex XDR - IR",
                          "poll_command": "core-get-quarantine-status",
                          "poll_args": {
                              "action_id": [6],
                              "endpoint_id": "endpoint_id",
                              "endpoint_id_list": ["endpoint_id"],
                              "file_hash": "file_hash",
                              "file_path": "file_path",
                              "integration_context_brand": "Core",
                              "integration_name": "Cortex Core - IR",
                              "interval_in_seconds": 60,
                              "timeout_in_seconds": "300"
                          },
                          "finalize_args": {
                              "file_hash": "file_hash",
                              "file_path": "file_path"
                          }
                      }

        Raises:
            QuarantineException: If the initial quarantine command fails.
        """
        demisto.debug(f"[{self.brand} Handler] Initiating quarantine action.")

        quarantine_args = {
            "endpoint_id_list": args.get(QuarantineOrchestrator.ENDPOINT_IDS_ARG),
            "file_hash": args.get(QuarantineOrchestrator.FILE_HASH_ARG),
            "file_path": args.get(QuarantineOrchestrator.FILE_PATH_ARG),
            "timeout_in_seconds": args.get("timeout", DEFAULT_TIMEOUT),
        }

        cmd = Command(name=self.quarantine_command, args=quarantine_args, brand=self.brand)
        raw_response, verbose_res = cmd.execute()
        if self.orchestrator.verbose:
            self.orchestrator.verbose_results.extend(verbose_res)

        metadata = raw_response[0].get("Metadata", {})
        demisto.debug(f"[{self.brand} Handler] Received metadata for polling: {metadata}")

        job = {
            "brand": self.brand,
            "poll_command": metadata.get("pollingCommand", self.quarantine_command),
            "poll_args": metadata.get("pollingArgs", {}),
            "finalize_args": {
                "file_hash": args.get(QuarantineOrchestrator.FILE_HASH_ARG),
                "file_path": args.get(QuarantineOrchestrator.FILE_PATH_ARG),
            },
        }
        return job

    def finalize(self, last_poll_response: list) -> list[QuarantineResult]:
        """
        Finalizes a completed quarantine job for the XDR brand.

        It parses the results from the last polling response and calls
        `_process_final_endpoint_status` for each endpoint to determine the
        definitive outcome.

        Args:
            last_poll_response (list): The raw response from the final polling command.

        Returns:
            list[QuarantineResult]: A list of final QuarantineResult objects.
        """
        final_results = []

        quarantine_endpoints_final_results: list = Command.get_entry_context_object_containing_key(
            last_poll_response, "GetActionStatus"
        )

        demisto.debug(f"[{self.brand} Handler] Finalizing endpoint results from job.")
        for quarantine_endpoint_result in quarantine_endpoints_final_results:
            try:
                final_results.append(self._process_final_endpoint_status(quarantine_endpoint_result))
            except Exception as e:
                demisto.error(
                    f"[{self.brand} Handler] Failed to get status of quarantine for endpoint:"
                    f" {quarantine_endpoint_result.get('endpoint_id')}: {e}"
                )
                final_results.append(
                    QuarantineResult.create(
                        endpoint_id=quarantine_endpoint_result.get("endpoint_id", "Unknown"),
                        status=QuarantineResult.Statuses.FAILED,
                        message=QuarantineResult.Messages.GENERAL_FAILURE,
                        brand=self.brand,
                        script_args=self.orchestrator.args,
                    )
                )
        return final_results


class MDEHandler(BrandHandler):
    """Handler for Microsoft Defender Advanced Threat Protection quarantine operation"""

    QUARANTINE_STATUS_SUCCESS = "Succeeded"
    QUARANTINE_COMMAND = "microsoft-atp-stop-and-quarantine-file"

    def __init__(self, orchestrator):
        """
        Initializes the MDEHandler.

        Args:
            orchestrator (QuarantineOrchestrator): The main orchestrator instance.
        """
        super().__init__(Brands.MDE, orchestrator)

    def validate_args(self, args: dict) -> None:
        return

    def initiate_quarantine(self, args: dict):
        """
        Initiates the quarantine action for a list of MDE endpoints.

        This method calls the appropriate MDE quarantine command (microsoft-atp-stop-and-quarantine-file)
        and constructs a job object for polling.

        Args:
            args (dict): The script arguments, including the list of endpoint IDs to action.

        Returns:
            dict: A job object containing metadata required for polling.
                  The poll_command and poll_args fields are populated based on the Metadata returned from the PollResult response.
                  Example:
                      {
                          "poll_command": "microsoft-atp-stop-and-quarantine-file",
                          "poll_args": {
                              "action_ids": ["111111"],
                              "machine_id": ["22222", "33333"],
                              "file_hash": "sha1sha1",
                              "timeout_in_seconds" : "300"
                          },
                      }

        Raises:
            QuarantineException: If the initial quarantine command fails.
        """
        demisto.debug(f"[{self.brand} Handler] Initiating quarantine action.")

        quarantine_args = {
            "machine_id": args.get(QuarantineOrchestrator.ENDPOINT_IDS_ARG),
            "file_hash": args.get(QuarantineOrchestrator.FILE_HASH_ARG),
            "comment": f"Quarantine file hash: {args.get(QuarantineOrchestrator.FILE_HASH_ARG)}",
            "timeout_in_seconds": args.get("timeout", DEFAULT_TIMEOUT),
            "polling": True,
        }

        cmd = Command(name=MDEHandler.QUARANTINE_COMMAND, args=quarantine_args, brand=self.brand)
        raw_response, verbose_res = cmd.execute()

        if self.orchestrator.verbose:
            self.orchestrator.verbose_results.extend(verbose_res)

        quarantine_kick_off_results: list = Command.get_entry_context_object_containing_key(raw_response, "MachineAction")

        demisto.debug(f"[MDE Handler] Quarantine Kick Off Results: {quarantine_kick_off_results}")

        if not quarantine_kick_off_results:
            raise QuarantineException("Failed to initiate quarantine.")

        pending_jobs = False
        # Iterate over kick-off response to check if any/all jobs have completed.
        for quarantine_endpoint_result in quarantine_kick_off_results:
            status = quarantine_endpoint_result.get("Status", "Unknown")
            message = QuarantineResult.Messages.SUCCESS if status == "Succeeded" else QuarantineResult.Messages.GENERAL_FAILURE
            if status in ["Succeeded", "Failed", "Cancelled", "TimeOut"]:
                self.orchestrator.completed_results.append(
                    QuarantineResult.create(
                        endpoint_id=quarantine_endpoint_result.get("MachineID", "Unknown"),
                        status=quarantine_endpoint_result.get("Status", "Unknown"),
                        message=message,
                        brand=self.brand,
                        script_args=self.orchestrator.args,
                    )
                )
            else:
                pending_jobs = True

        if not pending_jobs:
            return None

        metadata = raw_response[0].get("Metadata", {})
        demisto.debug(f"[MDEHandler] Returned Metadata from MDE Quarantine Kickoff: {metadata}")

        job = {
            "brand": self.brand,
            "poll_command": metadata.get("pollingCommand", MDEHandler.QUARANTINE_COMMAND),
            "poll_args": metadata.get("pollingArgs", {}),
        }

        if not job.get("poll_command") or not job.get("poll_args"):
            raise QuarantineException("Failed to initiate quarantine.")

        demisto.debug(f"[{self.brand} Handler] Created new polling job object: {job}")
        return job

    def finalize(self, last_poll_response: list):
        """
        Finalizes a completed quarantine job for the MDE brand.

        It parses the results from the last polling response and calls

        Args:
            last_poll_response (list):
                The raw response from the final polling command.
                Example:
                   [{ 'EntryContext': {
                   'MicrosoftATP.MachineAction(val.ID && val.ID == obj.ID)':
                      [
                       {
                       'Commands': None, 'ComputerDNSName': 'win10',
                       'CreationDateTimeUtc': '2025-09-04T15:54:42.3940602Z',
                       'ID': '867a0014-12c1-4445-b3b5-c001eea7db4d',
                       'LastUpdateTimeUtc': '2025-09-04T15:55:08.1123822Z',
                       'MachineID': '123',
                       'RelatedFileInfo':
                           {'FileIdentifier': 'sha1sha1',
                            'FileIdentifierType': 'Sha1'},
                        'Requestor': 'Cortex XSOAR - Microsoft Defender ATP',
                        'RequestorComment': 'Quarantine file hash: sha1sha1',
                        'Scope': None, 'Status': 'Succeeded', 'Type': 'StopAndQuarantineFile'
                        }]}}]

        Returns:
            list[QuarantineResult]: A list of final QuarantineResult objects.
        """
        final_results = []
        quarantine_endpoints_final_results: list = Command.get_entry_context_object_containing_key(
            last_poll_response, "MachineAction"
        )

        demisto.debug(f"[{self.brand} Handler] Finalizing endpoint results from job.")
        for quarantine_endpoint_result in quarantine_endpoints_final_results:
            final_results.append(
                QuarantineResult.create(
                    endpoint_id=quarantine_endpoint_result.get("MachineID", "Unknown"),
                    status=quarantine_endpoint_result.get("Status", "Unknown"),
                    message=QuarantineResult.Messages.SUCCESS,
                    brand=self.brand,
                    script_args=self.orchestrator.args,
                )
            )
        return final_results


def handler_factory(brand: str, orchestrator) -> BrandHandler:
    """
    Factory function that returns an instance of the correct brand handler.

    This allows the orchestrator to dynamically select the appropriate logic
    based on the brand name discovered for a group of endpoints.

    Args:
        brand (str): The name of the brand.
        orchestrator (QuarantineOrchestrator): The orchestrator instance.

    Returns:
        BrandHandler: An instance of a concrete BrandHandler subclass (e.g., XDRHandler).

    Raises:
        ValueError: If no handler is available for the specified brand.
    """
    demisto.debug(f"[Factory] Creating handler for brand: '{brand}'")
    if brand in [Brands.CORTEX_CORE_IR, Brands.CORTEX_XDR_IR]:
        return XDRHandler(brand, orchestrator)
    elif brand == Brands.MDE:
        return MDEHandler(orchestrator)
    else:
        raise QuarantineException(f"No handler available for brand: {brand}")


""" SCRIPT ORCHESTRATOR """


class QuarantineOrchestrator:
    """Manages the entire quarantine lifecycle from start to finish."""

    ENDPOINT_IDS_ARG = "endpoint_id"
    FILE_HASH_ARG = "file_hash"
    FILE_PATH_ARG = "file_path"
    BRANDS_ARG = "brands"

    HASH_TYPE_TO_BRANDS = {"sha256": [Brands.CORTEX_CORE_IR, Brands.CORTEX_XDR_IR], "sha1": [Brands.MDE]}

    def __init__(self, args: dict):
        """
        Initializes the QuarantineOrchestrator.

        This involves loading the current state (pending jobs and completed results)
        from the given args to support polling.

        Args:
            args (dict): The arguments passed to the script.
        """
        demisto.debug("[Orchestrator] Initializing.")
        self.args = args
        self.verbose = argToBoolean(args.get("verbose", False))
        self.verbose_results: list[CommandResults] = []

        # load pending jobs if they exist from kick-off
        self.pending_jobs = argToList(args.get("pending_jobs", []))
        # Load completed jobs if they exist from kick-off
        self.completed_results: list[QuarantineResult] = [
            QuarantineResult(**res) for res in (argToList(args.get("completed_results", [])))
        ]
        demisto.debug(
            f"[Orchestrator] Loaded state. Pending jobs: {len(self.pending_jobs)}, "
            f"Completed results: {len(self.completed_results)}"
        )
        demisto.debug(f"[Orchestrator] Loaded pending jobs: {self.pending_jobs}")
        demisto.debug(f"[Orchestrator] Loaded completed results: {self.completed_results}")

    def _verify_and_dedup_endpoint_ids(self):
        """
        Verifies that endpoint IDs are provided and removes duplicates.

        Returns:
            list: A list of unique endpoint IDs.

        Raises:
            QuarantineException: If the 'endpoint_id' argument is missing.
        """
        if not self.args.get(self.ENDPOINT_IDS_ARG):
            raise QuarantineException(f"Missing required argument: '{self.ENDPOINT_IDS_ARG}'.")

        given_ids = argToList(self.args.get(self.ENDPOINT_IDS_ARG))
        unique_ids = set(given_ids)

        return list(unique_ids)

    def _verify_and_get_valid_brands(self):
        """
        Verifies the 'brands' argument and filters for active integrations.

        It determines the final list of brands to run actions on by intersecting the
        user-provided brands (or all valid brands if none are provided) with the
        set of currently enabled integration instances.

        Returns:
            list: A list of brand names that are both valid and have an active instance.

        Raises:
            QuarantineException: If an invalid brand is specified or no valid, enabled
                              integrations are found.
        """
        user_given_brands: list = argToList(self.args.get(QuarantineOrchestrator.BRANDS_ARG))

        # Verify if brands are given, that they are ALL valid
        for brand in user_given_brands:
            if brand not in Brands.values():
                raise QuarantineException(f"Invalid brand: {brand}. Valid brands are: {Brands.values()}")

        enabled_brands = {module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"}
        demisto.debug(f"Enabled brands are: {enabled_brands}")
        brands_to_consider = set(user_given_brands) if user_given_brands else set(Brands.values())

        # The final list of brands to run on is the intersection of the brands we
        # should consider and the brands that are actually enabled.
        brands_to_run = list(brands_to_consider.intersection(enabled_brands))

        if not brands_to_run:
            raise QuarantineException(
                f"None of the brands: {brands_to_consider} have an enabled integration instance. "
                f"Ensure valid integration IDs are specified, and that the integrations are enabled."
            )

        demisto.debug(f"Final list of brands to run actions on: {brands_to_run}")
        return brands_to_run

    def _verify_file_hash(self, brands_to_run):
        """
        Verifies that a file hash is provided and that its type is supported by the target brands.

        Args:
            brands_to_run (list): The list of active brands that will be used.

        Returns:
            list: The list of brands to run actions on, after removing brands that do not support the file hash type.

        Raises:
            QuarantineException: If the hash argument is missing, the hash type is unsupported,
                              or no enabled integration supports the given hash type.
        """
        if not self.args.get(self.FILE_HASH_ARG):
            raise QuarantineException(f"Missing required argument. Please provide '{self.FILE_HASH_ARG}'.")

        hash_type = get_hash_type(self.args.get(self.FILE_HASH_ARG)).lower()
        supported_brands_for_hash = self.HASH_TYPE_TO_BRANDS.get(hash_type)
        demisto.debug(f"brands to run are: {brands_to_run}")

        if not supported_brands_for_hash:
            raise QuarantineException(
                f"Unsupported hash type: {hash_type}. Supported types are: {', '.join(self.HASH_TYPE_TO_BRANDS.keys())}"
            )

        if not any(brand in brands_to_run for brand in supported_brands_for_hash):
            raise QuarantineException(
                "Could not find enabled integrations for the requested hash type.\n"
                f"For hash_type {hash_type.upper()} please use one of the following brands: "
                f"{', '.join(supported_brands_for_hash)}"
            )

        # Return only the list of brands that both support the given hash type
        # and are included in the specified set of brands to run.
        return list(set(brands_to_run).intersection(supported_brands_for_hash))

    def _sanitize_and_validate_args(self):
        """
        Performs all upfront argument validation and sanitization.

        This method orchestrates the various verification checks to ensure the script
        is running with valid and clean inputs before any actions are taken.

        Raises:
            QuarantineException: If any validation check fails.
        """
        demisto.debug("[Orchestrator] Sanitizing and validating script arguments.")

        unique_ids = self._verify_and_dedup_endpoint_ids()
        self.args[self.ENDPOINT_IDS_ARG] = unique_ids

        brands_to_run = self._verify_and_get_valid_brands()
        self.args[QuarantineOrchestrator.BRANDS_ARG] = brands_to_run

        brands_to_run = self._verify_file_hash(brands_to_run)
        self.args[QuarantineOrchestrator.BRANDS_ARG] = brands_to_run

        demisto.debug("[Orchestrator] Finished sanitizing and validating script arguments.")

    def _is_first_run(self) -> bool:
        """
        Determines if this is the first execution of the script for this task.

        Returns:
            bool: True if there are no pending jobs in the args, False otherwise.
        """

        return not argToList(self.args.get("pending_jobs", []))

    def _job_is_still_polling(self, metadata: dict) -> bool:
        """
        Checks the metadata from a command response to see if polling should continue.

        Args:
            metadata (dict): The 'Metadata' dictionary from a command's raw response.

        Returns:
            bool: True if the 'polling' flag in the metadata is set to True, False otherwise.
        """
        return metadata.get("polling") is True

    def run(self) -> PollResult:
        """
        The main execution method for the orchestrator.

        It determines if this is the first run or a polling run and calls the
        appropriate methods (`_initiate_jobs` or `_check_pending_jobs`). At the end
        of each cycle, it saves state and returns a PollResult to the XSOAR server.

        Returns:
            PollResult: An object indicating whether to continue polling or to finish
                        and display final results.
        """
        demisto.debug("[Orchestrator] Starting run.")

        if self._is_first_run():
            demisto.debug("[Orchestrator] Detected first run.")
            try:
                self._sanitize_and_validate_args()
            except Exception as e:
                self.completed_results = []
                demisto.debug("[Orchestrator] Failed to sanitize and validate script arguments. Failing the script")
                for endpoint_id in argToList(self.args.get(self.ENDPOINT_IDS_ARG)):
                    self.completed_results.append(
                        QuarantineResult.create(
                            endpoint_id,
                            QuarantineResult.Statuses.FAILED,
                            QuarantineResult.Messages.FAILED_WITH_REASON.format(reason=str(e)),
                            "Unknown",
                            {
                                self.FILE_PATH_ARG: self.args.get(self.FILE_PATH_ARG),
                                self.FILE_HASH_ARG: self.args.get(self.FILE_HASH_ARG),
                            },
                        )
                    )

                return self._get_final_results(fatal_error_msg=str(e))
            self._initiate_jobs()
        else:
            demisto.debug("[Orchestrator] Detected polling run.")
            self._check_pending_jobs()

        # After work is done, decide whether to continue polling or finish.
        if self.pending_jobs:
            demisto.debug(f"[Orchestrator] {len(self.pending_jobs)} jobs still pending. Saving state and scheduling next poll.")

            if self._is_first_run() and self.completed_results:
                demisto.debug("Returning the failed quarantine operations from the kick-off stage to war room")
                demisto.debug(f"The failed results being returned are: {self.completed_results}")
                hr = tableToMarkdown(
                    name=f"Unable to Quarantine the file hash: {self.args.get(self.FILE_HASH_ARG)} "
                    f"for the following endpoints:",
                    headers=["EndpointID", "Status", "Message", "Brand"],
                    t=QuarantineResult.to_context_entry(self.completed_results),
                    removeNull=True,
                )
                interim_results = CommandResults(
                    outputs_prefix="QuarantineFile",
                    outputs_key_field=["EndpointID", "FilePath", "FileHash"],
                    readable_output=hr,
                    outputs=QuarantineResult.to_context_entry(self.completed_results),
                )
                return_results(interim_results)

            interim_results = CommandResults(readable_output="Quarantine operations are still in progress...")
            args_for_next_run = {
                "pending_jobs": self.pending_jobs,
                "completed_results": QuarantineResult.to_context_entry(self.completed_results),
                **self.args,
            }
            demisto.debug(f"[Orchestrator] Initiating polling with args: {args_for_next_run}")

            return PollResult(
                response=interim_results,
                continue_to_poll=True,
                args_for_next_run=args_for_next_run,
                partial_result=interim_results,
            )
        else:
            demisto.debug("[Orchestrator] No pending jobs remain. Finishing.")
            return self._get_final_results()

    def _initiate_jobs(self):
        """
        Handles the first run logic: maps endpoints to brands and initiates actions.

        It uses the EndpointBrandMapper to discover and group endpoints, then calls
        `_execute_quarantine_for_brand` for each discovered brand.
        """
        demisto.debug("[Orchestrator] Initiating jobs.")
        mapper = EndpointBrandMapper(self.args, self)

        try:
            grouped_endpoints_by_brand = mapper.group_by_brand()
            self.completed_results.extend(mapper.initial_results)
        except Exception as e:
            demisto.error(f"[Orchestrator] Critical error during endpoint mapping, skipping quarantine operations {e}")
            self.completed_results.extend(mapper.initial_results)
            return

        demisto.debug(f"[Orchestrator] Executing quarantine for endpoints: {grouped_endpoints_by_brand.keys()}")
        for brand, endpoint_ids in grouped_endpoints_by_brand.items():
            self._execute_quarantine_for_brand(brand, endpoint_ids)

    def _execute_quarantine_for_brand(self, brand: str, endpoint_ids: list):
        """
        Handles the entire "first run" logic for a single group of endpoints.

        It gets the correct handler for the brand, validates arguments, runs pre-checks,
        and initiates the quarantine action, creating a new pending job if necessary.

        Args:
            brand (str): The brand to process.
            endpoint_ids (list): The list of endpoint IDs for this brand.
        """
        demisto.debug(f"[Orchestrator] Processing {len(endpoint_ids)} endpoints for brand '{brand}'.")
        try:
            handler = handler_factory(brand, self)
            brand_args = self.args.copy()
            brand_args[self.ENDPOINT_IDS_ARG] = endpoint_ids
            handler.validate_args(brand_args)

            if endpoint_ids:
                demisto.debug(f"[Orchestrator] {len(endpoint_ids)} endpoints for '{brand}' need quarantine action.")
                initiate_args = self.args.copy()
                initiate_args[self.ENDPOINT_IDS_ARG] = endpoint_ids
                new_job = handler.initiate_quarantine(initiate_args)
                if new_job:
                    self.pending_jobs.append(new_job)
            return
        except QuarantineException as e:
            demisto.error(f"Failed to process endpoints for brand '{brand}': {e}")
            error_msg = QuarantineResult.Messages.FAILED_WITH_REASON.format(reason=e)
        except Exception as e:
            demisto.error(f"Failed to process endpoints for brand '{brand}': {e}")
            error_msg = QuarantineResult.Messages.GENERAL_FAILURE

        for endpoint_id in endpoint_ids:
            self.completed_results.append(
                QuarantineResult.create(
                    endpoint_id=endpoint_id,
                    status=QuarantineResult.Statuses.FAILED,
                    message=error_msg,
                    brand=brand,
                    script_args=self.args,
                )
            )

    def _check_pending_jobs(self):
        """
        Handles a polling run: checks the status of all pending jobs.

        For each job, it executes the polling command. If the job is still running,
        it is kept in the pending list. If it has finished, it is finalized, and
        the results are collected.
        """
        demisto.debug(f"[Orchestrator] Checking status of {len(self.pending_jobs)} pending jobs.")
        remaining_jobs = []
        for job in self.pending_jobs:
            demisto.debug(f"[Orchestrator] The Job: {job}")
            demisto.debug(f"[Orchestrator] Polling job for brand '{job['brand']}'.")

            # Get the command for this job to poll for status. i.e.: GetActionStatus
            poll_cmd = Command(name=job["poll_command"], args=job["poll_args"], brand=job["brand"])
            raw_response, verbose_res = poll_cmd.execute()
            if self.verbose:
                self.verbose_results.extend(verbose_res)

            metadata = raw_response[0].get("Metadata", {}) if raw_response else {}
            demisto.debug(f"The raw response from executing: {raw_response}")

            if self._job_is_still_polling(metadata):
                demisto.debug(f"[Orchestrator] Job for brand '{job['brand']}' is still pending. Re-scheduling.")
                job["poll_args"] = metadata.get("pollingArgs", {})
                remaining_jobs.append(job)
            else:
                demisto.debug(f"[Orchestrator] Polling complete for job brand '{job['brand']}'. Finalizing.")
                handler = handler_factory(job["brand"], self)
                final_results = handler.finalize(raw_response)
                self.completed_results.extend(final_results)

        self.pending_jobs = remaining_jobs

    def _all_jobs_have_failed(self) -> bool:
        """
        Checks if all jobs in the completed results have failed.

        Returns:
            bool: True if all jobs have failed, False otherwise.
        """
        return all(result.Status == QuarantineResult.Statuses.FAILED for result in self.completed_results)

    def _get_final_results(self, fatal_error_msg=None) -> PollResult:
        """
        Args:
            fatal_error_msg: An error message in case of fatal error.
                             If given, the command will continue to error path.

        Formats and returns the final report after all jobs are complete.

        This method builds a Markdown table for the war room, and constructs the final CommandResults object.
        It will also return error_path if given a fatal_error_msg or none of the endpoints were successfully quarantined.

        Returns:
            PollResult: A PollResult object with `continue_to_poll=False` and the final results.
        """
        demisto.debug("[Orchestrator] Formatting final results.")

        results_list = QuarantineResult.to_context_entry(self.completed_results)
        # Build final report
        final_readable_output = tableToMarkdown(
            name=f"Quarantine Results for Hash: {self.args.get(self.FILE_HASH_ARG)}",
            headers=["EndpointID", "Status", "Message", "Brand"],
            t=results_list,
            removeNull=True,
        )

        final_command_results = CommandResults(
            outputs_prefix="QuarantineFile",
            outputs_key_field=["EndpointID", "FilePath", "FileHash"],  # these 3 make a unique key
            readable_output=final_readable_output,
            outputs=results_list,
        )

        if fatal_error_msg or self._all_jobs_have_failed():
            # If there is a fatal error message or all jobs have failed, we want to be on error path.
            demisto.results(
                {
                    "Type": entryTypes["error"],
                    "ContentsFormat": formats["text"],
                    "Contents": fatal_error_msg or "Could not quarantine file on all endpoints.",
                    "EntryContext": {},
                }
            )
        # Prepend verbose results if the flag is set
        if self.verbose:
            self.verbose_results.append(final_command_results)
            return PollResult(response=self.verbose_results, continue_to_poll=False)

        demisto.debug("[Orchestrator] Final results report created.")
        return PollResult(response=final_command_results, continue_to_poll=False)


""" SCRIPT ENTRYPOINT """


@polling_function(name="quarantine-file", timeout=arg_to_number(demisto.args().get("timeout", DEFAULT_TIMEOUT)))
def quarantine_file_script(args: dict) -> PollResult:
    """
    Main polling script function that delegates all work to the Orchestrator.

    This function is decorated with `@polling_function`, making it the entry point
    for XSOAR's polling mechanism.

    Args:
        args (dict): The arguments for the script execution.

    Returns:
        PollResult: The result from the orchestrator's run.
    """
    if not args:
        args = demisto.args()

    orchestrator = QuarantineOrchestrator(args)
    return orchestrator.run()


def main():
    """
    Main execution block of the script.

    It sets up the arguments, calls the main polling function, and handles
    any top-level exceptions, returning an error to the user if one occurs.
    """
    demisto.debug(f"Command being called is quarantine-file,  with arguments: {demisto.args()} ---")
    try:
        args = demisto.args()
        args["polling"] = True
        return_results(quarantine_file_script(args))
    except Exception as e:
        demisto.error(f"--- Unhandled Exception in quarantine-file script: {traceback.format_exc()} ---")
        return_error(f"Failed to execute quarantine-file script. Error: {str(e)}")

    demisto.debug("--- quarantine-file script execution complete. ---")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
