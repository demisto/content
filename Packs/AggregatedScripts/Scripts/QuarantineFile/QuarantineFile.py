from DemistoClassApiModule import *  # type:ignore [no-redef]  # noqa:E402

from dataclasses import dataclass, asdict

import demistomock as demisto
from CommonServerPython import *

""" CONSTANTS """
DEFAULT_TIMEOUT = 300

BRAND_CORE_IR = "Cortex Core - IR"
BRAND_XDR_IR = "Cortex XDR - IR"

VALID_BRANDS = [BRAND_CORE_IR, BRAND_XDR_IR]

""" DATA STRUCTURES """


@dataclass
class QuarantineResult:
    """A structured object to hold the result of a quarantine action for a single endpoint."""

    endpoint_id: str
    status: str
    message: str
    brand: str
    file_path: str
    file_hash: str

    class Statuses:
        SUCCESS = "Success"
        FAILED = "Failed"

    class Messages:
        """A namespace for standardized human-readable messages."""

        GENERAL_FAILURE = "Failed to quarantine file. See logs for more details."
        ALREADY_QUARANTINED = "Already quarantined."
        SUCCESS = "File successfully quarantined."
        ENDPOINT_OFFLINE = "Failed to quarantine file. The endpoint is offline or unreachable, please try again later."
        ENDPOINT_STATUS_UNKNOWN = "Failed to quarantine file. Endpoint status is '{status}'."
        ENDPOINT_NOT_FOUND = "Endpoint not found by any active integration."
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
            endpoint_id=endpoint_id,
            status=status,
            message=message,
            brand=brand,
            file_path=script_args.get(QuarantineOrchestrator.FILE_PATH_ARG, ""),
            file_hash=script_args.get(QuarantineOrchestrator.FILE_HASH_ARG, ""),
        )

    @staticmethod
    def to_simple_list(results_list: list) -> list[dict]:
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
            DemistoException: If the command execution returns an error entry.
        """
        demisto.debug(f"[Command] Executing: '{self.name}' with args: {self.args} for brand: {self.brand}")
        raw_response = demisto.executeCommand(self.name, self.args)
        demisto.debug(f"[Command] Received response for '{self.name}'.")

        verbose_results = []
        for result in raw_response:
            if is_error(result):
                # Log the full error for debugging, then raise to halt execution for this brand
                demisto.error(f"Error executing {self.name}:\n{get_error(entry)}")
                hr = f"Error executing {self.name}:\n{get_error(result)}"
            else:
                hr = result.get("HumanReadable", f"Successfully executed {self.name}")
            verbose_results.append(CommandResults(readable_output=hr))

        return raw_response, verbose_results

    @staticmethod
    def parse_entry_context(raw_response: list) -> list[dict]:
        """
        Safely extracts all EntryContext objects from a raw command response.

        It iterates through all entries in a command's raw response and collects
        any populated EntryContext objects into a single list.

        Args:
            raw_response (list): The raw list of results from a command execution.

        Returns:
            list[dict]: A list containing all non-empty entry context objects from the response.
        """
        demisto.debug("[Command] Parsing entry context from raw response.")
        entry_context: list[dict] = []
        for result in raw_response:
            if is_error(result):
                demisto.debug(f"[Command] Skipping error entry: {get_error(result)}")
                continue

            # The EntryContext can be None or an empty dict/list. We only want populated ones.
            if entry_context_item := result.get("EntryContext"):
                if isinstance(entry_context_item, list):
                    entry_context.extend(entry_context_item)
                else:
                    entry_context.append(entry_context_item)
        demisto.debug(f"[Command] Parsed entry context successfully. Found {len(entry_context)} items.")
        demisto.debug(f"[Command] Entry context: {entry_context}")
        return entry_context

    @staticmethod
    def get_first_filled_entry_context_list(raw_response: list) -> list:
        """
        Parses the entry context and returns the first non-empty list found.

        This is a helper for dealing with commands where the primary result is a list
        nested within the context, and the exact key is unknown or dynamic.

        Args:
            raw_response (list): The raw list of results from a command execution.

        Returns:
            list: The first list found within the entry context, or an empty list if none is found.
        """
        entry_context = Command.parse_entry_context(raw_response)

        outputs = []
        for context_item in entry_context:
            if not isinstance(context_item, dict):
                continue
            for value in context_item.values():
                if isinstance(value, list):
                    outputs = value
                    break
            if outputs:
                break

        return outputs


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
        demisto.debug("[EndpointBrandMapper] Initializing.")
        self.script_args = script_args
        self.orchestrator = orchestrator
        self.endpoint_ids_to_map = argToList(script_args.get(QuarantineOrchestrator.ENDPOINT_IDS_ARG))
        demisto.debug(f"[EndpointBrandMapper] Endpoint IDs to map: {self.endpoint_ids_to_map}")
        self.initial_results: list[QuarantineResult] = []
        demisto.debug(f"[EndpointBrandMapper] Ready to map {len(self.endpoint_ids_to_map)} endpoints.")

    def group_by_brand(self) -> dict[str, list]:
        """
        Groups online endpoints by their managing brand using 'get-endpoint-data'.

        This is the main public method of the class. It orchestrates the fetching
        and filtering of endpoint data to produce a clean mapping of brands to the
        online endpoints they manage.

        Returns:
            dict[str, list]: A dictionary mapping each brand name to a list of its
                             online endpoint IDs. Example: {'Cortex XDR - IR': ['id1', 'id2']}.

        Raises:
            DemistoException: If no endpoint IDs are provided, no data can be retrieved,
                              or no online endpoints are found.
        """
        demisto.debug("[EndpointBrandMapper] Starting endpoint grouping process.")
        if not self.endpoint_ids_to_map:
            demisto.debug("[EndpointBrandMapper] No endpoint IDs provided. Skipping.")
            raise DemistoException("No endpoint IDs provided. Please provide at least one endpoint ID.")

        endpoint_data = self._fetch_endpoint_data()
        if not endpoint_data:
            demisto.debug("[EndpointBrandMapper] No endpoint data found. Skipping.")
            raise DemistoException("Could not retrieve endpoint data.")

        online_endpoints = self._filter_endpoint_data(endpoint_data)
        if not online_endpoints:
            demisto.debug("[EndpointBrandMapper] No online endpoints found. Skipping.")
            raise DemistoException("No online endpoints found. Please verify the endpoints are online and try again later.")

        grouped_endpoints: dict[str, list] = {}
        for endpoint_id, brand in online_endpoints.items():
            if brand not in grouped_endpoints:
                grouped_endpoints[brand] = []
            grouped_endpoints[brand].append(endpoint_id)

        demisto.debug(f"[EndpointBrandMapper] Discovered endpoint groups: {grouped_endpoints}")

        if not grouped_endpoints:
            demisto.error("[Orchestrator] No endpoints to process. Finishing.")
            raise DemistoException("Error parsing endpoints. Please check the logs for more information.")

        return grouped_endpoints

    def _fetch_endpoint_data(self) -> list:
        """
        Makes a single, efficient call to 'get-endpoint-data' for all target endpoints.

        Returns:
            list: The list of endpoint data objects from the command's entry context.
                  Returns an empty list if no data is found.
        """
        demisto.debug("[EndpointBrandMapper] Fetching endpoint data.")

        demisto.debug(
            f"[EndpointBrandMapper] Querying get-endpoint-data limited to brands: {self.script_args.get(QuarantineOrchestrator.BRANDS_ARG)}"
        )
        command_args = {
            "endpoint_id": self.endpoint_ids_to_map,
            "brands": self.script_args.get(QuarantineOrchestrator.BRANDS_ARG),
        }

        cmd = Command(name="get-endpoint-data", args=command_args)
        raw_response, verbose_res = cmd.execute()

        if self.orchestrator.verbose:
            self.orchestrator.verbose_results.extend(verbose_res)
        demisto.debug(f"[EndpointBrandMapper] Received RAW response from get-endpoint-data command: {raw_response}")

        # Always parse from EntryContext, which is more reliable.
        entry_contexts = Command.parse_entry_context(raw_response)

        # Explicitly find the data list by looking for the correct key prefix.
        endpoint_data = []
        for context_item in entry_contexts:
            if not isinstance(context_item, dict):
                continue
            # Find the key that starts with 'EndpointData' to handle the auto-generated names.
            for key, value in context_item.items():
                if key.startswith("EndpointData") and isinstance(value, list):
                    endpoint_data = value
                    demisto.debug(f"[EndpointBrandMapper] Found endpoint data under the key '{key}'.")
                    break
            if endpoint_data:
                break

        if not endpoint_data:
            demisto.warning("[EndpointBrandMapper] Could not find a valid 'EndpointData' list in the EntryContext.")

        demisto.debug(f"[EndpointBrandMapper] Fetched data for {len(endpoint_data)} endpoints.")
        demisto.debug(f"[EndpointBrandMapper] Endpoint data: {endpoint_data}")
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
        demisto.debug(f"[EndpointBrandMapper] Processing raw endpoint data for {len(endpoint_data)} entries.")
        online_endpoints = {}
        all_found_ids = set()

        if not endpoint_data:
            demisto.debug("[EndpointBrandMapper] No endpoint data found. Skipping.")
            return {}

        # First pass: find all successful, online endpoints. These take precedence.
        for result in endpoint_data:
            endpoint_id = result.get("ID")
            if not endpoint_id or endpoint_id in online_endpoints:
                continue

            if result.get("Message") == "Command successful" and result.get("Status") == "Online":
                demisto.debug(f"[EndpointBrandMapper] Found 'Online' status for endpoint {endpoint_id}.")
                online_endpoints[endpoint_id] = result.get("Brand")

        # Second pass: Create failure results for any endpoint that was found, but not as 'Online'.
        for result in endpoint_data:
            endpoint_id = result.get("ID")
            if not endpoint_id or endpoint_id in all_found_ids:
                continue

            all_found_ids.add(endpoint_id)

            # Skip endpoints that were found as 'Online'
            if endpoint_id in online_endpoints:
                continue

            if result.get("Message") == "Command successful":
                message = QuarantineResult.Messages.ENDPOINT_STATUS_UNKNOWN.format(status=result.get("Status", "Unknown"))
            else:  # Message is not 'Command successful', i.e. "Command failed - no endpoint found"
                message = result.get("Message", QuarantineResult.Messages.ENDPOINT_OFFLINE)

            demisto.debug(f"[EndpointBrandMapper] Creating failure result for endpoint {endpoint_id}. Reason: {message}")
            self.initial_results.append(
                QuarantineResult.create(
                    endpoint_id=endpoint_id,
                    status=QuarantineResult.Statuses.FAILED,
                    message=message,
                    brand=result.get("Brand", "Unknown"),
                    script_args=self.script_args,
                )
            )

        unprocessed_ids = [eid for eid in self.endpoint_ids_to_map if eid not in all_found_ids]
        if unprocessed_ids:
            demisto.warning(
                f"[EndpointBrandMapper] Error in get-endpoint-data command. Endpoints not found in any the response: {unprocessed_ids}"
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


class BrandHandler:
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

    def validate_args(self, args: dict) -> None:
        """
        Validates that all required arguments for this brand are present.

        Raises:
            NotImplementedError: This method must be implemented by a subclass.
            ValueError: If a required argument is missing.
        """
        raise NotImplementedError

    def run_pre_checks_and_get_initial_results(self, args: dict) -> tuple[list, list[QuarantineResult]]:
        """
        Runs brand-specific pre-checks, like checking if a file is already quarantined.

        Raises:
            NotImplementedError: This method must be implemented by a subclass.
        """
        raise NotImplementedError

    def initiate_quarantine(self, args: dict) -> dict:
        """
        Initiates the quarantine action for the brand and returns a polling job object.

        Raises:
            NotImplementedError: This method must be implemented by a subclass.
        """
        raise NotImplementedError

    def finalize(self, job: dict, last_poll_response: list) -> list[QuarantineResult]:
        """
        Processes the final results of a completed polling job for the brand.

        Raises:
            NotImplementedError: This method must be implemented by a subclass.
        """
        raise NotImplementedError


class XDRHandler(BrandHandler):
    """Concrete handler for Cortex XDR and Cortex Core quarantine actions."""

    CORE_COMMAND_PREFIX = "core"
    XDR_COMMAND_PREFIX = "xdr"

    def __init__(self, brand: str, orchestrator):
        """
        Initializes the XDRHandler.

        Args:
            brand (str): The brand name ('Cortex XDR - IR' or 'Cortex Core - IR').
            orchestrator (QuarantineOrchestrator): The main orchestrator instance.
        """
        super().__init__(brand, orchestrator)
        self.command_prefix = self.CORE_COMMAND_PREFIX if self.brand == BRAND_CORE_IR else self.XDR_COMMAND_PREFIX

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
            raise DemistoException(f"The '{QuarantineOrchestrator.FILE_PATH_ARG}' argument is required for brand {self.brand}.")

    def _endpoint_already_quarantined(self, endpoint_id: str, file_hash: str, file_path: str) -> bool:
        """
        Checks if a file is already quarantined on a specific endpoint.

        Args:
            endpoint_id (str): The ID of the endpoint to check.
            file_hash (str): The SHA256 hash of the file.
            file_path (str): The path of the file on the endpoint.

        Returns:
            bool: True if the file is already quarantined, False otherwise.

        Raises:
            DemistoException: If the underlying 'get-quarantine-status' command fails.
        """
        demisto.debug(f"[{self.brand} Handler] Checking quarantine status for endpoint {endpoint_id}.")
        status_cmd = Command(
            name=f"{self.command_prefix}-get-quarantine-status",
            args={"endpoint_id": endpoint_id, "file_hash": file_hash, "file_path": file_path},
            brand=self.brand,
        )
        raw_response, verbose_res = status_cmd.execute()
        if self.orchestrator.verbose:
            self.orchestrator.verbose_results.extend(verbose_res)

        status_context = Command.parse_entry_context(raw_response)
        quarantine_status = self._extract_quarantine_status_from_context(status_context).get("status")

        return quarantine_status is True

    def _extract_quarantine_status_from_context(self, status_context: list) -> dict:
        """
        Extracts the core data dictionary from a command's nested entry context.

        Args:
            status_context (list): The entry context list from a command response.

        Returns:
            dict: The inner dictionary containing the status data, or an empty dict if not found.
        """
        demisto.debug(f"[{self.brand} Handler] Extracting status data from context: {status_context}")
        if not status_context or not isinstance(status_context[0], dict):
            return {}
        # The context is often a list with one dict, where the key is the command name
        # and the value is the actual data dictionary.
        return list(status_context[0].values())[0]

    def _process_final_endpoint_status(self, endpoint_result: dict, job_data: dict) -> QuarantineResult:
        """
        Processes the final result for a single endpoint from a completed polling job.

        If the initial quarantine action was successful, this method makes a second,
        separate call to 'get-quarantine-status' to get the true final result.

        Args:
            endpoint_result (dict): The result object for a single endpoint from the polling command's 'Contents'.
            job_data (dict): The original job object containing metadata and finalize_args.

        Returns:
            QuarantineResult: A structured result object for the endpoint.
        """
        endpoint_id = endpoint_result.get("endpoint_id")
        demisto.debug(f"[{self.brand} Handler] Processing final status for endpoint {endpoint_id}.")

        if endpoint_result.get("status") == "COMPLETED_SUCCESSFULLY":
            status_cmd = Command(
                name=f"{self.command_prefix}-get-quarantine-status",
                args={
                    "endpoint_id": endpoint_id,
                    "file_hash": job_data.get("finalize_args", {}).get("file_hash"),
                    "file_path": job_data.get("finalize_args", {}).get("file_path"),
                },
                brand=self.brand,
            )
            raw_response, verbose_res = status_cmd.execute()
            if self.orchestrator.verbose:
                self.orchestrator.verbose_results.extend(verbose_res)

            status_context = Command.parse_entry_context(raw_response)
            quarantine_status_data = self._extract_quarantine_status_from_context(status_context)
            quarantine_status = quarantine_status_data.get("status")
            message = (
                QuarantineResult.Messages.SUCCESS
                if quarantine_status
                else QuarantineResult.Messages.FAILED_WITH_REASON.format(reason=quarantine_status_data.get("error_description"))
            )
            status = QuarantineResult.Statuses.SUCCESS if quarantine_status else QuarantineResult.Statuses.FAILED
            demisto.debug(f"[{self.brand} Handler] Final status for {endpoint_id}: {status}")
        else:
            message = QuarantineResult.Messages.FAILED_WITH_REASON.format(reason=endpoint_result.get("error_description"))
            status = QuarantineResult.Statuses.FAILED
            demisto.debug(f"[{self.brand} Handler] Quarantine action failed for {endpoint_id}. Reason: {message}")

        return QuarantineResult(
            endpoint_id=endpoint_id,
            status=status,
            message=message,
            brand=self.brand,
            file_path=job_data.get("finalize_args", {}).get("file_path", ""),
            file_hash=job_data.get("finalize_args", {}).get("file_hash", ""),
        )

    def run_pre_checks_and_get_initial_results(self, args: dict) -> tuple[list, list[QuarantineResult]]:
        """
        Runs pre-checks for XDR endpoints to see if files are already quarantined.

        This prevents redundant API calls. For each endpoint, it checks the quarantine
        status. If already quarantined, a success result is created. Otherwise, the
        endpoint is added to a list for quarantine action.

        Args:
            args (dict): The script arguments for this brand's endpoints.

        Returns:
            tuple[list, list[QuarantineResult]]: A tuple containing:
                - A list of endpoint IDs that still need to be quarantined.
                - A list of QuarantineResult objects for endpoints already processed.
        """
        demisto.debug(f"[{self.brand} Handler] Running pre-checks.")
        online_endpoint_ids = argToList(args.get(QuarantineOrchestrator.ENDPOINT_IDS_ARG))
        completed_results = []
        endpoints_to_quarantine = []

        for e_id in online_endpoint_ids:
            try:
                if self._endpoint_already_quarantined(
                    e_id, args[QuarantineOrchestrator.FILE_HASH_ARG], args[QuarantineOrchestrator.FILE_PATH_ARG]
                ):
                    demisto.debug(f"[{self.brand} Handler] File already quarantined on endpoint {e_id}.")
                    completed_results.append(
                        QuarantineResult.create(
                            endpoint_id=e_id,
                            status=QuarantineResult.Statuses.SUCCESS,
                            message=QuarantineResult.Messages.ALREADY_QUARANTINED,
                            brand=self.brand,
                            script_args=args,
                        )
                    )
                else:
                    demisto.debug(f"[{self.brand} Handler] File not quarantined. Adding to quarantine list.")
                    endpoints_to_quarantine.append(e_id)

            except Exception as e:
                demisto.error(f"[{self.brand} Handler] Failed during pre-check for endpoint {e_id}: {e}")
                completed_results.append(
                    QuarantineResult.create(
                        endpoint_id=e_id,
                        status=QuarantineResult.Statuses.FAILED,
                        message=QuarantineResult.Messages.ENDPOINT_OFFLINE,
                        brand=self.brand,
                        script_args=args,
                    )
                )

        demisto.debug(f"[{self.brand} Handler] Pre-checks complete. {len(endpoints_to_quarantine)} endpoints require action.")
        return endpoints_to_quarantine, completed_results

    def initiate_quarantine(self, args: dict) -> dict:
        """
        Initiates the quarantine action for a list of XDR endpoints.

        This method calls the appropriate quarantine command ('core-quarantine-files' or
        'xdr-file-quarantine') and constructs a job object for polling.

        Args:
            args (dict): The script arguments, including the list of endpoint IDs to action.

        Returns:
            dict: A job object containing metadata required for polling.

        Raises:
            DemistoException: If the initial quarantine command fails.
        """
        demisto.debug(f"[{self.brand} Handler] Initiating quarantine action.")
        command_name = "core-quarantine-files" if self.command_prefix == self.CORE_COMMAND_PREFIX else "xdr-file-quarantine"

        quarantine_args = {
            "endpoint_id_list": args.get(QuarantineOrchestrator.ENDPOINT_IDS_ARG),
            "file_hash": args.get(QuarantineOrchestrator.FILE_HASH_ARG),
            "file_path": args.get(QuarantineOrchestrator.FILE_PATH_ARG),
            "timeout_in_seconds": args.get("timeout", DEFAULT_TIMEOUT),
        }

        cmd = Command(name=command_name, args=quarantine_args, brand=self.brand)
        raw_response, verbose_res = cmd.execute()
        if self.orchestrator.verbose:
            self.orchestrator.verbose_results.extend(verbose_res)

        metadata = raw_response[0].get("Metadata", {})
        demisto.debug(f"[{self.brand} Handler] Received metadata for polling: {metadata}")

        job = {
            "brand": self.brand,
            "poll_command": metadata.get("pollingCommand", command_name),
            "poll_args": metadata.get("pollingArgs", {}),
            "finalize_args": {
                "file_hash": args.get(QuarantineOrchestrator.FILE_HASH_ARG),
                "file_path": args.get(QuarantineOrchestrator.FILE_PATH_ARG),
            },
        }
        demisto.debug(f"[{self.brand} Handler] Created new job object: {job}")
        return job

    def finalize(self, job: dict, last_poll_response: list) -> list[QuarantineResult]:
        """
        Finalizes a completed quarantine job for the XDR brand.

        It parses the results from the last polling response and calls
        `_process_final_endpoint_status` for each endpoint to determine the
        definitive outcome.

        Args:
            job (dict): The job object that has just completed polling.
            last_poll_response (list): The raw response from the final polling command.

        Returns:
            list[QuarantineResult]: A list of final QuarantineResult objects.
        """
        demisto.debug(f"[{self.brand} Handler] Finalizing job.")
        final_results = []

        outputs = Command.get_first_filled_entry_context_list(last_poll_response)
        demisto.debug(f"[{self.brand} Handler] Finalizing {len(outputs)} endpoint results from job.")
        for res in outputs:
            try:
                final_results.append(self._process_final_endpoint_status(res, job))
            except Exception as e:
                demisto.error(
                    f"[{self.brand} Handler] Failed to get status of quarantine for endpoint {res.get('endpoint_id')}: {e}"
                )
                final_results.append(
                    QuarantineResult(
                        endpoint_id=res.get("endpoint_id", "Unknown"),
                        status=QuarantineResult.Statuses.FAILED,
                        message=QuarantineResult.Messages.GENERAL_FAILURE,
                        brand=self.brand,
                        file_path=job.get("finalize_args", {}).get("file_path", ""),
                        file_hash=job.get("finalize_args", {}).get("file_hash", ""),
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
    if brand in [BRAND_CORE_IR, BRAND_XDR_IR]:
        demisto.debug("[Factory] Selected XDRHandler.")
        return XDRHandler(brand, orchestrator)
    raise ValueError(f"No handler available for brand: {brand}")


""" SCRIPT ORCHESTRATOR """


class QuarantineOrchestrator:
    """Manages the entire quarantine lifecycle from start to finish."""

    CONTEXT_PENDING_JOBS = "quarantine_pending_jobs"
    CONTEXT_COMPLETED_RESULTS = "quarantine_completed_results"
    ENDPOINT_IDS_ARG = "endpoint_id"
    FILE_HASH_ARG = "file_hash"
    FILE_PATH_ARG = "file_path"
    BRANDS_ARG = "quarantine_brands"

    HASH_TYPE_TO_BRANDS = {"sha256": [BRAND_CORE_IR, BRAND_XDR_IR]}

    def __init__(self, args: dict):
        """
        Initializes the QuarantineOrchestrator.

        This involves loading the current state (pending jobs and completed results)
        from the incident context to support polling.

        Args:
            args (dict): The arguments passed to the script.
        """
        demisto.debug("[Orchestrator] Initializing.")
        self.args = args
        self.verbose = argToBoolean(args.get("verbose", False))
        self.verbose_results: list[CommandResults] = []
        self.pending_jobs = demisto.get(demisto.context(), self.CONTEXT_PENDING_JOBS) or []
        # Load results from context, ensuring they are dictionaries
        self.completed_results: list[QuarantineResult] = [
            QuarantineResult(**res) for res in (demisto.get(demisto.context(), self.CONTEXT_COMPLETED_RESULTS) or [])
        ]
        demisto.debug(
            f"[Orchestrator] Loaded state. Pending jobs: {len(self.pending_jobs)}, Completed results: {len(self.completed_results)}"
        )

    def _verify_and_dedup_endpoint_ids(self):
        """
        Verifies that endpoint IDs are provided and removes duplicates.

        Returns:
            list: A list of unique endpoint IDs.

        Raises:
            DemistoException: If the 'endpoint_id' argument is missing.
        """
        if not self.args.get(self.ENDPOINT_IDS_ARG):
            raise DemistoException(f"Missing required argument. Please provide '{self.ENDPOINT_IDS_ARG}'.")

        given_ids = argToList(self.args.get(self.ENDPOINT_IDS_ARG))
        unique_ids = set(given_ids)

        return list(unique_ids)

    def _verify_and_get_valid_brands(self):
        """
        Verifies the 'quarantine_brands' argument and filters for active integrations.

        It determines the final list of brands to run actions on by intersecting the
        user-provided brands (or all valid brands if none are provided) with the
        set of currently enabled integration instances.

        Returns:
            list: A list of brand names that are both valid and have an active instance.

        Raises:
            DemistoException: If an invalid brand is specified or no valid, enabled
                              integrations are found.
        """
        user_given_brands: list = argToList(self.args.get("quarantine_brands"))

        # Verify if brands are given, that they are ALL valid
        for brand in user_given_brands:
            if brand not in VALID_BRANDS:
                raise DemistoException(f"Invalid brand: {brand}. Valid brands are: {VALID_BRANDS}")

        enabled_brands = {module.get("brand") for module in demisto.getModules().values() if module.get("state") == "active"}

        brands_to_consider = set(user_given_brands) if user_given_brands else set(VALID_BRANDS)

        # The final list of brands to run on is the intersection of the brands we
        # should consider and the brands that are actually enabled.
        brands_to_run = list(brands_to_consider.intersection(enabled_brands))

        if not brands_to_run:
            raise DemistoException(
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

        Raises:
            DemistoException: If the hash argument is missing, the hash type is unsupported,
                              or no enabled integration supports the given hash type.
        """
        if not self.args.get(self.FILE_HASH_ARG):
            raise DemistoException(f"Missing required argument. Please provide '{self.FILE_HASH_ARG}'.")

        hash_type = get_hash_type(self.args.get(self.FILE_HASH_ARG)).lower()
        supported_brands_for_hash = self.HASH_TYPE_TO_BRANDS.get(hash_type)

        if not supported_brands_for_hash:
            raise DemistoException(
                f"Unsupported hash type: {hash_type}. Supported types are: {', '.join(self.HASH_TYPE_TO_BRANDS.keys())}"
            )

        if not any(brand in brands_to_run for brand in supported_brands_for_hash):
            raise DemistoException(
                "Could not find enabled integrations for the requested hash type.\n"
                f"For hash_type {hash_type.upper()} please use one of the following brands: {', '.join(supported_brands_for_hash)}"
            )

    def _sanitize_and_validate_args(self):
        """
        Performs all upfront argument validation and sanitization.

        This method orchestrates the various verification checks to ensure the script
        is running with valid and clean inputs before any actions are taken.

        Raises:
            DemistoException: If any validation check fails.
        """
        demisto.debug("[Orchestrator] Sanitizing and validating script arguments.")

        unique_ids = self._verify_and_dedup_endpoint_ids()
        self.args[self.ENDPOINT_IDS_ARG] = unique_ids

        brands_to_run = self._verify_and_get_valid_brands()
        self.args["quarantine_brands"] = brands_to_run

        self._verify_file_hash(brands_to_run)

        demisto.debug("[Orchestrator] Finished sanitizing and validating script arguments.")

    def _is_first_run(self) -> bool:
        """
        Determines if this is the first execution of the script for this task.

        Returns:
            bool: True if there are no pending jobs in the context, False otherwise.
        """
        return not self.pending_jobs

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
            self._sanitize_and_validate_args()
            self._initiate_jobs()
        else:
            demisto.debug("[Orchestrator] Detected polling run.")
            self._check_pending_jobs()

        # After work is done, decide whether to continue polling or finish.
        if self.pending_jobs:
            demisto.debug(f"[Orchestrator] {len(self.pending_jobs)} jobs still pending. Saving state and scheduling next poll.")
            demisto.setContext(self.CONTEXT_PENDING_JOBS, self.pending_jobs)
            demisto.setContext(self.CONTEXT_COMPLETED_RESULTS, QuarantineResult.to_simple_list(self.completed_results))
            interim_results = CommandResults(readable_output=f"Quarantine file script is still running...")
            return PollResult(
                response=interim_results, continue_to_poll=True, args_for_next_run=self.args, partial_result=interim_results
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
        try:
            mapper = EndpointBrandMapper(self.args, self)
            grouped_endpoints_by_brand = mapper.group_by_brand()
            self.completed_results.extend(mapper.initial_results)
        except Exception as e:
            demisto.error(f"[Orchestrator] Critical error during endpoint mapping, skipping quarantine operations {e}")
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
            endpoints_to_poll, initial_results = handler.run_pre_checks_and_get_initial_results(brand_args)
            self.completed_results.extend(initial_results)
            if endpoints_to_poll:
                demisto.debug(f"[Orchestrator] {len(endpoints_to_poll)} endpoints for '{brand}' need quarantine action.")
                initiate_args = self.args.copy()
                initiate_args[self.ENDPOINT_IDS_ARG] = endpoints_to_poll
                new_job = handler.initiate_quarantine(initiate_args)
                self.pending_jobs.append(new_job)
            return
        except DemistoException as e:
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
            demisto.debug(f"[Orchestrator] Polling job for brand '{job['brand']}'.")
            demisto.debug(f"[Orchestrator] The Job: {job}")
            poll_cmd = Command(name=job["poll_command"], args=job["poll_args"], brand=job["brand"])
            raw_response, verbose_res = poll_cmd.execute()
            if self.verbose:
                self.verbose_results.extend(verbose_res)

            metadata = raw_response[0].get("Metadata", {}) if raw_response else {}

            if self._job_is_still_polling(metadata):
                demisto.debug(f"[Orchestrator] Job for brand '{job['brand']}' is still pending. Re-scheduling.")
                job["poll_args"] = metadata.get("pollingArgs", {})
                remaining_jobs.append(job)
            else:
                demisto.debug(f"[Orchestrator] Polling complete for job brand '{job['brand']}'. Finalizing.")
                handler = handler_factory(job["brand"], self)
                final_results = handler.finalize(job, raw_response)
                self.completed_results.extend(final_results)

        self.pending_jobs = remaining_jobs

    def _get_final_results(self) -> PollResult:
        """
        Formats and returns the final report after all jobs are complete.

        This method cleans up the working data from the incident context, builds
        a markdown table for the war room, and constructs the final CommandResults object.

        Returns:
            PollResult: A PollResult object with `continue_to_poll=False` and the final results.
        """
        demisto.debug("[Orchestrator] Formatting final results.")
        # Clean up the context keys before returning the final result
        demisto.debug("[Orchestrator] Cleaning up context keys.")
        demisto.executeCommand(
            "DeleteContext",
            {"key": f"{QuarantineOrchestrator.CONTEXT_PENDING_JOBS},{QuarantineOrchestrator.CONTEXT_COMPLETED_RESULTS}"},
        )

        results_list = QuarantineResult.to_simple_list(self.completed_results)

        # Build final report
        final_readable_output = tableToMarkdown(
            name=f"Quarantine File Results for: {self.args.get(self.FILE_PATH_ARG)}",
            headers=["endpoint_id", "status", "message", "brand"],
            t=results_list,
            removeNull=True,
        )

        final_command_results = CommandResults(
            outputs_prefix="QuarantineFile",
            outputs_key_field=["endpoint_id", "file_path", "file_hash"],
            readable_output=final_readable_output,
            outputs=results_list,
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
    demisto.debug(f"--- quarantine-file script started with arguments: {demisto.args()} ---")
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
