from DemistoClassApiModule import * # type:ignore [no-redef]  # noqa:E402

from typing import Any

import demistomock as demisto
from CommonServerPython import *

""" CONSTANTS """
# Note: Most global constants have been moved into their respective classes for better encapsulation.
BRAND_CORE_IR = "Cortex Core - IR"
BRAND_XDR_IR = "Cortex XDR - IR"
BRAND_MDE = "Microsoft Defender for Endpoint"

""" HELPER CLASSES & FUNCTIONS """


class Command:
    """Helper class for executing commands and parsing results."""

    def __init__(self, name: str, args: dict, brand: str | None = None) -> None:
        """Initializes a Command object.
        Args:
            name (str): The name of the command to execute.
            args (dict): The arguments to pass to the command.
            brand (str | None): The specific integration brand to use for execution.
        """
        self.brand: str | None = brand
        self.name: str = name
        self.args: dict = args

    def execute(self) -> list:
        """Executes the command and returns the raw response list.
        Returns:
            list: The raw response from demisto.executeCommand.
        """
        demisto.debug(f"[Command] Executing: '{self.name}' with args: {self.args} for brand: {self.brand}")
        response = demisto.executeCommand(self.name, self.args)
        demisto.debug(f"[Command] Received response for '{self.name}'.")
        return response

    @staticmethod
    def parse_entry_context(raw_response: list) -> list[dict]:
        """Parses the entry context from a raw command response.
        Args:
            raw_response (list): The raw list of results from a command execution.
        Returns:
            list[dict]: A list containing all entry context objects from the response.
        """
        demisto.debug("[Command] Parsing entry context from raw response.")
        entry_context: list[dict] = []
        for result in raw_response:
            if is_error(result):
                demisto.debug(f"[Command] Skipping error entry: {get_error(result)}")
                continue
            if entry_context_item := result.get("EntryContext"):
                if isinstance(entry_context_item, list):
                    entry_context.extend(entry_context_item)
                else:
                    entry_context.append(entry_context_item)
        demisto.debug(f"[Command] Parsed entry context successfully. Found {len(entry_context)} items.")
        demisto.debug(f"[Command] Entry context: {entry_context}")
        return entry_context


class EndpointBrandMapper:
    """
    Handles the discovery and grouping of endpoints by their brand.
    This class encapsulates all logic related to mapping endpoints to vendors.
    """
    # Known aliases for brand names
    BRAND_ALIASES = {
        "Microsoft Defender ATP": BRAND_MDE,
        "Microsoft Defender Advanced Threat Protection": BRAND_MDE
    }

    # Mapping of our internal brand names to the names expected by the `get-endpoint-data` command
    GET_ENDPOINT_DATA_BRAND_MAP = {
        BRAND_CORE_IR: "Cortex Core - IR",
        BRAND_XDR_IR: "Cortex XDR - IR",
        BRAND_MDE: "Generic Command"
    }

    def __init__(self, script_args: dict):
        """Initializes the EndpointBrandMapper.
        Args:
            script_args (dict): The original arguments passed to the script.
        """
        demisto.debug("[EndpointBrandMapper] Initializing.")
        self.script_args = script_args
        self.endpoint_ids_to_map = argToList(script_args.get(QuarantineOrchestrator.ENDPOINT_IDS))
        demisto.debug(f"[EndpointBrandMapper] Endpoint IDs to map: {self.endpoint_ids_to_map}")
        self.initial_results: list[dict] = []
        demisto.debug(f"[EndpointBrandMapper] Ready to map {len(self.endpoint_ids_to_map)} endpoints.")

    def group_by_brand(self) -> dict[str, list]:
        """Runs the entire discovery and grouping process.
        Returns:
            dict[str, list]: A dictionary mapping each brand name to a list of its endpoint IDs that are online.
        """
        demisto.debug("[EndpointBrandMapper] Starting endpoint grouping process.")
        if not self.endpoint_ids_to_map:
            demisto.debug("[EndpointBrandMapper] No endpoint IDs provided. Skipping.")
            return {}

        endpoint_data = self._fetch_endpoint_data()
        online_endpoints = self._process_endpoint_data(endpoint_data)
        if not online_endpoints:
            demisto.debug("[EndpointBrandMapper] No online endpoints found. Skipping.")
            return {}

        grouped_endpoints: dict[str, list] = {}
        for endpoint_id, brand in online_endpoints.items():
            normalized_brand = self.BRAND_ALIASES.get(brand, brand)
            if normalized_brand not in grouped_endpoints:
                grouped_endpoints[normalized_brand] = []
            grouped_endpoints[normalized_brand].append(endpoint_id)

        demisto.debug(f"[EndpointBrandMapper] Grouping complete. Grouped endpoints: {grouped_endpoints}")
        return grouped_endpoints

    def _fetch_endpoint_data(self) -> list:
        """Makes a single, efficient call to get data for all endpoints.
        Returns:
            list: The list of endpoint data objects from the command response.
        """
        demisto.debug("[EndpointBrandMapper] Fetching endpoint data.")
        brands_to_query = list(self.GET_ENDPOINT_DATA_BRAND_MAP.values())
        demisto.debug(f"[EndpointBrandMapper] Querying get-endpoint-data limited to brands: {brands_to_query}")
        command_args = {"endpoint_id": self.endpoint_ids_to_map, "brands": brands_to_query}

        cmd = Command(name="get-endpoint-data", args=command_args)
        raw_response = cmd.execute()
        demisto.debug(f"[EndpointBrandMapper] Received RAW response from get-endpoint-data command: {raw_response}")

        if not raw_response or not isinstance(raw_response[0].get('Contents'), list):
            demisto.debug("[EndpointBrandMapper] 'get-endpoint-data' did not return valid 'Contents'.")
            return []

        endpoint_data = raw_response[0].get('Contents', [])
        demisto.debug(f"[EndpointBrandMapper] Fetched data for {len(endpoint_data)} endpoints.")
        demisto.debug(f"[EndpointBrandMapper] Endpoint data: {endpoint_data}")
        return endpoint_data

    def _process_endpoint_data(self, endpoint_data: list) -> dict:
        """
        Parses endpoint data to group online endpoints and create results for offline/unfound ones.
        This method handles duplicate entries by prioritizing successful, online results.
        Args:
            endpoint_data (list): A list of endpoint data objects from the API.
        Returns:
            dict: A dictionary mapping online endpoint IDs to their brand.
        """
        demisto.debug(f"[EndpointBrandMapper] Processing raw endpoint data for {len(endpoint_data)} entries.")
        online_endpoints = {}
        all_found_ids = set()

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

            # If an endpoint was successfully found as 'Online', we don't need to process it here as a failure.
            if endpoint_id in online_endpoints:
                continue

            # This endpoint was found, but wasn't 'Online'. Create a failure result.
            if result.get("Message") == "Command successful":
                message = f"Failed to quarantine file. Endpoint status is '{result.get('Status', 'Unknown')}'."
            else:  # The command itself failed for this endpoint in this brand context
                message = result.get("Message", "Failed to get endpoint data.")

            demisto.debug(f"[EndpointBrandMapper] Creating failure result for endpoint {endpoint_id}. Reason: {message}")
            self.initial_results.append({
                "endpoint_id": endpoint_id, "file_path": self.script_args.get(QuarantineOrchestrator.FILE_PATH),
                "file_hash": self.script_args.get(QuarantineOrchestrator.FILE_HASH), "status": "Failed",
                "message": message, "brand": result.get("Brand", "Unknown")
            })

        # Final step: handle endpoints that were in the input but never appeared in the response at all.
        unprocessed_ids = [eid for eid in self.endpoint_ids_to_map if eid not in all_found_ids]
        if unprocessed_ids:
            demisto.debug(f"[EndpointBrandMapper] Endpoints not found in any response: {unprocessed_ids}")
            for endpoint_id in unprocessed_ids:
                self.initial_results.append({
                    "endpoint_id": endpoint_id, "file_path": self.script_args.get(QuarantineOrchestrator.FILE_PATH),
                    "file_hash": self.script_args.get(QuarantineOrchestrator.FILE_HASH), "status": "Failed",
                    "message": f"Endpoint ID {endpoint_id} not found by any active integration.", "brand": "Unknown"
                })

        demisto.debug(f"[EndpointBrandMapper] Processing complete. Found {len(online_endpoints)} online endpoints.")
        return online_endpoints


""" BRAND HANDLER INTERFACE & FACTORY """


class BrandHandler:
    """Abstract base class (Interface) for all brand-specific handlers."""

    def __init__(self, brand: str):
        self.brand = brand

    def validate_args(self, args: dict) -> None:
        pass

    def run_pre_checks_and_get_initial_results(self, args: dict) -> tuple[list, list]:
        return argToList(args.get(QuarantineOrchestrator.ENDPOINT_IDS)), []

    def initiate_quarantine(self, args: dict) -> dict:
        raise NotImplementedError

    def finalize(self, job: dict, last_poll_response: list) -> list[dict]:
        return []


class XDRHandler(BrandHandler):
    """Concrete handler for Cortex XDR and Cortex Core."""
    CORE_COMMAND_PREFIX = "core"
    XDR_COMMAND_PREFIX = "xdr"

    def validate_args(self, args: dict) -> None:
        demisto.debug(f"[{self.brand} Handler] Validating args.")
        if not args.get(QuarantineOrchestrator.FILE_PATH):
            raise ValueError(f"The '{QuarantineOrchestrator.FILE_PATH}' argument is required for {self.brand}.")

    def run_pre_checks_and_get_initial_results(self, args: dict) -> tuple[list, list]:
        demisto.debug(f"[{self.brand} Handler] Running pre-checks.")
        online_endpoint_ids = argToList(args.get(QuarantineOrchestrator.ENDPOINT_IDS))
        file_hash = args.get(QuarantineOrchestrator.FILE_HASH)
        file_path = args.get(QuarantineOrchestrator.FILE_PATH)
        completed_results = []
        endpoints_to_quarantine = []

        command_prefix = self.CORE_COMMAND_PREFIX if self.brand == BRAND_CORE_IR else self.XDR_COMMAND_PREFIX

        for e_id in online_endpoint_ids:
            try:
                demisto.debug(f"[{self.brand} Handler] Checking quarantine status for endpoint {e_id}.")
                status_cmd = Command(
                    name=f"{command_prefix}-get-quarantine-status",
                    args={"endpoint_id": e_id, "file_hash": file_hash, "file_path": file_path},
                    brand=self.brand
                )
                status_context = Command.parse_entry_context(status_cmd.execute())

                quarantine_status = list(status_context[0].values())[0].get("status")
                if quarantine_status:
                    demisto.debug(f"[{self.brand} Handler] File already quarantined on endpoint {e_id}.")
                    completed_results.append({
                        "endpoint_id": e_id, "file_path": file_path, "file_hash": file_hash,
                        "status": "Success", "message": "Already quarantined.", "brand": self.brand
                    })
                else:
                    demisto.debug(f"[{self.brand} Handler] File not quarantined on endpoint {e_id}. Adding to quarantine list.")
                    endpoints_to_quarantine.append(e_id)
            except Exception as e:
                demisto.error(f"[{self.brand} Handler] Failed during pre-check for endpoint {e_id}: {e}")
                completed_results.append({
                    "endpoint_id": e_id, "file_path": file_path, "file_hash": file_hash,
                    "status": "Failed", "message": f"Failed during pre-check stage: {e}", "brand": self.brand
                })

        demisto.debug(f"[{self.brand} Handler] Pre-checks complete. {len(endpoints_to_quarantine)} endpoints require action.")
        return endpoints_to_quarantine, completed_results

    def initiate_quarantine(self, args: dict) -> dict:
        demisto.debug(f"[{self.brand} Handler] Initiating quarantine action.")
        command_prefix = self.CORE_COMMAND_PREFIX if self.brand == BRAND_CORE_IR else self.XDR_COMMAND_PREFIX
        command_name = "core-quarantine-files" if command_prefix == self.CORE_COMMAND_PREFIX else "xdr-file-quarantine"

        quarantine_args = {
            "endpoint_id_list": args.get(QuarantineOrchestrator.ENDPOINT_IDS),
            "file_hash": args.get(QuarantineOrchestrator.FILE_HASH),
            "file_path": args.get(QuarantineOrchestrator.FILE_PATH)
        }

        cmd = Command(name=command_name, args=quarantine_args, brand=self.brand)
        raw_response = cmd.execute()
        metadata = raw_response[0].get("Metadata", {})
        demisto.debug(f"[{self.brand} Handler] Received metadata for polling: {metadata}")

        job = {
            "brand": self.brand,
            "poll_command": metadata.get("pollingCommand", command_name),
            "poll_args": metadata.get("pollingArgs", {}),
            "finalize_args": {
                "file_hash": args.get(QuarantineOrchestrator.FILE_HASH),
                "file_path": args.get(QuarantineOrchestrator.FILE_PATH)
            }
        }
        demisto.debug(f"[{self.brand} Handler] Created new job object: {job}")
        return job

    def finalize(self, job: dict, last_poll_response: list) -> list[dict]:
        demisto.debug(f"[{self.brand} Handler] Finalizing job.")
        final_results = []
        command_prefix = self.CORE_COMMAND_PREFIX if self.brand == BRAND_CORE_IR else self.XDR_COMMAND_PREFIX
        outputs = last_poll_response[0].get("Contents", [])

        demisto.debug(f"[{self.brand} Handler] Finalizing {len(outputs)} endpoint results from job.")
        for res in outputs:
            endpoint_id = res.get("endpoint_id")
            demisto.debug(f"[{self.brand} Handler] Finalizing endpoint {endpoint_id}.")
            if res.get("status") == "COMPLETED_SUCCESSFULLY":
                status_cmd = Command(
                    name=f"{command_prefix}-get-quarantine-status",
                    args={
                        "endpoint_id": endpoint_id,
                        "file_hash": job.get("finalize_args", {}).get("file_hash"),
                        "file_path": job.get("finalize_args", {}).get("file_path")
                    },
                    brand=self.brand
                )
                status_context = Command.parse_entry_context(status_cmd.execute())

                quarantine_status_data = list(status_context[0].values())[0]
                quarantine_status = quarantine_status_data.get("status")
                message = "File successfully quarantined." if quarantine_status else f"Failed to quarantine file. {quarantine_status_data.get('error_description')}"
                status = "Success" if quarantine_status else "Failed"
                demisto.debug(f"[{self.brand} Handler] Final status for {endpoint_id}: {status}")
            else:
                message = f"Failed to quarantine file. {res.get('error_description')}"
                status = "Failed"
                demisto.debug(f"[{self.brand} Handler] Quarantine action failed for {endpoint_id}. Reason: {message}")

            final_results.append({
                "endpoint_id": endpoint_id, "file_path": job.get("finalize_args", {}).get("file_path"),
                "file_hash": job.get("finalize_args", {}).get("file_hash"), "status": status,
                "message": message, "brand": self.brand
            })
        return final_results


class MDEHandler(BrandHandler):
    """Concrete handler for Microsoft Defender for Endpoint."""

    def initiate_quarantine(self, args: dict) -> dict:
        demisto.debug("[MDE Handler] Initiate quarantine called, but it is not implemented.")
        raise NotImplementedError("MDEHandler is not yet implemented.")


def handler_factory(brand: str) -> BrandHandler:
    """Factory function that returns an instance of the correct brand handler."""
    demisto.debug(f"[Factory] Creating handler for brand: '{brand}'")
    normalized_brand = EndpointBrandMapper.BRAND_ALIASES.get(brand, brand)
    if normalized_brand in [BRAND_CORE_IR, BRAND_XDR_IR]:
        demisto.debug("[Factory] Selected XDRHandler.")
        return XDRHandler(normalized_brand)
    elif normalized_brand == BRAND_MDE:
        demisto.debug("[Factory] Selected MDEHandler.")
        return MDEHandler(normalized_brand)
    raise ValueError(f"No handler available for brand: {brand}")


""" SCRIPT ORCHESTRATOR """


class QuarantineOrchestrator:
    """Manages the entire quarantine lifecycle."""
    CONTEXT_PENDING_JOBS = "quarantine_pending_jobs"
    CONTEXT_COMPLETED_RESULTS = "quarantine_completed_results"
    ENDPOINT_IDS = "endpoint_ids"
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"

    def __init__(self, args: dict):
        demisto.debug("[Orchestrator] Initializing.")
        self.args = args
        self.pending_jobs = demisto.get(demisto.context(), self.CONTEXT_PENDING_JOBS) or []
        self.completed_results = demisto.get(demisto.context(), self.CONTEXT_COMPLETED_RESULTS) or []
        demisto.debug(
            f"[Orchestrator] Loaded state. Pending jobs: {len(self.pending_jobs)}, Completed results: {len(self.completed_results)}")

    def run(self) -> PollResult:
        demisto.debug("[Orchestrator] Starting run.")
        is_first_run = not self.pending_jobs and self.args
        if is_first_run:
            demisto.debug("[Orchestrator] Detected first run.")
            self._initiate_jobs()
        else:
            demisto.debug("[Orchestrator] Detected polling run.")
            self._check_pending_jobs()

        demisto.debug(
            f"[Orchestrator] Run complete. Saving state. Pending jobs: {len(self.pending_jobs)}, Completed results: {len(self.completed_results)}")
        demisto.setContext(self.CONTEXT_PENDING_JOBS, self.pending_jobs)
        demisto.setContext(self.CONTEXT_COMPLETED_RESULTS, self.completed_results)

        if not self.pending_jobs:
            demisto.debug("[Orchestrator] No pending jobs remain. Finishing.")
            return self._get_final_results()
        else:
            demisto.debug(f"[Orchestrator] Jobs still pending. Scheduling next poll with args: {self.args}")
            interim_results = CommandResults(readable_output=f"{len(self.pending_jobs)} quarantine actions are still pending.")
            return PollResult(response=interim_results, continue_to_poll=True, args_for_next_run=self.args,
                              partial_result=interim_results)

    def _initiate_jobs(self):
        demisto.debug("[Orchestrator] Initiating jobs.")
        try:
            mapper = EndpointBrandMapper(self.args)
            grouped_endpoints = mapper.group_by_brand()
            self.completed_results.extend(mapper.initial_results)
        except Exception as e:
            demisto.error(f"[Orchestrator] Critical error during endpoint mapping: {e}")
            for endpoint_id in argToList(self.args.get(self.ENDPOINT_IDS)):
                self.completed_results.append({
                    "endpoint_id": endpoint_id, "file_path": self.args.get(self.FILE_PATH),
                    "file_hash": self.args.get(self.FILE_HASH), "status": "Failed",
                    "message": f"Could not retrieve endpoint data. Error: {e}", "brand": "Unknown"
                })
            return

        if not grouped_endpoints:
            demisto.debug("[Orchestrator] No endpoints to process. Finishing.")
            return

        demisto.debug(f"[Orchestrator] Processing grouped endpoints: {grouped_endpoints.keys()}")
        for brand, endpoint_ids in grouped_endpoints.items():
            try:
                handler = handler_factory(brand)
                demisto.debug(f"[Orchestrator] Processing {len(endpoint_ids)} endpoints for brand '{brand}'.")
                brand_args = self.args.copy()
                brand_args[self.ENDPOINT_IDS] = endpoint_ids
                handler.validate_args(brand_args)
                endpoints_to_poll, initial_results = handler.run_pre_checks_and_get_initial_results(brand_args)
                self.completed_results.extend(initial_results)
                if endpoints_to_poll:
                    demisto.debug(f"[Orchestrator] {len(endpoints_to_poll)} endpoints for '{brand}' need quarantine action.")
                    initiate_args = self.args.copy()
                    initiate_args[self.ENDPOINT_IDS] = endpoints_to_poll
                    new_job = handler.initiate_quarantine(initiate_args)
                    self.pending_jobs.append(new_job)
            except Exception as e:
                demisto.error(f"[Orchestrator] Failed to process group for brand '{brand}': {e}")
                for endpoint_id in endpoint_ids:
                    self.completed_results.append({
                        "endpoint_id": endpoint_id, "file_path": self.args.get(self.FILE_PATH),
                        "file_hash": self.args.get(self.FILE_HASH), "status": "Failed",
                        "message": str(e), "brand": brand
                    })

    def _check_pending_jobs(self):
        demisto.debug(f"[Orchestrator] Checking status of {len(self.pending_jobs)} pending jobs.")
        remaining_jobs = []
        for job in self.pending_jobs:
            demisto.debug(f"[Orchestrator] Polling job for brand '{job['brand']}'.")
            demisto.debug(f"[Orchestrator] The Job: {job}")
            poll_cmd = Command(name=job["poll_command"], args=job["poll_args"], brand=job["brand"])
            raw_response = poll_cmd.execute()
            metadata = raw_response[0].get("Metadata", {}) if raw_response else {}

            if metadata.get("polling"):
                demisto.debug(f"[Orchestrator] Job for brand '{job['brand']}' is still pending. Re-scheduling.")
                job["poll_args"] = metadata.get("pollingArgs", {})
                remaining_jobs.append(job)
            else:
                demisto.debug(f"[Orchestrator] Polling complete for job brand '{job['brand']}'. Finalizing.")
                handler = handler_factory(job["brand"])
                final_results = handler.finalize(job, raw_response)
                self.completed_results.extend(final_results)

        self.pending_jobs = remaining_jobs

    def _get_final_results(self) -> PollResult:
        """Formats and returns the final report."""
        demisto.debug("[Orchestrator] Formatting final results.")
        # Clean up the context keys before returning the final result
        demisto.debug("[Orchestrator] Cleaning up context keys.")
        keys_to_delete = f"{self.CONTEXT_PENDING_JOBS},{self.CONTEXT_COMPLETED_RESULTS}"
        demisto.executeCommand("DeleteContext", {"key": keys_to_delete})

        final_readable_output = tableToMarkdown(
            name=f"Quarantine File Results for: {self.args.get(self.FILE_PATH)}",
            headers=["endpoint_id", "status", "message", "brand"],
            t=self.completed_results,
            removeNull=True
        )
        demisto.debug("[Orchestrator] Final results report created.")
        return PollResult(
            response=CommandResults(
                outputs_prefix="QuarantineFile",
                outputs_key_field=["endpoint_id", "file_path"],
                readable_output=final_readable_output,
                outputs=self.completed_results
            ),
            continue_to_poll=False
        )


""" SCRIPT ENTRYPOINT """


@polling_function(
    name="quarantine-file",
    interval=60,
    timeout=600,
)
def quarantine_file_script(args: dict) -> PollResult:
    """Main polling script function that delegates all work to the Orchestrator."""
    if not args:
        args = demisto.args()
    orchestrator = QuarantineOrchestrator(args)
    return orchestrator.run()


def main():
    """Main function, which runs the entire script logic."""
    demisto.debug(f"--- quarantine-file script started with arguments: {demisto.args()} ---")
    try:
        args = demisto.args()
        args["polling"] = True
        return_results(quarantine_file_script(args))
    except Exception as e:
        demisto.error(f"--- Unhandled Exception in quarantine-file script: {traceback.format_exc()} ---")
        return_error(f"Failed to execute quarantine-file script. Error: {str(e)}")
    demisto.debug("--- quarantine-file script finished ---")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
