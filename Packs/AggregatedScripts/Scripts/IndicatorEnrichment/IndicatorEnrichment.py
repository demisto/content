import demistomock as demisto
from CommonServerPython import *
from AggregatedCommandApiModule import *
from enum import Enum
from typing import NamedTuple, Any, Optional
from collections import defaultdict
import traceback


MAX_INDICATORS = 100

MSG_NO_VALID_INDICATORS = (
    "No valid indicators provided. You must provide at least one valid indicator " "in arguments: indicator_list or text."
)

ERR_LIMIT_TEMPLATE = (
    "Error: Indicator limit exceeded. Found {found} indicators, but the limit is {limit}. "
    "To process all indicators, set the ignore_indicator_limit argument to true. "
    "Note: This should be avoided if possible."
)


class ValidationError(Exception):
    """
    Raised when business logic constraints are violated.
    This exception should result in a return_error action.
    """



class GracefulExit(Exception):
    """
    Raised when the script should stop execution and return a status message.
    This exception should result in a return_results action (success status), not an error.
    """



class IndicatorType(Enum):
    """
    Configuration registry for supported indicator types.
    Acts as the single source of truth for command mapping, argument keys, and context prefixes.
    """

    IP = ("ip_list", "IP", "ip-enrichment", "IPEnrichment", ["ip", "ipv4"])
    URL = ("url_list", "URL", "url-enrichment", "URLEnrichment", ["url"])
    DOMAIN = ("domain_list", "Domain", "domain-enrichment", "DomainEnrichment", ["domain"])
    CVE = ("cve_list", "CVE", "cve-enrichment", "CVEEnrichment", ["cve"])
    FILE = ("file_hash", "File", "file-enrichment", "FileEnrichment", ["file"])

    def __init__(self, argument_key: str, display_name: str, command_name: str, context_prefix: str, aliases: list[str]):
        """
        Initializes the IndicatorType configuration.

        Args:
            argument_key: The argument name expected by the child command (e.g., 'ip_list').
            display_name: The human-readable name for headers (e.g., 'IP').
            command_name: The XSOAR command to execute (e.g., 'ip-enrichment').
            context_prefix: The prefix used in EntryContext (e.g., 'IPEnrichment').
            aliases: A list of string representations used for type detection.
        """
        self.argument_key = argument_key
        self.display_name = display_name
        self.command_name = command_name
        self.context_prefix = context_prefix
        self.aliases = aliases

    @classmethod
    def resolve_from_string(cls, value: str) -> Optional["IndicatorType"]:
        """
        Maps a raw string type (e.g., 'IPv4', 'sha256') to the corresponding IndicatorType Enum.

        Args:
            value: The raw type string to resolve.

        Returns:
            The matching IndicatorType member, or None if the type is not supported.
        """
        if not value:
            return None
        normalized_value = value.lower()
        for member in cls:
            if normalized_value in member.aliases:
                return member
        return None


class UnsupportedIndicator(NamedTuple):
    """
    Represents an indicator that was detected but is not supported by the configured Enrichment commands.
    """

    type: str
    value: str


class EnrichmentTask(NamedTuple):
    """
    Represents a unit of work: a specific XSOAR command configured for a specific indicator type.
    """

    indicator_type: IndicatorType
    command: Command


class EnrichmentRequest:
    """
    Immutable Data Transfer Object (DTO) representing the sanitized, deduplicated,
    and validated input data ready for processing.
    """

    def __init__(
        self,
        valid_indicators_by_type: defaultdict[IndicatorType, list[str]],
        unsupported_items: list[UnsupportedIndicator],
        unknown_items: list[str],
        duplicates_removed_count: int,
        sub_command_arguments: dict[str, Any],
        include_raw_context: bool,
    ):
        """
        Initializes the EnrichmentRequest.

        Args:
            valid_indicators_by_type: A mapping of IndicatorType to a list of valid indicator values.
            unsupported_items: A list of items that have a type but are not supported by this script.
            unknown_items: A list of items where type detection failed.
            duplicates_removed_count: The count of duplicate items filtered out during building.
            sub_command_arguments: Arguments to be passed down to child commands (e.g., brands).
            include_raw_context: Whether to include the raw enrichment keys in the final output.
        """
        self.valid_indicators_by_type = valid_indicators_by_type
        self.unsupported_items = unsupported_items
        self.unknown_items = unknown_items
        self.duplicates_removed_count = duplicates_removed_count
        self.sub_command_arguments = sub_command_arguments
        self.include_raw_context = include_raw_context

    @property
    def total_valid_count(self) -> int:
        """Returns the total number of valid indicators across all types."""
        return sum(len(indicators) for indicators in self.valid_indicators_by_type.values())


class EnrichmentResult:
    """
    Accumulator for the results of the enrichment execution phase.
    """

    def __init__(self):
        self.enriched_data: list[ContextResult] = []
        self.raw_context: ContextResult = {}
        self.markdown_sections: list[str] = []


class EnrichmentRequestBuilder:
    """
    Responsible for parsing raw XSOAR arguments, extracting indicators from text and lists,
    deduplicating inputs, and enforcing business validation rules.
    """

    def __init__(self, raw_arguments: dict[str, Any]):
        """
        Args:
            raw_arguments: The dictionary of arguments provided to the command (demisto.args()).
        """
        self.raw_arguments = raw_arguments
        # this is for the deduplication tracking
        self._seen_indicators: set[str] = set()

        self.valid_indicators_by_type: defaultdict[IndicatorType, list[str]] = defaultdict(list)
        self.unsupported_items: list[UnsupportedIndicator] = []
        self.unknown_items: list[str] = []
        self.duplicates_count: int = 0

    def get_validated_request(self) -> EnrichmentRequest:
        """
        Orchestrates the creation of an EnrichmentRequest.

        Returns:
            A fully populated and validated EnrichmentRequest.

        Raises:
            ValidationError: If inputs are invalid or limits are exceeded.
            GracefulExit: If valid inputs are provided but result in no actionable work.
        """
        self._extract_indicators_from_text_argument()
        self._extract_indicators_from_list_argument()
        self._enforce_enrichment_arg_rules()

        return EnrichmentRequest(
            valid_indicators_by_type=self.valid_indicators_by_type,
            unsupported_items=self.unsupported_items,
            unknown_items=self.unknown_items,
            duplicates_removed_count=self.duplicates_count,
            sub_command_arguments=self._filter_passthrough_arguments(),
            include_raw_context=argToBoolean(self.raw_arguments.get("raw_context", False)),
        )

    def _classify_and_store(self, raw_type: str, value: str) -> None:
        """
        Normalizes, deduplicates, and classifies a single indicator value.
        Populates the internal state buckets (valid, unknown, unsupported).

        Args:
            raw_type: The string type representation (e.g., 'IP', 'Unknown').
            value: The indicator value string.
        """
        if not value:
            return

        clean_value = str(value).strip()
        if not clean_value:
            return

        if clean_value in self._seen_indicators:
            self.duplicates_count += 1
            return

        self._seen_indicators.add(clean_value)

        indicator_type = IndicatorType.resolve_from_string(raw_type)

        if indicator_type:
            self.valid_indicators_by_type[indicator_type].append(clean_value)
        elif not raw_type or raw_type.lower() == "unknown":
            self.unknown_items.append(clean_value)
        else:
            self.unsupported_items.append(UnsupportedIndicator(raw_type, clean_value))

    def _extract_indicators_from_text_argument(self) -> None:
        """
        Extracts indicators from the 'text' argument using the 'extractIndicators' command.

        Example of Response of the extractIndicators command:
        {
        "IP": ["1.1.1.1"],
        "Domain": ["google.com"]
        }
        """
        text_argument = self.raw_arguments.get("text", "")
        if not text_argument:
            return

        res = execute_command("extractIndicators", {"text": text_argument}, extract_contents=False)
        if not res or not isinstance(res, list):
            return

        entry_context = res[0].get("EntryContext", {}) or {}
        extracted_indicators = entry_context.get("ExtractedIndicators", {}) or {}

        for type_str, values in extracted_indicators.items():
            items = values if isinstance(values, list) else [values]
            for val in items:
                self._classify_and_store(type_str, val)

    def _extract_indicators_from_list_argument(self) -> None:
        """
        Parses the 'indicator_list' argument and attempts to auto-detect the type of each item.
        """
        raw_list = argToList(self.raw_arguments.get("indicator_list"))
        for item in raw_list:
            detected_type = auto_detect_indicator_type(item)  # type: ignore
            self._classify_and_store(detected_type or "Unknown", item)

    def _enforce_enrichment_arg_rules(self) -> None:
        """
        Validates the state of collected indicators against business rules.

        Raises:
            ValidationError: If:
             - indicator_list and text are not given
             - indicator_list given with no valid indicators
             - Over 100 indicators given (after clearing invalid and duplicates)
            GracefulExit: If text input yields no valid indicators (non-error state).
        """
        total_valid = sum(len(v) for v in self.valid_indicators_by_type.values())
        has_invalid = bool(self.unsupported_items or self.unknown_items)

        text_provided = bool(self.raw_arguments.get("text", "").strip())
        list_key_present = "indicator_list" in self.raw_arguments
        list_has_values = bool(argToList(self.raw_arguments.get("indicator_list")))

        if not text_provided and not list_has_values and not list_key_present:
            raise ValidationError(MSG_NO_VALID_INDICATORS)

        if list_key_present and (not list_has_values or total_valid == 0):
            raise ValidationError(MSG_NO_VALID_INDICATORS)

        if text_provided and not list_key_present and total_valid == 0 and not has_invalid:
            raise GracefulExit(MSG_NO_VALID_INDICATORS)

        ignore_limit = argToBoolean(self.raw_arguments.get("ignore_indicator_limit", False))
        if not ignore_limit and total_valid > MAX_INDICATORS:
            raise ValidationError(ERR_LIMIT_TEMPLATE.format(found=total_valid, limit=MAX_INDICATORS))

    def _filter_passthrough_arguments(self) -> dict[str, Any]:
        """
        Filters the raw arguments to include only those intended for child commands.

        Returns:
            A dictionary of arguments to pass to the enrichment commands.
        """
        keys = ["external_enrichment", "brands", "additional_fields"]
        return {k: self.raw_arguments.get(k) for k in keys if self.raw_arguments.get(k) is not None}


class EnrichmentService:
    """
    Coordinates the execution of child enrichment commands based on the request.
    """

    def __init__(self):
        self._result = EnrichmentResult()

    def execute(self, request: EnrichmentRequest) -> EnrichmentResult:
        """
        Executes the enrichment plan.

        Args:
            request: The EnrichmentRequest containing grouped indicators.

        Returns:
            An EnrichmentResult object containing aggregated outputs.
        """

        if not request.valid_indicators_by_type:
            return self._result

        tasks = self._create_execution_plan(request)

        batch_output = BatchExecutor().execute_batch([t.command for t in tasks], brands_to_run=None, verbose=False)

        for task, output in zip(tasks, batch_output):
            self._parse_task_output(task, output)

        return self._result

    def _create_execution_plan(self, request: EnrichmentRequest) -> list[EnrichmentTask]:
        """Creates a list of tasks mapping indicator types to configured Commands."""
        tasks = []
        for type_enum, indicators in request.valid_indicators_by_type.items():
            cmd = self._build_command(type_enum, indicators, request.sub_command_arguments)
            tasks.append(EnrichmentTask(type_enum, cmd))
        return tasks

    def _build_command(self, type_enum: IndicatorType, indicators: list[str], extra_args: dict) -> Command:
        """
        Constructs a single XSOAR Command pointing to the corresponding underlying script based on the type given..

        Args:
            type_enum: IndicatorType IP, Domain, etc..
            indicators: List of indicators to pass to this command
            extra_args: any other args to pass to this command (i.e. additional_fields)

        Returns:
            Command: A command object which can later be executed.
        """
        cmd_args = {type_enum.argument_key: indicators}
        cmd_args.update(extra_args)

        return Command(
            name=type_enum.command_name,
            args=cmd_args,
            command_type=CommandType.INTERNAL,
            ignore_using_brand=True,
            is_multi_input=True,
            is_aggregated_output=True,
        )

    def _parse_task_output(self, task: EnrichmentTask, task_output: CommandProcessResults) -> None:
        """
        Parses the output of a BatchExecutor task and updates the result object.
        Handles Error extraction, HumanReadable aggregation, and Context extraction.
        """
        human_readable_strings = []

        for entry, hr, err in task_output:
            if err:
                self._result.markdown_sections.append(f"### Error from {task.command.name}\n{err}")
                continue

            valid_hr = hr
            if not valid_hr and isinstance(entry, dict):
                valid_hr = entry.get("HumanReadable")

            if valid_hr:
                human_readable_strings.append(valid_hr)

            entry_context = entry.get("EntryContext") or entry.get("Contents") or {}
            if isinstance(entry_context, dict):
                self._result.raw_context.update(entry_context)
                self._add_new_keys_to_enrichment_data(task.indicator_type, entry_context)

        if human_readable_strings:
            combined_md = "\n".join(human_readable_strings)
            header = f"### {task.command.name}"
            self._result.markdown_sections.append(f"{header}\n{combined_md}")

    def _add_new_keys_to_enrichment_data(self, indicator_type: IndicatorType, context: ContextResult) -> None:
        """
        Extracts specific enrichment data based on the indicator type prefix and add "Type" key to it.

        Args:
            indicator_type: The configuration enum for the current indicator type.
            context: The raw EntryContext dictionary from the sub-command.
        """
        for key, value in context.items():
            if key.startswith(indicator_type.context_prefix):
                items = value if isinstance(value, list) else [value]
                for item in items:
                    if isinstance(item, dict):
                        unified_entry = item.copy()
                        unified_entry["Type"] = indicator_type.display_name
                        self._result.enriched_data.append(unified_entry)


class ResponseFormatter:
    """
    Transforms the internal EnrichmentResult into the final XSOAR CommandResults object.
    """

    def format(self, result: EnrichmentResult, request: EnrichmentRequest) -> CommandResults:
        """
        Formats the result into Markdown and Context.

        Args:
            result: The results from the service execution.
            request: The original request (used for error collection and raw_context flags).

        Returns:
            A populated CommandResults object.
        """
        markdown = self._format_markdown(result, request)
        context = self._format_context(result, request)
        return CommandResults(readable_output=markdown, outputs=context)

    def _format_markdown(self, result: EnrichmentResult, request: EnrichmentRequest) -> str:
        """Generates the final Markdown string, including notes, results, and error tables."""
        sections = []

        if request.duplicates_removed_count > 0:
            sections.append(
                f"Note: Removed {request.duplicates_removed_count} duplicate indicator occurrences before enrichment."
            )

        sections.extend(result.markdown_sections)

        error_table = self._generate_error_table(request)
        if error_table:
            sections.append(error_table)

        return "\n\n".join(sections) if sections else "No enrichment results found."

    def _remove_enrichment_keys_from_ctx(self, raw_context: ContextResult) -> ContextResult:
        filtered_context = {}
        enrichment_prefixes = tuple(indicator_type.context_prefix for indicator_type in IndicatorType)
        for k, v in raw_context.items():
            if not k.startswith(enrichment_prefixes):
                filtered_context[k] = v
        return filtered_context

    def _format_context(self, result: EnrichmentResult, request: EnrichmentRequest) -> ContextResult:
        """Generates the final Context dictionary, handling raw context filtering and unified list generation."""
        final_context = {}

        if not request.include_raw_context:
            filtered_context = self._remove_enrichment_keys_from_ctx(result.raw_context)
            final_context.update(filtered_context)
        else:
            final_context.update(result.raw_context)

        # Construct the enriched data for IndicatorEnrichment key
        final_context_output = result.enriched_data[:]
        final_context_output.extend(self._collect_error_objects(request))

        if final_context_output:
            final_context["IndicatorEnrichment"] = final_context_output

        return final_context

    def _generate_error_table(self, request: EnrichmentRequest) -> str:
        rows = self._collect_error_rows(request)
        if not rows:
            return ""
        return tableToMarkdown("Invalid or unsupported indicators", rows, headers=["Type", "Value", "Status", "Message"])

    def _collect_error_rows(self, request: EnrichmentRequest) -> list[ContextResult]:
        rows = []
        for item in request.unsupported_items:
            rows.append(
                {"Type": item.type, "Value": item.value, "Status": "Error", "Message": "No script supports this indicator type."}
            )
        for value in request.unknown_items:
            rows.append({"Type": "Unknown", "Value": value, "Status": "Error", "Message": "Not a valid indicator."})

        rows.sort(key=lambda x: (x["Type"].lower(), x["Value"].lower()))
        return rows

    def _collect_error_objects(self, request: EnrichmentRequest) -> list[ContextResult]:
        return self._collect_error_rows(request)  # type: ignore


def main():
    """
    Entry point for the indicator enrichment command.
    Orchestrates building the request, executing the service, and formatting the response.
    """
    try:
        enrichment_request_builder = EnrichmentRequestBuilder(demisto.args())
        validated_request = enrichment_request_builder.get_validated_request()

        result = EnrichmentService().execute(validated_request)

        command_results = ResponseFormatter().format(result, validated_request)

        return_results(command_results)

    except GracefulExit as info_message:
        return_results(CommandResults(readable_output=str(info_message), outputs={}))

    except ValidationError as error_message:
        demisto.debug(f"Validation Error: {error_message}")
        return_error(str(error_message))

    except Exception as system_error:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute !indicator-enrichment. Error: {str(system_error)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
