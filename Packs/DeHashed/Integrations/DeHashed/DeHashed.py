# ruff: noqa: F403, F405
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Any, Literal
from pydantic import Field, SecretStr, root_validator, validator  # pylint: disable=no-name-in-module

from ContentClientApiModule import *
from BaseContentApiModule import *

# region Constants

BASE_CONTEXT_OUTPUT_PREFIX = "DeHashed"
BASE_URL = "https://api.dehashed.com/v2/"

REQUEST_PAGE_SIZE = 5000
MAX_REQUEST_PAGE_SIZE = 10_000

# DBotScore severity labels (instance config values).
SCORE_SUSPICIOUS_LABEL = "SUSPICIOUS"
SCORE_MALICIOUS_LABEL = "MALICIOUS"

AssetType = Literal[
    "email",
    "ip_address",
    "username",
    "hashed_password",
    "name",
    "vin",
    "address",
    "phone",
    "all_fields",
]
Operation = Literal["is", "regex"]

# endregion

# region Helpers


def _build_search_query(asset_type: str, value: str, operation: str) -> str:
    """
    Builds the DeHashed query string from the user-provided ``asset_type``, ``value``, and ``operation``.

    Args:
        asset_type (str): The asset type (e.g. "email", "all_fields").
        values (str): The value to search for.
        operation (str): The operation - "is" or "regex".

    Returns:
        str: The constructed query string.
    """
    if not value:
        raise DemistoException('This command must get "value" as an argument.')

    query_value = f'"{value}"' if operation == "is" else value

    return query_value if asset_type == "all_fields" else f"{asset_type}:{query_value}"


def _filter_results(
    entries: list[dict[str, Any]],
    results_from: int,
    results_to: int,
) -> tuple[list[dict[str, Any]], int, int]:
    """
    Performs the client-side slicing of search entries given a 1-based inclusive range.

    Args:
        entries (list[dict[str, Any]]): The full list of entries from the API.
        results_from (int): 1-based start index (inclusive).
        results_to (int): 1-based end index (inclusive).

    Returns:
        tuple[list[dict[str, Any]], int, int]: A tuple of the sliced entries,
            the resolved ``results_from``, and the resolved ``results_to``.
    """
    total_entries = len(entries)
    if results_to > total_entries:
        results_to = total_entries

    return entries[results_from - 1 : results_to], results_from, results_to


def _transform_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """
    Converts a single raw v2 DeHashed entry into the CamelCase-keyed dict
    matching the v1 context paths.

    The v2 API returns most identity fields as JSON arrays
    (e.g. ``email: ["example@example.com"]``, ``phone: ["1", "2"]``), but the v1 context
    paths consumed by existing playbooks expect scalars — so list-typed fields
    are flattened into comma-separated strings while non-list fields are passed
    through unchanged. Empty / missing fields are omitted so playbook
    conditionals behave the same as in v1.

    Rules:
        - List-typed fields (e.g. ``email``, ``ip_address``, ``phone``,
          ``hashed_password``) are flattened into a comma-separated string
          (``", "`` separator).
        - Plain string / scalar fields (e.g. ``id``, ``database_name``)
          are passed through unchanged.
        - Dict / nested fields (e.g. ``raw_record``) are passed through.
        - Empty list / ``None`` / empty string fields are omitted from the
          output.
        - Keys are converted from ``snake_case`` to ``CamelCase``.

    Args:
        entry (dict[str, Any]): A single raw entry from ``response.entries``.

    Returns:
        dict[str, Any]: The flattened, CamelCase-keyed entry.
    """
    out: dict[str, Any] = {}
    for raw_key, value in entry.items():
        if isinstance(value, list):
            non_empty = [str(v) for v in value if v not in ("", None)]
            if not non_empty:
                continue
            value = ", ".join(non_empty)
        elif value in ("", None):
            continue

        out[underscoreToCamelCase(raw_key)] = value

    return out


def compute_score(entries: list[dict[str, Any]], dbot_score_config: str) -> int:
    """
    Computes the DBotScore for an email lookup based on the v2 ``database_name``
    field.

    Args:
        entries (list[dict[str, Any]]): Raw v2 entries from ``response.entries``.
        dbot_score_config (str): The configured severity label —
            ``"SUSPICIOUS"`` or ``"MALICIOUS"``.

    Returns:
        int: ``Common.DBotScore.NONE`` (0) when no breach sources are found,
        ``Common.DBotScore.SUSPICIOUS`` (2) when configured as
        ``"SUSPICIOUS"``, otherwise ``Common.DBotScore.BAD`` (3).
    """
    sources = [e.get("database_name") for e in entries if e.get("database_name")]
    if not sources:
        return Common.DBotScore.NONE
    if dbot_score_config == SCORE_SUSPICIOUS_LABEL:
        return Common.DBotScore.SUSPICIOUS  # numeric 2
    return Common.DBotScore.BAD  # numeric 3 — labeled "MALICIOUS" in UI


# endregion

# region Parameters


class Credentials(ContentBaseModel):
    """Credentials model for API authentication."""

    # username field omitted because `hiddenusername: true` in YML
    password: SecretStr


class DehashedParams(BaseParams):
    """Integration parameters for DeHashed."""

    credentials: Credentials
    email_dbot_score: str = Field("SUSPICIOUS", alias="email_dbot_score")
    integration_reliability: str = Field("B - Usually reliable", alias="integration_reliability")

    @property
    def api_key(self):
        return self.credentials.password


# endregion

# region Auth & Client


class DehashedAuthHandler(APIKeyAuthHandler):
    """Custom authentication handler for DeHashed."""

    def __init__(self, api_key: SecretStr):
        super().__init__(
            key=api_key.get_secret_value(),
            header_name="Dehashed-Api-Key",
        )


class DehashedClient(ContentClient):
    """Client for DeHashed API."""

    def __init__(self, params: DehashedParams):
        auth_handler = DehashedAuthHandler(params.api_key)
        super().__init__(
            base_url=BASE_URL,
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=auth_handler,
            client_name="DehashedClient",
        )

    def general_search(
        self,
        query: str,
        page: int | None = None,
        size: int | None = None,
        wildcard: bool | None = None,
        regex: bool | None = None,
        de_dupe: bool | None = None,
    ) -> dict[str, Any]:
        """
        Searches across the DeHashed database with various filtering options.

        Args:
            query (str): The search query string.
            page (int | None): Page number for results pagination.
            size (int | None): Number of results per page.
            wildcard (bool | None): Whether to use wildcard matching.
            regex (bool | None): Whether to use regex matching.
            de_dupe (bool | None): Whether to remove duplicate results.

        Returns:
            dict[str, Any]: The search results.
        """
        url_suffix = "/search"
        json_data: dict[str, Any] = assign_params(
            query=query,
            page=page,
            size=size,
            wildcard=wildcard,
            regex=regex,
            de_dupe=de_dupe,
        )

        demisto.debug(f"Sending a POST Request to {url_suffix}.")

        return self.post(
            url_suffix=url_suffix,
            json_data=json_data,
            resp_type="json",
        )


# endregion

# region test-module


def test_module(client: DehashedClient) -> str:
    """
    Verifies connectivity with the DeHashed API by issuing a sample search.

    Args:
        client (DehashedClient): The DeHashed API client.

    Returns:
        str: "ok" if the connection is successful, otherwise an error message.
    """
    try:
        demisto.debug("[Testing] Testing API connectivity")
        client.general_search(query="email:example@example.com", page=1, size=1)
        demisto.debug("[Testing] API connectivity test passed")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return f"AuthenticationError: Connection failed. Make sure credentials are correctly set. {str(e)}"

    demisto.debug("[Testing] All tests passed.")
    return "ok"


# endregion

# region dehashed-search


class DehashedSearchArgs(ContentBaseModel):
    asset_type: AssetType = Field(alias="asset_type")
    value: str = Field(alias="value")
    operation: Operation = Field(alias="operation")
    page: int = Field(1, alias="page")
    results_from: int = Field(1, alias="results_from")
    results_to: int = Field(50, alias="results_to")

    @validator("page", pre=True, allow_reuse=True)
    @classmethod
    def validate_page(cls, v):
        result = arg_to_number(v)
        if result is None or result <= 0:
            raise ValueError('"page" expected to be greater than zero.')
        return result

    @validator("results_from", pre=True, allow_reuse=True)
    @classmethod
    def validate_results_from(cls, v):
        result = arg_to_number(v)
        if result is None or result <= 0:
            raise ValueError('"results_from" expected to be greater than zero.')
        return result

    @validator("results_to", pre=True, allow_reuse=True)
    @classmethod
    def validate_results_to(cls, v):
        result = arg_to_number(v)
        if result is None or result <= 0:
            raise ValueError('"results_to" expected to be greater than zero.')
        return result

    @root_validator(allow_reuse=True)
    @classmethod
    def validate_range(cls, values):
        results_from = values.get("results_from")
        results_to = values.get("results_to")

        if results_to < results_from:
            raise DemistoException('"results_from" expected to be less than or equal to "results_to"')

        return values


def dehashed_search_command(client: DehashedClient, args: DehashedSearchArgs) -> list[CommandResults] | CommandResults:
    """
    Executes the dehashed-search command.

    Performs a search against the DeHashed v2 API while preserving the
    user-facing arguments and outputs of the original DeHashed integration.

    Args:
        client (DehashedClient): The DeHashed API client.
        args (DehashedSearchArgs): The command arguments.

    Returns:
        list[CommandResults] | CommandResults: The results of the command execution.
    """
    query_string = _build_search_query(args.asset_type, args.value, args.operation)
    demisto.debug(f"[dehashed-search] Built query string: {query_string!r}")

    result = client.general_search(
        query=query_string,
        page=args.page,
        size=REQUEST_PAGE_SIZE,
        wildcard=None,
        regex=True if args.operation == "regex" else None,
        de_dupe=None,
    )

    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected output from api: {result}")

    query_data = result.get("entries")
    if not query_data:
        return CommandResults(readable_output="No matching results found")

    filtered_results, results_from, results_to = _filter_results(query_data, args.results_from, args.results_to)
    demisto.debug(f"[dehashed-search] Transforming {len(filtered_results)} entries to v1-compat shape.")
    transformed_entries = [_transform_entry(entry) for entry in filtered_results]

    last_query = {
        "ResultsFrom": results_from,
        "ResultsTo": results_to,
        "DisplayedResults": len(filtered_results),
        "TotalResults": result.get("total"),
        "PageNumber": args.page,
    }

    returned_page_size = min(REQUEST_PAGE_SIZE, len(query_data))

    readable_output = tableToMarkdown(
        f"DeHashed Search - got total results: {result.get('total')}, page number: {args.page}"
        f", page size is: {returned_page_size}. returning results from {results_from} to {results_to}.",
        transformed_entries,
        headerTransform=pascalToSpace,
    )

    return [
        CommandResults(
            # NOTE: `(true)` forces a full overwrite of the LastQuery context on each run.
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.LastQuery(true)",
            outputs=last_query,
            readable_output=readable_output,
            raw_response=result,
        ),
        CommandResults(
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Search",
            outputs_key_field="Id",
            outputs=transformed_entries,
            raw_response=result,
        ),
    ]


# endregion

# region email


class EmailArgs(ContentBaseModel):
    email: list[str] = Field(alias="email")

    @validator("email", pre=True, allow_reuse=True)
    @classmethod
    def validate_email(cls, v):
        return argToList(v)


def email_command(
    client: DehashedClient,
    args: EmailArgs,
    email_dbot_score: str,
    reliability: str | None,
) -> list[CommandResults]:
    """
    Executes the email command.

    Iterates over each email address in ``args.email`` and performs a separate
    DeHashed search per email. For each email a dedicated ``CommandResults`` is
    returned, including a ``Common.EMAIL`` indicator with its own
    ``Common.DBotScore`` scoped to that email's search results.

    Args:
        client (DehashedClient): The DeHashed API client.
        args (EmailArgs): The command arguments.
        email_dbot_score (str): The configured DBotScore severity ("SUSPICIOUS" or "MALICIOUS").
        reliability (str | None): The configured reliability of the source.

    Returns:
        list[CommandResults]: A list of ``CommandResults``, one per email address
        in ``args.email``. Each entry contains its own indicator, DBotScore, and
        per-email outputs/readable output.
    """
    command_results: list[CommandResults] = []

    for indicator_value in args.email:
        query_string = _build_search_query("email", indicator_value, "is")
        demisto.debug(f"[email] Built query string for {indicator_value!r}: {query_string!r}")

        result = client.general_search(
            query=query_string,
            page=None,
            size=MAX_REQUEST_PAGE_SIZE,
            wildcard=None,
            regex=None,
            de_dupe=None,
        )

        if not isinstance(result, dict):
            raise DemistoException(f"Got unexpected output from api: {result}")

        query_data: list[dict[str, Any]] = result.get("entries") or []
        transformed_entries = [_transform_entry(entry) for entry in query_data]

        score = compute_score(query_data, email_dbot_score)
        sources = [entry.get("database_name") for entry in query_data if entry.get("database_name")]

        description: str | None = None
        if score >= Common.DBotScore.SUSPICIOUS:
            unique_sources = sorted({s for s in sources if s})
            description = f"Found in {len(unique_sources)} breach(es): {', '.join(unique_sources)}"

        dbot_kwargs: dict[str, Any] = {
            "indicator": indicator_value,
            "indicator_type": DBotScoreType.EMAIL,
            "integration_name": BASE_CONTEXT_OUTPUT_PREFIX,
            "score": score,
        }
        if reliability:
            dbot_kwargs["reliability"] = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        if description:
            dbot_kwargs["malicious_description"] = description
        dbot_score_obj = Common.DBotScore(**dbot_kwargs)

        common_email = Common.EMAIL(
            address=indicator_value,
            domain=indicator_value.split("@")[1] if "@" in indicator_value else None,
            description=description,
            dbot_score=dbot_score_obj,
        )

        if not transformed_entries:
            command_results.append(
                CommandResults(
                    indicator=common_email,
                    readable_output=f"No matching results found for {indicator_value}",
                    raw_response=result,
                )
            )
            continue

        readable_output = tableToMarkdown(
            f"DeHashed Search for {indicator_value} - got total results: {result.get('total')}",
            transformed_entries,
            headerTransform=pascalToSpace,
        )

        command_results.append(
            CommandResults(
                outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.Search",
                outputs_key_field="Id",
                outputs=transformed_entries,
                indicator=common_email,
                readable_output=readable_output,
                raw_response=result,
            )
        )

    return command_results


# endregion

# region ExecutionConfig


class DehashedExecutionConfig(BaseExecutionConfig):
    """Execution configuration for DeHashed."""

    @property
    def params(self) -> DehashedParams:
        return DehashedParams(**self._raw_params)

    @property
    def dehashed_search_args(self) -> DehashedSearchArgs:
        return DehashedSearchArgs(**self._raw_args)

    @property
    def email_args(self) -> EmailArgs:
        return EmailArgs(**self._raw_args)


# endregion

# region Main


def main() -> None:
    """
    Main entry point for the DeHashed integration.

    Initializes the execution configuration, client, and dispatches the command
    to the appropriate command function.
    """
    execution = DehashedExecutionConfig()
    command = execution.command
    demisto.debug(f"[Main] Starting to execute {command=}.")

    try:
        params = execution.params
        client = DehashedClient(params)

        match command:
            case "test-module":
                return_results(test_module(client))

            case "dehashed-search":
                return_results(dehashed_search_command(client, execution.dehashed_search_args))

            case "email":
                return_results(
                    email_command(
                        client,
                        execution.email_args,
                        email_dbot_score=params.email_dbot_score,
                        reliability=params.integration_reliability,
                    )
                )

            case _:
                raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
