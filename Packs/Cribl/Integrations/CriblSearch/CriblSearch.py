# ruff: noqa: F403, F405
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
from typing import Any
from pydantic import AnyUrl, Field, SecretStr, root_validator, validator  # pylint: disable=no-name-in-module

from ContentClientApiModule import *
from BaseContentApiModule import *

# region Constants

BASE_CONTEXT_OUTPUT_PREFIX = "Cribl"
CRIBL_TOKEN_URL = "https://login.cribl.cloud/oauth/token"
API_PREFIX = "/api/v1/m/default_search"

# endregion

# region Helpers


def _parse_ndjson(response_text: str) -> dict[str, Any]:
    """
    Parses a newline-delimited JSON (ndjson) response.

    The first line contains metadata (isFinished, job, etc.).
    Subsequent lines contain the actual event data.

    Args:
        response_text (str): The raw ndjson response text.

    Returns:
        dict[str, Any]: The parsed metadata dict with an 'events' key containing parsed event lines.
    """
    lines = [line for line in response_text.strip().split("\n") if line.strip()]
    if not lines:
        return {}
    # Parse the first line as the metadata
    try:
        metadata: dict[str, Any] = json.loads(lines[0])
    except json.JSONDecodeError as e:
        raise DemistoException(f"Failed to parse Cribl Search response metadata: {e}") from e
    # Parse remaining lines as events
    events: list[dict[str, Any]] = []
    for line in lines[1:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    metadata["events"] = events
    return metadata


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

    identifier: str
    password: SecretStr


class CriblSearchParams(BaseParams):
    """Integration parameters for Cribl Search."""

    url: AnyUrl
    credentials: Credentials

    @property
    def client_id(self):
        return self.credentials.identifier

    @property
    def client_secret(self):
        return self.credentials.password


# endregion

# region Auth & Client


class CriblSearchAuthHandler(OAuth2ClientCredentialsHandler):
    """Custom authentication handler for Cribl Search."""

    def __init__(self, client_id: str, client_secret: SecretStr):
        # Create context store for token persistence
        context_store = ContentClientContextStore(namespace="CriblSearch")

        super().__init__(
            token_url=CRIBL_TOKEN_URL,
            client_id=client_id,
            client_secret=client_secret.get_secret_value(),
            audience="https://api.cribl.cloud",
            context_store=context_store,
        )


class CriblSearchClient(ContentClient):
    """Client for Cribl Search API."""

    def __init__(self, params: CriblSearchParams):
        auth_handler = CriblSearchAuthHandler(
            params.client_id,
            params.client_secret,
        )
        super().__init__(
            base_url=urljoin(str(params.url), API_PREFIX),
            verify=params.verify,
            proxy=params.proxy,
            auth_handler=auth_handler,
            client_name="CriblSearchClient",
        )

    def search_query(
        self,
        query_id: str | None = None,
        job_id: str | None = None,
        query: str | None = None,
        earliest: str | None = None,
        latest: str | None = None,
        sample_rate: int | None = None,
        force: bool | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """
        Executes a search query.

        Args:
            query_id (str | None): The query ID.
            job_id (str | None): The job ID.
            query (str | None): The search query string.
            earliest (str | None): The earliest time boundary.
            latest (str | None): The latest time boundary.
            sample_rate (int | None): The sample rate.
            force (bool | None): Whether to force the query.
            offset (int | None): The offset for pagination.
            limit (int | None): The maximum number of results.

        Returns:
            dict[str, Any]: The search query response.
        """
        url_suffix = "/search/query"
        params: dict[str, Any] = assign_params(
            queryId=query_id,
            jobId=job_id,
            query=query,
            earliest=earliest,
            latest=latest,
            sampleRate=sample_rate,
            force=force,
            offset=offset,
            limit=limit,
        )

        demisto.debug(f"Sending a GET Request to {url_suffix}.")

        response_text = self.get(
            url_suffix=url_suffix,
            params=params,
            resp_type="text",
        )
        return _parse_ndjson(response_text)

    def search_job_status(self, job_id: str) -> dict[str, Any]:
        """
        Gets the status of a search job.

        Args:
            job_id (str): The ID of the search job.

        Returns:
            dict[str, Any]: The search job status.
        """
        url_suffix = f"/search/jobs/{job_id}/status"

        demisto.debug(f"Sending a GET Request to {url_suffix}.")

        response = self.get(
            url_suffix=url_suffix,
            resp_type="json",
        )
        items = response.get("items", [])
        return items[0] if items else {}

    def search_job_results(
        self,
        job_id: str,
        lower_bound: int | None = None,
        upper_bound: int | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """
        Gets the results of a search job.

        Args:
            job_id (str): The ID of the search job.
            lower_bound (int | None): The lower bound for results.
            upper_bound (int | None): The upper bound for results.
            offset (int | None): The offset for pagination.
            limit (int | None): The maximum number of results.

        Returns:
            dict[str, Any]: The search job results.
        """
        url_suffix = f"/search/jobs/{job_id}/results"
        params: dict[str, Any] = assign_params(
            lowerBound=lower_bound,
            upperBound=upper_bound,
            offset=offset,
            limit=limit,
        )

        demisto.debug(f"Sending a GET Request to {url_suffix}.")

        response_text = self.get(
            url_suffix=url_suffix,
            params=params,
            resp_type="text",
        )
        return _parse_ndjson(response_text)

    def search_job_create(
        self,
        query: str,
        earliest: int | None = None,
        latest: int | None = None,
        sample_rate: int | None = None,
        num_events_before: int | None = None,
        num_events_after: int | None = None,
        target_event_time: int | None = None,
        is_private: bool | None = None,
        set_options: dict[str, Any] | None = None,
        expected_output_type: str | None = None,
    ) -> dict[str, Any]:
        """
        Creates a new search job.

        Args:
            query (str): The search query string.
            earliest (int | None): The earliest time boundary.
            latest (int | None): The latest time boundary.
            sample_rate (int | None): The sample rate.
            num_events_before (int | None): Number of events before.
            num_events_after (int | None): Number of events after.
            target_event_time (int | None): Target event time.
            is_private (bool | None): Whether the job is private.
            set_options (dict[str, Any] | None): Additional options.
            expected_output_type (str | None): Expected output type.

        Returns:
            dict[str, Any]: The created search job.
        """
        url_suffix = "/search/jobs"
        json_data: dict[str, Any] = assign_params(
            query=query,
            earliest=earliest,
            latest=latest,
            sampleRate=sample_rate,
            numEventsBefore=num_events_before,
            numEventsAfter=num_events_after,
            targetEventTime=target_event_time,
            isPrivate=is_private,
            setOptions=set_options,
            expectedOutputType=expected_output_type,
        )

        demisto.debug(f"Sending a POST Request to {url_suffix}.")

        response = self.post(
            url_suffix=url_suffix,
            json_data=json_data,
            resp_type="json",
        )
        items = response.get("items", [])
        return items[0] if items else {}

    def search_jobs_list(self, job_id: str | None = None) -> list[dict[str, Any]] | dict[str, Any]:
        """
        Gets a list of all search jobs or a specific search job.

        Args:
            job_id (str | None): The ID of the search job to get.

        Returns:
            list[dict[str, Any]] | dict[str, Any]: A list of search jobs or a specific search job.
        """
        url_suffix = "/search/jobs"
        if job_id:
            url_suffix += f"/{job_id}"

        demisto.debug(f"Sending a GET Request to {url_suffix}.")

        response = self.get(
            url_suffix=url_suffix,
            resp_type="json",
        )
        items = response.get("items", [])
        if job_id:
            return items[0] if items else {}
        return items

    def search_job_update(
        self,
        job_id: str,
        status: str | None = None,
        is_private: bool | None = None,
    ) -> dict[str, Any]:
        """
        Updates a search job.

        Args:
            job_id (str): The ID of the search job to update.
            status (str | None): The new status for the job.
            is_private (bool | None): Whether the job is private.

        Returns:
            dict[str, Any]: The updated search job.
        """
        url_suffix = f"/search/jobs/{job_id}"
        json_data: dict[str, Any] = assign_params(
            status=status,
            isPrivate=is_private,
        )

        demisto.debug(f"Sending a PATCH Request to {url_suffix}.")

        response = self.patch(
            url_suffix=url_suffix,
            json_data=json_data,
            resp_type="json",
        )
        items = response.get("items", [])
        return items[0] if items else {}

    def search_job_delete(self, job_id: str) -> str:
        """
        Deletes a search job.

        Args:
            job_id (str): The ID of the search job to delete.

        Returns:
            str: The deletion response text.
        """
        url_suffix = f"/search/jobs/{job_id}"

        demisto.debug(f"Sending a DELETE Request to {url_suffix}.")

        return self.delete(
            url_suffix=url_suffix,
            resp_type="text",
        )

    def search_datasets_list(self, dataset_id: str | None = None) -> list[dict[str, Any]] | dict[str, Any]:
        """
        Gets a list of all datasets or a specific dataset.

        Args:
            dataset_id (str | None): The ID of the dataset to get.

        Returns:
            list[dict[str, Any]] | dict[str, Any]: A list of datasets or a specific dataset.
        """
        url_suffix = "/search/datasets"
        if dataset_id:
            url_suffix += f"/{dataset_id}"

        demisto.debug(f"Sending a GET Request to {url_suffix}.")

        response = self.get(
            url_suffix=url_suffix,
            resp_type="json",
        )
        items = response.get("items", [])
        if dataset_id:
            return items[0] if items else {}
        return items

    def saved_searches_list(self, search_id: str | None = None) -> list[dict[str, Any]] | dict[str, Any]:
        """
        Gets a list of all saved searches or a specific saved search.

        Args:
            search_id (str | None): The ID of the saved search to get.

        Returns:
            list[dict[str, Any]] | dict[str, Any]: A list of saved searches or a specific saved search.
        """
        url_suffix = "/search/saved"
        if search_id:
            url_suffix += f"/{search_id}"

        demisto.debug(f"Sending a GET Request to {url_suffix}.")

        response = self.get(
            url_suffix=url_suffix,
            resp_type="json",
        )
        items = response.get("items", [])
        if search_id:
            return items[0] if items else {}
        return items


# endregion

# region test-module


def test_module(client: CriblSearchClient) -> str:
    """
    Verifies the connectivity with the Cribl Search API.

    This function attempts to list datasets to ensure
    that the provided credentials and Server URL are valid and reachable.

    Args:
        client (CriblSearchClient): The Cribl Search API client.

    Returns:
        str: Returns "ok" if the connection is successful, otherwise an error message.
    """
    try:
        demisto.debug("[Testing] Testing API connectivity")
        client.search_datasets_list()
        demisto.debug("[Testing] API connectivity test passed")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return f"AuthenticationError: Connection failed. Make sure Server URL and credentials are correctly set. {str(e)}"

    demisto.debug("[Testing] All tests passed.")
    return "ok"


# endregion

# region cribl-search-query


class SearchQueryArgs(ContentBaseModel):
    # NOTE: API enforces a oneOf on this endpoint - exactly one of:
    #   (A) query_id alone, (B) job_id alone, or (C) query + earliest + latest (all three).
    # Combos (A)/(B)/(C) presence is enforced client-side via @root_validator below
    # (raises ValueError -> Pydantic ValidationError). Conflicting combos still bubble from the API.
    query_id: str | None = Field(None, alias="query_id")
    job_id: str | None = Field(None, alias="job_id")
    query: str | None = Field(None, alias="query")
    earliest: str | None = Field(None, alias="earliest")
    latest: str | None = Field(None, alias="latest")
    sample_rate: int | None = Field(None, alias="sample_rate")
    force: bool = Field(False, alias="force")
    page: int | None = Field(None, alias="page")
    limit: int | None = Field(50, alias="limit")

    @validator("sample_rate", pre=True, allow_reuse=True)
    @classmethod
    def validate_sample_rate(cls, v):
        return arg_to_number(v)

    @validator("force", pre=True, allow_reuse=True)
    @classmethod
    def validate_force(cls, v):
        return argToBoolean(v)

    @validator("page", pre=True, allow_reuse=True)
    @classmethod
    def validate_page(cls, v):
        return arg_to_number(v)

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @root_validator(allow_reuse=True)
    @classmethod
    def validate_oneof_combos(cls, values):
        query = values.get("query")
        query_id = values.get("query_id")
        job_id = values.get("job_id")
        earliest = values.get("earliest")
        latest = values.get("latest")

        if query is None and query_id is None and job_id is None:
            raise ValueError("At least one of 'query', 'query_id', or 'job_id' must be provided.")
        if query is not None and (earliest is None or latest is None):
            raise ValueError("When 'query' is provided, both 'earliest' and 'latest' must also be provided.")
        return values


def search_query_command(client: CriblSearchClient, args: SearchQueryArgs) -> CommandResults:
    """
    Executes the cribl-search-query command.

    Runs a search query against the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchQueryArgs): The command arguments.

    Returns:
        CommandResults: The results of the command execution.
    """
    offset = None
    if args.page and args.limit:
        offset = (args.page - 1) * args.limit

    results = client.search_query(
        query_id=args.query_id,
        job_id=args.job_id,
        query=args.query,
        earliest=args.earliest,
        latest=args.latest,
        sample_rate=args.sample_rate,
        force=args.force or None,
        offset=offset,
        limit=args.limit,
    )

    # Flatten job info for display
    job_info = results.get("job", {})
    display_data = {
        "isFinished": results.get("isFinished"),
        "id": job_info.get("id"),
        "status": job_info.get("status"),
        "query": job_info.get("query"),
        "earliest": job_info.get("earliest"),
        "latest": job_info.get("latest"),
        "totalEventCount": results.get("totalEventCount"),
        "persistedEventCount": results.get("persistedEventCount"),
    }

    readable_parts: list[str] = []
    readable_parts.append(
        tableToMarkdown(
            "Search Query - Job Info",
            display_data,
            headers=["isFinished", "id", "status", "query", "earliest", "latest", "totalEventCount"],
            headerTransform=lambda x: {
                "isFinished": "Is Finished",
                "id": "Job ID",
                "status": "Status",
                "query": "Query",
                "earliest": "Earliest",
                "latest": "Latest",
                "totalEventCount": "Total Events",
            }.get(x, x),
            removeNull=True,
        )
    )

    events = results.get("events", [])
    if events:
        readable_parts.append(
            tableToMarkdown(
                "Search Query - Events",
                events,
                removeNull=True,
            )
        )

    readable_output = "\n".join(readable_parts)

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchQuery",
        outputs_key_field="job.id",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region cribl-search-status


class SearchStatusArgs(ContentBaseModel):
    job_id: str = Field(alias="job_id")


def search_status_command(client: CriblSearchClient, args: SearchStatusArgs) -> CommandResults:
    """
    Executes the cribl-search-status command.

    Retrieves the status of a search job from the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchStatusArgs): The command arguments including job_id.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.search_job_status(job_id=args.job_id)

    readable_output = tableToMarkdown(
        f"Search Job {args.job_id} Status",
        results,
        headers=["status", "timeStarted", "timeCreated", "timeCompleted"],
        headerTransform=lambda x: {
            "status": "Status",
            "timeStarted": "Time Started",
            "timeCreated": "Time Created",
            "timeCompleted": "Time Completed",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchStatus",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region cribl-search-result


class SearchResultArgs(ContentBaseModel):
    job_id: str = Field(alias="job_id")
    lower_bound: int | None = Field(None, alias="lower_bound")
    upper_bound: int | None = Field(None, alias="upper_bound")
    page: int | None = Field(None, alias="page")
    limit: int | None = Field(50, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("lower_bound", pre=True, allow_reuse=True)
    @classmethod
    def validate_lower_bound(cls, v):
        return arg_to_number(v)

    @validator("upper_bound", pre=True, allow_reuse=True)
    @classmethod
    def validate_upper_bound(cls, v):
        return arg_to_number(v)

    @validator("page", pre=True, allow_reuse=True)
    @classmethod
    def validate_page(cls, v):
        return arg_to_number(v)

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def search_result_command(client: CriblSearchClient, args: SearchResultArgs) -> CommandResults:
    """
    Executes the cribl-search-result command.

    Retrieves the results of a search job from the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchResultArgs): The command arguments including job_id and pagination options.

    Returns:
        CommandResults: The results of the command execution.
    """
    offset = None
    if args.page and args.limit:
        offset = (args.page - 1) * args.limit

    results = client.search_job_results(
        job_id=args.job_id,
        lower_bound=args.lower_bound,
        upper_bound=args.upper_bound,
        offset=offset,
        limit=None if args.all_results else args.limit,
    )

    # Flatten job info for display
    job_info = results.get("job", {})
    display_data = {
        "isFinished": results.get("isFinished"),
        "id": job_info.get("id"),
        "status": job_info.get("status"),
        "query": job_info.get("query"),
        "earliest": job_info.get("earliest"),
        "latest": job_info.get("latest"),
        "totalEventCount": results.get("totalEventCount"),
        "persistedEventCount": results.get("persistedEventCount"),
    }

    readable_parts: list[str] = []
    readable_parts.append(
        tableToMarkdown(
            f"Search Job {args.job_id} Results - Job Info",
            display_data,
            headers=["isFinished", "id", "status", "query", "earliest", "latest", "totalEventCount"],
            headerTransform=lambda x: {
                "isFinished": "Is Finished",
                "id": "Job ID",
                "status": "Status",
                "query": "Query",
                "earliest": "Earliest",
                "latest": "Latest",
                "totalEventCount": "Total Events",
            }.get(x, x),
            removeNull=True,
        )
    )

    events = results.get("events", [])
    if events:
        readable_parts.append(
            tableToMarkdown(
                f"Search Job {args.job_id} Results - Events",
                events,
                removeNull=True,
            )
        )

    readable_output = "\n".join(readable_parts)

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchResult",
        outputs_key_field="job.id",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region cribl-search-job-create


class SearchJobCreateArgs(ContentBaseModel):
    query: str = Field(alias="query")
    earliest: int | None = Field(None, alias="earliest")
    latest: int | None = Field(None, alias="latest")
    sample_rate: int | None = Field(None, alias="sample_rate")
    num_events_before: int | None = Field(None, alias="num_events_before")
    num_events_after: int | None = Field(None, alias="num_events_after")
    target_event_time: int | None = Field(None, alias="target_event_time")
    is_private: bool = Field(True, alias="is_private")
    set_options: dict[str, Any] | None = Field(None, alias="set_options")
    expected_output_type: str | None = Field(None, alias="expected_output_type")

    @validator("earliest", pre=True, allow_reuse=True)
    @classmethod
    def validate_earliest(cls, v):
        return arg_to_number(v)

    @validator("latest", pre=True, allow_reuse=True)
    @classmethod
    def validate_latest(cls, v):
        return arg_to_number(v)

    @validator("sample_rate", pre=True, allow_reuse=True)
    @classmethod
    def validate_sample_rate(cls, v):
        return arg_to_number(v)

    @validator("num_events_before", pre=True, allow_reuse=True)
    @classmethod
    def validate_num_events_before(cls, v):
        return arg_to_number(v)

    @validator("num_events_after", pre=True, allow_reuse=True)
    @classmethod
    def validate_num_events_after(cls, v):
        return arg_to_number(v)

    @validator("target_event_time", pre=True, allow_reuse=True)
    @classmethod
    def validate_target_event_time(cls, v):
        return arg_to_number(v)

    @validator("is_private", pre=True, allow_reuse=True)
    @classmethod
    def validate_is_private(cls, v):
        return argToBoolean(v)

    @validator("set_options", pre=True, allow_reuse=True)
    @classmethod
    def validate_set_options(cls, v):
        return validate_json(v)


def search_job_create_command(client: CriblSearchClient, args: SearchJobCreateArgs) -> CommandResults:
    """
    Executes the cribl-search-job-create command.

    Creates a new search job in the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchJobCreateArgs): The command arguments including query and optional parameters.

    Returns:
        CommandResults: The results of the command execution, including the created job details.
    """
    results = client.search_job_create(
        query=args.query,
        earliest=args.earliest,
        latest=args.latest,
        sample_rate=args.sample_rate,
        num_events_before=args.num_events_before,
        num_events_after=args.num_events_after,
        target_event_time=args.target_event_time,
        is_private=args.is_private,
        set_options=args.set_options,
        expected_output_type=args.expected_output_type,
    )

    readable_output = tableToMarkdown(
        "Search Job Created",
        results,
        headers=["user", "id", "isPrivate", "type", "status"],
        headerTransform=lambda x: {
            "user": "User",
            "id": "ID",
            "isPrivate": "Is Private",
            "type": "Type",
            "status": "Status",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchJob",
        outputs_key_field="id",
        outputs=results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region cribl-search-job-list


class SearchJobListArgs(ContentBaseModel):
    job_id: str | None = Field(None, alias="job_id")
    limit: int | None = Field(10, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def search_job_list_command(client: CriblSearchClient, args: SearchJobListArgs) -> CommandResults:
    """
    Executes the cribl-search-job-list command.

    Retrieves a list of all search jobs or a specific search job from the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchJobListArgs): The command arguments including optional job_id, limit, and all_results.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.search_jobs_list(job_id=args.job_id)

    if args.job_id:
        # Single job result
        job = results if isinstance(results, dict) else results[0] if results else {}

        readable_output = tableToMarkdown(
            f"Search Job {args.job_id} Details",
            job,
            headers=["user", "id", "isPrivate", "type", "status"],
            headerTransform=lambda x: {
                "user": "User",
                "id": "ID",
                "isPrivate": "Is Private",
                "type": "Type",
                "status": "Status",
            }.get(x, x),
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchJob",
            outputs_key_field="id",
            outputs=job,
            readable_output=readable_output,
            raw_response=results,
        )

    # List of jobs
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(
        "Search Jobs List",
        paginated_results,
        headers=["user", "id", "isPrivate", "type", "status"],
        headerTransform=lambda x: {
            "user": "User",
            "id": "ID",
            "isPrivate": "Is Private",
            "type": "Type",
            "status": "Status",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchJob",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region cribl-search-job-update


class SearchJobUpdateArgs(ContentBaseModel):
    job_id: str = Field(alias="job_id")
    status: str | None = Field(None, alias="status")
    is_private: bool | None = Field(None, alias="is_private")

    @validator("is_private", pre=True, allow_reuse=True)
    @classmethod
    def validate_is_private(cls, v):
        if v is None:
            return None
        return argToBoolean(v)

    @root_validator(allow_reuse=True)
    @classmethod
    def validate_at_least_one_field(cls, values):
        status = values.get("status")
        is_private = values.get("is_private")
        if status is None and is_private is None:
            raise ValueError("At least one of 'status' or 'is_private' must be provided.")
        return values


def search_job_update_command(client: CriblSearchClient, args: SearchJobUpdateArgs) -> CommandResults:
    """
    Executes the cribl-search-job-update command.

    Updates an existing search job in the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchJobUpdateArgs): The command arguments including job_id and fields to update.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.search_job_update(
        job_id=args.job_id,
        status=args.status,
        is_private=args.is_private,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchJob",
        outputs_key_field="id",
        outputs=results,
        readable_output=f"The job {args.job_id} has been successfully updated.",
        raw_response=results,
    )


# endregion

# region cribl-search-job-delete


class SearchJobDeleteArgs(ContentBaseModel):
    job_id: str = Field(alias="job_id")


def search_job_delete_command(client: CriblSearchClient, args: SearchJobDeleteArgs) -> CommandResults:
    """
    Executes the cribl-search-job-delete command.

    Deletes a search job from the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchJobDeleteArgs): The command arguments including the job_id to delete.

    Returns:
        CommandResults: A message indicating the successful deletion of the job.
    """
    client.search_job_delete(job_id=args.job_id)

    return CommandResults(readable_output=f"The job {args.job_id} has been successfully deleted.")


# endregion

# region cribl-search-dataset-list


class SearchDatasetListArgs(ContentBaseModel):
    dataset_id: str | None = Field(None, alias="dataset_id")
    limit: int | None = Field(10, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def search_dataset_list_command(client: CriblSearchClient, args: SearchDatasetListArgs) -> CommandResults:
    """
    Executes the cribl-search-dataset-list command.

    Retrieves a list of all datasets or a specific dataset from the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SearchDatasetListArgs): The command arguments including optional dataset_id, limit, and all_results.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.search_datasets_list(dataset_id=args.dataset_id)

    if args.dataset_id:
        # Single dataset result
        dataset = results if isinstance(results, dict) else results[0] if results else {}

        readable_output = tableToMarkdown(
            f"Dataset {args.dataset_id} Details",
            dataset,
            headers=["id", "provider", "type", "region"],
            headerTransform=lambda x: {
                "id": "ID",
                "provider": "Provider",
                "type": "Type",
                "region": "Region",
            }.get(x, x),
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchDataset",
            outputs_key_field="id",
            outputs=dataset,
            readable_output=readable_output,
            raw_response=results,
        )

    # List of datasets
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(
        "Datasets List",
        paginated_results,
        headers=["id", "provider", "type", "region"],
        headerTransform=lambda x: {
            "id": "ID",
            "provider": "Provider",
            "type": "Type",
            "region": "Region",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SearchDataset",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region cribl-saved-search-list


class SavedSearchListArgs(ContentBaseModel):
    search_id: str | None = Field(None, alias="search_id")
    limit: int | None = Field(10, alias="limit")
    all_results: bool = Field(False, alias="all_results")

    @validator("limit", pre=True, allow_reuse=True)
    @classmethod
    def validate_limit(cls, v):
        return arg_to_number(v)

    @validator("all_results", pre=True, allow_reuse=True)
    @classmethod
    def validate_all_results(cls, v):
        return argToBoolean(v)


def saved_search_list_command(client: CriblSearchClient, args: SavedSearchListArgs) -> CommandResults:
    """
    Executes the cribl-saved-search-list command.

    Retrieves a list of all saved searches or a specific saved search from the Cribl Search API.

    Args:
        client (CriblSearchClient): The Cribl Search API client.
        args (SavedSearchListArgs): The command arguments including optional search_id, limit, and all_results.

    Returns:
        CommandResults: The results of the command execution.
    """
    results = client.saved_searches_list(search_id=args.search_id)

    if args.search_id:
        # Single saved search result
        saved_search = results if isinstance(results, dict) else results[0] if results else {}

        readable_output = tableToMarkdown(
            f"Saved Search {args.search_id} Details",
            saved_search,
            headers=["id", "description", "name", "query"],
            headerTransform=lambda x: {
                "id": "ID",
                "description": "Description",
                "name": "Name",
                "query": "Query",
            }.get(x, x),
            removeNull=True,
        )

        return CommandResults(
            outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SavedSearch",
            outputs_key_field="id",
            outputs=saved_search,
            readable_output=readable_output,
            raw_response=results,
        )

    # List of saved searches
    paginated_results = truncate_results(results, limit=args.limit, all_results=args.all_results)  # type: ignore[arg-type]
    readable_output = tableToMarkdown(
        "Saved Searches List",
        paginated_results,
        headers=["id", "description", "name", "query"],
        headerTransform=lambda x: {
            "id": "ID",
            "description": "Description",
            "name": "Name",
            "query": "Query",
        }.get(x, x),
        removeNull=True,
    )

    return CommandResults(
        outputs_prefix=f"{BASE_CONTEXT_OUTPUT_PREFIX}.SavedSearch",
        outputs_key_field="id",
        outputs=paginated_results,
        readable_output=readable_output,
        raw_response=results,
    )


# endregion

# region ExecutionConfig


class CriblSearchExecutionConfig(BaseExecutionConfig):
    """Execution configuration for Cribl Search."""

    @property
    def params(self) -> CriblSearchParams:
        return CriblSearchParams(**self._raw_params)

    @property
    def search_query_args(self) -> SearchQueryArgs:
        return SearchQueryArgs(**self._raw_args)

    @property
    def search_status_args(self) -> SearchStatusArgs:
        return SearchStatusArgs(**self._raw_args)

    @property
    def search_result_args(self) -> SearchResultArgs:
        return SearchResultArgs(**self._raw_args)

    @property
    def search_job_create_args(self) -> SearchJobCreateArgs:
        return SearchJobCreateArgs(**self._raw_args)

    @property
    def search_job_list_args(self) -> SearchJobListArgs:
        return SearchJobListArgs(**self._raw_args)

    @property
    def search_job_update_args(self) -> SearchJobUpdateArgs:
        return SearchJobUpdateArgs(**self._raw_args)

    @property
    def search_job_delete_args(self) -> SearchJobDeleteArgs:
        return SearchJobDeleteArgs(**self._raw_args)

    @property
    def search_dataset_list_args(self) -> SearchDatasetListArgs:
        return SearchDatasetListArgs(**self._raw_args)

    @property
    def saved_search_list_args(self) -> SavedSearchListArgs:
        return SavedSearchListArgs(**self._raw_args)


# endregion

# region Main


def main() -> None:
    """
    Main entry point for the Cribl Search integration.

    Initializes the execution configuration, client, and dispatches the command
    to the appropriate command function.
    """
    execution = CriblSearchExecutionConfig()
    command = execution.command
    demisto.debug(f"[Main] Starting to execute {command=}.")

    try:
        params = execution.params
        client = CriblSearchClient(params)

        match command:
            case "test-module":
                return_results(test_module(client))

            case "cribl-search-query":
                return_results(search_query_command(client, execution.search_query_args))

            case "cribl-search-status":
                return_results(search_status_command(client, execution.search_status_args))

            case "cribl-search-result":
                return_results(search_result_command(client, execution.search_result_args))

            case "cribl-search-job-create":
                return_results(search_job_create_command(client, execution.search_job_create_args))

            case "cribl-search-job-list":
                return_results(search_job_list_command(client, execution.search_job_list_args))

            case "cribl-search-job-update":
                return_results(search_job_update_command(client, execution.search_job_update_args))

            case "cribl-search-job-delete":
                return_results(search_job_delete_command(client, execution.search_job_delete_args))

            case "cribl-search-dataset-list":
                return_results(search_dataset_list_command(client, execution.search_dataset_list_args))

            case "cribl-saved-search-list":
                return_results(saved_search_list_command(client, execution.saved_search_list_args))

            case _:
                raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# endregion
