import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Cisco ThreatGird integration
"""
import copy
import hashlib
from datetime import datetime
from typing import (
    Any,
)
from collections.abc import Callable, MutableMapping, MutableSequence

DEFAULT_INTERVAL = 90
DEFAULT_TIMEOUT = 600

MIN_PAGE_NUM = 1
MAX_PAGE_SIZE = 50
MIN_PAGE_SIZE = 1
MAX_LIMIT = 50
MIN_LIMIT = 1

API_V2_PREFIX = "/api/v2/"
API_V3_PREFIX = "/api/v3/"

MAX_DAYS_DIFF = 14
TIME_FORMAT = "%Y-%m-%d"

ANALYSIS_OUTPUTS: dict[str, Any] = {
    "artifacts": {
        "output": "ArtifactAnalysis",
        "keys_to_delete": ["antivirus", "forensics"],
    },
    "iocs": {"output": "IOCAnalysis", "keys_to_delete": ["data"]},
    "metadata": {"output": "AnalysisMetadata", "keys_to_get": "malware_desc"},
    "network_stream": {
        "output": "NetworkAnalysis",
        "keys_to_delete": ["ssl", "relation"],
    },
    "processes": {"output": "ProcessAnalysis", "keys_to_delete": ["startup_info"]},
    "annotations": {"output": "SampleAnnotations", "keys_to_get": "network"},
}

PREFIX_OUTPUTS: dict[str, Any] = {
    "artifact": "Artifact",
    "path": "Path",
    "domain": "Domain",
    "network_stream": "NetworkStreams",
    "url": "Url",
    "ip": "Ip",
    "registry_key": "RegistryKey",
}

DEFAULT_MALICIOUS_THRESHOLD = 85
DEFAULT_SUSPICIOUS_THRESHOLD = 50


class Client(BaseClient):
    """API Client to communicate with ThreatGrid API."""

    def __init__(self, base_url: str, api_token: str, proxy: bool, verify: bool):
        self.api_key = api_token
        headers = {
            "Authorization": f"bearer {self.api_key}",
        }
        super().__init__(
            base_url=base_url,
            verify=verify,
            headers=headers,
            proxy=proxy,
        )

    def get_sample(
        self,
        sample_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        artifact: str | None = None,
        summary: str | None = None,
        user_only: bool | None = False,
        org_only: bool | None = False,
        sha1: str | None = None,
        sha256: str | None = None,
        md5: str | None = None,
    ) -> dict[str, Any]:
        """Retrieves the Sample Info record of a submission by sample ID.

        Args:
            sample_id (str, optional): The sample ID.
            limit (int, optional): The number of items per page.
            offset (int, optional): Page number of paginated results.
            artifact (str, optional): The artifact to download.
                Sample ID is required when choosing 'artifact'.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "offset": offset,
                "user_only": user_only,
                "org_only": org_only,
                "md5": md5,
                "sha1": sha1,
                "sha256": sha256,
            }
        )

        url_suffix = f"samples/{sample_id}" if sample_id else "samples"
        url_suffix = f"{url_suffix}/summary" if summary else url_suffix

        if artifact:
            resp_type = "content"
            url_suffix = f"{url_suffix}/{artifact}"
        else:
            resp_type = "json"

        return self._http_request(
            "GET",
            urljoin(API_V2_PREFIX, url_suffix),
            params=params,
            resp_type=resp_type,
        )

    def analysis_sample(
        self,
        sample_id: str,
        analysis_type: str,
        arg_value: str | None = None,
    ) -> dict[str, Any]:
        """Get analysis data for a specific sample.

        Args:
            sample_id (str): The sample ID.
            analysis_type (str): URL parameter (processes/network-streams/iocs/annotations).
            arg_value (str, optional): argument value for the URL parameter
                    (specific process/network-stream/ioc).

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        analysis_type = (
            f"{analysis_type}s" if analysis_type == "network_stream" else analysis_type
        )
        url_prefix = f"{analysis_type}/{arg_value}" if arg_value else analysis_type

        return self._http_request(
            "GET",
            urljoin(API_V2_PREFIX, f"samples/{sample_id}/analysis/{url_prefix}"),
        )

    def whoami(self) -> dict[str, Any]:
        """Get details about correct login user and organization.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        return self._http_request("GET", urljoin(API_V3_PREFIX, "session/whoami"))

    def list_associated_samples(
        self,
        arg_name: str,
        arg_value: str,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """Returns a list of samples associated to the domain /
            IP / URL / path / artifact / registry key that specified.

        Args:
            arg_name (str): argument name (URL parameter).
            arg_value (str): argument value (specific value for the URL parameter).

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        params = remove_empty_elements(
            {
                "limit": limit,
                "offset": offset,
            }
        )
        return self._http_request(
            "GET",
            urljoin(API_V2_PREFIX, f"{arg_name}s/{arg_value}/samples"),
            params=params,
        )

    def get_sample_state(self, sample_id: str) -> dict[str, Any]:
        """Get the sample state.

        Args:
            sample_id (str): The sample ID.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        return self._http_request(
            "GET", urljoin(API_V2_PREFIX, f"samples/{sample_id}/state")
        )

    def upload_sample(
        self,
        files: dict | None = None,
        payload: dict | None = None,
        private: bool | None = None,
        vm: str | None = None,
        playbook: str | None = None,
    ) -> dict[str, Any]:
        """Submits a sample (file or URL) to Malware Analytics for analysis.
        Args:
            files (dict, optional): File name and path in XSOAR.
            payload (dict, optional): The URL object.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        params = remove_empty_elements(
            {"private": private, "vm": vm, "playbook": playbook}
        )

        # When the sample is a file, send the api_key via the data request
        if files:
            demisto.debug("the sample id is a file, added the api_key to data request")
            if self._headers:
                self._headers.pop("Authorization")
            payload = {"api_key": self.api_key, "classify": True}

        return self._http_request(
            "POST",
            urljoin(API_V2_PREFIX, "samples"),
            files=files,
            data=payload,
            params=params,
        )

    def associated_samples(
        self, arg_name: str, arg_value: str, url_arg: str
    ) -> dict[str, Any]:
        """Returns a list of domains / URLs associated with the IP or
            list of IPs / URLs associated with the domain.

        Args:
            arg_name (str): argument name (URL parameter: IPs/domains).
            arg_value (str): argument value (specific value for the URL parameter).
            url_arg (str): URL argument (URL parameter: IPs/URLs/domains).

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        url_prefix = f"{arg_name}s/{arg_value}/{url_arg}"
        return self._http_request(
            "GET",
            urljoin(API_V2_PREFIX, url_prefix),
        )

    def get_feeds(
        self,
        arg_name: str,
        arg_value: Any | None,
        ioc: Any | None,
        severity: int | None,
        confidence: int | None,
        sample_id: str | None = None,
        before: str | None = None,
        after: Any | None = None,
        user_only: bool | None = False,
        org_only: bool | None = False,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """Retrieves a list of ips/iocs/domains/urls/paths associated with
            an Indicator of Compromise (IOC).

        Args:
            arg_name (str): argument name (URL parameter: IPs/domains).
            arg_value (str): argument value for the arg_name.
            ioc (str): The IOC to get.
            severity (int, optional): The severity score. Defaults to 80.
            confidence (int, optional): The confidence score. Defaults to 80.
            sample_id (str, optional): The sample ID. Defaults to None.
            before (str, optional): Date. Restricting results to samples submitted before it.
                Defaults to None.
            after (str, optional): Date. Restricting results to samples submitted after it.
                Defaults to None.
            user_only (bool, optional): Match against samples submitted by your user.
                Defaults to False.
            org_only (bool, optional): Match against samples submitted by your organization.
                Defaults to False.
            limit (int, optional): The number of items per page. Defaults to None.
            offset (int, optional): Page number of paginated results. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        params = remove_empty_elements(
            {
                arg_name: arg_value,
                "sample_id": sample_id,
                "severity": severity,
                "ioc": ioc,
                "before": before,
                "after": after,
                "user_only": user_only,
                "org_only": org_only,
                "confidence": confidence,
                "limit": limit,
                "offset": offset,
            }
        )

        return self._http_request(
            "GET",
            urljoin(API_V2_PREFIX, f"iocs/feeds/{arg_name}s"),
            params=params,
        )

    def search_submission(
        self,
        query: str | None = None,
        sort_by: str | None = None,
        term: str | None = None,
        state: str | None = None,
        before: str | None = None,
        after: str | None = None,
        user_only: bool | None = None,
        org_only: bool | None = None,
        highlight: bool | None = None,
        sort_order: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """Search submission that has been submitted to Cisco Malware Analytics for
            analysis has an associated Submission record.

        Args:
            query (str, optional): Query text. Defaults to None.
            sort_by (str, optional): An argument to sort by. Defaults to None.
            term (str, optional): Query terms to search. Defaults to None.
            state (str, optional): The state of the sample, one of a stable set of strings
                "wait, prep, run, proc, succ, fail". Defaults to None.
            before (str, optional): Date. Restricting results to samples submitted before it.
                Defaults to None.
            after (str, optional): Date. Restricting results to samples submitted after it.
                Defaults to None.
            highlight (bool, optional): Provide a 'matches' field in results, indicating which
                fields were matched. Defaults to None.
            sort_order (str, optional): Sort order argument. Defaults to None.
            user_only (bool, optional): Match against samples submitted by your user.
                Defaults to False.
            org_only (bool, optional): Match against samples submitted by your organization.
                Defaults to False.
            limit (int, optional): The number of items per page. Defaults to None.
            offset (int, optional): Page number of paginated results. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        params = remove_empty_elements(
            {
                "q": query,
                "sort_by": sort_by,
                "term": term,
                "state": state,
                "before": before,
                "after": after,
                "user_only": user_only,
                "org_only": org_only,
                "highlight": highlight,
                "sort_order": sort_order,
                "limit": limit,
                "offset": offset,
            }
        )
        return self._http_request(
            "GET",
            urljoin(API_V2_PREFIX, "search/submissions"),
            params=params,
        )

    def search(
        self,
        arg_name: str,
        arg_value: str,
    ) -> dict[str, Any]:
        """Get details about specified IP/URL/domain/path.

        Args:
            arg_name (str, optional): The argument name.
            arg_value (str, optional): The argument value.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        return self._http_request(
            "GET",
            urljoin(API_V2_PREFIX, f"{arg_name}s/{arg_value}"),
        )

    def get_rate_limit(
        self,
        login: str,
    ) -> dict[str, Any]:
        """Get rate limit for a specific user name.

        Args:
            login (str): User name.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        return self._http_request(
            "GET",
            urljoin(API_V3_PREFIX, f"users/{login}/rate-limit"),
        )

    def get_specific_feed(
        self,
        feed_name: str,
        output_type: str,
        before: str | None = None,
        after: str | None = None,
    ) -> dict[str, Any]:
        """Gets a specific threat feed.

        Args:
            feed_name (str): The feed name.
            output_type (str): The output type (json,csv,stix,snort,txt).
            before (str, optional): Date. Restricting results to samples submitted before it.
                Defaults to None.
            after (str, optional): Date. Restricting results to samples submitted after it.
                Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ThreatGrid.
        """
        params = remove_empty_elements({"before": before, "after": after})
        return self._http_request(
            method="GET",
            url_suffix=urljoin(API_V3_PREFIX, f"feeds/{feed_name}.{output_type}"),
            params=params,
        )


def search_submission_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Search submission that has been submitted to Cisco Malware Analytics
        for analysis has an associated Submission record.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    query = args.get("query")
    sort_by = args.get("sort_by")
    term = args.get("term")
    state = args.get("state")
    sort_order = args.get("sort_order")
    highlight = optional_arg_to_boolean(args.get("highlight"))
    before = args.get("before")
    after = args.get("after")
    user_only = optional_arg_to_boolean(args.get("user_only"))
    org_only = optional_arg_to_boolean(args.get("org_only"))

    limit, offset, pagination_message = pagination(args)

    response = client.search_submission(
        query=query,
        sort_by=sort_by,
        term=term,
        state=state,
        before=before,
        after=after,
        user_only=user_only,
        org_only=org_only,
        highlight=highlight,
        sort_order=sort_order,
        limit=limit,
        offset=offset,
    )
    submissions = [
        delete_keys_from_dict(
            sample["item"],
            ["login", "organization_id", "vm_runtime", "login", "tags"],
        )
        for sample in response["data"]["items"]
    ]
    readable_output = tableToMarkdown(
        name="Samples Submitted :",
        metadata=pagination_message,
        t=submissions,
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.Sample",
        outputs_key_field="sample",
        outputs=submissions,
        raw_response=response,
    )


def search_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Search submission that has been submitted to Cisco Malware Analytics
        for analysis has an associated Submission record.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    arg_name = get_arg_from_command_name(args["command_name"], 2)
    arg_value = args[arg_name]

    arg_value = validate_url_template(arg_value) if arg_name == "url" else arg_value
    arg_value = url_to_sha256(arg_value) if arg_name == "url" else arg_value

    response = client.search(
        arg_name=arg_name,
        arg_value=arg_value,
    )
    search_data = (
        response["data"]["url"] if response["data"].get("url") else response["data"]
    )

    readable_output = tableToMarkdown(
        name=f"{arg_name} data:", t=search_data, headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.search",
        outputs_key_field=arg_name,
        outputs=search_data,
        raw_response=response,
    )


def list_associated_samples_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Returns a list of samples associated to the
        domain / IP / URL / path / artifact / registry key that specified.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    arg_name = get_arg_from_command_name(args["command_name"], 2)
    arg_value = args[arg_name]

    arg_value = validate_url_template(arg_value) if arg_name == "url" else arg_value
    arg_value = url_to_sha256(arg_value) if arg_name == "url" else arg_value

    limit, offset, pagination_message = pagination(args)
    response = client.list_associated_samples(
        arg_name,
        arg_value,
        limit,
        offset,
    )

    samples = response["data"]["samples"]
    sample_list = delete_key_from_list(
        samples, ["details", "relation", "owner", "iocs"]
    )

    readable_output = tableToMarkdown(
        name=f"List of samples associated to the {arg_name} - {arg_value} : ",
        metadata=pagination_message,
        t=sample_list,
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"ThreatGrid.{PREFIX_OUTPUTS[arg_name]}AssociatedSample",
        outputs_key_field="sample",
        outputs=response["data"],
        raw_response=response["data"],
    )


def analysis_sample_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Get data about a specific IOC / processes / artifact / network-stream
        from the relevant section of the sample's analysis.json.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    url_param = get_arg_from_command_name(args["command_name"], 3)
    arg_name = ANALYSIS_ARG_NAME.get(url_param)
    arg_value = args.get(arg_name) if arg_name else None
    sample_id = args["sample_id"]
    response = client.analysis_sample(sample_id, url_param, arg_value)
    if not response or not response.get("data"):
        return CommandResults(
            readable_output=f"### No results were found for sample_id {sample_id}"
        )

    items = (
        response["data"]["items"] if response["data"].get("items") else response["data"]
    )

    items_to_display = (
        parse_output(items, url_param) if isinstance(items, dict) else items
    )

    response["data"].update({"sample_id": sample_id})

    readable_output = tableToMarkdown(
        name="List of samples analysis:",
        t=items_to_display,
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'ThreatGrid.{ANALYSIS_OUTPUTS[url_param]["output"]}',
        outputs_key_field=arg_name,
        outputs=response["data"],
        raw_response=response,
    )


def get_rate_limit_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Get rate limit for a specific user name.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    login = args["login"]
    entity_type = args["entity_type"]
    response = client.get_rate_limit(login)

    entity_data = response["data"][entity_type]

    readable_output = tableToMarkdown(
        name=f"{entity_type} rate limit:",
        t=entity_data,
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.RateLimit",
        outputs=entity_data,
        raw_response=response,
    )


def who_am_i_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Get data about a specific IOC / processes / artifact / network-stream
        from the relevant section of the sample's analysis.json.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.whoami()

    whoami_data = response["data"]
    whoami_data = delete_keys_from_dict(whoami_data, ["properties"])
    readable_output = tableToMarkdown(
        name="Who am I ?", t=whoami_data, headerTransform=string_to_table_header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.User",
        outputs_key_field="email",
        outputs=whoami_data,
        raw_response=response,
    )


def get_specific_feed_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Get data about a specific IOC / processes / artifact / network-stream
        from the relevant section of the sample's analysis.json.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    feed_name = args["feed_name"]
    output_type = args["output_type"]
    before = args.get("before")
    after = args.get("after")

    response = client.get_specific_feed(
        feed_name,
        output_type,
        before,
        after,
    )

    readable_output = tableToMarkdown(
        name="Specific feed:",
        t=response,
        headers=["sample", "description"],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.Feed",
        outputs_key_field="sample",
        outputs=response,
        raw_response=response,
    )


def associated_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Returns a list of domains / URLs associated with the IP or
        list of IPs / URLs associated with the domain.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    command_name = args["command_name"]
    arg_name = get_arg_from_command_name(command_name, 2)
    url_arg = get_arg_from_command_name(command_name, 4)
    arg_value = args[arg_name]

    response = client.associated_samples(arg_name, arg_value, url_arg)
    items = response["data"][url_arg]

    item_list = delete_key_from_list(items, ["details"]) if url_arg == "urls" else items

    readable_output = tableToMarkdown(
        name=f"List of {url_arg} associated to the {arg_name} - {arg_value} :",
        t=item_list,
        headerTransform=string_to_table_header,
    )
    output_suffix = f"{arg_name.capitalize()}Associated{url_arg[:-1].capitalize()}"
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"ThreatGrid.{output_suffix}",
        outputs_key_field=arg_name,
        outputs=response["data"],
        raw_response=response["data"],
    )


def feeds_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Retrieves a list of domain / IP / URL / path / artifact / registry key that specified,
        associated with an Indicator of Compromise (IOC).

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    arg_name = get_arg_from_command_name(args["command_name"], 3)

    arg_value = args.get(arg_name)
    sample_id = args.get("sample_id")
    severity = arg_to_number(args.get("severity"))
    confidence = arg_to_number(args.get("confidence"))
    ioc = args.get("ioc")
    before = args.get("before")
    after = args.get("after")
    user_only = optional_arg_to_boolean(args.get("user_only"))
    org_only = optional_arg_to_boolean(args.get("org_only"))

    limit, offset, pagination_message = pagination(args)

    response = client.get_feeds(
        arg_name,
        arg_value,
        ioc,
        severity=severity,
        confidence=confidence,
        sample_id=sample_id,
        before=before,
        after=after,
        user_only=user_only,
        org_only=org_only,
        limit=limit,
        offset=offset,
    )

    feeds_list = response["data"]["items"]
    readable_output = tableToMarkdown(
        name=f"Feeds IOCs list {arg_name} :",
        metadata=pagination_message,
        t=feeds_list,
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"ThreatGrid.{PREFIX_OUTPUTS[arg_name]}",
        outputs_key_field="sample_id",
        outputs=feeds_list,
        raw_response=response,
    )


def upload_sample_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Submits a sample (file ID or URL) to Malware Analytics for analysis.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    file_id = args.get("file_id")
    url = args.get("url")
    private = optional_arg_to_boolean(args.get("private"))
    vm = args.get("vm")
    playbook = args.get("playbook")

    if (file_id and url) or (not file_id and not url):
        raise ValueError("You must specified file_id or url, not both.")

    if file_id:
        file = parse_file_to_sample(file_id)
        response = client.upload_sample(
            files=file, private=private, vm=vm, playbook=playbook
        )
    else:
        payload = {"url": url}
        response = client.upload_sample(
            payload=payload, private=private, vm=vm, playbook=playbook
        )
    uploaded_sample = response["data"]

    return CommandResults(
        raw_response=uploaded_sample,
        outputs=uploaded_sample,
        outputs_prefix="ThreatGrid.Sample",
        outputs_key_field="id",
    )


def get_sample_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Retrieves the Sample Info record of a submission by sample ID.

    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    arg_name = get_arg_from_command_name(args["command_name"], 2)
    is_summary = get_arg_from_command_name(args["command_name"], 3)
    arg_name = is_summary if is_summary == "summary" else arg_name
    sample_id = args.get("sample_id")
    sha1 = args.get("sha1")
    sha256 = args.get("sha256")
    md5 = args.get("md5")
    user_only = args.get("user_only")
    org_only = args.get("org_only")

    artifact = args.get("artifact")
    limit, offset, pagination_message = pagination(args)

    if artifact and not sample_id:
        raise ValueError(
            "When 'artifact' argument is specified - 'sample_id' argument is required"
        )

    response = client.get_sample(
        sample_id=sample_id,
        limit=limit,
        offset=offset,
        artifact=artifact,
        summary=SAMPLE_ARGS[arg_name]["summary"],  # type: ignore[arg-type]
        user_only=user_only,
        org_only=org_only,
        sha1=sha1,
        sha256=sha256,
        md5=md5,
    )

    sample_details = response
    content_format = "json"

    if artifact:
        content_format = "html"
        return fileResult(filename=f"{sample_id}-{artifact}", data=response)
    else:
        sample_details = dict_safe_get(response, ["data", "items"]) or response.get(
            "data"
        )  # type: ignore[assignment]

    readable_output = tableToMarkdown(
        name=SAMPLE_ARGS[arg_name]["name"],
        t=sample_details,
        metadata=pagination_message,
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        content_format=content_format,
        outputs_prefix=SAMPLE_ARGS[arg_name][
            "outputs_prefix"
        ],  # type: ignore[arg-type]
        outputs_key_field=SAMPLE_ARGS[arg_name]["outputs_key_field"],
        outputs=sample_details,
        raw_response=response,
    )


def sample_state_get_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """Get sample state.
    Args:
        client (Client): ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: status, outputs, readable outputs and raw response for XSOAR.
    """
    sample_id = args["sample_id"]
    response = client.get_sample_state(sample_id)
    output = response["data"]

    readable_output = "The command was executed successfully"
    return CommandResults(
        readable_output=readable_output, outputs=output, raw_response=output
    )


@polling_function(
    name="threat-grid-sample-upload",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    poll_message="Upload sample is executing",
    requires_polling_arg=False,
)
def schedule_command(args: dict[str, Any], client: Client) -> PollResult:
    """Build scheduled command if sample state is not 'succ'.
    Args:
        client (Client): ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        ScheduledCommand: Command, args, timeout and interval for CommandResults.
    """
    first_run = False
    if "sample_id" not in args:
        first_run = True
        command_results = upload_sample_command(client, args)
        if not dict_safe_get(command_results.raw_response, ["analyzing"]):
            return PollResult(
                response=CommandResults(
                    readable_output=(
                        "The file has not been analyzed. Reason:"
                        " The file type is not supported or the file is low risk "
                    )
                ),
                continue_to_poll=False,
            )
        sample_id = command_results.raw_response["id"]  # type: ignore[index]
        args["sample_id"] = sample_id
    else:
        command_results = sample_state_get_command(client, args)

    sample_state = dict_safe_get(command_results.raw_response, ["state"])
    sample_id = args["sample_id"]
    args_for_next_run = {"sample_id": sample_id, **args}

    if sample_state == "succ":
        command_results = get_sample_command(client, args)
        return PollResult(
            response=command_results,
            continue_to_poll=False,
        )

    if sample_state == "fail":
        # In case the upload not succeeded raise the error
        raise DemistoException(f"Uploading {args['sample_id']} to ThreatGrid failed")

    return PollResult(
        response=command_results,
        continue_to_poll=True,
        args_for_next_run=args_for_next_run,
        partial_result=(
            CommandResults(
                readable_output=(
                    f"Upload sample is executing. Sample ID: {sample_id}."
                ),
            )
            if first_run
            else None
        ),
    )


def get_dbotscore(
    api_score: int,
    generic_command_name: str,
    indicator_value: str,
    reliability: str,
) -> Common.DBotScore:
    """Get XSOAR score for the file's / IP's / URL's / domain's disposition.

    Args:
        api_score (int): The API score.
        generic_command_name (str): The generic command name for identify
            witch command are used for the indicator type.
        indicator_value (str): The command argument - the indicator.
        reliability (str): The reliability that chosen.

    Returns:
        Common.DBotScore: DBot Score according to the disposition.
    """
    if api_score == 0:
        score = Common.DBotScore.NONE
    elif api_score >= DEFAULT_MALICIOUS_THRESHOLD:
        score = Common.DBotScore.BAD
    elif api_score >= DEFAULT_SUSPICIOUS_THRESHOLD:
        score = Common.DBotScore.SUSPICIOUS
    else:
        score = Common.DBotScore.GOOD

    return Common.DBotScore(
        indicator=indicator_value,
        indicator_type=generic_command_name,
        integration_name="ThreatGrid",
        reliability=reliability,
        score=score,
    )


def reputation_command(
    client: Client,
    args: dict[str, Any],
) -> list[CommandResults] | CommandResults:
    """
    Generic reputation command that returns information about Files/IPs/URLs/Domains.
    Args:
        client (Client): Cisco ThreatGrid API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        List[CommandResults]: Indicator for every file_hash
    """
    generic_command_name = args["command_name"]
    command_args = argToList(args[generic_command_name])
    reliability = args["reliability"]
    sample_id = ""
    score = 0
    command_results = []

    for command_arg in command_args:
        response = client.search_submission(
            query=command_arg,
            state="succ",
            sort_by="analyzed_at",
        )

        if response["data"]["current_item_count"] == 0:
            score = 0
            sample_details = {generic_command_name: command_arg}
            sample_id = ""

        else:
            sample_details = response["data"]["items"][0]["item"]
            sample_details[generic_command_name] = command_arg
            sample_analysis_date = dict_safe_get(
                sample_details,
                ["analysis", "metadata", "sandcastle_env", "analysis_end"],
            )

            sample_id = sample_details["sample"]
            score = sample_details["analysis"]["threat_score"]

            if not is_day_diff_valid(sample_analysis_date):
                score = 0
                sample_details = {generic_command_name: command_arg}
                sample_id = ""

        dbot_score = get_dbotscore(
            score, generic_command_name, command_arg, reliability
        )
        reputation_helper_command: Callable = REPUTATION_TYPE_TO_FUNCTION[
            generic_command_name
        ]
        kwargs = {
            "client": client,
            "command_arg": command_arg,
            "sample_id": sample_id,
            "dbot_score": dbot_score,
            "sample_details": sample_details,
        }

        command_results.append(reputation_helper_command(**kwargs))

    return command_results


""" HELPER FUNCTIONS """


def validate_url_template(url: str) -> str:
    """Validate URL argument is according to the 'http://example.com:80' template.

    Args:
        url (str): The URL argument.

    Raises:
        ValueError: In case URL suffix is different than '.com'.

    Returns:
        str: The updated URL.
    """
    correct_prefix = "http://"
    correct_suffix = ".com:80/"

    if not url.startswith(correct_prefix):
        if url.startswith("www."):
            url = url.replace("www.", correct_prefix)
        elif url.startswith("https://"):
            url = url.replace("https://", correct_prefix)
        else:
            url = correct_prefix + url
    if not url.endswith(correct_suffix):
        if url.endswith(".com:80"):
            url += "/"
        elif url.endswith(".com"):
            url += ":80/"
        else:
            raise ValueError("Threat Grid only supports for URL suffix '.com'. ")
    return url


def is_day_diff_valid(sample_analysis_date: str) -> bool:
    """Validate days diff between today and the specified
        date is no more than 14 days.

    Args:
        sample_analysis_date (str): The specified date.

    Returns:
        bool: Return True is diff smaller than 14.
    """
    try:
        analysis_date = sample_analysis_date.split("T")[0]
        today_date = str(datetime.now()).split(" ")[0]
    except IndexError as exc:
        raise IndexError(
            f"The time doesnt match the expected format {TIME_FORMAT} \n {exc}"
        ) from exc

    start = datetime.strptime(analysis_date, TIME_FORMAT)
    end = datetime.strptime(today_date, TIME_FORMAT)
    diff = end - start

    return diff.days <= MAX_DAYS_DIFF


def url_to_sha256(url: str) -> str:
    """Encrypt URL to sha256 in ThreatGrid expected format.

    Args:
        url (str): URL.

    Returns:
        str: URL sha256.
    """

    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def parse_domain_indicator(
    command_arg: str,
    dbot_score: Common.DBotScore,
    **kwargs,
) -> CommandResults:
    """Build outputs for generic command reputation.

    Args:
        command_arg (str): command argument value.
        scores (list): scores list.
        dbot_score (Common.DBotScore): DBotScore object.
        sample_details (dict): sample details from the API.
        sample_id (str): sample ID.

    Returns:
        Tuple: Return command_indicator, outputs_prefix, outputs_key_field, and outputs.
    """
    command_indicator = Common.Domain(
        domain=command_arg,
        dbot_score=dbot_score,
    )
    outputs = {
        "domain": command_arg,
        "name": command_arg,
        "dns": command_arg,
    }

    readable_output = tableToMarkdown(
        name=f"ThreatGrid Domain Reputation for {command_arg} \n",
        t=outputs,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.Domain",
        outputs=outputs,
        outputs_key_field="domain",
        indicator=command_indicator,
    )


def parse_file_indicator(
    dbot_score: Common.DBotScore,
    sample_details: dict,
    **kwargs,
) -> CommandResults:
    """Build outputs for generic command reputation.

    Args:
        command_arg (str): command argument value.
        scores (list): scores list.
        dbot_score (Common.DBotScore): DBotScore object.
        sample_details (dict): sample details from the API.
        sample_id (str): sample ID.

    Returns:
        Tuple: Return command_indicator, outputs_prefix, outputs_key_field, and outputs.
    """
    md5 = sample_details.get("md5")
    sha1 = sample_details.get("sha1")
    sha256 = sample_details.get("sha256")

    command_indicator = Common.File(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        name=sample_details.get("filename"),
        dbot_score=dbot_score,
    )
    outputs = {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }

    file_hash = sample_details.get("file")
    if md5 or sha1 or sha256:
        readable_output = tableToMarkdown(
            name=f"ThreatGrid File Reputation for {file_hash} \n",
            t=outputs,
        )
    else:
        readable_output = tableToMarkdown(
            name=f"ThreatGrid File Not Found for {file_hash} \n", t={"file": file_hash}
        )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.File",
        outputs=outputs,
        outputs_key_field="md5",
        indicator=command_indicator,
    )


def parse_ip_indicator(
    client: Client,
    command_arg: str,
    dbot_score: Common.DBotScore,
    sample_id: str,
    **kwargs,
) -> CommandResults:
    """Build outputs for generic command reputation.

    Args:
        command_arg (str): command argument value.
        scores (list): scores list.
        dbot_score (Common.DBotScore): DBotScore object.
        sample_details (dict): sample details from the API.
        sample_id (str): sample ID.

    Returns:
        Tuple: Return command_indicator, outputs_prefix, outputs_key_field, and outputs.
    """

    response = (
        client.analysis_sample(sample_id=sample_id, analysis_type="annotations")
        if sample_id
        else None
    )
    command_indicator = Common.IP(
        ip=command_arg,
        asn=dict_safe_get(response, ["data", "items", "network", command_arg, "asn"]),
        dbot_score=dbot_score,
    )
    outputs = {
        "indicator": command_arg,
        "asn": dict_safe_get(
            response, ["data", "items", "network", command_arg, "asn"]
        ),
        "confidence": "",
    }
    readable_output = tableToMarkdown(
        name=f"ThreatGrid IP Reputation for {command_arg} \n",
        t=outputs,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.IP",
        outputs=outputs,
        outputs_key_field="ip",
        indicator=command_indicator,
    )


def parse_url_indicator(
    command_arg: str,
    dbot_score: Common.DBotScore,
    **kwargs,
) -> CommandResults:
    """Build outputs for generic command reputation.

    Args:
        command_arg (str): command argument value.
        scores (list): scores list.
        dbot_score (Common.DBotScore): DBotScore object.
        sample_details (dict): sample details from the API.

    Returns:
        Tuple: Return command_indicator, outputs_prefix, outputs_key_field, and outputs.
    """
    command_indicator = Common.URL(
        url=command_arg,
        dbot_score=dbot_score,
    )

    outputs = {
        "url": command_arg,
    }
    readable_output = tableToMarkdown(
        name=f"ThreatGrid URL Reputation for {command_arg} \n",
        t=outputs,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="ThreatGrid.URL",
        outputs=outputs,
        outputs_key_field="url",
        indicator=command_indicator,
    )


def delete_keys_from_dict(
    dictionary: MutableMapping, keys_to_delete: set[str] | list[str]
) -> dict[str, Any]:
    """Get a modified dictionary without the requested keys.
    Args:
        dictionary (Dict[str, Any]): Dictionary to modify according to.
        keys_to_delete (List[str]): Keys to not include in the modified dictionary.
    Returns:
        Dict[str, Any]: Modified dictionary without requested keys.
    """
    keys_set = set(keys_to_delete)
    modified_dict: dict[str, Any] = {}

    for key, value in dictionary.items():
        if key not in keys_set:
            if isinstance(value, MutableMapping):
                modified_dict[key] = delete_keys_from_dict(value, keys_set)

            elif (
                isinstance(value, MutableSequence)
                and value
                and isinstance(value[0], MutableMapping)
            ):
                modified_dict[key] = [
                    delete_keys_from_dict(val, keys_set) for val in value
                ]
            else:
                modified_dict[key] = copy.deepcopy(value)

    return modified_dict


def validate_pagination_arguments(
    page: int | None = None,
    page_size: int | None = None,
    limit: int | None = None,
):
    """Validate pagination arguments according to their default.
    Args:
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of items per page.
        limit (int, optional): The maximum number of records to retrieve.
    Raises:
        ValueError: Appropriate error message.
    """
    if page_size and (page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE):
        raise ValueError(
            f"page size argument must be greater than {MIN_PAGE_SIZE} and smaller than {MAX_PAGE_SIZE}."
        )

    if page is not None and page < MIN_PAGE_NUM:
        raise ValueError(f"page argument must be greater than {MIN_PAGE_NUM-1}.")

    if limit is not None and limit < MIN_LIMIT:
        raise ValueError(f"limit argument must be greater than {MIN_LIMIT}.")


def pagination(args: dict[str, Any]) -> tuple:
    """Return the correct limit and offset for the API
        based on the user arguments page, page_size and limit.

    Args:
        args (Dict[str, Any]): demisto args.

    Returns:
        Tuple: new_limit, offset, pagination_message.
    """
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", 20))

    validate_pagination_arguments(page, page_size, limit)

    offset = 0
    new_limit = limit

    if page is not None and page_size:
        new_limit = page_size
        offset = page - 1

    pagination_message = f"Showing page {offset+1}. \n Current page size: {new_limit}"

    return new_limit, offset, pagination_message


def optional_arg_to_boolean(arg: Any | None) -> bool | None:
    """Retrieve arg boolean value if it's not none.
    Args:
        arg (str): Boolean argument.
    Returns:
        Optional[bool]: The argument boolean value.
    """
    return argToBoolean(arg) if arg is not None else None


REPUTATION_TYPE_TO_FUNCTION: dict[str, Callable] = {
    "ip": parse_ip_indicator,
    "url": parse_url_indicator,
    "domain": parse_domain_indicator,
    "file": parse_file_indicator,
}

ANALYSIS_ARG_NAME = {
    "network_stream": "network_stream_id",
    "artifacts": "artifact_id",
    "processes": "process_id",
}

SAMPLE_ARGS = {
    "sample": {
        "name": "Sample details:",
        "outputs_prefix": "ThreatGrid.Sample",
        "outputs_key_field": "id",
        "summary": False,
    },
    "summary": {
        "name": "Sample summary:",
        "outputs_prefix": "ThreatGrid.SampleAnalysisSummary",
        "outputs_key_field": "sample",
        "summary": True,
    },
}


def parse_output(
    items: dict,
    analysis_arg: str,
) -> dict[Any, Any] | Any | None:
    """Get relevant output from response.

    Args:
        items (Union[List, Dict]): The API response.
        analysis_arg (str): The analysis arg.

    Returns:
        Union[List, Dict]: The relevant data to display.
    """
    items_to_display = items
    if ANALYSIS_OUTPUTS[analysis_arg].get("keys_to_get"):
        items_to_display = (
            items[ANALYSIS_OUTPUTS[analysis_arg]["keys_to_get"]]
            if items.get(ANALYSIS_OUTPUTS[analysis_arg]["keys_to_get"])
            else items
        )
    if ANALYSIS_OUTPUTS[analysis_arg].get("keys_to_delete"):
        items_to_display = delete_keys_from_dict(
            items,
            ANALYSIS_OUTPUTS[analysis_arg]["keys_to_delete"],
        )
    return items_to_display


def parse_file_to_sample(file_id: str) -> dict[str, Any]:
    """Open file to send data to API.

    Args:
        file_id (str): The file ID.

    Returns:
        Dict[str, Any]: Dict with file data.
    """
    file_data = demisto.getFilePath(file_id)
    file_name = file_data["name"]
    with open(file_data["path"], "rb") as f:
        file = {"sample": (file_name, f.read())}
    return file


def get_arg_from_command_name(
    command_name: str,
    position_number: int,
) -> str:
    """Get argument name from the command name to fetch the command value.
        This way help that function be more general.
        Get full argument name if it's two words argument.

    Args:
        command_name (str): The command name.
        position_number (int): The number of the required value from the
                        command name after split the command name by '-'.

    Returns:
        str: Argument name for the specific command.
    """
    try:
        arg_name = command_name.split("-")[position_number]
        if arg_name == "network":
            return "network_stream"
        elif arg_name == "registry":
            return "registry_key"

        return arg_name
    except IndexError as exc:
        raise IndexError(
            f"Argument name from command {command_name} in position {position_number} dose not exist.\n Error: {exc}"
        ) from exc


def delete_key_from_list(items: list, keys_to_delete: list) -> list[dict]:
    """Delete keys from list.

    Args:
        samples (list): List of items.

    Returns:
        List[str, Any]: List without the specified keys.
    """
    return [delete_keys_from_dict(item, keys_to_delete) for item in items]


def test_module(client: Client):
    """Test integration instance for Cisco ThreatGrid.

    Args:
        client (Client): Cisco ThreatGrid API client.

    Raises:
        e: Authorization Error.

    Returns:
        str: Authorization message.
    """
    client.whoami()
    return "ok"


def main() -> None:

    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

    base_url = params["base_url"]
    api_token = params.get("credentials", {}).get("password")

    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    reliability = params.get("integrationReliability")

    args["reliability"] = reliability

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    commands = {
        "threat-grid-submissions-search": search_submission_command,
        "threat-grid-domain-samples-list": list_associated_samples_command,
        "threat-grid-ip-samples-list": list_associated_samples_command,
        "threat-grid-path-samples-list": list_associated_samples_command,
        "threat-grid-url-samples-list": list_associated_samples_command,
        "threat-grid-registry-key-samples-list": list_associated_samples_command,
        "threat-grid-sample-upload": upload_sample_command,
        "threat-grid-sample-list": get_sample_command,
        "file": reputation_command,
        "ip": reputation_command,
        "url": reputation_command,
        "domain": reputation_command,
        "threat-grid-ip-associated-domains": associated_command,
        "threat-grid-ip-associated-urls": associated_command,
        "threat-grid-domain-associated-urls": associated_command,
        "threat-grid-domain-associated-ips": associated_command,
        "threat-grid-feeds-artifact": feeds_command,
        "threat-grid-feeds-domain": feeds_command,
        "threat-grid-feeds-ip": feeds_command,
        "threat-grid-feeds-network-stream": feeds_command,
        "threat-grid-feeds-url": feeds_command,
        "threat-grid-feeds-path": feeds_command,
        "threat-grid-analysis-artifacts-get": analysis_sample_command,
        "threat-grid-analysis-iocs-get": analysis_sample_command,
        "threat-grid-analysis-metadata-get": analysis_sample_command,
        "threat-grid-analysis-network-streams-get": analysis_sample_command,
        "threat-grid-analysis-processes-get": analysis_sample_command,
        "threat-grid-analysis-annotations-get": analysis_sample_command,
        "threat-grid-rate-limit-get": get_rate_limit_command,
        "threat-grid-who-am-i": who_am_i_command,
        "threat-grid-feed-specific-get": get_specific_feed_command,
        "threat-grid-ip-search": search_command,
        "threat-grid-url-search": search_command,
        "threat-grid-sample-summary-get": get_sample_command,
    }

    try:
        client: Client = Client(base_url, api_token, proxy, verify_certificate)
        args["command_name"] = str(command)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "threat-grid-sample-upload":
            return_results(schedule_command(args, client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"The {command} command is not implemented.")

    except Exception as exc:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command." f"\nError:\n{str(exc)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
