import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from enum import Enum
from typing import Any
from dataclasses import dataclass
from datetime import datetime


DEFAULT_OFFSET = 0
DEFAULT_LIMIT = 10
DATE_FORMAT = "%m/%d/%Y %H:%M"
XSOAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
INTEGRATION_PREFIX = "DataBee"


class AdditionalContext(str, Enum):
    evidence = "Finding.Evidence"
    related_event = "Finding.Finding.RelatedEvent"
    remediation = "Finding.Finding.Remediation"
    metadata = "Finding.Metadata"
    observable = "Finding.Observable"
    process = "Finding.Process"


class SearchTypes(str, Enum):
    USER = "user"
    DEVICE = "device"
    FINDING = "security_finding"


@dataclass
class SearchConfiguration:
    type: SearchTypes
    headers: list[str]
    title: str
    output_prefix: str
    output_keys: list[str]
    filters: list[tuple[str, str]]


SEARCH_CONFIGURATIONS: dict[SearchTypes, SearchConfiguration] = {
    SearchTypes.USER: SearchConfiguration(
        filters=[("email_address", "email_addr"), ("full_name", "full_name"), ("name", "name")],
        type=SearchTypes.USER,
        headers=["uid", "type", "name", "start_time", "end_time", "modified_time"],
        title="User",
        output_prefix="User",
        output_keys=["uid", "type", "name", "start_time", "end_time", "modified_time"],
    ),
    SearchTypes.DEVICE: SearchConfiguration(
        filters=[("hostname", "hostname"), ("mac", "mac"), ("name", "name"), ("ip", "ip"), ("id", "uid"), ("uid", "uid")],
        type=SearchTypes.DEVICE,
        headers=[
            "uid",
            "type",
            "region",
            "name",
            "ip",
            "interface_uid",
            "interface_name",
            "instance_uid",
            "hostname",
            "start_time",
            "end_time",
            "modified_time",
        ],
        title="Device",
        output_prefix="Device",
        output_keys=[
            "uid",
            "type",
            "region",
            "owner",
            "os",
            "name",
            "ip",
            "interface_uid",
            "interface_name",
            "instance_uid",
            "hostname",
            "start_time",
            "end_time",
            "modified_time",
            "mac",
        ],
    ),
    SearchTypes.FINDING: SearchConfiguration(
        filters=[
            ("analytic_name", "analytic.name"),
            ("confidence", "confidence"),
            ("device_environment", "device.environment"),
            ("device_risk_level", "device.risk_level"),
            ("impact", "impact"),
            ("risk_level", "risk_level"),
            ("severity", "severity"),
        ],
        type=SearchTypes.FINDING,
        headers=[
            "time",
            "activity_name",
            "impact",
            "state",
            "severity",
            "user",
            "device",
            "analytic",
            "confidence",
        ],
        title="Finding",
        output_prefix="Finding",
        output_keys=[],
    ),
}


class Client(BaseClient):
    """Client class to interact with DataBee API."""

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        password: str,
        username: str | None = None,
    ):
        base_url = urljoin(base_url, "api")
        if not username:
            super().__init__(
                base_url=base_url,
                headers={"Authorization": f"Token {password}"},
                verify=verify,
                proxy=proxy,
            )
        else:
            super().__init__(
                base_url=base_url,
                verify=verify,
                proxy=proxy,
            )
            api_token = self.authenticate(
                username=username,
                password=password,
            ).json()["api_key"]
            super().__init__(
                base_url=base_url,
                headers={"Authorization": f"Token {api_token}"},
                verify=verify,
                proxy=proxy,
            )

    def _http_request(self, *args, **kwargs) -> requests.Response:
        """
        Warp to _http_request command, for adding error handler.

        Returns:
            requests.Response: API response from DataBee API.
        """
        kwargs["error_handler"] = self.error_handler
        res = super()._http_request(*args, **kwargs)
        return res

    def error_handler(self, res: requests.Response):
        """
        Handling with request errors.

        Args:
            res (requests.Response): API response from DataBee API.

        Raises:
            DemistoException: Error response.
        """
        match res.status_code:
            case HTTPStatus.UNAUTHORIZED:
                raise DemistoException(
                    "Unauthorized error. Please check your API token/ username/ password."
                )
            case _:
                if "application/json" in res.headers.get("Content-Type", ""):
                    json_response = res.json()
                    if detail := json_response.get("detail"):
                        raise DemistoException(detail)

                    raise DemistoException(json_response)

                raise DemistoException(res)

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> requests.Response:
        """Get API token with username and password.

        Args:
            username (str): DataBee username.
            password (str): DataBee password.

        Returns:
            Response: API response from DataBee.
        """
        return self._http_request(
            method="POST",
            url_suffix="login/",
            json_data={
                "username": username,
                "password": password,
            },
            resp_type="response",
        )

    def search(
        self,
        table: str,
        query: str,
        limit: int | None = None,
        offset: int = 0,
    ) -> requests.Response:
        """Search data in DataBee.

        Args:
            table (str): Table (to search for) name.
            query (str): Query.
            limit (int | None): requests.Response limit. Defaults to None.
            offset (int): Offset. Defaults to 0.

        Returns:
            requests.Response: API response from DataBee.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/search/{table}",
            params=remove_empty_elements(
                {
                    "query": query,
                    "offset": offset,
                    "limit": limit,
                }
            ),
            resp_type="response",
        )


def parse_response(
    type: str,
    data: list[dict[str, Any]],
    keys: list[str],
    additional_context: list[AdditionalContext],
) -> list[dict[str, Any]]:
    """
    Parse response to outputs.

    Args:
        type (str): The search table type.
        data (list[dict[str, Any]]): The readable output title.
        keys (list[str]): The output prefix.

    Returns:
        list[dict[str, Any]]: XSOAR context outputs.
    """
    if type == SearchTypes.FINDING:
        normalize_data = [normalize_finding(d, additional_context) for d in data]
    else:
        fixed_data = [
            remove_empty_elements(
                {
                    camelize_string(key) if isinstance(obj.get(key), dict) else key: obj.get(key)
                    for key in keys
                    if key in obj
                }
            )
            for obj in data
        ]
        normalize_data = fixed_data
    return normalize_data


def generate_command_results(
    title: str,
    outputs_prefix: str,
    outputs_key_field: str,
    headers: list[str],
    outputs: list[dict[str, Any]] | dict[str, Any],
    raw_response: list[dict[str, Any]] | dict[str, Any],
    readable_outputs: dict[str, Any] = None,
) -> CommandResults:
    """
    Generates Command Results object.

    Args:
        title (str): The readable output title.
        outputs_prefix (str): The output prefix.
        outputs_key_field (str): The output key field.
        headers (list): The readable output headers.
        outputs (list[dict[str, Any]] | dict[str, Any]): The outputs.
        raw_response (dict[str, Any]): The raw response.
        readable_outputs (dict[str, Any], optional): Readable outputs data. Defaults to None.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{outputs_prefix}",
        outputs_key_field=outputs_key_field,
        raw_response=raw_response,
        outputs=outputs,
        readable_output=tableToMarkdown(
            title,
            readable_outputs or outputs,
            headers=headers,
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
    )


def create_query(operator: str | None, key: str, value: str | list | None):
    """
    Create query single filter.

    Args:
        operator (str | None): The filter operator.
        key (str): The DataBee key filter.
        value (str | list | None): The value.

    Returns:
        str: Formated query for search.
    """
    operator = operator.replace(" ", "") if operator else operator
    if value:
        if operator and operator != "between":
            values = (",").join(argToList(value))
            return f"{key} {operator.lower()} ({values})"
        elif "." in key:
            operator = operator or "in"
            values = (",").join(argToList(value))
            return f"{key} {operator.lower()} ({values})"
        else:
            operator = operator or "contains"
            return f"{key} {operator.lower()} {value}"

    return None


def build_full_query(search_type: SearchTypes, args: dict[str, Any]) -> str:
    """
    Build full query for table search.

    Args:
        search_type (SearchTypes): The search type (user/ device/ finding).
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case query or filters not provided.

    Returns:
        str: Formated query for search.
    """
    if query := args.get("query"):
        return query

    query = []
    filter_keys = []

    # Handle with common filters
    start_time = arg_to_datetime(args.get("start_time"))
    end_time = arg_to_datetime(args.get("end_time"))
    time_range = (
        parse_date_range(date_range=args["time_range"], date_format=DATE_FORMAT)
        if args.get("time_range")
        else None
    )

    if start_time and end_time:
        format_start_time = start_time.strftime(DATE_FORMAT)
        format_end_time = end_time.strftime(DATE_FORMAT)
        query.append(
            create_query(
                operator="between", key="start_time", value=f"{format_start_time},{format_end_time}"
            )
        )

    if time_range:
        query.append(
            create_query(
                operator="between", key="start_time", value=f"{time_range[0]},{time_range[1]}"
            )
        )

    # Handle with custom filters
    filter_keys = SEARCH_CONFIGURATIONS[search_type].filters
    search_operator = args.get("search_operator")
    for xsoar_key, databee_key in filter_keys:
        query.append(
            create_query(operator=search_operator, key=databee_key, value=args.get(xsoar_key))
        )
    query = remove_empty_elements(query)
    if len(query) == 0:
        raise ValueError("You have to provide at least one filter or use the query argument.")

    if search_type == SearchTypes.FINDING:
        query.append("metadata.product.name in databee")
    return (" and ").join(query)


def get_pagination_args(
    page: str,
    limit: str,
    page_size: str | None,
) -> tuple[int, int]:
    """
    Get XSOAR pagination in DataBee format.

    Args:
        page (str): Page.
        limit (str): Limit.
        page_size (str): Page Size.

    Returns:
        tuple[int, int]: DataBee limit and offset.
    """
    xsoar_limit = arg_to_number(page_size if page_size else limit)
    xsoar_offset = DEFAULT_OFFSET
    if (
        page_size
        and (new_page := arg_to_number(page))
        and (new_page_size := arg_to_number(page_size))
    ):
        xsoar_offset = new_page * new_page_size

    return (xsoar_limit or DEFAULT_LIMIT, xsoar_offset or DEFAULT_OFFSET)


def search_command(
    client: Client,
    args: dict[str, Any],
    settings: SearchConfiguration,
    additional_context: list[AdditionalContext],
) -> CommandResults:
    """
    Search for DataBee tables.

    Args:
        client (Client): DataBee API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit, offset = get_pagination_args(
        page=args["page"],
        limit=args["limit"],
        page_size=args.get("page_size"),
    )

    response = client.search(
        table=settings.type.value,
        query=build_full_query(search_type=settings.type, args=args),
        limit=limit,
        offset=offset,
    ).json()
    return generate_command_results(
        title=f"{settings.title} List",
        outputs_prefix=settings.output_prefix,
        outputs_key_field="uid",
        headers=settings.headers,
        outputs=parse_response(
            type=settings.type,
            data=response.get("results") or [],
            keys=settings.output_keys,
            additional_context=additional_context,
        ),
        raw_response=response,
    )


def get_endpoint_command(
    client: Client,
    args: dict[str, Any],
) -> list[CommandResults]:
    hostname = args.get("hostname")
    ip = args.get("ip")
    id = args.get("id")

    if not ip and not hostname and not id:
        # in order not to return all the devices
        raise ValueError("Please add a filter argument - ip, hostname ot id.")

    # use OR operator between filters (https://github.com/demisto/etc/issues/46353)
    raw_res = client.search(
        table=SearchTypes.DEVICE.value,
        query=build_full_query(
            search_type=SEARCH_CONFIGURATIONS[SearchTypes.DEVICE].type,
            args=(args | {"search_operator": "in"}),
        ),
    ).json()

    devices = raw_res.get("results", [])
    if not devices:
        raise ValueError("No devices was found")

    standard_endpoints = []
    for single_device in devices:
        endpoint = Common.Endpoint(
            id=single_device.get("uid"),
            hostname=single_device.get("hostname"),
            ip_address=single_device.get("ip"),
            os=dict_safe_get(single_device, ["os", "type"]),
            os_version=dict_safe_get(single_device, ["os", "version"]),
            mac_address=single_device.get("mac"),
            vendor=INTEGRATION_PREFIX,
        )
        standard_endpoints.append(endpoint)

    command_results = []
    for endpoint in standard_endpoints:
        endpoint_context = endpoint.to_context().get(Common.Endpoint.CONTEXT_PATH)
        hr = tableToMarkdown("DataBee Endpoint", endpoint_context)

        command_results.append(
            CommandResults(readable_output=hr, raw_response=raw_res, indicator=endpoint)
        )
    return command_results


def test_module(client: Client) -> str:
    """
    Test module.

    Args:
        client (Client): DataBee client.
        params (Dict): Integration parameters.

    Raises:
        ValueError: In case of wrong request.

    Returns:
        str: Output message.
    """
    try:
        response = client.search(table=SearchTypes.USER.value, query="start_time is None", limit=1)
        if response.status_code == HTTPStatus.OK:
            return "ok"
        else:
            raise ValueError(response.status_code)
    except Exception as error:
        demisto.debug(str(error))
        return f"Error: {error}"


def fetch_incidents(
    client: Client, args: dict[str, Any], params: dict[str, Any], current_time: datetime
) -> tuple[list[dict], dict[str, Any]]:
    """
    Retrieves findings every interval (default is 1 minute).
    By default it's invoked by XSOAR every minute.
    It will use last_run to save the time of the last incident it processed and previous incident IDs.
    If last_run is not provided, first_fetch_time will be used to determine when to start fetching the first time.
    Args:
        client (Client): DataBee client.
        args (dict[str, Any]): Command arguments from XSOAR.
        params (dict[str, Any]: Instance params from XSOAR.
        end_time (str): The current time string formated.
    Returns:
        tuple[list[dict], dict[str, Any]]:
            incidents: List of incidents that will be created in XSOAR.
            next_run: Contains information that will be used in the next run.
    """
    end_time = current_time.strftime(DATE_FORMAT)
    incidents = []
    first_fetch = arg_to_datetime(params.get("first_fetch"))
    if not first_fetch:
        raise ValueError("First fetch time must be specified.")
    max_fetch = arg_to_number(params["max_fetch"])
    last_run = arg_to_datetime(demisto.getLastRun().get("time"))

    demisto.debug(f"fetch: last_run is: {last_run}.")

    start_date = last_run or first_fetch
    start_time = start_date.strftime(DATE_FORMAT)
    query = f"start_time between {start_time},{end_time} and metadata.product.name in databee"

    if severity := params.get("severity"):
        query = f"{query} and severity contains {severity}"
    if impact := params.get("impact"):
        query = f"{query} and impact contains {impact}"

    demisto.debug(f"fetch: Start to fetch incidents, query: {query}.")

    data = None
    offset = 0
    while data is None or len(data) > 0:
        response = client.search(
            table=SearchTypes.FINDING.value,
            limit=(max_fetch or DEFAULT_LIMIT),
            query=query,
            offset=(offset or DEFAULT_OFFSET),
        ).json()

        count = response["count"]
        data = response["results"]
        offset += len(data)

        demisto.debug(f"fetch: fetched status {offset}/{count}.")
        next_run = start_date

        for finding in data:
            time = arg_to_datetime(finding["time"])

            incidents.append(
                {
                    "name": str(finding["id"]),
                    "occurred": time.strftime(XSOAR_DATE_FORMAT) if time else None,
                    "rawJSON": json.dumps(finding),
                }
            )
            if time and time > next_run:
                next_run = time

    new_last_run = (current_time).strftime(XSOAR_DATE_FORMAT)

    demisto.debug(f"fetch: Update last run time to {new_last_run}.")
    demisto.debug(f"fetch: Fetched {len(incidents)} incidents.")
    return incidents, {"time": new_last_run}


''' HELPER COMMANDS '''


def normalize_finding(data: dict[str, Any], additional_context: list[AdditionalContext]):
    process: dict[str, Any] = data.get("process", {})

    normalize_data = {
        "device_id": data.get("device_id"),
        "user_id": data.get("user_id"),
        "activity_id": data.get("activity_id"),
        "activity_name": data.get("activity_name"),
        "Analytic": {
            "category": dict_safe_get(data, ["analytic", "category"]),
            "desc": dict_safe_get(data, ["analytic", "desc"]),
            "name": dict_safe_get(data, ["analytic", "name"]),
            "type": dict_safe_get(data, ["analytic", "type"]),
            "uid": dict_safe_get(data, ["analytic", "uid"]),
        },
        "Attack": [
            {
                "Tactic": [
                    {
                        "id": tactic.get("id"),
                        "name": tactic.get("name"),
                        "uid": tactic.get("uid"),
                    }
                    for tactic in attack.get("tactics", [])
                ],
                "Technique": {
                    "id": dict_safe_get(attack, ["technique", "id"]),
                    "name": dict_safe_get(attack, ["technique", "name"]),
                    "uid": dict_safe_get(attack, ["technique", "uid"]),
                },
            }
            for attack in data.get("attacks", [])
        ],
        "category_name": data.get("category_name"),
        "CisCsc": [
            {
                "control": value.get("control"),
                "id": value.get("id"),
                "version": value.get("version"),
            }
            for value in data.get("cis_csc", [])
        ],
        "class_name": data.get("class_name"),
        "confidence": data.get("confidence"),
        "data_source": data.get("data_sources", []),
        "Device": {
            "ip": dict_safe_get(data, ["device", "ip"]),
            "mac": dict_safe_get(data, ["device", "mac"]),
            "hostname": dict_safe_get(data, ["device", "hostname"]),
            "os": dict_safe_get(data, ["device", "os"]),
        },
        "duration": data.get("duration"),
        "end_time": data.get("end_time"),
        "Evidence": (
            data.get("evidence", {}) if AdditionalContext.evidence in additional_context else {}
        ),
        "Finding": {
            "created_time": dict_safe_get(data, ["finding", "created_time"]),
            "desc": dict_safe_get(data, ["finding", "desc"]),
            "first_seen_time": dict_safe_get(data, ["finding", "first_seen_time"]),
            "last_seen_time": dict_safe_get(data, ["finding", "last_seen_time"]),
            "modified_time": dict_safe_get(data, ["finding", "modified_time"]),
            "product_uid": dict_safe_get(data, ["finding", "product_uid"]),
            "RelatedEvent": (
                dict_safe_get(data, ["finding", "related_events"])
                if AdditionalContext.related_event in additional_context
                else None
            ),
            "Remediation": (
                dict_safe_get(data, ["finding", "remediation"])
                if AdditionalContext.remediation in additional_context
                else None
            ),
            "src_url": dict_safe_get(data, ["finding", "src_url"]),
            "supporting_data": dict_safe_get(data, ["finding", "supporting_data"]),
            "title": dict_safe_get(data, ["finding", "title"]),
            "types_": dict_safe_get(data, ["finding", "types_"]),
            "uid": dict_safe_get(data, ["finding", "uid"]),
        },
        "id": data.get("id"),
        "impact": data.get("impact"),
        "impact_score": data.get("impact_score"),
        "KillChain": data.get("kill_chain", {}),
        "message": data.get("message"),
        "Metadata": (
            data.get("metadata") if AdditionalContext.metadata in additional_context else {}
        ),
        "Observable": (
            [
                {
                    "name": ob.get("name"),
                    "Reputation": ob.get("reputation"),
                    "type": ob.get("type"),
                    "value": ob.get("value"),
                }
                for ob in data.get("observables", [])
            ]
            if AdditionalContext.observable not in additional_context
            else None
        ),
        "Process": (
            {
                "cmd_line": process.get("cmd_line"),
                "container": process.get("container"),
                "created_time": process.get("created_time"),
                "File": {
                    "company_name": dict_safe_get(process, ["file", "company_name"]),
                    "desc": dict_safe_get(process, ["file", "desc"]),
                    "Hashes": [
                        {
                            "algorithm": hash.get("algorithm"),
                            "fingerprint_value": hash.get("fingerprint_value"),
                            "value": hash.get("value"),
                        }
                        for hash in dict_safe_get(process, ["file", "hashes"], [])
                    ],
                    "is_system": dict_safe_get(process, ["file", "is_system"]),
                    "md5": dict_safe_get(process, ["file", "md5"]),
                    "mime_type": dict_safe_get(process, ["file", "mime_type"]),
                    "modified_time": dict_safe_get(process, ["file", "modified_time"]),
                    "name": dict_safe_get(process, ["file", "name"]),
                    "owner": dict_safe_get(process, ["file", "owner"]),
                    "parent_folder": dict_safe_get(process, ["file", "parent_folder"]),
                    "path": dict_safe_get(process, ["file", "path"]),
                    "security_descriptor": dict_safe_get(process, ["file", "security_descriptor"]),
                    "sha1": dict_safe_get(process, ["file", "sha1"]),
                    "sha256": dict_safe_get(process, ["file", "sha256"]),
                    "sha512": dict_safe_get(process, ["file", "sha512"]),
                    "signature": dict_safe_get(process, ["file", "signature"]),
                    "size": dict_safe_get(process, ["file", "size"]),
                    "type": dict_safe_get(process, ["file", "type"]),
                    "xattributes": dict_safe_get(process, ["file", "xattributes"]),
                },
                "name": process.get("name"),
                "namespace_pid": process.get("namespace_pid"),
                "parent_process": process.get("parent_process"),
                "pid": process.get("pid"),
                "sandbox": process.get("sandbox"),
                "user": process.get("user"),
            }
            if AdditionalContext.process in additional_context
            else {}
        ),
        "risk_level": data.get("risk_level"),
        "risk_score": data.get("risk_score"),
        "severity": data.get("severity"),
        "start_time": data.get("start_time"),
        "state": data.get("state"),
        "status": data.get("status"),
        "status_detail": data.get("status_detail"),
        "time": data.get("time"),
        "type_name": data.get("type_name"),
        "User": data.get("user", {}),
    }
    return normalize_data


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    base_url = params["url"]
    username = dict_safe_get(params, ["credentials", "identifier"])
    password = dict_safe_get(params, ["credentials", "password"])
    insecure: bool = not params.get("insecure", False)
    proxy = argToBoolean(params.get("proxy", ""))
    command = demisto.command()
    demisto.debug(f"The command being called is {command}.")
    search_types: dict[str, SearchConfiguration] = {
        "databee-user-search": SEARCH_CONFIGURATIONS[SearchTypes.USER],
        "databee-device-search": SEARCH_CONFIGURATIONS[SearchTypes.DEVICE],
        "databee-finding-search": SEARCH_CONFIGURATIONS[SearchTypes.FINDING],
    }
    try:
        client: Client = Client(
            base_url=base_url,
            username=username,
            password=password,
            verify=insecure,
            proxy=proxy,
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command in search_types:
            return_results(
                search_command(
                    client, args, search_types[command], params.get("additional_context", [])
                )
            )
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(
                client=client,
                args=args,
                params=params,
                current_time=datetime.now(),
            )
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command == "endpoint":
            return_results(get_endpoint_command(client, args))

        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
