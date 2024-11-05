"""Demisto Integration for Axonius."""
from axonius_api_client.api.assets.devices import Devices
from axonius_api_client.api.assets.users import Users
from axonius_api_client.connect import Connect
from axonius_api_client.tools import dt_parse, strip_left
from CommonServerPython import *
import requests
# Added ignore RemovedInMarshmallow4Warning in Axonius_test file.


MAX_ROWS: int = 50
"""Maximum number of assets to allow user to fetch."""
SKIPS: List[str] = ["specific_data.data.image", "view"]
"""Fields to remove from each asset if found."""
FIELDS_TIME: List[str] = ["seen", "fetch", "time", "date"]
"""Fields to try and convert to date time if they have these words in them."""
AXONIUS_ID = "internal_axon_id"


def get_int_arg(
    key: str,
    required: Optional[bool] = False,
    default: Optional[int] = None,
) -> int:
    """Get a key from a command arg and convert it into an int."""
    args: dict = demisto.args()
    value: int = args.get(key, default)

    if value is None and required:
        raise ValueError(f"No value supplied for argument {key!r}")

    try:
        return int(value)
    except Exception:
        raise ValueError(
            f"Supplied value {value!r} for argument {key!r} is not an integer."
        )


def get_csv_arg(
    key: str,
    required: Optional[bool] = False,
    default: Optional[str] = "",
) -> List[str]:
    """Get string values from CSV."""
    args: dict = demisto.args()
    value: List[str] = argToList(arg=args.get(key, default))
    value = [x for x in value if x]

    if not value and required:
        raise ValueError(f"No value supplied for argument {key!r}")

    return value


def test_module(client: Connect) -> str:
    """Tests Axonius API Client connectivity."""
    client.start()
    return "ok"


def parse_kv(key: str, value: Any) -> Any:
    """Parse time stamp into required format."""
    for word in FIELDS_TIME:
        if word in key:
            try:
                return dt_parse(value).isoformat()
            except Exception:
                return value
    return value


def parse_key(key: str) -> str:
    """Parse fields into required format."""
    if key.startswith("specific_data.data."):
        key = strip_left(obj=key, fix="specific_data.data.")
        key = f"aggregated_{key}"
    if key.startswith("adapters_data."):
        key = strip_left(obj=key, fix="adapters_data.")
    key = key.replace(".", "_")
    return key


def parse_asset(asset: dict) -> dict:
    """Initiate field format correction on assets."""
    return {
        parse_key(key=k): parse_kv(key=k, value=v)
        for k, v in asset.items()
        if k not in SKIPS
    }


def get_saved_queries(
    client: Connect, args: dict
) -> CommandResults:  # noqa: F821, F405
    """Get assets with their defined fields returned by a saved query."""
    api_obj = client.devices if args["type"] == "devices" else client.users
    saved_queries = api_obj.saved_query.get()
    return parse_assets(
        assets=saved_queries,
        api_obj=api_obj,
        outputs_key_field="",
        extension="saved_queries",
        exclude_raw=True,
    )


def make_api_call(
    endpoint: str,
    payload: dict = None,
) -> requests.Response | None:
    params: dict = demisto.params()
    url: str | None = params.get('ax_url')
    key: str = params.get('credentials', {}).get('identifier')
    secret: str = params.get('credentials', {}).get('password')
    certverify: bool = not params.get('insecure', False)

    if not url:
        return None

    url = url + '/' if url[-1] != '/' else url
    url = url + endpoint

    headers: dict = {
        "accept": "application/json",
        "api-key": key,
        "api-secret": secret,
        "content-type": "application/json",
    }

    return requests.post(url, json=payload, headers=headers, verify=certverify)


def add_note(
    client: Connect,
    args: dict
) -> CommandResults:
    """Add notes to assets."""
    note: str = args["note"]
    asset_type: str = args["type"]
    internal_axon_id_arr: list = args["ids"]
    success_count: int = 0
    if isinstance(internal_axon_id_arr, str):
        internal_axon_id_arr = argToList(internal_axon_id_arr, separator=",")

    payload: dict = {
        "meta": None,
        "data": {
            "attributes": {
                "note": note,
            },
            "type": "notes_schema"
        },
    }

    for id in internal_axon_id_arr:
        response = make_api_call(endpoint=f'api/{asset_type}/{id}/notes', payload=payload)
        if response and response.status_code == 200:
            success_count += 1

    readable_output = f"{success_count} {asset_type}(s) updated."
    return CommandResults(
        outputs_prefix="Axonius.asset.updates",
        readable_output=readable_output,
        outputs=success_count,
        raw_response=success_count,
    )


def get_tags(client: Connect, args: dict) -> CommandResults:  # noqa: F821, F405
    """Get assets with their defined fields returned by a saved query."""
    api_obj = client.devices if args["type"] == "devices" else client.users
    tags = api_obj.labels.get()
    return CommandResults(
        outputs_prefix=f"Axonius.tags.{args['type']}",
        readable_output=",".join(tags),
        outputs=tags,
        raw_response=tags,
    )


def update_tags(
    client: Connect, args: dict, method_name: str
) -> CommandResults:  # noqa: F821, F405
    tag_name: str = args["tag_name"]
    internal_axon_id_arr: list = args["ids"]
    if isinstance(internal_axon_id_arr, str):
        internal_axon_id_arr = argToList(internal_axon_id_arr, separator=",")
    api_obj = client.devices if args["type"] == "devices" else client.users
    api_name = api_obj.__class__.__name__

    if method_name == "add":
        res = api_obj.labels.add(rows=internal_axon_id_arr, labels=[tag_name])
    else:
        res = api_obj.labels.remove(rows=internal_axon_id_arr, labels=[tag_name])

    # res is count of rows included in the output, regardless of success.
    readable_output = f"{res} {api_name}(s) updated."
    return CommandResults(
        outputs_prefix=f"Axonius.asset.updates.{args['type']}",
        readable_output=readable_output,
        outputs=res,
        raw_response=res,
    )


def get_by_sq(
    api_obj: Union[Users, Devices], args: dict
) -> CommandResults:  # noqa: F821, F405
    """Get assets with their defined fields returned by a saved query."""
    name: str = args["saved_query_name"]
    fields: List[str] = get_csv_arg(key="fields", required=False)
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)
    assets = api_obj.get_by_saved_query(name=name, max_rows=max_rows, fields=fields)
    return parse_assets(assets=assets, api_obj=api_obj)


def get_by_value(
    api_obj: Union[Users, Devices],
    args: dict,
    method_name: str,
) -> CommandResults:  # noqa: F821, F405
    """Get assets by a value using a api_obj.get_by_{method_name}."""
    api_name = api_obj.__class__.__name__
    value: str = args["value"]
    fields: List[str] = get_csv_arg(key="fields", required=False)
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)

    api_method_name = f"get_by_{method_name}"
    if not hasattr(api_obj, api_method_name):
        valid = []

        for x in dir(api_obj):
            if not x.startswith("get_by_") or x.endswith("s"):
                continue

            valid.append(x.replace("get_by_", ""))

        valid = ", ".join(valid)
        raise Exception(f"Invalid get by {method_name} for {api_name}, valid: {valid}")

    method = getattr(api_obj, api_method_name)
    assets = method(value=value, max_rows=max_rows, fields=fields)
    return parse_assets(assets=assets, api_obj=api_obj)


def get(
    api_obj: Union[Users, Devices],
    args: dict,
) -> CommandResults:
    """Get assets by a query using a api_obj.get."""
    query: str = args["query"]
    fields: List[str] = get_csv_arg(key="fields", required=False)
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)
    assets = api_obj.get(query=query, max_rows=max_rows, fields=fields)
    return parse_assets(assets=assets, api_obj=api_obj)


def parse_assets(
    assets: List[dict],
    api_obj: Union[Users, Devices],
    outputs_key_field=AXONIUS_ID,
    extension="",
    exclude_raw=False,
) -> CommandResults:  # noqa: F821, F405
    """Parse assets into CommandResults."""
    api_name = api_obj.__class__.__name__
    aql = api_obj.LAST_GET.get("filter")
    results = [parse_asset(asset=asset) for asset in assets]

    readable_output: Optional[str] = None
    outputs: Union[List[dict], dict] = results

    if not results:
        readable_output = f"No {api_name} assets found using AQL: {aql}"

    if len(results) == 1:
        outputs = results[0]

    outputs_prefix = f"Axonius.{api_name}"
    if extension:
        outputs_prefix += f".{extension}"
    raw_response = None if exclude_raw else assets

    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=outputs_key_field,
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )  # noqa: F821, F405


def run_command(client: Connect, args: dict, command: str):

    results: Union[CommandResults, str, None] = None

    if command == "test-module":
        results = test_module(client=client)

    elif command == "axonius-get-devices-by-savedquery":
        results = get_by_sq(api_obj=client.devices, args=args)

    elif command == "axonius-get-users-by-savedquery":
        results = get_by_sq(api_obj=client.users, args=args)

    elif command == "axonius-get-devices-by-aql":
        results = get(api_obj=client.devices, args=args)

    elif command == "axonius-get-users-by-aql":
        results = get(api_obj=client.users, args=args)

    elif command == "axonius-get-users-by-mail":
        results = get_by_value(api_obj=client.users, args=args, method_name="mail")

    elif command == "axonius-get-users-by-mail-regex":
        results = get_by_value(
            api_obj=client.users, args=args, method_name="mail_regex"
        )

    elif command == "axonius-get-users-by-username":
        results = get_by_value(
            api_obj=client.users, args=args, method_name="username"
        )

    elif command == "axonius-get-users-by-username-regex":
        results = get_by_value(
            api_obj=client.users, args=args, method_name="username_regex"
        )

    elif command == "axonius-get-devices-by-hostname":
        results = get_by_value(
            api_obj=client.devices, args=args, method_name="hostname"
        )

    elif command == "axonius-get-devices-by-hostname-regex":
        results = get_by_value(
            api_obj=client.devices, args=args, method_name="hostname_regex"
        )

    elif command == "axonius-get-devices-by-ip":
        results = get_by_value(api_obj=client.devices, args=args, method_name="ip")

    elif command == "axonius-get-devices-by-ip-regex":
        results = get_by_value(
            api_obj=client.devices, args=args, method_name="ip_regex"
        )

    elif command == "axonius-get-devices-by-mac":
        results = get_by_value(api_obj=client.devices, args=args, method_name="mac")

    elif command == "axonius-get-devices-by-mac-regex":
        results = get_by_value(
            api_obj=client.devices, args=args, method_name="mac_regex"
        )

    elif command == "axonius-get-saved-queries":
        results = get_saved_queries(client=client, args=args)

    elif command == "axonius-get-tags":
        results = get_tags(client=client, args=args)

    elif command == "axonius-add-note":
        results = add_note(client=client, args=args)

    elif command == "axonius-add-tag":
        results = update_tags(client=client, args=args, method_name="add")

    elif command == "axonius-remove-tag":
        results = update_tags(client=client, args=args, method_name="remove")

    return results


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    params: dict = demisto.params()
    command: str = demisto.command()

    url: str = params["ax_url"]
    key: str = params.get('credentials', {}).get('identifier')
    secret: str = params.get('credentials', {}).get('password')
    certverify: bool = not params.get("insecure", False)

    proxies: dict = handle_proxy()  # noqa: F821, F405
    demisto.debug(f"Attempting to connect via proxy with: {proxies}")

    demisto.debug(f"Command being called is {command}")
    args: dict = demisto.args()

    try:
        client = Connect(
            url=url,
            key=key,
            secret=secret,
            certverify=certverify,
            certwarn=False,
            proxy=proxies.get("https") or proxies.get("http"),
        )
        return_results(run_command(client, args, command))  # noqa: F821, F405

    except Exception as exc:
        demisto.error(traceback.format_exc())
        msg: List[str] = [f"Failed to execute {command} command", "Error:", str(exc)]
        return_error("\n".join(msg))  # noqa: F821, F405


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
