"""Demisto Integration for Axonius."""
import traceback
from typing import Any, List, Optional, Union

import demistomock as demisto
from axonius_api_client.api.assets.devices import Devices
from axonius_api_client.api.assets.users import Users
from axonius_api_client.connect import Connect
from axonius_api_client.tools import dt_parse, strip_left
from CommonServerPython import *
from CommonServerUserPython import *

MAX_ROWS: int = 50
"""Maximum number of assets to allow user to fetch."""
SKIPS: List[str] = ["specific_data.data.image"]
"""Fields to remove from each asset if found."""
FIELDS_TIME: List[str] = ["seen", "fetch", "time", "date"]
"""Fields to try and convert to date time if they have these words in them."""


def get_int_arg(
    key: str, required: Optional[bool] = False, default: Optional[int] = None,
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
    key: str, required: Optional[bool] = False, default: Optional[str] = "",
) -> List[str]:
    """Get a key from a command arg and convert it into an int."""
    args: dict = demisto.args()
    value: int = args.get(key, default)

    if not value and required:
        raise ValueError(f"No value supplied for argument {key!r}")

    return [x.strip() for x in value.split(",") if x.strip()]


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


def check_asset_count(api_obj: Union[Users, Devices], assets: List[dict], src: str):
    """Raise exception for no assets found."""
    if not assets:
        api_name = api_obj.__class__.__name__
        raise Exception(f"No {api_name} assets returned from {src}.")


def get_by_sq(api_obj: Union[Users, Devices]) -> CommandResults:  # noqa: F821, F405
    """Get assets with their defined fields returned by a saved query."""
    api_name = api_obj.__class__.__name__
    args: dict = demisto.args()
    name: str = args["saved_query_name"]
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)

    assets = api_obj.get_by_saved_query(name=name, max_rows=max_rows)
    check_asset_count(
        api_obj=api_obj, assets=assets, src=f"{api_name} Saved Query named {name}"
    )
    results = [parse_asset(asset=asset) for asset in assets]

    return CommandResults(  # noqa: F821, F405
        outputs_prefix=f"Axonius.{api_name}",
        outputs_key_field="internal_axon_id",
        outputs=results,
    )


def get_by_value(
    api_obj: Union[Users, Devices], method_name: str,
) -> CommandResults:  # noqa: F821, F405
    """Get assets by a value using a api_obj.get_by_{method_name}."""
    api_name = api_obj.__class__.__name__
    args: dict = demisto.args()
    value: str = args["value"]
    fields: List[str] = get_csv_arg(key="fields", required=False)
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)

    api_method_name = f"get_by_{method_name}"
    if not hasattr(api_obj, api_method_name):
        valid = []

        for x in dir(api_obj):
            if not x.startswith("get_by_") or x.endswith("s") or x.endswith("_regex"):
                continue

            valid.append(x.replace("get_by_", ""))

        valid = ", ".join(valid)
        raise Exception(f"Invalid get by {method_name} for {api_name}, valid: {valid}")

    method = getattr(api_obj, api_method_name)
    assets = method(value=value, max_rows=max_rows, fields=fields)

    check_asset_count(
        api_obj=api_obj, assets=assets, src=f"{api_name} by {method_name} {value}"
    )
    results = [parse_asset(asset=asset) for asset in assets]

    if len(results) == 1:
        results = results[0]

    return CommandResults(  # noqa: F821, F405
        outputs_prefix=f"Axonius.{api_name}",
        outputs_key_field="internal_axon_id",
        outputs=results,
    )


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    params: dict = demisto.params()
    command: str = demisto.command()

    url: str = params["ax_url"]
    key: str = params["ax_key"]
    secret: str = params["ax_secret"]
    certverify: bool = not params.get("insecure", False)

    handle_proxy()  # noqa: F821, F405

    demisto.debug(f"Command being called is {command}")

    try:
        client = Connect(
            url=url, key=key, secret=secret, certverify=certverify, certwarn=False,
        )

        if command == "test-module":
            result = test_module(client=client)
            return_results(result)  # noqa: F821, F405
        elif command == "axonius-get-devices-by-savedquery":
            results = get_by_sq(api_obj=client.devices)
            return_results(results)  # noqa: F821, F405
        elif command == "axonius-get-users-by-savedquery":
            results = get_by_sq(api_obj=client.users)
            return_results(results)  # noqa: F821, F405
        elif command == "axonius-get-users-by-mail":
            results = get_by_value(api_obj=client.users, method_name="mail")
            return_results(results)  # noqa: F821, F405
        elif command == "axonius-get-users-by-username":
            results = get_by_value(api_obj=client.users, method_name="username")
            return_results(results)  # noqa: F821, F405
        elif command == "axonius-get-devices-by-hostname":
            results = get_by_value(api_obj=client.devices, method_name="hostname")
            return_results(results)  # noqa: F821, F405
        elif command == "axonius-get-devices-by-ip":
            results = get_by_value(api_obj=client.devices, method_name="ip")
            return_results(results)  # noqa: F821, F405
        elif command == "axonius-get-devices-by-mac":
            results = get_by_value(api_obj=client.devices, method_name="mac")
            return_results(results)  # noqa: F821, F405

    except Exception as exc:
        demisto.error(traceback.format_exc())

        msg: List[str] = [f"Failed to execute {command} command", "Error:", str(exc)]
        return_error("\n".join(msg))  # noqa: F821, F405


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
