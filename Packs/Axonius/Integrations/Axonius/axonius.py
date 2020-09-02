"""Demisto Integration for Axonius."""
import traceback
from typing import Any, List, Optional

import demistomock as demisto
from axonius_api_client.api.assets.asset_mixin import AssetMixin
from axonius_api_client.connect import Connect
from axonius_api_client.tools import dt_parse, strip_left
from CommonServerPython import *
from CommonServerUserPython import *

MAX_ROWS: int = 50
"""Maximum number of assets to allow user to fetch."""
SKIPS: List[str] = ["specific_data.data.image"]
"""Fields to remove from each asset if found."""


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


def test_module(client: Connect) -> str:
    """Tests Axonius API Client connectivity."""
    client.start()
    return "ok"


def parse_kv(key: str, value: Any) -> Any:
    """Parse time stamp into required format."""
    if "last_seen" in key:
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


def get_by_sq(api_obj: AssetMixin,) -> CommandResults:
    """Get assets with their defined fields returned by a saved query."""
    args: dict = demisto.args()
    name: str = args["saved_query_name"]
    max_rows: int = get_int_arg(key="max_results", required=False, default=MAX_ROWS)

    assets = api_obj.get_by_saved_query(name=name, max_rows=max_rows)
    check_asset_count(api_obj=api_obj, assets=assets, src=f"Saved query named {name}")
    results = [parse_asset(asset=asset) for asset in assets]

    return CommandResults(
        outputs_prefix=f"Axonius.{api_obj.__class__.__name__}",
        outputs_key_field="internal_axon_id",
        outputs=results,
    )


def check_asset_count(api_obj: AssetMixin, assets: List[dict], src: str):
    """Raise exception for no assets found."""
    if not assets:
        api_name = api_obj.__class__.__name__
        raise Exception(f"No {api_name} assets returned from {src}.")


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    params: dict = demisto.params()
    command: str = demisto.command()

    url: str = params["ax_url"]
    key: str = params["ax_key"]
    secret: str = params["ax_secret"]
    certverify: bool = not params.get("insecure", False)

    handle_proxy()

    demisto.debug(f"Command being called is {command}")

    try:
        client = Connect(
            url=url, key=key, secret=secret, certverify=certverify, certwarn=False,
        )

        if command == "test-module":
            result = test_module(client=client)
            return_results(result)

        elif command == "axonius-get-devices-by-savedquery":
            results = get_by_sq(api_obj=client.devices)
            return_results(results)

        elif command == "axonius-get-users-by-savedquery":
            results = get_by_sq(api_obj=client.users)
            return_results(results)

    except Exception as exc:
        demisto.error(traceback.format_exc())

        msg: List[str] = [f"Failed to execute {command} command", "Error:", str(exc)]
        return_error("\n".join(msg))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
