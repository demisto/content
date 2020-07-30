"""Demisto Integration for Axonius."""
from typing import Any, List

import axonius_api_client
import demistomock as demisto


def test_module(client: axonius_api_client.connect.Connect) -> str:
    client.start()
    return "ok"


def get_by_sq(api_obj: axonius_api_client.api.assets.AssetMixin) -> List[dict]:
    args: dict = demisto.args()
    name: str = args["saved_query_name"]
    max_rows: int = args.get("max_results", None)
    # XXX: this could be 100's of thousands results, should we default to limit to
    # something sane like 20??
    # XXX: How to handle exceptions and return
    results = api_obj.get_by_saved_query(name=name, max_rows=max_rows)
    return results


# XXX what is the full path of the type of object returned by return_results??
def main() -> Any:
    """PARSE AND VALIDATE INTEGRATION PARAMS."""
    params: dict = demisto.params()
    command: str = demisto.command()

    url: str = params["ax_url"]
    key: str = params.get("credentials")["ax_key"]
    secret: str = params.get("credentials")["ax_secret"]
    certverify: bool = params.get("insecure", False)
    # XXX: proxy: str = params.get("proxy", None)

    demisto.debug(f"Command being called is {command}")
    # XXX: better to use LOG or demisto.debug ????

    try:
        client = axonius_api_client.Connect(
            url=url,
            key=key,
            secret=secret,
            certverify=certverify,
            # https_proxy=proxy,
        )

        if command == "test-module":
            # XXX: does this have to be called "test-module"?
            result: str = test_module(client=client)
            demisto.results(result)

        elif command == "axonius-get-devices-by-savedquery":
            results: List[dict] = get_by_sq(api_obj=client.devices)
            return_results(results)  # noqa:F821

        elif command == "axonius-get-users-by-savedquery":
            results: List[dict] = get_by_sq(api_obj=client.users)
            return_results(results)  # noqa:F821

    except Exception as exc:
        msg: str = f"Failed to execute {command} command. Error: {exc}"
        return_error(msg)  # noqa:F821


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
