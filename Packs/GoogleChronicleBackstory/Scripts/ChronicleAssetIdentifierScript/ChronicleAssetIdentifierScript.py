from typing import Any

from CommonServerPython import *


def has_key(dictionary: dict[str, Any], key: str) -> bool:
    """
    Check whether dictionary has given key is present or not

    :param dictionary: Dictionary that need to check if key present or not
    :param key: Key value that need to check
    :return: Boolean value based on given key is present in the dictionary
    """
    return key in dictionary


def get_entry_context(identifiers: dict[str, Any]) -> dict[str, list[list | None]]:
    """
    Prepare entry context for asset identifiers - hostname, IP address and MAC address.

    :param identifiers: asset information that contains hostname, IP address and MAC address.
    :return: Entry context for asset identifiers.
    """
    asset_list = []

    if has_key(identifiers, key="HostName"):
        asset_list.append(identifiers.get("HostName"))
    elif has_key(identifiers, key="IpAddress"):
        asset_list.append(identifiers.get("IpAddress"))
    elif has_key(identifiers, key="MacAddress"):
        asset_list.append(identifiers.get("MacAddress"))

    ec = {"AssetIdentifiers": asset_list}
    return ec


def main() -> None:  # pragma: no cover
    try:
        artifact_identifiers = demisto.args().get("artifact_identifiers", [])

        ec = get_entry_context(artifact_identifiers)
        demisto.results({"Type": entryTypes["note"], "EntryContext": ec, "Contents": {}, "ContentsFormat": formats["json"]})
    except Exception as e:
        return_error(f"Error occurred while extracting Domain(s):\n{e}")


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
