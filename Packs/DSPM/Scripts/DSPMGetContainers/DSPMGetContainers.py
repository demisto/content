import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback


def get_containers(args: dict[str, Any]) -> CommandResults:
    """
    Function takes asset file data as argument and
    returns a list of all containers.
    """

    asset_files = args.get("asset_files")
    containers = []
    if not asset_files:
        raise ValueError("Asset files data is not specified")

    asset_files = asset_files.get("files")

    for assets in asset_files:
        path = assets.get("path")
        folder_name = path.split("/")[0]
        containers.append(folder_name)
    return CommandResults(
        outputs_prefix="containers",
        outputs=containers,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(get_containers(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute get_containers. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
