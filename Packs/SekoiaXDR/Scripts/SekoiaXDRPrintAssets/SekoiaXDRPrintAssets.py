import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_assets_info(assets_ids: list):
    assets_infos = []
    for asset in assets_ids:
        asset_infos = execute_command("sekoia-xdr-get-asset", {"asset_uuid": asset})
        asset_dict = {
            "name": asset_infos["name"],  # type: ignore
            "description": asset_infos["description"],  # type: ignore
        }
        assets_infos.append(asset_dict)
    return assets_infos


def get_assets_ids(alert_uuid: str):
    try:
        alert_infos = execute_command("sekoia-xdr-get-alert", {"id": alert_uuid})
    except Exception as e:
        return_error(f"Failed to get alert information: {str(e)}")

    assets_ids = alert_infos.get("assets")  # type: ignore
    if assets_ids:
        assets_infos = get_assets_info(assets_ids)
        headers = ["name", "description"]
        readable_output = tableToMarkdown(
            "Impacted assets:", assets_infos, headers=headers
        )
    else:
        readable_output = (
            "### {{color:green}}(There is no case information related to this alert.)"
        )

    return readable_output


def main():
    incident = demisto.incident()
    alert_uuid = incident.get("CustomFields", {}).get("alertid")

    readable_output = get_assets_ids(alert_uuid)
    command_results = CommandResults(readable_output=readable_output)
    return_results(command_results)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
