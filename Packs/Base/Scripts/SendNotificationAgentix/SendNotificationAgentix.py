import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

BRAND_MAPPING = {
    "Microsoft Teams": {
        "brand": "Microsoft Teams",
        "valid_args": {"brand", "message", "to", "channel", "team"},
    },
    "Slack": {
        "brand": "SlackV3",
        "valid_args": {"brand", "message", "to", "channel", "channel_id"},
    },
    "Mattermost": {
        "brand": "MattermostV2",
        "valid_args": {"brand", "message", "to", "channel"},
    },
    "Zoom": {
        "brand": "Zoom",
        "valid_args": {"brand", "message", "to", "channel", "channel_id"},
    },
}


def send_notification_by_brand(brand: str, args: dict):
    if not (brand_map := BRAND_MAPPING.get(brand)):
        raise DemistoException(f"Brand - {brand} is not supported. Supported brands: {BRAND_MAPPING.keys()}")

    valid_args = set(brand_map.get("valid_args", []))
    invalid_args = list(set(args.keys()) - valid_args)
    if invalid_args:
        raise DemistoException(f"Arguments {invalid_args} are not supported for brand - {brand}")

    command_args = {"using-brand": brand_map.get("brand")}
    command_args.update(args)

    return demisto.executeCommand("send-notification", args=command_args)


def main():
    try:
        args = demisto.args()
        demisto.debug(f"Calling SendNotificationAgentix with args: {args}")

        return_results(send_notification_by_brand(args.get("brand"), args))

    except Exception as ex:
        return_error(f"Failed to execute SendNotificationAgentix. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
