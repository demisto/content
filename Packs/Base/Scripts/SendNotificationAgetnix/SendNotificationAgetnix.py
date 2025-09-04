import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def send_notification_by_brand(brand: str, args: dict):
    args.update({"using-brand": brand})
    return demisto.executeCommand("send-notification", args=args)
        
def main():
    try:
        args = demisto.args()
        brands = argToList(args.get("brand"))
        for brand in brands:
            return_results(send_notification_by_brand(brand, args))
    except Exception as ex:
        return_error(f"Failed to execute SendNotificationAgetnix. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
