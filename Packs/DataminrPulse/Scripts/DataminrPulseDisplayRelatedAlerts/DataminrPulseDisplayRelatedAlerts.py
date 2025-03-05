import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""DataminrPulseDisplayRelatedAlerts Script for Cortex XSOAR (aka Demisto)."""


""" MAIN FUNCTION """


def main():
    try:
        # Get the related alerts data from the Incident Context.
        alerts = demisto.get(demisto.context(), "RelatedAlerts")

        if not alerts or alerts == "null":
            return_results(CommandResults(readable_output="\n#### No related alerts available for this alert."))
        else:
            heading = "\n# Related Alerts Information: "
            hr_outputs = []
            HR_DATE_FORMAT = "%d %b %Y, %I:%M %p UTC"
            for alert in alerts:
                watchlist_names = [watchlist.get("name", "") for watchlist in alert.get("watchlistsMatchedByType", [])]

                hr_outputs.append(
                    {
                        "Alert Type": alert.get("alertType", {}).get("name", ""),
                        "Alert ID": alert.get("alertId", ""),
                        "Caption": alert.get("caption", ""),
                        "Alert URL": alert.get("expandAlertURL", ""),
                        "Watchlist Name": ", ".join(watchlist_names),
                        "Alert Time": timestamp_to_datestring(alert.get("eventTime", 0), HR_DATE_FORMAT, is_utc=True),
                        "Alert Location": alert.get("eventLocation", {}).get("name"),
                        "Post Link": alert.get("post", {}).get("link", ""),
                        "Is source verified": alert.get("source", {}).get("verified", ""),
                        "Publisher Category": alert.get("publisherCategory", {}).get("name", ""),
                    }
                )

            # Table headers.
            headers = [
                "Alert Type",
                "Alert ID",
                "Caption",
                "Alert URL",
                "Watchlist Name",
                "Alert Time",
                "Alert Location",
                "Post Link",
                "Is source verified",
                "Publisher Category",
            ]
            human_readable = tableToMarkdown(heading, hr_outputs, headers, removeNull=True, url_keys=["Post Link", "Alert URL"])

            return_results(CommandResults(readable_output=human_readable))

    except Exception as e:
        return_results(CommandResults(readable_output=f"\n#### Could not find related alerts Information. \n {e}"))


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
