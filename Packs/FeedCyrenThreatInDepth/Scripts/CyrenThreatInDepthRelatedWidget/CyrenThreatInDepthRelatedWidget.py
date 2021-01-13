import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from datetime import datetime


SCORE_TO_REPUTATION_TEXT = {
    Common.DBotScore.NONE: f"None ({Common.DBotScore.NONE})",
    Common.DBotScore.GOOD: f"Good ({Common.DBotScore.GOOD})",
    Common.DBotScore.SUSPICIOUS: f"Suspicious ({Common.DBotScore.SUSPICIOUS})",
    Common.DBotScore.BAD: f"Bad ({Common.DBotScore.BAD})",
}


def create_relationship_object(value: str, relationship_type: str, indicator_type: str,
                               timestamp: str, entity_category: str, reputation: int = Common.DBotScore.NONE):
    try:
        timestamp_parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        timestamp_human_readable = timestamp_parsed.strftime("%Y-%m-%d, %H:%M:%S")
    except ValueError:
        demisto.info("could not parse timestamp %s, keeping original string", timestamp)
        timestamp_human_readable = timestamp

    indicator_object = {
        "Value": f"{value}\n",
        "Reputation": SCORE_TO_REPUTATION_TEXT[reputation],
        "Relationship Type": relationship_type,
        "Indicator Type": indicator_type,
        "Timestamp UTC": timestamp_human_readable,
        "Entity Category": entity_category,
    }

    return indicator_object


def cyren_feed_relationship(args) -> CommandResults:
    if not "indicator" in args:
        raise ValueError("Please provide 'indicator' argument!")

    indicator = args["indicator"]
    relationships = indicator.get("CustomFields", {}).get("cyrenfeedrelationships", []) or []

    content = []

    for item in relationships:
        ioc_value = item.get("value", "")
        results = demisto.searchIndicators(value=ioc_value).get("iocs", [])

        if results:
            result = results[0]
            ioc_score = result.get("score")
            ioc_id = result.get("id")

            content.append(create_relationship_object(
                value=f"[{ioc_value}](#/indicator/{ioc_id})" if ioc_value else "",
                relationship_type=item.get("relationshiptype"),
                indicator_type=item.get("indicatortype"),
                timestamp=item.get("timestamp"),
                entity_category=item.get("entitycategory"),
                reputation=ioc_score,
            ))

        else:
            # In case that no related indicators were found, return the table without the link.
            content.append(create_relationship_object(
                value=ioc_value,
                relationship_type=item.get("relationshiptype"),
                indicator_type=item.get("indicatortype"),
                timestamp=item.get("timestamp"),
                entity_category=item.get("entitycategory"),
            ))

    headers = ["Indicator Type", "Value", "Reputation", "Relationship Type", "Entity Category", "Timestamp UTC"]
    output = tableToMarkdown("", content, headers, removeNull=True)
    return CommandResults(readable_output=output)


def main(args):
    try:
        return_results(cyren_feed_relationship(args))
    except Exception as e:
        return_error(f"Failed to execute CyrenThreatInDepthRelatedWidget. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main(demisto.args())
