import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from enum import Enum
from datetime import datetime
import json


SCORE_TO_REPUTATION_TEXT = {
    Common.DBotScore.NONE: f"None ({Common.DBotScore.NONE})",
    Common.DBotScore.GOOD: f"Good ({Common.DBotScore.GOOD})",
    Common.DBotScore.SUSPICIOUS: f"Suspicious ({Common.DBotScore.SUSPICIOUS})",
    Common.DBotScore.BAD: f"Bad ({Common.DBotScore.BAD})",
}


class AcceptedHeader(str, Enum):
    INDICATOR_TYPE = "Indicator Type"
    VALUE = "Value"
    REPUTATION = "Reputation"
    RELATIONSHIP_TYPE = "Relationship Type"
    ENTITY_CATEGORY = "Entity Category"
    TIMESTAMP = "Timestamp UTC"


ACCEPTED_HEADERS = [
    AcceptedHeader.INDICATOR_TYPE, AcceptedHeader.VALUE,
    AcceptedHeader.REPUTATION, AcceptedHeader.RELATIONSHIP_TYPE,
    AcceptedHeader.ENTITY_CATEGORY, AcceptedHeader.TIMESTAMP
]


def check_acceptable_headers(headers):
    for header in headers:
        if header not in ACCEPTED_HEADERS:
            raise ValueError(f"Please provide columns from {ACCEPTED_HEADERS}!")


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
    if "indicator" not in args:
        raise ValueError("Please provide 'indicator' argument!")

    indicator = args["indicator"]
    if isinstance(indicator, str):
        try:
            indicator = json.loads(indicator)
        except json.JSONDecodeError:
            raise ValueError("Please provide JSON-encoded 'indicator' param!")
    elif not isinstance(indicator, dict):
        raise ValueError("Please provide JSON-encoded 'indicator' param!")

    headers = args.get("columns", ACCEPTED_HEADERS)
    if isinstance(headers, str):
        headers = [s.strip() for s in headers.split(",")]

    check_acceptable_headers(headers)

    relationships = indicator.get("CustomFields", {}).get("cyrenfeedrelationships", []) or []

    content = []

    for item in relationships:
        ioc_value = item.get("value", "")
        search_indicators = IndicatorsSearcher()

        results = search_indicators.search_indicators_by_version(value=ioc_value).get("iocs", [])

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

    output = tableToMarkdown("", content, headers, removeNull=True)
    return CommandResults(readable_output=output)


def main(args):
    try:
        return_results(cyren_feed_relationship(args))
    except Exception as e:
        return_error(f"Failed to execute CyrenThreatInDepthRenderRelated. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main(demisto.args())
