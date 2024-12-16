import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from enum import Enum
from random import randrange

import yaml


class FeedName(str, Enum):
    IP_REPUTATION = "ip_reputation"
    PHISHING_URLS = "phishing_urls"
    MALWARE_URLS = "malware_urls"
    MALWARE_FILES = "malware_files"


def simple_result(text):
    return CommandResults(readable_output=text)


def create_random_hunt_incident(args):
    indicator_type = args.get("indicator_type")
    incident_type = args.get("incident_type", "Hunt")
    assignee = args.get("assignee")

    query_parts = [
        "lastseenbysource:>=\"7 days ago\"",
        "sourceBrands:CyrenThreatInDepth ",
        "investigationIDs:\"\"",
        "cyrensourcetags:primary",
        "-cyrensourcetags:related",
        "cyrenfeedaction:add",
        "cyrenfeedrelationships.timestamp:>=\"2000-01-01T00:00:00 +0100\"",
    ]
    if indicator_type == FeedName.IP_REPUTATION:
        query_parts.append("type:IP")
        query_parts.append("cyreniprisk:>80")
    elif indicator_type == FeedName.MALWARE_URLS:
        query_parts.append("tags:malware")
        query_parts.append("type:URL")
    elif indicator_type == FeedName.PHISHING_URLS:
        query_parts.append("tags:phishing")
        query_parts.append("type:URL")
    elif indicator_type == FeedName.MALWARE_FILES:
        query_parts.append("type:File")

    query = " ".join(query_parts)

    random_page = randrange(10) + 1
    res = demisto.executeCommand("findIndicators", {"query": query, "size": 1, "page": random_page})
    if isError(res[0]):
        raise DemistoException(f"Could not find any indicators: {res}")

    indicators = res[0]["Contents"]
    if not any(indicators):
        return simple_result(f"Could not find any indicators for \"{query}\"!")

    incident = {"name": "Cyren Threat InDepth Threat Hunt",
                "type": incident_type,
                "details": yaml.dump(indicators[0])}

    if assignee:
        incident["owner"] = assignee
    else:
        res = demisto.executeCommand("getUsers", {"current": True})
        if not isError(res[0]):
            current_user = res[0]["Contents"][0]
            current_user_id = current_user.get("id")
            incident["owner"] = current_user_id

    res = demisto.executeCommand("createNewIncident", incident)
    if isError(res[0]):
        raise DemistoException(f"Could not create new incident: {res}")

    created_incident = res[0]
    id = created_incident.get("EntryContext", {}).get("CreatedIncidentID")
    data = f"Successfully created incident {incident['name']}.\n" \
           f"Click here to investigate: [{id}](#/incident/{id})."
    res = demisto.executeCommand("investigate", {"id": id})
    if isError(res[0]):
        data = data + "\n(An investigation has not been started.)"

    return simple_result(text=data)


def main(args):
    try:
        return_results(create_random_hunt_incident(args))
    except Exception as e:
        return_error(f"Failed to execute CyrenThreatInDepthRandomHunt. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main(demisto.args())
