import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def calculate_overall(data: dict = None) -> str:
    if not data:
        return ""
    results = [x["Result"] for x in data]
    if "Not Achieved" in results:
        return "Not Achieved"
    elif "Partially Achieved" in results:
        return "Partially Achieved"
    else:
        return "Achieved"


def main():

    query = '-status:closed -category:job type:"NCSC CAF Assessment"'
    incidents = demisto.executeCommand("getIncidents", {"query": query})[0]["Contents"][
        "data"
    ]
    if len(incidents) < 1:
        return ""
    incidents = sorted(incidents, key=lambda x: x["id"])
    incident = incidents[0]

    if incident:
        md: str = ""

        custom_fields = incident.get("CustomFields")
        assessment_a_details = json.loads(custom_fields.get("cafaresultraw"))
        assessment_b_details = json.loads(custom_fields.get("cafbresultraw"))
        assessment_c_details = json.loads(custom_fields.get("cafcresultraw"))
        assessment_d_details = json.loads(custom_fields.get("cafdresultraw"))

        assessments = [
            {
                "assessment": "CAF Objective A - Managing security risk",
                "details": assessment_a_details,
            },
            {
                "assessment": "CAF Objective B - Protecting against cyber-attack",
                "details": assessment_b_details,
            },
            {
                "assessment": "CAF Objective C - Detecting cyber security events",
                "details": assessment_c_details,
            },
            {
                "assessment": "CAF Objective D - Minimising the impact of cyber security incidents",
                "details": assessment_d_details,
            },
        ]

        for assessment in assessments:
            table = tableToMarkdown(
                assessment["assessment"],
                assessment["details"],
                ["Question", "Result", "Reason"],
            )
            md += f"{table}\n\n"

    else:
        md = ""
    demisto.results(md)


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
