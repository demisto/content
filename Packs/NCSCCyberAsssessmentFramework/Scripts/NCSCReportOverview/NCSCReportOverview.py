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
        achieved: int = 0
        partially_achieved: int = 0
        not_achieved: int = 0

        custom_fields = incident.get("CustomFields")
        assessment_a_details = json.loads(custom_fields.get("cafaresultraw"))
        assessment_a_achievement = calculate_overall(assessment_a_details)
        if assessment_a_achievement == "Achieved":
            achieved += 1
        elif assessment_a_achievement == "Partially Achieved":
            partially_achieved += 1
        else:
            not_achieved += 1

        assessment_b_details = json.loads(custom_fields.get("cafbresultraw"))
        assessment_b_achievement = calculate_overall(assessment_b_details)
        if assessment_b_achievement == "Achieved":
            achieved += 1
        elif assessment_b_achievement == "Partially Achieved":
            partially_achieved += 1
        else:
            not_achieved += 1

        assessment_c_details = json.loads(custom_fields.get("cafcresultraw"))
        assessment_c_achievement = calculate_overall(assessment_c_details)
        if assessment_c_achievement == "Achieved":
            achieved += 1
        elif assessment_c_achievement == "Partially Achieved":
            partially_achieved += 1
        else:
            not_achieved += 1

        assessment_d_details = json.loads(custom_fields.get("cafdresultraw"))
        assessment_d_achievement = calculate_overall(assessment_d_details)
        if assessment_d_achievement == "Achieved":
            achieved += 1
        elif assessment_d_achievement == "Partially Achieved":
            partially_achieved += 1
        else:
            not_achieved += 1

        md += f"Out of the four objectives answered:\n\n### Achieved: **{achieved}**\n\n### Partially Achieved: " \
              f"**{partially_achieved}**\n\n### Not Achieved: **{not_achieved}**\n\n"

        if not_achieved or partially_achieved:
            md += "There is material available on the NCSC Website under [Table view of principles and related " \
                  "guidance](https://www.ncsc.gov.uk/collection/caf/table-view-principles-and-related-guidance) that " \
                  "will help with achieving all those that are either 'Not Achieved' or 'Partially Achived'.\n\n"

        else:
            md += "This assessment was fully 'Achieved', great work! There is nothing more to do than ensure that " \
                  "your standards remain as high as they are now.\n\n"

    else:
        md = ""
    demisto.results(md)


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
