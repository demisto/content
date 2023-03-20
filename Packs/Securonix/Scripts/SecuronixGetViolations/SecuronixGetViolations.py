import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' MAIN FUNCTION '''


def main():
    try:
        # Get the Violations data from the Incident Context.
        violations = demisto.get(demisto.context(), 'Securonix.ViolationData')

        if not violations:
            return_results(
                CommandResults(
                    readable_output="\n#### No violations information available for threat."
                )
            )
        else:
            # If only 1 violation, convert it into list.
            if isinstance(violations, dict):
                violations = [violations]

            # Get the latest 200 violations from the API.
            violation_output = violations[-200:]

            heading = f"\n# Latest {len(violation_output)} Violation Events:"

            headers = [
                "Eventid", "Violator", "Policyname", "Riskthreatname", "Tenantname", "Category", "Jobstarttime"
            ]

            human_readable = tableToMarkdown(
                heading,
                t=remove_empty_elements(violation_output),
                headers=headers,
                removeNull=True
            )

            if len(violations) > 200:
                human_readable += "\n### For all violations navigate to the War Room and search with the filter " \
                                  "\"Playbook task results\". "
            return_results(CommandResults(readable_output=human_readable))

    except Exception as e:
        return_results(CommandResults(readable_output=f"\n#### Could not find violations Information. \n {e}"))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
