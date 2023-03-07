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
            heading = "\n# Violations Events Information:"

            headers = [
                "Eventid", "Violator", "Policyname", "TenantName", "ResourceName", "Riskthreatname", "Ipaddress"
                "Accountname", "Baseeventid", "Category", "Categoryseverity", "Destinationntdomain", "Deviceexternalid",
                "Generationtime", "ID", "Invalid", "Jobstarttime", "Message", "Policyname",
                "TenantID", "Timeline", "Transactionstring1", "ResourceGroupName", "Resourcegroupid",
                "ResourceType", "Emailsenderdomain", "Requesturl", "Emailrecipient", "Emailsender"
            ]

            human_readable = tableToMarkdown(heading, t=violations, headers=headers, removeNull=True)
            return_results(CommandResults(readable_output=human_readable))

    except Exception as e:
        return_results(CommandResults(readable_output=f"\n#### Could not find violations Information. \n {e}"))


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
