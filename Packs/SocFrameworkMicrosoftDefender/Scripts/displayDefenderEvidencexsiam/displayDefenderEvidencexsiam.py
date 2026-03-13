import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# This is a helper script designed to be used with the "[BETA] MSGraph Endpoint Alert Layout". This populates a dynamic section of the layout with the full MS Graph alert record
#



def main():

    # Fetch data from context
    try:
        context_data = demisto.alert()
        context_data = context_data['CustomFields']['microsoftgraphsecurityalertevidence']
        if isinstance(context_data, dict):

            return_results(context_data)
        else:
            data = json.loads(context_data)
            return_results(data)

    except Exception as e:
        error_statement = "🔴 There seems to be an issue rendering this field.\n\nContents of this are controlled by the Script 'displayDefenderEvidence_xsiam' which can be located under Investigation & Response -> Automation -> Scripts.\nThis script pulls data from the *microsoftgraphsecurityalertevidence key in the alert/issue context - if that key is improperly populated, or missing, nothing will be displayed here. Please review the correlation rule, alert mapping, and MS Graph Alert dataset. "
        error_statement += "\n\nException thrown by script: " + str(e)
        return_results(error_statement)

if __name__ in ("builtins", "__builtin__", "__main__"):
    main()

