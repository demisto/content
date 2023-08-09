import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

APPLICATIONS_HEADER = ["Brand", "Instance Name", "User ID", "Active"]


user_applications = demisto.get(
    demisto.args()["indicator"], "CustomFields.applications"
)

if user_applications:
    try:
        user_applications = json.loads(user_applications)
        md = tableToMarkdown(
            name="  ",
            t=user_applications,
            headers=APPLICATIONS_HEADER,
            headerTransform=string_to_table_header,
            removeNull=True,
        )
    except Exception:
        md = user_applications

    return_results(CommandResults(readable_output=md))

else:
    return_results(
        "The user doesn't seem to be synced into any application at the moment. This will update when IAM - App Add, IAM - App Remove or IAM - App Update incidents occur."
    )
