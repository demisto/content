import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def to_cli_name(field_name):
    return field_name.lower().replace(" ", "")


OKTA_INSTANCE_FIELD = to_cli_name("Okta IAM Instance")
OKTA_IAM_CONFIGURATION_FIELD = to_cli_name("Okta IAM Configuration")
SINGLE_SELECT_PLACEHOLDER = "Select"


def create_configuration_markdown(configuration):
    data = []
    # in the next lint, the empty string is the logo header name
    headers = [
        "Integration instance in XSOAR",
        "App name in Okta",
        "App label in Okta",
        "App ID in Okta",
        "",
    ]
    for conf in configuration:
        data.append(
            {
                headers[0]: conf.get("Instance"),
                headers[1]: conf.get("Name"),
                headers[2]: conf.get("Label"),
                headers[3]: conf.get("ApplicationID"),
                headers[4]: conf.get("Logo"),
            }
        )
    return tableToMarkdown("", data, headers=headers)


def main():
    incident = demisto.incidents()[0]
    incident_id = incident.get("id")
    custom_fields = incident.get("CustomFields")
    okta_iam_instance = custom_fields.get(OKTA_INSTANCE_FIELD)

    if okta_iam_instance and okta_iam_instance != SINGLE_SELECT_PLACEHOLDER:
        configuration = demisto.executeCommand(
            "okta-iam-get-configuration", {"using": okta_iam_instance}
        )[0]["Contents"]
        if not configuration:
            configuration = []
        markdown = create_configuration_markdown(configuration)
        demisto.executeCommand(
            "setIncident",
            {
                "id": incident_id,
                "customFields": {OKTA_IAM_CONFIGURATION_FIELD: markdown},
            },
        )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
