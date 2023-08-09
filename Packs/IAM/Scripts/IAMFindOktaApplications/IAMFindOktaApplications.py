import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def to_cli_name(field_name):
    return field_name.lower().replace(" ", "")


OKTA_INSTANCE_FIELD = to_cli_name("Okta IAM Instance")
OKTA_APPS_FIELD = to_cli_name("Available Okta applications")
OKTA_APPS_DATA_FIELD = to_cli_name("Available Okta applications data")
APPLICATION_ID_PLACEHOLDER = "Insert Okta Application ID"
SINGLE_SELECT_PLACEHOLDER = "Select"


def get_apps_from_okta(okta_iam_instance):
    full_res = []
    okta_apps_data = {}
    if okta_iam_instance != SINGLE_SELECT_PLACEHOLDER:
        page_num = 0
        apps_batch = get_apps_batch(okta_iam_instance, page_num)
        while apps_batch:
            full_res.extend(apps_batch)
            page_num += 1
            apps_batch = get_apps_batch(okta_iam_instance, page_num)

    configured_app_ids = get_configured_application_ids(okta_iam_instance)

    for app in full_res:
        if app.get("ID") not in configured_app_ids:
            okta_apps_data[app.get("Label")] = {
                "ID": app.get("ID"),
                "Name": app.get("Name"),
            }

    return list(okta_apps_data.keys()), json.dumps(okta_apps_data)


def get_apps_batch(okta_iam_instance, page_num):
    args = {"page": page_num, "using": okta_iam_instance}
    res = demisto.executeCommand("okta-iam-list-applications", args)[0]["Contents"]
    return res


def get_configured_application_ids(okta_iam_instance):
    args = {"using": okta_iam_instance}
    configuration = demisto.executeCommand("okta-iam-get-configuration", args)[0][
        "Contents"
    ]
    if not configuration:
        configuration = []
    return [conf.get("ApplicationID") for conf in configuration]


def main():
    incident = demisto.incidents()[0]
    custom_fields = incident.get("CustomFields")
    okta_iam_instance = custom_fields.get(OKTA_INSTANCE_FIELD)

    app_labels, okta_apps_data = get_apps_from_okta(okta_iam_instance)

    # update okta apps data for later use
    incident_data = {
        "id": incident.get("id"),
        "customFields": {OKTA_APPS_DATA_FIELD: okta_apps_data},
    }
    demisto.executeCommand("setIncident", incident_data)

    demisto.results({"hidden": False, "options": sorted(app_labels)})


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
