import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def to_cli_name(field_name):
    return field_name.lower().replace(" ", "")


OKTA_INSTANCE_FIELD = to_cli_name("Okta IAM Instance")
INSTANCE_NAME_FIELD = to_cli_name("Integration instance in XSOAR")
SELECTED_APP_FIELD = to_cli_name("Available Okta applications")
APP_ID_FIELD = to_cli_name("Application ID in Okta")
APP_NAME_FIELD = to_cli_name("Application name in Okta")
CONNECTED_INSTANCE_NAME_FIELD = to_cli_name("Connected integration instance in XSOAR")
CONNECTED_APP_ID_FIELD = to_cli_name("Connected application ID in Okta")
CONFIGURATION_FIELD = to_cli_name("Okta IAM Configuration")
SINGLE_SELECT_PLACEHOLDER = "Select"


def get_app_from_okta(app_id, okta_iam_instance):
    okta_apps = demisto.executeCommand(
        "okta-iam-list-applications", {"query": app_id, "using": okta_iam_instance}
    )[0]["Contents"]
    if len(okta_apps) == 1 and okta_apps[0].get("ID") == app_id:
        okta_apps[0].pop("ID")
        okta_apps[0]["ApplicationID"] = app_id
        return okta_apps[0]
    return None


def is_valid_instance(instance_name):
    all_instances = demisto.getModules()
    for instance, details in all_instances.items():
        if (
            instance == instance_name
            and details.get("category") == "Identity and Access Management"
            and details.get("state") == "active"
        ):
            return True
    return False


def check_instance_and_application_availability(configuration, instance_name, app_id):
    for conf in configuration:
        if conf.get("Instance") == instance_name:
            app_id = conf.get("ApplicationID")
            raise DemistoException(
                f'The selected instance is already connected to the application "{app_id}".'
            )
        elif conf.get("ApplicationID") == app_id:
            instance = conf.get("Instance")
            raise DemistoException(
                f'The selected application is already connected to instance "{instance}".'
            )


def remove_configuration(configuration, custom_fields):
    config_removed = False
    instance_name = custom_fields.get(CONNECTED_INSTANCE_NAME_FIELD)
    if instance_name != SINGLE_SELECT_PLACEHOLDER:
        for conf in configuration:
            if conf.get("Instance") == instance_name:
                configuration.remove(conf)
                config_removed = True
                break
    return config_removed


def add_configuration(configuration, custom_fields, okta_iam_instance):
    config_added = False
    instance_name = custom_fields.get(INSTANCE_NAME_FIELD)
    app_id = custom_fields.get(APP_ID_FIELD)

    if instance_name != SINGLE_SELECT_PLACEHOLDER:
        check_instance_and_application_availability(
            configuration, instance_name, app_id
        )

        okta_app = get_app_from_okta(app_id, okta_iam_instance)
        if okta_app is None:
            raise DemistoException(f"Invalid Application ID: {app_id}")

        okta_app["Instance"] = instance_name
        configuration.append(okta_app)
        config_added = True
    return config_added


def update_configuration_in_okta(configuration, okta_iam_instance):
    cmd_res = demisto.executeCommand(
        "okta-iam-set-configuration",
        {"configuration": configuration, "using": okta_iam_instance},
    )
    if is_error(cmd_res):
        raise Exception(
            "An unexpected error occurred - the configuration was not updated."
        )


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
    custom_fields = incident.get("CustomFields")
    okta_iam_instance = custom_fields.get(OKTA_INSTANCE_FIELD)

    configuration = demisto.executeCommand(
        "okta-iam-get-configuration", {"using": okta_iam_instance}
    )[0]["Contents"]
    if not configuration:
        configuration = []

    if demisto.args().get("add_or_remove") == "remove":
        config_removed = remove_configuration(configuration, custom_fields)
        if not config_removed:
            return
        custom_fields_to_clear = {
            CONNECTED_APP_ID_FIELD: "",
            CONNECTED_INSTANCE_NAME_FIELD: SINGLE_SELECT_PLACEHOLDER,
        }
    else:
        config_added = add_configuration(
            configuration, custom_fields, okta_iam_instance
        )
        if not config_added:
            return
        custom_fields_to_clear = {
            INSTANCE_NAME_FIELD: SINGLE_SELECT_PLACEHOLDER,
            APP_ID_FIELD: "",
            APP_NAME_FIELD: "",
            SELECTED_APP_FIELD: SINGLE_SELECT_PLACEHOLDER,
        }

    update_configuration_in_okta(configuration, okta_iam_instance)

    markdown = create_configuration_markdown(configuration)
    custom_fields = {CONFIGURATION_FIELD: markdown}
    custom_fields.update(custom_fields_to_clear)
    demisto.executeCommand(
        "setIncident", {"id": incident.get("id"), "customFields": custom_fields}
    )


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
