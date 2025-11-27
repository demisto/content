import demistomock as demisto
from CommonServerPython import *


def update_integration_instance_state(instance_name: str, enable: bool):
    """
    Retrieves an integration instance's configuration by name and updates its 'enabled' state.
    """

    # 1. SEARCH FOR INSTANCE TO GET ITS CONFIGURATION
    demisto.debug(f"Searching for integration {instance_name=}.")

    search_res = demisto.executeCommand("core-api-post", {"uri": "/settings/integration/search", "body": {}})

    if is_error(search_res):
        raise DemistoException(f"Failed to search integrations via API: {get_error(search_res)}")

    instances = search_res[0]["Contents"]["response"]["instances"]
    instance_config = None
    for instance in instances:
        if instance["name"] == instance_name:
            instance_config = instance
            break

    if not instance_config:
        raise DemistoException(f"Could not find instance for instance: '{instance_name}'.")

    # 2. PREPARE THE UPDATE PAYLOAD
    update_payload = {
        "id": instance_config.get("id"),
        "brand": instance_config.get("brand"),
        "name": instance_name,
        "data": instance_config.get("data"),
        "isIntegrationScript": instance_config.get("isIntegrationScript", True),
        "version": instance_config.get("version", -1),
        "enabled": "true" if enable else "false",
    }

    action = "Enabling" if enable else "Disabling"
    demisto.debug(f"{action} integration instance {instance_name} (ID: {instance_config['id']})")

    update_res = demisto.executeCommand("core-api-put", {"uri": "/settings/integration", "body": json.dumps(update_payload)})

    if is_error(update_res):
        raise DemistoException(f"Failed to {action.lower()} instance {instance_name} via API: {get_error(update_res)}")

    demisto.debug(f"Successfully {action.lower()} integration instance {instance_name}.")
    return CommandResults(readable_output=f"Successfully {action.lower()} integration instance **{instance_name}**.")


def main():
    try:
        args = demisto.args()
        instance_name = args.get("instance_name")
        enable_state = argToBoolean(args.get("enable"))

        if not instance_name or enable_state is None:
            raise DemistoException("Arguments 'instance_name' and 'enable' are required.")

        return_results(update_integration_instance_state(instance_name, enable_state))

    except Exception as ex:
        return_error(f"Error executing UpdateIntegrationInstanceState script. Exception: {ex!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
