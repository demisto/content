import json


def get_network_adapter_sys_ids(ip_address: str):
    command_results = demisto.executeCommand('servicenow-cmdb-records-list',
                                             {"class": "cmdb_ci_network_adapter", "query": f"ip_address={ip_address}"})
    result = command_results[0].get("Contents").get("result")
    network_adapter_sys_ids = [res.get("sys_id") for res in result]

    return network_adapter_sys_ids


def get_network_adapter(sid: str):
    cr = demisto.executeCommand('servicenow-cmdb-record-get-by-id', {"class": "cmdb_ci_network_adapter", "sys_id": sid})
    parsed = cr[0].get("Contents").get("result")
    attributes = parsed.get("attributes", {})
    instance_url = (attributes.get("sys_domain").get("link")).replace(
        "/api/now/table/sys_user_group/global", "")

    return {
        "sys_id": sid,
        "name": attributes.get("name"),
        "ip": attributes.get("ip_address"),
        "owner": attributes.get("assigned_to", {}).get("display_value", ""),
        "owner_id": attributes.get("assigned_to", {}).get("value", ""),
        "related_configuration_item_name": attributes.get("cmdb_ci", {}).get("display_value"),
        "related_configuration_item_id": attributes.get("cmdb_ci", {}).get("value"),
        "instance_url": instance_url,
        "url": f"{instance_url}/nav_to.do?uri=cmdb_ci_network_adapter.do?sys_id={sid}",
    }


def get_related_configuration_item(sid: str, instance_url: str):
    cr = demisto.executeCommand('servicenow-cmdb-record-get-by-id', {"class": "cmdb_ci", "sys_id": sid})
    parsed = cr[0].get("Contents").get("result")
    ci_class = parsed.get("attributes").get("sys_class_name")

    # re-fetch with explicit class
    cr = demisto.executeCommand('servicenow-cmdb-record-get-by-id', {"class": ci_class, "sys_id": sid})
    parsed = cr[0].get("Contents").get("result")

    return {
        "sys_id": sid,
        "name": parsed.get("attributes").get("name"),
        "ip": parsed.get("attributes").get("ip_address"),
        "owner": parsed.get("attributes").get("assigned_to", {}).get("display_value"),
        "owner_id": parsed.get("attributes").get("assigned_to", {}).get("value"),
        "hostname": parsed.get("attributes").get("host_name"),
        "os": parsed.get("attributes").get("os"),
        "os_version": parsed.get("attributes").get("os_version"),
        "ci_class": ci_class,
        "use": parsed.get("attributes").get("used_for"),
        "url": f"{instance_url}/nav_to.do?uri={ci_class}.do?sys_id={sid}"
    }


def main():
    """
    This script acts as a wrapper for the 'servicenow-cmdb-records-list' and 'servicenow-cmdb-record-get-by-id' commands.
    Given an IP address, the intended use is to pull the most valuable fields from ServiceNow CMDB cmdb_ci_network_adapter table.
    """
    ip_address = demisto.args().get('ip_address')
    if ip_address is None:
        return_error(f"Please provide an IP address.")

    try:
        related_ci_details = []
        network_adapter_sys_ids = get_network_adapter_sys_ids(ip_address)
        # https://[your-instance].service-now.com/nav_to.do?uri=cmdb_ci.do?sys_id=[sys_id]
        instance_url = ""
        network_adapter_details = [get_network_adapter(sid) for sid in network_adapter_sys_ids]

        for na in network_adapter_details:
            if na.get("related_configuration_item_id"):
                ci_class_values = get_related_configuration_item(na.get("related_configuration_item_id") , na.get("instance_url"))
                related_ci_details.append(ci_class_values)

        outputs = {
            "summary": f"Found {len(network_adapter_sys_ids)} related network adapters and {len(network_adapter_sys_ids) + len(related_ci_details)} total configuration items in ServiceNow ({instance_url})",
            "network_adapters": network_adapter_details,
            "related_configuration_items": related_ci_details
        }

        human_readable: str = f"### {outputs.get('summary')}\n```json\n{json.dumps(outputs.get('related_configuration_items'), indent=4)}\n```"

        return_results(CommandResults(outputs=outputs, outputs_prefix="ServiceNowEnrichment", readable_output=human_readable,
                                      raw_response=outputs))

    except Exception as e:
        return_error(f"Failed to execute ResolveNetworkAdapters: {e}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
