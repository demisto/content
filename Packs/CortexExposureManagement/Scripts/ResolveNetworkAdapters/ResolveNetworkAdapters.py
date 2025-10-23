import json


def main():
    """
    This script acts as a wrapper for the 'servicenow-cmdb-records-list' command.
    It retrieves arguments and passes them directly to the underlying command.
    """
    ip_address = demisto.args().get('ip_address')

    if ip_address is None:
        return_error(f"An ip_address argument is required")

    try:
        # First search all network interfaces, and relations to each interface
        command_results = demisto.executeCommand('servicenow-cmdb-records-list',
                                                 {"class": "cmdb_ci_network_adapter", "query": f"ip_address={ip_address}"})
        result = command_results[0].get("Contents").get("result")
        demisto.results(result)
        network_adapter_sys_ids = [res.get("sys_id") for res in result]
        network_adapter_details = []
        related_ci_details = []
        # https://[your-instance].service-now.com/nav_to.do?uri=cmdb_ci.do?sys_id=[sys_id]
        instance_url = ""

        # Fetch details from each identified network interface
        for sid in network_adapter_sys_ids:
            cr = demisto.executeCommand('servicenow-cmdb-record-get-by-id', {"class": "cmdb_ci_network_adapter", "sys_id": sid})
            parsed = cr[0].get("Contents").get("result")
            demisto.results(parsed)
            instance_url = (parsed.get("attributes").get("sys_domain").get("link")).replace(
                "/api/now/table/sys_user_group/global", "")

            if parsed.get("attributes").get("assigned_to"):
                network_adapter_values = {
                    "sys_id": sid,
                    "name": parsed.get("attributes").get("name"),
                    "ip": parsed.get("attributes").get("ip_address"),
                    "owner": parsed.get("attributes").get("assigned_to", {}).get("display_value"),
                    "owner_id": parsed.get("attributes").get("assigned_to", {}).get("value"),
                    "related_configuration_item_name": parsed.get("attributes").get("cmdb_ci", {}).get("display_value"),
                    "related_configuration_item_id": parsed.get("attributes").get("cmdb_ci", {}).get("value"),
                    "url": f"{instance_url}/nav_to.do?uri=cmdb_ci_network_adapter.do?sys_id={sid}"
                }
            else:
                network_adapter_values = {
                    "sys_id": sid,
                    "name": parsed.get("attributes").get("name"),
                    "ip": parsed.get("attributes").get("ip_address"),
                    "owner": "",
                    "owner_id": "",
                    "related_configuration_item_name": parsed.get("attributes").get("cmdb_ci", {}).get("display_value"),
                    "related_configuration_item_id": parsed.get("attributes").get("cmdb_ci", {}).get("value"),
                    "url": f"{instance_url}/nav_to.do?uri=cmdb_ci_network_adapter.do?sys_id={sid}"
                }

            network_adapter_details.append(network_adapter_values)

        # Follow for related CIs
        for na in network_adapter_details:
            if na.get("related_configuration_item_id") is not None:
                sid = na.get("related_configuration_item_id")
                cr = demisto.executeCommand('servicenow-cmdb-record-get-by-id', {"class": "cmdb_ci", "sys_id": sid})
                parsed = cr[0].get("Contents").get("result")
                ci_class = parsed.get("attributes").get("sys_class_name")

                # re-fetch with explicit class
                cr = demisto.executeCommand('servicenow-cmdb-record-get-by-id', {"class": ci_class, "sys_id": sid})
                parsed = cr[0].get("Contents").get("result")

                ci_class_values = {
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
                related_ci_details.append(ci_class_values)

        # Populate overview
        overview = {
            "summary": f"Found {len(network_adapter_sys_ids)} related network adapters and {len(network_adapter_sys_ids) + len(related_ci_details)} total configuration items in ServiceNow ({instance_url})",
            "network_adapters": network_adapter_details,
            "related_configuration_items": related_ci_details
        }

        # Return the results of the command
        return_outputs(
            readable_output=f"### {overview.get('summary')}\n```json\n{json.dumps(overview.get('related_configuration_items'), indent=4)}\n```",
            outputs={
                'ServiceNowEnrichment.Summary': overview.get('summary'),
                'ServiceNowEnrichment.network_adapters': overview.get('network_adapters'),
                'ServiceNowEnrichment.related_configuration_items': overview.get('related_configuration_items'),
            },
            raw_response=overview
        )

    except Exception as e:
        return_error(f"Failed to execute ServiceNowCMDBRecordsListWrapper: {e}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()