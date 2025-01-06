GuardiCoreV2 Integration allows to get information about incidents and endpoints (aseets) via the guardicore api.
This integration was integrated and tested with version 3.0.0 of the GuardiCore API.

## Configure GuardiCore v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Server URL | For example: `https://example.com/api/v3.0/` | True |
| Username for API |  | True |
| Password for API |  | True |
| Source | Fetch incidents - Guardicore Source Incident Value | False |
| Desctination | Fetch incidents - Guardicore Desctination Incident Value | False |
| Tag |  | False |
| Incident Type | Fetch incidents - Guardicore Incident Type Value | False |
| Incident Severity | Fetch incidents - Guardicore Incident Severity Value | False |
| Maximum alerts to fetch | Fetch incidents - limit on incidents to fetch | False |
| First fetch time | Fetch incidents - First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### guardicore-search-asset
***
Display information about assets.


#### Base Command

`guardicore-search-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP Address (takes priority before name if defined). | Optional | 
| name | Name of endpoint. | Optional | 
| asset_id | Asset ID (must start with :vm). | Optional | 
| limit | Limit results. Default is 50. | Optional | 
| offset | Offset results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Guardicore.Endpoint._id | String | Guardicore Endpoint ID | 
| Guardicore.Endpoint.active | String | Guardicore Endpoint Active | 
| Guardicore.Endpoint.bios_uuid | String | Guardicore Endpoint BIOS UUID | 
| Guardicore.Endpoint.first_seen | Date | Guardicore Endpoint First Seen | 
| Guardicore.Endpoint.host_id | String | Guardicore Endpoint Host ID | 
| Guardicore.Endpoint.host_orchestration_id | String | Guardicore Endpoint Host Orchestration ID | 
| Guardicore.Endpoint.is_on | String | Guardicore Endpoint Is On Status | 
| Guardicore.Endpoint.last_seen | Date | Guardicore Endpoint Last Seen | 
| Guardicore.Endpoint.metadata.InventoryAPI.report_source | String | Guardicore Endpoint Metadata InventoryAPI Report Source | 
| Guardicore.Endpoint.metadata.InventoryAPI.OsType | String | Guardicore Endpoint Metadata InventoryAPI OsType | 
| Guardicore.Endpoint.metadata.InventoryAPI.OsVersion | String | Guardicore Endpoint Metadata InventoryAPI OsVersion | 
| Guardicore.Endpoint.metadata.InventoryAPI.DeviceDescr | String | Guardicore Endpoint Metadata InventoryAPI DeviceDescr | 
| Guardicore.Endpoint.metadata.InventoryAPI.DeviceType | String | Guardicore Endpoint Metadata InventoryAPI DeviceType | 
| Guardicore.Endpoint.name | String | Guardicore Endpoint Name | 
| Guardicore.Endpoint.nics.vif_id | String | Guardicore Endpoint NICs Vif ID | 
| Guardicore.Endpoint.nics.mac_address | Date | Guardicore Endpoint NICs MAC Address | 
| Guardicore.Endpoint.nics.network_id | String | Guardicore Endpoint NICs Network ID | 
| Guardicore.Endpoint.nics.network_name | String | Guardicore Endpoint NICs Network Name | 
| Guardicore.Endpoint.nics.cloud_network | String | Guardicore Endpoint NICs Cloud Network | 
| Guardicore.Endpoint.nics.is_cloud_public | String | Guardicore Endpoint NICs Is Cloud Public Status | 
| Guardicore.Endpoint.nics.vlan_id | Number | Guardicore Endpoint NICs VLAN ID | 
| Guardicore.Endpoint.nics.switch_id | String | Guardicore Endpoint NICs Switch ID | 
| Guardicore.Endpoint.nics.ip_addresses | String | Guardicore Endpoint NICs IP Addresses | 
| Guardicore.Endpoint.orchestration_details.orchestration_id | String | Guardicore Endpoint Orchestration Details Orchestration ID | 
| Guardicore.Endpoint.orchestration_details.orchestration_type | String | Guardicore Endpoint Orchestration Details Orchestration Type | 
| Guardicore.Endpoint.orchestration_details.orchestration_obj_id | String | Guardicore Endpoint Orchestration Details Orchestration Object ID | 
| Guardicore.Endpoint.orchestration_details.revision_id | Date | Guardicore Endpoint Orchestration Details Revision ID | 
| Guardicore.Endpoint.orchestration_details.orchestration_name | String | Guardicore Endpoint Orchestration Details Orchestration Name | 
| Guardicore.Endpoint.orchestration_labels | String | Guardicore Endpoint Orchestration Labels | 
| Guardicore.Endpoint.orchestration_labels_dict.Type | String | Guardicore Endpoint Orchestration Labels Dictionary Type | 
| Guardicore.Endpoint.orchestration_labels_dict.Risk | String | Guardicore Endpoint Orchestration Labels Dictionary Risk | 
| Guardicore.Endpoint.orchestration_labels_dict.OS | String | Guardicore Endpoint Orchestration Labels Dictionary OS | 
| Guardicore.Endpoint.tenant_name | String | Guardicore Endpoint Tenant Name | 
| Guardicore.Endpoint.replicated_labels | String | Guardicore Endpoint Replicated Labels | 
| Guardicore.Endpoint.asset_id | String | Guardicore Endpoint Asset ID | 
| Guardicore.Endpoint.id | String | Guardicore Endpoint ID | 
| Guardicore.Endpoint.vm_name | String | Guardicore Endpoint VM Name | 
| Guardicore.Endpoint.vm_id | String | Guardicore Endpoint VM ID | 
| Guardicore.Endpoint.ip_addresses | String | Guardicore Endpoint IP Addresses | 
| Guardicore.Endpoint.mac_addresses | Date | Guardicore Endpoint MAC Addresses | 
| Guardicore.Endpoint.vm.name | String | Guardicore Endpoint VM Name | 
| Guardicore.Endpoint.vm.tenant_name | String | Guardicore Endpoint VM Tenant Name | 
| Guardicore.Endpoint.vm.vm_id | String | Guardicore Endpoint VM VM ID | 
| Guardicore.Endpoint.vm.orchestration_details.orchestration_id | String | Guardicore Endpoint VM Orchestration Details Orchestration ID | 
| Guardicore.Endpoint.vm.orchestration_details.orchestration_type | String | Guardicore Endpoint VM Orchestration Details Orchestration Type | 
| Guardicore.Endpoint.vm.orchestration_details.orchestration_obj_id | String | Guardicore Endpoint VM Orchestration Details Orchestration Object ID | 
| Guardicore.Endpoint.vm.orchestration_details.revision_id | Date | Guardicore Endpoint VM Orchestration Details Revision ID | 
| Guardicore.Endpoint.vm.orchestration_details.orchestration_name | String | Guardicore Endpoint VM Orchestration Details Orchestration Name | 
| Guardicore.Endpoint.full_name | String | Guardicore Endpoint Full Name | 
| Guardicore.Endpoint.status | String | Guardicore Endpoint Status | 
| Guardicore.Endpoint.comments | String | Guardicore Endpoint Comments | 
| Guardicore.Endpoint.recent_domains | String | Guardicore Endpoint Recent Domains | 
| Guardicore.Endpoint.labels.id | String | Guardicore Endpoint Labels ID | 
| Guardicore.Endpoint.labels.key | String | Guardicore Endpoint Labels Key | 
| Guardicore.Endpoint.labels.value | String | Guardicore Endpoint Labels Value | 
| Guardicore.Endpoint.labels.name | String | Guardicore Endpoint Labels Name | 
| Guardicore.Endpoint.labels.color_index | Number | Guardicore Endpoint Labels Color Index | 


#### Command Example
```!guardicore-search-asset ip_address=1.1.1.1```

#### Context Example
```json
{
    "Guardicore": {
        "Endpoint": {
            "asset_id": "920b9a05-889e-429e-97d0-94a92ccbe376",
            "ip_addresses": [
                "1.1.1.1",
                "fe80::250:56ff:fe84:da1e"
            ],
            "last_seen": 1627909413816,
            "name": "Accounting-web-1",
            "status": "on",
            "tenant_name": "esx10/lab_a/Apps/Accounting"
        }
    }
}
```

#### Human Readable Output

>### GuardiCoreV2 - Asset: Accounting-web-1
>|asset_id|ip_addresses|last_seen|name|status|tenant_name|
>|---|---|---|---|---|---|
>| 920b9a05-889e-429e-97d0-94a92ccbe376 | 1.1.1.1,<br/>fe80::250:56ff:fe84:da1e | 1627909413816 | Accounting-web-1 | on | esx10/lab_a/Apps/Accounting |


### guardicore-get-incident
***
Display information about an incident.


#### Base Command

`guardicore-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of incident. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Guardicore.Incident._cls | String | Guardicore Incident Cls | 
| Guardicore.Incident.doc_version | Number | Guardicore Incident Doc Version | 
| Guardicore.Incident.sensor_type | String | Guardicore Incident Sensor Type | 
| Guardicore.Incident.start_time | Date | Guardicore Incident Start Time | 
| Guardicore.Incident.end_time | Date | Guardicore Incident End Time | 
| Guardicore.Incident.last_updated_time | Date | Guardicore Incident Last Updated Time | 
| Guardicore.Incident.ended | String | Guardicore Incident Ended | 
| Guardicore.Incident.closed_time | Date | Guardicore Incident Closed Time | 
| Guardicore.Incident.severity | Number | Guardicore Incident Severity | 
| Guardicore.Incident.affected_assets.labels | String | Guardicore Incident Affected Assets Labels | 
| Guardicore.Incident.affected_assets.ip | String | Guardicore Incident Affected Assets IP | 
| Guardicore.Incident.affected_assets.vm_id | String | Guardicore Incident Affected Assets VM ID | 
| Guardicore.Incident.affected_assets.vm.id | String | Guardicore Incident Affected Assets VM ID | 
| Guardicore.Incident.affected_assets.vm.name | String | Guardicore Incident Affected Assets VM Name | 
| Guardicore.Incident.affected_assets.vm.tenant_name | String | Guardicore Incident Affected Assets VM Tenant Name | 
| Guardicore.Incident.affected_assets.vm.full_name | String | Guardicore Incident Affected Assets VM Full Name | 
| Guardicore.Incident.affected_assets.is_inner | String | Guardicore Incident Affected Assets Is Inner Status | 
| Guardicore.Incident.enriched | String | Guardicore Incident Enriched | 
| Guardicore.Incident.reenrich_count | Number | Guardicore Incident Reenrich Count | 
| Guardicore.Incident.tags.id | String | Guardicore Incident Tags ID | 
| Guardicore.Incident.tags.visible | String | Guardicore Incident Tags Visible | 
| Guardicore.Incident.tags.tag_class | String | Guardicore Incident Tags Tag Class | 
| Guardicore.Incident.tags.display_name | String | Guardicore Incident Tags Display Name | 
| Guardicore.Incident.tags.search_names | String | Guardicore Incident Tags Search Names | 
| Guardicore.Incident.tags.shortened_group_display_name | String | Guardicore Incident Tags Shortened Group Display Name | 
| Guardicore.Incident.tags.tag_type_key | String | Guardicore Incident Tags Tag Type Key | 
| Guardicore.Incident.tags.tag_args.category | String | Guardicore Incident Tags Tag Args Category | 
| Guardicore.Incident.tags.source | String | Guardicore Incident Tags Source | 
| Guardicore.Incident.tags.tag_args.process_name | String | Guardicore Incident Tags Tag Args Process Name | 
| Guardicore.Incident.tags.tag_args.process_path | String | Guardicore Incident Tags Tag Args Process Path | 
| Guardicore.Incident.tags.tag_args.side | Number | Guardicore Incident Tags Tag Args Side | 
| Guardicore.Incident.tags.tag_args.reason | String | Guardicore Incident Tags Tag Args Reason | 
| Guardicore.Incident.tags.events | String | Guardicore Incident Tags Events | 
| Guardicore.Incident.tags.time | Date | Guardicore Incident Tags Time | 
| Guardicore.Incident.recommendations.id | String | Guardicore Incident Recommendations ID | 
| Guardicore.Incident.recommendations.parts.type | String | Guardicore Incident Recommendations Parts Type | 
| Guardicore.Incident.recommendations.parts.value | String | Guardicore Incident Recommendations Parts Value | 
| Guardicore.Incident.recommendations.rule_type | String | Guardicore Incident Recommendations Rule Type | 
| Guardicore.Incident.recommendations.handle_template | String | Guardicore Incident Recommendations Handle Template | 
| Guardicore.Incident.recommendations.details.parts.value | String | Guardicore Incident Recommendations Details Parts Value | 
| Guardicore.Incident.recommendations.details.parts.type | String | Guardicore Incident Recommendations Details Parts Type | 
| Guardicore.Incident.recommendations.type | String | Guardicore Incident Recommendations Type | 
| Guardicore.Incident.similarity_calculated | String | Guardicore Incident Similarity Calculated | 
| Guardicore.Incident.incident_group.gname | String | Guardicore Incident Incident Group Gname | 
| Guardicore.Incident.incident_group.gid | String | Guardicore Incident Incident Group GID | 
| Guardicore.Incident.stories.template | String | Guardicore Incident Stories Template | 
| Guardicore.Incident.stories.arguments.malicious_process.process_name | String | Guardicore Incident Stories Arguments Malicious Process Process Name | 
| Guardicore.Incident.stories.arguments.malicious_process.reputation_info | String | Guardicore Incident Stories Arguments Malicious Process Reputation Information | 
| Guardicore.Incident.stories.arguments.destination_port | Number | Guardicore Incident Stories Arguments Destination Port | 
| Guardicore.Incident.stories.arguments.asset_name | String | Guardicore Incident Stories Arguments Asset Name | 
| Guardicore.Incident.stories.arguments.ip_address | String | Guardicore Incident Stories Arguments IP Address | 
| Guardicore.Incident.stories.arguments.malicious_process->process_name | String | Guardicore Incident Stories Arguments Malicious Process, Process Name | 
| Guardicore.Incident.stories.arguments.malicious_process->reputation_info | String | Guardicore Incident Stories Arguments Malicious Process, Reputation Information | 
| Guardicore.Incident.stories.tags.display_name | String | Guardicore Incident Stories Tags Display Name | 
| Guardicore.Incident.stories.tags.tag_class | String | Guardicore Incident Stories Tags Tag Class | 
| Guardicore.Incident.stories.tags.events | String | Guardicore Incident Stories Tags Events | 
| Guardicore.Incident.stories.time | Date | Guardicore Incident Stories Time | 
| Guardicore.Incident.stories.parts.type | String | Guardicore Incident Stories Parts Type | 
| Guardicore.Incident.stories.parts.value | String | Guardicore Incident Stories Parts Value | 
| Guardicore.Incident.flow_ids | String | Guardicore Incident Flow IDs | 
| Guardicore.Incident.remote_index | String | Guardicore Incident Remote Index | 
| Guardicore.Incident.is_experimental | String | Guardicore Incident Is Experimental Status | 
| Guardicore.Incident.original_id | String | Guardicore Incident Original ID | 
| Guardicore.Incident.experimental_id | String | Guardicore Incident Experimental ID | 
| Guardicore.Incident.first_asset.asset_type | String | Guardicore Incident First Asset Asset Type | 
| Guardicore.Incident.first_asset.asset_id | String | Guardicore Incident First Asset Asset ID | 
| Guardicore.Incident.second_asset.asset_type | String | Guardicore Incident Second Asset Asset Type | 
| Guardicore.Incident.second_asset.asset_id | String | Guardicore Incident Second Asset Asset ID | 
| Guardicore.Incident.labels.id | String | Guardicore Incident Labels ID | 
| Guardicore.Incident.labels.key | String | Guardicore Incident Labels Key | 
| Guardicore.Incident.labels.value | String | Guardicore Incident Labels Value | 
| Guardicore.Incident.labels.name | String | Guardicore Incident Labels Name | 
| Guardicore.Incident.labels.color_index | Number | Guardicore Incident Labels Color Index | 
| Guardicore.Incident.labels.asset_ids | String | Guardicore Incident Labels Asset IDs | 
| Guardicore.Incident.policy_revision | Number | Guardicore Incident Policy Revision | 
| Guardicore.Incident.id | String | Guardicore Incident ID | 
| Guardicore.Incident.incident_type | String | Guardicore Incident Incident Type | 
| Guardicore.Incident.has_export | String | Guardicore Incident Has Export Flag | 
| Guardicore.Incident.concatenated_tags.display_name | String | Guardicore Incident Concatenated Tags Display Name | 
| Guardicore.Incident.concatenated_tags.tag_class | String | Guardicore Incident Concatenated Tags Tag Class | 
| Guardicore.Incident.concatenated_tags.events | String | Guardicore Incident Concatenated Tags Events | 
| Guardicore.Incident.direction | String | Guardicore Incident Direction | 
| Guardicore.Incident.source_asset.labels | String | Guardicore Incident Source Asset Labels | 
| Guardicore.Incident.source_asset.ip | String | Guardicore Incident Source Asset IP | 
| Guardicore.Incident.source_asset.vm_id | String | Guardicore Incident Source Asset VM ID | 
| Guardicore.Incident.source_asset.vm.id | String | Guardicore Incident Source Asset VM ID | 
| Guardicore.Incident.source_asset.vm.name | String | Guardicore Incident Source Asset VM Name | 
| Guardicore.Incident.source_asset.vm.tenant_name | String | Guardicore Incident Source Asset VM Tenant Name | 
| Guardicore.Incident.source_asset.vm.full_name | String | Guardicore Incident Source Asset VM Full Name | 
| Guardicore.Incident.source_asset.is_inner | String | Guardicore Incident Source Asset Is Inner Status | 
| Guardicore.Incident.destination_asset.labels | String | Guardicore Incident Destination Asset Labels | 
| Guardicore.Incident.destination_asset.ip | String | Guardicore Incident Destination Asset IP | 
| Guardicore.Incident.destination_asset.vm_id | String | Guardicore Incident Destination Asset VM ID | 
| Guardicore.Incident.destination_asset.vm.id | String | Guardicore Incident Destination Asset VM ID | 
| Guardicore.Incident.destination_asset.vm.name | String | Guardicore Incident Destination Asset VM Name | 
| Guardicore.Incident.destination_asset.vm.tenant_name | String | Guardicore Incident Destination Asset VM Tenant Name | 
| Guardicore.Incident.destination_asset.vm.full_name | String | Guardicore Incident Destination Asset VM Full Name | 
| Guardicore.Incident.destination_asset.is_inner | String | Guardicore Incident Destination Asset Is Inner Status | 
| Guardicore.Incident.has_policy_violations | String | Guardicore Incident Has Policy Violations Flag | 
| Guardicore.Incident.total_events_count | Number | Guardicore Incident Total Events Count | 
| Guardicore.Incident.limited_events_count | Number | Guardicore Incident Limited Events Count | 
| Guardicore.Incident.events._cls | String | Guardicore Incident Events Cls | 
| Guardicore.Incident.events.doc_version | Number | Guardicore Incident Events Doc Version | 
| Guardicore.Incident.events.uuid | String | Guardicore Incident Events UUID | 
| Guardicore.Incident.events.time | Date | Guardicore Incident Events Time | 
| Guardicore.Incident.events.received_time | Date | Guardicore Incident Events Received Time | 
| Guardicore.Incident.events.processed_time | Date | Guardicore Incident Events Processed Time | 
| Guardicore.Incident.events.event_source | String | Guardicore Incident Events Event Source | 
| Guardicore.Incident.events.is_experimental | String | Guardicore Incident Events Is Experimental Status | 
| Guardicore.Incident.events.incident_id | String | Guardicore Incident Events Incident ID | 
| Guardicore.Incident.events.flow_id | String | Guardicore Incident Events Flow ID | 
| Guardicore.Incident.events.flow.count | Number | Guardicore Incident Events Flow Count | 
| Guardicore.Incident.events.flow.ip_protocols | String | Guardicore Incident Events Flow IP Protocols | 
| Guardicore.Incident.events.flow.destination_ports | Number | Guardicore Incident Events Flow Destination Ports | 
| Guardicore.Incident.events.flow.source_username | String | Guardicore Incident Events Flow Source Username | 
| Guardicore.Incident.events.flow.source_node_type | String | Guardicore Incident Events Flow Source Node Type | 
| Guardicore.Incident.events.flow.source_process_id | String | Guardicore Incident Events Flow Source Process ID | 
| Guardicore.Incident.events.flow.source_ip | String | Guardicore Incident Events Flow Source IP | 
| Guardicore.Incident.events.flow.source_process_name | String | Guardicore Incident Events Flow Source Process Name | 
| Guardicore.Incident.events.flow.source_process | String | Guardicore Incident Events Flow Source Process | 
| Guardicore.Incident.events.flow.destination_node_type | String | Guardicore Incident Events Flow Destination Node Type | 
| Guardicore.Incident.events.flow.destination_process_id | String | Guardicore Incident Events Flow Destination Process ID | 
| Guardicore.Incident.events.flow.destination_ip | String | Guardicore Incident Events Flow Destination IP | 
| Guardicore.Incident.events.flow.destination_process_name | String | Guardicore Incident Events Flow Destination Process Name | 
| Guardicore.Incident.events.flow.destination_process | String | Guardicore Incident Events Flow Destination Process | 
| Guardicore.Incident.events.source_asset.asset_type | String | Guardicore Incident Events Source Asset Asset Type | 
| Guardicore.Incident.events.source_asset.asset_id | String | Guardicore Incident Events Source Asset Asset ID | 
| Guardicore.Incident.events.source_asset.asset_value | String | Guardicore Incident Events Source Asset Asset Value | 
| Guardicore.Incident.events.source_asset.asset_name | String | Guardicore Incident Events Source Asset Asset Name | 
| Guardicore.Incident.events.destination_asset.asset_type | String | Guardicore Incident Events Destination Asset Asset Type | 
| Guardicore.Incident.events.destination_asset.asset_id | String | Guardicore Incident Events Destination Asset Asset ID | 
| Guardicore.Incident.events.destination_asset.asset_value | String | Guardicore Incident Events Destination Asset Asset Value | 
| Guardicore.Incident.events.destination_asset.asset_name | String | Guardicore Incident Events Destination Asset Asset Name | 
| Guardicore.Incident.events.connection_type | String | Guardicore Incident Events Connection Type | 
| Guardicore.Incident.events.side | Number | Guardicore Incident Events Side | 
| Guardicore.Incident.events.date | Date | Guardicore Incident Events Date | 
| Guardicore.Incident.events.result.verdict | String | Guardicore Incident Events Result Verdict | 
| Guardicore.Incident.events.result.reasons | String | Guardicore Incident Events Result Reasons | 
| Guardicore.Incident.events.result.score | Number | Guardicore Incident Events Result Score | 
| Guardicore.Incident.events.result.severity | String | Guardicore Incident Events Result Severity | 
| Guardicore.Incident.events.result.experimental_verdict | String | Guardicore Incident Events Result Experimental Verdict | 
| Guardicore.Incident.events.result.experimental_reasons | String | Guardicore Incident Events Result Experimental Reasons | 
| Guardicore.Incident.events.result.experimental_score | Number | Guardicore Incident Events Result Experimental Score | 
| Guardicore.Incident.events.result.experimental_severity | String | Guardicore Incident Events Result Experimental Severity | 
| Guardicore.Incident.events.answer_origin | String | Guardicore Incident Events Answer Origin | 
| Guardicore.Incident.events.destination_port | Number | Guardicore Incident Events Destination Port | 
| Guardicore.Incident.events.source_process_name | String | Guardicore Incident Events Source Process Name | 
| Guardicore.Incident.events.destination_process_name | String | Guardicore Incident Events Destination Process Name | 
| Guardicore.Incident.events.process_name | String | Guardicore Incident Events Process Name | 
| Guardicore.Incident.events.process_path | String | Guardicore Incident Events Process Path | 
| Guardicore.Incident.events.process_hash | String | Guardicore Incident Events Process Hash | 
| Guardicore.Incident.events.asset_name | String | Guardicore Incident Events Asset Name | 
| Guardicore.Incident.events.ip_address | String | Guardicore Incident Events IP Address | 
| Guardicore.Incident.events.slot_start_time | Date | Guardicore Incident Events Slot Start Time | 
| Guardicore.Incident.events.count | Number | Guardicore Incident Events Count | 
| Guardicore.Incident.events.protocol | String | Guardicore Incident Events Protocol | 
| Guardicore.Incident.events.service_port | Number | Guardicore Incident Events Service Port | 
| Guardicore.Incident.events.event_group | String | Guardicore Incident Events Event Group | 
| Guardicore.Incident.events.type | String | Guardicore Incident Events Type | 
| Guardicore.Incident.events.type_title | String | Guardicore Incident Events Type Title | 
| Guardicore.Incident.events.visibility | String | Guardicore Incident Events Visibility | 
| Guardicore.Incident.events.policy_revision | Number | Guardicore Incident Events Policy Revision | 
| Guardicore.Incident.events.violating_policy_rule_id | String | Guardicore Incident Events Violating Policy Rule ID | 
| Guardicore.Incident.events.violating_policy_verdict | String | Guardicore Incident Events Violating Policy Verdict | 
| Guardicore.Incident.events.source_agent_matching.verdict | String | Guardicore Incident Events Source Agent Matching Verdict | 
| Guardicore.Incident.events.source_agent_matching.rule_id | String | Guardicore Incident Events Source Agent Matching Rule ID | 
| Guardicore.Incident.events.source_agent_matching.revision | Number | Guardicore Incident Events Source Agent Matching Revision | 
| Guardicore.Incident.events.destination_agent_matching.verdict | String | Guardicore Incident Events Destination Agent Matching Verdict | 
| Guardicore.Incident.events.destination_agent_matching.rule_id | String | Guardicore Incident Events Destination Agent Matching Rule ID | 
| Guardicore.Incident.events.destination_agent_matching.revision | Number | Guardicore Incident Events Destination Agent Matching Revision | 
| Guardicore.Incident.events.management_matching.rule_action | Number | Guardicore Incident Events Management Matching Rule Action | 
| Guardicore.Incident.events.management_matching.rule_id | String | Guardicore Incident Events Management Matching Rule ID | 
| Guardicore.Incident.events.management_matching.revision | Number | Guardicore Incident Events Management Matching Revision | 
| Guardicore.Incident.events.has_mismatch_alert | String | Guardicore Incident Events Has Mismatch Alert Flag | 
| Guardicore.Incident.events.last_connection.destination_node_id | String | Guardicore Incident Events Last Connection Destination Node ID | 
| Guardicore.Incident.events.last_connection.slot_start_time | Date | Guardicore Incident Events Last Connection Slot Start Time | 
| Guardicore.Incident.events.last_connection.source_node_id | String | Guardicore Incident Events Last Connection Source Node ID | 
| Guardicore.Incident.events.last_connection.flow_id | String | Guardicore Incident Events Last Connection Flow ID | 
| Guardicore.Incident.events.last_connection.incidents.incident_id | String | Guardicore Incident Events Last Connection Incidents Incident ID | 
| Guardicore.Incident.events.last_connection.incidents.incident_type | String | Guardicore Incident Events Last Connection Incidents Incident Type | 
| Guardicore.Incident.events.last_connection.policy_verdict | String | Guardicore Incident Events Last Connection Policy Verdict | 
| Guardicore.Incident.events.last_connection.destination_process_id | String | Guardicore Incident Events Last Connection Destination Process ID | 
| Guardicore.Incident.events.last_connection.source_process_id | String | Guardicore Incident Events Last Connection Source Process ID | 
| Guardicore.Incident.events.last_connection.policy_rule | String | Guardicore Incident Events Last Connection Policy Rule | 
| Guardicore.Incident.events.last_connection.has_mismatch_alert | String | Guardicore Incident Events Last Connection Has Mismatch Alert Flag | 
| Guardicore.Incident.events.last_connection.original_policy_verdict | String | Guardicore Incident Events Last Connection Original Policy Verdict | 
| Guardicore.Incident.events.last_connection.source_agent_matching.verdict | String | Guardicore Incident Events Last Connection Source Agent Matching Verdict | 
| Guardicore.Incident.events.last_connection.source_agent_matching.rule | String | Guardicore Incident Events Last Connection Source Agent Matching Rule | 
| Guardicore.Incident.events.last_connection.destination_agent_matching.verdict | String | Guardicore Incident Events Last Connection Destination Agent Matching Verdict | 
| Guardicore.Incident.events.last_connection.destination_agent_matching.rule | String | Guardicore Incident Events Last Connection Destination Agent Matching Rule | 
| Guardicore.Incident.events.last_connection.management_matching.rule_action | String | Guardicore Incident Events Last Connection Management Matching Rule Action | 
| Guardicore.Incident.events.last_connection.management_matching.rule | String | Guardicore Incident Events Last Connection Management Matching Rule | 
| Guardicore.Incident.events.reputation_tags.id | String | Guardicore Incident Events Reputation Tags ID | 
| Guardicore.Incident.events.reputation_tags.visible | String | Guardicore Incident Events Reputation Tags Visible | 
| Guardicore.Incident.events.reputation_tags.tag_class | String | Guardicore Incident Events Reputation Tags Tag Class | 
| Guardicore.Incident.events.reputation_tags.display_name | String | Guardicore Incident Events Reputation Tags Display Name | 
| Guardicore.Incident.events.reputation_tags.search_names | String | Guardicore Incident Events Reputation Tags Search Names | 
| Guardicore.Incident.events.reputation_tags.shortened_group_display_name | String | Guardicore Incident Events Reputation Tags Shortened Group Display Name | 
| Guardicore.Incident.events.reputation_tags.tag_type_key | String | Guardicore Incident Events Reputation Tags Tag Type Key | 
| Guardicore.Incident.events.reputation_tags.tag_args.process_name | String | Guardicore Incident Events Reputation Tags Tag Args Process Name | 
| Guardicore.Incident.events.reputation_tags.tag_args.process_path | String | Guardicore Incident Events Reputation Tags Tag Args Process Path | 
| Guardicore.Incident.events.reputation_tags.tag_args.side | Number | Guardicore Incident Events Reputation Tags Tag Args Side | 
| Guardicore.Incident.events.reputation_tags.tag_args.reason | String | Guardicore Incident Events Reputation Tags Tag Args Reason | 
| Guardicore.Incident.events.reputation_tags.source | String | Guardicore Incident Events Reputation Tags Source | 
| Guardicore.Incident.events.reputation_tags.events | String | Guardicore Incident Events Reputation Tags Events | 
| Guardicore.Incident.events.reputation_tags.time | Date | Guardicore Incident Events Reputation Tags Time | 
| Guardicore.Incident.events.policy_verdict | String | Guardicore Incident Events Policy Verdict | 
| Guardicore.Incident.events.source_ip | String | Guardicore Incident Events Source IP | 
| Guardicore.Incident.events.source_node_type | String | Guardicore Incident Events Source Node Type | 
| Guardicore.Incident.events.source_process_id | String | Guardicore Incident Events Source Process ID | 
| Guardicore.Incident.events.source_process | String | Guardicore Incident Events Source Process | 
| Guardicore.Incident.events.source.vm._id | String | Guardicore Incident Events Source VM ID | 
| Guardicore.Incident.events.source.vm.name | String | Guardicore Incident Events Source VM Name | 
| Guardicore.Incident.events.destination_ip | String | Guardicore Incident Events Destination IP | 
| Guardicore.Incident.events.destination_node_type | String | Guardicore Incident Events Destination Node Type | 
| Guardicore.Incident.events.destination_process_id | String | Guardicore Incident Events Destination Process ID | 
| Guardicore.Incident.events.destination_process | String | Guardicore Incident Events Destination Process | 
| Guardicore.Incident.events.destination.vm._id | String | Guardicore Incident Events Destination VM ID | 
| Guardicore.Incident.events.destination.vm.name | String | Guardicore Incident Events Destination VM Name | 
| Guardicore.Incident.is_bc_format_incident | String | Guardicore Incident Is Bc Format Incident Status | 


#### Command Example
```!guardicore-get-incident id="c2acca07-e9bf-4d63-9a26-ff6c749d24d2"```

#### Context Example
```json
{
    "Guardicore": {
        "Incident": {
            "_cls": "Incident.NetworkVisibilityIncident",
            "affected_assets": [
                {
                    "ip": "1.1.1.1",
                    "is_inner": true,
                    "labels": [
                        "source"
                    ],
                    "vm": {
                        "full_name": "esx10/lab_a/Apps/Accounting\\Accounting-lb-1",
                        "id": "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285",
                        "name": "Accounting-lb-1",
                        "recent_domains": [],
                        "tenant_name": "esx10/lab_a/Apps/Accounting"
                    },
                    "vm_id": "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
                },
                {
                    "ip": "1.1.1.1",
                    "is_inner": true,
                    "labels": [
                        "destination"
                    ],
                    "vm": {
                        "full_name": "esx10/lab_a/Endpoints\\DC-01",
                        "id": "e69d1434-28d3-4774-a933-c2c993412edc",
                        "name": "DC-01",
                        "recent_domains": [],
                        "tenant_name": "esx10/lab_a/Endpoints"
                    },
                    "vm_id": "e69d1434-28d3-4774-a933-c2c993412edc"
                }
            ],
            "closed_time": 1625203656083,
            "concatenated_tags": [
                {
                    "display_name": "Internal",
                    "events": [],
                    "tag_class": "ENRICHER"
                },
                {
                    "display_name": "Known malware",
                    "events": [
                        "8ad2d6d9-fe7c-4894-ad9c-0760fd7e5a22",
                        "686e7645-1c75-458e-8bad-ff2b01cb7651"
                    ],
                    "tag_class": "ENRICHER"
                }
            ],
            "destination_asset": {
                "ip": "1.1.1.1",
                "is_inner": true,
                "labels": [
                    "destination"
                ],
                "vm": {
                    "full_name": "esx10/lab_a/Endpoints\\DC-01",
                    "id": "e69d1434-28d3-4774-a933-c2c993412edc",
                    "name": "DC-01",
                    "recent_domains": [],
                    "tenant_name": "esx10/lab_a/Endpoints"
                },
                "vm_id": "e69d1434-28d3-4774-a933-c2c993412edc"
            },
            "direction": "unidirectional",
            "doc_version": 143,
            "end_time": 1625203336164,
            "ended": true,
            "enriched": true,
            "events": [
                {
                    "_cls": "VisibilityDetectionEvent.PassiveDetectionNodeEvent.PassiveDetectionProcessEvent",
                    "answer_origin": "QServer",
                    "asset_name": "Accounting-lb-1",
                    "connection_type": "SUCCESSFUL",
                    "count": 2,
                    "date": 1625203133278,
                    "destination": {
                        "vm": {
                            "_id": "e69d1434-28d3-4774-a933-c2c993412edc",
                            "name": "DC-01"
                        }
                    },
                    "destination_agent_matching": {
                        "revision": 1,
                        "rule_id": "default",
                        "verdict": "ALLOW"
                    },
                    "destination_asset": {
                        "asset_id": "e69d1434-28d3-4774-a933-c2c993412edc",
                        "asset_name": "DC-01",
                        "asset_type": "asset",
                        "asset_value": "DC-01 (1.1.1.1)"
                    },
                    "destination_ip": "1.1.1.1",
                    "destination_node_type": "asset",
                    "destination_port": 53,
                    "destination_process": "Unknown Server (53/UDP)",
                    "destination_process_id": "b1e023747e3bafa4bd279fe1a346973541428360d1e166e8c80c8a568004b787",
                    "destination_process_name": "Unknown Server (53/UDP)",
                    "doc_version": 143,
                    "event_group": "Passive Detection",
                    "event_source": "Visibility Detection",
                    "flow": {
                        "count": 2,
                        "destination_ip": "1.1.1.1",
                        "destination_node_type": "asset",
                        "destination_ports": [
                            53
                        ],
                        "destination_process": "Unknown Server (53/UDP)",
                        "destination_process_id": "b1e023747e3bafa4bd279fe1a346973541428360d1e166e8c80c8a568004b787",
                        "destination_process_name": "Unknown Server (53/UDP)",
                        "ip_protocols": [
                            "Udp"
                        ],
                        "source_ip": "1.1.1.1",
                        "source_node_type": "asset",
                        "source_process": "xzas9876",
                        "source_process_id": "a6b7627587bcb5efb4c36af5e678d02676695080f2f2678e8cdff38b10e4d79f",
                        "source_process_name": "xzas9876",
                        "source_username": null
                    },
                    "flow_id": "dec9a88051eb8a761f4e5b9ca7f9b04e2422211ea2a9daa94f5bedf25f7e2b0e",
                    "has_mismatch_alert": false,
                    "incident_id": "c2acca07-e9bf-4d63-9a26-ff6c749d24d2",
                    "ip_address": "1.1.1.1",
                    "is_experimental": false,
                    "management_matching": {
                        "revision": 1,
                        "rule_action": 0,
                        "rule_id": "default"
                    },
                    "policy_revision": 1,
                    "policy_verdict": "allowed",
                    "process_hash": "c31d3e52ddcc0d9c32c79f43febf5e1609cce5ae60546e112163c4329f52cbd9",
                    "process_name": "xzas9876",
                    "process_path": "/bin/xzas9876",
                    "processed_time": 1625203336484,
                    "protocol": "Udp",
                    "received_time": 1625203336484,
                    "reputation_tags": [
                        {
                            "display_name": "Known malware",
                            "events": [
                                "686e7645-1c75-458e-8bad-ff2b01cb7651",
                                "8ad2d6d9-fe7c-4894-ad9c-0760fd7e5a22"
                            ],
                            "id": "dff5c483-99b5-474c-a839-07ad111fe46d",
                            "search_names": [
                                "Suspicious Process",
                                "Reputation",
                                "Known malware"
                            ],
                            "shortened_group_display_name": "Known malware",
                            "source": "PassiveDetector\\detect_process",
                            "tag_args": {
                                "process_name": "xzas9876",
                                "process_path": "/bin/xzas9876",
                                "reason": "Known malware",
                                "side": 1
                            },
                            "tag_class": "ENRICHER",
                            "tag_type_key": "suspicious process",
                            "time": 1625203336484,
                            "visible": true
                        }
                    ],
                    "result": {
                        "experimental_reasons": [
                            "Known malware"
                        ],
                        "experimental_score": 1,
                        "experimental_severity": "High",
                        "experimental_verdict": "malicious",
                        "reasons": [
                            "Known malware"
                        ],
                        "score": 1,
                        "severity": "High",
                        "verdict": "malicious"
                    },
                    "service_port": 53,
                    "side": 1,
                    "slot_start_time": 1625203133278,
                    "source": {
                        "vm": {
                            "_id": "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285",
                            "name": "Accounting-lb-1"
                        }
                    },
                    "source_agent_matching": {
                        "revision": 1,
                        "rule_id": "default",
                        "verdict": "ALLOW"
                    },
                    "source_asset": {
                        "asset_id": "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285",
                        "asset_name": "Accounting-lb-1",
                        "asset_type": "asset",
                        "asset_value": "Accounting-lb-1 (1.1.1.1)"
                    },
                    "source_ip": "1.1.1.1",
                    "source_node_type": "asset",
                    "source_process": "xzas9876",
                    "source_process_id": "a6b7627587bcb5efb4c36af5e678d02676695080f2f2678e8cdff38b10e4d79f",
                    "source_process_name": "xzas9876",
                    "tag_refs": [],
                    "time": 1625203336484,
                    "type": "PassiveDetectionProcessEvent",
                    "type_title": "suspicious process",
                    "uuid": "686e7645-1c75-458e-8bad-ff2b01cb7651",
                    "violating_policy_rule_id": "default",
                    "violating_policy_verdict": "allowed",
                    "visibility": "Front"
                }
            ],
            "experimental_id": "",
            "first_asset": {
                "asset_id": "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285",
                "asset_type": "VM"
            },
            "flow_ids": [
                "dec9a88051eb8a761f4e5b9ca7f9b04e2422211ea2a9daa94f5bedf25f7e2b0e"
            ],
            "has_export": true,
            "has_policy_violations": false,
            "id": "c2acca07-e9bf-4d63-9a26-ff6c749d24d2",
            "incident_group": [
                {
                    "gid": "00ac9ead-4228-47f2-8bac-35bf12ca2b4f",
                    "gname": "GRP-00ac9ead"
                }
            ],
            "incident_type": "Reveal",
            "iocs": [],
            "is_bc_format_incident": false,
            "is_experimental": false,
            "labels": [
                {
                    "asset_ids": [
                        "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
                    ],
                    "color_index": -1,
                    "id": "0a76d1b7-357d-4573-96ce-b6ce359e73e6",
                    "key": "Akamai ETP",
                    "name": "Akamai ETP: Quarantine IP",
                    "value": "Quarantine IP"
                },
                {
                    "asset_ids": [
                        "e69d1434-28d3-4774-a933-c2c993412edc"
                    ],
                    "color_index": -1,
                    "id": "18fc433d-519d-4f70-8342-c657cb097eb4",
                    "key": "Environment",
                    "name": "Environment: Infrastructure",
                    "value": "Infrastructure"
                },
                {
                    "asset_ids": [
                        "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
                    ],
                    "color_index": -1,
                    "id": "36d3ceab-f727-4a58-8112-0e346b13a851",
                    "key": "App",
                    "name": "App: Accounting",
                    "value": "Accounting"
                },
                {
                    "asset_ids": [
                        "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
                    ],
                    "color_index": -1,
                    "id": "55d8137f-ca2a-48cf-9366-fb9790120986",
                    "key": "Environment",
                    "name": "Environment: Production",
                    "value": "Production"
                },
                {
                    "asset_ids": [
                        "e69d1434-28d3-4774-a933-c2c993412edc"
                    ],
                    "color_index": -1,
                    "id": "705ad925-f6da-4812-9500-b69d50a03836",
                    "key": "AI_GC_Role",
                    "name": "AI_GC_Role: File Share",
                    "value": "File Share"
                },
                {
                    "asset_ids": [
                        "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
                    ],
                    "color_index": -1,
                    "id": "7b8a6cc4-0a4b-4700-83d1-969a2bbab12c",
                    "key": "Role",
                    "name": "Role: LB",
                    "value": "LB"
                },
                {
                    "asset_ids": [
                        "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
                    ],
                    "color_index": -1,
                    "id": "7f272bfd-ff13-4636-b708-550af524ae8d",
                    "key": "vCenter folder",
                    "name": "vCenter folder: esx10/lab_a/Apps/Accounting",
                    "value": "esx10/lab_a/Apps/Accounting"
                },
                {
                    "asset_ids": [
                        "e69d1434-28d3-4774-a933-c2c993412edc"
                    ],
                    "color_index": -1,
                    "id": "91e90fa6-a100-4cfd-97be-2096983047fd",
                    "key": "App",
                    "name": "App: DC",
                    "value": "DC"
                },
                {
                    "asset_ids": [
                        "e69d1434-28d3-4774-a933-c2c993412edc"
                    ],
                    "color_index": -1,
                    "id": "a734f7c4-c46d-4990-951c-a6729e9c1039",
                    "key": "AI_GC_App",
                    "name": "AI_GC_App: AD",
                    "value": "AD"
                },
                {
                    "asset_ids": [
                        "e69d1434-28d3-4774-a933-c2c993412edc"
                    ],
                    "color_index": -1,
                    "id": "b1d09b79-b92a-4f32-bc30-5a6d461cbbf4",
                    "key": "Role",
                    "name": "Role: DC",
                    "value": "DC"
                },
                {
                    "asset_ids": [
                        "e69d1434-28d3-4774-a933-c2c993412edc"
                    ],
                    "color_index": -1,
                    "id": "bfaf8e8c-db37-4388-a237-35c5b64376ec",
                    "key": "vCenter folder",
                    "name": "vCenter folder: esx10/lab_a/Endpoints",
                    "value": "esx10/lab_a/Endpoints"
                },
                {
                    "asset_ids": [
                        "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
                    ],
                    "color_index": -1,
                    "id": "f8f96eb3-3476-476e-9ff9-f7312372ed4f",
                    "key": "ZT_host",
                    "name": "ZT_host: accounting.gc.procellab.zone",
                    "value": "accounting.gc.procellab.zone"
                }
            ],
            "last_updated_time": 1625203336164,
            "limited_events_count": 1,
            "original_id": "",
            "policy_revision": 62,
            "recommendations": [
                {
                    "details": [
                        {
                            "parts": [
                                {
                                    "type": "bold",
                                    "value": "Asset Name:"
                                },
                                {
                                    "type": "text",
                                    "value": " "
                                },
                                {
                                    "type": "expression",
                                    "value": "Accounting-lb-1"
                                }
                            ]
                        },
                        {
                            "parts": [
                                {
                                    "type": "bold",
                                    "value": "Asset Tenant:"
                                },
                                {
                                    "type": "text",
                                    "value": " "
                                },
                                {
                                    "type": "expression",
                                    "value": "esx10/lab_a/Apps/Accounting"
                                }
                            ]
                        },
                        {
                            "parts": [
                                {
                                    "type": "bold",
                                    "value": "Asset IP:"
                                },
                                {
                                    "type": "text",
                                    "value": " "
                                },
                                {
                                    "type": "expression",
                                    "value": "1.1.1.1"
                                }
                            ]
                        }
                    ],
                    "handle_template": "Details",
                    "id": "24d64a0a-012d-4eb5-90ad-5d8f55f107a6",
                    "parts": [
                        {
                            "type": "text",
                            "value": "Compromised VM "
                        },
                        {
                            "type": "expression",
                            "value": "Accounting-lb-1"
                        },
                        {
                            "type": "text",
                            "value": " - take a snapshot, suspend or stop the VM, or disconnect its network cards"
                        }
                    ],
                    "rule_type": "",
                    "type": "VMRecommendation"
                }
            ],
            "reenrich_count": 0,
            "remote_index": "incidents__1__2021_07_02_00_00_00",
            "second_asset": {
                "asset_id": "e69d1434-28d3-4774-a933-c2c993412edc",
                "asset_type": "VM"
            },
            "sensor_type": "VISIBILITY",
            "severity": 50,
            "similarity_calculated": true,
            "source_asset": {
                "ip": "1.1.1.1",
                "is_inner": true,
                "labels": [
                    "source"
                ],
                "vm": {
                    "full_name": "esx10/lab_a/Apps/Accounting\\Accounting-lb-1",
                    "id": "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285",
                    "name": "Accounting-lb-1",
                    "recent_domains": [],
                    "tenant_name": "esx10/lab_a/Apps/Accounting"
                },
                "vm_id": "53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285"
            },
            "start_time": 1625203133278,
            "stories": [
                {
                    "arguments": {
                        "asset_name": "Accounting-lb-1",
                        "destination_port": 53,
                        "ip_address": "1.1.1.1",
                        "malicious_process": {
                            "process_name": "xzas9876",
                            "reputation_info": "{Known malware}"
                        },
                        "malicious_process->process_name": "xzas9876",
                        "malicious_process->reputation_info": "{Known malware}"
                    },
                    "parts": [
                        {
                            "type": "text",
                            "value": "Process "
                        },
                        {
                            "type": "processes",
                            "value": "xzas9876"
                        },
                        {
                            "type": "text",
                            "value": " on asset "
                        },
                        {
                            "type": "expression",
                            "value": "Accounting-lb-1"
                        },
                        {
                            "type": "text",
                            "value": " ("
                        },
                        {
                            "type": "ip",
                            "value": "1.1.1.1"
                        },
                        {
                            "type": "text",
                            "value": "), communicating on port "
                        },
                        {
                            "type": "expression",
                            "value": "53"
                        },
                        {
                            "type": "text",
                            "value": ", was identified as "
                        },
                        {
                            "type": "expression",
                            "value": "Known malware"
                        },
                        {
                            "type": "text",
                            "value": " by Guardicore Reputation Service"
                        }
                    ],
                    "tags": [
                        {
                            "display_name": "Known malware",
                            "events": [
                                "686e7645-1c75-458e-8bad-ff2b01cb7651",
                                "8ad2d6d9-fe7c-4894-ad9c-0760fd7e5a22"
                            ],
                            "tag_class": "ENRICHER"
                        }
                    ],
                    "template": "Process {type:processes|[malicious_process->process_name]} on asset {[asset_name]} ({type:ip|[ip_address]}), communicating on port {[destination_port]}, was identified as [malicious_process->reputation_info] by Guardicore Reputation Service",
                    "time": 1625203336484
                }
            ],
            "tags": [
                {
                    "display_name": "Internal",
                    "events": [],
                    "id": "c5376c29-4648-45c4-9675-8a00aa9e9cd3",
                    "search_names": [
                        "Internal",
                        "Listed IP"
                    ],
                    "shortened_group_display_name": "Internal",
                    "source": "NetworkActivityDetector\\detect_listed_ips",
                    "tag_args": {
                        "category": "Internal"
                    },
                    "tag_class": "ENRICHER",
                    "tag_type_key": "listed ip",
                    "visible": true
                },
                {
                    "display_name": "Known malware",
                    "events": [
                        "686e7645-1c75-458e-8bad-ff2b01cb7651",
                        "8ad2d6d9-fe7c-4894-ad9c-0760fd7e5a22"
                    ],
                    "id": "dff5c483-99b5-474c-a839-07ad111fe46d",
                    "search_names": [
                        "Suspicious Process",
                        "Reputation",
                        "Known malware"
                    ],
                    "shortened_group_display_name": "Known malware",
                    "source": "PassiveDetector\\detect_process",
                    "tag_args": {
                        "process_name": "xzas9876",
                        "process_path": "/bin/xzas9876",
                        "reason": "Known malware",
                        "side": 1
                    },
                    "tag_class": "ENRICHER",
                    "tag_type_key": "suspicious process",
                    "time": 1625203336484,
                    "visible": true
                }
            ],
            "total_events_count": 1
        }
    }
}
```

#### Human Readable Output

>### GuardiCoreV2 - Incident: c2acca07-e9bf-4d63-9a26-ff6c749d24d2
>|affected_assets|end_time|ended|id|incident_type|severity|start_time|
>|---|---|---|---|---|---|---|
>| {'labels': ['source'], 'ip': '1.1.1.1', 'vm_id': '53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285', 'vm': {'id': '53d49bdc-0be0-4b7e-b7e3-d3dcc79bc285', 'name': 'Accounting-lb-1', 'recent_domains': [], 'tenant_name': 'esx10/lab_a/Apps/Accounting', 'full_name': 'esx10/lab_a/Apps/Accounting\\Accounting-lb-1'}, 'is_inner': True},<br/>{'labels': ['destination'], 'ip': '1.1.1.1', 'vm_id': 'e69d1434-28d3-4774-a933-c2c993412edc', 'vm': {'id': 'e69d1434-28d3-4774-a933-c2c993412edc', 'name': 'DC-01', 'recent_domains': [], 'tenant_name': 'esx10/lab_a/Endpoints', 'full_name': 'esx10/lab_a/Endpoints\\DC-01'}, 'is_inner': True} | 1625203336164 | true | c2acca07-e9bf-4d63-9a26-ff6c749d24d2 | Reveal | 50 | 1625203133278 |


### guardicore-get-incidents
***
Display information about incidents.


#### Base Command

`guardicore-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_time | From time. | Required | 
| to_time | To time. | Required | 
| limit | Limit results. Default is 50. | Optional | 
| offset | Results offset. | Optional | 
| severity | Severity (Low, Medium, High). | Optional | 
| source | Source. | Optional | 
| destination | Destination. | Optional | 
| tag | Tag. | Optional | 
| incident_type | Type (Incident, Deception, Network Scan, Reveal, Experimental). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Guardicore.Incident._id | String | Guardicore Incident ID | 
| Guardicore.Incident._cls | String | Guardicore Incident Cls | 
| Guardicore.Incident.doc_version | Number | Guardicore Incident Doc Version | 
| Guardicore.Incident.sensor_type | String | Guardicore Incident Sensor Type | 
| Guardicore.Incident.start_time | Date | Guardicore Incident Start Time | 
| Guardicore.Incident.end_time | Date | Guardicore Incident End Time | 
| Guardicore.Incident.last_updated_time | Date | Guardicore Incident Last Updated Time | 
| Guardicore.Incident.ended | String | Guardicore Incident Ended | 
| Guardicore.Incident.severity | Number | Guardicore Incident Severity | 
| Guardicore.Incident.affected_assets.labels | String | Guardicore Incident Affected Assets Labels | 
| Guardicore.Incident.affected_assets.ip | String | Guardicore Incident Affected Assets IP | 
| Guardicore.Incident.affected_assets.is_inner | String | Guardicore Incident Affected Assets Is Inner Status | 
| Guardicore.Incident.affected_assets.vm_id | String | Guardicore Incident Affected Assets VM ID | 
| Guardicore.Incident.affected_assets.vm.id | String | Guardicore Incident Affected Assets VM ID | 
| Guardicore.Incident.affected_assets.vm.name | String | Guardicore Incident Affected Assets VM Name | 
| Guardicore.Incident.affected_assets.vm.tenant_name | String | Guardicore Incident Affected Assets VM Tenant Name | 
| Guardicore.Incident.affected_assets.vm.full_name | String | Guardicore Incident Affected Assets VM Full Name | 
| Guardicore.Incident.enriched | String | Guardicore Incident Enriched | 
| Guardicore.Incident.reenrich_count | Number | Guardicore Incident Reenrich Count | 
| Guardicore.Incident.similarity_calculated | String | Guardicore Incident Similarity Calculated | 
| Guardicore.Incident.incident_group.gname | String | Guardicore Incident Incident Group Gname | 
| Guardicore.Incident.incident_group.gid | String | Guardicore Incident Incident Group GID | 
| Guardicore.Incident.flow_ids | String | Guardicore Incident Flow IDs | 
| Guardicore.Incident.remote_index | String | Guardicore Incident Remote Index | 
| Guardicore.Incident.is_experimental | String | Guardicore Incident Is Experimental Status | 
| Guardicore.Incident.original_id | String | Guardicore Incident Original ID | 
| Guardicore.Incident.experimental_id | String | Guardicore Incident Experimental ID | 
| Guardicore.Incident.first_asset.asset_type | Number | Guardicore Incident First Asset Asset Type | 
| Guardicore.Incident.first_asset.asset_id | String | Guardicore Incident First Asset Asset ID | 
| Guardicore.Incident.second_asset.asset_type | Number | Guardicore Incident Second Asset Asset Type | 
| Guardicore.Incident.second_asset.asset_id | String | Guardicore Incident Second Asset Asset ID | 
| Guardicore.Incident.labels.id | String | Guardicore Incident Labels ID | 
| Guardicore.Incident.labels.key | String | Guardicore Incident Labels Key | 
| Guardicore.Incident.labels.value | String | Guardicore Incident Labels Value | 
| Guardicore.Incident.labels.name | String | Guardicore Incident Labels Name | 
| Guardicore.Incident.labels.color_index | Number | Guardicore Incident Labels Color Index | 
| Guardicore.Incident.labels.asset_ids | String | Guardicore Incident Labels Asset IDs | 
| Guardicore.Incident.policy_revision | Number | Guardicore Incident Policy Revision | 
| Guardicore.Incident.closed_time | Date | Guardicore Incident Closed Time | 
| Guardicore.Incident.id | String | Guardicore Incident ID | 
| Guardicore.Incident.incident_type | String | Guardicore Incident Incident Type | 
| Guardicore.Incident.has_export | String | Guardicore Incident Has Export Flag | 
| Guardicore.Incident.concatenated_tags.display_name | String | Guardicore Incident Concatenated Tags Display Name | 
| Guardicore.Incident.concatenated_tags.tag_class | String | Guardicore Incident Concatenated Tags Tag Class | 
| Guardicore.Incident.concatenated_tags.events | String | Guardicore Incident Concatenated Tags Events | 
| Guardicore.Incident.direction | String | Guardicore Incident Direction | 
| Guardicore.Incident.source_asset.labels | String | Guardicore Incident Source Asset Labels | 
| Guardicore.Incident.source_asset.ip | String | Guardicore Incident Source Asset IP | 
| Guardicore.Incident.source_asset.is_inner | String | Guardicore Incident Source Asset Is Inner Status | 
| Guardicore.Incident.destination_asset.labels | String | Guardicore Incident Destination Asset Labels | 
| Guardicore.Incident.destination_asset.ip | String | Guardicore Incident Destination Asset IP | 
| Guardicore.Incident.destination_asset.vm_id | String | Guardicore Incident Destination Asset VM ID | 
| Guardicore.Incident.destination_asset.vm.id | String | Guardicore Incident Destination Asset VM ID | 
| Guardicore.Incident.destination_asset.vm.name | String | Guardicore Incident Destination Asset VM Name | 
| Guardicore.Incident.destination_asset.vm.tenant_name | String | Guardicore Incident Destination Asset VM Tenant Name | 
| Guardicore.Incident.destination_asset.vm.full_name | String | Guardicore Incident Destination Asset VM Full Name | 
| Guardicore.Incident.destination_asset.is_inner | String | Guardicore Incident Destination Asset Is Inner Status | 


#### Command Example
```!guardicore-get-incidents from_time="2020-12-12T15:31:17Z" to_time="2022-07-07T15:31:17Z" limit=1```

#### Context Example
```json
{
    "Guardicore": {
        "Incident": [
            {
                "affected_assets": [
                    {
                        "ip": "1.1.1.1",
                        "is_inner": false,
                        "labels": [
                            "source"
                        ]
                    },
                    {
                        "ip": "1.1.1.1",
                        "is_inner": true,
                        "labels": [
                            "destination"
                        ],
                        "vm": {
                            "full_name": "esx10/lab_a/Endpoints\\jumpbox-linux-1",
                            "id": "7b868cc2-9f61-4c81-ac75-ff74bc8ee7c5",
                            "name": "jumpbox-linux-1",
                            "recent_domains": [],
                            "tenant_name": "esx10/lab_a/Endpoints"
                        },
                        "vm_id": "7b868cc2-9f61-4c81-ac75-ff74bc8ee7c5"
                    }
                ],
                "end_time": 1611322117545,
                "ended": true,
                "id": "adb636b7-f941-438f-82ce-c0f44ddb5324",
                "incident_type": "Reveal",
                "severity": 30,
                "start_time": 1611321257006
            }
        ]
    }
}
```

#### Human Readable Output

>### GuardiCoreV2 - Incidents: 1
>|affected_assets|end_time|ended|id|incident_type|severity|start_time|
>|---|---|---|---|---|---|---|
>| {'labels': ['source'], 'ip': '1.1.1.1', 'is_inner': False},<br/>{'labels': ['destination'], 'ip': '1.1.1.1', 'vm_id': '7b868cc2-9f61-4c81-ac75-ff74bc8ee7c5', 'vm': {'id': '7b868cc2-9f61-4c81-ac75-ff74bc8ee7c5', 'name': 'jumpbox-linux-1', 'recent_domains': [], 'tenant_name': 'esx10/lab_a/Endpoints', 'full_name': 'esx10/lab_a/Endpoints\\jumpbox-linux-1'}, 'is_inner': True} | 1611322117545 | true | adb636b7-f941-438f-82ce-c0f44ddb5324 | Reveal | 30 | 1611321257006 |


### endpoint
***
Endpoint command (uses `guardicore-search-asset` internally).


#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID (takes priority over ip and hostname). | Optional | 
| ip | Query assets with specified IP address (ip takes priority over hostname). | Optional | 
| hostname | Query assets with matching hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | Endpoint Hostname | 
| Endpoint.ID | String | Endpoint ID | 
| Endpoint.IPAddress | String | Endpoint IPAddress | 
| Endpoint.OS | String | Endpoint OS | 
| Endpoint.OSVersion | String | Endpoint OSVersion | 
| Endpoint.Status | String | Endpoint Status | 
| Endpoint.MACAddress | String | Endpoint MACAddress | 


#### Command Example
```!endpoint ip=1.1.1.1```

#### Context Example
```json
{
    "Endpoint": [
        {
            "ID": "961ac4ac-3e81-4212-bc92-0eb5a86f918d",
            "IPAddress": "1.1.1.1",
            "MACAddress": "aa:bb:aa:bb:aa:bb",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "bce101be-6a75-4bca-8fdc-d1343fd93ecc",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:b5:ab",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "fd8fc658-5b82-45b0-9d66-c07833b40b3a",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:97:ab",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "cd319566-e61c-4365-93bb-af6884e60db2",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:ab:bf",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "5fc8ba67-b729-45ef-8867-fb33323deb95",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:83:97",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "a6867d27-42aa-4161-bc61-55ff7b16215d",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:bf:83",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "2312f849-372a-43a3-84ee-4600c19b7275",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:bf:bf",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "7eb79620-9f08-40f1-a7f4-6df57c5cf4d1",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:83:8d",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "f5a6498b-b8eb-4d43-91d6-8a803a32f248",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:6f:65",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "db07486a-2c8a-49e3-812b-269e595e02f1",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:a1:79",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "548f78e3-7970-47b7-ab6a-ee2b3743db7d",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:a1:83",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "45ed0523-dc20-4469-befa-b97262e9ecc3",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:83:ab",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "2dfa8cb0-0e22-43c7-a282-cd03cbc964db",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:97:97",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "bd413f7e-14e5-4a6b-b158-3a76b3e8aaad",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:6f:ab",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "f3b5819e-792e-47ff-8a4e-056aee964899",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:97:79",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "311a6083-a8c2-4046-94a7-bcb4dd01b4cb",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:8d:97",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "82057e3e-3f16-4b3e-ad85-0f0260adf8a8",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:8d:b5",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "f1c10d5b-6861-4932-a4c1-d9b37f8ba20a",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:65:83",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "1443019f-7b0f-46d0-bf46-cdd0a0aad9f9",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:b5:8d",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        },
        {
            "ID": "a9900e49-b8d5-479d-93e1-a199f2b2e7a4",
            "IPAddress": "1.1.1.1",
            "MACAddress": "00:00:00:00:a1:6f",
            "OS": "0",
            "Vendor": "GuardiCore Response"
        }
    ]
}
```

#### Human Readable Output

>### GuardiCoreV2 - Endpoint: 
>|ID|IPAddress|MACAddress|OS|Vendor|
>|---|---|---|---|---|
>| a9900e49-b8d5-479d-93e1-a199f2b2e7a4 | 1.1.1.1 | 00:00:00:00:a1:6f | 0 | GuardiCore Response |


## Breaking changes from the previous version of this integration - GuardiCore v2
This is a new version, old version of the API is deprecated (by GuardiCore).

## Additional Considerations for this version
