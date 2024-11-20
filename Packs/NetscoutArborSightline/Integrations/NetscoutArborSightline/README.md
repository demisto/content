DDoS protection and network visibility.
This integration was integrated and tested with version 9.3 of Netscout Arbor Sightline.

## Configure NetscoutArborSightline in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident type |  | False |
| Server URL (e.g., https://....) |  | True |
| API Key | If using 6.0.2 or lower version, put your API Key in the **Password** field, leave the **User** field empty. | False |
| Fetch incidents |  | False |
| First fetch time | First fetch query \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days or ISO format 2020-01-01T10:00:00\). Maximal number of past events to fetch is 10,000. | False |
| Fetch Limit | Maximum number of alerts per fetch. Default is 50, maximum is 100. | False |
| Alert Class | Alert class to filter by. Only one class can be configured at a time. If none is chosen, all classes will be fetched. | False |
| Alert Type | Alert type to filter by. Only one type can be configured at a time. If none is chosen, all types will be fetched. | False |
| Minimal importance to fetch | Minimal alert importance to filter by. If none or Low is chosen, all importances will be fetched. | False |
| Event Status | Alert status to filter by. If none is chosen, all statuses will be fetched. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### na-sightline-alert-annotation-list
***
Lists the collection of annotations for a given alert.


#### Base Command

`na-sightline-alert-annotation-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to list the annotation for. Can be obtained from the na-sightline-alert-list command. | Required | 
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.AlertAnnotation.AlertID | String | The alert ID of the annotation. | 
| NASightline.AlertAnnotation.Annotations.added | Date | Date and time the annotation was made. | 
| NASightline.AlertAnnotation.Annotations.author | String | User ID of the annotation author. | 
| NASightline.AlertAnnotation.Annotations.id | String | The ID of the annotation. | 
| NASightline.AlertAnnotation.Annotations.text | String | Annotation text. | 
| NASightline.AlertAnnotation.Annotations.type | String | Type of the returned object. | 
| NASightline.AlertAnnotation.Annotations.relationships | Unknown | Relationships of the annotation \(only visible when extending the data\). | 


#### Command Example
```!na-sightline-alert-annotation-list alert_id="2009" limit=2```

#### Context Example
```json
{
    "NASightline": {
        "AlertAnnotation": {
            "AlertID": "2009",
            "Annotations": [
                {
                    "added": "2021-03-29T18:18:13+00:00",
                    "author": "auto-annotation",
                    "id": "886",
                    "text": "Flowspec mitigation 'testMit2' started",
                    "type": "alert_annotation"
                },
                {
                    "added": "2021-03-07T19:09:05+00:00",
                    "author": "auto-annotation",
                    "id": "797",
                    "text": "Flowspec mitigation 'testMit' started",
                    "type": "alert_annotation"
                },
                {
                    "added": "2021-03-07T11:00:02+00:00",
                    "author": "auto-annotation",
                    "id": "795",
                    "text": "This alert was generated due to fast flood detection. The \"Total Traffic\" host alert signature has been triggered at router \"Traffic-PCAP-CentOS\". (expected rate: 5 bps/50.00 Kpps, observed rate: 11 bps/0 pps)",
                    "type": "alert_annotation"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Alert 2009 annotations
>|added|author|id|text|type|
>|---|---|---|---|---|
>| 2021-03-29T18:18:13+00:00 | auto-annotation | 886 | Flowspec mitigation 'testMit2' started | alert_annotation |
>| 2021-03-07T19:09:05+00:00 | auto-annotation | 797 | Flowspec mitigation 'testMit' started | alert_annotation |
>| 2021-03-07T11:00:02+00:00 | auto-annotation | 795 | This alert was generated due to fast flood detection. The "Total Traffic" host alert signature has been triggered at router "Traffic-PCAP-CentOS". (expected rate: 5 bps/50.00 Kpps, observed rate: 11 bps/0 pps) | alert_annotation |


### na-sightline-alert-list
***
List all alerts. When an alert ID is given, only the relevant alert will be fetched.


#### Base Command

`na-sightline-alert-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. If given, all other arguments will be ignored. | Optional | 
| alert_class | Alert class to filter by. Possible values are: bgp, cloudsignal, data, dos, smart, system_error, system_event, tms, traffic. | Optional | 
| alert_type | Alert type to filter by. Possible values are: autoclassify_restart, bgp_down, bgp_hijack, bgp_instability, bgp_trap, blob_thresh, cloud_mit_request, cloudsignal_fault, collector_down, collector_start, config_change, device_system_error, dns_baseline, dos, dos_host_detection, dos_mo_profiled, dos_profiled_network, dos_profiled_router, fingerprint_thresh, flexible_license_error, flow_down, flow_missing, gre_down, hw_failure, smart_thresh, interface_usage, nucleus_fault, routing_failover, routing_interface_failover, service_thresh, smart_thresh, snmp_down, spcomm_failure, tms_fault, traffic_auto_mitigation. | Optional | 
| classification | Alert classification to filter by. Possible values are: Possible Attack, False Positive, Verified Attack, Network Failure, Flash Crowd, Trivial. | Optional | 
| importance | Alert importance to filter by. For more complex operators use the 'importance_operator' argument. Possible values are: Low, Medium, High. | Optional | 
| importance_operator | The operator to apply on the importance argument ("&gt;" is greater than, "&lt;" is less than, "=" is equal to). For example: if the chosen operator is "&gt;" and the chosen importance is "Low", only alerts with and importance greater than Low will be fetched. Possible values are: &lt;, =, &gt;. | Optional | 
| ongoing | Alert status to filter by. If not set, all statuses will be fetched. Possible values are: true, false. | Optional | 
| start_time | Alert start time to filter by. For more complex operators use the 'start_time_operator' argument. | Optional | 
| start_time_operator | The operator to apply on the "start_time" argument. For example: if the chosen operator is "&gt;" and the given time is "2020-12-01T13:15:00", only alerts with a starting time greater than "2020-12-01T13:15:00" will be fetched. Possible values are: =, &gt;, &lt;. | Optional | 
| stop_time | Alert stop time to filter by. For more complex operators use the 'stop_time_operator' argument. | Optional | 
| stop_time_operator | The operator to apply on the "stop_time" argument. For example: if the chosen operator is "&gt;" and the given time is "2020-12-01T13:15:00", only alerts with a stopping time greater than "2020-12-01T13:15:00" will be fetched. Possible values are: =, &gt;, &lt;. | Optional | 
| managed_object_id | ID of the managed object associated with the alert. Can be obtained from the na-sightline-managed-object-list command. | Optional | 
| page | The page to return starting from 1. | Optional | 
| limit | Maximal number of alerts to retrieve. Also sets the size of the returned page. Default is 50. | Optional | 
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.Alert.alert_class | String | The class of the alert. One of the following: bgp, cloudsignal, data, dos, smart, system_error, system_event ,tms ,traffic. | 
| NASightline.Alert.alert_type | String | The type of the alert. One of the following: bgp_hijack, bgp_instability, bgp_trap, cloudsignal, cloudsignal_fault, cloud_mit_request, data, bgp_down, flow_down, snmp_down, dos, dos_host_detection, dos_profiled_network, dos_profiled_router, mobile, mobile_fault, smart, smart_thresh, system_error, collector_down, flexible_license, hw_failure, routing_failover, routing_failover_interface, spcomm_failure, system_monitor, system_event, config_change, tms, dns_baseline, gre_down, tms_fault, traffic, blob_thresh, fingerprint_thresh, interface_usage, service_thresh, traffic_auto_mitigation. | 
| NASightline.Alert.id | String | The ID of the alert. | 
| NASightline.Alert.importance | Number | Importance of the alert. One of the following 2: high, 1: medium, 0: low | 
| NASightline.Alert.ongoing | Boolean | Whether the alert is currently active. | 
| NASightline.Alert.relationships | Unknown | Relationships of the alert \(only visible when extending the data\). | 
| NASightline.Alert.start_time | Date | Date and time at which the alert activity was first detected. | 
| NASightline.Alert.type | String | Type of the returned object. | 
| NASightline.Alert.classification | String | Classification of the alert. One of the following: False Positive, Flash Crowd, Network Failure, Possible Attack, Trivial, Verified Attack  | 
| NASightline.Alert.stop_time | Date | Date and time at which the alert activity was no longer detected. | 
| NASightline.Alert.subobject | Unknown | Subobject data \(only visible when extending the data\). | 


#### Command Example
```!na-sightline-alert-list limit=2```

#### Context Example
```json
{
    "NASightline": {
        "Alert": [
            {
                "alert_class": "data",
                "alert_type": "flow_down",
                "id": "2799",
                "importance": 1,
                "ongoing": true,
                "start_time": "2021-05-08T16:07:13+00:00",
                "subobject": {},
                "type": "alert"
            },
            {
                "alert_class": "dos",
                "alert_type": "dos_host_detection",
                "classification": "Possible Attack",
                "id": "2798",
                "importance": 2,
                "ongoing": false,
                "start_time": "2021-05-08T16:00:02+00:00",
                "stop_time": "2021-05-08T16:10:29+00:00",
                "subobject": {
                    "direction": "Incoming",
                    "fast_detected": true,
                    "host_address": "1.2.3.4",
                    "impact_boundary": "managed object",
                    "impact_bps": 1072,
                    "impact_pps": 3,
                    "ip_version": 4,
                    "misuse_types": [
                        "Total Traffic"
                    ],
                    "severity_percent": 10720,
                    "severity_threshold": 10,
                    "severity_unit": "bps",
                    "summary_url": "/page?id=customer_summary&gid=122"
                },
                "type": "alert"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alerts
>|alert_class|alert_type|id|importance|links|ongoing|start_time|subobject|type|
>|---|---|---|---|---|---|---|---|---|
>| data | flow_down | 2799 | 1 | self: https://xsoar-example:57585/api/sp/v7/alerts/2799 | true | 2021-05-08T16:07:13+00:00 |  | alert |
>| dos | dos_host_detection | 2798 | 2 | self: https://xsoar-example:57585/api/sp/v7/alerts/2798 | false | 2021-05-08T16:00:02+00:00 |  | alert |


### na-sightline-mitigation-list
***
List all mitigations. When a mitigation ID is given, only the relevant mitigation will be fetched.


#### Base Command

`na-sightline-mitigation-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_id | The mitigation ID to get. Can be obtained from the na-sightline-mitigation-list command. | Optional | 
| page | The page to return starting from 1. | Optional | 
| limit | Maximal number of mitigations to retrieve. Also sets the size of the returned page. Default is 50. | Optional | 
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.Mitigation.description | String | Description of the mitigation. | 
| NASightline.Mitigation.id | String | The ID of the mitigation. | 
| NASightline.Mitigation.ip_version | Number | IP version of the traffic that is being mitigated. | 
| NASightline.Mitigation.is_automitigation | Boolean | Whether the mitigation is an auto-mitigation. | 
| NASightline.Mitigation.name | String | Mitigation name. | 
| NASightline.Mitigation.ongoing | Boolean | Whether the mitigation is currently running. | 
| NASightline.Mitigation.start | String | Start date and time of the mitigation in ISO 8601 format. | 
| NASightline.Mitigation.subtype | String | The type of mitigation. One of the following: blackhole, flowspec, tms. | 
| NASightline.Mitigation.type | String | Type of the returned object. | 
| NASightline.Mitigation.user | String | The user who initiated a mitigation. | 
| NASightline.Mitigation.relationships | Unknown | Relationships of the mitigation \(only visible when extending the data\). | 
| NASightline.Mitigation.subobject | Unknown | Subobject data \(only visible when extending the data\). | 


#### Command Example
```!na-sightline-mitigation-list limit=2```

#### Context Example
```json
{
    "NASightline": {
        "Mitigation": [
            {
                "description": "TMS mitigation for alert 101",
                "id": "flowspec-36",
                "ip_version": 4,
                "is_automitigation": false,
                "name": "DoS Alert 1079",
                "ongoing": true,
                "start": "2021-04-22T07:39:27.849350+00:00",
                "subtype": "flowspec",
                "type": "mitigation",
                "user": "demisto"
            },
            {
                "description": "Some annotation description",
                "id": "flowspec-12",
                "ip_version": 4,
                "is_automitigation": false,
                "name": "Mitigation Annotation Name1",
                "ongoing": true,
                "start": "2021-04-17T18:03:54.875020+00:00",
                "subtype": "flowspec",
                "type": "mitigation",
                "user": "demisto"
            }
        ]
    }
}
```

#### Human Readable Output

>### Mitigation list
>|description|id|ip_version|is_automitigation|links|name|ongoing|start|subtype|type|user|
>|---|---|---|---|---|---|---|---|---|---|---|
>| TMS mitigation for alert 101 | flowspec-36 | 4 | false | self: https://xsoar-example:57585/api/sp/v7/mitigations/flowspec-36 | DoS Alert 1079 | true | 2021-04-22T07:39:27.849350+00:00 | flowspec | mitigation | demisto |
>| Some annotation description | flowspec-12 | 4 | false | self: https://xsoar-example:57585/api/sp/v7/mitigations/flowspec-12 | Mitigation Annotation Name1 | true | 2021-04-17T18:03:54.875020+00:00 | flowspec | mitigation | demisto |


### na-sightline-mitigation-create
***
Add a TMS or flowspec mitigation with the attributes and relationships passed in the JSON sub_object.


#### Base Command

`na-sightline-mitigation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Mitigation name. | Required | 
| ip_version | IP version of the traffic that is being mitigated. This attribute cannot be changed once it is set. Possible values are: IPv4, IPv6. | Required | 
| description | Description of the mitigation. | Optional | 
| ongoing | Whether to start the mitigation (true) or not (false). Possible values are: true, false. Default is false. | Optional | 
| sub_type | The type of mitigation. Possible values are: tms, flowspec. | Required | 
| sub_object | JSON object that specifies the attributes specific to the mitigation subtype. For example: {"bgp_announce": false, "protection_prefixes": ["192.0.2.0/24"]}. List of values supported for each sub-type can be found in the Netscout Arbor Sightline documentation: &lt;your_server_url&gt;/api/sp/doc/v7/mitigations.html#url-/mitigations/. | Required | 
| alert_id | ID of the alert associated with the mitigation. Can be obtained from the na-sightline-alert-list command. | Optional | 
| mitigation_template_id | ID of the mitigation template applied to this mitigation. To get a list of available templates and their IDs, run the na-sightline-mitigation-template-list command. | Optional | 
| router_ids | (Flowspec mitigations only) Comma-separated list of IDs of the routers to which the flowspec announcement is made. To get a list of available routers and their IDs run the na-sightline-router-list command. | Optional | 
| managed_object_id | (TMS mitigations only) ID of the managed object associated with the alert. To get a list of available managed objects and their IDs run the na-sightline-managed-object-list command. | Optional | 
| tms_group_id | (TMS mitigations only) ID of the TMS group that the associated managed object belongs to. To get a list of available TMS groups and their IDs run the na-sightline-tms-group-list command. | Optional | 
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.Mitigation.id | String | The ID of the mitagation. | 
| NASightline.Mitigation.ip_version | Number | IP version of the traffic that is being mitigated. | 
| NASightline.Mitigation.is_automitigation | Boolean | Whether the mitigation is an auto-mitigation. | 
| NASightline.Mitigation.name | String | Mitigation name. | 
| NASightline.Mitigation.ongoing | Boolean | Whether the mitigation is currently running. | 
| NASightline.Mitigation.subobject | Unknown | Subobject data \(only visible when extending the data\). | 
| NASightline.Mitigation.subtype | String | The type of mitigation. One of the following: blackhole, flowspec, tms. | 
| NASightline.Mitigation.type | String | Type of the returned object. | 
| NASightline.Mitigation.relationships | Unknown | Relationships of the mitigation \(only visible when extending the data\). | 


#### Command Example
```!na-sightline-mitigation-create description="Some mitigation description" ip_version=IPv4 name="Mitigation Annotation Name" ongoing=true sub_object="{\"protection_prefixes\": [\"192.0.2.0/24\"]}" sub_type=flowspec```

#### Context Example
```json
{
    "NASightline": {
        "Mitigation": {
            "description": "Some mitigation description",
            "id": "flowspec-58",
            "ip_version": 4,
            "is_automitigation": false,
            "name": "Mitigation Annotation Name",
            "ongoing": true,
            "start": "2021-05-08T20:16:53.251710+00:00",
            "subobject": {
                "action": {
                    "type": "accept"
                },
                "bgp_communities": [],
                "l3vpn_route_distinguisher": "",
                "l3vpn_route_targets": []
            },
            "subtype": "flowspec",
            "type": "mitigation",
            "user": "demisto"
        }
    }
}
```

#### Human Readable Output

>### Mitigation was created
>|description|id|ip_version|is_automitigation|links|name|ongoing|start|subtype|type|user|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Some mitigation description | flowspec-58 | 4 | false | self: https://xsoar-example:57585/api/sp/v7/mitigations/flowspec-58 | Mitigation Annotation Name | true | 2021-05-08T20:16:53.251710+00:00 | flowspec | mitigation | demisto |


### na-sightline-mitigation-delete
***
Delete a given mitigation.


#### Base Command

`na-sightline-mitigation-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_id | The mitigation ID to delete. Can be obtained from the na-sightline-mitigation-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-sightline-mitigation-delete mitigation_id=flowspec-34```

#### Human Readable Output

>### Mitigation flowspec-34 was deleted


### na-sightline-mitigation-template-list
***
Get a list of available mitigation templates.


#### Base Command

`na-sightline-mitigation-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.MitigationTemplate.description | String | The description of the mitigation template. | 
| NASightline.MitigationTemplate.id | String | The ID of the mitigation template. | 
| NASightline.MitigationTemplate.ip_version | Number | The IP version of the traffic that you want to mitigate with this mitigation template. | 
| NASightline.MitigationTemplate.name | String | The name of the mitigation template. | 
| NASightline.MitigationTemplate.subtype | String | The type of mitigation this template can be applied to. | 
| NASightline.MitigationTemplate.system | Boolean | System or custom object. | 
| NASightline.MitigationTemplate.type | String | Type of the returned object. | 
| NASightline.MitigationTemplate.subobject | Unknown | Subobject data \(only visible when extending the data\). | 
| NASightline.MitigationTemplate.relationships | Unknown | Relationships of the mitigation template \(only visible when extending the data\). | 


#### Command Example
```!na-sightline-mitigation-template-list limit=2```

#### Context Example
```json
{
    "NASightline": {
        "MitigationTemplate": [
            {
                "description": "Default mitigation values inherited by all new IPv4 mitigations (unless otherwise scoped)",
                "id": "1",
                "ip_version": 4,
                "name": "Default IPv4",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "Auto-Mitigation template use by default for all IPv4 auto-mitigations. Auto-mitigation must be enabled for the managed object.",
                "id": "2",
                "ip_version": 4,
                "name": "Auto-Mitigation IPv4",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "Template contains countermeasures that support TMS deployments focused on VoIP Gateway Flood Protection",
                "id": "3",
                "ip_version": 4,
                "name": "VoIP Gateway Protection",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "Template provides example countermeasures that would support deployments for DNS infrastructure protection",
                "id": "4",
                "ip_version": 4,
                "name": "DNS Flood Protection",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "Rogue DC++ P2P clients have been used to attack HTTP Server infrastructure. This template provides an example of payload REGEX inspection for filtering clients used for a DC++ HTTP attack",
                "id": "5",
                "ip_version": 4,
                "name": "Rogue DC++ Protection",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "TCP SYN flood countermeasure",
                "id": "6",
                "ip_version": 4,
                "name": "TCP SYN Flood",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "ICMP Flood Countermeasure",
                "id": "7",
                "ip_version": 4,
                "name": "ICMP Flood",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "Default mitigation values inherited by all new IPv6 mitigations (unless otherwise scoped)",
                "id": "8",
                "ip_version": 6,
                "name": "Default IPv6",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            },
            {
                "description": "Auto-Mitigation template use by default for all IPv6 auto-mitigations. Auto-mitigation must be enabled for the managed object.",
                "id": "9",
                "ip_version": 6,
                "name": "Auto-Mitigation IPv6",
                "subtype": "tms",
                "system": true,
                "type": "mitigation_template"
            }
        ]
    }
}
```

#### Human Readable Output

>### Mitigation template list
>|description|id|ip_version|links|name|subtype|system|type|
>|---|---|---|---|---|---|---|---|
>| Default mitigation values inherited by all new IPv4 mitigations (unless otherwise scoped) | 1 | 4 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/1 | Default IPv4 | tms | true | mitigation_template |
>| Auto-Mitigation template use by default for all IPv4 auto-mitigations. Auto-mitigation must be enabled for the managed object. | 2 | 4 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/2 | Auto-Mitigation IPv4 | tms | true | mitigation_template |
>| Template contains countermeasures that support TMS deployments focused on VoIP Gateway Flood Protection | 3 | 4 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/3 | VoIP Gateway Protection | tms | true | mitigation_template |
>| Template provides example countermeasures that would support deployments for DNS infrastructure protection | 4 | 4 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/4 | DNS Flood Protection | tms | true | mitigation_template |
>| Rogue DC++ P2P clients have been used to attack HTTP Server infrastructure. This template provides an example of payload REGEX inspection for filtering clients used for a DC++ HTTP attack | 5 | 4 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/5 | Rogue DC++ Protection | tms | true | mitigation_template |
>| TCP SYN flood countermeasure | 6 | 4 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/6 | TCP SYN Flood | tms | true | mitigation_template |
>| ICMP Flood Countermeasure | 7 | 4 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/7 | ICMP Flood | tms | true | mitigation_template |
>| Default mitigation values inherited by all new IPv6 mitigations (unless otherwise scoped) | 8 | 6 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/8 | Default IPv6 | tms | true | mitigation_template |
>| Auto-Mitigation template use by default for all IPv6 auto-mitigations. Auto-mitigation must be enabled for the managed object. | 9 | 6 | self: https://xsoar-example:57585/api/sp/v7/mitigation_templates/9 | Auto-Mitigation IPv6 | tms | true | mitigation_template |


### na-sightline-router-list
***
Get a list of available routers.


#### Base Command

`na-sightline-router-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.Router.advanced_fallback_alg | String | The algorithm used to classify interfaces during auto-configuration that either report no traffic or have no associated BGP information: internal, external, or use_bgp_and_local. use_bgp_and_local classifies each observed flow, based on learned BGP information and the configured IP address space. | 
| NASightline.Router.advanced_use_simpson_flowspec_redirect_ip | Boolean | If true, BGP Redirect-to-IP flowspec announcements are generated conforming to draft-simpson-idr-flowspec-redirect-02.txt. | 
| NASightline.Router.bgp2_capabilities_labeled_unicast | Boolean | If true, Sightline is permitted to generate BGP 6PE diversion announcements for IPv6 destinations over the secondary BGP session per RFC 4798. | 
| NASightline.Router.bgp_capabilities_l3vpn_flowspec_ipv4 | Boolean | \(MPLS Layer 3 VPNs only\) If true, Sightline includes the route distinguisher \(RD\) and route target \(RT\) values in BGP flowspec diversion announcements for IPv4 traffic in flowspec mitigations and TMS mitigations. | 
| NASightline.Router.bgp_capabilities_l3vpn_flowspec_ipv6 | Boolean | \(MPLS Layer 3 VPNs only\) If true, Sightline includes the route distinguisher \(RD\) and route target \(RT\) values in BGP flowspec diversion announcements for IPv6 traffic in flowspec mitigations and TMS mitigations. | 
| NASightline.Router.bgp_capabilities_labeled_unicast | Boolean | If true, Sightline is permitted to generate BGP 6PE diversion announcements for for IPv6 destinations over the primary BGP session per RFC 4798. | 
| NASightline.Router.description | String | Router description. | 
| NASightline.Router.flow_alerting | Boolean | If true, enables flow down alerting for this router. | 
| NASightline.Router.flow_export_ip | String | The IP address of the router that sends flow records to Sightline. | 
| NASightline.Router.flow_flow_ignored | String | Either ignore NetFlow from this router \(on\) or not \(off\). | 
| NASightline.Router.flow_flow_ignored_ipv6 | String | Either ignore IPv6 NetFlow from this router \(on\) or not \(off\). | 
| NASightline.Router.flow_sample_rate | String | The sample rate of the flow information sent by this router. | 
| NASightline.Router.id | String | The ID of the router. | 
| NASightline.Router.is_proxy | Boolean | If true, Sightline treats the router as a proxy for other routers. | 
| NASightline.Router.license_type | String | The router license type: core, edge, or unset. For more information, see “Configuring Routers” in the Sightline and TMS User Guide. | 
| NASightline.Router.name | String | Router name | 
| NASightline.Router.snmp_authprotocol | String | SNMP v3 authentication protocol. One of the following: md5, sha, sha-224, sha-256, sha-384, sha-512. | 
| NASightline.Router.snmp_priv_protocol | String | The SNMP v3 privacy protocol: DES or AES. | 
| NASightline.Router.snmp_security_level | String | SNMP v3 security level. One of the following: noAuthNoPriv \(no pass-phrase authentication is performed\), authNoPriv \(pass-phrase authentication is performed, but there is no encryption of the data in the trap messages\), authPriv \(pass-phrase authentication is performed and the data in the trap messages is encrypted\). | 
| NASightline.Router.snmp_version | Number | SNMP version: 1, 2, or 3. | 
| NASightline.Router.type | String | Type of the returned object. | 
| NASightline.Router.advanced_local_as | String | The default local AS number override. | 
| NASightline.Router.bgp_capabilities_flowspec | Boolean | If true, Sightline can use the primary BGP peering session to generate BGP flowspec diversion announcements for IPv4 traffic in flowspec mitigations and TMS mitigations. | 
| NASightline.Router.bgp_capabilities_flowspec_ipv4 | Boolean | If true, Sightline can use the primary BGP peering session to generate BGP flowspec diversion announcements for IPv4 traffic in flowspec mitigations and TMS mitigations. | 
| NASightline.Router.bgp_capabilities_monitor_routes_ipv4 | String | If primary, the primary BGP peering session is used to monitor the IPv4 routes on the router for the purposes of classifying IPv4 traffic. If secondary, the secondary BGP peering session is used. If disabled, IPv4 routes are not monitored and IPv4 traffic is not classified using BGP routing information from this router. | 
| NASightline.Router.bgp_ip_address | String | The remote IP address that you want Sightline to use to create a BGP peering session with this router. | 
| NASightline.Router.bgp_remote_as | String | The ASN of the router. | 
| NASightline.Router.bgp_session_name | String | A name to help identify the BGP peering session in the Sightline UI when you create a blackhole or TMS mitigation. | 
| NASightline.Router.relationships | Unknown | Relationships of the router \(only visible when extending the data\). | 


#### Command Example
```!na-sightline-router-list limit=2```

#### Context Example
```json
{
    "NASightline": {
        "Router": [
            {
                "advanced_fallback_alg": "internal",
                "advanced_use_simpson_flowspec_redirect_ip": false,
                "bgp2_capabilities_labeled_unicast": false,
                "bgp_capabilities_l3vpn_flowspec_ipv4": false,
                "bgp_capabilities_l3vpn_flowspec_ipv6": false,
                "bgp_capabilities_labeled_unicast": false,
                "description": "Traffic-PCAP-CentOS - 192.168.1.116",
                "flow_alerting": true,
                "flow_export_ip": "192.168.1.116",
                "flow_flow_ignored": "off",
                "flow_flow_ignored_ipv6": "off",
                "flow_sample_rate": "1",
                "id": "121",
                "is_proxy": false,
                "license_type": "core",
                "name": "Traffic-PCAP-CentOS",
                "snmp_authprotocol": "md5",
                "snmp_priv_protocol": "DES",
                "snmp_security_level": "noAuthNoPriv",
                "snmp_version": 2,
                "type": "router"
            },
            {
                "advanced_fallback_alg": "internal",
                "advanced_local_as": "44",
                "advanced_use_simpson_flowspec_redirect_ip": false,
                "bgp2_capabilities_labeled_unicast": false,
                "bgp_capabilities_flowspec": true,
                "bgp_capabilities_flowspec_ipv4": true,
                "bgp_capabilities_l3vpn_flowspec_ipv4": false,
                "bgp_capabilities_l3vpn_flowspec_ipv6": false,
                "bgp_capabilities_labeled_unicast": false,
                "bgp_capabilities_monitor_routes_ipv4": "primary",
                "bgp_ip_address": "192.168.1.124",
                "bgp_remote_as": "4",
                "bgp_session_name": "NetscoutProfile",
                "description": "To Netscout PANW FW Router",
                "flow_alerting": true,
                "flow_flow_ignored": "off",
                "flow_flow_ignored_ipv6": "off",
                "id": "186",
                "is_proxy": false,
                "license_type": "core",
                "name": "PANW-FW_Netscout",
                "snmp_authprotocol": "md5",
                "snmp_priv_protocol": "DES",
                "snmp_security_level": "noAuthNoPriv",
                "snmp_version": 2,
                "type": "router"
            }
        ]
    }
}
```

#### Human Readable Output

>### Router list
>|id|name|description|is_proxy|license_type|snmp_authprotocol|snmp_priv_protocol|snmp_security_level|snmp_version|
>|---|---|---|---|---|---|---|---|---|
>| 121 | Traffic-PCAP-CentOS | Traffic-PCAP-CentOS - 192.168.1.116 | false | core | md5 | DES | noAuthNoPriv | 2 |
>| 186 | PANW-FW_Netscout | To Netscout PANW FW Router | false | core | md5 | DES | noAuthNoPriv | 2 |


### na-sightline-managed-object-list
***
Get a list of available managed objects.


#### Base Command

`na-sightline-managed-object-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page to return starting from 1. | Optional | 
| limit | Maximal number of mitigations to retrieve. Also sets the size of the returned page. Default is 50. | Optional | 
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.ManagedObject.autodetected | Boolean | If true, Sightline automatically detects and configures VPN sites when the match type of a VPN managed object is a route target and the VPN sites match the configured route targets. | 
| NASightline.ManagedObject.automitigation_precise_protection_prefixes | Boolean | If true, the precise protection prefixes feature for auto-mitigations is enabled. | 
| NASightline.ManagedObject.detection_network_country_enabled | Boolean | If true, profiled country detection is enabled. | 
| NASightline.ManagedObject.detection_network_enabled | Boolean | If true, profiled network detection is enabled. | 
| NASightline.ManagedObject.detection_profiled_autorate | Boolean | If true, automatic rate calculation for profiled router detection is enabled. | 
| NASightline.ManagedObject.detection_profiled_enabled | Boolean | If true, profiled router detection is enabled. | 
| NASightline.ManagedObject.detection_profiled_fast_flood_enabled | Boolean | If true, fast flood detection for profiled routers is enabled. | 
| NASightline.ManagedObject.detection_profiled_outgoing_enabled | Boolean | If true, outgoing detection for profiled router detection is enabled. | 
| NASightline.ManagedObject.detection_profiled_severity_duration | Number | Number of seconds that traffic must exceed a given severity threshold before Sightline escalates its severity for profiled router detection. | 
| NASightline.ManagedObject.detection_profiled_severity_snmp_enabled | Boolean | If true, SNMP link rate severity calculation is enabled for profiled router detection. | 
| NASightline.ManagedObject.detection_profiled_threshold_bandwidth | Number | Threshold for interface bandwidth alerts for profiled router detection. An integer from 1 to 5, where: 1 = detect more alerts, 2 = default, 3 = detect fewer alerts, 4 = detect even fewer alerts, 5 = detect fewest alerts. | 
| NASightline.ManagedObject.detection_profiled_threshold_packet_rate | Number | Threshold for interface packet alerts for profiled router detection. An integer from 1 to 5, where: 1 = detect more alerts, 2 = default, 3 = detect fewer alerts, 4 = detect even fewer alerts, 5 = detect fewest alerts. | 
| NASightline.ManagedObject.detection_profiled_threshold_protocol | Number | Threshold for all protocol alerts for profiled router detection. An integer from 1 to 5, where: 1 = detect more alerts, 2 = default, 3 = detect fewer alerts, 4 = detect even fewer alerts, 5 = detect fewest alerts. | 
| NASightline.ManagedObject.dynamic_match_enabled | Boolean | If true, Sightline can monitor traffic for OTT domains that have frequently changing service IP addresses. | 
| NASightline.ManagedObject.editable | Boolean | If true, is editable. | 
| NASightline.ManagedObject.family | String | A valid managed object type. Not all values appear in the UI as managed object types. One of the following: none, peer, profile, customer, worm \(deprecated\), vpn, vpnsite, service, subscriber. | 
| NASightline.ManagedObject.id | String | The ID of the managed object. | 
| NASightline.ManagedObject.match | String | A value appropriate for the specified match_type. | 
| NASightline.ManagedObject.match_enabled | Boolean | If true, Sightline records flow for this managed object. | 
| NASightline.ManagedObject.match_type | String | The managed object’s match type. One of the following: advanced, appid, asregexp, cidr_blocks, cidr_groups, cidr_v6_blocks, community, extended_community, interface, profiled_interface_group, subas, peer_as, tmsports. | 
| NASightline.ManagedObject.mitigation_automitigation_stop_event | String | The event that stops this TMS auto-mitigation. One of the following: manual, after_mitigation_starts, after_alert_ends. | 
| NASightline.ManagedObject.mitigation_automitigation_stop_minutes | Number | Stops the TMS auto-mitigation after the specified number of minutes for the after_mitigation_starts or after_alert_ends stop events. This is automatically set to 0 if mitigation_automitigation_stop_event is manual. | 
| NASightline.ManagedObject.mitigation_automitigation_tms_enabled | Boolean | If true, TMS auto-mitigation is enabled. | 
| NASightline.ManagedObject.mitigation_blackhole_auto_enabled | Boolean | If true, blackhole auto-mitigation is enabled. | 
| NASightline.ManagedObject.mitigation_flowspec_auto_enabled | Boolean | If true, flowspec auto-mitigation is enabled. | 
| NASightline.ManagedObject.name | String | The managed object’s name. | 
| NASightline.ManagedObject.num_children | Number | The number of child managed objects assigned to this one. | 
| NASightline.ManagedObject.parent_editable | Boolean | If false, parent is read-only. | 
| NASightline.ManagedObject.relationships | Unknown | Relationships of the managed object \(only visible when extending the data\). | 
| NASightline.ManagedObject.scrub_insight_mo_match | Boolean | If true, Sightline disassociates the managed object from the flow before sending the flow to Insight, thereby preventing the managed object from being subject to or appearing in Insight queries. | 
| NASightline.ManagedObject.tags | String | A list of tags that are applied to the managed object. | 
| NASightline.ManagedObject.type | String | Type of the returned object. | 


#### Command Example
```!na-sightline-managed-object-list limit=2```

#### Context Example
```json
{
    "NASightline": {
        "ManagedObject": {
            "autodetected": false,
            "automitigation_precise_protection_prefixes": false,
            "automitigation_precise_protection_prefixes_mit_on_query_failure": false,
            "custom_shared_host_detection_setting": true,
            "detection_network_country_enabled": false,
            "detection_network_enabled": false,
            "detection_profiled_autorate": false,
            "detection_profiled_enabled": false,
            "detection_profiled_fast_flood_enabled": false,
            "detection_profiled_outgoing_enabled": true,
            "detection_profiled_severity_duration": 300,
            "detection_profiled_severity_snmp_enabled": false,
            "detection_profiled_threshold_bandwidth": 2,
            "detection_profiled_threshold_packet_rate": 2,
            "detection_profiled_threshold_protocol": 2,
            "dynamic_match_enabled": false,
            "editable": true,
            "family": "customer",
            "id": "122",
            "match": "1.2.3.4/32",
            "match_enabled": true,
            "match_type": "cidr_blocks",
            "mitigation_automitigation": false,
            "mitigation_automitigation_stop_event": "after_alert_ends",
            "mitigation_automitigation_stop_minutes": 0,
            "mitigation_automitigation_tms_enabled": false,
            "mitigation_blackhole_auto_enabled": false,
            "mitigation_flowspec_auto_enabled": false,
            "name": "TestMO1",
            "num_children": 0,
            "parent_editable": false,
            "scrub_insight_mo_match": false,
            "tags": [
                "customer"
            ],
            "type": "managed_object"
        }
    }
}
```

#### Human Readable Output

>### Managed object list
>|id|name|tags|match_type|match_enabled|match|family|autodetected|
>|---|---|---|---|---|---|---|---|
>| 122 | TestMO1 | customer | cidr_blocks | true | 1.2.3.4/32 | customer | false |


### na-sightline-tms-group-list
***
Get a list of available TMS groups.


#### Base Command

`na-sightline-tms-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| extend_data | Whether to extend the results with all available data. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NASightline.TMSGroup.check_available_bw | Boolean | If true, ensures that all TMS appliances or Cisco ASR 9000 vDDoS Protection devices in a group use less than 90% of the allowed traffic rate in order for a mitigation to start. | 
| NASightline.TMSGroup.check_bgp_peering | Boolean | If true, ensures that the TMS appliances or Cisco ASR 9000 vDDoS Protection devices are part of a peering session. | 
| NASightline.TMSGroup.check_group_allup | Boolean | If true, requires all group members to be up before starting a mitigation. This ensures that sufficient resources are available before a mitigation starts. | 
| NASightline.TMSGroup.default_bgp_offramp | Boolean | If true, the default BGP diversion nexthops of the TMS appliances or Cisco ASR 9000 vDDoS Protection devices in the TMS group are used. | 
| NASightline.TMSGroup.description | String | Description of the TMS group. | 
| NASightline.TMSGroup.fail_open | Boolean | If true, ends the mitigation if one or more group members fails or becomes unreachable. | 
| NASightline.TMSGroup.flowspec_redirect_ipv4_destination | String | In TMS flowspec diversion deployments, these attributes each specify a destination route target or IP address. The Sightline peer uses these destinations in TMS mitigations to advertise routes to its BGP peers. | 
| NASightline.TMSGroup.flowspec_redirect_ipv4_type | String | In TMS flowspec diversion deployments, these attributes define whether the Sightline peer redirects TMS mitigation traffic to a route target or to an IP address. | 
| NASightline.TMSGroup.flowspec_redirect_ipv6_destination | String | In TMS flowspec diversion deployments, these attributes each specify a destination route target or IP address. The Sightline peer uses these destinations in TMS mitigations to advertise routes to its BGP peers. | 
| NASightline.TMSGroup.flowspec_redirect_ipv6_type | String | In TMS flowspec diversion deployments, these attributes define whether the Sightline peer redirects TMS mitigation traffic to a route target or to an IP address. | 
| NASightline.TMSGroup.id | String | The TMS group ID. | 
| NASightline.TMSGroup.l3vpn_flowspec_ipv4_route_distinguisher | String | The route distinguisher \(RD\) for a VPN, which uniquely identifies the routes for that VPN. | 
| NASightline.TMSGroup.l3vpn_flowspec_ipv6_route_distinguisher | String | The route distinguisher \(RD\) for a VPN, which uniquely identifies the routes for that VPN. | 
| NASightline.TMSGroup.member_limits_differ | Boolean | If true, TMS device limits \(such as maximum mitigations or filter lists\) differ, which leads to either performance issues if devices change midstream for ongoing mitigations, or failure to start or save mitigations. | 
| NASightline.TMSGroup.mitigation_orchestration.bandwidth_threshold_percent | Number | The percentage of total bandwidth capacity at which this TMS group will become overloaded. | 
| NASightline.TMSGroup.mitigation_orchestration.enabled | Boolean | If true, mitigation orchestration is enabled for this TMS group. | 
| NASightline.TMSGroup.name | String | TMS group name. | 
| NASightline.TMSGroup.nexthop | String | The IPv4 address for the BGP diversion nexthop. It overrides the default nexthops of the TMS appliances or Cisco ASR 9000 vDDoS Protection devices that are in the TMS group. | 
| NASightline.TMSGroup.nexthop_v6 | String | The IPv6 address for the BGP diversion nexthop. It overrides the default nexthops of the TMS appliances or Cisco ASR 9000 vDDoS Protection devices that are in the TMS group. | 
| NASightline.TMSGroup.relationships | Unknown | Relationships of the managed object \(only visible when extending the data\). | 
| NASightline.TMSGroup.system | Boolean | If true, the TMS group is pre-configured in Sightline and is not editable. | 
| NASightline.TMSGroup.tms_group_type | String | Type of the TMS group. | 
| NASightline.TMSGroup.type | String | Type of the returned object. | 


#### Command Example
```!na-sightline-tms-group-list limit=2```

#### Context Example
```json
{
    "NASightline": {
        "TMSGroup": [
            {
                "bgp_communities": [],
                "check_available_bw": true,
                "check_bgp_peering": true,
                "check_group_allup": true,
                "default_bgp_offramp": true,
                "description": "Default all mitigation group. Mitigations will use all ports on all configured TMS devices.",
                "dns_auth_active_secondary_servers": [],
                "fail_open": false,
                "flowspec_communities": [],
                "flowspec_offramp": "",
                "flowspec_redirect_ipv4_destination": "",
                "flowspec_redirect_ipv4_type": "",
                "flowspec_redirect_ipv6_destination": "",
                "flowspec_redirect_ipv6_type": "",
                "id": "3",
                "l3vpn_flowspec_ipv4_route_distinguisher": "",
                "l3vpn_flowspec_ipv4_route_targets": [],
                "l3vpn_flowspec_ipv6_route_distinguisher": "",
                "l3vpn_flowspec_ipv6_route_targets": [],
                "member_limits_differ": false,
                "mitigation_orchestration": {
                    "bandwidth_threshold_percent": 85,
                    "enabled": false
                },
                "name": "All",
                "nexthop": "",
                "nexthop_v6": "",
                "system": true,
                "tms_group_type": "",
                "type": "tms_group"
            },
            {
                "bgp_communities": [],
                "check_available_bw": true,
                "check_bgp_peering": true,
                "check_group_allup": true,
                "default_bgp_offramp": false,
                "description": "",
                "dns_auth_active_secondary_servers": [],
                "fail_open": true,
                "flowspec_communities": [],
                "flowspec_offramp": "",
                "flowspec_redirect_ipv4_destination": "",
                "flowspec_redirect_ipv4_type": "route_target",
                "flowspec_redirect_ipv6_destination": "",
                "flowspec_redirect_ipv6_type": "route_target",
                "id": "192",
                "l3vpn_flowspec_ipv4_route_distinguisher": "",
                "l3vpn_flowspec_ipv4_route_targets": [],
                "l3vpn_flowspec_ipv6_route_distinguisher": "",
                "l3vpn_flowspec_ipv6_route_targets": [],
                "member_limits_differ": false,
                "mitigation_orchestration": {
                    "bandwidth_threshold_percent": 85,
                    "enabled": false
                },
                "name": "anar_test",
                "nexthop": "",
                "nexthop_v6": "",
                "system": false,
                "tms_group_type": "",
                "type": "tms_group"
            }
        ]
    }
}
```

#### Human Readable Output

>### TMS group list
>|check_available_bw|check_bgp_peering|check_group_allup|default_bgp_offramp|description|fail_open|flowspec_redirect_ipv4_type|flowspec_redirect_ipv6_type|id|links|member_limits_differ|mitigation_orchestration|name|system|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | true | true | true | Default all mitigation group. Mitigations will use all ports on all configured TMS devices. | false |  |  | 3 | self: https://xsoar-example:57585/api/sp/v7/tms_groups/3 | false | bandwidth_threshold_percent: 85<br/>enabled: false | All | true | tms_group |
>| true | true | true | false |  | true | route_target | route_target | 192 | self: https://xsoar-example:57585/api/sp/v7/tms_groups/192 | false | bandwidth_threshold_percent: 85<br/>enabled: false | anar_test | false | tms_group |
