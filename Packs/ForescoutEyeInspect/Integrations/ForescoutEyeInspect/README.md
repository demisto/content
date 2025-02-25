## Forescout EyeInspect

Delivers flexible and scalable OT/ICS asset visibility.
This integration was integrated and tested with version 4.2.20 of Forescout EyeInspect.

## Configure Forescout EyeInspect in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Username |  | True |
| Password |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Maximum incidents per fetch | Default is 50. Maximum is 200. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, like 12 hours, 7 days) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### forescout-ei-host-list
***
Retrieves information about the hosts in the eyeInspect CC database.


#### Base Command

`forescout-ei-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
| last_seen | List only records with the last seen timestamp greater than or equal to the provided parameter. | Optional |
| id_min | Retrieve hosts that are equal to or greater than the specified ID. | Optional |
| ip | A comma-separated list of IP addresses. The command will filter the results from the returned page according to the provided values. | Optional |
| vlan_id | A comma-separated list of VLAN IDs. The command will filter the results from the returned page according to the provided values. | Optional |
| mac_address | A comma-separated list of MAC addresses. The command will filter the results from the returned page according to the provided values. | Optional |
| sensor_id | A comma-separated list of sensor IDs. The command will filter the results from the returned page according to the provided values. | Optional |
| sort_field | List records and sort them based on the specified field, as well as on the ID. Also, the command will filter the results from the returned page. Possible values are: ip_reuse_domain_id, ip_reuse_domain, address, ip, vlan, nested_address, mac_addresses, sorted_mac_addresses, real_mac_addresses, sorted_real_mac_addresses, observed_mac_addresses, sorted_observed_mac_addresses, mac_vendors, vendor_with_real_macs, vendor_with_observed_macs, sensor_ids, is_broadcast_ip, is_multicast_ip, is_public_ip, is_learnt_host, name, all_names, description, role, all_roles, vendor_model, all_vendors_models, os_version, client_proto_port_info, server_proto_port_info, first_seen, last_seen, labels, sorted_labels, purdue_level, criticality, firmware_version, hardware_version, serial_number, project, ip_type, monitored_networks, open_ports, complex_cves, sorted_client_protocols, sorted_server_protocols, module_count, sorted_module_details, security_risk, operational_risk, alert_count. | Optional |
| sort_ascending | Indicates whether the result list should be sorted in ascending or descending order. Possible values are: true, false. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.Host.id | Number | The unique ID of the host in the eyeInspect CC. |
| ForescoutEyeInspect.Host.ip_reuse_domain_id | Number | The unique ID of the IP Reuse Domain the host is in. |
| ForescoutEyeInspect.Host.ip | String | The IP address of the host. |
| ForescoutEyeInspect.Host.nested_address | String | In case of a nested device host, the nested address of the host. |
| ForescoutEyeInspect.Host.vlan | String | The VLAN ID of the host. |
| ForescoutEyeInspect.Host.mac_addresses | String | The MAC addresses associated to the host. |
| ForescoutEyeInspect.Host.sensor_ids | String | The unique IDs of the sensors that have "seen" this host. |
| ForescoutEyeInspect.Host.main_name | String | The main name of the host. |
| ForescoutEyeInspect.Host.description | String | Description of the host. |
| ForescoutEyeInspect.Host.os_version | String | The operating system version of the host. |
| ForescoutEyeInspect.Host.first_seen | String | The ISO-formatted timestamp of when the host was first seen. |
| ForescoutEyeInspect.Host.last_seen | String | The ISO-formatted timestamp of when the host was last seen. |
| ForescoutEyeInspect.Host.open_ports | String | The open TCP and UDP ports of the host. |

#### Command example
```!forescout-ei-host-list page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "Host": {
            "first_seen": "2022-03-18T00:58:27.000+01:00",
            "host_mac_addresses": [],
            "id": 34558,
            "ip": "20.190.159.71",
            "ip_reuse_domain_id": 1,
            "last_seen": "2022-03-18T00:58:27.000+01:00",
            "mac_addresses": [
                "C4:24:56:A4:86:11"
            ],
            "nested_address": "",
            "sensor_ids": [
                9
            ],
            "vlan": ""
        }
    }
}
```

#### Human Readable Output

>### Hosts List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|ID|IP|MAC Addresses|
>|---|---|---|
>| 34558 | 20.190.159.71 | C4:24:56:A4:86:11 |

### forescout-ei-link-list
***
Retrieves information about the links in the eyeInspect CC database.


#### Base Command

`forescout-ei-link-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
| src_host_id | List only records with the src_host_id property set to the specified value. | Optional |
| dst_host_id | List only records with the dst_host_id property set to the specified value. | Optional |
| proto | List only records with the proto field containing the specified value. | Optional |
| port | List only records with one of the values of the port property equal to the specified parameter. | Optional |
| last_seen | List only records with the last_seen timestamp greater than or equal to the provided parameter. | Optional |
| id_min | Retrieve links that are greater than or equal to the specified ID. | Optional |
| sort_field | List records and sort them based on the specified field, as well as on the ID. Possible values are: src_host_id, dst_host_id, proto, ports, tx_bytes, rx_bytes, first_seen, last_seen. | Optional |
| sort_ascending | Indicates whether the result list should be sorted in ascending or descending order. Possible values are: true, false. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.Link.id | Number | The unique ID of the link in the eyeInspect CC. |
| ForescoutEyeInspect.Link.src_host_id | Number | The unique ID of the source host in the eyeInspect CC. |
| ForescoutEyeInspect.Link.dst_host_id | Number | The unique ID of the destination host in the eyeInspect CC. |
| ForescoutEyeInspect.Link.proto | String | The name of the protocol \(application layer \(L7\) and transport or datalink layer \(L4 or L3/L2\) detected for the link. |
| ForescoutEyeInspect.Link.tx_bytes | Number | The total number of bytes sent upstream \(i. |
| ForescoutEyeInspect.Link.rx_bytes | Number | The total number of bytes sent downstream \(i. |
| ForescoutEyeInspect.Link.first_seen | String | Timestamp in ISO format of when the link was first seen. |
| ForescoutEyeInspect.Link.last_seen | String | Timestamp in ISO format of when the link was last seen. |
| ForescoutEyeInspect.Link.ports | String | TCP or UDP ports used in the link. |

#### Command example
```!forescout-ei-link-list page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "Link": {
            "dst_host_id": 34555,
            "first_seen": "2022-03-18T10:28:47.000+01:00",
            "id": 203725,
            "last_seen": "2022-03-18T10:28:56.000+01:00",
            "proto": "FailedConnection (TCP)",
            "src_host_id": 8
        }
    }
}
```

#### Human Readable Output

>### Host Links List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|ID|Source Host ID|Destination Host ID|Protocol|
>|---|---|---|---|
>| 203725 | 8 | 34555 | FailedConnection (TCP) |

### forescout-ei-vulnerability-info-get
***
Retrieves information about a specific vulnerability stored in the eyeInspect CC database.


#### Base Command

`forescout-ei-vulnerability-info-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | The unique ID of the vulnerability information record to be retrieved. The CVE ID can be retrieved from public vulnerability databases, such as NVD, or from the "CVEs and IoCs" page inside Forescout EyeInspect. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.CVE.id | String | The vulnerability ID. |
| ForescoutEyeInspect.CVE.cve_id | String | The CVE ID from the NVD. |
| ForescoutEyeInspect.CVE.icsa_id | String | The ICS Cert Security Advisory ID related to the vulnerability. |
| ForescoutEyeInspect.CVE.vendor_specific_id | String | The vendor-specific advisory ID related to the vulnerability. |
| ForescoutEyeInspect.CVE.published_date | String | The timestamp in ISO format when the vulnerability information was published. |
| ForescoutEyeInspect.CVE.last_modified_date | String | The timestamp in ISO format when the vulnerability information was last modified. |
| ForescoutEyeInspect.CVE.cvss_score | Number | The CVSS score of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_temporal_score | Number | The CVSS temporal score of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_access_vector | String | The CVSS access vector scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_access_complexity | String | The CVSS access complexity scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_authentication | String | The CVSS authentication scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_confidentiality_impact | String | The CVSS confidentiality impact scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_integrity_impact | String | The CVSS integrity impact scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_availability_impact | String | The CVSS availability impact scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_exploitability | String | The CVSS exploitability scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_remediation_level | String | The CVSS remediation level scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.cvss_reporting_confidence | String | The CVSS reporting confidence scoring of the vulnerability. |
| ForescoutEyeInspect.CVE.references | String | The list of references \(URLs\) related to the vulnerability. |
| ForescoutEyeInspect.CVE.vendor | String | The vendor of the product affected by the vulnerability. |
| ForescoutEyeInspect.CVE.title | String | A short summary of the vulnerability. |
| ForescoutEyeInspect.CVE.description | String | Description of the vulnerability \(including list of vulnerable devices and versions\). |
| ForescoutEyeInspect.CVE.solution | String | Description of the proposed vulnerability solution \(including to what version to update the software/firmware\). |

#### Command example
```!forescout-ei-vulnerability-info-get cve_id=CVE-2019-20218```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "CVE": {
            "cve_id": "CVE-2019-20218",
            "cvss_access_complexity": "LOW",
            "cvss_access_vector": "NETWORK",
            "cvss_authentication": "NONE",
            "cvss_availability_impact": "PARTIAL",
            "cvss_confidentiality_impact": "NONE",
            "cvss_exploitability": "UNDEFINED",
            "cvss_integrity_impact": "NONE",
            "cvss_remediation_level": "UNAVAILABLE",
            "cvss_reporting_confidence": "CONFIRMED",
            "cvss_score": 5,
            "cvss_temporal_score": 0,
            "cvss_version": "VERSION_2",
            "icsa_id": "",
            "id": "CVE-2019-20218",
            "last_modified_date": "2020-04-14T02:00:00.000+02:00",
            "published_date": "2018-11-27T01:00:00.000+01:00",
            "references": [
                {
                    "label": "Siemens CERT",
                    "url": "https://cert-portal.siemens.com/productcert/pdf/ssb-439005.pdf"
                }
            ],
            "solution": "Siemens is working on an update for the firmware, and recommends the following mitigations until an update is available:\n - Apply Defense-in-Depth: https://www.siemens.com/cert/operational-guidelines-industrial-security\n - Only build and run applications from trusted sources",
            "summary": "selectExpander in select.c in SQLite 3.30.1 proceeds with WITH stack unwinding even after a parsing error.\n VULNERABLE PRODUCT\n - SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP (incl. SIPLUS variant): firmware version V2.6.1, and might also affect previous versions of the firmware",
            "title": "Improper handling of exceptional conditions vulnerability in SQLite database in the SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP",
            "vendor": "Siemens",
            "vendor_specific_id": "SSB-439005"
        }
    }
}
```

#### Human Readable Output

>### CVE CVE-2019-20218 Information:
>|ID|Title|Published Date|Cvss Score|
>|---|---|---|---|
>| CVE-2019-20218 | Improper handling of exceptional conditions vulnerability in SQLite database in the SIMATIC S7-1500 CPU 1518(F)-4 PN/DP MFP | 2018-11-27T01:00:00.000+01:00 | 5.0 |

### forescout-ei-alert-list
***
Retrieves information about the alerts inside eyeInspect CC.


#### Base Command

`forescout-ei-alert-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
| start_timestamp | List only records with the timestamp property greater than or equal to the specified value. For example, 2020-05-26T15:00:00.000Z+01:00. | Optional |
| end_timestamp | List only records with the timestamp property less than or equal to the specified value. For example, 2020-05-26T15:00:00.000Z+01:00. | Optional |
| event_type_id | List records that have the event_type_id property containing the specified parameter. | Optional |
| l4_proto | List records that have the l4_proto property equal to the specified parameter. Possible values are: TCP, UDP, ICMP, UNDEFINED. | Optional |
| l7_proto | List records that have the l7_proto property equal to the specified parameter. | Optional |
| src_ip | List records that have the src_ip property equal to the specified parameter, or contained in the given CIDR-defined network. | Optional |
| dst_ip | List records that have the dst_ip property equal to the specified parameter, or contained in the given CIDR-defined network. | Optional |
| ip | List records that have either the src_ip or the dst_ip property equal to the specified parameter, or contained in the given CIDR-defined network. | Optional |
| severity | A comma-separated list of severities. The command will filter the results from the returned page according to the provided values. | Optional |
| vlan_id | A comma-separated list of vLAN IDs. The command will filter the results from the returned page according to the provided values. | Optional |
| status | A comma-separated list of statuses. The command will filter the results from the returned page according to the provided values. Possible values are: Not analysed, In progress, Analyzed, False alert, Relevant, Not relevant, Unknown, Trimmed. | Optional |
| sensor_name | A comma-separated list of sensor names. The command will filter the results from the returned page according to the provided values. | Optional |
| dst_port | Fetch records that have the dst_port property equal to the specified parameter. | Optional |
| src_host_id | List records that have the src_ip or src_mac property equal to the IP address or MAC address of the host with ID equal to the specified parameter. | Optional |
| dst_host_id | List records that have the dst_ip or dst_mac property equal to the IP address or MAC address of the host with ID equal to the specified parameter. | Optional |
| host_id | List records that have either the src_ip, src_mac or dst_ip, dst_mac equal to the IP address or MAC address of the host with ID equal to the specified parameter. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.Alert.alert_id | Number | The ID of the alert in the eyeInspect database. |
| ForescoutEyeInspect.Alert.timestamp | String | Timestamp of the alert in ISO format. |
| ForescoutEyeInspect.Alert.event_type_ids | String | The list of unique IDs identifying the type of events reported in the alert. |
| ForescoutEyeInspect.Alert.event_type_names | String | The list of names of the type of events reported in the alert. |
| ForescoutEyeInspect.Alert.description | String | A description of the event types reported in the alert, as well as other details regarding the specific alert instance coming from the sensor. |
| ForescoutEyeInspect.Alert.notes | String | Notes that a eyeInspect user may have attached to the alert. |
| ForescoutEyeInspect.Alert.sensor_id | Number | The unique ID of the sensor firing the Alert. |
| ForescoutEyeInspect.Alert.sensor_name | String | The name of the sensor firing the alert. |
| ForescoutEyeInspect.Alert.engine | String | The detection engine that raised the Alert. |
| ForescoutEyeInspect.Alert.profile_module_name | String | The name of the profile or module that raised the Alert. |
| ForescoutEyeInspect.Alert.profile_id | Number | The unique ID of the profile that raised the alert. |
| ForescoutEyeInspect.Alert.l2_proto | String | The layer 2 \(datalink\) protocol. |
| ForescoutEyeInspect.Alert.l3_proto | String | The layer 3 \(network\) protocol. |
| ForescoutEyeInspect.Alert.l4_proto | String | The layer 4 \(transport\) protocol. |
| ForescoutEyeInspect.Alert.l7_proto | String | The layer 7 \(application\) protocol. |
| ForescoutEyeInspect.Alert.vlan | String | The VLAN ID used in the network communication reported in the alert. |
| ForescoutEyeInspect.Alert.src_mac | String | The MAC address of the host initiating the connection reported in the alert. |
| ForescoutEyeInspect.Alert.dst_mac | String | The MAC address of the host receiving the connection reported in the alert. |
| ForescoutEyeInspect.Alert.src_ip | String | The IP address of the host initiating the connection reported in the alert. |
| ForescoutEyeInspect.Alert.dst_ip | String | The IP address of the host receiving the connection reported in the alert. |
| ForescoutEyeInspect.Alert.src_port | Number | The source TCP or UDP port used in the connection reported in the alert. |
| ForescoutEyeInspect.Alert.dst_port | Number | The destination TCP or UDP port used in the connection reported in the alert. |
| ForescoutEyeInspect.Alert.severity | Number | The severity level of the alert. |
| ForescoutEyeInspect.Alert.status | String | The status of the alert. |

#### Command example
```!forescout-ei-alert-list page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "Alert": {
            "alert_id": 1,
            "case_id": 0,
            "case_name": "",
            "description": "TCP portscan: the attacker sends multiple out-of-state ACK packets to scan the victim's hosts and determine the open ports. This might be intelligence gathering or (the first phase of) an attack (e.g., DoS, exploit)\n\nFailed connections:\n - (scanner) 213.8.143.143  \n    - 192.168.92.12  \n        * 54009 (    1 failed connection(s) [ ACK: 1 ] )\n        * 54010 (    1 failed connection(s) [ ACK: 1 ] )\n        * 54011 (    1 failed connection(s) [ ACK: 1 ] )\n        * 54013 (    1 failed connection(s) [ ACK: 1 ] )\n        * 54017 (    1 failed connection(s) [ ACK: 1 ] )\n",
            "direction_certain": false,
            "dst_ip": "192.168.92.12",
            "dst_mac": "",
            "dst_port": 0,
            "engine": "PORTSCAN",
            "event_type_ids": [
                "ps_tcp_ack"
            ],
            "event_type_names": [
                "TCP ACK portscan"
            ],
            "fea_alert_count": 0,
            "fea_duration_sec": 0,
            "fea_start": "1970-01-01T01:00:00.000+01:00",
            "fea_state": "None",
            "hotstart": false,
            "l2_proto": "ETHERNET",
            "l3_proto": "IP",
            "l4_proto": "TCP",
            "l7_proto": "UNDEFINED",
            "labels": "",
            "link": "https://192.168.30.115/evt?id=1",
            "normalized": false,
            "notes": "",
            "profile_id": 0,
            "profile_module_name": "Portscan",
            "sensor_id": 9,
            "sensor_name": "Test1",
            "severity": 2,
            "src_ip": "213.8.143.143",
            "src_mac": "",
            "src_port": 0,
            "status": "Not analyzed",
            "timestamp": "2022-02-03T07:49:50.092+01:00",
            "vlan": "",
            "xsoar_severity": 1
        }
    }
}
```

#### Human Readable Output

>### Alerts List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Alert ID|Description|Timestamp|Source IP|Destination IP|
>|---|---|---|---|---|
>| 1 | TCP portscan: the attacker sends multiple out-of-state ACK packets to scan the victim's hosts and determine the open ports. This might be intelligence gathering or (the first phase of) an attack (e.g., DoS, exploit)<br/><br/>Failed connections:<br/> - (scanner) 213.8.143.143  <br/>    - 192.168.92.12  <br/>        * 54009 (    1 failed connection(s) [ ACK: 1 ] )<br/>        * 54010 (    1 failed connection(s) [ ACK: 1 ] )<br/>        * 54011 (    1 failed connection(s) [ ACK: 1 ] )<br/>        * 54013 (    1 failed connection(s) [ ACK: 1 ] )<br/>        * 54017 (    1 failed connection(s) [ ACK: 1 ] )<br/> | 2022-02-03T07:49:50.092+01:00 | 213.8.143.143 | 192.168.92.12 |

### forescout-ei-alert-pcap-get
***
Retrieves the PCAP file associated to a given alert.


#### Base Command

`forescout-ei-alert-pcap-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The unique ID of the alert to get the PCAP of. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Size | Number | The size of the file. |
| InfoFile.Name | String | The name of the file. |
| InfoFile.EntryID | String | The entry ID of the file. |
| InfoFile.Info | String | File information. |
| InfoFile.Type | String | The file type. |
| InfoFile.Extension | String | The file extension. |

#### Command example
```!forescout-ei-alert-pcap-get alert_id=1```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "3111@8479e914-8493-4968-8f32-78852375d17b",
        "Extension": "pcap",
        "Info": "application/vnd.tcpdump.pcap",
        "Name": "alert_1_sniff.pcap",
        "Size": 424,
        "Type": "tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 65535)"
    }
}
```

#### Human Readable Output



### forescout-ei-sensor-list
***
Retrieves information about the sensors associated to the eyeInspect CC.


#### Base Command

`forescout-ei-sensor-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
| all_sensors | Whether to retrieve all the sensors (ICS Patrol and passive) or only the passive ones. Possible values are: true, false. | Optional |
| name | A comma-separated list of sensor names. The command will filter the results from the returned page according to the provided values. | Optional |
| address | A comma-separated list of IP addresses or domain names. The command will filter the results from the returned page according to the provided values. | Optional |
| port | A comma-separated list of listening ports. The command will filter the results from the returned page according to the provided values. | Optional |
| type | A comma-separated list of sensor types. The command will filter the results according to the provided values. Possible values are: PASSIVE, PATROL. | Optional |
| state | A comma-separated list of sensor states. The command will filter the results from the returned page according to the provided values. Possible values are: OPERATIVE_ON, OPERATIVE_OFF, DISCONNECTED, LICENSE_EXPIRED, LICENSE_INVALID, UNKNOWN. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.Sensor.id | Number | Unique ID of the sensor in the eyeInspect CC. |
| ForescoutEyeInspect.Sensor.name | String | Name of the sensor. |
| ForescoutEyeInspect.Sensor.address | String | IP address or domain name of the sensor's management interface. |
| ForescoutEyeInspect.Sensor.port | Number | TCP port number on which the sensor is listening for incoming CC connections. |
| ForescoutEyeInspect.Sensor.type | String | Type of the sensor \(PASSIVE / PATROL\). |
| ForescoutEyeInspect.Sensor.sensor_version | String | Version of the eyeInspect sensor software. |
| ForescoutEyeInspect.Sensor.state | String | Current status of the sensor. |
| ForescoutEyeInspect.Sensor.health_status | String | Current health status of the sensor. |

#### Command example
```!forescout-ei-sensor-list page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "Sensor": {
            "address": "127.0.0.1",
            "health_status": {
                "cpu_load_avg_1_min": {
                    "current_value": "8.5%",
                    "level": "NORMAL",
                    "name": ""
                },
                "disk_usage": [
                    {
                        "current_value": "8%",
                        "level": "NORMAL",
                        "name": "/"
                    }
                ],
                "dropped_packets": {
                    "current_value": "0%",
                    "level": "NORMAL",
                    "name": ""
                },
                "license_status": {
                    "current_value": "VALID",
                    "level": "NORMAL",
                    "name": ""
                },
                "memory_usage": {
                    "current_value": "84.62%",
                    "level": "WARNING",
                    "name": ""
                },
                "net_if_status": [
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "br-1b1f2d7e6a87"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "ens160"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "ens192"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "veth24fab08"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "vethf0fd758"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "vethfb6c608"
                    }
                ],
                "services": [],
                "throughput": {
                    "current_value": "0.0 bps",
                    "level": "CRITICAL",
                    "name": ""
                }
            },
            "id": 2,
            "name": "sensor1",
            "port": 9999,
            "sensor_version": "4.3.21",
            "state": "OPERATIVE_ON",
            "type": "PASSIVE"
        }
    }
}
```

#### Human Readable Output

>### Sensors List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|ID|Name|Address|Port|Type|
>|---|---|---|---|---|
>| 2 | sensor1 | 127.0.0.1 | 9999 | PASSIVE |

### forescout-ei-sensor-module-list
***
Retrieves information about the modules of the specified sensor.


#### Base Command

`forescout-ei-sensor-module-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor to query for modules. | Required |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.SensorModule.id | Number | Unique ID of the module in the eyeInspect CC. |
| ForescoutEyeInspect.SensorModule.sensor_id | Number | Unique ID of the sensor the module is deployed in, in the eyeInspect CC. |
| ForescoutEyeInspect.SensorModule.engine | String | Name of the engine powering the module in the sensor. |
| ForescoutEyeInspect.SensorModule.singleton | Boolean | Whether the module can only have one single instance or can have multiple instances in the sensor. |
| ForescoutEyeInspect.SensorModule.name | String | The name of the module. |
| ForescoutEyeInspect.SensorModule.description | String | The description of the module. |
| ForescoutEyeInspect.SensorModule.started | Boolean | Whether the module is started or paused in the sensor. |
| ForescoutEyeInspect.SensorModule.operational_mode | String | Operational mode of the module in the sensor. |
| ForescoutEyeInspect.SensorModule.date_last_update | String | Timestamp in ISO format of when the module was last updated. |

#### Command example
```!forescout-ei-sensor-module-list sensor_id=2 page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "SensorModule": {
            "date_last_update": "2022-03-18T11:13:09.898+01:00",
            "description": "",
            "engine": "THREAT_LIBRARY",
            "id": 1,
            "name": "Industrial threat library (ITL)",
            "operational_mode": "",
            "sensor_id": 2,
            "singleton": true,
            "started": true
        }
    }
}
```

#### Human Readable Output

>### Sensor 2 Modules List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|ID|Name|Engine|Started|
>|---|---|---|---|
>| 1 | Industrial threat library (ITL) | THREAT_LIBRARY | true |

### forescout-ei-sensor-module-update
***
Changes the specified properties of the specified module.


#### Base Command

`forescout-ei-sensor-module-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor that has the module to update. | Required |
| module_id | The unique ID of the module to update. | Required |
| name | Name of the module. | Optional |
| description | Description of the module. | Optional |
| started | If set to true, the module will be started. If set to false, the module will be paused. Possible values are: true, false. | Optional |
| operational_mode | Changes the operational mode of the module to the specified value. Possible values are: Learning, Detecting. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.SensorModule.id | Number | Unique ID of the module in the eyeInspect CC. |
| ForescoutEyeInspect.SensorModule.sensor_id | Number | Unique ID of the sensor the module is deployed in, in the eyeInspect CC. |
| ForescoutEyeInspect.SensorModule.engine | String | Name of the engine powering the module in the sensor. |
| ForescoutEyeInspect.SensorModule.singleton | Boolean | Whether the module can only have one single instance or can have multiple instances in the sensor. |
| ForescoutEyeInspect.SensorModule.name | String | The name of the module. |
| ForescoutEyeInspect.SensorModule.description | String | The description of the module. |
| ForescoutEyeInspect.SensorModule.started | Boolean | Whether the module is started or paused in the sensor. |
| ForescoutEyeInspect.SensorModule.operational_mode | String | Operational mode of the module in the sensor. |
| ForescoutEyeInspect.SensorModule.date_last_update | String | Timestamp in ISO format of when the module was last updated. |

#### Command example
```!forescout-ei-sensor-module-update sensor_id=2 module_id=5 started=true```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "SensorModule": {
            "date_last_update": "1970-01-01T01:00:00.000+01:00",
            "description": "",
            "engine": "PORTSCAN",
            "id": 5,
            "name": "Portscan",
            "operational_mode": "",
            "sensor_id": 2,
            "singleton": true,
            "started": true
        }
    }
}
```

#### Human Readable Output

>### Updated Module 5 of Sensor 2:
>|Name|Engine|Started|
>|---|---|---|
>| Portscan | PORTSCAN | true |

### forescout-ei-sensor-module-delete
***
Deletes the specified module from the specified sensor and from the eyeInspect CC database.


#### Base Command

`forescout-ei-sensor-module-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor of the module to delete. | Required |
| module_id | The unique ID of the module to delete. | Required |


#### Context Output

There is no context output for this command.

#### Command example
```!forescout-ei-sensor-module-delete sensor_id=2 module_id=8```
#### Human Readable Output
>## The module 8 of sensor 2 was successfully deleted!
### forescout-ei-ip-blacklist-get
***
Retrieves the IP blacklist from the Industrial Threat Library of the specified sensor.
#### Base Command
`forescout-ei-ip-blacklist-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor for which to retrieve the IP blacklist. | Required |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.IPBlacklist.address | String | A blacklisted IP address. |
| ForescoutEyeInspect.IPBlacklist.comment | String | A comment provided by the user. The comment might be empty. |
#### Command example
```!forescout-ei-ip-blacklist-get sensor_id=2 page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "IPBlacklist": {
            "address": "1.1.1.5",
            "comment": "demo test",
            "sensor_id": 2
        }
    }
}
```

#### Human Readable Output

>### IP Blacklist of Sensor 2:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Address|Comment|
>|---|---|
>| 1.1.1.5 | demo test |

### forescout-ei-ip-blacklist-add
***
Adds a new entry to the IP blacklist from the Industrial Threat Library of the specified sensor.


#### Base Command

`forescout-ei-ip-blacklist-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor for which to update the IP blacklist. | Required |
| address | The IP address to add to the blacklist. | Required |
| comment | A comment about the blacklisted IP address. | Optional |


#### Context Output

There is no context output for this command.

#### Command example
```!forescout-ei-ip-blacklist-add sensor_id=2 address=3.4.5.6 comment=Malicious```
#### Human Readable Output
>### New IP Blacklist Entry of Sensor 2:
>|Address|Comment|
>|---|---|
>| 3.4.5.6 | Malicious |
### forescout-ei-domain-blacklist-get
***
Retrieves the domain name blacklist from the Industrial Threat Library of the specified sensor.
#### Base Command
`forescout-ei-domain-blacklist-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor that contains the domain blacklist. | Required |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.DomainBlacklist.domain_name | String | A blacklisted domain name. |
| ForescoutEyeInspect.DomainBlacklist.comment | String | A comment provided by the user. The comment might be empty. |
#### Command example
```!forescout-ei-domain-blacklist-get sensor_id=2 page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "DomainBlacklist": {
            "comment": "demo command",
            "domain_name": "028xmz.com",
            "sensor_id": 2
        }
    }
}
```

#### Human Readable Output

>### Domain Blacklist of Sensor 2:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Domain Name|Comment|
>|---|---|
>| 028xmz.com | demo command |

### forescout-ei-domain-blacklist-add
***
Adds a new entry to the domain name blacklist from the Industrial Threat Library of the specified sensor.


#### Base Command

`forescout-ei-domain-blacklist-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor of which the domain to be updated. | Required |
| domain_name | The domain name to add to the blacklist. | Required |
| comment | A comment about the domain name. Default is Command and Control server. | Optional |


#### Context Output

There is no context output for this command.

#### Command example
```!forescout-ei-domain-blacklist-add sensor_id=2 domain_name=malicious.xyz comment=Maleware```
#### Human Readable Output
>### New Domain Blacklist Entry of Sensor 2
>|Domain Name|Comment|
>|---|---|
>| malicious.xyz | Maleware |
### forescout-ei-ssl-client-blacklist-get
***
Retrieves the SSL client application blacklist from the Industrial Threat Library of the specified sensor.
#### Base Command
`forescout-ei-ssl-client-blacklist-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor for which to retrieve the SSL client blacklist. | Required |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.SSLClientBlacklist.sensor_id | Number | The unique ID of the sensor for which to retrieve the SSL client. |
| ForescoutEyeInspect.SSLClientBlacklist.application_name | String | The application name related to the entry. |
| ForescoutEyeInspect.SSLClientBlacklist.ja3_hash | String | The JA3 hash of a blacklisted client application. |
| ForescoutEyeInspect.SSLClientBlacklist.comment | String | A comment provided by the user. The comment might be empty. |
#### Command example
```!forescout-ei-ssl-client-blacklist-get sensor_id=2 page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "SSLClientBlacklist": {
            "application_name": "Potential malware: eitest-hoeflertext-chrome-popup-traffic-4-of-6",
            "comment": "Generated from all PCAPs on https://www.malware-traffic-analysis.net",
            "ja3_hash": "098f55e27d8c4b0a590102cbdb3a5f3a",
            "sensor_id": 2
        }
    }
}
```

#### Human Readable Output

>### SSL Client Applications Blacklist of Sensor 2:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Application Name|Ja3 Hash|Comment|
>|---|---|---|
>| Potential malware: eitest-hoeflertext-chrome-popup-traffic-4-of-6 | 098f55e27d8c4b0a590102cbdb3a5f3a | Generated from all PCAPs on https:<span>//</span>www.malware-traffic-analysis.net |

### forescout-ei-ssl-client-blacklist-add
***
Adds a new entry to the SSL client application blacklist from the Industrial Threat Library of the specified sensor.


#### Base Command

`forescout-ei-ssl-client-blacklist-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor of which the SSL client. | Required |
| application_name | The related application name to add to the blacklist. | Required |
| ja3_hash | The JA3 hash of a blacklisted client application. | Required |
| comment | Comment about the SSL client application. | Optional |


#### Context Output

There is no context output for this command.

#### Command example
```!forescout-ei-ssl-client-blacklist-add sensor_id=2 application_name=Shodan ja3_hash=0ad94fcb7d3a2c56679fbd004f6b12cd comment=Malicious```
#### Human Readable Output
>### New SSL Client Blacklist Entry of Sensor 2:
>|Application Name|Ja3 Hash|Comment|
>|---|---|---|
>| Shodan | 0ad94fcb7d3a2c56679fbd004f6b12cd | Malicious |
### forescout-ei-file-operation-blacklist-get
***
Retrieves the file operation blacklist from the Industrial Threat Library of the specified sensor.
#### Base Command
`forescout-ei-file-operation-blacklist-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor for which to retrieve the file operation blacklist. | Required |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.FileOperationBlacklist.matching_type | String | The way file or folder should be matched. |
| ForescoutEyeInspect.FileOperationBlacklist.file_or_folder | String | The name of the file or folder the entry applies to. |
| ForescoutEyeInspect.FileOperationBlacklist.operation | String | The name of the file operation. |
| ForescoutEyeInspect.FileOperationBlacklist.comment | String | A comment provided by the user. The comment might be empty. |
#### Command example
```!forescout-ei-file-operation-blacklist-get sensor_id=2 page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "FileOperationBlacklist": {
            "comment": "Access 2007 Database File. A database file created with Microsoft Access 2007 or later. It typically contains data organized into tables and fields. (default blacklist entry).",
            "file_or_folder": "\\.accdb$",
            "matching_type": "REGEX",
            "operation": "WRITE",
            "sensor_id": 2
        }
    }
}
```

#### Human Readable Output

>### File Operation Blacklist of Sensor 2:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Matching Type|File Or Folder|Operation|Comment|
>|---|---|---|---|
>| REGEX | \.accdb$ | WRITE | Access 2007 Database File. A database file created with Microsoft Access 2007 or later. It typically contains data organized into tables and fields. (default blacklist entry). |

### forescout-ei-file-operation-blacklist-add
***
Adds entries to the file operation blacklist from the Industrial Threat Library of the specified sensor.


#### Base Command

`forescout-ei-file-operation-blacklist-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The unique ID of the sensor for which to update the file operation blacklist. | Required |
| matching_type | The way file or folder should be matched. Possible values are: CONTAINS, STARTS_WITH, ENDS_WITH, MATCHES, REGEX. | Required |
| file_or_folder | The name of the file or folder the entry applies to. | Required |
| operation | The name of the file operation. Possible values are: WRITE, READWRITE. | Required |
| comment | A comment provided by the user. | Optional |


#### Context Output

There is no context output for this command.

#### Command example
```!forescout-ei-file-operation-blacklist-add sensor_id=2 matching_type=REGEX file_or_folder=\\.mal$ operation=WRITE comment=Virus```
#### Human Readable Output
>### New File Operation Blacklist Entry of Sensor 2:
>|Matching Type|File Or Folder|Operation|Comment|
>|---|---|---|---|
>| REGEX | \.mal$ | WRITE | Virus |
### forescout-ei-diagnostics-information-get
***
Retrieves information about all monitored Command Center resources and their health status excluding the logs.
#### Base Command
`forescout-ei-diagnostics-information-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.CCInfo.ip_address | String | IP address of the Command Center. |
| ForescoutEyeInspect.CCInfo.hostname | String | Hostname of the Command Center. |
| ForescoutEyeInspect.CCInfo.open_ports | String | TCP open port number of the Command Center. |
| ForescoutEyeInspect.CCInfo.cc_version | String | Version of the Command Center software. |
| ForescoutEyeInspect.CCInfo.health_status | String | Current health status of the Command Center. |
#### Command example
```!forescout-ei-diagnostics-information-get```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "CCInfo": {
            "cc_version": "4.3.21",
            "health_status": {
                "analytics_db_used_mem": {
                    "current_value": "4.3 GiB",
                    "name": ""
                },
                "cpu_load_avg_1_min": {
                    "current_value": "5.5%",
                    "level": "NORMAL",
                    "name": ""
                },
                "disk_usage": [
                    {
                        "current_value": "8%",
                        "level": "NORMAL",
                        "name": "/"
                    }
                ],
                "memory_usage": {
                    "current_value": "84.56%",
                    "level": "WARNING",
                    "name": ""
                },
                "message_queue_used_mem": {
                    "current_value": "602.4 MiB",
                    "name": ""
                },
                "net_if_status": [
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "ens160"
                    },
                    {
                        "current_value": "Not running",
                        "level": "NORMAL",
                        "name": "docker0"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "br-1b1f2d7e6a87"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "ens192"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "vethf0fd758"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "veth24fab08"
                    },
                    {
                        "current_value": "Running",
                        "level": "NORMAL",
                        "name": "vethfb6c608"
                    }
                ],
                "relational_db_used_mem": {
                    "current_value": "3.4 GiB",
                    "name": "silentdefense"
                },
                "web_server_used_mem": {
                    "current_value": "4.4 GiB",
                    "name": ""
                }
            },
            "hostname": "4321-bundle-16g",
            "ip_address": "192.168.30.115",
            "open_ports": [
                "443"
            ]
        }
    }
}
```

#### Human Readable Output

>### Command Center Diagnostics Information:
>|IP Address|Hostname|Open Ports|Cc Version|
>|---|---|---|---|
>| 192.168.30.115 | 4321-bundle-16g | 443 | 4.3.21 |

### forescout-ei-diagnostic-logs-get
***
Download the ZIP file which contains diagnostic logs of the Command Center.


#### Base Command

`forescout-ei-diagnostic-logs-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cc_info | Whether to include Command Center diagnostic logs inside the downloaded zip, in addition to sensors logs. If this value is false, the downloaded zip won't contain the general server logs, but only the logs about the sensors. Possible values are: true, false. Default is True. | Optional |
| sensor_id | Include logs from a specific sensor by its ID, or all sensors (by specifying All). | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Size | Number | The size of the file. |
| InfoFile.Name | String | The name of the file. |
| InfoFile.EntryID | String | The entry ID of the file. |
| InfoFile.Info | String | File information. |
| InfoFile.Type | String | The file type. |
| InfoFile.Extension | String | The file extension. |

#### Command example
```!forescout-ei-diagnostic-logs-get sensor_id=2```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "3167@8479e914-8493-4968-8f32-78852375d17b",
        "Extension": "zip",
        "Info": "application/zip",
        "Name": "command_center_diagnostic_logs.zip",
        "Size": 26280500,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output



### forescout-ei-group-policy-list
***
Get all group policies.


#### Base Command

`forescout-ei-group-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.GroupPolicy.id | Number | The ID of the policy. |
| ForescoutEyeInspect.GroupPolicy.name | String | The name of the group policy. |
| ForescoutEyeInspect.GroupPolicy.description | String | The description of the group policy. |
| ForescoutEyeInspect.GroupPolicy.constraints | Unknown | List of constraints of the policy. |

#### Command example
```!forescout-ei-group-policy-list page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "GroupPolicy": {
            "constraints": [
                {
                    "operator": "equals",
                    "os_version": "Windows 10",
                    "type": "os_version"
                }
            ],
            "description": "Test",
            "id": 8,
            "name": "Test Playbook Policy"
        }
    }
}
```

#### Human Readable Output

>### Group Policies List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|ID|Name|Description|
>|---|---|---|
>| 8 | Test Playbook Policy | Test |

### forescout-ei-group-policy-create
***
Create a new group policy.


#### Base Command

`forescout-ei-group-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the group policy. | Required |
| description | The description of the group policy. | Required |
| constraints | List of constraints of the policy.<br/><br/>Each policy constraint is an object that includes the following fields:<br/>* type: The type of the constraint. Possible values are os_version, firmware_version, open_ports.<br/>* operator: The operator of the constraint. Possible values are equals (all types), allowed (open_ports) and contains (os_version, firmware_version).<br/>* os_version: The value of the OS version for the os_version type.<br/>* firmware_version: The value of the firmware version for the firmware_version type.<br/>* open_ports_tcp: Comma-separated list of ports or range of ports for the open_ports type. Example: "10, 20-30".<br/>* open_ports_udp: Comma-separated list of ports or range of ports for the open_ports type. Example: "10, 20-30".<br/><br/>Example for list of policy constraints: [{ "type": "os_version", "operator": "contains", "os_version": "Windows" }]. . | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.GroupPolicy.id | Number | The ID of the policy. |
| ForescoutEyeInspect.GroupPolicy.name | String | The name of the group policy. |
| ForescoutEyeInspect.GroupPolicy.description | String | The description of the group policy. |
| ForescoutEyeInspect.GroupPolicy.constraints | Unknown | List of constraints of the policy. |

#### Command example
```!forescout-ei-group-policy-create name="example policy" description="policy" constraints="[{\"type\": \"os_version\", \"operator\": \"equals\", \"os_version\": \"Windows 10\"}]"```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "GroupPolicy": {
            "constraints": [
                {
                    "operator": "equals",
                    "os_version": "Windows 10",
                    "type": "os_version"
                }
            ],
            "description": "policy",
            "id": 20,
            "name": "example policy"
        }
    }
}
```

#### Human Readable Output

>### Group Policy Information:
>|ID|Name|Description|
>|---|---|---|
>| 20 | example policy | policy |
>### Group Policy Constraints:
>|Type|Operator|Os Version|
>|---|---|---|
>| os_version | equals | Windows 10 |

### forescout-ei-group-policy-update
***
Update a group policy. Note: the whole policy will be overridden, therefore all fields are required.


#### Base Command

`forescout-ei-group-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique ID of the policy to be updated. | Required |
| name | The name of the group policy. | Required |
| description | The description of the group policy. | Required |
| constraints | List of constraints of the policy.<br/><br/>Each policy constraint is an object that includes the following fields:<br/>* type: The type of the constraint. Possible values are os_version, firmware_version, open_ports.<br/>* operator: The operator of the constraint. Possible values are equals (all types), allowed (open_ports) and contains (os_version, firmware_version).<br/>* os_version: The value of the OS version for the os_version type.<br/>* firmware_version: The value of the firmware version for the firmware_version type.<br/>* open_ports_tcp: Comma-separated list of ports or range of ports for the open_ports type. Example: "10, 20-30".<br/>* open_ports_udp: Comma-separated list of ports or range of ports for the open_ports type. Example: "10, 20-30".<br/><br/>Example for list of policy constraints: [{ "type": "os_version", "operator": "contains", "os_version": "Windows" }]. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.GroupPolicy.id | Number | The ID of the policy. |
| ForescoutEyeInspect.GroupPolicy.name | String | The name of the group policy. |
| ForescoutEyeInspect.GroupPolicy.description | String | The description of the group policy. |
| ForescoutEyeInspect.GroupPolicy.constraints | Unknown | List of constraints of the policy. |

#### Command example
```!forescout-ei-group-policy-update policy_id=20 name="example policy" description="policy" constraints="[{\"type\": \"os_version\", \"operator\": \"equals\", \"os_version\": \"Windows 10\"}]"```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "GroupPolicy": {
            "constraints": [
                {
                    "operator": "equals",
                    "os_version": "Windows 10",
                    "type": "os_version"
                }
            ],
            "description": "policy",
            "id": 20,
            "name": "example policy"
        }
    }
}
```

#### Human Readable Output

>### Updated Group Policy:
>|ID|Name|Description|
>|---|---|---|
>| 20 | example policy | policy |
>### Group Policy Constraints:
>|Type|Operator|Os Version|
>|---|---|---|
>| os_version | equals | Windows 10 |

### forescout-ei-group-policy-delete
***
Delete a group policy.


#### Base Command

`forescout-ei-group-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique ID of the policy for which the hosts will be added to. | Required |


#### Context Output

There is no context output for this command.
#### Command example
```!forescout-ei-group-policy-delete policy_id=20```
#### Human Readable Output
>## The group policy 20 was successfully deleted!
### forescout-ei-group-policy-hosts-assign
***
Add all hosts not assigned to any policy (individual or group) matching the filter to the group policy.
#### Base Command
`forescout-ei-group-policy-hosts-assign`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique ID of the policy for which the hosts will be added to. | Required |
| filter_type | The type of the filter. Possible values are: address, host_mac_address_exact, vendor_model, os_version, firmware_version, ip_reuse_domain. | Required |
| filter_value | The value of the filter. | Required |
#### Context Output
There is no context output for this command.
#### Command example
```!forescout-ei-group-policy-hosts-assign policy_id=20 filter_type=address filter_value=192.168.1.1```
#### Human Readable Output
>## 1 Additional Hosts Were Assigned to Group Policy 20!
### forescout-ei-group-policy-hosts-unassign
***
Unassign all hosts assigned to the group policy matching the filter.
#### Base Command
`forescout-ei-group-policy-hosts-unassign`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The unique ID of the policy for which the hosts will be removed. | Required |
| filter_type | The type of the filter. Possible values are: address, host_mac_address_exact, vendor_model, os_version, firmware_version, ip_reuse_domain. | Required |
| filter_value | The value of the filter. | Required |
#### Context Output
There is no context output for this command.
#### Command example
```!forescout-ei-group-policy-hosts-unassign policy_id=20 filter_type=address filter_value=192.168.1.1```
#### Human Readable Output
>## 1 Additional Hosts Were Unassigned from Group Policy 20!
### forescout-ei-ip-reuse-domain-list
***
Get all IP reuse domains.
#### Base Command
`forescout-ei-ip-reuse-domain-list`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.IPReuseDomain.id | Number | The ID of the IP reuse domain. |
| ForescoutEyeInspect.IPReuseDomain.name | String | The name of the IP reuse domain. |
| ForescoutEyeInspect.IPReuseDomain.description | String | The description of the IP reuse domain. |
| ForescoutEyeInspect.IPReuseDomain.address | String | The address of the IP reuse domain. |
| ForescoutEyeInspect.IPReuseDomain.mask | Number | The number of bits in the mask. |
| ForescoutEyeInspect.IPReuseDomain.vlan_ids | String | VLAN IDs of the IP reuse domain. |
#### Command example
```!forescout-ei-ip-reuse-domain-list page=2 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "IPReuseDomain": {
            "address": "192.168.99.0",
            "description": "Servers IP Reuse",
            "id": 2,
            "mask": 0,
            "name": "servers",
            "vlan_ids": "any"
        }
    }
}
```

#### Human Readable Output

>### IP Reuse Domains List:
> Current page size: 1
> Showing page 2 out of others that may exist.
>|ID|Name|Description|Address|
>|---|---|---|---|
>| 2 | servers | Servers IP Reuse | 192.168.99.0 |

### forescout-ei-hosts-changelog-list
***
Retrieves information about the changes of host properties and configuration from the eyeInspect CC database.


#### Base Command

`forescout-ei-hosts-changelog-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve (minimum is 1). Default is 1. | Optional |
| limit | Maximum number of records to retrieve. Default is 50. | Optional |
| host_id | List only records with the host_id property equal to the provided parameter. | Optional |
| start_timestamp | List only records with the timestamp property greater than or equal to the specified value. For example, 2020-05-26T15:00:00.000Z+01:00. | Optional |
| end_timestamp | List only records with the timestamp property less than or equal to the specified value. 2020-05-26T15:00:00.000Z+01:00. | Optional |
| event_type_id | List only records with the event_type_id property equal to the specified value. Possible values are: hostcl_new_host, hostcl_new_mac, hostcl_new_name, hostcl_new_role, hostcl_new_vendor_model, hostcl_new_os_version, hostcl_changed_os_version, hostcl_new_client_proto, hostcl_new_client_port, hostcl_new_server_proto, hostcl_new_server_port, hostcl_new_label, hostcl_new_fw_version, hostcl_changed_fw_version, hostcl_new_hw_version, hostcl_changed_hw_version, hostcl_changed_serial, hostcl_new_project, hostcl_changed_project, hostcl_new_module, hostcl_changed_module_name, hostcl_changed_module_type, hostcl_changed_module_vendor. | Optional |
| event_category | List only records with the event_type_id property equal to the specified value. Possible values are: PROPERTIES, CONFIGURATION, ALL. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForescoutEyeInspect.HostChangeLog.id | Number | The unique ID of the HostChangeLog in the eyeInspect CC. |
| ForescoutEyeInspect.HostChangeLog.timestamp | String | Timestamp in ISO format of when the host change was detected. |
| ForescoutEyeInspect.HostChangeLog.event_type_id | String | An identifier of the type of change detected. |
| ForescoutEyeInspect.HostChangeLog.event_type_name | String | A more human readable representation of the type of change detected. |
| ForescoutEyeInspect.HostChangeLog.event_category | String | A more general type of the change detected. |
| ForescoutEyeInspect.HostChangeLog.host_id | Number | The unique ID of the host in the eyeInspect CC database in which the change was detected. |
| ForescoutEyeInspect.HostChangeLog.information_source | String | The source of information for the detected change. |
| ForescoutEyeInspect.HostChangeLog.sensor_id | Number | In case the detected change was reported from a sensor, the unique ID in the eyeInspect CC database of the sensor reporting the information. |
| ForescoutEyeInspect.HostChangeLog.sensor_id | Number | In case the detected change was reported from a sensor, the unique ID in the eyeInspect CC database of the sensor reporting the information. |
| ForescoutEyeInspect.HostChangeLog.username | String | In case the detected change was reported from a eyeInspect user, the username of the user reporting the information. |
| ForescoutEyeInspect.HostChangeLog.old_value | String | The old value of the host property. |
| ForescoutEyeInspect.HostChangeLog.new_value | String | The new value of the host property. |
| ForescoutEyeInspect.HostChangeLog.host_address | String | The IP address, or nested address \(in case of a nested device\) of the host. |
| ForescoutEyeInspect.HostChangeLog.host_vlan | String | The VLAN ID of the host \(only present if the process_vlan_tags option is enabled in the sensor\). |
| ForescoutEyeInspect.HostChangeLog.host_name | String | The main name of the host. |
| ForescoutEyeInspect.HostChangeLog.host_ip_reuse_domain_id | String | The unique ID of the IP Reuse Domain the host is in. |
| ForescoutEyeInspect.HostChangeLog.host_mac_addresses | String | The MAC addresses associated to the host. |

#### Command example
```!forescout-ei-hosts-changelog-list page=1 limit=1```
#### Context Example
```json
{
    "ForescoutEyeInspect": {
        "HostChangeLog": {
            "event_category": "PROPERTIES",
            "event_type_id": "hostcl_new_host",
            "event_type_name": "New host",
            "host_address": "192.168.30.82",
            "host_id": 1,
            "host_ip_reuse_domain_id": 1,
            "host_mac_addresses": [
                "00:50:56:A6:41:89",
                "C4:24:56:A4:86:11"
            ],
            "host_name": "",
            "host_vlan": "",
            "id": 1,
            "information_source": "USER",
            "new_value": "",
            "old_value": "",
            "sensor_id": 0,
            "timestamp": "2022-01-16T17:38:41.505+01:00",
            "username": "admin"
        }
    }
}
```

#### Human Readable Output

>### Hosts Changes List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|ID|Host ID|Event Type Name|
>|---|---|---|
>| 1 | 1 | New host |