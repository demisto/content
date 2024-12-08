ExtraHop Reveal(x) for Cortex XSOAR is a network detection and response solution that provides complete visibility of network communications at enterprise scale, real-time threat detections backed by machine learning, and guided investigation workflows that simplify response.

## Configure ExtraHop Reveal(x) in Cortex
    

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | The name of the instance. | True |
| Fetches incidents | Select to enable this instance to fetch detection events. Otherwise, select **Do not fetch**. Each API call fetches a maximum of 200 detection events. | True  |
| Classifier | Specifies the type of incident to be created for detection events ingested by this instance. | False |
| Incident type | Specifies the type of incident to be created for detection events ingested by this instance if a **Classifier** is not specified. | False |
| Mapper | Specifies how detection events ingested by this instance are mapped to Cortex XSOAR incident fields. | False |
| On Cloud | The type of ExtraHop system the integration will connect to. Select if connecting to ExtraHop Reveal(x) 360. Leave unselected if connecting to Reveal(x) Enterprise. | False |
| URL | The URL of the ExtraHop system this integration will connect to. | True |
| API Key | The API key required for authentication if connecting to ExtraHop Reveal(x) Enterprise. [The API key is generated on your ExtraHop system.](https://docs.extrahop.com/current/rest-api-guide/#generate-an-api-key) | False |
| Client ID and Client Secret | The credential pair required for authentication if connecting to ExtraHop Reveal(x) 360. [The client ID and secret are generated on your ExtraHop system.](https://docs.extrahop.com/current/rx360-integrations-cortex-xsoar/) | False |
| Trust any certificate (not secure) | Specifies whether to allow connections without verifying SSL certificate's validity. | False |
| Use system proxy settings | Specifies whether to use XSOAR system proxy settings to connect to the API. | False |
| First fetch time | Specifies the beginning timestamp from which to start fetching detection events. | False |
| Incidents Fetch Interval | Specifies how often the instance fetches detection events. Because each API call fetches a maximum of 200 detection events, we recommend specifying one minute intervals to fetch all detection events. | False |
| Advanced Filter | Applies a filter to the list of detections based on a JSON-specific query.<br/><br/>Example for detections:<br/>\{<br/>  "categories": \["sec.attack"\],<br/>  "risk_score_min": 51<br/>\}<br/><br/>If the categories and category are not specified, then categories will be set to \["sec.attack"\]. The category field is deprecated by the API, so please use the categories field instead.<br/>For a complete reference to the Extrahop detections filter fields, please refer to the ExtraHop REST API documentation at<br/>https://docs.extrahop.com/current/rest-api-guide/ | False |
| Do not use by default | Select to disable running commands through the Cortex XSOAR CLI on this instance of the integration. | False |
| Log Level | Specifies the level of logging to enable for this instance of the integration. | False |
| Run on | Specifies whether to run the instance of the integration on a single engine. | False |
    

## Commands
You can run the following commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully run a command, a DBot message appears in the War Room with the command details.

<ul>
  <li>Get detections from ExtraHop Reveal(x): extrahop-detections-list</li>
  <li>Link an ExtraHop Reveal(x) detection to a Cortex XSOAR incident: extrahop-ticket-track</li>
  <li>Search for devices in ExtraHop Reveal(x): extrahop-devices-search</li>
  <li>Get all active network protocols for a device from ExtraHop Reveal(x): extrahop-protocols-get</li>
  <li>Get all peers for a device from ExtraHop Reveal(x): extrahop-peers-get</li>
  <li>Get a link to a live activity map in ExtraHop Reveal(x): extrahop-activity-map-get</li>
  <li>Get all devices on the Advanced Analysis watchlist in ExtraHop Reveal(x): extrahop-watchlist-get</li>
  <li>Add or remove devices from the Advanced Analysis watchlist in ExtraHop Reveal(x): extrahop-watchlist-edit</li>
  <li>Add or remove a tag from devices in ExtraHop Reveal(x): extrahop-devices-tag</li>
  <li>Get all alert rules from ExtraHop Reveal(x): extrahop-alert-rules-get</li>
  <li>Create a new alert rule in ExtraHop Reveal(x): extrahop-alert-rule-create</li>
  <li>Modify an alert rule in ExtraHop Reveal(x): extrahop-alert-rule-edit</li>
  <li>Get metrics for specified objects from ExtraHop Reveal(x): extrahop-metrics-list</li>
  <li>Search for specific packets in ExtraHop Reveal(x): extrahop-packets-search</li>
</ul>

### extrahop-watchlist-get
***
Get all devices on the advanced analysis watchlist in ExtraHop Reveal(x).


#### Base Command

`extrahop-watchlist-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.Device.Macaddr | String | The MAC Address of the device. | 
| ExtraHop.Device.DeviceClass | String | The class of this device. | 
| ExtraHop.Device.UserModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.AutoRole | String | The role automatically detected by the ExtraHop system. | 
| ExtraHop.Device.ParentId | Number | The ID of the parent device. | 
| ExtraHop.Device.Vendor | String | The device vendor. | 
| ExtraHop.Device.Analysis | string | The level of analysis received by the device. | 
| ExtraHop.Device.DiscoveryId | String | The UUID for this device. | 
| ExtraHop.Device.DefaultName | String | The default name for this device. | 
| ExtraHop.Device.DisplayName | String | The display name of device. | 
| ExtraHop.Device.OnWatchlist | Boolean | Whether the device is on the advanced analysis watch list. | 
| ExtraHop.Device.ModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.IsL3 | Boolean | Indicates whether the device is a layer 3 device. | 
| ExtraHop.Device.Role | String | The role of the device. | 
| ExtraHop.Device.DiscoverTime | Number | The time that the device was discovered. | 
| ExtraHop.Device.Id | Number | The ID of the device. | 
| ExtraHop.Device.Ipaddr4 | String | The IPv4 address for this device. | 
| ExtraHop.Device.Vlanid | Number | The unique identifier for the VLAN associated with the device. | 
| ExtraHop.Device.Ipaddr6 | string | The IPv6 address of the device. | 
| ExtraHop.Device.NodeId | number | The node ID of the sensor associated with this device. | 
| ExtraHop.Device.Description | string | A user customizable description of the device. | 
| ExtraHop.Device.DnsName | string | The DNS name associated with the device. | 
| ExtraHop.Device.DhcpName | string | The DHCP name associated with the device. | 
| ExtraHop.Device.CdpName | string | The Cisco Discovery Protocol name associated with the device. | 
| ExtraHop.Device.NetbiosName | string | The NetBIOS name associated with the device. | 
| ExtraHop.Device.Url | string | Link to the device details page in ExtraHop Reveal(x). | 

#### Command example
```!extrahop-watchlist-get```
#### Context Example
```json
{
    "ExtraHop": {
        "Device": [
            {
                "analysis": "advanced",
                "analysis_level": 2,
                "auto_role": "other",
                "critical": false,
                "default_name": "VM9",
                "device_class": "node",
                "dhcp_name": "test",
                "discover_time": 1635499650000,
                "discovery_id": "0000000000000000",
                "display_name": "test",
                "extrahop_id": "0000000000000000",
                "id": 25769803982,
                "ipaddr4": "0.0.0.0",
                "is_l3": false,
                "macaddr": "00:00:00:00:00:00",
                "mod_time": 1676638611398,
                "model": "vmware_vm",
                "node_id": 6,
                "on_watchlist": true,
                "role": "other",
                "url": "https://dummy_url/extrahop/#/metrics/devices/overview/",
                "user_mod_time": 1676290306316,
                "vendor": "VMware",
                "vlanid": 0
            },
            {
                "analysis": "advanced",
                "analysis_level": 2,
                "auto_role": "other",
                "critical": false,
                "default_name": "VM8",
                "device_class": "node",
                "discover_time": 1675318050000,
                "discovery_id": "0000000000000000",
                "display_name": "VM8",
                "extrahop_id": "0000000000000000",
                "id": 25769808133,
                "ipaddr4": "0.0.0.0",
                "is_l3": false,
                "last_seen_time": 1675319010000,
                "macaddr": "00:00:00:00:00:00",
                "mod_time": 1675425919964,
                "model": "vmware_vm",
                "node_id": 6,
                "on_watchlist": true,
                "role": "other",
                "url": "https://dummy_url/extrahop/#/metrics/devices/00000000000000000000000000000000.0000000000000000/overview/",
                "user_mod_time": 0,
                "vendor": "VMware",
                "vlanid": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Device Details:
>
>|Display Name|IP Address|MAC Address|Role|Vendor| URL|
>|---|---|---|---|---|---|
>| test | 0.0.0.0 | 00:00:00:00:00:00 | other | VMware | [View Device in ExtraHop](https://dummy_url/extrahop/#/metrics/devices/overview/)|
>| VM 8 | 0.0.0.0 | 00:00:00:00:00:00 | other | VMware | [View Device in ExtraHop](https://dummy_url/extrahop/#/metrics/devices/overview/)|


### extrahop-peers-get
***
Get all peers for a device from ExtraHop Reveal(x).


#### Base Command

`extrahop-peers-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_or_id | The IP address or ExtraHop API ID of the source device to get peer devices. | Required | 
| query_from | The beginning timestamp of the time range the query will search, expressed in milliseconds since the epoch. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. Default is -30m. | Optional | 
| query_until | The ending timestamp of the time range the query will search, expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. | Optional | 
| peer_role | The role of the peer device in relation to the origin device. Possible values are: any, client, server. Default is any. | Optional | 
| protocol | A filter to only return peers that the source device has communicated with over this protocol. If no value is set, the object includes any protocol. Possible values are: any, AAA, ActiveMQ, AJP, amf, CIFS, DB, DHCP, DICOM, DNS, FIX, FTP, HL7, HTTP, IBMMQ, ICA, IKE/ISAKMP, IMAP, IPFIX, IPsec NAT-T, IRC, iSCSI, Kerberos, L2TP, LDAP, lync-compress, memcache, Modbus, MongoDB, MSMQ, MSN, MSRPC, NetFlow, NFS, NTP, OpenVPN, PCoIP, Perforce, POP3, RDP, Redis, RFB, RTCP, RTP, sFlow, SIP, SMPP, SMTP, SNMP, SSH, SSL, Syslog, TCP, telnet, UDP, WebSocket. Default is any. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.Device.Macaddr | String | The MAC address of the device. | 
| ExtraHop.Device.DeviceClass | String | The class of the device. | 
| ExtraHop.Device.UserModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.AutoRole | String | The role automatically detected by the ExtraHop system. | 
| ExtraHop.Device.ParentId | Number | The ID of the parent device. | 
| ExtraHop.Device.Vendor | String | The device vendor. | 
| ExtraHop.Device.Analysis | string | The level of analysis received by the device. | 
| ExtraHop.Device.DiscoveryId | String | The UUID given of the device. | 
| ExtraHop.Device.DefaultName | String | The default name for this device. | 
| ExtraHop.Device.DisplayName | String | The display name of device. | 
| ExtraHop.Device.OnWatchlist | Boolean | Whether the device is on the advanced analysis watch list. | 
| ExtraHop.Device.ModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.IsL3 | Boolean | Indicates whether the device is a layer 3 device. | 
| ExtraHop.Device.Role | String | The role of the device. | 
| ExtraHop.Device.DiscoverTime | Number | The time that the device was discovered. | 
| ExtraHop.Device.Id | Number | The ID of the device. | 
| ExtraHop.Device.Ipaddr4 | String | The IPv4 address for this device. | 
| ExtraHop.Device.Vlanid | Number | The unique identifier for the VLAN associated with the device. | 
| ExtraHop.Device.Ipaddr6 | string | The IPv6 address of the device. | 
| ExtraHop.Device.NodeId | number | The node ID of the sensor associated with the device. | 
| ExtraHop.Device.Description | string | A user customizable description of the device. | 
| ExtraHop.Device.DnsName | string | The DNS name associated with the device. | 
| ExtraHop.Device.DhcpName | string | The DHCP name associated with the device. | 
| ExtraHop.Device.CdpName | string | The Cisco Discovery Protocol name associated with the device. | 
| ExtraHop.Device.NetbiosName | string | The NetBIOS name associated with the device. | 
| ExtraHop.Device.Url | string | Link to the device details page in ExtraHop Reveal(x). | 

#### Command example
```!extrahop-peers-get ip_or_id=0.0.0.0 peer_role=server protocol=any query_from=-60m query_until=0```
#### Context Example
```json
{
    "ExtraHop": {
        "Device": {
            "analysis": "advanced",
            "analysis_level": 1,
            "auto_role": "gateway",
            "critical": true,
            "default_name": "Cisco Meraki 23D27A",
            "device_class": "gateway",
            "discover_time": 1655102100000,
            "discovery_id": "0000000000000000",
            "display_name": "Cisco Meraki 23D27A",
            "extrahop_id": "0000000000000000",
            "id": 25769805776,
            "ipaddr4": "0.0.0.0",
            "is_l3": false,
            "macaddr": "00:00:00:00:00:00",
            "mod_time": 1676638911830,
            "node_id": 6,
            "on_watchlist": false,
            "role": "gateway",
            "server_protocols": [
                "UDP:NTP"
            ],
            "url": "https://dummy_url/extrahop/#/metrics/devices/overview/",
            "user_mod_time": 0,
            "vendor": "Cisco Meraki",
            "vlanid": 0
        }
    }
}
```

#### Human Readable Output

>### Device Details:
>
>|Display Name| IP Address |MAC Address|Role|Protocols|URL|Vendor|
>|---|---|---|---|---|---|---|
>| Cisco Meraki 23D27A | 0.0.0.0 | 00:00:00:00:00:00 | gateway | Server: UDP:NTP | [View Device in ExtraHop](https://dummy_url/extrahop/#/metrics/devices/overview/) | Cisco Meraki |


### extrahop-devices-search
***
Search for devices in ExtraHop Reveal(x).


#### Base Command

`extrahop-devices-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the device. This searches for matches on all ExtraHop Reveal(x) name fields (DHCP, DNS, NetBIOS, Cisco Discovery Protocol, etc). | Optional | 
| ip | The IP address of the device. | Optional | 
| mac | The MAC address of the device. | Optional | 
| role | The role of the device. Possible values are: db_server, dhcp_server, dns_server, file_server, firewall, gateway, http_server, domain_controller, web_proxy, load_balancer, pc, medical_device, mobile_device, printer, scanner, custom, voip_phone, other. | Optional | 
| software | The OS of the device. Possible values are: android, apple_ios, arista_eos, cisco_ios, cisco_nx-os, chrome_os, linux, mac_os, windows, windows_server, windows_server_2008, windows_server_2008_r2, windows_server_2012, windows_server_2012_r2, windows_server_2016, windows_vista, windows_7, windows_8, windows_8.1, windows_10. | Optional | 
| tag | A tag present on the device. | Optional | 
| vendor | The vendor of the device, based on MAC address via OUI lookup. Possible values are: alcatel-lucent, apple, arista, asus, brother, canon, cisco, cisco-linksys, citrix, dell, dellemc, d-link, emc, f5, google, hp, htc, huawei, ibm, juniper, kyocera, microsoft, netapp, netgear, nokia, nortel, oracle, paloalto, samsung, 3com, toshiba, virtualbox, vmware, zte. | Optional | 
| discover_time | The time that device was first seen by the ExtraHop system, expressed in milliseconds since the epoch. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with the following unit suffixes: ms, s, m, h, d, w, M, y. For example, to look one day back enter -1d or -24h. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. | Optional | 
| vlan | The VLAN ID of the Virtual LAN that the device is on. | Optional | 
| activity | The activity of the device. Possible values are: aaa_client, aaa_server, ajp_client, ajp_server, amf_client, amf_server, cifs_client, cifs_server, db_client, db_server, dhcp_client, dhcp_server, dicom_client, dicom_server, dns_client, dns_server, fix_client, fix_server, ftp_client, ftp_server, hl7_client, hl7_server, http_client, http_server, ibmmq_client, ibmmq_server, ica_client, ica_server, icmp, iscsi_client, iscsi_server, kerberos_client, kerberos_server, ldap_client, ldap_server, llmnr_client, llmnr_server, memcache_client, memcache_server, modbus_client, modbus_server, mongo_client, mongo_server, msmq, nbns_client, nbns_server, nfs_client, nfs_server, pcoip_client, pcoip_server, pop3_client, pop3_server, rdp_client, rdp_server, redis_client, redis_server, rfb_client, rfb_server, rpc_client, rpc_server, rtcp, rtp, scanner, sip_client, sip_server, smpp_client, smpp_server, smtp_client, smtp_server, ssh_client, ssh_server, ssl_client, ssl_server, tcp, telnet_client, telnet_server, udp, websocket_client, websocket_server, wsman_client, wsman_server. | Optional | 
| operator | The compare method applied when matching the fields against their values. For example, to find devices with names that begin with 'SEA1' (set name=SEA1, operator=startswith). Possible values are: &gt;, &lt;, &lt;=, &gt;=, =, !=, startswith, exists, not_exists, ~, !~. Default is =. | Optional | 
| match_type | The match operator to use when chaining the search fields together. For example, to find all HTTP servers running Windows on the network (set match_type=and, role=http_server, software=windows). Possible values are: and, or, not. Default is and. | Optional | 
| active_from | The beginning timestamp for the request. Return only devices active after this time. Time is expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. | Optional | 
| active_until | The ending timestamp for the request. Return only devices active before this time. Time is expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. | Optional | 
| limit | The maximum number of devices to return. Default is 10. | Optional | 
| l3_only | Only returns layer 3 devices by filtering out any layer 2 parent devices. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.Device.Macaddr | String | The MAC address of the device. | 
| ExtraHop.Device.DeviceClass | String | The class of the device. | 
| ExtraHop.Device.UserModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.AutoRole | String | The role automatically detected by the ExtraHop system. | 
| ExtraHop.Device.ParentId | Number | The ID of the parent device. | 
| ExtraHop.Device.Vendor | String | The device vendor. | 
| ExtraHop.Device.Analysis | string | The level of analysis received by the device. | 
| ExtraHop.Device.DiscoveryId | String | The UUID of the device. | 
| ExtraHop.Device.DefaultName | String | The default name of the device. | 
| ExtraHop.Device.DisplayName | String | The display name of device. | 
| ExtraHop.Device.OnWatchlist | Boolean | Whether the device is on the advanced analysis watch list. | 
| ExtraHop.Device.ModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.IsL3 | Boolean | Indicates whether the device is a layer 3 device. | 
| ExtraHop.Device.Role | String | The role of the device. | 
| ExtraHop.Device.DiscoverTime | Number | The time that the device was discovered. | 
| ExtraHop.Device.Id | Number | The ID of the device. | 
| ExtraHop.Device.Ipaddr4 | String | The IPv4 address of the device. | 
| ExtraHop.Device.Vlanid | Number | The ID of the VLAN associated with the device. | 
| ExtraHop.Device.Ipaddr6 | String | The IPv6 address of the device. | 
| ExtraHop.Device.NodeId | Number | The node ID of the sensor associated with the device. | 
| ExtraHop.Device.Description | String | A user customizable description of the device. | 
| ExtraHop.Device.DnsName | String | The DNS name associated with the device. | 
| ExtraHop.Device.DhcpName | String | The DHCP name associated with the device. | 
| ExtraHop.Device.CdpName | String | The Cisco Discovery Protocol name associated with the device. | 
| ExtraHop.Device.NetbiosName | String | The NetBIOS name associated with the device. | 
| ExtraHop.Device.Url | String | Link to the device details page in ExtraHop Reveal(x). | 

#### Command example
```!extrahop-devices-search activity=aaa_client discover_time=-10m ip=0.0.0.0 l3_only=true limit=2 mac=00:00:00:00:00:00 match_type=or name=DNS operator=!= role=file_server software=linux tag=tag1 vendor=cisco```
#### Context Example
```json
{
    "ExtraHop": {
        "Device": [
            {
                "analysis": "advanced",
                "analysis_level": 1,
                "auto_role": "other",
                "critical": false,
                "default_name": "VMware 8",
                "device_class": "node",
                "discover_time": 1676633640000,
                "discovery_id": "0000000000000000",
                "display_name": "VMware 8",
                "extrahop_id": "0000000000000000",
                "id": 25769808421,
                "ipaddr4": "0.0.0.0",
                "is_l3": false,
                "last_seen_time": 1676634840000,
                "macaddr": "00:00:00:00:00:00",
                "mod_time": 1676634890174,
                "model": "vmware_vm",
                "node_id": 6,
                "on_watchlist": false,
                "role": "other",
                "url": "https://dummy_url/extrahop/#/metrics/devices/overview/",
                "user_mod_time": 0,
                "vendor": "VMware",
                "vlanid": 0
            },
            {
                "analysis": "advanced",
                "analysis_level": 1,
                "auto_role": "other",
                "critical": false,
                "default_name": "VMware 3",
                "device_class": "node",
                "discover_time": 1676614620000,
                "discovery_id": "0000000000000000",
                "display_name": "VMware 3",
                "extrahop_id": "0000000000000000",
                "id": 25769808417,
                "ipaddr4": "0.0.0.0",
                "is_l3": false,
                "last_seen_time": 1676616960000,
                "macaddr": "00:00:00:00:00:00",
                "mod_time": 1676616977189,
                "model": "vmware_vm",
                "node_id": 6,
                "on_watchlist": false,
                "role": "other",
                "url": "https://dummy_url/extrahop/#/metrics/devices/overview/",
                "user_mod_time": 0,
                "vendor": "VMware",
                "vlanid": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Device Details:
>
>|Display Name|IP Address|MAC Address|Role|Vendor|URL|
>|---|---|---|---|---|---|
>| VMware 8 | 0.0.0.0 | 00:00:00:00:00:00 | other | VMware | [View Device in ExtraHop](https://dummy_url/extrahop/#/metrics/devices/overview/) |
>| VMware 3 | 0.0.0.0 | 00:00:00:00:00:00 | other | VMware | [View Device in ExtraHop](https://dummy_url/extrahop/#/metrics/devices/overview/) |


### extrahop-protocols-get
***
Get all active network protocols for a device from ExtraHop Reveal(x).


#### Base Command

`extrahop-protocols-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_or_id | The IP address or ExtraHop API ID of the device to get all active network protocols. | Required | 
| query_from | The beginning timestamp of the time range the query will search, expressed in milliseconds since the epoch. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. Default is -30m. | Optional | 
| query_until | The ending timestamp of the time range the query will search, expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.Device.Macaddr | String | The MAC address of the device. | 
| ExtraHop.Device.DeviceClass | String | The class of the device. | 
| ExtraHop.Device.UserModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.AutoRole | String | The role automatically detected by the ExtraHop system. | 
| ExtraHop.Device.ParentId | Number | The ID of the parent device. | 
| ExtraHop.Device.Vendor | String | The device vendor. | 
| ExtraHop.Device.Analysis | String | The level of analysis received by the device. | 
| ExtraHop.Device.DiscoveryId | String | The UUID of the device. | 
| ExtraHop.Device.DefaultName | String | The default name of the device. | 
| ExtraHop.Device.DisplayName | String | The display name of device. | 
| ExtraHop.Device.OnWatchlist | Boolean | Whether the device is on the advanced analysis watch list. | 
| ExtraHop.Device.ModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Device.IsL3 | Boolean | Indicates whether the device is a layer 3 device. | 
| ExtraHop.Device.Role | String | The role of the device. | 
| ExtraHop.Device.DiscoverTime | Number | The time that the device was discovered. | 
| ExtraHop.Device.Id | Number | The ID of the device. | 
| ExtraHop.Device.Ipaddr4 | String | The IPv4 address of the device. | 
| ExtraHop.Device.Vlanid | Number | The ID of the VLAN associated with the device. | 
| ExtraHop.Device.Ipaddr6 | String | The IPv6 address of the device. | 
| ExtraHop.Device.NodeId | Number | The node ID of the sensor associated with the device. | 
| ExtraHop.Device.Description | String | A user customizable description of the device. | 
| ExtraHop.Device.DnsName | String | The DNS name associated with the device. | 
| ExtraHop.Device.DhcpName | String | The DHCP name associated with the device. | 
| ExtraHop.Device.CdpName | String | The Cisco Discovery Protocol name associated with the device. | 
| ExtraHop.Device.NetbiosName | String | The NetBIOS name associated with the device. | 
| ExtraHop.Device.Url | String | Link to the device details page in ExtraHop Reveal(x). | 
| ExtraHop.Device.ClientProtocols | String | The list of protocols the peer device is communicating on as a client. | 
| ExtraHop.Device.ServerProtocols | String | The list of protocols the peer device is communicating on as a server. | 

#### Command example
```!extrahop-protocols-get ip_or_id=0.0.0.0 query_from=-20m query_until=0```
#### Context Example
```json
{
    "ExtraHop": {
        "Device": {
            "analysis": "advanced",
            "analysis_level": 2,
            "auto_role": "other",
            "client_protocols": [
                "UDP:NTP"
            ],
            "critical": false,
            "default_name": "VMware 9",
            "device_class": "node",
            "dhcp_name": "test",
            "discover_time": 1635499650000,
            "discovery_id": "0000000000000000",
            "display_name": "test",
            "extrahop_id": "0000000000000000",
            "id": 10000000000,
            "ipaddr4": "0.0.0.0",
            "is_l3": false,
            "macaddr": "00:00:00:00:00:000",
            "mod_time": 1676638611398,
            "model": "vmware_vm",
            "node_id": 6,
            "on_watchlist": true,
            "role": "other",
            "url": "https://dummy_url/extrahop/#/metrics/devices/overview/",
            "user_mod_time": 1676290306316,
            "vendor": "VMware",
            "vlanid": 0
        }
    }
}
```

#### Human Readable Output

>### Device Activity Found:
>
>|Display Name|IP Address|MAC Address|Protocols (Client)|Role|Vendor|URL|
>|---|---|---|---|---|---|---|
>| test | 0.0.0.0 | 00:00:00:00:00:000 | UDP:NTP | other | VMware | [View Device in ExtraHop](https://dummy_url/extrahop/#/metrics/devices/overview/) |


### extrahop-activity-map-get
***
Get a link to a live activity map in ExtraHop Reveal(x).


#### Base Command

`extrahop-activity-map-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_or_id | The IP address or ExtraHop API ID of the source device to get an activity map. | Required | 
| time_interval | The time interval of the live activity map, expressed as the "Last" 30 minutes. For example, specify a value of 30 minutes to get an activity map showing the time range of the last 30 minutes. This field is ignored if from_time and until_time are provided. Possible values are: 30 minutes, 6 hours, 1 day, 1 week. Default is 30 minutes. | Optional | 
| from_time | The beginning timestamp of a fixed time range the activity map will display, expressed in seconds since the epoch. | Optional | 
| until_time | The ending timestamp of a fixed time range the activity map will display, expressed in seconds since the epoch. | Optional | 
| peer_role | The role of the peer devices in relation to the source device. For example, specifying a peer_role of client will show All Clients communicating with the source device. Additionally specifying a protocol of HTTP will result in further filtering and only showing HTTP Clients communicating with the source device. Possible values are: any, client, server. Default is any. | Optional | 
| protocol | The protocol over which the source device is communicating. For example, specifying a protocol of HTTP show only HTTP Clients and HTTP Servers communicating with the source device. Additionally specifying a peer_role of client will result in further filtering and only showing HTTP Clients communicating with the source device. Possible values are: any, AAA, ActiveMQ, AJP, amf, CIFS, DB, DHCP, DICOM, DNS, FIX, FTP, HL7, HTTP, IBMMQ, ICA, IKE/ISAKMP, IMAP, IPFIX, IPsec NAT-T, IRC, iSCSI, Kerberos, L2TP, LDAP, lync-compress, memcache, Modbus, MongoDB, MSMQ, MSN, MSRPC, NetFlow, NFS, NTP, OpenVPN, PCoIP, Perforce, POP3, RDP, Redis, RFB, RTCP, RTP, sFlow, SIP, SMPP, SMTP, SNMP, SSH, SSL, Syslog, TCP, telnet, UDP, WebSocket. Default is any. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.ActivityMap.url | String | The link to a visual activity map in ExtraHop Reveal(x). | 

#### Command example
```!extrahop-activity-map-get ip_or_id=0.0.0.0 peer_role=server protocol=any time_interval="30 minutes"```
#### Context Example
```json
{
    "ExtraHop": {
        "ActivityMap": {
            "url": "https://dummy_url/extrahop/#/activitymaps?appliance_id=00000000000000000000000000000000&discovery_id=0000000000000000&from=30&interval_type=MIN&object_type=device&protocol=any&role=server&until=0"
        }
    }
}
```

#### Human Readable Output

>[View Live Activity Map in ExtraHop](https://dummy_url/extrahop/#/activitymaps?appliance_id=00000000000000000000000000000000&discovery_id=0000000000000000&from=30&interval_type=MIN&object_type=device&protocol=any&role=server&until=0)

### extrahop-alert-rules-get
***
Get all alert rules from ExtraHop Reveal(x).


#### Base Command

`extrahop-alert-rules-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.Alert.Operator | String | The logical operator applied when comparing the value of the operand field to alert conditions. | 
| ExtraHop.Alert.FieldName | String | The name of the monitored metric. | 
| ExtraHop.Alert.NotifySnmp | Boolean | Indicates whether to send an SNMP trap when an alert is generated. | 
| ExtraHop.Alert.Operand | String | The value to compare against alert conditions. | 
| ExtraHop.Alert.IntervalLength | Number | The length of the alert interval, expressed in seconds. | 
| ExtraHop.Alert.Author | String | The name of the user that created the alert. | 
| ExtraHop.Alert.Name | String | The unique, friendly name for the alert. | 
| ExtraHop.Alert.FieldName2 | String | The second monitored metric when applying a ratio. | 
| ExtraHop.Alert.RefireInterval | Number | The time interval in which alert conditions are monitored, expressed in seconds. | 
| ExtraHop.Alert.ModTime | Number | The time of the most recent update, expressed in milliseconds since the epoch. | 
| ExtraHop.Alert.Units | String | The interval in which to evaluate the alert condition. | 
| ExtraHop.Alert.ApplyAll | Boolean | Indicates whether the alert is assigned to all available data sources. | 
| ExtraHop.Alert.Type | String | The type of alert. | 
| ExtraHop.Alert.FieldOp | String | The type of comparison between the "field_name" and "field_name2" fields when applying a ratio. | 
| ExtraHop.Alert.Id | Number | The unique identifier for the alert. | 
| ExtraHop.Alert.Disabled | Boolean | Indicates whether the alert is disabled. | 
| ExtraHop.Alert.Description | String | An optional description for the alert. | 
| ExtraHop.Alert.Severity | Number | The severity level of the alert. | 
| ExtraHop.Alert.StatName | String | The statistic name for the alert. | 

#### Command example
```!extrahop-alert-rules-get```
#### Context Example
```json
{
    "ExtraHop": {
        "Alert": [
            {
                "apply_all": false,
                "author": "ExtraHop",
                "description": "Alert triggered when ratio of DB errors is greater than 1%.",
                "disabled": false,
                "field_name": "rsp_error",
                "field_name2": "rsp",
                "field_op": "/",
                "id": 15,
                "interval_length": 30,
                "mod_time": 1617887147538,
                "name": "DB Error Ratio - Orange",
                "notify_snmp": false,
                "operand": "0.01",
                "operator": ">",
                "refire_interval": 300,
                "severity": 3,
                "stat_name": "extrahop.application.db",
                "type": "threshold",
                "units": "none"
            },
            {
                "apply_all": false,
                "author": "ExtraHop",
                "description": "Alert triggered when ratio of DB errors is greater than 5%.",
                "disabled": false,
                "field_name": "rsp_error",
                "field_name2": "rsp",
                "field_op": "/",
                "id": 14,
                "interval_length": 30,
                "mod_time": 1617887147615,
                "name": "DB Error Ratio - Red",
                "notify_snmp": false,
                "operand": "0.05",
                "operator": ">",
                "refire_interval": 300,
                "severity": 1,
                "stat_name": "extrahop.application.db",
                "type": "threshold",
                "units": "none"
            },
            {
                "apply_all": false,
                "author": "ExtraHop",
                "description": "Alert triggered when ratio of DNS errors is greater than 0.1%.",
                "disabled": false,
                "field_name": "rsp_error",
                "field_name2": "rsp",
                "field_op": "/",
                "id": 19,
                "interval_length": 30,
                "mod_time": 1617887147785,
                "name": "DNS Error Ratio - Yellow",
                "notify_snmp": false,
                "operand": "0.001",
                "operator": ">",
                "refire_interval": 300,
                "severity": 5,
                "stat_name": "extrahop.application.dns",
                "type": "threshold",
                "units": "none"
            }
        ]
    }
}
```

#### Human Readable Output

>### Found 3 Alert(s)
>|Apply All|Author|Description|Disabled|Field Name|Field Name2|Field Op|Id|Interval Length|Mod Time|Name|Notify Snmp|Operand|Operator|Refire Interval|Severity|Stat Name|Type|Units|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | ExtraHop | Alert triggered when ratio of DB errors is greater than 1%. | false | rsp_error | rsp | / | 15 | 30 | 1617887147538 | DB Error Ratio - Orange | false | 0.01 | > | 300 | 3 | extrahop.application.db | threshold | none |
>| false | ExtraHop | Alert triggered when ratio of DB errors is greater than 5%. | false | rsp_error | rsp | / | 14 | 30 | 1617887147615 | DB Error Ratio - Red | false | 0.05 | > | 300 | 1 | extrahop.application.db | threshold | none |
>| false | ExtraHop | Alert triggered when ratio of DNS errors is greater than 0.1%. | false | rsp_error | rsp | / | 19 | 30 | 1617887147785 | DNS Error Ratio - Yellow | false | 0.001 | > | 300 | 5 | extrahop.application.dns | threshold | none |


### extrahop-packets-search
***
Search for specific packets in ExtraHop Reveal(x).


#### Base Command

`extrahop-packets-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| output | The output format. A pcap file, A keylog.txt file that can be loaded in wireshark to decode ssl packets, or a zip file containing both a packets.pcap and keylog.txt. Possible values are: pcap, keylog_txt, zip. Default is pcap. | Optional | 
| limit_bytes | The maximum number of bytes to return. Default is 10MB. | Optional | 
| limit_search_duration | The maximum amount of time to run the packet search. The default unit is milliseconds, but other units can be specified with a unit suffix. Default is 5m. | Optional | 
| query_from | The beginning timestamp of the time range the search will include, expressed in milliseconds since the epoch. A negative value specifies that the search will begin with packets captured at a time in the past relative to the current time. For example, specify -10m to begin the search with packets captured 10 minutes before the time of the request. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. Default is -10m. | Optional | 
| query_until | The ending timestamp of the time range the search will include, expressed in milliseconds since the epoch. A 0 value specifies that the search will end with packets captured at the time of the search. A negative value specifies that the search will end with packets captured at a time in the past relative to the current time. For example, specify -5m to end the search with packets captured 5 minutes before the time of the request. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes. | Optional | 
| bpf | The Berkeley Packet Filter (BPF) syntax for the packet search. | Optional | 
| ip1 | Returns packets sent to or received by the specified IP address. | Optional | 
| port1 | Returns packets sent from or received on the specified port. | Optional | 
| ip2 | Returns packets sent to or received by the specified IP address. | Optional | 
| port2 | Returns packets sent from or received on the specified port. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command example
```!extrahop-packets-search ip1=0.0.0.0 ip2=0.0.0.0 limit_bytes=10MB limit_search_duration=10m output=pcap port1=8000 port2=8000 query_from=-15m query_until=0```
#### Human Readable Output

>Uploaded file: extrahop 2022-12-15 21.12.29 to 21.27.29 IST.pcapDownload.
> 
> | Property | Value |
> |--- | --- |
> | Type | pcap |
> | Size | 1,122,020 bytes |
> | Info | data |
> | MD5 | 710737f2d9874690f130da14da38e7cb |
> | SHA1 | a89d4696c11ee0a8890d8f4effba8fad891cf05d |
> | SHA256 | 433f238d350d8eb19979f0f513974d97b9e9f3445f99deb75c0a1f46e54de111 |
> | SHA512 | fbb914a425d324e4d50bdcf15fc31499720e48d9242005c796d91c345dcb44e1f2fb1435d6bf44c89e0f8256dbae43638f5d8175872bcd29e5bf4fbcba4124cb |
> | SSDeep | 12288:WzC9IOFcF8jgBXx00uMOsOFtKu1R4mF48f6G2GeXCuX:Wgo8cNx3QsODKugmnfjcPX |

### extrahop-devices-tag
***
Add or remove a tag from devices in ExtraHop Reveal(x).


#### Base Command

`extrahop-devices-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | The case-sensitive value of the tag. | Required | 
| add | The list of IP addresses or ExtraHop API IDs of the devices to tag, comma separated. | Optional | 
| remove | The list of IP addresses or ExtraHop API IDs of the devices to remove the tag from, comma separated. | Optional | 


#### Context Output

There is no context output for this command.<br>
#### Command example
```!extrahop-devices-tag tag=MyTag add=0.0.0.0 remove=0.0.0.0```
#### Human Readable Output

>Successfully tagged untagged the device/s.

### extrahop-alert-rule-create
***
Create a new alert rule in ExtraHop Reveal(x).


#### Base Command

`extrahop-alert-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| apply_all | Indicates whether the alert is assigned to all available data sources. Possible values are: true, false. | Required |
| disabled | Indicates whether the alert is disabled. Possible values are: true, false. | Required | 
| field_name | The name of the monitored metric. Only applicable to threshold alerts. | Optional | 
| field_name2 | The second monitored metric when applying a ratio. Only applicable to threshold alerts. | Optional | 
| field_op | The type of comparison between the field_name and field_name2 fields when applying a ratio. Only applicable to threshold alerts. Possible values are: /, null. | Optional | 
| interval_length | The length of the alert interval, expressed in seconds. Only applicable to threshold alerts. Possible values are: 30, 60, 120, 300, 600, 900, 1200, 1800. Default is 30. | Optional | 
| name | The unique, friendly name for the alert. | Required | 
| notify_snmp | Indicates whether to send an SNMP trap when an alert is generated. Possible values are: true, false. | Required | 
| object_type | The type of metric source monitored by the alert configuration. Only applicable to detection alerts. Possible values are: application, device. | Optional | 
| operand | The value to compare against alert conditions. The compare method is specified by the value of the operator field. Only applicable to threshold alerts. | Optional | 
| operator | The logical operator applied when comparing the value of the operand field to alert conditions. Only applicable to threshold alerts. Possible values are: ==, &gt;, &lt;, &gt;=, &lt;=. | Optional | 
| param | The first alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts. | Optional | 
| param2 | The second alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts. | Optional | 
| protocols | The list of monitored protocols. Only applicable to detection alerts. | Optional | 
| refire_interval | The time interval in which alert conditions are monitored, expressed in seconds. Possible values are: 300, 600, 900, 1800, 3600, 7200, 14400. | Required | 
| severity | The severity level of the alert, which is displayed in the Alert History, email notifications, and SNMP traps. Possible values are: 0, 1, 2, 3, 4, 5, 6, 7. | Required | 
| stat_name | The statistic name for the alert. Only applicable to threshold alerts. | Optional | 
| type | The type of alert. Possible values are: detection, threshold. | Required | 
| units | The interval in which to evaluate the alert condition. Only applicable to threshold alerts. Possible values are: none, period, 1 sec, 1 min, 1 hr. | Optional | 


#### Context Output

There is no context output for this command.<br>
#### Command example
```!extrahop-alert-rule-create apply_all=true interval_length=30 disabled=false name="test10" notify_snmp=false refire_interval=300 severity=4 type=detection object_type=device protocols="udp"```
<br>
#### Human Readable Output

>Successfully created alert rule.
### extrahop-ticket-track
***
Link an ExtraHop Reveal(x) detection to a Cortex XSOAR incident.


#### Base Command

`extrahop-ticket-track`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the Cortex XSOAR incident to track. | Required | 
| detection_id | The ID of the ExtraHop Reveal(x) detection to track. | Required | 
| incident_owner | Owner of the incident. | Optional | 
| incident_status | Status of the incident. Possible values are: 0, 1, 2, 3. | Optional | 
| incident_close_reason | Reason the incident was closed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- |---|
| ExtraHop.TicketId | String | Cortex XSOAR incident ID successfully tracked to the ExtraHop Reveal(x) detection. | 

#### Command example
```!extrahop-ticket-track detection_id=1234 incident_id=1 incident_owner=John incident_status=1```
#### Context Example
```json
{
    "ExtraHop": {
        "ExtraHop": {
            "TicketId": "1"
        }
    }
}
```

#### Human Readable Output

>Successfully linked detection(1234) with incident(1)

### extrahop-alert-rule-edit
***
Modify an alert rule in ExtraHop Reveal(x).


#### Base Command

`extrahop-alert-rule-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The unique identifier for the alert. | Required | 
| apply_all | Indicates whether the alert is assigned to all available data sources. Possible values are: true, false. | Required |
| disabled | Indicates whether the alert is disabled. Possible values are: true, false. | Required | 
| field_name | The name of the monitored metric. Only applicable to threshold alerts. | Optional | 
| field_name2 | The second monitored metric when applying a ratio. Only applicable to threshold alerts. | Optional | 
| field_op | The type of comparison between the field_name and field_name2 fields when applying a ratio. Only applicable to threshold alerts. Possible values are: /, null. | Optional | 
| interval_length | The length of the alert interval, expressed in seconds. Only applicable to threshold alerts. Possible values are: 30, 60, 120, 300, 600, 900, 1200, 1800. Default is 30. | Optional | 
| name | The unique, friendly name for the alert. | Required | 
| notify_snmp | Indicates whether to send an SNMP trap when an alert is generated. Possible values are: true, false. | Required | 
| object_type | The type of metric source monitored by the alert configuration. Only applicable to detection alerts. Possible values are: application, device. | Optional | 
| operand | The value to compare against alert conditions. The compare method is specified by the value of the operator field. Only applicable to threshold alerts. | Optional | 
| operator | The logical operator applied when comparing the value of the operand field to alert conditions. Only applicable to threshold alerts. Possible values are: ==, &gt;, &lt;, &gt;=, &lt;=. | Optional | 
| param | The first alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts. | Optional | 
| param2 | The second alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts. | Optional | 
| protocols | The list of monitored protocols. Only applicable to detection alerts. | Optional | 
| refire_interval | The time interval in which alert conditions are monitored, expressed in seconds. Possible values are: 300, 600, 900, 1800, 3600, 7200, 14400. | Required | 
| severity | The severity level of the alert, which is displayed in the Alert History, email notifications, and SNMP traps. Possible values are: 0, 1, 2, 3, 4, 5, 6, 7. | Required | 
| stat_name | The statistic name for the alert. Only applicable to threshold alerts. | Optional | 
| type | The type of alert. Possible values are: detection, threshold. | Required | 
| units | The interval in which to evaluate the alert condition. Only applicable to threshold alerts. Possible values are: none, period, 1 sec, 1 min, 1 hr. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!extrahop-alert-rule-edit interval_length=30 alert_id=36 apply_all=true disabled=false name="t127" notify_snmp=false refire_interval=300 severity=4 type=detection protocols="udp" object_type=device```
#### Human Readable Output

>Successfully updated alert rule.

### extrahop-watchlist-edit
***
Add or remove devices from the advanced analysis watchlist in ExtraHop Reveal(x).


#### Base Command

`extrahop-watchlist-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| add | The list of IP addresses or ExtraHop API IDs of the devices to add, comma separated. | Optional | 
| remove | The list of IP addresses or ExtraHop API IDs of the devices to remove, comma separated. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!extrahop-watchlist-edit add=0.0.0.0 remove=0.0.0.0```
#### Human Readable Output

>Successfully added new devices(0.0.0.0) in the watchlist 
>Successfully removed devices(0.0.0.0) from the watchlist

### extrahop-metrics-list
***
Get metrics for specified objects from ExtraHop Reveal(x).


#### Base Command

`extrahop-metrics-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cycle | The aggregation period for metrics.<br/>Supported values: "auto", "1sec", "30sec", "5min", "1hr", "24hr". Possible values are: auto, 1sec, 30sec, 5min, 1hr, 24hr. | Required | 
| from_time | The beginning timestamp for the request. Return only metrics collected after this time. Time is expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with a unit suffix.<br/>For example, to request devices active in the last 30 minutes, specify the following parameter value: "-30m". | Required | 
| metric_category | The group of metrics that are searchable in the metric catalog. | Required | 
| object_ids | The list of numeric values that represent unique identifiers. Unique identifiers can be retrieved through the /networks, /devices, /applications, /vlans, /devicegroups, /activitygroups, and /appliances resources. For system health metrics, specify the ID of the sensor or console and set the object_type parameter to "system". | Required | 
| object_type | Indicates the object type of unique identifiers specified in the object_ids property.<br/>Supported values: "network", "device", "application", "vlan", "device_group", "system". Possible values are: network, device, application, vlan, device_group, system. | Required | 
| until_time | The ending timestamp for the request. Return only metrics collected before this time. Time is expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with a unit suffix.<br/>For example, to request devices active in the last 30 minutes, specify the following parameter value: "-30m". | Required | 
| metric_specs | An array of metric specification objects. <br/>Refer to the ExtraHop REST API Guide at https://docs.extrahop.com/current/rest-api-guide/. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.Metrics.cycle | String | The aggregation period for metrics. | 
| ExtraHop.Metrics.node_id | Number | Node ID of the sensor associated with the object. | 
| ExtraHop.Metrics.clock | Number | The current time. | 
| ExtraHop.Metrics.from | Number | The beginning time from which metrics were collected. | 
| ExtraHop.Metrics.until | Number | The ending time that metrics were collected. | 
| ExtraHop.Metrics.stats.oid | Number | The ID of the object. | 
| ExtraHop.Metrics.stats.time | Number | The time for which metrics were collected. | 
| ExtraHop.Metrics.stats.duration | Number | The duration that metrics were collected. | 
| ExtraHop.Metrics.stats.values | Unknown | The count value of the metrics that were collected. | 

#### Command example
```!extrahop-metrics-list cycle=auto from_time=0 metric_category=http object_ids=0 object_type=application until_time=0 metric_specs="[{\"name\": \"req\", \"key\": \"/GET/\"}]"```
#### Context Example
```json
{
    "ExtraHop": {
        "Metrics": {
            "clock": 1676883600000,
            "cycle": "1hr",
            "from": 0,
            "node_id": 0,
            "stats": [
                {
                    "duration": 3600000,
                    "oid": 0,
                    "time": 1637740800000,
                    "values": [
                        345
                    ]
                },
                {
                    "duration": 3600000,
                    "oid": 0,
                    "time": 1637744400000,
                    "values": [
                        178
                    ]
                },
                {
                    "duration": 3600000,
                    "oid": 0,
                    "time": 1637751600000,
                    "values": [
                        744
                    ]
                }
            ],
            "until": 1676883600000
        }
    }
}
```

#### Human Readable Output

Metrics Found:

| Cycle | 30 sec |
| --- | --- |
| Node Id | 0 |
| Clock | 1676873250000 |
| From Time | 1676871390000 |
| Until Time | 1676871990000 |
| Stats | {'oid': 0, 'time': 1637740800000, 'duration': 30000, 'values': [4]},<br>{'oid': 0, 'time': 1676871420000, 'duration': 30000, 'values': [9]},<br>{'oid': 0, 'time': 1676871450000, 'duration': 30000, 'values': [4]}, |

### extrahop-detections-list
***
Get detections from ExtraHop Reveal(x).


#### Base Command

`extrahop-detections-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Detection-specific filters.<br/>For eg:<br/>\{<br/>  "categories": ["sec.attack"],<br/>  "risk_score_min": 51<br/>\}<br/><br/>If the categories and category are not specified, then categories will be set to ["sec.attack"]. The category field is deprecated by the API, so please use the categories field instead.<br/>Refer to the ExtraHop REST API guide at https://docs.extrahop.com/current/rest-api-guide/. | Optional | 
| from | Returns detections that occurred after the specified date, expressed in milliseconds since the epoch. Detections that started before the specified date are returned if the detection was ongoing at that time.<br/><br/>For eg:<br/>from=1673508360001. | Optional | 
| limit | Returns no more than the specified number of detections.<br/><br/>For eg:<br/>limit=10. Default is 200. | Optional | 
| offset | The number of detections to skip for pagination.<br/><br/>For eg:<br/>offset=100. | Optional | 
| sort | Sorts returned detections by the specified fields. <br/>Comma separated "field" "direction" is the accepted format.<br/>By default, detections are sorted by most recent update time and then id in ascending order.<br/><br/>For eg:<br/>sort="end_time asc,id desc". | Optional | 
| until | Return detections that ended before the specified date, expressed in milliseconds since the epoch.<br/><br/>For eg:<br/>until=1673509360001. | Optional | 
| mod_time | Return detections that were modified on or after the specified date, expressed in milliseconds since the epoch.<br/><br/>For eg: 1675416916102 . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExtraHop.Detections.id | Number | The unique detection ID of the detection. | 
| ExtraHop.Detections.start_time | Number | The timestamp when the detection was identified. | 
| ExtraHop.Detections.mod_time | Number | The timestamp when the detection was last modified. | 
| ExtraHop.Detections.end_time | Number | The timestamp when the detection was completed. | 
| ExtraHop.Detections.title | String | The title of the detection. | 
| ExtraHop.Detections.description | String | The description of the event for which the detection was created. | 
| ExtraHop.Detections.categories | Unknown | The categories associated with the detection. | 
| ExtraHop.Detections.risk_score | Number | The risk level of the event. | 
| ExtraHop.Detections.type | String | The detection type. | 
| ExtraHop.Detections.properties | Unknown | The detection properties. | 
| ExtraHop.Detections.participants | Unknown | The participants involved in the event. | 
| ExtraHop.Detections.ticket_id | String | The unique ticket ID for the detection that is being tracked. | 
| ExtraHop.Detections.assignee | String | The user assigned to the detection. | 
| ExtraHop.Detections.status | String | The status of the detection. | 
| ExtraHop.Detections.resolution | String | The resolution status of the detection. | 
| ExtraHop.Detections.mitre_tactics | Unknown | The MITRE tactics associated with the attack. | 
| ExtraHop.Detections.mitre_techniques | Unknown | The MITRE techniques associated with the attack. | 
| ExtraHop.Detections.appliance_id | Number | The unique identifier of the sensor on which the attack was detected. | 
| ExtraHop.Detections.is_user_created | Boolean | Indicates whether the detection is user-created. | 

#### Command example
```!extrahop-detections-list limit=3```
#### Context Example
```json
{
    "ExtraHop": {
        "Detections": [
            {
                "appliance_id": 0,
                "categories": [
                    "sec",
                    "sec.exploit"
                ],
                "description": "The offender was recently observed carrying out a TCP SYN Scan and has now made a successful TCP 3-way handshake to the victim device. Investigate to determine if this is the result of the SYN Scan.",
                "end_time": 1676895361452,
                "id": 1110161,
                "is_user_created": true,
                "participants": [
                    {
                        "external": false,
                        "id": 2187135,
                        "object_type": "ipaddr",
                        "object_value": "0.0.0.0",
                        "role": "offender"
                    },
                    {
                        "external": true,
                        "id": 2187136,
                        "object_type": "ipaddr",
                        "object_value": "0.0.0.2",
                        "role": "victim"
                    }
                ],
                "risk_score": 50,
                "start_time": 1676895361452,
                "title": "Test_Detection_1_1676895361452",
                "type": "Test_Detection_1_1676895361452",
                "mod_time": 1676895361452
            },
            {
                "appliance_id": 0,
                "categories": [
                    "sec",
                    "sec.exploit"
                ],
                "description": "The offender was recently observed carrying out a TCP SYN Scan and has now made a successful TCP 3-way handshake to the victim device. Investigate to determine if this is the result of the SYN Scan.",
                "end_time": 1676895331451,
                "id": 1110160,
                "is_user_created": true,
                "participants": [
                    {
                        "external": false,
                        "id": 2187133,
                        "object_type": "ipaddr",
                        "object_value": "0.0.0.0",
                        "role": "offender"
                    },
                    {
                        "external": true,
                        "id": 2187134,
                        "object_type": "ipaddr",
                        "object_value": "0.0.0.2",
                        "role": "victim"
                    }
                ],
                "risk_score": 50,
                "start_time": 1676895331451,
                "title": "Test_Detection_1_1676895331451",
                "type": "Test_Detection_1_1676895331451",
                "mod_time": 1676895331451
            },
            {
                "appliance_id": 0,
                "categories": [
                    "sec",
                    "sec.exploit"
                ],
                "description": "The offender was recently observed carrying out a TCP SYN Scan and has now made a successful TCP 3-way handshake to the victim device. Investigate to determine if this is the result of the SYN Scan.",
                "end_time": 1676895301451,
                "id": 1110159,
                "is_user_created": true,
                "participants": [
                    {
                        "external": false,
                        "id": 2187131,
                        "object_type": "ipaddr",
                        "object_value": "0.0.0.0",
                        "role": "offender"
                    },
                    {
                        "external": true,
                        "id": 2187132,
                        "object_type": "ipaddr",
                        "object_value": "0.0.0.2",
                        "role": "victim"
                    }
                ],
                "risk_score": 50,
                "start_time": 1676895301451,
                "title": "Test_Detection_1_1676895301451",
                "type": "Test_Detection_1_1676895301451",
                "mod_time": 1676895301451
            }
        ]
    }
}
```

#### Human Readable Output

>### Found 3 Detection(s)
>|Detection ID|Risk Score|Description|Categories|Start Time|
>|---|---|---|---|---|
>| 1110161 | 50 | The offender was recently observed carrying out a TCP SYN Scan and has now made a successful TCP 3-way handshake to the victim device. Investigate to determine if this is the result of the SYN Scan. | sec,<br/>sec.exploit | 1676895361452 |
>| 1110160 | 50 | The offender was recently observed carrying out a TCP SYN Scan and has now made a successful TCP 3-way handshake to the victim device. Investigate to determine if this is the result of the SYN Scan. | sec,<br/>sec.exploit | 1676895331451 |
>| 1110159 | 50 | The offender was recently observed carrying out a TCP SYN Scan and has now made a successful TCP 3-way handshake to the victim device. Investigate to determine if this is the result of the SYN Scan. | sec,<br/>sec.exploit | 1676895301451 |


## Additional Information
<h2>ExtraHop Reveal(x) Playbooks</h2>
<ul>
  <li>ExtraHop - Default</li>
  <li>ExtraHop - CVE-2019-0708 (BlueKeep)</li>
  <li>ExtraHop - Ticket Tracking</li>
  <li>ExtraHop - Get Peers by Host</li>
</ul>
<h2>Use Cases</h2>
<ul>
<li>Create incidents for every detection that ExtraHop Reveal(x) surfaces in real-time.</li>
<li>Enable guided investigation and response through playbooks and automation scripts.</li>
<li>Query the ExtraHop Reveal(x) REST API using the simple and powerful Cortex XSOAR CLI.</li>
</ul>