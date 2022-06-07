Manage Palo Alto Networks Firewall and Panorama. For more information see Panorama documentation.
This integration was integrated and tested with version xx of Panorama

## Configure Palo Alto Networks PAN-OS on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks PAN-OS.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://192.168.0.1) |  | True |
    | API Key |  | False |
    | Port (e.g 443) |  | False |
    | Device group - Panorama instances only (write shared for Shared location) | Located in the Panorama UI. Go to Panorama, Device Groups and select the desired Device Group | False |
    | Vsys - Firewall instances only | Located in the Firewall URL; by default of PAN-OS it is vsys1 | False |
    | Template - Panorama instances only |  | False |
    | Use URL Filtering for auto enrichment | If selected, when running the \!url command, the command will execute using pan-os with PAN_DB \(with applied filters\). The URL filtering categories determine DBot score \(malicious, suspicious, benign\). | False |
    | URL Filtering Additional suspicious categories. CSV list of categories that will be considered suspicious. |  | False |
    | URL Filtering Additional malicious categories. CSV list of categories that will be considered malicious. |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | API Key (Deprecated) | Use the "API Key \(Recommended\)" parameter instead. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-os-push-to-template
***
Pushes the given PAN-OS template to the given devices or all devices that belong to the template.


#### Base Command

`pan-os-push-to-template`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template to push. | Optional | 
| validate-only | Whether to validate the policy. Possible values are: true, false. Default is false. | Optional | 
| description | The push description. | Optional | 
| serial_number | The serial number for a virtual system commit. If provided, the commit will be a virtual system commit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.Template | String | The device group in which the policies were pushed. | 
| Panorama.Push.JobID | Number | The job ID of the policies that were pushed. | 
| Panorama.Push.Status | String | The push status. | 
| Panorama.Push.Warnings | String | The push warnings. | 
| Panorama.Push.Errors | String | The push errors. | 

### pan-os-push-to-template-stack
***
Pushes the given PAN-OS template-stack to the given devices or all devices that belong to the template stack.


#### Base Command

`pan-os-push-to-template-stack`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template-stack | The template-stack to push. | Required | 
| validate-only | Whether to validate the policy. Possible values are: true, false. Default is false. | Optional | 
| description | The push description. | Optional | 
| serial_number | The serial number for a virtual system commit. If provided, the commit will be a virtual system commit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.TemplateStack | String | The device group in which the policies were pushed. | 
| Panorama.Push.JobID | Number | The job ID of the policies that were pushed. | 
| Panorama.Push.Status | String | The push status. | 
| Panorama.Push.Warnings | String | The push warnings. | 
| Panorama.Push.Errors | String | The push errors. | 

### panorama-edit-service-group
***
Edits a service group.


#### Base Command

`panorama-edit-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the service group to edit. | Required | 
| services_to_add | The services to add to the service group. Only existing service objects can be added. | Optional | 
| services_to_remove | The services to remove from the service group. Only existing service objects can be removed. | Optional | 
| tags | The tag of the service group to edit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | The service group name. | 
| Panorama.ServiceGroups.Services | string | The service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | The device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | The service group tags. | 

### panorama-get-url-category
***
Gets a URL category from URL filtering. This command is only available on firewall devices.


#### Base Command

`panorama-get-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Category | String | The URL category. | 

### panorama-get-logs
***
Retrieves the data of a logs query.


#### Base Command

`panorama-get-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID of the query. | Required | 
| ignore_auto_extract | Whether to auto-enrich the War Room entry. If "true", entry is not auto-enriched. If "false", entry is auto-extracted. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.Logs.Action | String | The action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", or "block-url". | 
| Panorama.Monitor.Logs.Application | String | The application associated with the session. | 
| Panorama.Monitor.Logs.Category | String | The URL category of the URL subtype. For WildFire subtype, it is the verdict on the file, and can be either "malicious", "phishing", "grayware", or "benign". For other subtypes, the value is "any". | 
| Panorama.Monitor.Logs.DeviceName | String | The hostname of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.DestinationAddress | String | The original session destination IP address. | 
| Panorama.Monitor.Logs.DestinationUser | String | The username of the user to which the session was destined. | 
| Panorama.Monitor.Logs.DestinationCountry | String | The destination country or internal region for private addresses. Maximum length is 32 bytes. | 
| Panorama.Monitor.Logs.DestinationPort | String | The destination port utilized by the session. | 
| Panorama.Monitor.Logs.FileDigest | String | Only for the WildFire subtype, all other types do not use this field. The filedigest string shows the binary hash of the file sent to be analyzed by the WildFire service. | 
| Panorama.Monitor.Logs.FileName | String | File name or file type when the subtype is file.
File name when the subtype is virus.
File name when the subtype is wildfire-virus.
File name when the subtype is wildfire. | 
| Panorama.Monitor.Logs.FileType | String | Only for the WildFire subtype, all other types do not use this field.
Specifies the type of file that the firewall forwarded for WildFire analysis. | 
| Panorama.Monitor.Logs.FromZone | String | The zone from which the session was sourced. | 
| Panorama.Monitor.Logs.URLOrFilename | String | The actual URL when the subtype is url.
File name or file type when the subtype is file.
File name when the subtype is virus.
File name when the subtype is wildfire-virus.
File name when the subtype is wildfire.
URL or file name when the subtype is vulnerability \(if applicable\). | 
| Panorama.Monitor.Logs.NATDestinationIP | String | The post-NAT destination IP address if destination NAT was performed. | 
| Panorama.Monitor.Logs.NATDestinationPort | String | The post-NAT destination port. | 
| Panorama.Monitor.Logs.NATSourceIP | String | The post-NAT source IP address if source NAT was performed. | 
| Panorama.Monitor.Logs.NATSourcePort | String | The post-NAT source port. | 
| Panorama.Monitor.Logs.PCAPid | String | The packet capture \(pcap\) ID is a 64 bit unsigned integral denoting
an ID to correlate threat pcap files with extended pcaps taken as a part of
that flow. All threat logs will contain either a pcap_id of 0 \(no associated
pcap\), or an ID referencing the extended pcap file. | 
| Panorama.Monitor.Logs.IPProtocol | String | The IP protocol associated with the session. | 
| Panorama.Monitor.Logs.Recipient | String | Only for the WildFire subtype, all other types do not use this field.
Specifies the name of the receiver of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.Rule | String | The name of the rule that the session matched. | 
| Panorama.Monitor.Logs.RuleID | String | The ID of the rule that the session matched. | 
| Panorama.Monitor.Logs.ReceiveTime | String | The time the log was received at the management plane. | 
| Panorama.Monitor.Logs.Sender | String | Only for the WildFire subtype; all other types do not use this field.
Specifies the name of the sender of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.SessionID | String | An internal numerical identifier applied to each session. | 
| Panorama.Monitor.Logs.DeviceSN | String | The serial number of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.Severity | String | The severity associated with the threat. Can be "informational", "low",
"medium", "high", or "critical". | 
| Panorama.Monitor.Logs.SourceAddress | String | The original session source IP address. | 
| Panorama.Monitor.Logs.SourceCountry | String | The source country or internal region for private addresses. Maximum
length is 32 bytes. | 
| Panorama.Monitor.Logs.SourceUser | String | The username of the user who initiated the session. | 
| Panorama.Monitor.Logs.SourcePort | String | The source port utilized by the session. | 
| Panorama.Monitor.Logs.ThreatCategory | String | The threat categories used to classify different types of
threat signatures. | 
| Panorama.Monitor.Logs.Name | String | The Palo Alto Networks identifier for the threat. A description
string followed by a 64-bit numerical identifier. | 
| Panorama.Monitor.Logs.ID | String | The Palo Alto Networks ID for the threat. | 
| Panorama.Monitor.Logs.ToZone | String | The zone to which the session was destined. | 
| Panorama.Monitor.Logs.TimeGenerated | String | The time the log was generated on the data plane. | 
| Panorama.Monitor.Logs.URLCategoryList | String | A list of the URL filtering categories that the firewall used to
enforce the policy. | 
| Panorama.Monitor.Logs.Bytes | String | The total log bytes. | 
| Panorama.Monitor.Logs.BytesReceived | String | The log bytes received. | 
| Panorama.Monitor.Logs.BytesSent | String | The log bytes sent. | 
| Panorama.Monitor.Logs.Vsys | String | The vsys on the firewall that generated the log. | 

### pan-os
***
Runs any command supported in the API.


#### Base Command

`pan-os`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to be taken, such as show, get, set, edit, delete, rename, clone, move, override, multi-move, multi-clone, or complete. Possible values are: set, edit, delete, rename, clone, move, override, muti-move, multi-clone, complete, show, get. | Optional | 
| category | The category parameter. For example, when exporting a configuration file, use "category=configuration". | Optional | 
| cmd | The XML structure that defines the command. Used for operation commands. | Optional | 
| command | The command to run. For example, command =&lt;show&gt;&lt;arp&gt;&lt;entry name='all'/&gt;&lt;/arp&gt;&lt;/show&gt;. | Optional | 
| dst | The specified destination. | Optional | 
| element | The new value defined for an object. | Optional | 
| to | The end time (used when cloning an object). | Optional | 
| from | The start time (used when cloning an object). | Optional | 
| key | The key value to set. | Optional | 
| log-type | The log type to retrieve. For example, log-type=threat for threat logs. | Optional | 
| where | The type of move operation (for example, where=after, where=before, where=top, where=bottom). | Optional | 
| period | The time period, for example period=last-24-hrs. | Optional | 
| xpath | The xpath location, for example, xpath=/config/predefined/application/entry[@name='hotmail']. | Optional | 
| pcap-id | The PCAP ID included in the threat log. | Optional | 
| serialno | The device serial number. | Optional | 
| reporttype | The report type, for example dynamic, predefined, or custom. | Optional | 
| reportname | The report name. | Optional | 
| type | The request type, for example export, import, log, config. Default is keygen,config,commit,op,report,log,import,export,user-id,version. | Optional | 
| search-time | The time the PCAP was received on the firewall. Used for threat PCAPs. | Optional | 
| target | The target number of the firewall. Use only on a Panorama instance. | Optional | 
| job-id | The job ID. | Optional | 
| query | The query string. | Optional | 
| vsys | The name of the virtual system to be configured. If no vsys is mentioned, this command will not use the vsys parameter. | Optional | 
| device-group | The device group to target. | Optional | 
| is_xml | Return raw XML. | Optional | 


#### Context Output

There is no context output for this command.
### pan-os-get-predefined-threats-list
***
Gets the predefined threats list from a Firewall or Panorama and stores it as a JSON file in the context.


#### Base Command

`pan-os-get-predefined-threats-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The firewall managed by Panorama from which to retrieve the predefined threats. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | The file size. | 
| File.Name | string | The file name. | 
| File.Type | string | The file type. | 
| File.Info | string | The file information. | 
| File.Extension | string | The file extension. | 
| File.EntryID | string | The file entry ID. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA512 | string | The SHA512 hash of the file. | 
| File.SSDeep | string | The SSDeep hash of the file. | 

### pan-os-commit
***
Commits a configuration to the Palo Alto firewall or Panorama, but does not validate if the commit was successful. Committing to Panorama does not push the configuration to the firewalls. To push the configuration, run the panorama-push-to-device-group command.


#### Base Command

`pan-os-commit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | The commit description. | Optional | 
| admin_name | The administrator name. To commit admin-level changes on a firewall, include the administrator name in the request. | Optional | 
| force_commit | Forces a commit. Possible values are: true, false. | Optional | 
| exclude_device_network_configuration | Performs a partial commit while excluding device and network configuration. Possible values are: true, false. | Optional | 
| exclude_shared_objects | Performs a partial commit while excluding shared objects. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Commit.JobID | number | The job ID to commit. | 
| Panorama.Commit.Status | string | The commit status. | 

### pan-os-push-to-device-group
***
Pushes rules from PAN-OS to the configured device group. In order to push the configuration to Prisma Access managed tenants (single or multi tenancy), use the device group argument with the device group which is associated with the tenant ID.


#### Base Command

`pan-os-push-to-device-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group to which to push (Panorama instances). | Optional | 
| validate-only | Pre policy validation. Possible values are: true, false. Default is false. | Optional | 
| include-template | Whether to include template changes. Possible values are: true, false. Default is true. | Optional | 
| description | The push description. | Optional | 
| serial_number | The serial number for a virtual system commit. If provided, the commit will be a virtual system commit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.DeviceGroup | String | The device group in which the policies were pushed. | 
| Panorama.Push.JobID | Number | The job ID of the policies that were pushed. | 
| Panorama.Push.Status | String | The push status. | 
| Panorama.Push.Warnings | String | The push warnings. | 
| Panorama.Push.Errors | String | The push errors. | 

### pan-os-list-addresses
***
Returns a list of addresses.


#### Base Command

`pan-os-list-addresses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tag to filter the list of addresses. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | The address name. | 
| Panorama.Addresses.Description | string | The address description. | 
| Panorama.Addresses.FQDN | string | The address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | The address IP netmask. | 
| Panorama.Addresses.IP_Range | string | The address IP range. | 
| Panorama.Addresses.DeviceGroup | String | The address device group. | 
| Panorama.Addresses.Tags | String | The address tags. | 

### pan-os-get-address
***
Returns address details for the supplied address name.


#### Base Command

`pan-os-get-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The address name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | The address name. | 
| Panorama.Addresses.Description | string | The address description. | 
| Panorama.Addresses.FQDN | string | The address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | The address IP netmask. | 
| Panorama.Addresses.IP_Range | string | The address IP range. | 
| Panorama.Addresses.DeviceGroup | String | The device group for the address \(Panorama instances\). | 
| Panorama.Addresses.Tags | String | The address tags. | 

### pan-os-create-address
***
Creates an address object.


#### Base Command

`pan-os-create-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The new address name. | Required | 
| description | The new address description. | Optional | 
| fqdn | The FQDN of the new address. | Optional | 
| ip_netmask | The IP netmask of the new address. For example, 10.10.10.10/24. | Optional | 
| ip_range | The IP range of the new address IP. For example, 10.10.10.0-10.10.10.255. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tag for the new address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | The address name. | 
| Panorama.Addresses.Description | string | The address description. | 
| Panorama.Addresses.FQDN | string | The address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | The address IP Netmask. | 
| Panorama.Addresses.IP_Range | string | The address IP range. | 
| Panorama.Addresses.DeviceGroup | String | The device group for the address \(Panorama instances\). | 
| Panorama.Addresses.Tag | String | The address tag. | 

### pan-os-delete-address
***
Deletes an address object.


#### Base Command

`pan-os-delete-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the address to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | The address name that was deleted. | 
| Panorama.Addresses.DeviceGroup | String | The device group for the address \(Panorama instances\). | 

### pan-os-list-address-groups
***
Returns a list of address groups.


#### Base Command

`pan-os-list-address-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tag for which to filter the address groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | The address group name. | 
| Panorama.AddressGroups.Type | string | The address group type. | 
| Panorama.AddressGroups.Match | string | The dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | The address group description. | 
| Panorama.AddressGroups.Addresses | String | The static address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | The device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tag | String | The address group tag. | 

### pan-os-get-address-group
***
Gets details for the specified address group


#### Base Command

`pan-os-get-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The address group name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | The address group name. | 
| Panorama.AddressGroups.Type | string | The address group type. | 
| Panorama.AddressGroups.Match | string | The dynamic address group match. | 
| Panorama.AddressGroups.Description | string | The address group description. | 
| Panorama.AddressGroups.Addresses | string | The static address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | The device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tags | String | The address group tags. | 

### pan-os-create-address-group
***
Creates a static or dynamic address group.


#### Base Command

`pan-os-create-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The address group name. | Required | 
| type | The address group type. Possible values are: dynamic, static. | Required | 
| match | The dynamic address group match. For example "1.1.1.1 or 2.2.2.2". | Optional | 
| addresses | The static address group list of addresses. | Optional | 
| description | The address group description. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | The tags for the address group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | The address group name. | 
| Panorama.AddressGroups.Type | string | The address group type. | 
| Panorama.AddressGroups.Match | string | The dynamic address group match. | 
| Panorama.AddressGroups.Addresses | string | The static address group list of addresses. | 
| Panorama.AddressGroups.Description | string | The address group description. | 
| Panorama.AddressGroups.DeviceGroup | String | The device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tag | String | The address group tags. | 

### pan-os-block-vulnerability
***
Sets a vulnerability signature to block mode.


#### Base Command

`pan-os-block-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| drop_mode | The type of session rejection. Possible values are: "drop", "alert", "block-ip", "reset-both", "reset-client", and "reset-server". Default is "drop". Possible values are: drop, alert, block-ip, reset-both, reset-client, reset-server. | Optional | 
| vulnerability_profile | The name of the vulnerability profile. | Required | 
| threat_id | The numerical threat ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Vulnerability.ID | string | The ID of the vulnerability that was blocked/overridden. | 
| Panorama.Vulnerability.NewAction | string | The new action for the vulnerability. | 

### pan-os-delete-address-group
***
Deletes an address group.


#### Base Command

`pan-os-delete-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the address group to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | The name of the address group that was deleted. | 
| Panorama.AddressGroups.DeviceGroup | String | The device group for the address group \(Panorama instances\). | 

### pan-os-edit-address-group
***
Edits a static or dynamic address group.


#### Base Command

`pan-os-edit-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the address group to edit. | Required | 
| type | The address group type. Possible values are: static, dynamic. | Required | 
| match | The address group new match. For example, '1.1.1.1 and 2.2.2.2'. | Optional | 
| element_to_add | The element to add to the list of the static address group. Only existing address objects can be added. | Optional | 
| element_to_remove | The element to remove from the list of the static address group. Only existing address objects can be removed. | Optional | 
| description | The address group new description. | Optional | 
| tags | The tag of the address group to edit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | The address group name. | 
| Panorama.AddressGroups.Type | string | The address group type. | 
| Panorama.AddressGroups.Filter | string | The dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | The address group description. | 
| Panorama.AddressGroups.Addresses | string | The static address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | The device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tags | String | The address group tags. | 

### pan-os-list-services
***
Returns a list of addresses.


#### Base Command

`pan-os-list-services`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tag to filter the services. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | The service name. | 
| Panorama.Services.Protocol | string | The service protocol. | 
| Panorama.Services.Description | string | The service description. | 
| Panorama.Services.DestinationPort | string | The service destination port. | 
| Panorama.Services.SourcePort | string | The service source port. | 
| Panorama.Services.DeviceGroup | string | The device group in which the service was configured \(Panorama instances\). | 
| Panorama.Services.Tags | String | The service tags. | 

### pan-os-get-service
***
Returns service details for the supplied service name.


#### Base Command

`pan-os-get-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The service name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | The service name. | 
| Panorama.Services.Protocol | string | The service protocol. | 
| Panorama.Services.Description | string | The service description. | 
| Panorama.Services.DestinationPort | string | The service destination port. | 
| Panorama.Services.SourcePort | string | The service source port. | 
| Panorama.Services.DeviceGroup | string | The device group for the service \(Panorama instances\). | 
| Panorama.Service.Tags | String | The service tags. | 

### pan-os-create-service
***
Creates a service.


#### Base Command

`pan-os-create-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for the new service. | Required | 
| protocol | The protocol for the new service. Possible values are: tcp, udp, sctp. | Required | 
| destination_port | The destination port  for the new service. | Required | 
| source_port | The source port for the new service. | Optional | 
| description | The description for the new service. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | The tags for the new service. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | The service name. | 
| Panorama.Services.Protocol | string | The service protocol. | 
| Panorama.Services.Descritpion | string | The service description. | 
| Panorama.Services.DestinationPort | string | The service destination port. | 
| Panorama.Services.SourcePort | string | The service source port. | 
| Panorama.Services.DeviceGroup | string | The device group for the service \(Panorama instances\). | 
| Panorama.Services.Tags | String | The service tags. | 

### pan-os-delete-service
***
Deletes a service.


#### Base Command

`pan-os-delete-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the service to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | The name of the deleted service. | 
| Panorama.Services.DeviceGroup | string | The device group for the service \(Panorama instances\). | 

### pan-os-list-service-groups
***
Returns a list of service groups.


#### Base Command

`pan-os-list-service-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tags for which to filter the Service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | The service group name. | 
| Panorama.ServiceGroups.Services | string | The service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | The device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | The service group tags. | 

### pan-os-get-service-group
***
Returns details for the specified service group.


#### Base Command

`pan-os-get-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The service group name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | The service group name. | 
| Panorama.ServiceGroups.Services | string | The service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | The device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | The service group tags. | 

### pan-os-create-service-group
***
Creates a service group.


#### Base Command

`pan-os-create-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The service group name. | Required | 
| services | The service group related services. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | The tags to filter service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | The service group name. | 
| Panorama.ServiceGroups.Services | string | The service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | The device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | The service group tags. | 

### pan-os-delete-service-group
***
Deletes a service group.


#### Base Command

`pan-os-delete-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the service group to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | The name of the deleted service group. | 
| Panorama.ServiceGroups.DeviceGroup | string | The device group for the service group \(Panorama instances\). | 

### pan-os-edit-service-group
***
Edits a service group.


#### Base Command

`pan-os-edit-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the service group to edit. | Required | 
| services_to_add | The services to add to the service group. Only existing service objects can be added. | Optional | 
| services_to_remove | The services to remove from the service group. Only existing Service objects can be removed. | Optional | 
| tags | The tag of the service group to edit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | The service group name. | 
| Panorama.ServiceGroups.Services | string | The service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | The device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | The service group tags. | 

### pan-os-get-custom-url-category
***
Returns information for a custom URL category.


#### Base Command

`pan-os-get-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The custom URL category name. | Required | 
| device-group | The device group for which to return addresses for the custom URL category (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | String | The category name of the custom URL. | 
| Panorama.CustomURLCategory.Description | String | The category description of the custom URL. | 
| Panorama.CustomURLCategory.Sites | String | The list of sites of the custom URL category. | 
| Panorama.CustomURLCategory.DeviceGroup | String | The device group for the custom URL Category \(Panorama instances\). | 
| Panorama.CustomURLCategory.Categories | String | The list of categories of the custom URL category. | 
| Panorama.CustomURLCategory.Type | String | The category type of the custom URL. | 

### pan-os-create-custom-url-category
***
Creates a custom URL category.


#### Base Command

`pan-os-create-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the custom URL category to create. | Required | 
| description | The description of the custom URL category to create. | Optional | 
| sites | The list of sites for the custom URL category. | Optional | 
| device-group | The device group for which to return addresses for the custom URL category (Panorama instances). | Optional | 
| type | The category type of the URL. Relevant from PAN-OS v9.x. Possible values are: URL List, Category Match. | Optional | 
| categories | The list of categories. Relevant from PAN-OS v9.x. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | String | The custom URL category name. | 
| Panorama.CustomURLCategory.Description | String | The custom URL category description. | 
| Panorama.CustomURLCategory.Sites | String | The custom URL category list of sites. | 
| Panorama.CustomURLCategory.DeviceGroup | String | The device group for the custom URL category \(Panorama instances\). | 
| Panorama.CustomURLCategory.Sites | String | The custom URL category list of categories. | 
| Panorama.CustomURLCategory.Type | String | The custom URL category type. | 

### pan-os-delete-custom-url-category
***
Deletes a custom URL category.


#### Base Command

`pan-os-delete-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the custom URL category to delete. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | string | The name of the custom URL category to delete. | 
| Panorama.CustomURLCategory.DeviceGroup | string | The device group for the Custom URL Category \(Panorama instances\). | 

### pan-os-edit-custom-url-category
***
Adds or removes sites to and from a custom URL category.


#### Base Command

`pan-os-edit-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the custom URL category to add or remove sites. | Required | 
| sites | A comma-separated list of sites to add to the custom URL category. | Optional | 
| action | Adds or removes sites or categories. Can be "add" or "remove". Possible values are: add, remove. | Required | 
| categories | A comma-separated list of categories to add to the custom URL category. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | string | The custom URL category name. | 
| Panorama.CustomURLCategory.Description | string | The custom URL category description. | 
| Panorama.CustomURLCategory.Sites | string | The custom URL category list of sites. | 
| Panorama.CustomURLCategory.DeviceGroup | string | The device group for the Custom URL Category \(Panorama instances\). | 

### url
***
Gets a URL category from URL filtering.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Category | String | The URL category. | 

### pan-os-get-url-category
***
Gets a URL category from URL filtering. This command is only available on firewall devices.


#### Base Command

`pan-os-get-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Category | String | The URL category. | 

### pan-os-get-url-category-from-cloud
***
Returns a URL category from URL filtering. This command is only available on firewall devices.


#### Base Command

`pan-os-get-url-category-from-cloud`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 

### pan-os-get-url-category-from-host
***
Returns a URL category from URL filtering. This command is only available on firewall devices.


#### Base Command

`pan-os-get-url-category-from-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 

### pan-os-get-url-filter
***
Returns information for a URL filtering rule.


#### Base Command

`pan-os-get-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | URL filter name. | Required | 
| device-group | The device group for which to return addresses for the URL filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | The URL filter name. | 
| Panorama.URLFilter.Category.Name | string | The URL filter category name. | 
| Panorama.URLFilter.Category.Action | string | The action for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | The URL filter override block list. | 
| Panorama.URLFilter.OverrideAllowList | string | The URL filter override allow list. | 
| Panorama.URLFilter.Description | string | The URL filter description. | 
| Panorama.URLFilter.DeviceGroup | string | The device group for the URL filter \(Panorama instances\). | 

### pan-os-create-url-filter
***
Creates a URL filtering rule.


#### Base Command

`pan-os-create-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the URL filter to create. | Required | 
| url_category | The URL category. | Required | 
| action | The action for the URL category. Can be "allow", "block", "alert", "continue", or "override". Possible values are: allow, block, alert, continue, override. | Required | 
| override_allow_list | The CSV list of URLs to exclude from the allow list. | Optional | 
| override_block_list | The CSV list of URLs to exclude from the blocked list. | Optional | 
| description | The URL filter description. | Optional | 
| device-group | The device group for which to return addresses for the URL filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | The URL filter name. | 
| Panorama.URLFilter.Category.Name | string | The URL filter category name. | 
| Panorama.URLFilter.Category.Action | string | The action for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | The URL filter override allow list. | 
| Panorama.URLFilter.OverrideBlockList | string | The URL filter override blocked list. | 
| Panorama.URLFilter.Description | string | The URL filter description. | 
| Panorama.URLFilter.DeviceGroup | string | The device group for the URL filter \(Panorama instances\). | 

### pan-os-edit-url-filter
***
Edits a URL filtering rule.


#### Base Command

`pan-os-edit-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the URL filter to edit. | Required | 
| element_to_change | The element to change. Possible values are: override_allow_list, override_block_list, allow_categories, block_categories, description. | Required | 
| element_value | The element value. Limited to one value. | Required | 
| add_remove_element | Adds or remove an element from the Allow List or Block List fields. Possible values are: add, remove. Default is add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | The URL filter name. | 
| Panorama.URLFilter.Description | string | The URL filter description. | 
| Panorama.URLFilter.Category.Name | string | The URL filter category. | 
| Panorama.URLFilter.Action | string | The action for the URL category. | 
| Panorama.URLFilter.OverrideAllowList | string | The allow list overrides for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | The block list overrides for the URL category. | 
| Panorama.URLFilter.DeviceGroup | string | The device group for the URL filter \(Panorama instances\). | 

### pan-os-delete-url-filter
***
Deletes a URL filtering rule.


#### Base Command

`pan-os-delete-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the URL filter rule to delete. | Required | 
| device-group | The device group for which to return addresses for the URL filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | The URL filter rule name. | 
| Panorama.URLFilter.DeviceGroup | string | The device group for the URL filter \(Panorama instances\). | 

### pan-os-list-edls
***
Returns a list of external dynamic lists.


#### Base Command

`pan-os-list-edls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | The name of the EDL. | 
| Panorama.EDL.Type | string | The type of EDL. | 
| Panorama.EDL.URL | string | The URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | The description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | The EDL certificate profile. | 
| Panorama.EDL.Recurring | string | The time interval the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | The device group for the EDL \(Panorama instances\). | 

### pan-os-get-edl
***
Returns information for an external dynamic list


#### Base Command

`pan-os-get-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the EDL. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | The name of the EDL. | 
| Panorama.EDL.Type | string | The type of EDL. | 
| Panorama.EDL.URL | string | The URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | The description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | The EDL certificate profile. | 
| Panorama.EDL.Recurring | string | The time interval the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | The device group for the EDL \(Panorama instances\). | 

### pan-os-create-edl
***
Creates an external dynamic list.


#### Base Command

`pan-os-create-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the EDL. | Required | 
| url | The URL from which to pull the EDL. | Required | 
| type | The type of EDL. Possible values are: ip, url, domain. | Required | 
| recurring | The time interval for pulling and updating the EDL. Possible values are: five-minute, hourly. | Required | 
| certificate_profile | The certificate profile name for the URL that was previously uploaded. to PAN OS. | Optional | 
| description | The description of the EDL. | Optional | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | The name of the EDL. | 
| Panorama.EDL.Type | string | The type of the EDL. | 
| Panorama.EDL.URL | string | The URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | The description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | The EDL certificate profile. | 
| Panorama.EDL.Recurring | string | The time interval the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | The device group for the EDL \(Panorama instances\). | 

### pan-os-edit-edl
***
Modifies an element of an external dynamic list.


#### Base Command

`pan-os-edit-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the external dynamic list to edit. | Required | 
| element_to_change | The element to change (“url”, “recurring”, “certificate_profile”, “description”). Possible values are: url, recurring, certificate_profile, description. | Required | 
| element_value | The element value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | The name of the EDL. | 
| Panorama.EDL.URL | string | The URL where the EDL is stored. | 
| Panorama.EDL.Description | string | The description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | The EDL certificate profile. | 
| Panorama.EDL.Recurring | string | The time interval the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | The device group for the EDL \(Panorama instances\). | 

### pan-os-delete-edl
***
Deletes an external dynamic list.


#### Base Command

`pan-os-delete-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the EDL to delete. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | The name of the EDL that was deleted. | 
| Panorama.EDL.DeviceGroup | string | The device group for the EDL \(Panorama instances\). | 

### pan-os-get-running-config
***
Pull the running config file


#### Base Command

`pan-os-get-running-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!pan-os-get-running-config target=00000000000```
#### Context Example
```json
{
    "File": {
        "EntryID": "3678@268ee30b-69fa-4496-8ab8-51cdeb19c452",
        "Info": "text/plain",
        "MD5": "da7faf4c6440d87a3e50ef93536ed81a",
        "Name": "running_config",
        "SHA1": "7910271adc8b3e9de28b804442a11a5160d4adda",
        "SHA256": "a4da4cbee7f3e411fbf76f2595d7dfcffce85bd6b3c000dac7a17e58747d1a2b",
        "SHA512": "e90d995061b5771f068c07e727ece3b57eeabdac424dabe8f420848e482e2ad18411c030bd4b455f589d8cdae9a1dae942bfef1ebd038104dd975e168cfb7d19",
        "SSDeep": "3072:KGH5vDQ4MEa4fM0EYRCmgQKQZyVlxgW0ITUj4MO2jCKH2:ZLMGyQKQZaw2",
        "Size": 1284823,
        "Type": "ASCII text, with very long lines"
    }
}
```


### pan-os-get-merged-config
***
Pull the merged config file


#### Base Command

`pan-os-get-merged-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The serial number of the device. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!pan-os-get-merged-config target=0000000000```
#### Context Example
```json
{
    "File": {
        "EntryID": "3682@268ee30b-69fa-4496-8ab8-51cdeb19c452",
        "Info": "text/plain",
        "MD5": "3204cc188e4b4a6616b449441d4d1ad4",
        "Name": "merged_config",
        "SHA1": "0b058a2ae4b595f80599ef0aeffda640ff386e95",
        "SHA256": "7178b16cb30880c93345ff80810af4e1428573a28d1ee354d5c79b03372cc027",
        "SHA512": "edf5b851eab40588e4e338071de3c18cc8d198d811ea0759670c0aa4c8028fa3b7870b9554c4b7d85f8429641d7cd6f6217a6b37500e24ad9c60b6cf39b39f3b",
        "SSDeep": "3072:OGH5vDQ4MEa4fM0EYRCmgQKQZyVlxDW0ITUj4MO2jCKH2:tLMGyQKQZtw2",
        "Size": 1322335,
        "Type": "ASCII text, with very long lines"
    }
}
```



### pan-os-refresh-edl
***
Refreshes the specified external dynamic list.


#### Base Command

`pan-os-refresh-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the EDL. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 
| edl_type | The type of the EDL. Required when refreshing an EDL object which is configured on Panorama. Possible values are: ip, url, domain. | Optional | 
| location | The location of the EDL. Required when refreshing an EDL object which is configured on Panorama. | Optional | 
| vsys | The VSYS of the EDL. Required when refreshing an EDL object which is configured on Panorama. | Optional | 


#### Context Output

There is no context output for this command.
### pan-os-create-rule
***
Creates a policy rule.


#### Base Command

`pan-os-create-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | The name of the rule to create. | Optional | 
| description | The description of the rule to create. | Optional | 
| action | The action for the rule. Can be "allow", "deny", or "drop". Possible values are: allow, deny, drop. | Required | 
| source | A comma-separated list of address object names, address group object names, or EDL object names. | Optional | 
| destination | A comma-separated list of address object names, address group object names, or EDL object names. | Optional | 
| source_zone | A comma-separated list of source zones. | Optional | 
| destination_zone | A comma-separated list of destination zones. | Optional | 
| negate_source | Whether to negate the source (address, address group). Can be "Yes" or "No". Possible values are: Yes, No. | Optional | 
| negate_destination | Whether to negate the destination (address, address group). Can be "Yes" or "No". Possible values are: Yes, No. | Optional | 
| service | A comma-separated list of service object names for the rule. | Optional | 
| disable | Whether to disable the rule. Can be "Yes" or "No". Possible values are: Yes, No. Default is No. | Optional | 
| application | A comma-separated list of application object names for the rule. to create. Default is any. | Optional | 
| source_user | The source user for the rule to create. Default is any. | Optional | 
| pre_post | The pre rule or post rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| target | The target firewall for the rule (Panorama instances). | Optional | 
| log_forwarding | The log forwarding profile. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 
| tags | The rule tags to create. | Optional | 
| category | A comma-separated list of URL categories. | Optional | 
| profile_setting | A profile setting group. | Optional | 
| where | Where to move the rule. Can be "before", "after", "top", or "bottom". If you specify "top" or "bottom", you need to supply the "dst" argument. Possible values are: before, after, top, bottom. Default is bottom. | Optional | 
| dst | The destination rule relative to the rule that you are moving. This field is only relevant if you specify "top" or "bottom" in the "where" argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | The rule name. | 
| Panorama.SecurityRule.Description | string | The rule description. | 
| Panorama.SecurityRule.Action | string | The action for the rule. | 
| Panorama.SecurityRule.Source | string | The source address. | 
| Panorama.SecurityRule.Destination | string | The destination address. | 
| Panorama.SecurityRule.NegateSource | boolean | Whether the source is negated \(address, address group\). | 
| Panorama.SecurityRule.NegateDestination | boolean | Whether the destination negated \(address, address group\). | 
| Panorama.SecurityRule.Service | string | The service for the rule. | 
| Panorama.SecurityRule.Disabled | string | Whether the rule is disabled. | 
| Panorama.SecurityRule.Application | string | The application for the rule. | 
| Panorama.SecurityRule.Target | string | The target firewall \(Panorama instances\). | 
| Panorama.SecurityRule.LogForwarding | string | The log forwarding profile \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | The device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRules.Tags | String | The rule tags. | 
| Panorama.SecurityRules.ProfileSetting | String | The profile setting group. | 

### pan-os-custom-block-rule
***
Creates a custom block policy rule.


#### Base Command

`pan-os-custom-block-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | The name of the custom block policy rule to create. | Optional | 
| object_type | The object type to block in the policy rule. Can be "ip", "address-group", "edl", or "custom-url-category". Possible values are: ip, address-group, application, url-category, edl. | Required | 
| object_value | A comma-separated list of object values for the object_type argument. | Required | 
| direction | The direction to block. Can be "to", "from", or "both". This argument is not applicable for the "custom-url-category" object_type. Possible values are: to, from, both. Default is both. | Optional | 
| pre_post | The pre rule or post rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| target | Specifies a target firewall for the rule (Panorama instances). | Optional | 
| log_forwarding | The log forwarding profile. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 
| tags | The tags to use for the custom block policy rule. | Optional | 
| where | Where to move the rule. Can be "before", "after", "top", or "bottom". If you specify "top" or "bottom", you need to supply the "dst" argument. Possible values are: before, after, top, bottom. Default is bottom. | Optional | 
| dst | The destination rule relative to the rule that you are moving. This field is only relevant if you specify "top" or "bottom" in the "where" argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | The rule name. | 
| Panorama.SecurityRule.Object | string | The blocked object. | 
| Panorama.SecurityRule.Direction | string | The direction blocked. | 
| Panorama.SecurityRule.Target | string | The target firewall \(Panorama instances\). | 
| Panorama.SecurityRule.LogForwarding | string | The log forwarding profile \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | The device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRule.Tags | String | The rule tags. | 
| Panorama.SecurityRules.ProfileSetting | String | The profile setting group. | 

### pan-os-move-rule
***
Changes the location of a policy rule.


#### Base Command

`pan-os-move-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | The name of the rule to move. | Required | 
| where | Where to move the rule. Can be "before", "after", "top", or "bottom". If you specify "top" or "bottom", you need to supply the "dst" argument. Possible values are: before, after, top, bottom. | Required | 
| dst | The destination rule relative to the rule that you are moving. This field is only relevant if you specify "top" or "bottom" in the "where" argument. | Optional | 
| pre_post | The rule location. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | The rule name. | 
| Panorama.SecurityRule.DeviceGroup | string | The device group for the rule \(Panorama instances\). | 

### pan-os-edit-rule
***
Edits a policy rule.


#### Base Command

`pan-os-edit-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | The name of the rule to edit. | Required | 
| element_to_change | The parameter in the security rule to change. Can be 'source', 'destination', 'application', 'action', 'category', 'description', 'disabled', 'target', 'log-forwarding', 'tag', 'source-user', 'service', or 'profile-setting'. Possible values are: source, destination, application, action, category, description, disabled, target, log-forwarding, tag, profile-setting, source-user, service. | Required | 
| element_value | The new value for the parameter. | Required | 
| pre_post | The pre rule or post rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| behaviour | Whether to replace, add, or remove the element_value from the current rule object value. Possible values are: replace, add, remove. Default is replace. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | The rule name. | 
| Panorama.SecurityRule.Description | string | The rule description. | 
| Panorama.SecurityRule.Action | string | The action for the rule. | 
| Panorama.SecurityRule.Source | string | The source address. | 
| Panorama.SecurityRule.Destination | string | The destination address. | 
| Panorama.SecurityRule.NegateSource | boolean | Whether the source is negated \(address, address group\). | 
| Panorama.SecurityRule.NegateDestination | boolean | Whether the destination is negated \(address, address group\). | 
| Panorama.SecurityRule.Service | string | The service for the rule. | 
| Panorama.SecurityRule.Disabled | string | Whether the rule is disabled. | 
| Panorama.SecurityRule.Application | string | The application for the rule. | 
| Panorama.SecurityRule.Target | string | The target firewall \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | The device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRule.Tags | String | The tags for the rule. | 

### pan-os-delete-rule
***
Deletes a policy rule.


#### Base Command

`pan-os-delete-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | The name of the rule to delete. | Required | 
| pre_post | The pre rule or post rule (Panorama instances). Possible values are: pre-rulebase, post-rulebase. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | The rule name. | 
| Panorama.SecurityRule.DeviceGroup | string | The device group for the rule \(Panorama instances\). | 

### pan-os-list-applications
***
Returns a list of applications.


#### Base Command

`pan-os-list-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| predefined | Whether to list predefined applications. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Applications.Name | string | The application name. | 
| Panorama.Applications.Id | number | The application ID. | 
| Panorama.Applications.Category | string | The application category. | 
| Panorama.Applications.SubCategory | string | The application sub-category. | 
| Panorama.Applications.Technology | string | The application technology. | 
| Panorama.Applications.Risk | number | The application risk \(1 to 5\). | 
| Panorama.Applications.Description | string | The application description. | 

### pan-os-commit-status
***
Returns commit status for a configuration.


#### Base Command

`pan-os-commit-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Commit.JobID | number | The job ID of the configuration to be committed. | 
| Panorama.Commit.Status | string | The commit status. | 
| Panorama.Commit.Details | string | The job ID details. | 
| Panorama.Commit.Warnings | String | The job ID warnings | 

### pan-os-push-status
***
Returns the push status for a configuration.


#### Base Command

`pan-os-push-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.DeviceGroup | string | The device group to which the policies were pushed. | 
| Panorama.Push.JobID | number | The job ID of the configuration to be pushed. | 
| Panorama.Push.Status | string | The push status. | 
| Panorama.Push.Details | string | The job ID details. | 
| Panorama.Push.Warnings | String | The job ID warnings | 

### pan-os-get-pcap
***
Returns information for a Panorama PCAP file. The recommended maximum file size is 5 MB. If the limit is exceeded, you may need to SSH the firewall and run the scp export command to export the PCAP file. See the Palo Alto Networks documentation.


#### Base Command

`pan-os-get-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pcapType | The type of packet capture. Possible values are: application-pcap, filter-pcap, threat-pcap, dlp-pcap. | Required | 
| serialNumber | The serial number of the firewall to download the PCAP from. | Optional | 
| from | The file name for the PCAP type ('dlp-pcap', 'filter-pcap', or 'application-pcap'). Required for 'filter-pcap'. | Optional | 
| localName | The new name for the PCAP file after downloading. If this argument is not specified, the file name is the PCAP file name set in the firewall. | Optional | 
| serialNo | The serial number for the request. See the Panorama XML API documentation. | Optional | 
| searchTime | The Search time for the request. For example: "2019/12/26 00:00:00", "2020/01/10". See the Panorama XML API documentation. Required for "threat-pcap". | Optional | 
| pcapID | The ID of the PCAP for the request. See the Panorama XML API documentation. Required for 'threat-pcap'. | Optional | 
| password | The password for Panorama, needed for the 'dlp-pcap' PCAP type only. | Optional | 
| deviceName | The device name on which the PCAP is stored. See the Panorama XML API documentation. Required for 'threat-pcap' in pan-os firewalls &lt; 9.0.7 versions. | Optional | 
| sessionID | The Session ID of the PCAP. See the Panorama XML API documentation. Required for 'threat-pcap' in pan-os firewalls &lt; 9.0.7 versions. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | The file size. | 
| File.Name | string | The file name. | 
| File.Type | string | The file type. | 
| File.Info | string | The file info. | 
| File.Extension | string | The file extension. | 
| File.EntryID | string | The file entryID. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.SHA512 | string | The SHA512 hash of the file. | 
| File.SSDeep | string | The SSDeep hash of the file. | 

### pan-os-list-pcaps
***
Returns a list of all PCAP files by PCAP type. Not available for threat PCAPs.


#### Base Command

`pan-os-list-pcaps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pcapType | The type of packet capture. Possible values are: application-pcap, filter-pcap, dlp-pcap. | Required | 
| serialNumber | The serial number of the firewall to download the PCAP from. | Optional | 
| password | The password for Panorama. Relevant for the 'dlp-pcap' PCAP type. | Optional | 


#### Context Output

There is no context output for this command.
### pan-os-register-ip-tag
***
Registers IP addresses to a tag.


#### Base Command

`pan-os-register-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | The tag for which to register IP addresses. | Required | 
| IPs | The IP addresses to register. | Required | 
| persistent | Whether the IP addresses remain registered to the tag after the device reboots ('true':persistent, 'false':non-persistent). Possible values are: true, false. Default is true. | Optional | 
| timeout | The timeout value to automatically unregister the IPs. Only applicable for PAN-OS 9.x and higher. Can not be used with persistent set to true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.DynamicTags.Tag | string | Name of the tag. | 
| Panorama.DynamicTags.IPs | string | Registered IP addresses. | 

### pan-os-unregister-ip-tag
***
Unregisters IP addresses from a tag.


#### Base Command

`pan-os-unregister-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to unregister IP addresses. | Required | 
| IPs | IP addresses to unregister. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-register-user-tag
***
Registers users to a tag. This command is only available for PAN-OS version 9.x and above.


#### Base Command

`pan-os-register-user-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to register users. | Required | 
| Users | A comma-separated list of users to register. | Required | 
| timeout | Timeout value to automatically unregister the users (in seconds). Only applicable to PAN-OS 9.x and higher. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.DynamicTags.Tag | string | The name of the tag. | 
| Panorama.DynamicTags.Users | string | The list of registered users. | 

### pan-os-unregister-user-tag
***
Unregisters users from a tag. This command is only available for PAN-OS version 9.x and higher.


#### Base Command

`pan-os-unregister-user-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | The tag from which to unregister users. | Required | 
| Users | A comma-separated list of users to unregister. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-list-rules
***
Returns a list of predefined Security Rules.


#### Base Command

`pan-os-list-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pre_post | The rules location. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tag to filter the rules. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | String | The rule name. | 
| Panorama.SecurityRule.Action | String | The action for the rule. | 
| Panorama.SecurityRule.Location | String | The rule location. | 
| Panorama.SecurityRule.Category | String | The rule category. | 
| Panorama.SecurityRule.Application | String | The application for the rule. | 
| Panorama.SecurityRule.Destination | String | The destination address. | 
| Panorama.SecurityRule.From | String | The rule from zone. | 
| Panorama.SecurityRule.Service | String | The service for the rule. | 
| Panorama.SecurityRule.To | String | The rule to zone. | 
| Panorama.SecurityRule.Source | String | The source address. | 
| Panorama.SecurityRule.DeviceGroup | string | The device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRules.Tags | String | The rule tags. | 

### pan-os-query-logs
***
The query logs in Panorama.


#### Base Command

`pan-os-query-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log-type | The log type. Can be "threat", "traffic", "wildfire", "url", or "data". Possible values are: threat, traffic, wildfire, url, data. | Required | 
| query | The query string by which to match criteria for the logs. This is similar to the query provided in the web interface under the Monitor tab when viewing the logs. | Optional | 
| time-generated | The time the log was generated from the timestamp and prior to it.<br/>For example "2019/08/11 01:10:44". | Optional | 
| addr-src | The source address. | Optional | 
| addr-dst | The destination address. | Optional | 
| ip | The source or destination IP address. | Optional | 
| zone-src | The source zone. | Optional | 
| zone-dst | The destination source. | Optional | 
| action | The rule action. | Optional | 
| port-dst | The destination port. | Optional | 
| rule | The rule name, for example "Allow all outbound". | Optional | 
| url | The URL, for example "safebrowsing.googleapis.com". | Optional | 
| filedigest | The file hash (for WildFire logs only). | Optional | 
| number_of_logs | The maximum number of logs to retrieve. If empty, the default is 100. The maximum is 5,000. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.JobID | String | The job ID of the logs query. | 
| Panorama.Monitor.Status | String | The status of the logs query. | 
| Panorama.Monitor.Message | String | The message of the logs query. | 

### pan-os-check-logs-status
***
Checks the status of a logs query.


#### Base Command

`pan-os-check-logs-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID of the query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.JobID | String | The job ID of the logs query. | 
| Panorama.Monitor.Status | String | The status of the logs query. | 

### pan-os-get-logs
***
Retrieves the data of a logs query.


#### Base Command

`pan-os-get-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID of the query. | Required | 
| ignore_auto_extract | Whether to auto-enrich the War Room entry. If "true", entry is not auto-enriched. If "false", entry is auto-extracted. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.Logs.Action | String | The action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", or "block-url". | 
| Panorama.Monitor.Logs.Application | String | The application associated with the session. | 
| Panorama.Monitor.Logs.Category | String | The URL category of the URL subtype. For WildFire subtype, it is the verdict on the file, and can be either "malicious", "phishing", "grayware", or "benign". For other subtypes, the value is "any". | 
| Panorama.Monitor.Logs.DeviceName | String | The hostname of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.DestinationAddress | String | The original session destination IP address. | 
| Panorama.Monitor.Logs.DestinationUser | String | The username of the user to which the session was destined. | 
| Panorama.Monitor.Logs.DestinationCountry | String | The destination country or internal region for private addresses. Maximum length is 32 bytes. | 
| Panorama.Monitor.Logs.DestinationPort | String | The destination port utilized by the session. | 
| Panorama.Monitor.Logs.FileDigest | String | Only for the WildFire subtype, all other types do not use this field. The filedigest string shows the binary hash of the file sent to be analyzed by the WildFire service. | 
| Panorama.Monitor.Logs.FileName | String | File name or file type when the subtype is file.
File name when the subtype is virus.
File name when the subtype is wildfire-virus.
File name when the subtype is wildfire. | 
| Panorama.Monitor.Logs.FileType | String | Only for the WildFire subtype, all other types do not use this field.
Specifies the type of file that the firewall forwarded for WildFire analysis. | 
| Panorama.Monitor.Logs.FromZone | String | The zone from which the session was sourced. | 
| Panorama.Monitor.Logs.URLOrFilename | String | The actual URL when the subtype is url.
The file name or file type when the subtype is file.
The file name when the subtype is virus.
The file name when the subtype is wildfire-virus.
The file name when the subtype is wildfire.
The URL or file name when the subtype is vulnerability \(if applicable\). | 
| Panorama.Monitor.Logs.NATDestinationIP | String | The post-NAT destination IP address if destination NAT was performed. | 
| Panorama.Monitor.Logs.NATDestinationPort | String | The post-NAT destination port. | 
| Panorama.Monitor.Logs.NATSourceIP | String | The post-NAT source IP address if source NAT was performed. | 
| Panorama.Monitor.Logs.NATSourcePort | String | The post-NAT source port. | 
| Panorama.Monitor.Logs.PCAPid | String | The packet capture \(pcap\) ID is a 64 bit unsigned integral denoting
an ID to correlate threat pcap files with extended pcaps taken as a part of
that flow. All threat logs will contain either a pcap_id of 0 \(no associated
pcap\), or an ID referencing the extended pcap file. | 
| Panorama.Monitor.Logs.IPProtocol | String | The IP protocol associated with the session. | 
| Panorama.Monitor.Logs.Recipient | String | Only for the WildFire subtype, all other types do not use this field.
Specifies the name of the receiver of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.Rule | String | The name of the rule that the session matched. | 
| Panorama.Monitor.Logs.RuleID | String | The ID of the rule that the session matched. | 
| Panorama.Monitor.Logs.ReceiveTime | String | The time the log was received at the management plane. | 
| Panorama.Monitor.Logs.Sender | String | Only for the WildFire subtype; all other types do not use this field.
Specifies the name of the sender of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.SessionID | String | An internal numerical identifier applied to each session. | 
| Panorama.Monitor.Logs.DeviceSN | String | The serial number of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.Severity | String | The severity associated with the threat. Can be "informational", "low",
"medium", "high", or "critical". | 
| Panorama.Monitor.Logs.SourceAddress | String | The original session source IP address. | 
| Panorama.Monitor.Logs.SourceCountry | String | The source country or internal region for private addresses. Maximum
length is 32 bytes. | 
| Panorama.Monitor.Logs.SourceUser | String | The username of the user who initiated the session. | 
| Panorama.Monitor.Logs.SourcePort | String | The source port utilized by the session. | 
| Panorama.Monitor.Logs.ThreatCategory | String | The threat categories used to classify different types of
threat signatures. | 
| Panorama.Monitor.Logs.Name | String | The Palo Alto Networks identifier for the threat. A description
string followed by a 64-bit numerical identifier. | 
| Panorama.Monitor.Logs.ID | String | The Palo Alto Networks ID for the threat. | 
| Panorama.Monitor.Logs.ToZone | String | The zone to which the session was destined. | 
| Panorama.Monitor.Logs.TimeGenerated | String | The time the log was generated on the data plane. | 
| Panorama.Monitor.Logs.URLCategoryList | String | A list of the URL filtering categories the firewall used to
enforce the policy. | 
| Panorama.Monitor.Logs.Bytes | String | The total log bytes. | 
| Panorama.Monitor.Logs.BytesReceived | String | The log bytes received. | 
| Panorama.Monitor.Logs.BytesSent | String | The log bytes sent. | 
| Panorama.Monitor.Logs.Vsys | String | The VSYS on the firewall that generated the log. | 

### pan-os-security-policy-match
***
Checks whether a session matches a specified security policy. This command is only available on firewall instances.


#### Base Command

`pan-os-security-policy-match`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application | The application name. | Optional | 
| category | The category name. | Optional | 
| destination | The destination IP address. | Required | 
| destination-port | The destination port. | Optional | 
| from | The from zone. | Optional | 
| to | The to zone. | Optional | 
| protocol | The IP protocol value. | Required | 
| source | The source IP address. | Required | 
| source-user | The source user. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 
| vsys | The target VSYS of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityPolicyMatch.Query | String | The query for the session to test. | 
| Panorama.SecurityPolicyMatch.Rules.Name | String | The matching rule name. | 
| Panorama.SecurityPolicyMatch.Rules.Action | String | The matching rule action. | 
| Panorama.SecurityPolicyMatch.Rules.Category | String | The matching rule category. | 
| Panorama.SecurityPolicyMatch.Rules.Destination | String | The matching rule destination. | 
| Panorama.SecurityPolicyMatch.Rules.From | String | The matching rule from zone. | 
| Panorama.SecurityPolicyMatch.Rules.Source | String | The matching rule source. | 
| Panorama.SecurityPolicyMatch.Rules.To | String | The matching rule to zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.Application | String | The application name. | 
| Panorama.SecurityPolicyMatch.QueryFields.Category | String | The category name. | 
| Panorama.SecurityPolicyMatch.QueryFields.Destination | String | The destination IP address. | 
| Panorama.SecurityPolicyMatch.QueryFields.DestinationPort | Number | The destination port. | 
| Panorama.SecurityPolicyMatch.QueryFields.From | String | The query fields from zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.To | String | The query fields to zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.Protocol | String | The IP protocol value. | 
| Panorama.SecurityPolicyMatch.QueryFields.Source | String | The destination IP address. | 
| Panorama.SecurityPolicyMatch.QueryFields.SourceUser | String | The source user. | 

### pan-os-list-static-routes
***
Lists the static routes of a virtual router.


#### Base Command

`pan-os-list-static-routes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | The name of the virtual router for which to list the static routes. | Required | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 
| show_uncommitted | Whether to show an uncommitted configuration. Default is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of a static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 
| Panorama.StaticRoutes.Uncommitted | Boolean | Whether the static route is committed. | 

### pan-os-get-static-route
***
Returns the specified static route of a virtual router.


#### Base Command

`pan-os-get-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | The name of the virtual router to display the static route. | Required | 
| static_route | The name of the static route to display. | Required | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 

### pan-os-add-static-route
***
Adds a static route.


#### Base Command

`pan-os-add-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | Virtual router to which the routes will be added. | Required | 
| static_route | The name of the static route to add. The argument is limited to a maximum of 31 characters, is case-sensitive, and supports letters, numbers, spaces, hyphens, and underscores. | Required | 
| destination | The IP address and network mask in Classless Inter-domain Routing (CIDR) notation: ip_address/mask. For example, 192.168.0.1/24 for IPv4 or 2001:db8::/32 for IPv6). | Required | 
| nexthop_type | The type for the next hop. Can be: "ip-address", "next-vr", "fqdn", or "discard". Possible values are: ip-address, next-vr, fqdn, discard. | Required | 
| nexthop_value | The next hop value. | Required | 
| metric | The metric port for the static route (1-65535). | Optional | 
| interface | The interface name in which to add the static route. | Optional | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 

### pan-os-delete-static-route
***
Deletes a static route.


#### Base Command

`pan-os-delete-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| route_name | The name of the static route to delete. | Required | 
| virtual_router | The virtual router from which the routes will be deleted. | Required | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route to delete. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
| Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
| Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
| Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
| Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
| Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 
| Panorama.StaticRoutes.Deleted | Boolean | Whether the static route was deleted. | 

### pan-os-show-device-version
***
Show firewall device software version.


#### Base Command

`pan-os-show-device-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The serial number of the target device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Device.Info.Devicename | String | The device name of the PAN-OS. | 
| Panorama.Device.Info.Model | String | The model of the PAN-OS. | 
| Panorama.Device.Info.Serial | String | The serial number of the PAN-OS. | 
| Panorama.Device.Info.Version | String | The version of the PAN-OS. | 

### pan-os-download-latest-content-update
***
Downloads the latest content update.


#### Base Command

`pan-os-download-latest-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device to which to download the content update. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Download.JobID | String | The job ID of the content download. | 
| Panorama.Content.Download.Status | String | The content download status. | 

### pan-os-content-update-download-status
***
Checks the download status of a content update.


#### Base Command

`pan-os-content-update-download-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device to which the content update is downloading. | Optional | 
| job_id | The job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Download.JobID | String | The job ID to monitor. | 
| Panorama.Content.Download.Status | String | The download status. | 
| Panorama.Content.Download.Details | String | The job ID details. | 

### pan-os-install-latest-content-update
***
Installs the latest content update.


#### Base Command

`pan-os-install-latest-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device on which to install the content update. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | String | The job ID of the installation. | 
| Content.Install.Status | String | The installation status. | 

### pan-os-content-update-install-status
***
Gets the installation status of the content update.


#### Base Command

`pan-os-content-update-install-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device on which to check the installation status of the content update. | Optional | 
| job_id | The job ID of the content installation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | String | The job ID of the content installation. | 
| Panorama.Content.Install.Status | String | The content installation status. | 
| Panorama.Content.Install.Details | String | The content installation status details. | 

### pan-os-check-latest-panos-software
***
Checks the PAN-OS software version from the repository.


#### Base Command

`pan-os-check-latest-panos-software`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the PAN-OS software version. | Optional | 


#### Context Output

There is no context output for this command.
### pan-os-download-panos-version
***
Downloads the target PAN-OS software version to install on the target device.


#### Base Command

`pan-os-download-panos-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to download the PAN-OS software version. | Optional | 
| target_version | The target version number to install. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Download.JobID | number | The job ID of the PAN-OS download. | 
| Panorama.PANOS.Download.Status | String | The status of the PAN-OS download. | 

### pan-os-download-panos-status
***
Gets the download status of the target PAN-OS software.


#### Base Command

`pan-os-download-panos-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the download status. | Optional | 
| job_id | The job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Download.JobID | string | The job ID of the PAN-OS download. | 
| Panorama.PANOS.Download.Status | String | The PAN-OS download status. | 
| Panorama.PANOS.Download.Details | String | The PAN-OS download details. | 

### pan-os-install-panos-version
***
Installs the target PAN-OS version on the specified target device.


#### Base Command

`pan-os-install-panos-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device on which to install the target PAN-OS software version. | Optional | 
| target_version | The target PAN-OS version to install. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Install.JobID | string | The job ID of the PAN-OS installation. | 
| Panorama.PANOS.Install.Status | String | The status of the PAN-OS installation. | 

### pan-os-install-panos-status
***
Gets the installation status of the PAN-OS software.


#### Base Command

`pan-os-install-panos-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the installation status. | Optional | 
| job_id | The job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Install.JobID | number | The job ID of the PAN-OS installation. | 
| Panorama.PANOS.Install.Status | String | The status of the PAN-OS installation. | 
| Panorama.PANOS.Install.Details | String | The PAN-OS installation details. | 

### pan-os-device-reboot
***
Reboots the firewall device.


#### Base Command

`pan-os-device-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device on which to reboot the firewall. | Optional | 


#### Context Output

There is no context output for this command.
### pan-os-show-location-ip
***
Gets location information for an IP address.


#### Base Command

`pan-os-show-location-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address from which to return information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Location.IP.country_code | String | The IP address location country code. | 
| Panorama.Location.IP.country_name | String | The IP address location country name. | 
| Panorama.Location.IP.ip_address | String | The IP address. | 
| Panorama.Location.IP.Status | String | Whether the IP address was found. | 

### pan-os-get-licenses
***
Gets information about available PAN-OS licenses and their statuses.


#### Base Command

`pan-os-get-licenses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.License.Authcode | String | The authentication code of the license. | 
| Panorama.License.Base-license-name | String | The base license name. | 
| Panorama.License.Description | String | The description of the license. | 
| Panorama.License.Expired | String | Whether the license has expired. | 
| Panorama.License.Expires | String | When the license will expire. | 
| Panorama.License.Feature | String | The feature of the license. | 
| Panorama.License.Issued | String | When the license was issued. | 
| Panorama.License.Serial | String | The serial number of the license. | 

### pan-os-get-security-profiles
***
Gets information for the specified security profile.


#### Base Command

`pan-os-get-security-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_profile | The security profile for which to get information. Can be "data-filtering", "file-blocking", "spyware", "url-filtering", "virus", "vulnerability", or "wildfire-analysis". Possible values are: data-filtering, file-blocking, spyware, url-filtering, virus, vulnerability, wildfire-analysis. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Spyware.Name | String | The profile name. | 
| Panorama.Spyware.Rules.Action | String | The rule action. | 
| Panorama.Spyware.Rules.Category | String | The category for which to apply the rule. | 
| Panorama.Spyware.Rules.Name | String | The rule name. | 
| Panorama.Spyware.Rules.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Spyware.Rules.Severity | String | The rule severity. | 
| Panorama.Spyware.Rules.Threat-name | String | The threat name to apply for the rule. | 
| Panorama.URLFilter.Name | String | The profile name. | 
| Panorama.URLFilter.Rules.Category.Action | String | The rule action to apply to the category. | 
| Panorama.URLFilter.Rules.Category.Name | String | The category name. | 
| Panorama.WildFire.Name | String | The WildFire profile name. | 
| Panorama.WildFire.Rules.Analysis | String | The rule analysis. | 
| Panorama.WildFire.Rules.Application | String | The application to apply for the rule. | 
| Panorama.WildFire.Rules.File-type | String | The file type to apply for the rule. | 
| Panorama.WildFire.Rules.Name | String | The rule name. | 
| Panorama.Vulnerability.Name | String | The vulnerability profile name. | 
| Panorama.Vulnerability.Rules.Vendor-id | String | The vendor ID to apply for the rule. | 
| Panorama.Vulnerability.Rules.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Vulnerability.Rules.Host | String | The rule host. | 
| Panorama.Vulnerability.Rules.Name | String | The rule name. | 
| Panorama.Vulnerability.Rules.Category | String | The category to apply for the rule. | 
| Panorama.Vulnerability.Rules.CVE | String | The CVE to apply for the rule. | 
| Panorama.Vulnerability.Rules.Action | String | The rule action. | 
| Panorama.Vulnerability.Rules.Severity | String | The rule severity. | 
| Panorama.Vulnerability.Rules.Threat-name | String | The threat to apply for the rule. | 
| Panorama.Antivirus.Name | String | The antivirus profile name. | 
| Panorama.Antivirus.Rules.Action | String | The rule action. | 
| Panorama.Antivirus.Rules.Name | String | The rule name. | 
| Panorama.Antivirus.Rules.WildFire-action | String | The WildFire action. | 
| Panorama.FileBlocking.Name | String | The file blocking profile name. | 
| Panorama.FileBlocking.Rules.Action | String | The rule action. | 
| Panorama.FileBlocking.Rules.Application | String | The application to apply for the rule. | 
| Panorama.FileBlocking.Rules.File-type | String | The file type to apply for the rule. | 
| Panorama.FileBlocking.Rules.Name | String | The rule name. | 
| Panorama.DataFiltering.Name | String | The data filtering profile name. | 
| Panorama.DataFiltering.Rules.Alert-threshold | String | The alert threshold. | 
| Panorama.DataFiltering.Rules.Application | String | The application to apply for the rule. | 
| Panorama.DataFiltering.Rules.Block-threshold | String | The block threshold. | 
| Panorama.DataFiltering.Rules.Data-object | String | The data object. | 
| Panorama.DataFiltering.Rules.Direction | String | The rule direction. | 
| Panorama.DataFiltering.Rules.File-type | String | The file type to apply for the rule. | 
| Panorama.DataFiltering.Rules.Log-severity | String | The log severity. | 
| Panorama.DataFiltering.Rules.Name | String | The rule name. | 

### pan-os-apply-security-profile
***
Applies a security profile to specific rules or rules with a specific tag.


#### Base Command

`pan-os-apply-security-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_type | The security profile type. Can be 'data-filtering', 'file-blocking', 'spyware', 'url-filtering', 'virus, 'vulnerability', or wildfire-analysis.'. Possible values are: data-filtering, file-blocking, spyware, url-filtering, virus, vulnerability, wildfire-analysis. | Required | 
| rule_name | The rule name to apply. | Required | 
| profile_name | The profile name to apply to the rule. | Required | 
| pre_post | The location of the rules. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 


#### Context Output

There is no context output for this command.
### pan-os-get-ssl-decryption-rules
***
Gets SSL decryption rules.


#### Base Command

`pan-os-get-ssl-decryption-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pre_post | The location of the rules. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. Possible values are: pre-rulebase, post-rulebase. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SSLRule.From | String | The SSL rule from the source. | 
| Panorama.SSLRule.Name | String | The name of the SSL rule. | 
| Panorama.SSLRule.Destination | String | The destination of the SSL rule. | 
| Panorama.SSLRule.Target | String | The target of the SSL rule. | 
| Panorama.SSLRule.Service | String | The SSL rule service. | 
| Panorama.SSLRule.Action | String | The SSL rule action. | 
| Panorama.SSLRule.Type | String | The SSL rule type. | 
| Panorama.SSLRule.Source | String | The source of the SSL rule. | 
| Panorama.SSLRule.To | String | The SSL rule to destination. | 
| Panorama.SSLRule.UUID | String | The SSL rule UUID. | 
| Panorama.SSLRule.Description | String | The SSL rule description. | 
| Panorama.SSLRule.Source-user | String | The SSL rule source user. | 
| Panorama.SSLRule.Category | String | The SSL rule category. | 

### pan-os-get-wildfire-configuration
***
Retrieves the Wildfire configuration.


#### Base Command

`pan-os-get-wildfire-configuration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.WildFire.Name | String | The file type. | 
| Panorama.WildFire.Size-limit | String | The file size limit. | 
| Panorama.WildFire.recurring | String | The schedule that is recurring. | 

### pan-os-url-filtering-block-default-categories
***
Sets default categories to block in the URL filtering profile.


#### Base Command

`pan-os-url-filtering-block-default-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The URL filtering profile name. Gets the name by running the get-security-profiles command. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-get-anti-spyware-best-practice
***
Get anti-spyware best practices.


#### Base Command

`pan-os-get-anti-spyware-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Spyware.BotentDomain.Name | String | The botnet domain name. | 
| Panorama.Spyware.BotentDomain.Action | String | The botnet domain action. | 
| Panorama.Spyware.BotentDomain.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Spyware.BotentDomain.Sinkhole.ipv4-address | String | The botnet domain IPv4 address. | 
| Panorama.Spyware.BotentDomain.Sinkhole.ipv6-address | String | The Botnet domain IPv6 address. | 
| Panorama.Spyware.Rule.Category | String | The rule category. | 
| Panorama.Spyware.Rule.Action | String | The rule action. | 
| Panorama.Spyware.Rule.Name | String | The rule name. | 
| Panorama.Spyware.Rule.Severity | String | The rule severity. | 
| Panorama.Spyware.Rule.Threat-name | String | The rule threat name. | 
| Panorama.Spyware.BotentDomain.Max_version | String | The botnet domain max version. | 

### pan-os-apply-dns-signature-policy
***
Enables assigning EDL to the anti-spyware profile under "DNS Signature Policies".


#### Base Command

`pan-os-apply-dns-signature-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| anti_spyware_profile_name | The name of the anti spyware profile. If the profile exists, the command will operate on it, otherwise, if a new name is given, a new anti-spyware profile will be created. | Required | 
| dns_signature_source | The EDL name to link to the profile. | Required | 
| action | The action on the DNS queries. Possible values are: alert, allow, block, sinkhole. | Required | 
| packet_capture | Allows capturing packets on match. Select "single-packet" to capture the first packet of the session or "extended-capture" to set between 1-50 packets. Packet capture can be very CPU intensive and can degrade firewall performance. Only use this feature when necessary and make sure you turn it off after you collect the required packets. Possible values are: disable, single-packet, extended-capture. Default is disable. | Optional | 


#### Context Output

There is no context output for this command.
### pan-os-get-file-blocking-best-practice
***
Gets file-blocking best practices.


#### Base Command

`pan-os-get-file-blocking-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.FileBlocking.Rule.Action | String | The rule action. | 
| Panorama.FileBlocking.Rule.Application | String | The rule application. | 
| Panorama.FileBlocking.Rule.File-type | String | The rule file type. | 
| Panorama.FileBlocking.Rule.Name | String | The rule name. | 

### pan-os-get-antivirus-best-practice
***
Gets anti-virus best practices.


#### Base Command

`pan-os-get-antivirus-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Antivirus.Decoder.Action | String | The rule action. | 
| Panorama.Antivirus.Decoder.Name | String | The rule name. | 
| Panorama.Antivirus.Decoder.WildFire-action | String | The WildFire action. | 

### pan-os-get-vulnerability-protection-best-practice
***
Gets vulnerability-protection best practices.


#### Base Command

`pan-os-get-vulnerability-protection-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Vulnerability.Rule.Action | String | The rule action. | 
| Panorama.Vulnerability.Rule.CVE | String | The rule CVE. | 
| Panorama.Vulnerability.Rule.Category | String | The rule category. | 
| Panorama.Vulnerability.Rule.Host | String | The rule host. | 
| Panorama.Vulnerability.Rule.Name | String | The rule name. | 
| Panorama.Vulnerability.Rule.Severity | String | The rule severity. | 
| Panorama.Vulnerability.Rule.Threat-name | String | The threat name. | 
| Panorama.Vulnerability.Rule.Vendor-id | String | The vendor ID. | 

### pan-os-get-wildfire-best-practice
***
Views WildFire best practices.


#### Base Command

`pan-os-get-wildfire-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.WildFire.Analysis | String | The WildFire analysis. | 
| Panorama.WildFire.Application | String | The WildFire application. | 
| Panorama.WildFire.File.File-size | String | The recommended file size. | 
| Panorama.WildFire.File.Name | String | The file name. | 
| Panorama.WildFire.File-type | String | The WildFire profile file type. | 
| Panorama.WildFire.Name | String | The WildFire profile name. | 
| Panorama.WildFire.SSLDecrypt | String | The SSL decrypt content. | 
| Panorama.WildFire.Schedule.Action | String | The WildFire schedule action. | 
| Panorama.WildFire.Schedule.Recurring | String | The WildFire schedule recurring. | 

### pan-os-get-url-filtering-best-practice
***
Views URL filtering best practices.


#### Base Command

`pan-os-get-url-filtering-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Category.Action | String | The action to perform on the category. | 
| Panorama.URLFilter.Category.Name | String | The category name. | 
| Panorama.URLFilter.DeviceGroup | String | The device group name. | 
| Panorama.URLFilter.Name | String | The profile name. | 
| Panorama.URLFilter.Header.log-container-page-only | String | The log container page only. | 
| Panorama.URLFilter.Header.log-http-hdr-referer | String | The log HTTP header referrer. | 
| Panorama.URLFilter.Header.log-http-hdr-user | String | The log HTTP header user. | 
| Panorama.URLFilter.Header.log-http-hdr-xff | String | The log HTTP header xff. | 

### pan-os-enforce-wildfire-best-practice
***
Enforces Wildfire best practices to upload files to the maximum size, forwards all file types, and updates the schedule.


#### Base Command

`pan-os-enforce-wildfire-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template name. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-create-antivirus-best-practice-profile
***
Creates an antivirus best practice profile.


#### Base Command

`pan-os-create-antivirus-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile to create. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-create-anti-spyware-best-practice-profile
***
Creates an Anti-Spyware best practice profile.


#### Base Command

`pan-os-create-anti-spyware-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name to create. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-create-vulnerability-best-practice-profile
***
Creates a vulnerability protection best practice profile.


#### Base Command

`pan-os-create-vulnerability-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-create-url-filtering-best-practice-profile
***
Creates a URL filtering best practice profile.


#### Base Command

`pan-os-create-url-filtering-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-create-file-blocking-best-practice-profile
***
Creates a file blocking best practice profile.


#### Base Command

`pan-os-create-file-blocking-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-create-wildfire-best-practice-profile
***
Creates a WildFire analysis best practice profile.


#### Base Command

`pan-os-create-wildfire-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile. | Required | 


#### Context Output

There is no context output for this command.
### pan-os-show-user-id-interfaces-config
***
Shows the user ID interface configuration.


#### Base Command

`pan-os-show-user-id-interfaces-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template to use when running the command. Overrides the template parameter (Panorama instances). If not given, will use the integration parameter. | Optional | 
| template_stack | The template stack to use when running the command. | Optional | 
| vsys | The name of the virtual system to be configured. Will use the configured VSYS parameter if exists. If given a value, will override the VSYS parameter. If neither the VSYS parameter and this argument are entered, will default to 'vsys1'. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.UserInterfaces.Name | String | The name of the user interface. | 
| Panorama.UserInterfaces.Zone | String | The zone to which the interface is connected. | 
| Panorama.UserInterfaces.EnableUserIdentification | String | Whether user identification is enabled. | 

### pan-os-show-zones-config
***
Shows the zones configuration.


#### Base Command

`pan-os-show-zones-config`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template to use when running the command. Overrides the template parameter (Panorama instances). If not given, will use the integration parameter. | Optional | 
| template_stack | The template stack to use when running the command. | Optional | 
| vsys | The name of the virtual system to be configured. Will use the configured VSYS parameter if it exists. If given a value, will override the VSYS parameter. If neither the VSYS parameter and this argument are entered, will default to 'vsys1'. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Zone.Name | String | The name of the zone. | 
| Panorama.Zone.Network | String | The network to which the zone is connected. | 
| Panorama.Zone.EnableUserIdentification | String | Whether user identification is enabled. | 
| Panorama.Zone.ZoneProtectionProfile | String | The zone protection profile. | 
| Panorama.Zone.LogSetting | String | The log setting for the zone. | 

### pan-os-list-configured-user-id-agents
***
Retrieves a list of user-ID agents configured in the system.


#### Base Command

`pan-os-list-configured-user-id-agents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template to use when running the command. Overrides the template parameter (Panorama instances). If not given, will use the integration parameter. | Optional | 
| template_stack | The template stack to use when running the command. | Optional | 
| vsys | The name of the virtual system to be configured. Will use the configured VSYS parameter if it exists. If given a value, will override the VSYS parameter. If neither the VSYS parameter and this argument are entered, will default to 'vsys1'. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.UserIDAgents.Name | String | The user ID agent name. | 
| Panorama.UserIDAgents.Host | String | The user ID agent host. | 
| Panorama.UserIDAgents.Port | Number | The user ID agent port. | 
| Panorama.UserIDAgents.LdapProxy | String | Whether LDAP proxy is used in the user ID agent. | 
| Panorama.UserIDAgents.NtlmAuth | String | Whether NLTM authentication is used in the user ID agent. | 
| Panorama.UserIDAgents.EnableHipCollection | String | Whether HIP collection is enabled in the user ID agent. | 
| Panorama.UserIDAgents.IpUserMapping | String | Whether IP user mapping is enabled in the user ID agent. | 
| Panorama.UserIDAgents.SerialNumber | Unknown | The serial number associated with the user ID agent. | 
| Panorama.UserIDAgents.CollectorName | String | The user ID agent collector name. | 
| Panorama.UserIDAgents.Secret | String | The user ID agent secret. | 
| Panorama.UserIDAgents.Disabled | String | Whether the user ID agent is disbaled. | 

### pan-os-upload-content-update-file
***
Uploads a content file to Panorama.


#### Base Command

`pan-os-upload-content-update-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | Entry ID of the file to upload. | Required | 
| category | The category of the content. Possible values are: wildfire, anti-virus, content. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Upload.Status | string | The content upload status. | 
| Panorama.Content.Upload.Message | string | The content upload message. | 

### pan-os-install-file-content-update
***
Installs a specific content update file.


#### Base Command

`pan-os-install-file-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| version_name | The update file name to be installed on PAN-OS. | Required | 
| category | The category of the content. Possible values are: wildfire, anti-virus, content. | Required | 
| skip_validity_check | Skips the file validity check with the PAN-OS update server. Use this option for air-gapped networks and only if you trust the content file. Possible values are: yes, no. Default is no. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | string | The job ID of the installation. | 
| Panorama.Content.Install.Status | string | The installation status. | 

### pan-os-platform-get-arp-tables
***
Gets all ARP tables from all firewalls in the topology.


#### Base Command

`pan-os-platform-get-arp-tables`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ShowArp.Summary.hostid | String | The ID of the PAN-OS host. | 
| PANOS.ShowArp.Summary.max | String | The maximum number of supported ARP entries. | 
| PANOS.ShowArp.Summary.total | String | The total number of current ARP entries. | 
| PANOS.ShowArp.Summary.timeout | String | The ARP entry timeout. | 
| PANOS.ShowArp.Summary.dp | String | The firewall dataplane associated with the entry. | 
| PANOS.ShowArp.Result.hostid | String | The ID of the PAN-OS host. | 
| PANOS.ShowArp.Result.interface | String | The network interface learned ARP entry. | 
| PANOS.ShowArp.Result.ip | String | The layer 3 address. | 
| PANOS.ShowArp.Result.mac | String | The layer 2 address. | 
| PANOS.ShowArp.Result.port | String | The network interface matching entry. | 
| PANOS.ShowArp.Result.status | String | The ARP entry status. | 
| PANOS.ShowArp.Result.ttl | String | The time to live. | 

### pan-os-platform-get-route-summary
***
Pulls all route summary information from the topology.


#### Base Command

`pan-os-platform-get-route-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ShowRouteSummary.Summary.hostid | Number | The ID of the PAN-OS host. | 
| PANOS.ShowRouteSummary.Summary.total | Number | The total number of routes. | 
| PANOS.ShowRouteSummary.Summary.limit | Number | The maximum number of routes for the platform. | 
| PANOS.ShowRouteSummary.Summary.active | Number | The active routes in the routing table. | 

### pan-os-platform-get-routes
***
Pulls all route summary information from the topology.


#### Base Command

`pan-os-platform-get-routes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ShowRoute.Summary.hostid | String | The ID of the PAN-OS host. | 
| PANOS.ShowRoute.Summary.interface | String | The next hop interface. | 
| PANOS.ShowRoute.Summary.route_count | Number | The total number of routes seen on the virtual router interface. | 
| PANOS.ShowRoute.Result.hostid | String | The ID of the PAN-OS host. | 
| PANOS.ShowRoute.Result.virtual_router | String | The virtual router this route belongs to. | 
| PANOS.ShowRoute.Result.destination | String | The network destination of the route. | 
| PANOS.ShowRoute.Result.nexthop | String | The next hop to the destination. | 
| PANOS.ShowRoute.Result.metric | String | The route metric. | 
| PANOS.ShowRoute.Result.flags | String | The route flags. | 
| PANOS.ShowRoute.Result.age | Number | The age of the route. | 
| PANOS.ShowRoute.Result.interface | String | The next hop interface. | 
| PANOS.ShowRoute.Result.route_table | String | The route table this route belongs to. | 

### pan-os-platform-get-system-info
***
Gets information from all PAN-OS systems in the topology.


#### Base Command

`pan-os-platform-get-system-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ShowSystemInfo.Summary.hostid | String | The ID of the PAN-OS host. | 
| PANOS.ShowSystemInfo.Summary.ip_address | String | The management IP address. | 
| PANOS.ShowSystemInfo.Summary.sw_version | String | The system software version. | 
| PANOS.ShowSystemInfo.Summary.family | String | The platform family. | 
| PANOS.ShowSystemInfo.Summary.model | String | The platform model. | 
| PANOS.ShowSystemInfo.Summary.uptime | String | The total system uptime. | 
| PANOS.ShowSystemInfo.Summary.hostname | String | The system hostname. | 
| PANOS.ShowSystemInfo.Result.hostid | String | The ID of the PAN-OS host. | 
| PANOS.ShowSystemInfo.Result.ip_address | String | The management IP address. | 
| PANOS.ShowSystemInfo.Result.netmask | String | The management netmask. | 
| PANOS.ShowSystemInfo.Result.mac_address | String | The management MAC address. | 
| PANOS.ShowSystemInfo.Result.uptime | String | The total system uptime. | 
| PANOS.ShowSystemInfo.Result.family | String | The platform family. | 
| PANOS.ShowSystemInfo.Result.model | String | The platform model. | 
| PANOS.ShowSystemInfo.Result.sw_version | String | The system software version. | 
| PANOS.ShowSystemInfo.Result.operational_mode | String | The xurrent operational mode. | 
| PANOS.ShowSystemInfo.Result.ipv6_address | String | The management IPv6 address. | 
| PANOS.ShowSystemInfo.Result.default_gateway | String | The management default gateway. | 
| PANOS.ShowSystemInfo.Result.public_ip_address | String | The firewall public IP address. | 
| PANOS.ShowSystemInfo.Result.hostname | String | The device hostname. | 
| PANOS.ShowSystemInfo.Result.av_version | String | The system anti-virus version. | 
| PANOS.ShowSystemInfo.Result.av_release_date | String | The release date of the antivirus content. | 
| PANOS.ShowSystemInfo.Result.app_version | String | The app content version. | 
| PANOS.ShowSystemInfo.Result.app_release_date | String | The release date of the application content. | 
| PANOS.ShowSystemInfo.Result.threat_version | String | The threat content version. | 
| PANOS.ShowSystemInfo.Result.threat_release_date | String | The release date of the threat content. | 
| PANOS.ShowSystemInfo.Result.wildfire_version | String | The Wildfire content version. | 
| PANOS.ShowSystemInfo.Result.wildfire_release_date | String | The Wildfire release date. | 
| PANOS.ShowSystemInfo.Result.url_filtering_version | String | The URL filtering content version. | 

### pan-os-platform-get-device-groups
***
Gets the operational information of the device groups in the topology.


#### Base Command

`pan-os-platform-get-device-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.DeviceGroupOp.hostid | String | The ID of the PAN-OS host. | 
| PANOS.DeviceGroupOp.serial | String | The serial number of the firewall. | 
| PANOS.DeviceGroupOp.connected | String | Whether the firewall is currently connected. | 
| PANOS.DeviceGroupOp.hostname | String | The firewall hostname. | 
| PANOS.DeviceGroupOp.last_commit_all_state_sp | String | The state of the last commit. | 
| PANOS.DeviceGroupOp.name | String | The device group name. | 

### pan-os-platform-get-template-stacks
***
Gets the operational information of the template stacks in the topology.


#### Base Command

`pan-os-platform-get-template-stacks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.TemplateStackOp.hostid | String | The ID of the PAN-OS host. | 
| PANOS.TemplateStackOp.serial | String | The serial number of the firewall. | 
| PANOS.TemplateStackOp.connected | String | Whether the firewall is currently connected. | 
| PANOS.TemplateStackOp.hostname | String | The firewall hostname. | 
| PANOS.TemplateStackOp.last_commit_all_state_tpl | String | The state of the last commit. | 
| PANOS.TemplateStackOp.name | String | The template stack name. | 

### pan-os-platform-get-global-counters
***
Gets global counter information from all the PAN-OS firewalls in the topology.


#### Base Command

`pan-os-platform-get-global-counters`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ShowCounters.Summary.hostid | String | The host ID. | 
| PANOS.ShowCounters.Summary.name | String | The human readable counter name. | 
| PANOS.ShowCounters.Summary.value | Number | The current counter value. | 
| PANOS.ShowCounters.Summary.rate | Number | The packets per second rate. | 
| PANOS.ShowCounters.Summary.desc | String | The human readable counter description. | 
| PANOS.ShowCounters.Result.hostid | String | The host ID. | 
| PANOS.ShowCounters.Result.category | String | The counter category. | 
| PANOS.ShowCounters.Result.name | String | The human readable counter name. | 
| PANOS.ShowCounters.Result.value | Number | The current counter value. | 
| PANOS.ShowCounters.Result.rate | Number | The packets per second rate. | 
| PANOS.ShowCounters.Result.aspect | String | The PAN-OS aspect. | 
| PANOS.ShowCounters.Result.desc | String | The human readable counter description. | 
| PANOS.ShowCounters.Result.id | String | The counter ID. | 
| PANOS.ShowCounters.Result.severity | String | The counter severity. | 

### pan-os-platform-get-bgp-peers
***
Retrieves all BGP peer information from the PAN-OS firewalls in the topology.


#### Base Command

`pan-os-platform-get-bgp-peers`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ShowBGPPeers.Summary.hostid | String | The host ID | 
| PANOS.ShowBGPPeers.Summary.peer | String | The name of the Border Gateway Protocol \(BGP\) peer. | 
| PANOS.ShowBGPPeers.Summary.status | String | The peer connection status. | 
| PANOS.ShowBGPPeers.Summary.incoming_accepted | String | The total number of accepted routes from the peer. | 
| PANOS.ShowBGPPeers.Result.hostid | String | The host ID. | 
| PANOS.ShowBGPPeers.Result.peer | String | The name of the Border Gateway Protocol \(BGP\) peer. | 
| PANOS.ShowBGPPeers.Result.vr | String | The virtual router in which the peer resides. | 
| PANOS.ShowBGPPeers.Result.remote_as | String | The remote AS \(Autonomous System\) of the peer. | 
| PANOS.ShowBGPPeers.Result.status | String | The peer connection status. | 
| PANOS.ShowBGPPeers.Result.peer_address | String | The IP address and port of the peer. | 
| PANOS.ShowBGPPeers.Result.local_address | String | The local router address and port. | 
| PANOS.ShowBGPPeers.Result.incoming_total | String | The total incoming routes from the peer. | 
| PANOS.ShowBGPPeers.Result.incoming_accepted | String | The total accepted routes from the peer. | 
| PANOS.ShowBGPPeers.Result.incoming_rejected | String | The total rejected routes from peer | 
| PANOS.ShowBGPPeers.Result.policy_rejected | String | The total routes rejected by the peer by policy. | 
| PANOS.ShowBGPPeers.Result.outgoing_total | String | The total routes advertised to the peer. | 
| PANOS.ShowBGPPeers.Result.outgoing_advertised | String | The number of advertised routes to the peer. | 

### pan-os-platform-get-available-software
***
Checks the devices for software that is available to be installed.


#### Base Command

`pan-os-platform-get-available-software`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.SoftwareVersions.Summary.hostid | String | The host ID. | 
| PANOS.SoftwareVersions.Summary.version | String | The software version in Major.Minor.Maint format. | 
| PANOS.SoftwareVersions.Summary.filename | String | The software version filename. | 
| PANOS.SoftwareVersions.Summary.size | String | The size of the software in MB. | 
| PANOS.SoftwareVersions.Summary.size_kb | String | The size of the software in KB. | 
| PANOS.SoftwareVersions.Summary.release_notes | String | The link to version release notes on PAN knowledge base. | 
| PANOS.SoftwareVersions.Summary.downloaded | Boolean | True if the software version is present on the system. | 
| PANOS.SoftwareVersions.Summary.current | Boolean | True if this is the currently installed software on the system. | 
| PANOS.SoftwareVersions.Summary.latest | Boolean | True if this is the most recently released software for this platform. | 
| PANOS.SoftwareVersions.Summary.uploaded | Boolean | True if the software version has been uploaded to the system. | 

### pan-os-platform-get-ha-state
***
Gets the HA state and associated details from the given device and any other details.


#### Base Command

`pan-os-platform-get-ha-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.HAState.hostid | String | The host ID. | 
| PANOS.HAState.active | Boolean | Whether this is the active firewall in a pair. "True" if standalone as well. | 
| PANOS.HAState.status | String | The string HA status. | 
| PANOS.HAState.peer | String | The HA peer. | 

### pan-os-platform-get-jobs
***
Gets all the jobs from the devices in the environment, or a single job when the ID is specified.


#### Base Command

`pan-os-platform-get-jobs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. | Optional | 
| status | The filter to return jobs by status. | Optional | 
| job_type | The filter to return jobs by type. | Optional | 
| id | The filter to return jobs by ID. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.JobStatus.hostid | String | The host ID. | 
| PANOS.JobStatus.id | String | The ID of the job. | 
| PANOS.JobStatus.type | String | The job type. | 
| PANOS.JobStatus.tfin | String | The time the job finished. | 
| PANOS.JobStatus.status | String | The status of the job. | 
| PANOS.JobStatus.result | String | The result of the job. | 
| PANOS.JobStatus.user | String | The user who initiated the job. | 
| PANOS.JobStatus.tenq | String | The time the job was queued into the system. | 
| PANOS.JobStatus.stoppable | String | Whether the job can be stopped after it started. | 
| PANOS.JobStatus.description | String | The job description. | 
| PANOS.JobStatus.positionInQ | String | The position of the job in the current job queue. | 
| PANOS.JobStatus.progress | String | The numerical progress of the job. | 

### pan-os-platform-download-software
***
Downloads the provided software version onto the device.


#### Base Command

`pan-os-platform-download-software`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| version | The software version to upgrade to, for example, 9.1.2. | Required | 
| device_filter_string | The string by which to filter the results to only install to specific devices or serial numbers. | Optional | 
| sync | If provided, runs the download synchronously. Make sure 'execution-timeout' is increased. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.DownloadStatus.Summary.hostid | String | The host ID. | 
| PANOS.DownloadStatus.Summary.started | String | Whether the download process started. | 

### pan-os-platform-reboot
***
Reboots the given device by host ID. Warning: This command has no confirmation and the device will immediately reboot. This command can be disruptive.



#### Base Command

`pan-os-platform-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The serial number, or IP address for a Panorama instance, to reboot. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.RestartStatus.Summary.hostid | String | The host ID | 
| PANOS.RestartStatus.Summary.started | String | Whether the download process started. | 

### pan-os-platform-get-system-status
***
Checks the status of the given device, checking whether it's up or down and if the operational mode is normal.


#### Base Command

`pan-os-platform-get-system-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The serial number, or IP address for a Panorama instance, to reboot. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.SystemStatus.hostid | String | The host ID. | 
| PANOS.SystemStatus.up | String | Whether the host device is up or still unavailable. | 

### pan-os-platform-update-ha-state
***
Checks the status of the given device, checking whether it's up or down and if the operational mode is normal.


#### Base Command

`pan-os-platform-update-ha-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The serial number, or IP address for a Panorama instance, to reboot. | Required | 
| state | The new state. Possible values are: functional, peer, suspend. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.HAStateUpdate.hostid | String | The host ID. | 
| PANOS.HAStateUpdate.state | String | The new HA state. | 

### pan-os-hygiene-check-log-forwarding
***
Checks that at least one log forwarding profile is configured according to best practices.


#### Base Command

`pan-os-hygiene-check-log-forwarding`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter so that only the given device is checked. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Summary.description | String | The description of the hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.issue_code | String | The shorthand code for this hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.result | String | Whether the check passed or failed. | 
| PANOS.ConfigurationHygiene.Summary.issue_count | Number | The total number of matching issues. | 
| PANOS.ConfigurationHygiene.Result.hostid | String | The host ID. | 
| PANOS.ConfigurationHygiene.Result.container_name | String | The parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygiene.Result.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygiene.Result.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygiene.Result.name | String | The affected object name. | 

### pan-os-hygiene-check-vulnerability-profiles
***
Checks the configured vulnerability profiles to ensure at least one meets best practices.


#### Base Command

`pan-os-hygiene-check-vulnerability-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter so that only the given device is checked. | Optional | 
| minimum_block_severities | A comma-separated list of severities that must be in drop/reset/block-ip mode. Default is critical,high. | Optional | 
| minimum_alert_severities | A comma-separated list of severities that must be in alert/default or higher mode. Default is medium,low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Summary.description | String | The description of the hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.issue_code | String | The shorthand code for this hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.result | String | Whether the check passed or failed. | 
| PANOS.ConfigurationHygiene.Summary.issue_count | Number | The total number of matching issues. | 
| PANOS.ConfigurationHygiene.Result.hostid | String | The host ID. | 
| PANOS.ConfigurationHygiene.Result.container_name | String | The parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygiene.Result.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygiene.Result.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygiene.Result.name | String | The affected object name. | 

### pan-os-platform-install-software
***
Installs the given software version onto the device. Downloads the software first with panorama-download-panos-version.


#### Base Command

`pan-os-platform-install-software`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| version | Software version to upgrade to, for example: 9.1.2. | Required | 
| device_filter_string | The string by which to filter to only install to specific devices or serial numbers. | Optional | 
| sync | If provided, runs the download synchronously. Make sure 'execution-timeout' is increased. | Optional | 
| target | The target number of the firewall. Used only on a Panorama instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.InstallStatus.Summary.hostid | String | The host ID. | 
| PANOS.InstallStatus.Summary.started | String | Whether the download process has started. | 

### pan-os-hygiene-check-spyware-profiles
***
Checks the configured anti-spyware profiles to ensure at least one meets best practices.


#### Base Command

`pan-os-hygiene-check-spyware-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string by which to filter to only check given devices. | Optional | 
| minimum_block_severities | A CSV list of severities that must be in drop/reset/block-ip mode. Default is critical,high. | Optional | 
| minimum_alert_severities | A CSV list of severities that must be in alert/default or higher mode. Default is medium,low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Summary.description | String | The description of the check. | 
| PANOS.ConfigurationHygiene.Summary.issue_code | String | The shorthand code for this hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.result | String | Whether the check passed or failed. | 
| PANOS.ConfigurationHygiene.Summary.issue_count | String | The total number of matching issues. | 
| PANOS.ConfigurationHygiene.Result.hostid | String | The host ID. | 
| PANOS.ConfigurationHygiene.Result.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygiene.Result.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygiene.Result.description | String | The human readable description of issue. | 
| PANOS.ConfigurationHygiene.Result.name | String | The affected object name. | 

### pan-os-hygiene-check-url-filtering-profiles
***
Checks the configured URL filtering profiles to ensure at least one meets best practices.


#### Base Command

`pan-os-hygiene-check-url-filtering-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string to filter to only check a given device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Summary.description | String | The description of the check. | 
| PANOS.ConfigurationHygiene.Summary.issue_code | String | The shorthand code for this hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.result | String | Whether the check passed or failed. | 
| PANOS.ConfigurationHygiene.Summary.issue_count | String | The total number of matching issues. | 
| PANOS.ConfigurationHygiene.Result.hostid | String | The host ID. | 
| PANOS.ConfigurationHygiene.Result.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygiene.Result.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygiene.Result.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygiene.Result.name | String | The affected object name. | 

### pan-os-hygiene-conforming-url-filtering-profiles
***
Returns a list of existing PANOS URL filtering objects that conform to best practices.


#### Base Command

`pan-os-hygiene-conforming-url-filtering-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string to filter to only check a given device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.PanosObject.hostid | String | The host ID. | 
| PANOS.PanosObject.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.PanosObject.name | String | The PAN-OS object name. | 
| PANOS.PanosObject.object_type | String | The PAN-OS-Python object type. | 

### pan-os-hygiene-conforming-spyware-profiles
***
Returns all anti-spyware profiles that conform to best practices.


#### Base Command

`pan-os-hygiene-conforming-spyware-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string to filter to only check a given device. | Optional | 
| minimum_block_severities | A CSV list of severities that must be in drop/reset/block-ip mode. Default is critical,high. | Optional | 
| minimum_alert_severities | A CSV list of severities that must be in alert/default or higher mode. Default is medium,low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.PanosObject.hostid | String | The host ID. | 
| PANOS.PanosObject.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.PanosObject.name | String | The PAN-OS object name. | 
| PANOS.PanosObject.object_type | String | The PAN-OS-Python object type. | 

### pan-os-hygiene-conforming-vulnerability-profiles
***
Returns all vulnerability profiles that conform to best practices.


#### Base Command

`pan-os-hygiene-conforming-vulnerability-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string to filter to only check a given device. | Optional | 
| minimum_block_severities | A CSV list of severities that must be in drop/reset/block-ip mode. Default is critical,high. | Optional | 
| minimum_alert_severities | A CSV list of severities that must be in alert/default or higher mode. Default is medium,low. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.PanosObject.hostid | String | The host ID. | 
| PANOS.PanosObject.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.PanosObject.name | String | The PAN-OS object name. | 
| PANOS.PanosObject.object_type | String | The PAN-OS-Python object type. | 

### pan-os-hygiene-check-security-zones
***
Checks that configured security zones have correct settings.


#### Base Command

`pan-os-hygiene-check-security-zones`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string to filter to only check a given device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Summary.description | String | The description of the check. | 
| PANOS.ConfigurationHygiene.Summary.issue_code | String | The shorthand code for this hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.result | String | Whether the check passed or failed. | 
| PANOS.ConfigurationHygiene.Summary.issue_count | String | The total number of matching issues. | 
| PANOS.ConfigurationHygiene.Result.hostid | String | The host ID. | 
| PANOS.ConfigurationHygiene.Result.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygiene.Result.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygiene.Result.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygiene.Result.name | String | The affected object name. | 

### pan-os-hygiene-check-security-rules
***
Checks that security rules are configured correctly.


#### Base Command

`pan-os-hygiene-check-security-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_filter_string | The string to filter to only check a given device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Summary.description | String | The description of the check. | 
| PANOS.ConfigurationHygiene.Summary.issue_code | String | The shorthand code for this hygiene check. | 
| PANOS.ConfigurationHygiene.Summary.result | String | Whether the check passed or failed. | 
| PANOS.ConfigurationHygiene.Summary.issue_count | String | The total number of matching issues. | 
| PANOS.ConfigurationHygiene.Result.hostid | String | The host ID. | 
| PANOS.ConfigurationHygiene.Result.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygiene.Result.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygiene.Result.description | String | The human readable description of issue. | 
| PANOS.ConfigurationHygiene.Result.name | String | The affected object name. | 

### pan-os-hygiene-fix-log-forwarding
***
Fixes log forwarding issues identified by pan-os-hygiene-check-log-forwarding.


#### Base Command

`pan-os-hygiene-fix-log-forwarding`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue | The Dictionary of Hygiene issue, from a hygiene check command. Can be a list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygieneFix.hostid | String | The host ID. | 
| PANOS.ConfigurationHygieneFix.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygieneFix.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygieneFix.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygieneFix.name | String | The affected object name. | 

### pan-os-hygiene-fix-security-zone-log-settings
***
Fixes security zones that are configured without a valid log forwarding profile.


#### Base Command

`pan-os-hygiene-fix-security-zone-log-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue | The Dictionary of Hygiene issue, from a hygiene check command. Can be a list. | Required | 
| log_forwarding_profile_name | The name of the log forwarding profile to set. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygieneFix.hostid | String | The host ID | 
| PANOS.ConfigurationHygieneFix.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygieneFix.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygieneFix.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygieneFix.name | String | The affected object name. | 

### pan-os-hygiene-fix-security-rule-log-settings
***
Fixes security rules that have incorrect log settings by adding a log forwarding profile and setting.


#### Base Command

`pan-os-hygiene-fix-security-rule-log-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue | The Dictionary of Hygiene issue, from a hygiene check command. Can be list. | Required | 
| log_forwarding_profile_name | The name of the log forwarding profile. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygieneFix.hostid | String | The host ID. | 
| PANOS.ConfigurationHygieneFix.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygieneFix.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygieneFix.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygieneFix.name | String | The affected object name. | 

### pan-os-hygiene-fix-security-rule-profile-settings
***
Fixes security rules that have incorrect log settings by adding a log forwarding profile and setting.


#### Base Command

`pan-os-hygiene-fix-security-rule-profile-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue | The Dictionary of Hygiene issue, from a hygiene check command. Can be list. | Required | 
| security_profile_group_name | The name of the security profile group to use as the log setting. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.ConfigurationHygieneFix.hostid | String | The host ID. | 
| PANOS.ConfigurationHygieneFix.container_name | String | What parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.ConfigurationHygieneFix.issue_code | String | The shorthand code for the issue. | 
| PANOS.ConfigurationHygieneFix.description | String | The human readable description of the issue. | 
| PANOS.ConfigurationHygieneFix.name | String | The affected object name. | 

### pan-os-config-get-object
***
Searches and returns a reference for the given object type and name. If no name is provided, all objects of the given type will be returned. Note this ONLY returns the object name and its location in the configuration hierachy, not the entire object.


#### Base Command

`pan-os-config-get-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The type of object to search. See https://pandevice.readthedocs.io/en/latest/module-objects.html. Possible values are: AddressObject, AddressGroup, ServiceGroup, ServiceObject, ApplicationObject, ApplicationGroup, LogForwardingProfile, SecurityProfileGroup, SecurityRule, NatRule. | Required | 
| device_filter_string | If provided, only objects from the given device are returned. | Optional | 
| object_name | The name of the object reference to return if looking for a specific object. Supports regex if "use_regex" is set. | Optional | 
| parent | The parent vsys or device group to search. If not provided, all will be returned. | Optional | 
| use_regex | Enables regex matching on an object name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOS.PanosObject.hostid | String | Host ID. | 
| PANOS.PanosObject.container_name | String | The parent container \(DG, Template, VSYS\) this object belongs to. | 
| PANOS.PanosObject.name | String | The PAN-OS object name. | 
| PANOS.PanosObject.object_type | String | The PAN-OS python object type. | 

### pan-os-platform-get-device-state
***
Get the device state from the provided device. Note; This will attempt to connect directly to the provided target to get the device state. If the IP address as reported in "show system info" is unreachable, this command will fail.


#### Base Command

`pan-os-platform-get-device-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Serial number of the device from which to fetch the device state. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | Filename. | 
| InfoFile.EntryID | String | Entry ID. | 
| InfoFile.Size | String | Size of the file. | 
| InfoFile.Type | String | Type of the file. | 
| InfoFile.Info | String | Basic information of the file. | 
