This integration supports both Palo Alto Networks Panorama and Palo Alto Networks Firewall. You can create separate instances of each integration, and they are not necessarily related or dependent on one another.
Manage Palo Alto Networks Firewall and Panorama. For more information see Panorama documentation.
This integration was integrated and tested with version 8.1.0 and 9.0.1 of Palo Alto Firewall, Palo Alto Panorama

## Panorama Playbook
* **PanoramaCommitConfiguration** : Based on the playbook input, the Playbook will commit the configuration to Palo Alto Firewall, or push the configuration from Panorama to predefined device groups of firewalls. The integration is available from Demisto v3.0, but playbook uses the GenericPooling sub-playbook, which is only available from Demisto v4.0.
* **Panorama Query Logs** : Wraps several commands (listed below) with genericPolling to enable a complete flow to query the following log types: traffic, threat, URL, data-filtering, and Wildfire.
   * [panorama-query-logs](#panorama-query-logs)
   * [panorama-check-logs-status](#panorama-check-logs-status)
   * [panorama-get-logs](#panorama-get-logs)
* PAN-OS DAG Configuration
* PAN-OS EDL Setup

## Use Cases
* Create custom security rules in Palo Alto Networks PAN-OS.
* Creating and updating address objects, address-groups, custom URL categories, URL filtering objects.
* Use the URL Filtering category information from Palo Alto Networks to enrich URLs by checking the *use_url_filtering* parameter. A valid license for the Firewall is required.
* Get URL Filtering category information from Palo Alto - Request Change is a known Palo Alto limitation.
* Add URL filtering objects including overrides to Palo Alto Panorama and Firewall.
* Committing configuration to Palo Alto FW and to Panorama, and pushing configuration from Panorama to Pre-Defined Device-Groups of Firewalls.
* Block IP addresses using registered IP tags from PAN-OS without committing the PAN-OS instance. First you have to create a registered IP tag, DAG, and security rule, and commit the instance. You can then register additional IP addresses to the tag without committing the instance.

   i. Create a registered IP tag and add the necessary IP addresses by running the [panorama-register-ip-tag](#panorama-register-ip-tag) command.
   
   ii. Create a dynamic address group (DAG), by running the [panorama-create-address-group](#panorama-create-address-group) command. Specify values for the following arguments: type="dynamic", match={ tagname }.
   
   iii. Create a security rule using the DAG created in the previous step, by running the [panorama-create-rule](#panorama-create-rule) command.
   
   iv. Commit the PAN-OS instance by running the PanoramaCommitConfiguration playbook.
   
   v. You can now register IP addresses to, or unregister IP addresses from, the IP tag by running the [panorama-register-ip-tag](#panorama-register-ip-tag) command, or [panorama-unregister-ip-tag command](#panorama-unregister-ip-tag), respectively, without committing the PAN-OS instance.

* Create a predefined security profiles with the best practices by Palo Alto Networks.
* Get security profiles best practices as defined by Palo Alto Networks. For more inforamtion about Palo Alto Networks best practices, visit [Palo Alto Networks best practices](https://docs.paloaltonetworks.com/best-practices/9-0/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles).
* Apply security profiles to specific rule.
* Set default categories to block in the URL filtering profile.
* Enforce WildFire best practice.
   
   i. Set file upload to the maximum size.
   ii. WildFire Update Schedule is set to download and install updates every minute.
   iii. All file types are forwarded.

## Known Limitations
* Maximum commit queue length is 3. Running numerous Panorama commands simultaneously might cause errors.
* After you run `panorama-create-` commands and the object is not committed, then the `panorama-edit` commands or `panorama-get` commands might not run correctly.
* URL Filtering `request change` of a URL is not available via the API. Instead, you need to use the https://urlfiltering.paloaltonetworks.com website.
* If you do not specify a vsys (Firewall instances) or a device group (Panorama instances), you will only be able to execute certain commands.
   * [panorama-get-url-category](#panorama-get-url-category)
   * [panorama-commit](#panorama-commit)
   * [panorama-push-to-device-group](#panorama-push-to-device-group)
   * [panorama-register-ip-tag](#panorama-register-ip-tag)
   * [panorama-unregister-ip-tag](#panorama-unregister-ip-tag)
   * [panorama-query-logs](#panorama-query-logs)
   * [panorama-check-logs-status](#panorama-check-logs-status)
   * [panorama-get-logs](#panorama-get-logs)

## Configure Panorama on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Panorama.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g., https://192.168.0.1\) | True |
| port | Port \(e.g 443\) | False |
| key | API Key | True |
| device_group | Device group - Panorama instances only \(write shared for Shared location\) | False |
| vsys | Vsys - Firewall instances only | False |
| template | Template - Panorama instances only | False |
| use_url_filtering | Use URL Filtering for auto enrichment | False |
| additional_suspicious | URL Filtering Additional suspicious categories. CSV list of categories that will be considered suspicious. | False |
| additional_malicious | URL Filtering Additional malicious categories. CSV list of categories that will be considered malicious. | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
   

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. [Run any command supported in the Panorama API: panorama](#panorama)
2. [Get pre-defined threats list from a Firewall or Panorama and stores as a JSON file in the context: panorama-get-predefined-threats-list](#panorama-get-predefined-threats-list)
3. [Commit a configuration: panorama-commit](#panorama-commit)
4. [Pushes rules from PAN-OS to the configured device group: panorama-push-to-device-group](#panorama-push-to-device-group)
5. [Returns a list of addresses: panorama-list-addresses](#panorama-list-addresses)
6. [Returns address details for the supplied address name: panorama-get-address](#panorama-get-address)
7. [Creates an address object: panorama-create-address](#panorama-create-address)
8. [Delete an address object: panorama-delete-address](#panorama-delete-address)
9. [Returns a list of address groups: panorama-list-address-groups](#panorama-list-address-groups)
10. [Get details for the specified address group: panorama-get-address-group](#panorama-get-address-group)
11. [Creates a static or dynamic address group: panorama-create-address-group](#panorama-create-address-group)
12. [Sets a vulnerability signature to block mode: panorama-block-vulnerability](#panorama-block-vulnerability)
13. [Deletes an address group: panorama-delete-address-group](#panorama-delete-address-group)
14. [Edits a static or dynamic address group: panorama-edit-address-group](#panorama-edit-address-group)
15. [Returns a list of addresses: panorama-list-services](#panorama-list-services)
16. [Returns service details for the supplied service name: panorama-get-service](#panorama-get-service)
17. [Creates a service: panorama-create-service](#panorama-create-service)
18. [Deletes a service: panorama-delete-service](#panorama-delete-service)
19. [Returns a list of service groups: panorama-list-service-groups](#panorama-list-service-groups)
20. [Returns details for the specified service group: panorama-get-service-group](#panorama-get-service-group)
21. [Creates a service group: panorama-create-service-group](#panorama-create-service-group)
22. [Deletes a service group: panorama-delete-service-group](#panorama-delete-service-group)
23. [Edit a service group: panorama-edit-service-group](#panorama-edit-service-group)
24. [Returns information for a custom URL category: panorama-get-custom-url-category](#panorama-get-custom-url-category)
25. [Creates a custom URL category: panorama-create-custom-url-category](#panorama-create-custom-url-category)
26. [Deletes a custom URL category: panorama-delete-custom-url-category](#panorama-delete-custom-url-category)
27. [Adds or removes sites to and from a custom URL category: panorama-edit-custom-url-category](#panorama-edit-custom-url-category)
28. [Gets a URL category from URL Filtering: panorama-get-url-category](#panorama-get-url-category)
29. [Gets a URL information: url](#url)
30. [Returns a URL category from URL Filtering in the cloud: panorama-get-url-category-from-cloud](#panorama-get-url-category-from-cloud)
31. [Returns a URL category from URL Filtering on the host: panorama-get-url-category-from-host](#panorama-get-url-category-from-host)
32. [Returns information for a URL filtering rule: panorama-get-url-filter](#panorama-get-url-filter)
33. [Creates a URL filtering rule: panorama-create-url-filter](#panorama-create-url-filter)
34. [Edit a URL filtering rule: panorama-edit-url-filter](#panorama-edit-url-filter)
35. [Deletes a URL filtering rule: panorama-delete-url-filter](#panorama-delete-url-filter)
36. [Returns a list of external dynamic lists: panorama-list-edls](#panorama-list-edls)
37. [Returns information for an external dynamic list: panorama-get-edl](#panorama-get-edl)
38. [Creates an external dynamic list: panorama-create-edl](#panorama-create-edl)
39. [Modifies an element of an external dynamic list: panorama-edit-edl](#panorama-edit-edl)
40. [Deletes an external dynamic list: panorama-delete-edl](#panorama-delete-edl)
41. [Refreshes the specified external dynamic list: panorama-refresh-edl](#panorama-refresh-edl)
42. [Creates a policy rule: panorama-create-rule](#panorama-create-rule)
43. [Creates a custom block policy rule: panorama-custom-block-rule](#panorama-custom-block-rule)
44. [Changes the location of a policy rule: panorama-move-rule](#panorama-move-rule)
45. [Edits a policy rule: panorama-edit-rule](#panorama-edit-rule)
46. [Deletes a policy rule: panorama-delete-rule](#panorama-delete-rule)
47. [Returns a list of applications: panorama-list-applications](#panorama-list-applications)
48. [Returns commit status for a configuration: panorama-commit-status](#panorama-commit-status)
49. [Returns the push status for a configuration: panorama-push-status](#panorama-push-status)
50. [Returns information for a Panorama PCAP file: panorama-get-pcap](#panorama-get-pcap)
51. [Returns a list of all PCAP files by PCAP type: panorama-list-pcaps](#panorama-list-pcaps)
52. [Registers IP addresses to a tag: panorama-register-ip-tag](#panorama-register-ip-tag)
53. [Unregisters IP addresses from a tag: panorama-unregister-ip-tag](#panorama-unregister-ip-tag)
54. [Registers Users to a tag: panorama-register-user-tag](#panorama-register-user-tag)
55. [Unregisters Users from a tag: panorama-unregister-user-tag](#panorama-unregister-user-tag)
56. [Deprecated. Queries traffic logs: panorama-query-traffic-logs](#panorama-query-traffic-logs)
57. [Deprecated. Checks the query status of traffic logs: panorama-check-traffic-logs-status](#panorama-check-traffic-logs-status)
58. [Deprecated. Retrieves traffic log query data by job id: panorama-get-traffic-logs](#panorama-get-traffic-logs)
59. [Returns a list of predefined Security Rules: panorama-list-rules](#panorama-list-rules)
60. [Query logs in Panorama: panorama-query-logs](#panorama-query-logs)
61. [Checks the status of a logs query: panorama-check-logs-status](#panorama-check-logs-status)
62. [Retrieves the data of a logs query: panorama-get-logs](#panorama-get-logs)
63. [Checks whether a session matches the specified security policy: panorama-security-policy-match](#panorama-security-policy-match)
64. [Lists the static routes of a virtual router: panorama-list-static-routes](#panorama-list-static-routes)
65. [Returns the specified static route of a virtual router: panorama-get-static-route](#panorama-get-static-route)
66. [Adds a static route: panorama-add-static-route](#panorama-add-static-route)
67. [Deletes a static route: panorama-delete-static-route](#panorama-delete-static-route)
68. [Show firewall device software version: panorama-show-device-version](#panorama-show-device-version)
69. [Downloads the latest content update: panorama-download-latest-content-update](#panorama-download-latest-content-update)
70. [Checks the download status of a content update: panorama-content-update-download-status](#panorama-content-update-download-status)
71. [Installs the latest content update: panorama-install-latest-content-update](#panorama-install-latest-content-update)
72. [Gets the installation status of the content update: panorama-content-update-install-status](#panorama-content-update-install-status)
73. [Checks the PAN-OS software version from the repository: panorama-check-latest-panos-software](#panorama-check-latest-panos-software)
74. [Downloads the target PAN-OS software version to install on the target device: panorama-download-panos-version](#panorama-download-panos-version)
75. [Gets the download status of the target PAN-OS software: panorama-download-panos-status](#panorama-download-panos-status)
76. [Installs the target PAN-OS version on the specified target device: panorama-install-panos-version](#panorama-install-panos-version)
77. [Gets the installation status of the PAN-OS software: panorama-install-panos-status](#panorama-install-panos-status)
78. [Reboots the Firewall device: panorama-device-reboot](#panorama-device-reboot)
79. [Gets location information for an IP address: panorama-show-location-ip](#panorama-show-location-ip)
80. [Gets information about available PAN-OS licenses and their statuses: panorama-get-licenses](#panorama-get-licenses)
81. [Gets information for the specified security profile: panorama-get-security-profiles](#panorama-get-security-profiles)
82. [Apply a security profile to specific rules or rules with a specific tag: panorama-apply-security-profile](#panorama-apply-security-profile)
83. [Get SSL decryption rules: panorama-get-ssl-decryption-rules](#panorama-get-ssl-decryption-rules)
84. [Retrieves the Wildfire configuration: panorama-get-wildfire-configuration](#panorama-get-wildfire-configuration)
85. [Set default categories to block in the URL filtering profile: panorama-url-filtering-block-default-categories](#panorama-url-filtering-block-default-categories)
86. [Get anti-spyware best practices: panorama-get-anti-spyware-best-practice](#panorama-get-anti-spyware-best-practice)
87. [Get file-blocking best practices: panorama-get-file-blocking-best-practice](#panorama-get-file-blocking-best-practice)
88. [Get anti-virus best practices: panorama-get-antivirus-best-practice](#panorama-get-antivirus-best-practice)
89. [Get vulnerability-protection best practices: panorama-get-vulnerability-protection-best-practice](#panorama-get-vulnerability-protection-best-practice)
90. [View WildFire best practices: panorama-get-wildfire-best-practice](#panorama-get-wildfire-best-practice)
91. [View URL Filtering best practices: panorama-get-url-filtering-best-practice](#panorama-get-url-filtering-best-practice)
92. [Enforces wildfire best practices to upload files to the maximum size, forwards all file types, and updates the schedule: panorama-enforce-wildfire-best-practice](#panorama-enforce-wildfire-best-practice)
93. [Creates an antivirus best practice profile: panorama-create-antivirus-best-practice-profile](#panorama-create-antivirus-best-practice-profile)
94. [Creates an Anti-Spyware best practice profile: panorama-create-anti-spyware-best-practice-profile](#panorama-create-anti-spyware-best-practice-profile)
95. [Creates a vulnerability protection best practice profile: panorama-create-vulnerability-best-practice-profile](#panorama-create-vulnerability-best-practice-profile)
96. [Creates a URL filtering best practice profile: panorama-create-url-filtering-best-practice-profile](#panorama-create-url-filtering-best-practice-profile)
97. [Creates a file blocking best practice profile: panorama-create-file-blocking-best-practice-profile](#panorama-create-file-blocking-best-practice-profile)
98. [Creates a WildFire analysis best practice profile: panorama-create-wildfire-best-practice-profile](#panorama-create-wildfire-best-practice-profile)


### panorama
***
Run any command supported in the API.


#### Base Command

`panorama`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Action to be taken, such as show, get, set, edit, delete, rename, clone, move, override, multi-move, multi-clone, or complete. | Optional | 
| category | Category parameter. For example, when exporting a configuration file, use "category=configuration". | Optional | 
| cmd | Specifies the xml structure that defines the command. Used for operation commands. | Optional | 
| command | Run a command. For example, command =&lt;show&gt;&lt;arp&gt;&lt;entry name='all'/&gt;&lt;/arp&gt;&lt;/show&gt; | Optional | 
| dst | Specifies a destination. | Optional | 
| element | Used to define a new value for an object. | Optional | 
| to | End time (used when cloning an object). | Optional | 
| from | Start time (used when cloning an object). | Optional | 
| key | Sets a key value. | Optional | 
| log-type | Retrieves log types. For example, log-type=threat for threat logs. | Optional | 
| where | Specifies the type of a move operation (for example, where=after, where=before, where=top, where=bottom). | Optional | 
| period | Time period. For example, period=last-24-hrs | Optional | 
| xpath | xpath location. For example, xpath=/config/predefined/application/entry[@name='hotmail'] | Optional | 
| pcap-id | PCAP ID included in the threat log. | Optional | 
| serialno | Specifies the device serial number. | Optional | 
| reporttype | Chooses the report type, such as dynamic, predefined or custom. | Optional | 
| reportname | Report name. | Optional | 
| type | Request type (e.g. export, import, log, config). | Optional | 
| search-time | The time that the PCAP was received on the firewall. Used for threat PCAPs. | Optional | 
| target | Target number of the firewall. Use only on a Panorama instance. | Optional | 
| job-id | Job ID. | Optional | 
| query | Query string. | Optional | 


#### Context Output

There is no context output for this command.


### panorama-get-predefined-threats-list
***
Gets the pre-defined threats list from a Firewall or Panorama and stores as a JSON file in the context.


#### Base Command

`panorama-get-predefined-threats-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The firewall managed by Panorama from which to retrieve the predefined threats. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.Name | string | File name. | 
| File.Type | string | File type. | 
| File.Info | string | File info. | 
| File.Extension | string | File extension. | 
| File.EntryID | string | File entryID. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.SHA512 | string | SHA512 hash of the file. |
| File.SSDeep | string | SSDeep hash of the file. |


#### Command Example
```!panorama-get-predefined-threats-list```


### panorama-commit
***
Commits a configuration to Palo Alto Firewall or Panorama, but does not validate if the commit was successful. Committing to Panorama does not push the configuration to the Firewalls. To push the configuration, run the panorama-push-to-device-group command.


#### Base Command

`panorama-commit`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Commit.JobID | number | Job ID to commit. | 
| Panorama.Commit.Status | string | Commit status | 


#### Command Example
```!panorama-commit```

#### Context Example
```json
{
    "Panorama": {
        "Commit": {
            "JobID": "113198",
            "Status": "Pending"
        }
    }
}
```

#### Human Readable Output

>### Commit:
>|JobID|Status|
>|---|---|
>| 113198 | Pending |


### panorama-push-to-device-group
***
Pushes rules from PAN-OS to the configured device group.


#### Base Command

`panorama-push-to-device-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.DeviceGroup | String | Device group in which the policies were pushed. | 
| Panorama.Push.JobID | Number | Job ID of the polices that were pushed. | 
| Panorama.Push.Status | String | Push status. | 


#### Command Example
```!panorama-push-to-device-group ```

#### Human Readable Output

>### Push to Device Group Status:
>|JobID|Status|
>|---|---|
>| 113198 | Pending |

### panorama-list-addresses
***
Returns a list of addresses.


#### Base Command

`panorama-list-addresses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the list of addresses. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name. | 
| Panorama.Addresses.Description | string | Address description. | 
| Panorama.Addresses.FQDN | string | Address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | Address IP Netmask. | 
| Panorama.Addresses.IP_Range | string | Address IP range. | 
| Panorama.Addresses.DeviceGroup | String | Address device group. | 
| Panorama.Addresses.Tags | String | Address tags. | 


#### Command Example
```!panorama-list-addresses```

#### Context Example
```json
{
    "Panorama": {
        "Addresses": [
            {
                "IP_Netmask": "10.10.10.1/24",
                "Name": "Demisto address"
            },
            {
                "Description": "a",
                "IP_Netmask": "1.1.1.1",
                "Name": "test1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Addresses:
>|Name|IP_Netmask|IP_Range|FQDN|
>|---|---|---|---|
>| Demisto address | 10.10.10.1/24 |  |  |
>| test1 | 1.1.1.1 |  |  |


### panorama-get-address
***
Returns address details for the supplied address name.


#### Base Command

`panorama-get-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Address name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name. | 
| Panorama.Addresses.Description | string | Address description. | 
| Panorama.Addresses.FQDN | string | Address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | Address IP Netmask. | 
| Panorama.Addresses.IP_Range | string | Address IP range. | 
| Panorama.Addresses.DeviceGroup | String | Device group for the address \(Panorama instances\). | 
| Panorama.Addresses.Tags | String | Address tags. | 


#### Command Example
```!panorama-get-address name="Demisto address"```

#### Context Example
```json
{
    "Panorama": {
        "Addresses": {
            "IP_Netmask": "10.10.10.1/24",
            "Name": "Demisto address"
        }
    }
}
```

#### Human Readable Output

>### Address:
>|Name|IP_Netmask|
>|---|---|
>| Demisto address | 10.10.10.1/24 |


### panorama-create-address
***
Creates an address object.


#### Base Command

`panorama-create-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | New address name. | Required | 
| description | New address description. | Optional | 
| fqdn | FQDN of the new address. | Optional | 
| ip_netmask | IP Netmask of the new address. For example, 10.10.10.10/24 | Optional | 
| ip_range | IP range of the new address IP. For example, 10.10.10.0-10.10.10.255 | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | The tag for the new address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name. | 
| Panorama.Addresses.Description | string | Address description. | 
| Panorama.Addresses.FQDN | string | Address FQDN. | 
| Panorama.Addresses.IP_Netmask | string | Address IP Netmask. | 
| Panorama.Addresses.IP_Range | string | Address IP range. | 
| Panorama.Addresses.DeviceGroup | String | Device group for the address \(Panorama instances\). | 
| Panorama.Addresses.Tag | String | Address tag. | 


#### Command Example
```!panorama-create-address name="address_test_pb" description="just a desc" ip_range="10.10.10.9-10.10.10.10"```

#### Context Example
```json
{
    "Panorama": {
        "Addresses": {
            "Description": "just a desc",
            "IP_Range": "10.10.10.9-10.10.10.10",
            "Name": "address_test_pb"
        }
    }
}
```

#### Human Readable Output

>Address was created successfully.

### panorama-delete-address
***
Delete an address object


#### Base Command

`panorama-delete-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Addresses.Name | string | Address name that was deleted. | 
| Panorama.Addresses.DeviceGroup | String | Device group for the address \(Panorama instances\). | 


#### Command Example
```!panorama-delete-address name="address_test_pb"```

#### Context Example
```json
{
    "Panorama": {
        "Addresses": {
            "Name": "address_test_pb"
        }
    }
}
```

#### Human Readable Output

>Address was deleted successfully.

### panorama-list-address-groups
***
Returns a list of address groups.


#### Base Command

`panorama-list-address-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the Address groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Match | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.Addresses | String | Static Address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tag | String | Address group tag. | 


#### Command Example
```!panorama-list-address-groups```

#### Context Example
```json
{
    "Panorama": {
        "AddressGroups": [
            {
                "Match": "2.2.2.2",
                "Name": "a_g_1",
                "Type": "dynamic"
            },
            {
                "Addresses": [
                    "Demisto address",
                    "test3",
                    "test_demo3"
                ],
                "Name": "Demisto group",
                "Type": "static"
            },
            {
                "Description": "jajja",
                "Match": "4.4.4.4",
                "Name": "dynamic2",
                "Type": "dynamic"
            },
            {
                "Addresses": [
                    "test4",
                    "test2"
                ],
                "Name": "static2",
                "Type": "static"
            }
        ]
    }
}
```

#### Human Readable Output

>### Address groups:
>|Name|Type|Addresses|Match|Description|Tags|
>|---|---|---|---|---|---|
>| a_g_1 | dynamic |  | 2.2.2.2 |  |  |
>| Demisto group | static | Demisto address,<br/>test3,<br/>test_demo3 |  |  |  |
>| dynamic2 | dynamic |  | 4.4.4.4 | jajja |  |
>| static2 | static | test4,<br/>test2 |  |  |  |


### panorama-get-address-group
***
Get details for the specified address group


#### Base Command

`panorama-get-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Address group name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Match | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.Addresses | string | Static Address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tags | String | Address group tags. | 


#### Command Example
```!panorama-get-address-group name=suspicious_address_group ```

#### Human Readable Output

>### Address groups:
>|Name|Type|Addresses|Match|Description|
>|---|---|---|---|---|
>| suspicious_address_group | dynamic | 1.1.1.1 | this ip is very bad |

### panorama-create-address-group
***
Creates a static or dynamic address group.


#### Base Command

`panorama-create-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Address group name. | Required | 
| type | Address group type. | Required | 
| match | Dynamic Address group match. e.g: "1.1.1.1 or 2.2.2.2" | Optional | 
| addresses | Static address group list of addresses. | Optional | 
| description | Address group description. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | The tags for the Address group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Match | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Addresses | string | Static Address group list of addresses. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tag | String | Address group tags. | 


#### Command Example
```!panorama-create-address-group name=suspicious_address_group type=dynamic match=1.1.1.1 description="this ip is very bad"```

#### Context Example
```json
{
    "Panorama": {
        "AddressGroups": {
            "Description": "this ip is very bad",
            "Match": "1.1.1.1",
            "Name": "suspicious_address_group",
            "Type": "dynamic"
        }
    }
}
```

#### Human Readable Output

>Address group was created successfully.

### panorama-block-vulnerability
***
Sets a vulnerability signature to block mode.


#### Base Command

`panorama-block-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| drop_mode | Type of session rejection. Possible values are: "drop", "alert", "block-ip", "reset-both", "reset-client", and "reset-server".' Default is "drop". | Optional | 
| vulnerability_profile | Name of vulnerability profile. | Required | 
| threat_id | Numerical threat ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Vulnerability.ID | string | ID of vulnerability that has been blocked/overridden. | 
| Panorama.Vulnerability.NewAction | string | New action for the vulnerability. | 


#### Command Example
```!panorama-block-vulnerability threat_id=18250 vulnerability_profile=name```

#### Human Readable Output

>Threat with ID 18250 overridden.

### panorama-delete-address-group
***
Deletes an address group.


#### Base Command

`panorama-delete-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of address group to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Name of address group that was deleted. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 


#### Command Example
```!panorama-delete-address-group name="dynamic_address_group_test_pb3"```


#### Human Readable Output

>Address group was deleted successfully

### panorama-edit-address-group
***
Edits a static or dynamic address group.


#### Base Command

`panorama-edit-address-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address group to edit. | Required | 
| type | Address group type. | Required | 
| match | Address group new match. For example, '1.1.1.1 and 2.2.2.2'. | Optional | 
| element_to_add | Element to add to the list of the static address group. Only existing Address objects can be added. | Optional | 
| element_to_remove | Element to remove from the list of the static address group. Only existing Address objects can be removed. | Optional | 
| description | Address group new description. | Optional | 
| tags | The tag of the Address group to edit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.AddressGroups.Name | string | Address group name. | 
| Panorama.AddressGroups.Type | string | Address group type. | 
| Panorama.AddressGroups.Filter | string | Dynamic Address group match. | 
| Panorama.AddressGroups.Description | string | Address group description. | 
| Panorama.AddressGroups.Addresses | string | Static Address group addresses. | 
| Panorama.AddressGroups.DeviceGroup | String | Device group for the address group \(Panorama instances\). | 
| Panorama.AddressGroups.Tags | String | Address group tags. | 


### panorama-list-services
***
Returns a list of addresses.


#### Base Command

`panorama-list-services`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the Services. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Service name. | 
| Panorama.Services.Protocol | string | Service protocol. | 
| Panorama.Services.Description | string | Service description. | 
| Panorama.Services.DestinationPort | string | Service destination port. | 
| Panorama.Services.SourcePort | string | Service source port. | 
| Panorama.Services.DeviceGroup | string | Device group in which the service was configured \(Panorama instances\). | 
| Panorama.Services.Tags | String | Service tags. | 


#### Command Example
```!panorama-list-services```

#### Context Example
```json
{
    "Panorama": {
        "Services": [
            {
                "Description": "rgfg",
                "DestinationPort": "55",
                "Name": "demisto_service1",
                "Protocol": "tcp",
                "SourcePort": "567-569"
            },
            {
                "Description": "mojo",
                "DestinationPort": "55",
                "Name": "demi_service_test_pb",
                "Protocol": "sctp",
                "SourcePort": "60"
            },
        ]
    }
}
```

#### Human Readable Output

>### Services:
>|Name|Protocol|SourcePort|DestinationPort|Description|
>|---|---|---|---|---|
>| demisto_service1 | tcp | 567-569 | 55 | rgfg |
>| demi_service_test_pb | sctp | 60 | 55 | mojo |


### panorama-get-service
***
Returns service details for the supplied service name.


#### Base Command

`panorama-get-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Service name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Service name. | 
| Panorama.Services.Protocol | string | Service protocol. | 
| Panorama.Services.Description | string | Service description. | 
| Panorama.Services.DestinationPort | string | Service destination port. | 
| Panorama.Services.SourcePort | string | Service source port. | 
| Panorama.Services.DeviceGroup | string | Device group for the service \(Panorama instances\). | 
| Panorama.Service.Tags | String | Service tags. | 


#### Command Example
```!panorama-get-service name=demisto_service1 ```

#### Human Readable Output

>### Address
>|Name|Protocol|SourcePort|DestinationPort|Description|
>|---|---|---|---|---|
>| demisto_service1 | tcp | 567-569 | 55 | rgfg |


### panorama-create-service
***
Creates a service.


#### Base Command

`panorama-create-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name for the new service. | Required | 
| protocol | Protocol for the new service. | Required | 
| destination_port | Destination port  for the new service. | Required | 
| source_port | Source port  for the new service. | Optional | 
| description | Description for the new service. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | Tags for the new service. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Service name. | 
| Panorama.Services.Protocol | string | Service protocol. | 
| Panorama.Services.Descritpion | string | Service description. | 
| Panorama.Services.DestinationPort | string | Service destination port. | 
| Panorama.Services.SourcePort | string | Service source port. | 
| Panorama.Services.DeviceGroup | string | Device group for the service \(Panorama instances\). | 
| Panorama.Services.Tags | String | Service tags. | 


#### Command Example
```!panorama-create-service name=guy_ser3 protocol=udp destination_port=36 description=bfds```

#### Context Example
```json
{
    "Panorama": {
        "Services": {
            "Description": "bfds",
            "DestinationPort": "36",
            "Name": "guy_ser3",
            "Protocol": "udp"
        }
    }
}
```

#### Human Readable Output

>Service was created successfully.

### panorama-delete-service
***
Deletes a service.


#### Base Command

`panorama-delete-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Services.Name | string | Name of the deleted service. | 
| Panorama.Services.DeviceGroup | string | Device group for the service \(Panorama instances\). | 


#### Command Example
```!panorama-delete-service name=guy_ser3```

#### Context Example
```json
{
    "Panorama": {
        "Services": {
            "Name": "guy_ser3"
        }
    }
}
```

#### Human Readable Output

>Service was deleted successfully.

### panorama-list-service-groups
***
Returns a list of service groups.


#### Base Command

`panorama-list-service-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tags for which to filter the Service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
```!panorama-list-service-groups```

#### Context Example
```json
{
    "Panorama": {
        "ServiceGroups": [
            {
                "Name": "demisto_default_service_groups",
                "Services": [
                    "service-http",
                    "service-https"
                ]
            },
            {
                "Name": "demisto_test_pb_service_group",
                "Services": "serice_tcp_test_pb"
            }
        ]
    }
}
```

#### Human Readable Output

>### Service groups:
>|Name|Services|
>|---|---|
>| demisto_default_service_groups | service-http,<br/>service-https |
>| demisto_test_pb_service_group | serice_tcp_test_pb |


### panorama-get-service-group
***
Returns details for the specified service group.


#### Base Command

`panorama-get-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Service group name. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
```!panorama-get-service-group name=ser_group6```

#### Context Example
```json
{
    "Panorama": {
        "ServiceGroups": {
            "Name": "ser_group6",
            "Services": [
                "serice_tcp_test_pb",
                "demi_service_test_pb"
            ]
        }
    }
}
```

#### Human Readable Output

>### Service group:
>|Name|Services|
>|---|---|
>| ser_group6 | serice_tcp_test_pb,<br/>demi_service_test_pb |


### panorama-create-service-group
***
Creates a service group.


#### Base Command

`panorama-create-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Service group name. | Required | 
| services | Service group related services. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tags | Tags for which to filter Service groups. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
```!panorama-create-service-group name=lalush_sg4 services=`["demisto_service1","demi_service_test_pb"]```


### panorama-delete-service-group
***
Deletes a service group.


#### Base Command

`panorama-delete-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service group to delete. | Required | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Name of the deleted service group. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 


#### Command Example
```!panorama-delete-service-group name=lalush_sg4```


### panorama-edit-service-group
***
Edit a service group.


#### Base Command

`panorama-edit-service-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service group to edit. | Required | 
| services_to_add | Services to add to the service group. Only existing Services objects can be added. | Optional | 
| services_to_remove | Services to remove from the service group. Only existing Services objects can be removed. | Optional | 
| tags | Tag of the Service group to edit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.ServiceGroups.Name | string | Service group name. | 
| Panorama.ServiceGroups.Services | string | Service group related services. | 
| Panorama.ServiceGroups.DeviceGroup | string | Device group for the service group \(Panorama instances\). | 
| Panorama.ServiceGroups.Tags | String | Service group tags. | 


#### Command Example
```!panorama-edit-service-group name=lalush_sg4 services_to_remove=`["serice_udp_test_pb","demisto_service1"] ```

#### Human Readable Output
>Service group was edited successfully


### panorama-get-custom-url-category
***
Returns information for a custom URL category.


#### Base Command

`panorama-get-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Custom URL category name. | Required | 
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


#### Command Example
```!panorama-get-custom-url-category name=my_personal_url_category```


#### Human Readable Output

>### Custom URL Category:
>|Name|Sites|Description|
>|---|---|
>| my_personal_url_category | thepill.com,<br/>abortion.com | just a desc |

### panorama-create-custom-url-category
***
Creates a custom URL category.


#### Base Command

`panorama-create-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the custom URL category to create. | Required | 
| description | Description of the custom URL category to create. | Optional | 
| sites | List of sites for the custom URL category. | Optional | 
| device-group | The device group for which to return addresses for the custom URL category (Panorama instances). | Optional | 
| type | The category type of the URL. Relevant from PAN-OS v9.x. | Optional | 
| categories | The list of categories. Relevant from PAN-OS v9.x. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | String | Custom URL category name. | 
| Panorama.CustomURLCategory.Description | String | Custom URL category description. | 
| Panorama.CustomURLCategory.Sites | String | Custom URL category list of sites. | 
| Panorama.CustomURLCategory.DeviceGroup | String | Device group for the Custom URL Category \(Panorama instances\). | 
| Panorama.CustomURLCategory.Sites | String | Custom URL category list of categories. | 
| Panorama.CustomURLCategory.Type | String | Custom URL category type. | 


#### Command Example
```!panorama-create-custom-url-category name=suspicious_address_group sites=["thepill.com","abortion.com"] description=momo```

#### Context Example
```json
{
    "Panorama": {
        "CustomURLCategory": {
            "Description": "momo",
            "Name": "suspicious_address_group",
            "Sites": [
                "thepill.com",
                "abortion.com"
            ]
        }
    }
}
```

#### Human Readable Output

>### Created Custom URL Category:
>|Name|Sites|Description|
>|---|---|---|
>| suspicious_address_group | thepill.com,<br/>abortion.com | momo |


### panorama-delete-custom-url-category
***
Deletes a custom URL category.


#### Base Command

`panorama-delete-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the custom URL category to delete. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | string | Name of the custom URL category to delete. | 
| Panorama.CustomURLCategory.DeviceGroup | string | Device group for the Custom URL Category \(Panorama instances\). | 


#### Command Example
```!panorama-delete-custom-url-category name=suspicious_address_group```

#### Context Example
```json
{
    "Panorama": {
        "CustomURLCategory": {
            "Name": "suspicious_address_group"
        }
    }
}
```

#### Human Readable Output

>Custom URL category was deleted successfully.

### panorama-edit-custom-url-category
***
Adds or removes sites to and from a custom URL category.


#### Base Command

`panorama-edit-custom-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the custom URL category to add or remove sites. | Required | 
| sites | A comma separated list of sites to add to the custom URL category. | Optional | 
| action | Adds or removes sites or categories. Can be "add",or "remove". | Required | 
| categories | A comma separated list of categories to add to the custom URL category. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.CustomURLCategory.Name | string | Custom URL category name. | 
| Panorama.CustomURLCategory.Description | string | Custom URL category description. | 
| Panorama.CustomURLCategory.Sites | string | Custom URL category list of sites. | 
| Panorama.CustomURLCategory.DeviceGroup | string | Device group for the Custom URL Category \(Panorama instances\). | 


### panorama-get-url-category
***
Gets a URL category from URL Filtering.


#### Base Command

`panorama-get-url-category`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | URL. | 
| Panorama.URLFilter.Category | string | URL category. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Category | String | The URL Category. | 


#### Command Example
```!panorama-get-url-category url="poker.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "poker.com",
        "Score": 1,
        "Type": "url",
        "Vendor": "PAN-OS"
    },
    "Panorama": {
        "URLFilter": {
            "Category": "gambling",
            "URL": [
                "poker.com"
            ]
        }
    },
    "URL": {
        "Category": "gambling",
        "Data": "poker.com"
    }
}
```

#### Human Readable Output

>### URL Filtering:
>|URL|Category|
>|---|---|
>| poker.com | gambling |


### url
***
Gets a URL category from URL Filtering.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| URL.Category | String | The URL category. | 


### panorama-get-url-category-from-cloud
***
Returns a URL category from URL filtering.


#### Base Command

`panorama-get-url-category-from-cloud`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | URL category. | 


#### Command Example
```!panorama-get-url-category-from-cloud url=google.com ```

#### Human Readable Output

>### URL Filtering from cloud:
>|URL|Category|
>|---|---|
>| google.com | search-engines |


### panorama-get-url-category-from-host
***
Returns a URL category from URL Filtering.


#### Base Command

`panorama-get-url-category-from-host`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.URL | string | The URL. | 
| Panorama.URLFilter.Category | string | The URL category. | 


#### Command Example
```!panorama-get-url-category-from-host url=google.com ```

#### Human Readable Output

>### URL Filtering from host:
>|URL|Category|
>|---|---|
>| google.com | search-engines |

### panorama-get-url-filter
***
Returns information for a URL filtering rule.


#### Base Command

`panorama-get-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | URL Filter name. | Required | 
| device-group | The device group for which to return addresses for the URL Filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL Filter name. | 
| Panorama.URLFilter.Category.Name | string | URL Filter category name. | 
| Panorama.URLFilter.Category.Action | string | Action for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | URL Filter override block list. | 
| Panorama.URLFilter.OverrideAllowList | string | URL Filter override allow list. | 
| Panorama.URLFilter.Description | string | URL Filter description. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
```!panorama-get-url-filter name=demisto_default_url_filter```


#### Human Readable Output

>### URL Filter:
>|Name|Category|OverrideAllowList|Description|
>|---|---|---|---|
>| demisto_default_url_filter | {'Action': 'block', 'Name': u'abortion'},<br/>{'Action': 'block', 'Name': u'abuse-drugs'} | 888.com,<br/>777.com | gres |

### panorama-create-url-filter
***
Creates a URL filtering rule.


#### Base Command

`panorama-create-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the URL filter to create. | Required | 
| url_category | URL categories. | Required | 
| action | Action for the URL categories. Can be "allow", "block", "alert", "continue", or "override". | Required | 
| override_allow_list | CSV list of URLs to exclude from the allow list. | Optional | 
| override_block_list | CSV list of URLs to exclude from the blocked list. | Optional | 
| description | URL Filter description. | Optional | 
| device-group | The device group for which to return addresses for the URL Filter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL Filter name. | 
| Panorama.URLFilter.Category.Name | string | URL Filter category name. | 
| Panorama.URLFilter.Category.Action | string | Action for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | URL Filter override allow list. | 
| Panorama.URLFilter.OverrideBlockList | string | URL Filter override blocked list. | 
| Panorama.URLFilter.Description | string | URL Filter description. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
```!panorama-create-url-filter action=block name=gambling_url url_category=gambling```

#### Context Example
```json
{
    "Panorama": {
        "URLFilter": {
            "Category": [
                {
                    "Action": "block",
                    "Name": "gambling"
                }
            ],
            "Name": "gambling_url"
        }
    }
}
```

#### Human Readable Output

>URL Filter was created successfully.

### panorama-edit-url-filter
***
Edit a URL filtering rule.


#### Base Command

`panorama-edit-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the URL filter to edit. | Required | 
| element_to_change | Element to change. Can be "override_allow_list", or "override_block_list" | Required | 
| element_value | Element value. Limited to one value. | Required | 
| add_remove_element | Add or remove an element from the Allow List or Block List fields. Default is to 'add' the element_value to the list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL Filter name. | 
| Panorama.URLFilter.Description | string | URL Filter description. | 
| Panorama.URLFilter.Category.Name | string | URL Filter category. | 
| Panorama.URLFilter.Action | string | Action for the URL category. | 
| Panorama.URLFilter.OverrideAllowList | string | Allow Overrides for the URL category. | 
| Panorama.URLFilter.OverrideBlockList | string | Block Overrides for the URL category. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
```!panorama-edit-url-filter name=demisto_default_url_filter element_to_change=override_allow_list element_value="poker.com" add_remove_element=add```


#### Human Readable Output

>URL Filter was edited successfully

### panorama-delete-url-filter
***
Deletes a URL filtering rule.


#### Base Command

`panorama-delete-url-filter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the URL filter rule to delete. | Required | 
| device-group | The device group for which to return addresses for the URL filter (Panorama instances) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Name | string | URL filter rule name. | 
| Panorama.URLFilter.DeviceGroup | string | Device group for the URL Filter \(Panorama instances\). | 


#### Command Example
```!panorama-delete-url-filter name=gambling_url```

#### Context Example
```json
{
    "Panorama": {
        "URLFilter": {
            "Name": "gambling_url"
        }
    }
}
```

#### Human Readable Output

>URL Filter was deleted successfully.

### panorama-list-edls
***
Returns a list of external dynamic lists.


#### Base Command

`panorama-list-edls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL. | 
| Panorama.EDL.Type | string | The type of EDL. | 
| Panorama.EDL.URL | string | URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
```!panorama-list-edls```

#### Context Example
```json
{
    "Panorama": {
        "EDL": [
            {
                "Description": "6u4ju7",
                "Name": "blabla3",
                "Recurring": "hourly",
                "Type": "url",
                "URL": "lolo"
            },
            {
                "Description": "ip",
                "Name": "bad_ip_edl_demisot_web_server",
                "Recurring": "five-minute",
                "Type": "ip",
                "URL": "http://192.168.1.15/files/very_bad_ip2.txt"
            }
        ]
    }
}
```

#### Human Readable Output

>### External Dynamic Lists:
>|Name|Type|URL|Recurring|Description|
>|---|---|---|---|---|
>| blabla3 | url | lolo | hourly | 6u4ju7 |
>| bad_ip_edl_demisot_web_server | ip | http://192.168.1.15/files/very_bad_ip2.txt | five-minute | ip |



### panorama-get-edl
***
Returns information for an external dynamic list


#### Base Command

`panorama-get-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL. | 
| Panorama.EDL.Type | string | The type of EDL. | 
| Panorama.EDL.URL | string | URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
```!panorama-get-edl name=test_pb_domain_edl_DONT_DEL```

#### Context Example
```json
{
    "Panorama": {
        "EDL": {
            "Description": "new description3",
            "Name": "test_pb_domain_edl_DONT_DEL",
            "Recurring": "hourly",
            "Type": "url",
            "URL": "https://test_pb_task.not.real"
        }
    }
}
```

#### Human Readable Output

>### External Dynamic List:
>|Name|Type|URL|Recurring|Description|
>|---|---|---|---|---|
>| test_pb_domain_edl_DONT_DEL | url | https://test_pb_task.not.real | hourly | new description3 |


### panorama-create-edl
***
Creates an external dynamic list.


#### Base Command

`panorama-create-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL. | Required | 
| url | URL from which to pull the EDL. | Required | 
| type | The type of EDL. | Required | 
| recurring | Time interval for pulling and updating the EDL. | Required | 
| certificate_profile | Certificate Profile name for the URL that was previously uploaded. to PAN OS. | Optional | 
| description | Description of the EDL. | Optional | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of theEDL. | 
| Panorama.EDL.Type | string | Type of the EDL. | 
| Panorama.EDL.URL | string | URL in which the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
```!panorama-create-edl name=new_EDL recurring="five-minute" type=url url="gmail.com"```

#### Context Example
```json
{
    "Panorama": {
        "EDL": {
            "Name": "new_EDL",
            "Recurring": "five-minute",
            "Type": "url",
            "URL": "gmail.com"
        }
    }
}
```

#### Human Readable Output

>External Dynamic List was created successfully.

### panorama-edit-edl
***
Modifies an element of an external dynamic list.


#### Base Command

`panorama-edit-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the external dynamic list to edit. | Required | 
| element_to_change | The element to change (“url”, “recurring”, “certificate_profile”, “description”). | Required | 
| element_value | The element value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL. | 
| Panorama.EDL.URL | string | URL where the EDL is stored. | 
| Panorama.EDL.Description | string | Description of the EDL. | 
| Panorama.EDL.CertificateProfile | string | EDL certificate profile. | 
| Panorama.EDL.Recurring | string | Time interval that the EDL was pulled and updated. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
```!panorama-edit-edl name=test_pb_domain_edl_DONT_DEL element_to_change=description element_value="new description3"```

#### Context Example
```json
{
    "Panorama": {
        "EDL": {
            "Description": "new description3",
            "Name": "test_pb_domain_edl_DONT_DEL"
        }
    }
}
```

#### Human Readable Output

>External Dynamic List was edited successfully

### panorama-delete-edl
***
Deletes an external dynamic list.


#### Base Command

`panorama-delete-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL to delete. | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.EDL.Name | string | Name of the EDL that was deleted. | 
| Panorama.EDL.DeviceGroup | string | Device group for the EDL \(Panorama instances\). | 


#### Command Example
```!panorama-delete-edl name=new_EDL```

#### Context Example
```json
{
    "Panorama": {
        "EDL": {
            "Name": "new_EDL"
        }
    }
}
```

#### Human Readable Output

>External Dynamic List was deleted successfully

### panorama-refresh-edl
***
Refreshes the specified external dynamic list.


#### Base Command

`panorama-refresh-edl`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the EDL | Required | 
| device-group | The device group for which to return addresses for the EDL (Panorama instances). | Optional | 
| edl_type | The type of the EDL. Required when refreshing an EDL object which is configured on Panorama. | Optional | 
| location | The location of the EDL. Required when refreshing an EDL object which is configured on Panorama. | Optional | 
| vsys | The Vsys of the EDL. Required when refreshing an EDL object which is configured on Panorama. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-refresh-edl name=test_pb_domain_edl_DONT_DEL ```

#### Human Readable Output

>Refreshed External Dynamic List successfully

### panorama-create-rule
***
Creates a policy rule.


#### Base Command

`panorama-create-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to create. | Optional | 
| description | Description of the rule to create. | Optional | 
| action | Action for the rule. Can be "allow", "deny", or "drop". | Required | 
| source | A comma-separated list of address object names, address group object names, or EDL object names. | Optional | 
| destination | A comma-separated list of address object names, address group object names, or EDL object names. | Optional | 
| source_zone | A comma-separated list of source zones. | Optional | 
| destination_zone | A comma-separated list of destination zones. | Optional | 
| negate_source | Whether to negate the source (address, address group). Can be "Yes" or "No". | Optional | 
| negate_destination | Whether to negate the destination (address, address group). Can be "Yes" or "No". | Optional | 
| service | Service object names for the rule (service object) to create. | Optional | 
| disable | Whether to disable the rule. Can be "Yes" or "No" (default is "No"). | Optional | 
| application | A comma-separated list of application object namesfor the rule to create. | Optional | 
| source_user | Source user for the rule to create. | Optional | 
| pre_post | Pre rule or Post rule (Panorama instances). | Optional | 
| target | Specifies a target firewall for the rule (Panorama instances). | Optional | 
| log_forwarding | Log forwarding profile. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 
| tags | Rule tags to create. | Optional | 
| category | A comma-separated list of URL categories. | Optional |
| profile_setting | A profile setting group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.Description | string | Rule description. | 
| Panorama.SecurityRule.Action | string | Action for the rule. | 
| Panorama.SecurityRule.Source | string | Source address. | 
| Panorama.SecurityRule.Destination | string | Destination address. | 
| Panorama.SecurityRule.NegateSource | boolean | Whether the source is negated \(address, address group\). | 
| Panorama.SecurityRule.NegateDestination | boolean | Whether the destination negated \(address, address group\). | 
| Panorama.SecurityRule.Service | string | Service for the rule. | 
| Panorama.SecurityRule.Disabled | string | Whether the rule is disabled. | 
| Panorama.SecurityRule.Application | string | Application for the rule. | 
| Panorama.SecurityRule.Target | string | Target firewall \(Panorama instances\). | 
| Panorama.SecurityRule.LogForwarding | string | Log forwarding profile \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRules.Tags | String | Rule tags. |
| Panorama.SecurityRules.ProfileSetting | String | Profile setting group. | 


#### Command Example
```!panorama-create-rule rulename="block_bad_application" description="do not play at work" action="deny" application="fortnite"```

#### Context Example
```json
{
    "Panorama": {
        "SecurityRule": {
            "Action": "deny",
            "Application": "fortnite",
            "Description": "do not play at work",
            "Disabled": "No",
            "Name": "block_bad_application",
            "SourceUser": "any"
        }
    }
}
```

#### Human Readable Output

>Rule configured successfully.

### panorama-custom-block-rule
***
Creates a custom block policy rule.


#### Base Command

`panorama-custom-block-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the custom block policy rule to create. | Optional | 
| object_type | Object type to block in the policy rule. Can be "ip", "address-group", "edl", or "custom-url-category". | Required | 
| object_value | A comma-separated list of object values for the object_type argument. | Required | 
| direction | Direction to block. Can be "to", "from", or "both". Default is "both". This argument is not applicable to the "custom-url-category" object_type. | Optional | 
| pre_post | Pre rule or Post rule (Panorama instances). | Optional | 
| target | Specifies a target firewall for the rule (Panorama instances). | Optional | 
| log_forwarding | Log forwarding profile. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 
| tags | Tags for which to use for the custom block policy rule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.Object | string | Blocked object. | 
| Panorama.SecurityRule.Direction | string | Direction blocked. | 
| Panorama.SecurityRule.Target | string | Target firewall \(Panorama instances\) | 
| Panorama.SecurityRule.LogForwarding | string | Log forwarding profile \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRule.Tags | String | Rule tags. | 


#### Command Example
```!panorama-custom-block-rule object_type=application object_value=fortnite```

#### Context Example
```json
{
    "Panorama": {
        "SecurityRule": {
            "Application": [
                "fortnite"
            ],
            "Direction": "both",
            "Disabled": false,
            "Name": "demisto-9c9ed15a"
        }
    }
}
```

#### Human Readable Output

>Object was blocked successfully.

### panorama-move-rule
***
Changes the location of a policy rule.


#### Base Command

`panorama-move-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to move. | Required | 
| where | Where to move the rule. Can be "before", "after", "top", or "bottom". If you specify "top" or "bottom", you need to supply the "dst" argument. | Required | 
| dst | Destination rule relative to the rule that you are moving. This field is only relevant if you specify "top" or "bottom" in the "where" argument. | Optional | 
| pre_post | Rule location. Mandatory for Panorama instances. | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 


#### Command Example
```!panorama-move-rule rulename="test_rule3" where="bottom" ```

#### Human Readable Output

>Rule test_rule3 moved successfully

### panorama-edit-rule
***
Edits a policy rule.


#### Base Command

`panorama-edit-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to edit. | Required | 
| element_to_change | Parameter in the security rule to change. Can be 'source', 'destination', 'application', 'action', 'category', 'description', 'disabled', 'target', 'log-forwarding', 'tag' or 'profile-setting'. | Required | 
| element_value | The new value for the parameter. | Required | 
| pre_post | Pre-rule or post-rule (Panorama instances). | Optional | 
| behaviour | Whether to replace, add, or remove the element_value from the current rule object value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.Description | string | Rule description. | 
| Panorama.SecurityRule.Action | string | Action for the rule. | 
| Panorama.SecurityRule.Source | string | Source address. | 
| Panorama.SecurityRule.Destination | string | Destination address. | 
| Panorama.SecurityRule.NegateSource | boolean | Whether the source is negated \(address, address group\). | 
| Panorama.SecurityRule.NegateDestination | boolean | Whether the destination is negated \(address, address group\). | 
| Panorama.SecurityRule.Service | string | Service for the rule. | 
| Panorama.SecurityRule.Disabled | string | Whether the rule is disabled. | 
| Panorama.SecurityRule.Application | string | Application for the rule. | 
| Panorama.SecurityRule.Target | string | Target firewall \(Panorama instances\). | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRule.Tags | String | Tags for the rule. | 
| Panorama.SecurityRules.ProfileSetting | String | Profile setting group. |

#### Command Example
```!panorama-edit-rule rulename="block_bad_application" element_to_change=action element_value=drop```

#### Context Example
```json
{
    "Panorama": {
        "SecurityRule": {
            "Action": "drop",
            "Name": "block_bad_application"
        }
    }
}
```

#### Human Readable Output

>Rule edited successfully.

### panorama-delete-rule
***
Deletes a policy rule.


#### Base Command

`panorama-delete-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rulename | Name of the rule to delete. | Required | 
| pre_post | Pre rule or Post rule (Panorama instances). | Optional | 
| device-group | The device group for which to return addresses for the rule (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | string | Rule name. | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 


#### Command Example
```!panorama-delete-rule rulename=block_bad_application```


#### Human Readable Output

>Rule deleted successfully.

### panorama-list-applications
***
Returns a list of applications.


#### Base Command

`panorama-list-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| predefined | Whether to list predefined applications or not. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Applications.Name | string | Application name. | 
| Panorama.Applications.Id | number | Application ID. | 
| Panorama.Applications.Category | string | Application category. | 
| Panorama.Applications.SubCategory | string | Application sub-category. | 
| Panorama.Applications.Technology | string | Application technology. | 
| Panorama.Applications.Risk | number | Application risk \(1 to 5\). | 
| Panorama.Applications.Description | string | Application description. | 


#### Command Example
```!panorama-list-applications```

#### Context Example
```json
{
    "Panorama": {
        "Applications": {
            "Description": "lala",
            "Id": null,
            "Name": "demisto_fw_app3",
            "Risk": "1",
            "SubCategory": "ip-protocol",
            "Technology": "peer-to-peer"
        }
    }
}
```

#### Human Readable Output

>### Applications
>|Id|Name|Risk|Category|SubCategory|Technology|Description|
>|---|---|---|---|---|---|---|
>|  | demisto_fw_app3 | 1 |  | ip-protocol | peer-to-peer | lala |


### panorama-commit-status
***
Returns commit status for a configuration.


#### Base Command

`panorama-commit-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Commit.JobID | number | Job ID of the configuration to be committed. | 
| Panorama.Commit.Status | string | Commit status. | 
| Panorama.Commit.Details | string | Job ID details. | 
| Panorama.Commit.Warnings | String | Job ID warnings | 


#### Command Example
```!panorama-commit-status job_id=948 ```

#### Human Readable Output

>### Commit Status:
>|JobID|Status|
>|---|---|
>| 948 | Pending |

### panorama-push-status
***
Returns the push status for a configuration.


#### Base Command

`panorama-push-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Push.DeviceGroup | string | Device group to which the policies were pushed. | 
| Panorama.Push.JobID | number | Job ID of the configuration to be pushed. | 
| Panorama.Push.Status | string | Push status. | 
| Panorama.Push.Details | string | Job ID details. | 
| Panorama.Push.Warnings | String | Job ID warnings | 


#### Command Example
```!panorama-push-status job_id=951 ```

#### Human Readable Output

>### Push to Device Group Status:
>|JobID|Status|Details|
>|---|---|---|
>| 951 | Completed | commit succeeded with warnings |

### panorama-get-pcap
***
Returns information for a Panorama PCAP file. The recommended maximum file size is 5 MB. If the limit is exceeded, you might need to SSH the firewall and run the scp export command to export the PCAP file. For more information, see the Palo Alto Networks documentation.


#### Base Command

`panorama-get-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pcapType | Type of Packet Capture. | Required | 
| from | The file name for the PCAP type ('dlp-pcap', 'filters-pcap', or 'application-pcap'). | Optional | 
| localName | The new name for the PCAP file after downloading. If this argument is not specified, the file name is the PCAP file name set in the firewall. | Optional | 
| serialNo | Serial number for the request. For further information, see the Panorama XML API Documentation. | Optional | 
| searchTime | The Search time for the request. For example: "2019/12/26 00:00:00", "2020/01/10". For more information, see the Panorama XML API documentation. | Optional | 
| pcapID | The ID of the PCAP for the request. For further information, see the Panorama XML API Documentation. | Optional | 
| password | Password for Panorama, needed for the 'dlp-pcap' PCAP type only. | Optional | 
| deviceName | The Device Name on which the PCAP is stored. For further information, see the Panorama XML API Documentation. | Optional | 
| sessionID | The Session ID of the PCAP. For further information, see the Panorama XML API Documentation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.Name | string | File name. | 
| File.Type | string | File type. | 
| File.Info | string | File info. | 
| File.Extenstion | string | File extension. | 
| File.EntryID | string | FIle entryID. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.SHA512 | string | SHA512 hash of the file. |
| File.SSDeep | string | SSDeep hash of the file. |


#### Command Example
```!panorama-get-pcap pcapType="filter-pcap" from=pcap_test ```


### panorama-list-pcaps
***
Returns a list of all PCAP files by PCAP type.


#### Base Command

`panorama-list-pcaps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pcapType | Type of Packet Capture. | Required | 
| password | Password for Panorama. Relevant for the 'dlp-pcap' PCAP type. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-list-pcaps pcapType=“filter-pcap” ```

#### Human Readable Output

>### List of Pcaps:
>|Pcap name|
>|---|
>| pcam_name |

### panorama-register-ip-tag
***
Registers IP addresses to a tag.


#### Base Command

`panorama-register-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to register IP addresses. | Required | 
| IPs | IP addresses to register. | Required | 
| persistent | Whether the IP addresses remain registered to the tag after the device reboots ('true':persistent, 'false':non-persistent). Default is 'true'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.DynamicTags.Tag | string | Name of the tag. | 
| Panorama.DynamicTags.IPs | string | Registered IP addresses. | 


#### Command Example
```!panorama-register-ip-tag tag=tag02 IPs=[“10.0.0.13”,“10.0.0.14”] ```

#### Human Readable Output

>Registered ip-tag successfully

### panorama-unregister-ip-tag
***
Unregisters IP addresses from a tag.


#### Base Command

`panorama-unregister-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to unregister IP addresses. | Required | 
| IPs | IP addresses to unregister. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-unregister-ip-tag tag=tag02 IPs=["10.0.0.13","10.0.0.14"] ```

#### Human Readable Output

>Unregistered ip-tag successfully


### panorama-register-user-tag
***
Registers users to a tag. This command is only available for PAN-OS version 9.x and above.


#### Base Command

`panorama-register-user-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag for which to register users. | Required | 
| Users | A comma-separated list of users to register. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.DynamicTags.Tag | string | Name of the tag. | 
| Panorama.DynamicTags.Users | string | List of registered users. | 


#### Command Example
```!panorama-register-user-tag tag-tag02 Users=Username```

#### Human Readable Output
>Registered user-tag successfully


### panorama-unregister-user-tag
***
Unregisters users from a tag. This command is only available for PAN-OS version 9.x and above.


#### Base Command

`panorama-unregister-user-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | Tag from which to unregister Users. | Required | 
| Users | A comma-separated list of users to unregister. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-unregister-user-tag tag-tag02 Users=Username ```

#### Human Readable Output
>Unregistered user-tag successfully


### panorama-query-traffic-logs
***
Deprecated. Queries traffic logs.

#### Base Command

`panorama-query-traffic-logs`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Specifies the match criteria for the logs. This is similar to the query provided in the web interface under the Monitor tab when viewing the logs. | Optional |
| number_of_logs | The number of logs to retrieve. Default is 100. Maximum is 5,000. | Optional |
| direction | Whether logs are shown oldest first (forward) or newest first (backward). Default is backward. | Optional |
| source | Source address for the query. | Optional |
| destination | Destination address for the query. | Optional |
| receive_time | Date and time after which logs were received, in the format: YYYY/MM/DD HH:MM:SS. | Optional |
| application | Application for the query. | Optional |
| to_port | Destination port for the query. | Optional |
| action | Action for the query. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.TrafficLogs.JobID | number | Job ID of the traffic logs query. | 
| Panorama.TrafficLogs.Status | string | Status of the traffic logs query. | 

#### Command Example
```!panorama-query-traffic-logs query="" number_of_logs="100" direction="backward" source="" destination="" receive_time="" application="" to_port="" action="allow"```

#### Human Readable Output

>### Query Traffic Logs:
>|JobID|Status|
>|---|---|
>| 1858 | Pending |


### panorama-check-traffic-logs-status
***
Deprecated. Checks the query status of traffic logs.

#### Base Command

`panorama-check-traffic-logs-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID of the query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.TrafficLogs.JobID | number | Job ID of the traffic logs query. | 
| Panorama.TrafficLogs.Status | string | Status of the traffic logs query. | 

#### Command Example
```!panorama-check-traffic-logs-status job_id="1865"```

#### Human Readable Output

>### Query Traffic Logs status:
>|JobID|Status|
>|---|---|
>| 1858 | Pending |


### panorama-get-traffic-logs
***
Deprecated. Retrieves traffic log query data by job id.

#### Base Command

`panorama-get-traffic-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID of the query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.TrafficLogs.JobID | number | Job ID of the traffic logs query. | 
| Panorama.TrafficLogs.Status | string | Status of the traffic logs query. | 
| Panorama.TrafficLogs.Logs.Action | string | Action of the traffic log. |
| Panorama.TrafficLogs.Logs.ActionSource | string | Action source of the traffic log. |
| Panorama.TrafficLogs.Logs.Application | string | Application of the traffic log. |
| Panorama.TrafficLogs.Logs.Category | string | Category of the traffic log. |
| Panorama.TrafficLogs.Logs.DeviceName | string | Device name of the traffic log. |
| Panorama.TrafficLogs.Logs.Destination | string | Destination of the traffic log. |
| Panorama.TrafficLogs.Logs.DestinationPort | string | Destination port of the traffic log. |
| Panorama.TrafficLogs.Logs.FromZone | string | From zone of the traffic log. |
| Panorama.TrafficLogs.Logs.Protocol | string | Protocol of the traffic log. |
| Panorama.TrafficLogs.Logs.ReceiveTime | string | Receive time of the traffic log. |
| Panorama.TrafficLogs.Logs.Rule | string | Rule of the traffic log. |
| Panorama.TrafficLogs.Logs.SessionEndReason | string | Session end reason of the traffic log. |
| Panorama.TrafficLogs.Logs.Source | string | Source of the traffic log. |
| Panorama.TrafficLogs.Logs.SourcePort | string | Source port of the traffic log. |
| Panorama.TrafficLogs.Logs.StartTime | string | Start time of the traffic log. |
| Panorama.TrafficLogs.Logs.ToZone | string | To zone of the traffic log. |

#### Command Example
```!panorama-get-traffic-logs job_id="1865"```


### panorama-list-rules
***
Returns a list of predefined Security Rules.


#### Base Command

`panorama-list-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pre_post | Rules location. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. | Optional | 
| device-group | The device group for which to return addresses (Panorama instances). | Optional | 
| tag | Tag for which to filter the rules. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityRule.Name | String | Rule name. | 
| Panorama.SecurityRule.Action | String | Action for the rule. | 
| Panorama.SecurityRule.Location | String | Rule location. | 
| Panorama.SecurityRule.Category | String | Rule category. | 
| Panorama.SecurityRule.Application | String | Application for the rule. | 
| Panorama.SecurityRule.Destination | String | Destination address. | 
| Panorama.SecurityRule.From | String | Rule from. | 
| Panorama.SecurityRule.Service | String | Service for the rule. | 
| Panorama.SecurityRule.To | String | Rule to. | 
| Panorama.SecurityRule.Source | String | Source address. | 
| Panorama.SecurityRule.DeviceGroup | string | Device group for the rule \(Panorama instances\). | 
| Panorama.SecurityRules.Tags | String | Rule tags. | 


#### Command Example
```!panorama-list-rules```

#### Context Example
```json
{
    "Panorama": {
        "SecurityRule": [
            {
                "Action": "drop",
                "Application": "fortnite",
                "Destination": "any",
                "From": "any",
                "Name": "demisto-7b6dc6e6",
                "Service": "any",
                "Source": "any",
                "To": "any"
            },
            {
                "Action": "drop",
                "Application": "fortnite",
                "Destination": "any",
                "From": "any",
                "Name": "demisto-125e5985",
                "Service": "any",
                "Source": "any",
                "To": "any"
            },
            {
                "Action": {
                    "#text": "drop",
                    "@admin": "api",
                    "@dirtyId": "2986",
                    "@time": "2020/10/13 05:00:06"
                },
                "Application": {
                    "#text": "fortnite",
                    "@admin": "api",
                    "@dirtyId": "2986",
                    "@time": "2020/10/13 05:00:06"
                },
                "Destination": {
                    "#text": "any",
                    "@admin": "api",
                    "@dirtyId": "2986",
                    "@time": "2020/10/13 05:00:06"
                },
                "From": {
                    "#text": "any",
                    "@admin": "api",
                    "@dirtyId": "2986",
                    "@time": "2020/10/13 05:00:06"
                },
                "Name": "demisto-9c9ed15a",
                "Service": {
                    "#text": "any",
                    "@admin": "api",
                    "@dirtyId": "2986",
                    "@time": "2020/10/13 05:00:06"
                },
                "Source": {
                    "#text": "any",
                    "@admin": "api",
                    "@dirtyId": "2986",
                    "@time": "2020/10/13 05:00:06"
                },
                "To": {
                    "#text": "any",
                    "@admin": "api",
                    "@dirtyId": "2986",
                    "@time": "2020/10/13 05:00:06"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Security Rules:
>|Name|Action|From|To|Service|
>|---|---|---|---|---|
>| demisto-7b6dc6e6 | drop | any | any | any |
>| demisto-125e5985 | drop | any | any | any |
>| demisto-9c9ed15a | @admin: api<br/>@dirtyId: 2986<br/>@time: 2020/10/13 05:00:06<br/>#text: drop | @admin: api<br/>@dirtyId: 2986<br/>@time: 2020/10/13 05:00:06<br/>#text: any | @admin: api<br/>@dirtyId: 2986<br/>@time: 2020/10/13 05:00:06<br/>#text: any | @admin: api<br/>@dirtyId: 2986<br/>@time: 2020/10/13 05:00:06<br/>#text: any |


### panorama-query-logs
***
Query logs in Panorama.


#### Base Command

`panorama-query-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| log-type | The log type. Can be "threat", "traffic", "wildfire", "url", or "data". | Required | 
| query | The query string by which to match criteria for the logs. This is similar to the query provided in the web interface under the Monitor tab when viewing the logs. | Optional | 
| time-generated | The time that the log was generated from the timestamp and prior to it.<br/>e.g "2019/08/11 01:10:44". | Optional | 
| addr-src | Source address. | Optional | 
| addr-dst | Destination address. | Optional | 
| ip | Source or destination IP address. | Optional | 
| zone-src | Source zone. | Optional | 
| zone-dst | Destination Source. | Optional | 
| action | Rule action. | Optional | 
| port-dst | Destination port. | Optional | 
| rule | Rule name, e.g "Allow all outbound". | Optional | 
| url | URL, e.g "safebrowsing.googleapis.com". | Optional | 
| filedigest | File hash (for WildFire logs only). | Optional | 
| number_of_logs | Maximum number of logs to retrieve. If empty, the default is 100. The maximum is 5,000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.JobID | String | Job ID of the logs query. | 
| Panorama.Monitor.Status | String | Status of the logs query. | 
| Panorama.Monitor.Message | String | Message of the logs query. | 


#### Command Example
```!panorama-query-logs log-type=data query="( addr.src in 192.168.1.12 )" ```

#### Human Readable Output

>### Query Logs:
>|JobID|Status|
>|---|---|
>| 678 | Pending |

### panorama-check-logs-status
***
Checks the status of a logs query.


#### Base Command

`panorama-check-logs-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID of the query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.JobID | String | Job ID of the logs query. | 
| Panorama.Monitor.Status | String | Status of the logs query. | 


#### Command Example
```!panorama-check-logs-status job_id=657 ```

#### Human Readable Output

>### Query Logs Status:
>|JobID|Status|
>|---|---|
>| 657 | Completed |

### panorama-get-logs
***
Retrieves the data of a logs query.


#### Base Command

`panorama-get-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job ID of the query. | Required | 
| ignore_auto_extract | Whether to auto-enrich the War Room entry. If "true", entry is not auto-enriched. If "false", entry is auto-extracted. Default is "true". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.Logs.Action | String | Action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", or "block-url". | 
| Panorama.Monitor.Logs.Application | String | Application associated with the session. | 
| Panorama.Monitor.Logs.Category | String | The URL category of the URL subtype. For WildFire subtype, it is the verdict on the file, and can be either "malicious", "phishing", "grayware"’, or "benign". For other subtypes, the value is "any". | 
| Panorama.Monitor.Logs.DeviceName | String | The hostname of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.DestinationAddress | String | Original session destination IP address. | 
| Panorama.Monitor.Logs.DestinationUser | String | Username of the user to which the session was destined. | 
| Panorama.Monitor.Logs.DestinationCountry | String | Destination country or internal region for private addresses. Maximum length is 32 bytes. | 
| Panorama.Monitor.Logs.DestinationPort | String | Destination port utilized by the session. | 
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
| Panorama.Monitor.Logs.NATDestinationIP | String | If destination NAT performed, the post-NAT destination IP address. | 
| Panorama.Monitor.Logs.NATDestinationPort | String | Post-NAT destination port. | 
| Panorama.Monitor.Logs.NATSourceIP | String | If source NAT performed, the post-NAT source IP address. | 
| Panorama.Monitor.Logs.NATSourcePort | String | Post-NAT source port. | 
| Panorama.Monitor.Logs.PCAPid | String | The packet capture \(pcap\) ID is a 64 bit unsigned integral denoting
an ID to correlate threat pcap files with extended pcaps taken as a part of
that flow. All threat logs will contain either a pcap_id of 0 \(no associated
pcap\), or an ID referencing the extended pcap file. | 
| Panorama.Monitor.Logs.IPProtocol | String | IP protocol associated with the session. | 
| Panorama.Monitor.Logs.Recipient | String | Only for the WildFire subtype, all other types do not use this field.
Specifies the name of the receiver of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.Rule | String | Name of the rule that the session matched. | 
| Panorama.Monitor.Logs.RuleID | String | ID of the rule that the session matched. | 
| Panorama.Monitor.Logs.ReceiveTime | String | Time the log was received at the management plane. | 
| Panorama.Monitor.Logs.Sender | String | Only for the WildFire subtype; all other types do not use this field.
Specifies the name of the sender of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | 
| Panorama.Monitor.Logs.SessionID | String | An internal numerical identifier applied to each session. | 
| Panorama.Monitor.Logs.DeviceSN | String | The serial number of the firewall on which the session was logged. | 
| Panorama.Monitor.Logs.Severity | String | Severity associated with the threat. Can be "informational", "low",
"medium", "high", or "critical". | 
| Panorama.Monitor.Logs.SourceAddress | String | Original session source IP address. | 
| Panorama.Monitor.Logs.SourceCountry | String | Source country or internal region for private addresses. Maximum
length is 32 bytes. | 
| Panorama.Monitor.Logs.SourceUser | String | Username of the user who initiated the session. | 
| Panorama.Monitor.Logs.SourcePort | String | Source port utilized by the session. | 
| Panorama.Monitor.Logs.ThreatCategory | String | Describes threat categories used to classify different types of
threat signatures. | 
| Panorama.Monitor.Logs.Name | String | Palo Alto Networks identifier for the threat. It is a description
string followed by a 64-bit numerical identifier | 
| Panorama.Monitor.Logs.ID | String | Palo Alto Networks ID for the threat. | 
| Panorama.Monitor.Logs.ToZone | String | The zone to which the session was destined. | 
| Panorama.Monitor.Logs.TimeGenerated | String | Time that the log was generated on the dataplane. | 
| Panorama.Monitor.Logs.URLCategoryList | String | A list of the URL filtering categories that the firewall used to
enforce the policy. | 
| Panorama.Monitor.Logs.Bytes | String | Total log bytes. | 
| Panorama.Monitor.Logs.BytesReceived | String | Log bytes received. | 
| Panorama.Monitor.Logs.BytesSent | String | Log bytes sent. | 
| Panorama.Monitor.Logs.Vsys | String | Vsys on the firewall that generated the log. | 


#### Command Example
```!panorama-get-logs job_id=678 ```

#### Human Readable Output

>### Query data Logs:
>|TimeGenerated|SourceAddress|DestinationAddress|Application|Action|Rule|
>|---|---|---|---|---|---|
>| 2019/07/24 08:50:24 | 1.1.1.1 | 2.3.4.5 | web-browsing | deny | any - any accept |

### panorama-security-policy-match
***
Checks whether a session matches a specified security policy. This command is only available on Firewall instances.


#### Base Command

`panorama-security-policy-match`
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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.SecurityPolicyMatch.Query | String | Query for the session to test. | 
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
| Panorama.SecurityPolicyMatch.QueryFields.From | String | The from zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.To | String | The to zone. | 
| Panorama.SecurityPolicyMatch.QueryFields.Protocol | String | The IP protocol value. | 
| Panorama.SecurityPolicyMatch.QueryFields.Source | String | The destination IP address. | 
| Panorama.SecurityPolicyMatch.QueryFields.SourceUser | String | The source user. | 


#### Command Example
```!panorama-security-policy-match destination=1.2.3.4 protocol=1 source=2.3.4.5```

#### Context Example
```json
{
    "Panorama": {
        "SecurityPolicyMatch": {
            "Query": "<test><security-policy-match><source>2.3.4.5</source><destination>1.2.3.4</destination><protocol>1</protocol></security-policy-match></test>",
            "QueryFields": {
                "Destination": "1.2.3.4",
                "Protocol": "1",
                "Source": "2.3.4.5"
            },
            "Rules": {
                "Action": "allow",
                "Category": "any",
                "Destination": "any",
                "From": "any",
                "Name": "any - any accept",
                "Source": "any",
                "To": "any"
            }
        }
    }
}
```

#### Human Readable Output

>### Matching Security Policies:
>|Name|Action|From|To|Source|Destination|
>|---|---|---|---|---|---|
>| any - any accept | allow | any | any | any | any |


### panorama-list-static-routes
***
Lists the static routes of a virtual router.


#### Base Command

`panorama-list-static-routes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | The name of the virtual router for which to list static routes. | Required | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 
| show_uncommitted | Whether to show an uncommitted configuration. Default is "false" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
|  Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
|  Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
|  Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
|  Panorama.StaticRoutes.RouteTable | String | The route table of a static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
|  Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 
| Panorama.StaticRoutes.Uncommitted | Boolean | Whether the static route is committed. | 


#### Command Example
```!panorama-list-static-routes virtual_router=virtual_router_test_DONT_DELETE```

#### Context Example
```json
{
    "Panorama": {
        "StaticRoutes": [
            {
                "BFDprofile": "None",
                "Destination": "2.3.4.5/32",
                "Metric": 14,
                "Name": "static_route_ip",
                "NextHop": "3.3.3.3",
                "RouteTable": "Unicast",
                "VirtualRouter": "virtual_router_test_DONT_DELETE"
            },
            {
                "Destination": "1.1.1.1/32",
                "Metric": 1012,
                "Name": "test_maya",
                "NextHop": "3.3.3.3",
                "VirtualRouter": "virtual_router_test_DONT_DELETE"
            }
        ]
    }
}
```

#### Human Readable Output

>### Displaying all Static Routes for the Virtual Router: virtual_router_test_DONT_DELETE
>|Name|Destination|NextHop|RouteTable|Metric|BFDprofile|
>|---|---|---|---|---|---|
>| static_route_ip | 2.3.4.5/32 | 3.3.3.3 | Unicast | 14 | None |
>| test_maya | 1.1.1.1/32 | 3.3.3.3 |  | 1012 |  |


### panorama-get-static-route
***
Returns the specified static route of a virtual router.


#### Base Command

`panorama-get-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | Name of the virtual router for which to display the static route. | Required | 
| static_route | Name of the static route to display. | Required | 
| template | The template for which to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
|  Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
|  Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
|  Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
|  Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
|  Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 


#### Command Example
```!panorama-get-static-route static_route=static_route_ip virtual_router=virtual_router_test_DONT_DELETE```

#### Context Example
```json
{
    "Panorama": {
        "StaticRoutes": {
            "BFDprofile": "None",
            "Destination": "2.3.4.5/32",
            "Metric": 14,
            "Name": "static_route_ip",
            "NextHop": "3.3.3.3",
            "RouteTable": "Unicast",
            "VirtualRouter": "virtual_router_test_DONT_DELETE"
        }
    }
}
```

#### Human Readable Output

>### Static route: static_route_ip
>|BFDprofile|Destination|Metric|Name|NextHop|RouteTable|VirtualRouter|
>|---|---|---|---|---|---|---|
>| None | 2.3.4.5/32 | 14 | static_route_ip | 3.3.3.3 | Unicast | virtual_router_test_DONT_DELETE |


### panorama-add-static-route
***
Adds a static route.


#### Base Command

`panorama-add-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| virtual_router | Virtual Router to which the routes will be added. | Required | 
| static_route | The name of the static route to add. The argument is limited to a maximum of 31 characters, is case-sensitive, and supports letters, numbers, spaces, hyphens, and underscores. | Required | 
| destination | The IP address and network mask in Classless Inter-domain Routing (CIDR) notation: ip_address/mask. For example, 192.168.0.1/24 for IPv4 or 2001:db8::/32 for IPv6). | Required | 
| nexthop_type | The type for the nexthop. Can be: "ip-address", "next-vr", "fqdn" or "discard". | Required | 
| nexthop_value | The next hop value. | Required | 
| metric | The metric port for the static route (1-65535). | Optional | 
| interface | The interface name in which to add the static route. | Optional | 
| template | The template to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
|  Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
|  Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
|  Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
|  Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
|  Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 


#### Command Example
```!panorama-add-static-route destination=2.3.4.5/32 nexthop_type="ip-address" nexthop_value=3.3.3.3 static_route=my_temp_route virtual_router=virtual_router_test_DONT_DELETE```

#### Context Example
```json
{
    "Panorama": {
        "StaticRoutes": {
            "@code": "20",
            "@status": "success",
            "msg": "command succeeded"
        }
    }
}
```

#### Human Readable Output

>New uncommitted static route my_temp_route configuration added.

### panorama-delete-static-route
***
Deletes a static route.


#### Base Command

`panorama-delete-static-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| route_name | The name of the static route to delete. | Required | 
| virtual_router | The virtual router from which the routes will be deleted. | Required | 
| template | The template for to use to run the command. Overrides the template parameter (Panorama instances). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.StaticRoutes.Name | String | The name of the static route. | 
| Panorama.StaticRoutes.BFDProfile | String | The BFD profile of the static route. | 
|  Panorama.StaticRoutes.Destination | String | The destination of the static route. | 
|  Panorama.StaticRoutes.Metric | Number | The metric \(port\) of the static route. | 
|  Panorama.StaticRoutes.NextHop | String | The next hop of the static route. Can be an IP address, FQDN, or a virtual router. | 
|  Panorama.StaticRoutes.RouteTable | String | The route table of the static route. | 
| Panorama.StaticRoutes.VirtualRouter | String | The virtual router to which the static router belongs. | 
|  Panorama.StaticRoutes.Template | String | The template in which the static route is defined \(Panorama instances only\). | 
| Panorama.StaticRoutes.Deleted | Boolean | Whether the static route was deleted. | 


#### Command Example
```!panorama-delete-static-route route_name=my_temp_route virtual_router=virtual_router_test_DONT_DELETE```

#### Context Example
```json
{
    "Panorama": {
        "StaticRoutes": {
            "Deleted": true,
            "Name": "my_temp_route"
        }
    }
}
```

#### Human Readable Output

>The static route: my_temp_route was deleted. Changes are not committed.

### panorama-show-device-version
***
Show firewall device software version.


#### Base Command

`panorama-show-device-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Serial number of the target device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Device.Info.Devicename | String | Devicename of the PAN-OS. | 
| Panorama.Device.Info.Model | String | Model of the PAN-OS. | 
| Panorama.Device.Info.Serial | String | Serial number of the PAN-OS. | 
| Panorama.Device.Info.Version | String | Version of the PAN-OS. | 


#### Command Example
```!panorama-show-device-version```

#### Context Example
```json
{
    "Panorama": {
        "Device": {
            "Info": {
                "Devicename": "PA-VM",
                "Model": "PA-VM",
                "Serial": "000000000000000",
                "Version": "8.1.7"
            }
        }
    }
}
```

#### Human Readable Output

>### Device Version:
>|Devicename|Model|Serial|Version|
>|---|---|---|---|
>| PA-VM | PA-VM | 000000000000000 | 8.1.7 |


### panorama-download-latest-content-update
***
Downloads the latest content update.


#### Base Command

`panorama-download-latest-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device to which to download the content update. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Download.JobID | String | Job ID of the content download. | 
| Panorama.Content.Download.Status | String | Content download status. | 


#### Command Example
```!panorama-download-latest-content-update ```

#### Human Readable Output

>### Content download:
>|JobID|Status|
>|---|---|
>| 657 | Pending |

### panorama-content-update-download-status
***
Checks the download status of a content update.


#### Base Command

`panorama-content-update-download-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device to which the content update is downloading. | Optional | 
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Download.JobID | String | Job ID to monitor. | 
| Panorama.Content.Download.Status | String | Download status. | 
| Panorama.Content.Download.Details | String | Job ID details. | 


#### Command Example
```!panorama-content-update-download-status job_id=678 ```

#### Human Readable Output

>### Content download status:
>|JobID|Status|Details|
>|---|---|---|
>| 678 | Completed | download succeeded with warnings |


### panorama-install-latest-content-update
***
Installs the latest content update.


#### Base Command

`panorama-install-latest-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device on which to install the content update. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | String | Job ID of the installation. | 
| Content.Install.Status | String | Installation status. | 


#### Command Example
```!panorama-install-latest-content-update ```

#### Human Readable Output

>### Result:
>|JobID|Status|
>|---|---|
>| 878 | Pending |


### panorama-content-update-install-status
***
Gets the installation status of the content update.


#### Base Command

`panorama-content-update-install-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The device on which to check the installation status of the content update. | Optional | 
| job_id | Job ID of the content installation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Content.Install.JobID | String | Job ID of the content installation. | 
| Panorama.Content.Install.Status | String | Content installation status. | 
| Panorama.Content.Install.Details | String | Content installation status details. | 


#### Command Example
```!panorama-content-update-install-status job_id=878 ```

#### Human Readable Output

>### Content install status:
>|JobID|Status|Details|
>|---|---|---|
>| 878 | Completed | installation succeeded with warnings |


### panorama-check-latest-panos-software
***
Checks the PAN-OS software version from the repository.


#### Base Command

`panorama-check-latest-panos-software`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the PAN-OS software version. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-check-latest-panos-software```


### panorama-download-panos-version
***
Downloads the target PAN-OS software version to install on the target device.


#### Base Command

`panorama-download-panos-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to download the PAN-OS software version. | Optional | 
| target_version | The target version number to install. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Download.JobID | number | Job ID of the PAN-OS download. | 
| Panorama.PANOS.Download.Status | String | Status of the PAN-OS download. | 


#### Command Example
```!panorama-download-panos-version target_version=1 ```

#### Human Readable Output

>### Result:
>|JobID|Status|
>|---|---|
>| 111 | Pending |

### panorama-download-panos-status
***
Gets the download status of the target PAN-OS software.


#### Base Command

`panorama-download-panos-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the download status. | Optional | 
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Download.JobID | string | Job ID of the PAN-OS download. | 
| Panorama.PANOS.Download.Status | String | PAN-OS download status. | 
| Panorama.PANOS.Download.Details | String | PAN-OS download details. | 


#### Command Example
```!panorama-download-panos-status job_id=999```

#### Human Readable Output

>### PAN-OS download status:
>|JobID|Status|Details|
>|---|---|---|
>| 999 | Completed | download succeeded with warnings |

### panorama-install-panos-version
***
Installs the target PAN-OS version on the specified target device.


#### Base Command

`panorama-install-panos-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device on which to install the target PAN-OS software version. | Optional | 
| target_version | Target PAN-OS version to install. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Install.JobID | string | Job ID from the PAN-OS installation. | 
| Panorama.PANOS.Install.Status | String | Status of the PAN-OS installation. | 


#### Command Example
```!panorama-install-panos-version target_version=1 ```

#### Human Readable Output

>### PAN-OS Installation:
>|JobID|Status|
>|---|---|
>| 111 | Pending |

### panorama-install-panos-status
***
Gets the installation status of the PAN-OS software.


#### Base Command

`panorama-install-panos-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device from which to get the installation status. | Optional | 
| job_id | Job ID to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.PANOS.Install.JobID | number | Job ID of the PAN-OS installation. | 
| Panorama.PANOS.Install.Status | String | Status of the PAN-OS installation. | 
| Panorama.PANOS.Install.Details | String | PAN-OS installation details. | 


#### Command Example
```!panorama-install-panos-status job_id=878 ```

#### Human Readable Output

>### PAN-OS installation status:
>|JobID|Status|Details|
>|---|---|---|
>| 878 | Completed | installation succeeded with warnings |

### panorama-device-reboot
***
Reboots the Firewall device.


#### Base Command

`panorama-device-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | The target device for which to reboot the firewall. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-device-reboot ```


### panorama-show-location-ip
***
Gets location information for an IP address.


#### Base Command

`panorama-show-location-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address from which to return information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Location.IP.country_code | String | The IP address location country code. | 
| Panorama.Location.IP.country_name | String | The IP addres location country name. | 
| Panorama.Location.IP.ip_address | String | The IP address. | 
| Panorama.Location.IP.Status | String | Whether the IP address was found. | 


#### Command Example
```!panorama-show-location-ip ip_address=8.8.8.8```

#### Context Example
```json
{
    "Panorama": {
        "Location": {
            "IP": {
                "country_code": "US",
                "country_name": "United States",
                "ip_address": "8.8.8.8",
                "status": "Found"
            }
        }
    }
}
```

#### Human Readable Output

>### IP 8.8.8.8 location:
>|ip_address|country_name|country_code|
>|---|---|---|
>| 8.8.8.8 | United States | US |


### panorama-get-licenses
***
Gets information about available PAN-OS licenses and their statuses.


#### Base Command

`panorama-get-licenses`
#### Input

There are no input arguments for this command.

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


#### Command Example
```!panorama-get-licences ```

#### Human Readable Output

>|Authcode|Description|Feature|Serial|Expired|Expires|Issued|
>|---|---|---|---|---|---|---|
>| I9805928  | NFR Support | NFR Support | 007DEMISTO1t | no | Never | November 25, 2019 |

### panorama-get-security-profiles
***
Gets information for the specified security profile.


#### Base Command

`panorama-get-security-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_profile | The security profile for which to get information. Can be "data-filtering", "file-blocking", "spyware", "url-filtering", "virus", "vulnerability", or "wildfire-analysis". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Spyware.Name | String | The profile name. | 
| Panorama.Spyware.Rules.Action | String | The rule action. | 
| Panorama.Spyware.Rules.Cateogry | String | The category for which to apply the rule. | 
| Panorama.Spyware.Rules.Name | String | The rule name. | 
| Panorama.Spyware.Rules.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Spyware.Rules.Severity | String | The rule severity. | 
| Panorama.Spyware.Rules.Threat-name | String | The threat name for which to apply the rule. | 
| Panorama.URLFilter.Name | String | The profile name. | 
| Panorama.URLFilter.Rules.Category.Action | String | The rule action to apply to the category. | 
| Panorama.URLFilter.Rules.Category.Name | String | The category name. | 
| Panorama.WildFire.Name | String | The WildFire profile name. | 
| Panorama.WildFire.Rules.Analysis | String | The rule analysis. | 
| Panorama.WildFire.Rules.Application | String | The application for which to apply the rule. | 
| Panorama.WildFire.Rules.File-type | String | The file type for which to apply the rule. | 
| Panorama.WildFire.Rules.Name | String | The rule name. | 
| Panorama.Vulnerability.Name | String | The vulnerability profile name. | 
| Panorama.Vulnerability.Rules.Vendor-id | String | The vendor ID for which to apply the rule. | 
| Panorama.Vulnerability.Rules.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Vulnerability.Rules.Host | String | The rule host. | 
| Panorama.Vulnerability.Rules.Name | String | The rule name. | 
| Panorama.Vulnerability.Rules.Cateogry | String | The category for which to apply the rule. | 
| Panorama.Vulnerability.Rules.CVE | String | The CVE for which to apply the rule. | 
| Panorama.Vulnerability.Rules.Action | String | The rule action. | 
| Panorama.Vulnerability.Rules.Severity | String | The rule severity. | 
| Panorama.Vulnerability.Rules.Threat-name | String | The threat for which to apply the rule. | 
| Panorama.Antivirus.Name | String | The Antivirus profile name. | 
| Panorama.Antivirus.Rules.Action | String | The rule action. | 
| Panorama.Antivirus.Rules.Name | String | The rule name. | 
| Panorama.Antivirus.Rules.WildFire-action | String | The WildFire action. | 
| Panorama.FileBlocking.Name | String | The file blocking profile name. | 
| Panorama.FileBlocking.Rules.Action | String | The rule action. | 
| Panorama.FileBlocking.Rules.Application | String | The application for which to apply the rule. | 
| Panorama.FileBlocking.Rules.File-type | String | The file type to apply the rule. | 
| Panorama.FileBlocking.Rules.Name | String | The rule name. | 
| Panorama.DataFiltering.Name | String | The data filtering profile name. | 
| Panorama.DataFiltering.Rules.Alert-threshold | String | The alert threshold. | 
| Panorama.DataFiltering.Rules.Application | String | The application to apply the rule. | 
| Panorama.DataFiltering.Rules.Block-threshold | String | The block threshold. | 
| Panorama.DataFiltering.Rules.Data-object | String | The data object. | 
| Panorama.DataFiltering.Rules.Direction | String | The rule direction. | 
| Panorama.DataFiltering.Rules.File-type | String | The file type for which to apply the rule. | 
| Panorama.DataFiltering.Rules.Log-severity | String | The log severity. | 
| Panorama.DataFiltering.Rules.Name | String | The rule name. | 


#### Command Example
```!panorama-get-security-profiles security_profile=spyware ```

#### Human Readable Output

>|Name|Rules|
>|---|---|
>| best-practice  | {'Name': 'simple-critical', 'Action': {'reset-both': None}, 'Category': 'any', 'Severity': 'critical', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br/>{'Name': 'simple-high', 'Action': {'reset-both': None}, 'Category': 'any', 'Severity': 'high', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br/>{'Name': 'simple-medium', 'Action': {'reset-both': None}, 'Category': 'any', 'Severity': 'medium', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br/>{'Name': 'simple-informational', 'Action': {'default': None}, 'Category': 'any', 'Severity': 'informational', 'Threat-name': 'any', 'Packet-capture': 'disable'},<br/>{'Name': 'simple-low', 'Action': {'default': None}, 'Category': 'any', 'Severity': 'low', 'Threat-name': 'any', 'Packet-capture': 'disable'} |

### panorama-apply-security-profile
***
Apply a security profile to specific rules or rules with a specific tag.


#### Base Command

`panorama-apply-security-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_type | Security profile type. Can be 'data-filtering', 'file-blocking', 'spyware', 'url-filtering', 'virus, 'vulnerability', or wildfire-analysis.' | Required | 
| rule_name | The rule name to apply. | Required | 
| profile_name | The profile name to apply to the rule. | Required | 
| pre_post | The location of the rules. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-apply-security-profile profile_name=test profile_type=spyware rule_name=rule1 pre_post="pre-rulebase" ```

#### Human Readable Output
>The profile test has been applied to the rule rule1


### panorama-get-ssl-decryption-rules
***
Get SSL decryption rules.


#### Base Command

`panorama-get-ssl-decryption-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pre_post | The location of the rules. Can be 'pre-rulebase' or 'post-rulebase'. Mandatory for Panorama instances. | Optional | 


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


#### Command Example
```!panorama-get-ssl-decryption-rules pre_post="pre-rulebase" ```

#### Human Readable Output

>|Name|UUID|Target|Service|Category|Type|From|To|Source|Destenation|Action|Source-user|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| test | some_uuid | negate: no | any | member: any | ssl-forward-proxy: null | any | any | any | any | no-decrypt | any |

### panorama-get-wildfire-configuration
***
Retrieves the Wildfire configuration.


#### Base Command

`panorama-get-wildfire-configuration`
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


#### Command Example
```!panorama-get-wildfire-configuration template=WildFire ```


>### WildFire Configuration
> Report Grayware File: yes
>|Name|Size-limit|
>|---|---|
>| pe | 10 |
>| apk | 30 |

>### The updated schedule for Wildfire
>|recurring|
>|---|
>| every-min: {"action": "download-and-install"} |


### panorama-url-filtering-block-default-categories
***
Set default categories to block in the URL filtering profile.


#### Base Command

`panorama-url-filtering-block-default-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The url-filtering profile name. Get the name by running the get-security-profiles command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-url-filtering-block-default-categories profile_name=test ```

#### Human Readable Output

>The default categories to block has been set successfully to test

### panorama-get-anti-spyware-best-practice
***
Get anti-spyware best practices.


#### Base Command

`panorama-get-anti-spyware-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Spyware.BotentDomain.Name | String | The botnet domain name. | 
| Panorama.Spyware.BotentDomain.Action | String | The botnet domain action. | 
| Panorama.Spyware.BotentDomain.Packet-capture | String | Whether packet capture is enabled. | 
| Panorama.Spyware.BotentDomain.Sinkhole.ipv4-address | String | The botnet domain IPv4 address. | 
| Panorama.Spyware.BotentDomain.Sinkhole.ipv6-address | String | The Botnet domain IPv6 address. | 
| Panorama.Spyware.Rule.Cateogry | String | The rule category. | 
| Panorama.Spyware.Rule.Action | String | The rule action. | 
| Panorama.Spyware.Rule.Name | String | The rule name. | 
| Panorama.Spyware.Rule.Severity | String | The rule severity. | 
| Panorama.Spyware.Rule.Threat-name | String | The rule threat name. | 
| Panorama.Spyware.BotentDomain.Max_version | String | The botnet domain max version. | 


#### Command Example
```!panorama-get-anti-spyware-best-practice ```

#### Human Readable Output

>### Anti Spyware Botnet-Domains Best Practice
>|Name|Action|Packet-capture|ipv4-address|ipv6-address|
>|---|---|---|---|---|
>| default-paloalto-dns | sinkhole: null | disable |  |  |
>| default-paloalto-cloud | allow: null | disable |  |  |
>|  |  |  | pan-sinkhole-default-ip | ::1 |

>### Anti Spyware Best Practice Rules
>|Name|Severity|Action|Category|Threat-name|
>|---|---|---|---|---|
>| simple-critical | critical | reset-both: null | any | any |
>| simple-high | high | reset-both: null | any | any |

### panorama-get-file-blocking-best-practice
***
Get file-blocking best practices.


#### Base Command

`panorama-get-file-blocking-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.FileBlocking.Rule.Action | String | The rule action. | 
| Panorama.FileBlocking.Rule.Application | String | The rule application. | 
| Panorama.FileBlocking.Rule.File-type | String | The rule file type. | 
| Panorama.FileBlocking.Rule.Name | String | The rule name. | 


#### Command Example
```!panorama-get-file-blocking-best-practice ```

#### Human Readable Output

>### File Blocking Profile Best Practice
>|Name|Action|File-type|Aplication|
>|---|---|---|---|
>| Block all risky file types | block | 7z,<br/>bat,<br/>cab,<br/>chm,<br/>class,<br/>cpl | any |
>| Block encrypted files | block | encrypted-rar,<br/>encrypted-zip| any |

### panorama-get-antivirus-best-practice
***
Get anti-virus best practices.


#### Base Command

`panorama-get-antivirus-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Antivirus.Decoder.Action | String | The rule action. | 
| Panorama.Antivirus.Decoder.Name | String | The rule name. | 
| Panorama.Antivirus.Decoder.WildFire-action | String | The WildFire action. | 


#### Command Example
```!panorama-get-antivirus-best-practice ```

#### Human Readable Output

>### Antivirus Best Practice Profile
>|Name|Action|WildFire-action|
>|---|---|---|
>| http | default | default|
>| smtp default | default |

### panorama-get-vulnerability-protection-best-practice
***
Get vulnerability-protection best practices.


#### Base Command

`panorama-get-vulnerability-protection-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Vulnerability.Rule.Action | String | The rule action. | 
| Panorama.Vulnerability.Rule.CVE | String | The rule CVE. | 
| Panorama.Vulnerability.Rule.Cateogry | String | The rule category. | 
| Panorama.Vulnerability.Rule.Host | String | The rule host. | 
| Panorama.Vulnerability.Rule.Name | String | The rule name. | 
| Panorama.Vulnerability.Rule.Severity | String | The rule severity. | 
| Panorama.Vulnerability.Rule.Threat-name | String | The threat name. | 
| Panorama.Vulnerability.Rule.Vendor-id | String | The vendor ID. | 


#### Command Example
```!panorama-get-vulnerability-protection-best-practice ```

#### Human Readable Output

>### vulnerability Protection Best Practice Profile
>|Name|Action|Host|Severity|Category|Threat-name|CVE|Vendor-id|
>|---|---|---|---|---|---|---|---|
>| simple-client-critical | reset-both: null | client | critical | any | any | any | any |
>| simple-client-high | reset-both: null | client | high | any | any | any | any |

### panorama-get-wildfire-best-practice
***
View WildFire best practices.


#### Base Command

`panorama-get-wildfire-best-practice`
#### Input

There are no input arguments for this command.

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


#### Command Example
```!panorama-get-wildfire-best-practice ```

#### Human Readable Output

>### WildFire Best Practice Profile
>|Name|Analysis|Aplication|File-type|
>|---|---|---|---|
>| default | public-cloud | any | any |

>### Wildfire Best Practice Schedule
>|Action|Recurring|
>|---|---|
>| download-and-install | every-minute |

>### Wildfire SSL Decrypt Settings
>|allow-forward-decrypted-content|
>|---|
>| yes |

>### Wildfire System Settings
>report-grayware-file: yes
>|Name|File-size|
>|---|---|
>| pe | 10 |
>| apk | 30 |

### panorama-get-url-filtering-best-practice
***
View URL Filtering best practices.


#### Base Command

`panorama-get-url-filtering-best-practice`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.URLFilter.Category.Action | String | The action to perform on the category. | 
| Panorama.URLFilter.Category.Name | String | The category name. | 
| Panorama.URLFilter.DeviceGroup | String | The device group name. | 
| Panorama.URLFilter.Name | String | The Profile name. | 
| Panorama.URLFilter.Header.log-container-page-only | String | The log container page only. | 
| Panorama.URLFilter.Header.log-http-hdr-referer | String | The log HTTP header referer. | 
| Panorama.URLFilter.Header.log-http-hdr-user | String | The log HTTP header user. | 
| Panorama.URLFilter.Header.log-http-hdr-xff | String | The log HTTP header xff. | 


#### Command Example
```!panorama-get-url-filtering-best-practice ```

#### Human Readable Output

>### URL Filtering Best Practice Profile Categories
>|Category|DeviceGroup|Name|
>|---|---|---|
>| {'Name': 'abortion', 'Action': 'alert'},<br/>{'Name': 'abused-drugs', 'Action': 'alert'} | Demisto sales lab | best-practice |


>### Best Practice Headers
>|log-container-page-only|log-http-hdr-referer|log-http-hdr-user|log-http-hdr-xff|
>|---|---|---|---|
>| yes | yes | yes | yes |

### panorama-enforce-wildfire-best-practice
***
Enforces wildfire best practices to upload files to the maximum size, forwards all file types, and updates the schedule.


#### Base Command

`panorama-enforce-wildfire-best-practice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template | The template name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-enforce-wildfire-best-practice template=WildFire ```

#### Human Readable Output

>The schedule was updated according to the best practice. Recurring every minute with the action of "download and install" The file upload for all file types is set to the maximum size.

### panorama-create-antivirus-best-practice-profile
***
Creates an antivirus best practice profile.


#### Base Command

`panorama-create-antivirus-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile to create. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-create-antivirus-best-practice-profile profile_name=test ```

#### Human Readable Output

>The profile test was created successfully.

### panorama-create-anti-spyware-best-practice-profile
***
Creates an Anti-Spyware best practice profile.


#### Base Command

`panorama-create-anti-spyware-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name to create. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-create-anti-spyware-best-practice-profile profile_name=test ```

#### Human Readable Output

>The profile test was created successfully.

### panorama-create-vulnerability-best-practice-profile
***
Creates a vulnerability protection best practice profile.


#### Base Command

`panorama-create-vulnerability-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-create-vulnerability-best-practice-profile profile_name=test ```

#### Human Readable Output

>The profile test was created successfully.

### panorama-create-url-filtering-best-practice-profile
***
Creates a URL filtering best practice profile.


#### Base Command

`panorama-create-url-filtering-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The profile name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-create-url-filtering-best-practice-profile profile_name=test ```

#### Human Readable Output

>The profile test was created successfully.

### panorama-create-file-blocking-best-practice-profile
***
Creates a file blocking best practice profile.


#### Base Command

`panorama-create-file-blocking-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-create-file-blocking-best-practice-profile profile_name=test ```

#### Human Readable Output

>The profile test was created successfully.

### panorama-create-wildfire-best-practice-profile
***
Creates a WildFire analysis best practice profile.


#### Base Command

`panorama-create-wildfire-best-practice-profile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the profile. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!panorama-create-wildfire-best-practice-profile profile_name=test ```

#### Human Readable Output

>The profile test was created successfully.
