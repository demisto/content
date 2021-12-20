Qualys Vulnerability Management let's you create, run, fetch and manage reports. Launch and manage vulnerability and compliance scans. Manage the host assets you want to scan for vulnerabilities and compliance
This integration was integrated and tested with version xx of QualysV2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-qualys-v2).

## Configure Qualys v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Qualys v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Username | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### qualys-ip-list
***
View a list of IP addresses in the user account.


#### Base Command

`qualys-ip-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | Show only certain IP addresses/ranges. | Optional | 
| network_id | Restrict the request to a certain custom network ID. | Optional | 
| tracking_method | Show only IP addresses/ranges which have a certain tracking method. Possible values are: IP, DNS, NETBIOS. | Optional | 
| compliance_enabled | Specify 1 to list compliance IP addresses in the user’s account. These hosts are assigned to the policy compliance module. or 0 to get host that are not. Possible values are: 0, 1. | Optional | 
| certview_enabled | (Optional) Set to 1 to list IP addresses in the user’s account assigned to the Certificate View module. Specify 0 to list IPs that are not assigned to the Certificate View module. Note - This option will be supported when Certificate View GA is released and is enabled for your account. Possible values are: 0, 1. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.IP.Address | unknown | IP Addresses. | 
| Qualys.IP.Range | unknown | IP Range. | 

### qualys-report-list
***
Get a list of generated reports in the system


#### Base Command

`qualys-report-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify a report ID of a report that is saved in the Report Share storage space. | Optional | 
| state | Specify reports with a certain state. Possible values are: Running, Finished, Canceled, Errors. | Optional | 
| user_login | Specify a user login ID to get reports launched by the specified user login ID. | Optional | 
| expires_before_datetime | Specify the date and time to get only reports that expire before it. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| client_id | (Optional) Id assigned to the client (Consultant type subscriptions). | Optional | 
| client_name | (Optional) Name of the client (Consultant type subscriptions). Note, The client_id and client_name parameters are mutually exclusive and cannot be specified together in the same request. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Report ID. | 
| Qualys.Report.TITLE | unknown | Report title. | 
| Qualys.Report.TYPE | unknown | Report type. | 
| Qualys.Report.LAUNCH_DATETIME | unknown | Date and time the report launched. | 
| Qualys.Report.OUTPUT_FORMAT | unknown | Report output format. | 
| Qualys.Report.SIZE | unknown | Report size. | 
| Qualys.Report.STATUS.STATE | unknown | Report state status. | 
| Qualys.Report.STATUS.MESSAGE | unknown | Report status message. | 
| Qualys.Report.STATUS.PERCENT | unknown | Report status percent. | 
| Qualys.Report.EXPIRATION_DATETIME | unknown | Report expiration datetime. | 

### qualys-vm-scan-list
***
Lists vulnerability scans in the user’s account


#### Base Command

`qualys-vm-scan-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_ref | Show only a scan with a certain scan referenc ecode. | Optional | 
| state | Show only one or more scan states. | Optional | 
| processed | Specify 0 to show only scans that are not processed. Specify 1 to show only scans that have been processed. Possible values are: 0, 1. | Optional | 
| type | Show only a certain scan type. Possible values are: On-Demand, Scheduled, API. | Optional | 
| target | Show only one or more target IP addresses. | Optional | 
| user_login | Show only a certain user login. | Optional | 
| launched_after_datetime | Show only scans launched after a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week.'. | Optional | 
| launched_before_datetime | Show only scans launched before a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week.'. | Optional | 
| show_ags | Specify 1 to show asset group information for each scan in the output. Possible values are: 1. | Optional | 
| show_op | Specify 1 to show option profile information for each scan in the output. Possible values are: 1. | Optional | 
| show_status | Specify 0 to not show scan status for each scan in the output. Possible values are: 0. | Optional | 
| show_last | Specify 1 to show only the most recent scan (which meets all other search filters in the request) in the output. Possible values are: 1. | Optional | 
| scan_id | (Optional) Show only a scan with a certain compliance scan ID. | Optional | 
| client_id | (Optional) Id assigned to the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| client_name | (Optional) Name of the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| pci_only | (Optional) Specify 1 to show only external PCI scans in the XML output. External PCI scans are vulnerability scans run with the option profile "Payment Card Industry (PCI) Options". When pci_only=1 is specified, the XML output will not include other types of scans run with other option profiles. Possible values are: 1. | Optional | 
| ignore_target | (Optional) Specify 1 to hide target information from the scan list. Specify 0 to display the target information. Possible values are: 1, 0. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Scan.REF | unknown | Scan REF. | 
| Qualys.Scan.TYPE | unknown | Scan type. | 
| Qualys.Scan.TITLE | unknown | Scan title. | 
| Qualys.Scan.LAUNCH_DATETIME | unknown | Date and time the scan launched. | 
| Qualys.Scan.DURATION | unknown | Scan Duration. | 
| Qualys.Scan.PROCESSING_PRIORITY | unknown | Scan Processing Priority. | 
| Qualys.Scan.PROCESSED | unknown | Scan Processed. | 
| Qualys.Scan.STATUS.STATE | unknown | Scan status state. | 
| Qualys.Scan.STATUS.SUB_STATE | unknown | Scan status sub state. | 
| Qualys.Scan.SCHEDULE | unknown | Scan Schedule. | 
| Qualys.Scan.TARGET | unknown | Scan Target. | 
| Qualys.Scan.ASSET_GROUP_TITLE | unknown | Target Asset Group Title. | 
| Qualys.Scan.DEFAULT_FLAG | unknown | Scan Deafualt Flag. | 
| Qualys.Scan.USER_LOGIN | unknown | The user that created the scan. | 

### qualys-scap-scan-list
***
Gives you a list of SCAP scans in your account


#### Base Command

`qualys-scap-scan-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_ref | Show only a scan with a certain scan reference code. | Optional | 
| state | Show only one or more scan states. | Optional | 
| processed | Specify 0 to show only scans that are not processed. Specify 1 to show only scans that have been processed. Possible values are: 0, 1. | Optional | 
| type | Show only a certain scan type. Possible values are: On-Demand, Scheduled, API. | Optional | 
| target | Show only one or more target IP addresses. | Optional | 
| user_login | Show only a certain user login. | Optional | 
| launched_after_datetime | Show only scans launched after a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week.'. | Optional | 
| launched_before_datetime | Show only scans launched before a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week.'. | Optional | 
| show_ags | Specify 1 to show asset group information for each scan in the output. Possible values are: 1. | Optional | 
| show_op | Specify 1 to show option profile information for each scan in the output. Possible values are: 1. | Optional | 
| show_status | Specify 0 to not show scan status for each scan in the output. Possible values are: 0. | Optional | 
| show_last | Specify 1 to show only the most recent scan (which meets all other search filters in the request) in the output. Possible values are: 1. | Optional | 
| scan_id | (Optional) Show only a scan with a certain compliance scan ID. | Optional | 
| client_id | (Optional) Id assigned to the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| client_name | (Optional) Name of the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| pci_only | (Optional) Specify 1 to show only external PCI scans in the XML output. External PCI scans are vulnerability scans run with the option profile "Payment Card Industry (PCI) Options". When pci_only=1 is specified, the XML output will not include other types of scans run with other option profiles. Possible values are: 1. | Optional | 
| ignore_target | (Optional) Specify 1 to hide target information from the scan list. Specify 0 to display the target information. Possible values are: 1, 0. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.SCAP.Scan.ID | unknown | Scan ID. | 
| Qualys.SCAP.Scan.Reference | unknown | Scan ref. | 
| Qualys.SCAP.Scan.REF | unknown | Scan REF. | 
| Qualys.SCAP.Scan.Type | unknown | Scan type. | 
| Qualys.SCAP.Scan.Title | unknown | Scan title. | 
| Qualys.SCAP.Scan.LaunchDatetime | unknown | Date and time the scan launched. | 
| Qualys.SCAP.Scan.Duration | unknown | Scan Duration. | 
| Qualys.SCAP.Scan.ProcessingPriority | unknown | Scan Processing Priority. | 
| Qualys.SCAP.Scan.Processed | unknown | Scan Processed. | 
| Qualys.SCAP.Scan.Status.State | unknown | Scan status state. | 
| Qualys.SCAP.Scan.Status.SubState | unknown | Scan status sub state. | 
| Qualys.SCAP.Scan.Schedule | unknown | Scan Schedule. | 
| Qualys.SCAP.Scan.Target | unknown | Scan Target. | 
| Qualys.SCAP.Scan.AssetGroupTitle | unknown | Target Asset Group Title. | 
| Qualys.SCAP.Scan.DeafualtFlag | unknown | Scan Deafualt Flag. | 
| Qualys.SCAP.Scan.UserLogin | unknown | The user that created the scan. | 

### qualys-pc-scan-list
***
Get a list of compliance scans in your account.


#### Base Command

`qualys-pc-scan-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | Scan id. | Optional | 
| scan_ref | Scan reference. | Optional | 
| state | Show only one or more scan states. | Optional | 
| processed | Specify 0 to show only scans that are not processed. Specify 1 to show only scans that have been processed. Possible values are: 0, 1. | Optional | 
| type | Show only a certain scan type. | Optional | 
| target | Show only one or more target IP addresses. | Optional | 
| user_login | Show only a certain user login. | Optional | 
| launched_after_datetime | Show only scans launched after a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week.'. | Optional | 
| launched_before_datetime | Show only scans launched before a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week.'. | Optional | 
| show_ags | Specify 1 to show asset group information for each scan in the output. Possible values are: 1. | Optional | 
| show_op | Specify 1 to show option profile information for each scan in the output. Possible values are: 1. | Optional | 
| show_status | Specify 0 to not show scan status for each scan in the output. Possible values are: 0. | Optional | 
| show_last | Specify 1 to show only the most recent scan (which meets all other search filters in the request) in the output. Possible values are: 1. | Optional | 
| pci_only | Specify 1 to show only external PCI scans in the XML output. External PCI scans are vulnerability scans run with the option profile "Payment Card Industry (PCI) Options". When pci_only=1 is specified, the XML output will not include other types of scans run with other option profiles. Possible values are: 1, 0. | Optional | 
| ignore_target | Specify 1 to hide target information from the scan list. Specify 0 to display the target information. Possible values are: 1, 0. | Optional | 
| client_id | (Optional) Id assigned to the client (Consultant type subscriptions). | Optional | 
| client_name | (Optional) Name of the client (Consultant type subscriptions). Note, The client_id and client_name parameters are mutually exclusive and cannot be specified together in the same request. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Scan.REF | unknown | Scan REF. | 
| Qualys.Scan.TYPE | unknown | Scan type. | 
| Qualys.Scan.TITLE | unknown | Scan title. | 
| Qualys.Scan.LAUNCH_DATETIME | unknown | Date and time the scan launched. | 
| Qualys.Scan.DURATION | unknown | Scan Duration. | 
| Qualys.Scan.PROCESSING_PRIORITY | unknown | Scan Processing Priority. | 
| Qualys.Scan.PROCESSED | unknown | Scan Processed. | 
| Qualys.Scan.STATUS.STATE | unknown | Scan status state. | 
| Qualys.Scan.STATUS.SUB_STATE | unknown | Scan status sub state. | 
| Qualys.Scan.SCHEDULE | unknown | Scan Schedule. | 
| Qualys.Scan.TARGET | unknown | Scan Target. | 
| Qualys.Scan.ASSET_GROUP_TITLE | unknown | Target Asset Group Title. | 
| Qualys.Scan.DEFAULT_FLAG | unknown | Scan Deafualt Flag. | 
| Qualys.Scan.USER_LOGIN | unknown | The user that created the scan. | 

### qualys-schedule-scan-list
***
Shows schedule scans


#### Base Command

`qualys-schedule-scan-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the scan schedule you want to display. | Optional | 
| active | Specify 1 for active schedules only, or 0 for deactivated schedules only. Possible values are: 0, 1. | Optional | 
| show_notifications | (Optional) Specify 1 to include the notification settings for each schedule in the XML output. | Optional | 
| scan_type | (Optional) Launch a scan with a certain type. Possible values are: certview, perimeter. | Optional | 
| fqdn | (Optional) The target FQDN for a vulnerability scan. You must specify at least one target i.e. IPs, asset groups or FQDNs. Multiple values are comma separated. | Optional | 
| show_cloud_details | (Optional) Set to 1 to display the cloud details (Provider, Connector, Scan Type and Cloud Target) in the XML output. Otherwise the details are not displayed in the output. The cloud details will show scan type "Cloud Perimeter" for cloud perimeter scans. | Optional | 
| client_id | (Optional) Id assigned to the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| client_name | (Optional) Name of the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Scan.ID | unknown | Scan ID. | 
| Qualys.Scan.REF | unknown | Scan REF. | 
| Qualys.Scan.TYPE | unknown | Scan type. | 
| Qualys.Scan.TITLE | unknown | Scan title. | 
| Qualys.Scan.LAUNCH_DATETIME | unknown | Date and time the scan launched. | 
| Qualys.Scan.DURATION | unknown | Scan Duration. | 
| Qualys.Scan.PROCESSING_PRIORITY | unknown | Scan Processing Priority. | 
| Qualys.Scan.PROCESSED | unknown | Scan Processed. | 
| Qualys.Scan.STATUS.STATE | unknown | Scan status state. | 
| Qualys.Scan.STATUS.SUB_STATE | unknown | Scan status sub state. | 
| Qualys.Scan.TARGET | unknown | Scan Target. | 
| Qualys.Scan.ASSET_GROUP_TITLE | unknown | Target Asset Group Title. | 
| Qualys.Scan.DEFAULT_FLAG | unknown | Scan Deafualt Flag. | 
| Qualys.Scan.USER_LOGIN | unknown | The user that created the scan. | 
| Qualys.Scan.ACTIVE | unknown | Scheduled scan active. | 
| Qualys.Scan.USER_ENTERED_IPS.RANGE.START | unknown | IP range requested start. | 
| Qualys.Scan.USER_ENTERED_IPS.RANGE.END | unknown | IP range requested end. | 
| Qualys.Scan.ISCANNER_NAME | unknown | Iscanner name used in the scan. | 
| Qualys.Scan.SCHEDULE.DAILY.@frequency_days | unknown | Frequency of usage of the scan. | 
| Qualys.Scan.SCHEDULE.START_DATE_UTC | unknown | Start date of the scheduled scan in UTC format. | 
| Qualys.Scan.SCHEDULE.START_HOUR | unknown | Start hour of the scheduled scan. | 
| Qualys.Scan.SCHEDULE.START_MINUTE | unknown | Start minute of the scheduled scan. | 
| Qualys.Scan.SCHEDULE.TIME_ZONE.TIME_ZONE_CODE | unknown | Time zone code of the time for the scheduled scan. | 
| Qualys.Scan.SCHEDULE.TIME_ZONE.TIME_ZONE_DETAILS | unknown | Time zone details of the time for the scheduled scan. | 
| Qualys.Scan.OPTION_PROFILE.DEFAULT_FLAG | unknown | Default flag of the option profile. | 
| Qualys.Scan.OPTION_PROFILE.TITLE | unknown | Title of the option profile. | 
| Qualys.Scan.EC2_INSTANCE.CONNECTOR_UUID | unknown | Connector UUID of EC2 instance. | 
| Qualys.Scan.EC2_INSTANCE.EC2_ENDPOINT | unknown | Endpoint of EC2 instance. | 
| Qualys.Scan.EC2_INSTANCE.EC2_ONLY_CLASSIC | unknown | EC2 only classic. | 

### qualys-host-list
***
View a list of scanned hosts in the user account.


#### Base Command

`qualys-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| os_pattern | Show only hosts which have an operating system matching a certain regular expression. An empty value cannot be specified. Use “%5E%24” to match empty string. | Optional | 
| truncation_limit | Specify the maximum number of host records processed per request. When not specified, the truncation limit is set to 1000 host records. You may specify a value less than the default (1-999) or greater than the default (1001-1000000). | Optional | 
| ips | Show only certain IP addresses/ranges. One or more IPs/ranges may be specified. Multiple entries are comma separated. An IP range is specified with a hyphen (for example, 10.10.10.1-10.10.10.100). | Optional | 
| ag_titles | Show only hosts belonging to asset groups with certain strings in the asset group title. One or more asset group titles may be specified. Multiple entries are comma separated (for example, My+First+Asset+Group,Another+Asset+Group). | Optional | 
| ids | Show only certain host IDs/ranges. One or more host IDs/ranges may be specified. Multiple entries are comma separated. A host ID range is specified with a hyphen (for example, 190-400).Valid host IDs are required. | Optional | 
| network_ids | (Optional, and valid only when the Network Support feature is enabled for the user’s account) Restrict the request to certain custom network IDs. Multiple network IDs are comma separated. | Optional | 
| no_vm_scan_since | Show hosts not scanned since a certain date and time (optional). use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. Permissions: An Auditor cannot specify this parameter. | Optional | 
| vm_scan_since | Show hosts that were last scanned for vulnerabilities since a certain date and time (optional). Hosts that were the target of a vulnerability scan since the date/time will be shown. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. Permissions: An Auditor cannot specify this parameter. | Optional | 
| no_compliance_scan_since | (Optional) Show compliance hosts not scanned since a certain date and time (optional). This parameter is invalid for an Express Lite user. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| use_tags | Specify 0 (the default) if you want to select hosts based on IP addresses/ranges and/or asset groups. Specify 1 if you want to select hosts based on asset tags. Possible values are: 0, 1. | Optional | 
| tag_set_by | (Optional when use_tags=1) Specify “id” (the default) to select a tag set by providing tag IDs. Specify “name” to select a tag set by providing tag names. Possible values are: id, name. | Optional | 
| tag_include_selector | (Optional when use_tags=1) Select “any” (the default) to include hosts that match at least one of the selected tags. Select “all” to include hosts that match all of the selected tags. Possible values are: any, all. | Optional | 
| tag_exclude_selector | (Optional when use_tags=1) Select “any” (the default) to exclude hosts that match at least one of the selected tags. Select “all” to exclude hosts that match all of the selected tags. Possible values are: any, all. | Optional | 
| tag_set_include | (Optional when use_tags=1) Specify a tag set to include. Hosts that match these tags will be included. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| tag_set_exclude | (Optional when use_tags=1) Specify a tag set to exclude. Hosts that match these tags will be excluded. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| show_tags | (Optional) Specify 1 to display asset tags associated with each host in the XML output. Possible values are: 0, 1. | Optional | 
| host_metadata | Specify the name of the cloud provider to show the assets managed by the cloud provider. Valid values: ec2, google, azure. | Optional | 
| host_metadata_fields | (Optional when host_metadata is specified) Specify metadata fields to only return data for certain attributes. | Optional | 
| show_cloud_tags | (Optional) Specify 1 to display cloud provider tags for each scanned host asset in the output. The default value of the parameter is set to 0. When set to 0, we will not show the cloud provider tags for the scanned assets. Possible values are: 0, 1. | Optional | 
| cloud_tag_fields | (Optional when show_cloud_tags is specified) Specify cloud tags or cloud tag and name combinations to only return information for specified cloud tags. A cloud tag name and value combination is specified with a colon (for example:SomeTag6:AY_ec2). For each cloud tag, we show the cloud tag’s name, its value, and last success date (the tag last success date/time, fetched from instance). If this parameter is not specified and "show_cloud_tags" is set to 1, we will show all the cloud provider tags for the assets. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Endpoint.ID | unknown | Endpoint ID. | 
| Qualys.Endpoint.IP | unknown | IP. | 
| Qualys.Endpoint.CLOUD_PROVIDER | unknown | Host's cloud provider. | 
| Qualys.Endpoint.DNS | unknown | DNS. | 
| Qualys.Endpoint.EC2_INSTANCE_ID | unknown | EC2 instance ID. | 
| Qualys.Endpoint.QG_HOSTID | unknown | QG host ID. | 
| Qualys.Endpoint.CLOUD_SERVICE | unknown | Cloud service of the endpoint. | 
| Qualys.Endpoint.TRACKING_METHOD | unknown | Tracking method of the endpoint. | 
| Qualys.Endpoint.CLOUD_RESOURCE_ID | unknown | Cloud resource ID of the endpoint. | 
| Qualys.Endpoint.DNS_DATA.DOMAIN | unknown | Domain of the endpoint. | 
| Qualys.Endpoint.DNS_DATA.HOSTNAME | unknown | Host name of the endpoint. | 
| Qualys.Endpoint.NETBIOS | unknown | NETBIOS. | 
| Qualys.Endpoint.OS | unknown | Endpoint operating system. | 

### qualys-virtual-host-list
***
View a list of virtual hosts in the user account.


#### Base Command

`qualys-virtual-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Show only virtual hosts that have a certain IP address. | Optional | 
| port | Show only virtual hosts that have a certain port. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.VirtualEndpoint.IP | unknown | IP. | 
| Qualys.VirtualEndpoint.PORT | unknown | Port. | 
| Qualys.VirtualEndpoint.FQDN | unknown | Fully qualified domain name. | 

### qualys-virtual-host-manage
***
View a list of virtual hosts in the user account.


#### Base Command

`qualys-virtual-host-manage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Virtual host action to perform. Possible values are: create, update, delete, add_fqdn, delete_fqdn. | Required | 
| ip | An IP address for the virtual host configuration. | Required | 
| port | A port number for the virtual host configuration. | Required | 
| network_id | Network support must be enabled to specify the network_id. If network support is enabled and you do not provide a network_id, then the Default Global Network is considered. You can specify only one network_id. | Optional | 
| fqdn | (Required for all actions except “delete”. Invalid for “delete”.) One or more fully-qualified domain names (FQDNs) for the virtual host configuration. Multiple entries are comma separated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.VirtualEndpoint.DATETIME | unknown | Date and time of the executed manage action. | 
| Qualys.VirtualEndpoint.TEXT | unknown | Result message of the executed action. | 

### qualys-host-excluded-list
***
Show the excluded host list for the user's account. Hosts in your excluded host list will not be scanned.


#### Base Command

`qualys-host-excluded-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | Get list of excluded hosts or addresses range. | Optional | 
| network_id | (Optional, and valid only when the Network Support feature is enabled for the user’s account) Restrict the request to a certain custom network ID. | Optional | 
| ag_ids | (Optional) Show excluded hosts belonging to asset groups with certain IDs. One or more asset group IDs and/or ranges may be specified. Multiple entries are comma separated. A range is specified with a dash (for example, 386941-386945). Valid asset group IDs are required. | Optional | 
| ag_titles | (Optional) Show excluded hosts belonging to asset groups with certain strings in the asset group title. One or more asset group titles may be specified. Multiple entries are comma separated (for example, My+First+Asset+Group,Another+Asset+Group). | Optional | 
| use_tags | (Optional) Specify 0 (the default) if you want to select hosts based on IP addresses/ranges and/or asset groups. Specify 1 if you want to select hosts based on asset tags. Possible values are: 0, 1. | Optional | 
| tag_include_selector | (Optional when use_tags=1) Specify "any" (the default) to include excluded hosts that match at least one of the selected tags. Specify "all" to include excluded hosts that match all of the selected tags. Possible values are: any, all. | Optional | 
| tag_exclude_selector | (Optional when use_tags=1) Specify "any" (the default) to ignore excluded hosts that match at least one of the selected tags. Specify "all" to ignore excluded hosts that match all of the selected tags. Possible values are: any, all. | Optional | 
| tag_set_by | (Optional when use_tags=1) Specify "id" (the default) to select a tag set by providing tag IDs. Specify "name" to select a tag set by providing tag names. Possible values are: id, name. | Optional | 
| tag_set_include | (Optional when use_tags=1) Specify a tag set to include. Excluded hosts that match these tags will be included. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| tag_set_exclude | (Optional when use_tags=1) Specify a tag set to exclude. Excluded hosts that match these tags will be ignored. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Excluded.Host.Address | unknown | IP Address. | 
| Qualys.Excluded.Host.Address.#text | unknown | IP of excluded host with expiration date. | 
| Qualys.Excluded.Host.Address.@expiration_date | unknown | Expiration date of excluded host address. | 
| Qualys.Excluded.Host.Range.#text | unknown | Range of excluded hosts with expiration date. | 
| Qualys.Excluded.Host.Range.@expiration_date | unknown | Expiration date of excluded hosts ranges. | 
| Qualys.Excluded.Host.Range | unknown | Range of IP addresses. | 

### qualys-scheduled-report-list
***
Get list of scheduled reports


#### Base Command

`qualys-scheduled-report-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Scheduled report ID. | Optional | 
| is_active | Select is_active=1 for active or is_active=0 for inactive scheduled reports to view. Possible values are: 1, 0. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Report ID. | 
| Qualys.Report.TITLE | unknown | Report title. | 
| Qualys.Report.TYPE | unknown | Report type. | 
| Qualys.Report.LAUNCH_DATETIME | unknown | Date and time the report launched. | 
| Qualys.Report.OUTPUT_FORMAT | unknown | Report output format. | 
| Qualys.Report.SIZE | unknown | Report size. | 
| Qualys.Report.STATUS.STATE | unknown | Report state status. | 
| Qualys.Report.STATUS.MESSAGE | unknown | Report status message. | 
| Qualys.Report.STATUS.PERCENT | unknown | Report status percent. | 
| Qualys.Report.EXPIRATION_DATETIME | unknown | Report expiration datetime. | 
| Qualys.Report.ACTIVE | unknown | Report active. | 
| Qualys.Report.TEMPLATE_TITLE | unknown | Title of the template. | 
| Qualys.Report.SCHEDULE.START_DATE_UTC | unknown | Start date of the scheduled report in UTC format. | 
| Qualys.Report.SCHEDULE.START_HOUR | unknown | Start hour of the scheduled report. | 
| Qualys.Report.SCHEDULE.START_MINUTE | unknown | Start minute of the scheduled report. | 
| Qualys.Report.SCHEDULE.DAILY.@frequency_days | unknown | Frequency of the schduled report. | 
| Qualys.Report.SCHEDULE.TIME_ZONE.TIME_ZONE_CODE | unknown | Timezone of the scheduled report. | 
| Qualys.Report.SCHEDULE.TIME_ZONE.TIME_ZONE_DETAILS | unknown | Timezone details of the scheduled report. | 

### qualys-report-template-list
***
get list of report template for user


#### Base Command

`qualys-report-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.ReportTemplate.ID | unknown | Report template ID. | 
| Qualys.ReportTemplate.TYPE | unknown | Report type. | 
| Qualys.ReportTemplate.TITLE | unknown | Report template title. | 
| Qualys.ReportTemplate.LAST_UPDATE | unknown | Last update time. | 
| Qualys.ReportTemplate.GLOBAL | unknown | Report template global. | 
| Qualys.ReportTemplate.DEFAULT | unknown | Report template default. | 
| Qualys.ReportTemplate.USER.LOGIN | unknown | Last updated user login. | 
| Qualys.ReportTemplate.USER.FIRSTNAME | unknown | Last updated user login first name. | 
| Qualys.ReportTemplate.USER.LASTNAME | unknown | Last updated user login last name. | 
| Qualys.ReportTemplate.TEMPLATE_TYPE | unknown | Type of report template. | 

### qualys-vulnerability-list
***
download a list of vulnerabilities from Qualys’ KnowledgeBase


#### Base Command

`qualys-vulnerability-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| details | Show the requested amount of information for each vulnerability in the XML output. A valid value is: Basic (default), All, or None. Basic includes basic elements plus CVSS Base and Temporal scores. All includes all vulnerability details, including the Basic details. Possible values are: Basic, All, None. | Optional | 
| ids | Used to filter the XML output to include only vulnerabilities that have QID numbers matching the QID numbers you specify. | Optional | 
| id_min | Used to filter the XML output to show only vulnerabilities that have a QID number greater than or equal to a QID number you specify. | Optional | 
| id_max | Used to filter the XML output to show only vulnerabilities that have a QID number less than or equal to a QID number you specify. | Optional | 
| is_patchable | Used to filter the XML output to show only vulnerabilities that are patchable or not patchable. A vulnerability is considered patchable when a patch exists for it. When 1 is specified, only vulnerabilities that are patchable will be included in the output. When 0 is specified, only vulnerabilities that are not patchable will be included in the output. When unspecified, patchable and unpatchable vulnerabilities will be included in the output. Possible values are: 0, 1. | Optional | 
| last_modified_after | Used to filter the XML output to show only vulnerabilities last modified after a certain date and time. When specified vulnerabilities last modified by a user or by the service will be shown. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| last_modified_before | Used to filter the XML output to show only vulnerabilities last modified before a certain date and time. When specified vulnerabilities last modified by a user or by the service will be shown. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| last_modified_by_user_after | Used to filter the XML output to show only vulnerabilities last modified by a user after a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| last_modified_by_user_before | Used to filter the XML output to show only vulnerabilities last modified by a user before a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| last_modified_by_service_after | Used to filter the XML output to show only vulnerabilities last modified by the service after a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| last_modified_by_service_before | Used to filter the XML output to show only vulnerabilities last modified by the service before a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| published_after | Used to filter the XML output to show only vulnerabilities published after a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| published_before | Used to filter the XML output to show only vulnerabilities published before a certain date and time. use YYYY-MM-DD[THH:MM:SSZ] like “2007-07-01” or “2007-01-25T23:12:00Z” or today, yesterday, 24hr ago, 3 days ago, last week. | Optional | 
| discovery_method |  (Optional) Used to filter the XML output to show only vulnerabilities assigned a certain discovery method. A valid value is: Remote, Authenticated, RemoteOnly, AuthenticatedOnly, or RemoteAndAuthenticated. Possible values are: Remote, Authenticated, RemoteOnly, AuthenticatedOnly, RemoteAndAuthenticated. | Optional | 
| discovery_auth_types | Used to filter the XML output to show only vulnerabilities having one or more authentication types. A valid value is: Windows, Oracle, Unix or SNMP. Multiple values are entered as a comma-separated list. | Optional | 
| show_pci_reasons | Used to filter the XML output to show reasons for passing or failing PCI compliance (when the CVSS Scoring feature is turned on in the user’s subscription). Specify 1 to view the reasons in the XML output. When unspecified, the reasons are not included in the XML output. Possible values are: 0, 1. | Optional | 
| show_supported_modules_info | Used to filter the XML output to show Qualys modules that can be used to detect each vulnerability. Specify 1 to view supported modules in the XML output. When unspecified, supported modules are not included in the XML output. Possible values are: 0, 1. | Optional | 
| show_disabled_flag | Specify 1 to include the disabled flag for each vulnerability in the XML output. Possible values are: 0, 1. | Optional | 
| show_qid_change_log | Specify 1 to include QID changes for each vulnerability in the XML output. Possible values are: 0, 1. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Vulnerability.List.QID | unknown | Vulnerability QID. | 
| Qualys.Vulnerability.List.PATCHABLE | unknown | Is Vulnerability patchable. | 
| Qualys.Vulnerability.List.SEVERITY_LEVEL | unknown | Severity level of the Vulnerability. | 
| Qualys.Vulnerability.List.CONSEQUENCE | unknown | Consequence of the Vulnerability. | 
| Qualys.Vulnerability.List.VENDOR_REFERENCE_LIST.VENDOR_REFERENCE.ID | unknown | ID of the vendor. | 
| Qualys.Vulnerability.List.VENDOR_REFERENCE_LIST.VENDOR_REFERENCE.URL | unknown | URL of the vendor. | 
| Qualys.Vulnerability.List.LAST_SERVICE_MODIFICATION_DATETIME | unknown | Date of the last service modification. | 
| Qualys.Vulnerability.List.CVE_LIST.CVE.ID | unknown | CVE ID. | 
| Qualys.Vulnerability.List.CVE_LIST.CVE.URL | unknown | CVE URL. | 
| Qualys.Vulnerability.List.PUBLISHED_DATETIME | unknown | Published date. | 
| Qualys.Vulnerability.List.DISCOVERY.ADDITIONAL_INFO | unknown | Additional info. | 
| Qualys.Vulnerability.List.DISCOVERY.AUTH_TYPE_LIST.AUTH_TYPE | unknown | Discovery Authentication type. | 
| Qualys.Vulnerability.List.DISCOVERY.REMOTE | unknown | Is discovery remote. | 
| Qualys.Vulnerability.List.DIAGNOSIS | unknown | Diagnosis of vulnerability. | 
| Qualys.Vulnerability.List.PCI_FLAG | unknown | PCI flag. | 
| Qualys.Vulnerability.List.SOFTWARE_LIST.SOFTWARE.PRODUCT | unknown | Product name. | 
| Qualys.Vulnerability.List.SOFTWARE_LIST.SOFTWARE.VENDOR | unknown | Vendor of the product. | 
| Qualys.Vulnerability.List.VULN_TYPE | unknown | Type of the vulnerability. | 
| Qualys.Vulnerability.List.TITLE | unknown | Title of the vulnerability. | 
| Qualys.Vulnerability.List.SOLUTION | unknown | Solution for the vulnerability. | 
| Qualys.Vulnerability.List.CATEGORY | unknown | Category of the vulnerability. | 

### qualys-group-list
***
Get account asset groups


#### Base Command

`qualys-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Show only asset groups with certain IDs. Multiple IDs are comma separated. | Optional | 
| id_min | Show only asset groups with certain IDs. Multiple IDs are comma separated. | Optional | 
| id_max | Show only asset groups that have an ID less than or equal to the specified ID. | Optional | 
| truncation_limit | Specify the maximum number of asset group records to output. By default this is set to 1000 records. If you specify truncation_limit=0, the output is not paginated and all records are returned in a single output. | Optional | 
| network_ids | Optional and valid only when the Networks feature is enabled in your account) Restrict the request to certain network IDs. Multiple IDs are comma separated. | Optional | 
| unit_id | Show only asset groups that have a business unit ID equal to the specified ID. | Optional | 
| user_id | Show only asset groups that have a user ID equal to the specified ID. | Optional | 
| title |  Show only the asset group that has a title equal to the specified string - this must be an exact match. | Optional | 
| show_attributes | Show attributes for each asset group along with the ID. Your options are: None, All or a comma-separated list of attribute names: ID, TITLE, OWNER_USER_NAME, OWNER_USER_ID, OWNER_UNIT_ID, NETWORK_IDS, LAST_UPDATE, IP_SET, APPLIANCE_LIST, DOMAIN_LIST, DNS_LIST, NETBIOS_LIST, EC2_ID_LIST, HOST_IDS, ASSIGNED_USER_IDS, ASSIGNED_UNIT_IDS, BUSINESS_IMPACT, CVSS, COMMENTS. | Optional | 
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.AssetGroup.ID | unknown | Asset Group ID. | 
| Qualys.AssetGroup.TITLE | unknown | Asset Group title. | 
| Qualys.AssetGroup.OWNER_ID | unknown | Asset Group owner ID. | 
| Qualys.AssetGroup.UNIT_ID | unknown | Asset Group unit ID. | 
| Qualys.AssetGroup.NETWORK_ID | unknown | Asset Group network ID. | 
| Qualys.AssetGroup.IP_SET.IP | unknown | IP in the asset group. | 
| Qualys.AssetGroup.IP_SET.IP_RANGE | unknown | Asset Group IP range. | 
| Qualys.AssetGroup.APPLIANCE_IDS | unknown | Appliance IDs of the asset group. | 
| Qualys.AssetGroup.DEFAULT_APPLIANCE_ID | unknown | Default appliance IDs of the asset group. | 

### qualys-report-fetch
***
Download report


#### Base Command

`qualys-report-fetch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Report ID of a saved report that you want to download. | Required | 
| file_format | Type of the file of the report. Can be checked by calling the qualys-report-list command. Possible values are: pdf, html, mht, xml, csv, docx, online. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | unknown | The file name. | 
| InfoFile.EntryID | unknown | The ID for locating the file in the War Room. | 
| InfoFile.Size | unknown | The size of the file \(in bytes\). | 
| InfoFile.Type | unknown | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| InfoFile.Extension | unknown | The file extension. | 
| InfoFile.Info | unknown | Basic information about the file. | 

### qualys-vm-scan-fetch
***
Download scan results when scan has status Finished, Canceled, Paused or Error


#### Base Command

`qualys-vm-scan-fetch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_ref | The scan reference for a vulnerability scan. This will have the format: scan/nnnnnnnnnn.nnnnn. | Required | 
| ips | Show only certain IP addresses/ranges in the scan results. One or more IPs/ranges may be specified. A range entry is specified using a hyphen (for example, 10.10.10.1-10.10.10.20). Multiple entries are comma separated.    . | Optional | 
| mode | The verbosity of the scan results details. One verbosity mode may be specified: brief (the default) or extended. The brief output includes this information: IP address, DNS hostname, NetBIOS hostname, QID and scan test results if applicable. The extended output includes the brief output plus this extended information: protocol, port, an SSL flag (“yes” is returned when SSL was used for the detection, “no” is returned when SSL was not used), and FQDN if applicable. Possible values are: brief, extended. | Optional | 
| client_id | Id assigned to the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| client_name | Name of the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.VM.Dns | unknown | Scanned device DNS. | 
| Qualys.VM.Instance | unknown | Scanned device instance. | 
| Qualys.VM.IP | unknown | Scanned device IP address. | 
| Qualys.VM.Netbios | unknown | Scanned device Netbios. | 
| Qualys.VM.QID | unknown | Qualys ID for vulnerabilities. | 
| Qualys.VM.Result | unknown | Scan result. | 

### qualys-pc-scan-fetch
***
fetch scan results for a scan


#### Base Command

`qualys-pc-scan-fetch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_ref | The scan reference for a compliance scan. This will have the format: compliance/nnnnnnnnnn.nnnnn. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.PC.USERNAME | unknown | The user who executed the scan. | 
| Qualys.PC.COMPANY | unknown | The company of the user who executed the scan. | 
| Qualys.PC.USERNAME | unknown | The user who executed the scan. | 
| Qualys.PC.DATE | unknown | The date of the scan. | 
| Qualys.PC.TITLE | unknown | The scan title. | 
| Qualys.PC.TARGET | unknown | IP’s which were scanned. | 
| Qualys.PC.EXCLUDED_TARGET | unknown | IP’s which were excluded from the scan. | 
| Qualys.PC.DURATION | unknown | The duration of the scan. | 
| Qualys.PC.NBHOST_ALIVE | unknown | Number of hosts that are available during the scan. | 
| Qualys.PC.NBHOST_TOTAL | unknown | Total number of hosts that were submitted to scan. | 
| Qualys.PC.REPORT_TYPE | unknown | Type of the report. | 
| Qualys.PC.OPTIONS | unknown | Scan option profile. | 
| Qualys.PC.STATUS | unknown | Status of the scan. | 

### qualys-report-cancel
***
Cancel running report


#### Base Command

`qualys-report-cancel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Report ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | ID of the canceled report | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for report cancellation. | 

### qualys-report-delete
***
Delete a saved report in the user’s Report Share


#### Base Command

`qualys-report-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Required) The report ID you want to take action on. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Deleted Report ID | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for report deletion. | 

### qualys-scorecard-launch
***
Launch a vulnerability scorecard report


#### Base Command

`qualys-scorecard-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Scorecard name for the vulnerability scorecard report. | Required | 
| report_title | User-defined report title. | Optional | 
| output_format | Output format of the report. One output format may be specified. Possible values are: pdf, html, mht, xml, csv. Default is xml. | Required | 
| source | The source asset groups for the report. | Required | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. Possible values are: 1, 0. | Optional | 
| pdf_password | The password to be used for encryption. | Optional | 
| recipient_group | The report recipients in the form of one or more distribution groups. | Optional | 
| recipient_group_id | Specify users who will receive the email notification when the report is complete. | Optional | 
| asset_groups | The titles of asset groups to be used as source asset groups for the scorecard report. | Optional | 
| all_asset_groups | et to 1 to select all asset groups available in your account as the source asset groups for the scorecard report. Possible values are: 1. | Optional | 
| business_unit | The title of a business unit containing the source asset groups. | Optional | 
| division | A business info tag identifying a division that asset group(s) belong to. | Optional | 
| function | A business info tag identifying a business function for asset group(s). | Optional | 
| location | A business info tag identifying a location where asset group(s) are located. | Optional | 
| patch_qids | Up to 10 QIDs for vulnerabilities or potential vulnerabilities with available patches. Multiple QIDs are comma separated. | Optional | 
| missing_qids | One or two QIDs for missing software. Two QIDs are comma separated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Report ID. | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for scorecard launch. | 

### qualys-vm-scan-launch
***
 launch vulnerability scans in the user’s account.


#### Base Command

`qualys-vm-scan-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_title | The scan title. This can be a maximum of 2000 characters (ascii). | Optional | 
| target_from | Specify “assets” (the default) when your scan target will include IP addresses/ranges and/or asset groups. Specify “tags” when your scan target will include asset tags. Possible values are: assets, tags. | Optional | 
| ip | The IP addresses to be scanned. You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| asset_groups | The titles of asset groups containing the hosts to be scanned. Multiple titles are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| asset_group_ids | The IDs of asset groups containing the hosts to be scanned. Multiple IDs are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| exclude_ip_per_scan | The IP addresses to be excluded from the scan when the scan target is specified as IP addresses (not asset tags). You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. | Optional | 
| tag_include_selector |  Select “any” (the default) to include hosts that match at least one of the selected tags. Select “all” to include hosts that match all of the selected tags. Possible values are: all, any. | Optional | 
| tag_exclude_selector | Select “any” (the default) to exclude hosts that match at least one of the selected tags. Select “all” to exclude hosts that match all of the selected tags. Possible values are: all, any. | Optional | 
| tag_set_by | Specify “id” (the default) to select a tag set by providing tag IDs. Specify “name” to select a tag set by providing tag names. Possible values are: id, name. | Optional | 
| tag_set_include | Specify a tag set to include. Hosts that match these tags will be included. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| tag_set_exclude | Specify a tag set to exclude. Hosts that match these tags will be excluded. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| use_ip_nt_range_tags_include | Specify “0” (the default) to select from all tags (tags with any tag rule). Specify “1” to scan all IP addresses defined in tag selection. When this is specified, only tags with the dynamic IP address rule called “IP address in Network Range(s)” can be selected. valid only when target_from=tags is specified. Possible values are: 0, 1. | Optional | 
| use_ip_nt_range_tags_exclude | Specify “0” (the default) to select from all tags (tags with any tag rule). Specify “1” to exclude all IP addresses defined in tag selection. When this is specified, only tags with the dynamic IP address rule called “IP address in Network Range(s)” can be selected.  valid only when target_from=tags is specified. Possible values are: 0, 1. | Optional | 
| use_ip_nt_range_tags | Specify “0” (the default) to select from all tags (tags with any tag rule). Specify “1” to scan all IP addresses defined in tags. When this is specified, only tags with the dynamic IP address rule called “IP address in Network Range(s)” can be selected. Possible values are: 0, 1. | Optional | 
| iscanner_id | The IDs of the scanner appliances to be used. Multiple entries are comma separated. For an Express Lite user, Internal Scanning must be enabled in the user's account. One of these parameters must also be specified in a request: iscanner_name, iscanner_id, default_scanner, scanners_in_ag, scanners_in_tagset. When none of these are specified, External scanners are used. These parameters are mutually exclusive and cannot be specified in the same request: iscanner_id and iscanner_name. | Optional | 
| iscanner_name | Specifies the name of the Scanner Appliance for the map, when the map target has private use internal IPs. Using Express Lite, Internal Scanning must be enabled in your account. | Optional | 
| default_scanner | Specify 1 to use the default scanner in each target asset group. For an Express Lite user, Internal Scanning must be enabled in the user’s account. Possible values are: 0, 1. | Optional | 
| scanners_in_ag | Specify 1 to distribute the scan to the target asset groups’ scanner appliances. Appliances in each asset group are tasked with scanning the IPs in the group. By default up to 5 appliances per group will be used and this can be configured for your account (please contact your Account Manager or Support). For an Express Lite user, Internal Scanning must be enabled in the user’s account. Possible values are: 0, 1. | Optional | 
| scanners_in_tagset | Specify 1 to distribute the scan to scanner appliances that match the asset tags specified for the scan target. One of these parameters must be specified in a request for an internal scan: iscanner_name, iscanner_id, default_scanner, scanners_in_ag, scanners_in_tagset. When none of these are specified, External scanners are used. valid when the target_from=tags is specified. Possible values are: 0, 1. | Optional | 
| scanners_in_network | Specify 1 to distribute the scan to all scanner appliances in the network. | Optional | 
| option_title | The title of the compliance option profile to be used. One of these parameters must be specified in a request: option_title or option_id. These are mutually exclusive and cannot be specified in the same request. | Optional | 
| option_id | The ID of the compliance option profile to be used. One of these parameters must be specified in a request: option_title or option_id. These are mutually exclusive and cannot be specified in the same request. | Optional | 
| priority | Specify a value of 0 - 9 to set a processing priority level for the scan. When not specified, a value of 0 (no priority) is used. 0 = No Priority (the default), 1 = Emergency, 2 = Ultimate, 3 = Critical, 4 = Major, 5 = High, 6 = Standard, 7 = Medium, 8 = Minor, 9 = Low. Possible values are: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9. | Optional | 
| connector_name | (Required for EC2 scan) The name of the EC2 connector for the AWS integration you want to run the scan on. | Optional | 
| ec2_endpoint | (Required for EC2 scan) The EC2 region code or the ID of the Virtual Private Cloud (VPC) zone. | Optional | 
| ec2_instance_ids | The ID of the EC2 instance on which you want to launch the VM or compliance scan. Multiple ec2 instance ids are comma separated. You can add up to maximum 10 instance Ids. | Optional | 
| ip_network_id | The ID of a network used to filter the IPs/ranges specified in the“ip” parameter. Set to a custom network ID (note this does not filter IPs/ranges specified in “asset_groups” or “asset_group_ids”). Or set to “0” (the default) for the Global Default Network - this is used to scan hosts outside of your custom networks. | Optional | 
| runtime_http_header | Set a custom value in order to drop defenses (such as logging, IPs, etc) when an authorized scan is being run. The value you enter will be used in the “Qualys-Scan:” header that will be set for many CGI and web application fingerprinting checks. Some discovery and web server fingerprinting checks will not use this header. | Optional | 
| scan_type | Launch a CertView type scan. This option will be supported when CertView GA is released and enabled for your account. Possible values are: certview. | Optional | 
| fqdn | The target FQDN for a vulnerability scan. You must specify at least one target i.e. IPs, asset groups or FQDNs. Multiple values are comma separated. | Optional | 
| client_id | Id assigned to the client (Consultant type subscription only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| client_name | Name of the client (Consultant type subscriptions  only). Parameter client_id or client_name may be specified for the same request. | Optional | 
| include_agent_targets | Specify 1 when your scan target includes agent hosts. This lets you scan private IPs where agents are installed when these IPs are not in your VM/PC license. Possible values are: 0, 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.VM.Launched.KEY | unknown | Key name of launched VM scan, either ID or a REFERENCE. | 
| Qualys.Report.VM.Launched.VALUE | unknown | Value of the key. | 

### qualys-vm-scan-action
***
allows users to take actions on vulnerability scans in their account, like cancel, pause, resume, delete and fetch completed scan results


#### Base Command

`qualys-vm-scan-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | One action required for the request. Possible values are: cancel, pause, resume, delete. | Required | 
| scan_ref | The scan reference for a vulnerability scan. This will have the format: scan/nnnnnnnnnn.nnnnn. | Required | 


#### Context Output

There is no context output for this command.
### qualys-pc-scan-manage
***
Allows users to take actions on compliance scans in their account, like cancel, pause, resume, delete and fetch completed scan results.


#### Base Command

`qualys-pc-scan-manage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | One action required for the request. Possible values are: cancel, pause, resume, delete. | Required | 
| scan_ref |  The scan reference for a compliance scan. This will have the format: compliance/nnnnnnnnnn.nnnnn. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Scan.KEY | unknown | Key name, either ID or REFERENCE. | 
| Qualys.Scan.VALUE | unknown | Value of either ID or REFERENCE. | 

### qualys-pc-scan-launch
***
launch compliance scans.


#### Base Command

`qualys-pc-scan-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_title | The scan title. This can be a maximum of 2000 characters (ascii). | Optional | 
| option_id |  The ID of the compliance option profile to be used. One of these parameters must be specified in a request: option_title or option_id. These are mutually exclusive and cannot be specified in the same request. | Optional | 
| option_title | The title of the compliance option profile to be used. One of these parameters must be specified in a request: option_title or option_id. These are mutually exclusive and cannot be specified in the same request. | Optional | 
| ip |  The IP addresses to be scanned. You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| asset_group_ids | The IDs of asset groups containing the hosts to be scanned. Multiple IDs are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| asset_groups | The titles of asset groups containing the hosts to be scanned. Multiple titles are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| exclude_ip_per_scan | The IP addresses to be excluded from the scan when the scan target is specified as IP addresses (not asset tags). You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. | Optional | 
| default_scanner | Specify 1 to use the default scanner in each target asset group. For an Express Lite user, Internal Scanning must be enabled in the user’s account. Possible values are: 0, 1. | Optional | 
| scanners_in_ag | Specify 1 to distribute the scan to the target asset groups’ scanner appliances. Appliances in each asset group are tasked with scanning the IPs in the group. By default up to 5 appliances per group will be used and this can be configured for your account (please contact your Account Manager or Support). For an Express Lite user, Internal Scanning must be enabled in the user’s account. Possible values are: 0, 1. | Optional | 
| target_from | Specify “assets” (the default) when your scan target will include IP addresses/ranges and/or asset groups. Specify “tags” when your scan target will include asset tags. Possible values are: assets, tags. | Optional | 
| tag_include_selector |  Select “any” (the default) to include hosts that match at least one of the selected tags. Select “all” to include hosts that match all of the selected tags. Possible values are: all, any. | Optional | 
| tag_exclude_selector | Select “any” (the default) to exclude hosts that match at least one of the selected tags. Select “all” to exclude hosts that match all of the selected tags. Possible values are: all, any. | Optional | 
| tag_set_by | Specify “id” (the default) to select a tag set by providing tag IDs. Specify “name” to select a tag set by providing tag names. Possible values are: id, name. | Optional | 
| tag_set_include | Specify a tag set to include. Hosts that match these tags will be included. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| tag_set_exclude | Specify a tag set to exclude. Hosts that match these tags will be excluded. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| use_ip_nt_range_tags | Specify “0” (the default) to select from all tags (tags with any tag rule). Specify “1” to scan all IP addresses defined in tags. When this is specified, only tags with the dynamic IP address rule called “IP address in Network Range(s)” can be selected. Possible values are: 0, 1. | Optional | 
| ip_network_id | The ID of a network used to filter the IPs/ranges specified in the“ip” parameter. Set to a custom network ID (note this does not filter IPs/ranges specified in “asset_groups” or “asset_group_ids”). Or set to “0” (the default) for the Global Default Network - this is used to scan hosts outside of your custom networks. | Optional | 
| runtime_http_header | Set a custom value in order to drop defenses (such as logging, IPs, etc) when an authorized scan is being run. The value you enter will be used in the “Qualys-Scan:” header that will be set for many CGI and web application fingerprinting checks. Some discovery and web server fingerprinting checks will not use this header. | Optional | 
| iscanner_name | Specifies the name of the Scanner Appliance for the map, when the map target has private use internal IPs. Using Express Lite, Internal Scanning must be enabled in your account. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Scan.KEY | unknown | Scan key, either ID or Reference | 
| Qualys.Scan.VALUE | unknown | Scan value, either value of ID or Reference | 

### qualys-ip-add
***
Add IP addresses to the subscription.


#### Base Command

`qualys-ip-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | The hosts you want to add to the subscription. . | Required | 
| tracking_method | The tracking method is set to IP for IP address by default. To use another tracking method specify DNS or NETBIOS. Possible values are: IP, DNS, NETBIOS. | Optional | 
| enable_vm | You must enable the hosts for the VM application (enable_vm=1) or the PC application (enable_pc=1) or both VM and PC. Possible values are: 0, 1. Default is 0. | Required | 
| enable_pc | You must enable the hosts for the VM application (enable_vm=1) or the PC application (enable_pc=1) or both VM and PC. Possible values are: 0, 1. Default is 0. | Required | 
| owner | The owner of the host asset(s). The owner must be a Manager or a Unit Manager. | Optional | 
| ud1 | Values for user-defined fields 1, 2 and 3. You can specify a maximum of 128 characters. | Optional | 
| ud2 | Values for user-defined fields 1, 2 and 3. You can specify a maximum of 128 characters. | Optional | 
| ud3 | Values for user-defined fields 1, 2 and 3. You can specify a maximum of 128 characters. | Optional | 
| comment | User-defined comments. | Optional | 
| ag_title | (Required if the request is being made by a Unit Manager; otherwise invalid) The title of an asset group in the Unit Manager’s business unit that the host(s) will be added to. | Optional | 
| enable_certview | Set to 1 to add IPs to your CertView license. By default IPs are not added to your CertView license. This option will be supported when CertView GA is released and is enabled for your account. Possible values are: 0, 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.IP.Add.TEXT | unknown | Action result message. | 
| Qualys.IP.Add.DATETIME | unknown | Date &amp; time of the action. | 

### qualys-ip-update
***
gives you the ability to update IP addresses within the subscription.


#### Base Command

`qualys-ip-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips |  The hosts within the subscription that you want to update. | Required | 
| network_id | (valid only when the Network Support feature is enabled for the user's account) Restrict the request to a certain custom network by specifying the network ID. When unspecified, we default to "0" for Global Default Network. | Optional | 
| host_dns | (Optional) The DNS hostname for the IP you want to update. A single IP must be specified in the same request and the IP will only be updated if it matches the hostname specified. | Optional | 
| host_netbios | (Optional) The NetBIOS hostname for the IP you want to update. A single IP must be specified in the same request and the IP will only be updated if it matches the hostname specified. | Optional | 
| tracking_method | The tracking method is set to IP for IP address by default. To use another tracking method specify DNS or NETBIOS. Possible values are: IP, DNS, NETBIOS. | Optional | 
| owner | The owner of the host asset(s). The owner must be a Manager or a Unit Manager. | Optional | 
| ud1 | Values for user-defined fields 1, 2 and 3. You can specify a maximum of 128 characters. | Optional | 
| ud2 | Values for user-defined fields 1, 2 and 3. You can specify a maximum of 128 characters. | Optional | 
| ud3 | Values for user-defined fields 1, 2 and 3. You can specify a maximum of 128 characters. | Optional | 
| comment | User-defined comments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.IP.Update.TEXT | unknown | Action result message. | 
| Qualys.IP.Update.DATETIME | unknown | Date &amp; time of the action. | 

### qualys-host-excluded-manage
***
Manage your excluded IPs list using the Excluded IP. The IPs in your excluded IPs list will not be scanned.


#### Base Command

`qualys-host-excluded-manage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Select add/remove/remove_all ips. Possible values are: add, remove, remove_all. | Required | 
| comment | User-defined notes (up to 1024 characters). | Required | 
| ips | The IP addresses to be added to the excluded IPs list. Enter a comma separated list of IPv4 singletons or ranges. For example: 10.10.10.13,10.10.10.25-10.10.10.29. | Optional | 
| expiry_days | (Optional when action=add) The number of days the IPs being added to the excluded IPs list will be considered valid for exclusion. When the expiration is reached, the IPs are removed from the list and made available again for scanning. When unspecified, the IPs being added have no expiration and will remain on the list until removed by a user. | Optional | 
| dg_names | (Optional when action=add) Specify users who will be notified 7 days before hosts are removed from the excluded hosts list (i.e. supply distribution group names as defined in the Qualys UI). | Optional | 
| network_id | Assign a network ID to the IPs being added to the excluded IPs list. By default, the user’s default network ID is assigned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Endpoint.KEY | unknown | Result of action requested. | 
| Qualys.Endpoint | unknown | IPs action was made on. | 

### qualys-scheduled-report-launch
***
Launch a scheduled report now


#### Base Command

`qualys-scheduled-report-launch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Scheduled report ID. Can be found by running the command qualys-scheduled-report-list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Launched Report ID | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for scheduled report launch. | 

### qualys-report-launch-map
***
Launches a map report


#### Base Command

`qualys-report-launch-map`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running the command qualys-report-template-list. | Required | 
| report_refs | Specifies the map references (1 or 2) to include. A map reference starts with the string "map/" followed by a reference ID number. When two map references are given, the report compares map results. Two map references are comma separated. | Required | 
| output_format | One output format may be specified. Possible values are: pdf, html, mht, xml, csv. | Required | 
| domain | Specifies the target domain for the map report. Include the domain name only; do not enter "www." at the start of the domain name. When the special “none” domain is specified as a parameter value, the ip_restriction parameter is required. | Required | 
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. | Optional | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. By default this information is included. Possible values are: 0, 1. | Optional | 
| pdf_password | (Required for secure PDF distribution, Manager or Unit Manager only) Used for secure PDF report distribution when this feature is enabled in the user's account (under Reports &gt; Setup &gt; Report Share). The password to be used for encryption. - the password must have a minimum of 8 characters (ascii), and a maximum of 32 characters - the password must contain alpha and numeric characters - the password cannot match the password for the user’s Qualys account. - the password must follow the password security guidelines defined for your subscription (under Users &gt; Setup &gt; Security). | Optional | 
| recipient_group | Used for secure PDF distribution. The report recipients in the form of one or more distribution group names, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. | Optional | 
| recipient_group_id | The report recipients in the form of one or more distribution group IDs. Multiple distribution group IDs are comma separated. Where do I find this ID? Log in to your Qualys account, go to Users &gt; Distribution Groups and select Info for a group in the list. | Optional | 
| ip_restriction | For a map report, specifies certain IPs/ranges to include in the report. Multiple IPs and/or ranges are comma separated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Launched Map Report ID | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for report launch map. | 

### qualys-report-launch-host-based-findings
***
Run host based findings report


#### Base Command

`qualys-report-launch-host-based-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running the command qualys-report-template-list. | Required | 
| output_format | output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Possible values are: pdf, html, mht, xml, csv. | Required | 
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. | Optional | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. By default this information is included. | Optional | 
| recipient_group_id | Specify users who will receive the email notification when the report is complete (i.e. supply a distribution group ID). Where do I find this ID? Log in to your Qualys account, go to Users &gt; Distribution Groups and select Info for a group in the list. | Optional | 
| pdf_password | (Optional; Required for secure PDF distribution) The password to be used for encryption. Requirements: - the password must have a minimum of 8 characters (ascii), and a maximum of 32 characters - the password must contain alpha and numeric characters - the password cannot match the password for the user’s Qualys account. - the password must follow the password security guidelines defined for your subscription (log in and go to Subscription Setup—&gt;Security Options). | Optional | 
| recipient_group | Optional; Optional for secure PDF distribution) The report recipients in the form of one or more distribution groups, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. Chapter 4 — Report API Launch Report  recipient_group={value}. | Optional | 
| ips | Specify IPs/ranges to change (override) the report target, as defined in the scan report template. Multiple IPs/ranges are comma separated. When specified, hosts defined in the report template are not included in the report. See also “Using Asset Tags.”. | Optional | 
| asset_group_ids | Specify asset group IDs to change (override) the report target, as defined in the scan report template. When specified, hosts defined in the report template are not included in the report. Looking for asset group IDs? Use the asset_group_list.php function (see the API v1 User Guide). | Optional | 
| ips_network_id | Optional, and valid only when the Network Support feature is enabled for the user’s account) The ID of a network that is used to restrict the report’s target to the IPs/ranges specified in the“ips” parameter. Set to a custom network ID (note this does not filter IPs/ranges specified in “asset_group_ids”). Or set to “0” (the default) for the Global Default Network - this is used to report on hosts outside of your custom networks. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Report ID. | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for scan based findings. | 

### qualys-report-launch-scan-based-findings
***
launches a scan report including scan based findings


#### Base Command

`qualys-report-launch-scan-based-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running qualys-report-template-list. | Required | 
| output_format | One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Possible values are: pdf, html, mht, xml, csv, docx. | Required | 
| report_refs | (Required) This parameter specifies the scan references to include. A scan reference starts with the string "scan/" followed by a reference ID number. Multiple scan references are comma separated. Reference can be found by running the command qualys-vm-scan-list. | Required | 
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. | Optional | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. By default this information is included. | Optional | 
| recipient_group_id | Specify users who will receive the email notification when the report is complete (i.e. supply a distribution group ID). Where do I find this ID? Log in to your Qualys account, go to Users &gt; Distribution Groups and select Info for a group in the list. | Optional | 
| pdf_password | (Optional; Required for secure PDF distribution) The password to be used for encryption. Requirements: - the password must have a minimum of 8 characters (ascii), and a maximum of 32 characters - the password must contain alpha and numeric characters - the password cannot match the password for the user’s Qualys account. - the password must follow the password security guidelines defined for your subscription (log in and go to Subscription Setup—&gt;Security Options). | Optional | 
| recipient_group | Optional; Optional for secure PDF distribution) The report recipients in the form of one or more distribution groups, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. Chapter 4 — Report API Launch Report  recipient_group={value}. | Optional | 
| ip_restriction | (Optional)  For a scan report, the report content will be restricted to the specified IPs/ranges. Multiple IPs and/or ranges are comma separated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Report ID. | 

### qualys-report-launch-patch
***
Run patch report


#### Base Command

`qualys-report-launch-patch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running the command qualys-report-template-list. | Required | 
| output_format | One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Possible values are: pdf, online, xml, csv. | Required | 
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. | Optional | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. By default this information is included. | Optional | 
| recipient_group_id | pecify users who will receive the email notification when the report is complete (i.e. supply a distribution group ID). Where do I find this ID? Log in to your Qualys account, go to Users &gt; Distribution Groups and select Info for a group in the list. | Optional | 
| pdf_password | (Optional; Required for secure PDF distribution) The password to be used for encryption. Requirements: - the password must have a minimum of 8 characters (ascii), and a maximum of 32 characters - the password must contain alpha and numeric characters - the password cannot match the password for the user’s Qualys account. - the password must follow the password security guidelines defined for your subscription (log in and go to Subscription Setup—&gt;Security Options). | Optional | 
| recipient_group | Optional; Optional for secure PDF distribution) The report recipients in the form of one or more distribution groups, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. Chapter 4 — Report API Launch Report  recipient_group={value}. | Optional | 
| ips | Specify IPs/ranges to change (override) the report target, as defined in the patch report template. Multiple IPs/ranges are comma separated. When specified, hosts defined in the report template are not included in the report. See also “Using Asset Tags.”. | Optional | 
| asset_group_ids | Specify IPs/ranges to change (override) the report target, as defined in the patch report template. Multiple asset group IDs are comma separated. When specified, hosts defined in the report template are not included in the report. Looking for asset group IDs? Use the asset_group_list.php function (see the API v1 User Guide). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Report ID. | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for launch patch. | 

### qualys-report-launch-remediation
***
Run remediation report


#### Base Command

`qualys-report-launch-remediation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running qualys-report-template-list. | Required | 
| output_format | One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. Possible values are: pdf, html, mht, csv. | Required | 
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. | Optional | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. By default this information is included. | Optional | 
| recipient_group_id | pecify users who will receive the email notification when the report is complete (i.e. supply a distribution group ID). Where do I find this ID? Log in to your Qualys account, go to Users &gt; Distribution Groups and select Info for a group in the list. | Optional | 
| pdf_password | (Optional; Required for secure PDF distribution) The password to be used for encryption. Requirements: - the password must have a minimum of 8 characters (ascii), and a maximum of 32 characters - the password must contain alpha and numeric characters - the password cannot match the password for the user’s Qualys account. - the password must follow the password security guidelines defined for your subscription (log in and go to Subscription Setup—&gt;Security Options). | Optional | 
| recipient_group | Optional; Optional for secure PDF distribution) The report recipients in the form of one or more distribution groups, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. Chapter 4 — Report API Launch Report  recipient_group={value}. | Optional | 
| ips | (Optional for remediation report) Specify IPs/ranges you want to include in the report. Multiple IPs and/or ranges are comma separated. | Optional | 
| asset_group_ids | Specify asset group IDs that identify hosts you want to include in the report. Multiple asset group IDs are comma separated. Looking for asset group IDs? Use the asset_group_list.php function (in the API v1 User Guide). | Optional | 
| assignee_type |  Specifies whether the report will include tickets assigned to the current user, or all tickets in the user account. By default tickets assigned to the current user are included. Valid values are: User (default) or All. Possible values are: User, All. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Remediation Report ID | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for launch remediation. | 

### qualys-report-launch-compliance
***
Run compliance report


#### Base Command

`qualys-report-launch-compliance`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running the command qualys-report-template-list. | Required | 
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. | Optional | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. By default this information is included. | Optional | 
| recipient_group_id | Specify users who will receive the email notification when the report is complete (i.e. supply a distribution group ID). Where do I find this ID? Log in to your Qualys account, go to Users &gt; Distribution Groups and select Info for a group in the list. | Optional | 
| pdf_password | (Optional; Required for secure PDF distribution) The password to be used for encryption. Requirements: - the password must have a minimum of 8 characters (ascii), and a maximum of 32 characters - the password must contain alpha and numeric characters - the password cannot match the password for the user’s Qualys account. - the password must follow the password security guidelines defined for your subscription (log in and go to Subscription Setup—&gt;Security Options). | Optional | 
| recipient_group | Optional; Optional for secure PDF distribution) The report recipients in the form of one or more distribution groups, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. Chapter 4 — Report API Launch Report  recipient_group={value}. | Optional | 
| output_format | One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. . Possible values are: pdf, html, mht. | Required | 
| ips | (Optional for compliance report) For a compliance report (except a PCI report), specify the IPs/ranges you want to include in the report. Multiple IPs and/or ranges are comma separated. | Optional | 
| asset_group_ids | (Optional for compliance report) For a compliance report (except a PCI report), specify asset groups IDs which identify hosts to include in the report. Multiple asset group IDs are comma separated. Looking for asset group IDs? Use the asset_group_list.php function (in the API v1 User Guide). | Optional | 
| report_refs | For a PCI compliance report, either the technical or executive report, this parameter specifies the scan reference to include. A scan reference starts with the string “scan/” followed by a reference ID number. The scan reference must be for a scan that was run using the PCI Options profile. Only one scan reference may be specified. Reference can be found by running the command qualys-pc-scan-list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Compliance Report ID | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for launch compliance. | 

### qualys-report-launch-compliance-policy
***
Run compliance policy report


#### Base Command

`qualys-report-launch-compliance-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The template ID of the report you want to launch. Can be found by running the command qualys-report-template-list. | Required | 
| report_title | A user-defined report title. The title may have a maximum of 128 characters. For a PCI compliance report, the report title is provided by Qualys and cannot be changed. | Optional | 
| hide_header | (Valid for CSV format report only). Specify hide_header=1 to omit the header information from the report. By default this information is included. | Optional | 
| recipient_group_id | Specify users who will receive the email notification when the report is complete (i.e. supply a distribution group ID). Where do I find this ID? Log in to your Qualys account, go to Users &gt; Distribution Groups and select Info for a group in the list. | Optional | 
| pdf_password | (Optional; Required for secure PDF distribution) The password to be used for encryption. Requirements: - the password must have a minimum of 8 characters (ascii), and a maximum of 32 characters - the password must contain alpha and numeric characters - the password cannot match the password for the user’s Qualys account. - the password must follow the password security guidelines defined for your subscription (log in and go to Subscription Setup—&gt;Security Options). | Optional | 
| recipient_group | Optional; Optional for secure PDF distribution) The report recipients in the form of one or more distribution groups, as defined using the Qualys UI. Multiple distribution groups are comma separated. A maximum of 50 distribution groups may be entered. Chapter 4 — Report API Launch Report  recipient_group={value}. | Optional | 
| output_format | One output format may be specified. When output_format=pdf is specified, the Secure PDF Distribution may be used. . Possible values are: pdf, html, mht, xml, csv. | Required | 
| policy_id | Specifies the policy to run the report on. A valid policy ID must be entered. | Required | 
| asset_group_ids | Specify asset group IDS if you want to include only certain asset groups in your report. These asset groups must be assigned to the policy you are reporting on. Multiple asset group IDs are comma separated. Looking for asset group IDs? Use the asset_group_list.php function (in the API v1 User Guide). | Optional | 
| ips | Specify IPs/ranges if you want to include only certain IP addresses in your report. These IPs must be assigned to the policy you’re reporting on. Multiple entries are comma separated. | Optional | 
| host_id |  In the policy report output, show only results for a single host instance. Specify the ID for the host to include in the report. A valid host ID must be entered. | Optional | 
| instance_string | Specifies a single instance on the selected host. The instance string may be “os” or a string like “oracle10:1:1521:ora10204u”. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Report.ID | unknown | Policy Report ID | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for launch compliance policy. | 

### qualys-ip-restricted-list
***
Get the list of restricted IPs within the user's subscription.


#### Base Command

`qualys-ip-restricted-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Specify a positive numeric value to limit the amount of results in the requested list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Restricted.Address | unknown | List of the restricted IPs. | 
| Qualys.Restricted.Range | unknown | List of the restricted IPs. | 

### qualys-ip-restricted-manage
***
Get the list of restricted IPs within the user's subscription.


#### Base Command

`qualys-ip-restricted-manage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | activate - enable or disable the restricted IPs feature. clear - clear all restricted IPs and de-active this feature. add - add restricted IPs. delete - delete restricted IPs. replace - replace restricted IPs. Possible values are: activate, clear, add, delete, replace. | Required | 
| enable | Enable or disable the restricted IPs list. set enable=1 to enable the list; set enable=0 to clear any IPs in the list and disable the feature. Possible values are: 0, 1. | Optional | 
| ips | The hosts you want to add to, remove from or replace in the restricted IPs list. How to specify IP addresses. One or more IPs/ranges may be specified. Multiple IPs/ranges are comma separated. An IP range is specified with a hyphen (for example, 10.10.30.1-10.10.30.50). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Restricted.Manage.TEXT | unknown | Action result message. | 
| Qualys.Restricted.Manage.DATETIME | unknown | Date &amp; time of the action. | 
| Qualys.Restricted.Manage.ITEM_LIST.ITEM.VALUE | unknown | Status of the restricted ips feature. | 

### qualys-host-list-detection
***
Get a list of hosts with the hosts latest vulnerability data, based on the host based scan data available in the user’s account.


#### Base Command

`qualys-host-list-detection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Show only certain host IDs/ranges. One or more host IDs/ranges may be specified. Multiple entries are comma separated. A host ID range is specified with a hyphen (for example, 190-400).Valid host IDs are required. | Optional | 
| ips | The hosts you want to retrieve list detection. How to specify IP addresses. One or more IPs/ranges may be specified. Multiple IPs/ranges are comma separated. An IP range is specified with a hyphen (for example, 10.10.30.1-10.10.30.50). | Optional | 
| qids | Show only detection records with certain QIDs. One or more QIDs may be specified. A range is specified with a dash (for example: 68518-68522). Multiple entries are comma separated. Valid QIDs are required. | Optional | 
| severities | Show only detection records which have certain severities. One or more levels may be specified. A range is specified with a dash (for example: 1-3). Multiple entries are comma separated. | Optional | 
| use_tags | Specify 0 (the default) if you want to select hosts based on IP addresses/ranges and/or asset groups. Specify 1 if you want to select hosts based on asset tags. Possible values are: 0, 1. | Optional | 
| tag_set_by | (Optional when use_tags=1) Specify “id” (the default) to select a tag set by providing tag IDs. Specify “name” to select a tag set by providing tag names. Possible values are: id, name. | Optional | 
| tag_include_selector | (Optional when use_tags=1) Select “any” (the default) to include hosts that match at least one of the selected tags. Select “all” to include hosts that match all of the selected tags. Possible values are: any, all. | Optional | 
| tag_exclude_selector | (Optional when use_tags=1) Select “any” (the default) to exclude hosts that match at least one of the selected tags. Select “all” to exclude hosts that match all of the selected tags. Possible values are: any, all. | Optional | 
| tag_set_include | (Optional when use_tags=1) Specify a tag set to include. Hosts that match these tags will be included. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| tag_set_exclude | (Optional when use_tags=1) Specify a tag set to exclude. Hosts that match these tags will be excluded. You identify the tag set by providing tag name or IDs. Multiple entries are comma separated. | Optional | 
| detection_processed_before | Show detections with vulnerability scan results processed before a certain date and time. Specify the date in YYYY-MMDD[THH:MM:SSZ] format (UTC/GMT), like “2016-09-12” or “2016-09-12T23:15:00Z”. | Optional | 
| detection_processed_after | Show detections with vulnerability scan results processed after a certain date and time. Specify the date in YYYY-MMDD[ THH:MM:SSZ] format (UTC/GMT), like “2016-09-12” or “2016-09-12T23:15:00Z”. | Optional | 
| vm_scan_since | Show hosts that were last scanned for vulnerabilities since a certain date and time (optional). Hosts that were the target of a vulnerability scan since the date/time will be shown. Date/time is specified in this format: YYYY-MM-DD[THH:MM:SSZ] (UTC/GMT). Permissions: An Auditor cannot specify this parameter. | Optional | 
| no_vm_scan_since | Show hosts not scanned since a certain date and time (optional). The date/time is specified in YYYY-MMDD[THH:MM:SSZ] format (UTC/GMT), like “2007-07-01” or “2007-01-25T23:12:00Z”. Permissions - An Auditor cannot specify this parameter. | Optional | 
| truncation_limit | Specify the maximum number of host records processed per request. When not specified, the truncation limit is set to 1000 host records. You may specify a value less than the default (1-999) or greater than the default (1001-1000000). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.HostDetections.ID | String | Host detection ID. | 
| Qualys.HostDetections.IP | String | Host detection IP. | 
| Qualys.HostDetections.TRACKING_METHOD | String | Tracking method. | 
| Qualys.HostDetections.OS | String | Host OS. | 
| Qualys.HostDetections.DNS | String | Host DNS. | 
| Qualys.HostDetections.DNS_DATA.HOSTNAME | String | DNS data host name. | 
| Qualys.HostDetections.DNS_DATA.DOMAIN | Unknown | DNS data domain. | 
| Qualys.HostDetections.DNS_DATA.FQDN | Unknown | DNS data FQDN. | 
| Qualys.HostDetections.NETBIOS | String | Netbios. | 
| Qualys.HostDetections.QG_HOSTID | String | QG Host ID. | 
| Qualys.HostDetections.LAST_SCAN_DATETIME | Date | Last scan date. | 
| Qualys.HostDetections.LAST_VM_SCANNED_DATE | Date | Last VM scan date. | 
| Qualys.HostDetections.LAST_VM_SCANNED_DURATION | String | Last vm scan duration. | 
| Qualys.HostDetections.LAST_PC_SCANNED_DATE | Date | Last PC scan date. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.QID | String | Detection QID. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.TYPE | String | Detection type. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.SEVERITY | String | Detection severity. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.SSL | String | Detection SSL. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.RESULTS | String | Detection results. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.STATUS | String | Detection status. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.FIRST_FOUND_DATETIME | Date | Detection first found date. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.LAST_FOUND_DATETIME | Date | Detection last found date. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.TIMES_FOUND | String | Detection number of times found. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.LAST_TEST_DATETIME | Date | Detection last tested date. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.LAST_UPDATE_DATETIME | Date | Detection last updated date. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.IS_IGNORED | String | Whether detection is ignored. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.IS_DISABLED | String | Whether detection is disabled. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.LAST_PROCESSED_DATETIME | Date | Detection last processed date. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.PORT | String | Detection port. | 
| Qualys.HostDetections.DETECTION_LIST.DETECTION.PROTOCOL | String | Detection protocol. | 

### qualys-host-update
***
Update host attributes using new update parameters (new_tracking_method, new_owner, new_ud1, new_ud2, new_ud3, and new_comment).


#### Base Command

`qualys-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Show only certain host IDs/ranges. One or more host IDs/ranges may be specified. Multiple entries are comma separated. A host ID range is specified with a hyphen (for example, 190-400).Valid host IDs are required. One of `ips` or `ids` parameters must be supplied. IDs or IPs can be retrieved via running the `qualys-host-list-detection` command, using the ID field or IPs field. | Optional | 
| ips | The hosts you want to add to, remove from or replace in the restricted IPs list. How to specify IP addresses. One or more IPs/ranges may be specified. Multiple IPs/ranges are comma separated. An IP range is specified with a hyphen (for example, 10.10.30.1-10.10.30.50). One of `ips` or `ids` parameters must be supplied. | Optional | 
| network_id | (Valid only when the Network Support feature is enabled for the user’s account) Restrict the request to a certain custom network by specifying the network ID. When unspecified, we default to Global Default Network. | Optional | 
| host_dns | The DNS hostname for the IP you want to update. A single IP must be specified in the same request and the IP will only be updated if it matches the hostname specified. | Optional | 
| host_netbios | The NetBIOS hostname for the IP you want to update. A single IP must be specified in the same request and the IP will only be updated if it matches the hostname specified. | Optional | 
| tracking_method | Show only IP addresses/ranges which have a certain tracking method. Possible values are: IP, DNS, NETBIOS. | Optional | 
| new_tracking_method | Change the tracking method. Specify IP for IP address, DNS or NETBIOS. Note - You cannot change the tracking method to EC2 or AGENT. If an IP is already tracked by EC2 or AGENT, you cannot change the tracking method to something else. Possible values are: IP, DNS, NETBIOS. | Optional | 
| new_owner | Change the owner of the host asset(s). The owner must be a Manager. Another user (Unit Manager, Scanner, Reader) can be the owner if the IP address is in the user’s account. | Optional | 
| new_comment | Change the user-defined comments. Specify new comments for the host asset(s). | Optional | 
| new_ud1 | Change value for user-defined field 1. You can specify a maximum of 128 characters (ascii) for each field value. | Optional | 
| new_ud2 | Change value for user-defined field 2. You can specify a maximum of 128 characters (ascii) for each field value. | Optional | 
| new_ud3 | Change value for user-defined field 3. You can specify a maximum of 128 characters (ascii) for each field value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Endpoint.Update.DATETIME | Date | Date of when command was executed. | 
| Qualys.Endpoint.Update.TEXT | String | Qualys response for host update. | 

### qualys-schedule-scan-create
***
Create a scan schedule in the user’s account.


#### Base Command

`qualys-schedule-scan-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_title | The scan title. | Required | 
| ip | The IP addresses to be scanned. You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| asset_group_ids | The IDs of asset groups containing the hosts to be scanned. Multiple IDs are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| asset_groups | The titles of asset groups containing the hosts to be scanned. Multiple titles are comma separated. One of these parameters is required: ip, asset_groups or asset_group_ids. | Optional | 
| option_title | The title of the compliance option profile to be used. | Required | 
| frequency_days | Frequency scan occurs, value between 1-365. For example: if specified '1', the schedule will occur every day. If specified '2', the schedule will occur every 2 days. One of these parameters is required: 'frequency_days', 'frequency_weeks', 'frequency_months'. | Optional | 
| frequency_weeks | Frequency scan occurs, value between 1-52. For example: if specified '1', the schedule will occur every week. If specified '2', the schedule will occur every 2 weeks. The argument 'weekdays' is required when frequency_weeks is given. Scan will occur only on specified days given in the 'weekdays' argument. One of these parameters is required: 'frequency_days', 'frequency_weeks', 'frequency_months'. | Optional | 
| frequency_months | Frequency scan occurs, value between 1-12. For example: if specified '1', the schedule will occur every month. If specified '2', the schedule will occur every 2 months. Either the argument 'day_of_month' or the arguments 'day_of_week' and 'week_of_month' are required when frequency_months is given. Scan will occur only on specified days given in the those arguments argument. One of these parameters is required: 'frequency_days', 'frequency_weeks', 'frequency_months'. | Optional | 
| weekdays | Required when 'frequency_weeks' is given. Days of when the scan will occur every week. E.g, weekdays='sunday,tuesday' along with 'frequency_weeks=2' means the scan will happen on sunday and tuesday every two weeks. Possible values are: sunday, monday, tuesday, wednesday, thursday, friday, saturday. | Optional | 
| day_of_month | Only relevant when 'frequency_months' value was given. Day of month that the monthly schedule will run on. Between 1-31 depending on the month. For example, day_of_month=15 along with frequency_months=2 will result in the scan running every 2 months in the 15th of the month. | Optional | 
| day_of_week | Only relevant when 'frequency_months' value was given. Must be given with 'week_of_month' as well. Day of week that the schedule will run on. Between 0-6, where 0 is Sunday, and 6 is Saturday depending on the month. For example, day_of_week=2, week_of_month=second along with frequency_months=2 will result in the scan running every 2 months on Tuesday in the second week of the month. Possible values are: 0, 1, 2, 3, 4, 5, 6. | Optional | 
| week_of_month | Comma separated list. Only relevant when 'frequency_months' value was given. Must be given with 'week_of_month' as well. Day of week that the schedule will run on. Between 0-6, where 0 is Sunday, and 6 is Saturday depending on the month. For example, day_of_week=2, week_of_month=second along with frequency_months=2 will result in the scan running every 2 months on Tuesday in the second week of the month. Possible values are: first, second, third, fourth, last. | Optional | 
| start_date | The start date of the schedule. Format of mm/dd/yyyy. For example, 12/15/2020. | Required | 
| start_hour | The start hour of the scheduled scan. Value between 0-23. | Required | 
| start_minute | The start minute of the scheduled scan. Value between 0-59. | Required | 
| time_zone_code | Time zone code of the given schedule scan. For example, US-CA for time zone California in US. | Required | 
| observe_dst | Specify yes to observe Daylight Saving Time (DST). This parameter is valid when the time zone code specified in time_zone_code supports DST. To get the list of time zones and their DST support, use the `qualys-time-zone-code` command. | Optional | 
| exclude_ip_per_scan | The IP addresses to be excluded from the scan when the scan target is specified as IP addresses (not asset tags). You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. One of these parameters must be set: 'scanners_in_ag', 'default_scanner'. | Optional | 
| default_scanner | Specify 1 to use the default scanner in each target asset group. For an Express Lite user, Internal Scanning must be enabled in the user’s account. One of these parameters must be set: 'scanners_in_ag', 'default_scanner'. Possible values are: 0, 1. | Optional | 
| scanners_in_ag | Specify 1 to distribute the scan to the target asset groups’ scanner appliances. Appliances in each asset group are tasked with scanning the IPs in the group. By default up to 5 appliances per group will be used and this can be configured for your account (please contact your Account Manager or Support). For an Express Lite user, Internal Scanning must be enabled in the user’s account. One of these parameters must be set: 'scanners_in_ag', 'default_scanner'. Possible values are: 0, 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.ScheduleScan.ID | String | New scheduled scan created ID. | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for schedule scan creation. | 

### qualys-schedule-scan-update
***
Updates a scan schedule in the user’s account.


#### Base Command

`qualys-schedule-scan-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The scan ID to update. the ID can be retrieved via running the `qualys-schedule-scan-list` command, and using the ID field. | Required | 
| scan_title | The scan title. | Optional | 
| ip | The IP addresses to be scanned. You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. At most one of these parameters can be supplied: ip, asset_groups or asset_group_ids. | Optional | 
| asset_group_ids | The IDs of asset groups containing the hosts to be scanned. Multiple IDs are comma separated. At most one of these parameters can be supplied: ip, asset_groups or asset_group_ids. | Optional | 
| asset_groups | The titles of asset groups containing the hosts to be scanned. Multiple titles are comma separated. At most one of these parameters can be supplied: ip, asset_groups or asset_group_ids. | Optional | 
| frequency_days | Frequency scan occurs, value between 1-365. For example: if specified '1', the schedule will occur every day. If specified '2', the schedule will occur every 2 days. At most one of these parameters can be supplied: 'frequency_days', 'frequency_weeks', 'frequency_months'. | Optional | 
| frequency_weeks | Frequency scan occurs, value between 1-52. For example: if specified '1', the schedule will occur every week. If specified '2', the schedule will occur every 2 weeks. The argument 'weekdays' is required when frequency_weeks is given. Scan will occur only on specified days given in the 'weekdays' argument. At most one of these parameters can be supplied: 'frequency_days', 'frequency_weeks', 'frequency_months'. | Optional | 
| frequency_months | Frequency scan occurs, value between 1-12. For example: if specified '1', the schedule will occur every month. If specified '2', the schedule will occur every 2 months. Either the argument 'day_of_month' or the arguments 'day_of_week' and 'week_of_month' are required when frequency_months is given. Scan will occur only on specified days given in the those arguments argument. At most one of these parameters can be supplied: 'frequency_days', 'frequency_weeks', 'frequency_months'. | Optional | 
| weekdays | Required when 'frequency_weeks' is given. Days of when the scan will occur every week. E.g, weekdays='sunday,tuesday' along with 'frequency_weeks=2' means the scan will happen on sunday and tuesday every two weeks. Possible values are: sunday, monday, tuesday, wednesday, thursday, friday, saturday. | Optional | 
| day_of_month | Only relevant when 'frequency_months' value was given. Day of month that the monthly schedule will run on. Between 1-31 depending on the month. For example, day_of_month=15 along with frequency_months=2 will result in the scan running every 2 months in the 15th of the month. | Optional | 
| day_of_week | Only relevant when 'frequency_months' value was given. Must be given with 'week_of_month' as well. Day of week that the schedule will run on. Between 0-6, where 0 is Sunday, and 6 is Saturday depending on the month. For example, day_of_week=2, week_of_month=second along with frequency_months=2 will result in the scan running every 2 months on Tuesday in the second week of the month. Possible values are: 0, 1, 2, 3, 4, 5, 6. | Optional | 
| week_of_month | Comma separated list. Only relevant when 'frequency_months' value was given. Must be given with 'week_of_month' as well. Day of week that the schedule will run on. Between 0-6, where 0 is Sunday, and 6 is Saturday depending on the month. For example, day_of_week=2, week_of_month=second along with frequency_months=2 will result in the scan running every 2 months on Tuesday in the second week of the month. Possible values are: first, second, third, fourth, last. | Optional | 
| start_date | The start date of the schedule. Format of mm/dd/yyyy. For example, 12/15/2020. | Optional | 
| start_hour | Required when 'start_date' is given. The start hour of the scheduled scan. Value between 0-23. | Optional | 
| start_minute | Required when 'start_date' is given. The start minute of the scheduled scan. Value between 0-59. | Optional | 
| time_zone_code | Required when 'start_date' is given. Time zone code of the given schedule scan. For example, US-CA for time zone California in US. | Optional | 
| observe_dst | Required when start_date is given. Specify yes to observe Daylight Saving Time (DST). This parameter is valid when the time zone code specified in time_zone_code supports DST. To get the list of time zones and their DST support, use the `qualys-time-zone-code` command. | Optional | 
| exclude_ip_per_scan | The IP addresses to be excluded from the scan when the scan target is specified as IP addresses (not asset tags). You may enter individual IP addresses and/or ranges. Multiple entries are comma separated. One of these parameters must be set: 'scanners_in_ag', 'default_scanner'. | Optional | 
| default_scanner | Specify 1 to use the default scanner in each target asset group. For an Express Lite user, Internal Scanning must be enabled in the user’s account. At most one of these parameters can be supplied: 'scanners_in_ag', 'default_scanner'. Possible values are: 0, 1. | Optional | 
| scanners_in_ag | Specify 1 to distribute the scan to the target asset groups’ scanner appliances. Appliances in each asset group are tasked with scanning the IPs in the group. By default up to 5 appliances per group will be used and this can be configured for your account (please contact your Account Manager or Support). For an Express Lite user, Internal Scanning must be enabled in the user’s account. At most one of these parameters can be supplied: 'scanners_in_ag', 'default_scanner'. Possible values are: 0, 1. | Optional | 
| active | Whether schedule scan is activated. Possible values are: 0, 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.ScheduleScan.Update.Status | unknown | TODO | 
| Qualys.ScheduleScan.Update.Timestamp | unknown | TODO | 

### qualys-asset-group-add
***
Create a new asset group.


#### Base Command

`qualys-asset-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The asset group title to add. | Required | 
| network_id | Restrict the request to a certain custom network ID. | Optional | 
| ips | Add IPs to asset group. IP addresses/ranges. One or more IPs/ranges may be specified. Multiple entries are comma separated. An IP range is specified with a hyphen (for example, 10.10.10.1-10.10.10.100). | Optional | 
| domains | Add domains to asset group; do not enter "www." at the start of the domain name. Multiple entries are comma separated. | Optional | 
| dns_names | Add DNS names to asset group. Multiple entries are comma separated. | Optional | 
| netbios_names | Add NETBIOS names to asset group. Multiple entries are comma separated. | Optional | 
| cvss_enviro_td | Add CVSS environment target distribution. Possible values are: high, medium, low, none. | Optional | 
| cvss_enviro_cr | Add CVSS environment confidentiality requirement. Possible values are: high, medium, low. | Optional | 
| cvss_enviro_ir | Add CVSS environment integrity requirement. Possible values are: high, medium, low. | Optional | 
| cvss_enviro_ar | Add CVSS environment availability requirement. Possible values are: high, medium, low. | Optional | 
| appliance_ids | Add appliance IDs to asset group. Multiple entries are comma separated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.AssetGroup.ID | String | Asset group ID. | 
| Qualys.AssetGroup.DATETIME | Date | Date of when command was executed. | 
| Qualys.AssetGroup.TEXT | String | Qualys response for asset group creation. | 

### qualys-asset-group-edit
***
Update an asset group.


#### Base Command

`qualys-asset-group-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| set_title | Set a new asset group title. | Optional | 
| id | ID of the asset group to edit. ID of asset groups can be retrieved via running the `qualys-group-list` command and using its ID field. | Required | 
| add_ips | Add IPs to asset group. IP addresses/ranges. One or more IPs/ranges may be specified. Multiple entries are comma separated. An IP range is specified with a hyphen (for example, 10.10.10.1-10.10.10.100). | Optional | 
| set_ips | Set IPs of asset group. IP addresses/ranges. One or more IPs/ranges may be specified. Multiple entries are comma separated. An IP range is specified with a hyphen (for example, 10.10.10.1-10.10.10.100). | Optional | 
| remove_ips | Remove IPs from asset group. IP addresses/ranges. One or more IPs/ranges may be specified. Multiple entries are comma separated. An IP range is specified with a hyphen (for example, 10.10.10.1-10.10.10.100). | Optional | 
| add_domains | Add domains to asset group; do not enter "www." at the start of the domain name. Multiple entries are comma separated. | Optional | 
| set_domains | Set domains of asset group; do not enter "www." at the start of the domain name. Multiple entries are comma separated. | Optional | 
| remove_domains | Remove domains from asset group; do not enter "www." at the start of the domain name. Multiple entries are comma separated. | Optional | 
| add_dns_names | Add DNS names to asset group. Multiple entries are comma separated. | Optional | 
| set_dns_names | Set DNS names of asset group. Multiple entries are comma separated. | Optional | 
| remove_dns_names | Remove DNS names from asset group. Multiple entries are comma separated. | Optional | 
| netbios_names | Add NETBIOS names to asset group. Multiple entries are comma separated. | Optional | 
| add_netbios_names | Add NETBIOS names to asset group. Multiple entries are comma separated. | Optional | 
| set_netbios_names | Set NETBIOS names of asset group. Multiple entries are comma separated. | Optional | 
| remove_netbios_names | Remove NETBIOS names from asset group. Multiple entries are comma separated. | Optional | 
| set_cvss_enviro_td | Set CVSS environment target distribution. Possible values are: high, medium, low, none. | Optional | 
| set_cvss_enviro_cr | Set CVSS environment confidentiality requirement. Possible values are: high, medium, low. | Optional | 
| set_cvss_enviro_ir | Set CVSS environment integrity requirement. Possible values are: high, medium, low. | Optional | 
| set_cvss_enviro_ar | Set CVSS environment availability requirement. Possible values are: high, medium, low. | Optional | 
| add_appliance_ids | Add appliance IDs to asset group. Multiple entries are comma separated. | Optional | 
| set_appliance_ids | Set appliance IDs of asset group. Multiple entries are comma separated. | Optional | 
| remove_appliance_ids | Remove appliance IDs from asset group. Multiple entries are comma separated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.AssetGroup.ID | String | Asset group ID. | 
| Qualys.AssetGroup.DATETIME | Date | Date of when command was executed. | 
| Qualys.AssetGroup.TEXT | String | Qualys response for asset group update. | 

### qualys-asset-group-delete
***
Delete an asset group.


#### Base Command

`qualys-asset-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset group ID to delete. ID of asset groups can be retrieved via running the `qualys-group-list` command and using its ID field. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.AssetGroup.ID | String | Asset group ID. | 
| Qualys.AssetGroup.DATETIME | Date | Date of when command was executed. | 
| Qualys.AssetGroup.TEXT | String | Qualys response for asset group deletion. | 

### qualys-schedule-scan-delete
***
Delete a scheduled scan.


#### Base Command

`qualys-schedule-scan-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Scheduled Scan ID to delete. the ID can be retrieved via running the `qualys-schedule-scan-list` command, and using the ID field. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.ScheduleScan.ID | String | ID of the scheduled scan to be deleted. | 
| Qualys.ScheduleScan.DATETIME | Date | Date of when command was executed. | 
| Qualys.ScheduleScan.TEXT | String | Qualys response for schedule scan deletion. | 

### qualys-time-zone-code
***
Gets a list of the supported time zone codes.


#### Base Command

`qualys-time-zone-code`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qualys.Timezone.Code.TIME_ZONE_CODE | unknown | Time zone code. | 
| Qualys.Timezone.Code.TIME_ZONE_DETAILS | unknown | Timezone code details. | 

#### Command example
```!qualys-time-zone-code```
#### Context Example
```json
{
    "Qualys": {
        "TimeZone": {
            "Code": [
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "AS",
                    "TIME_ZONE_DETAILS": "(GMT -11:00) American Samoa"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "UM2",
                    "TIME_ZONE_DETAILS": "(GMT -11:00) Midway Islands (U.S.)"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "NU",
                    "TIME_ZONE_DETAILS": "(GMT -11:00) Niue"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "CK",
                    "TIME_ZONE_DETAILS": "(GMT -10:00) Cook Islands"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "PF2A",
                    "TIME_ZONE_DETAILS": "(GMT -10:00) French Polynesia, Austral Islands"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "PF",
                    "TIME_ZONE_DETAILS": "(GMT -10:00) French Polynesia, Society Islands (including Tahiti)"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "PF2B",
                    "TIME_ZONE_DETAILS": "(GMT -10:00) French Polynesia, Tuamotu Archipelago"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "UM1",
                    "TIME_ZONE_DETAILS": "(GMT -10:00) Johnston Atoll (U.S.)"
                },
                {
                    "DST_SUPPORTED": "1",
                    "TIME_ZONE_CODE": "US-AK1",
                    "TIME_ZONE_DETAILS": "(GMT -10:00) United States, Alaska (Aleutian Islands)"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "US-HI",
                    "TIME_ZONE_DETAILS": "(GMT -10:00) United States, Hawaii"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "PF1",
                    "TIME_ZONE_DETAILS": "(GMT -09:30) French Polynesia, Marquesas Islands"
                },
                {
                    "DST_SUPPORTED": "0",
                    "TIME_ZONE_CODE": "PF3",
                    "TIME_ZONE_DETAILS": "(GMT -09:00) French Polynesia, Gambier Islands"
                },
                {
                    "DST_SUPPORTED": "1",
                    "TIME_ZONE_CODE": "US-AK",
                    "TIME_ZONE_DETAILS": "(GMT -09:00) United States, Alaska"
                },
                {
                    "DST_SUPPORTED": "1",
                    "TIME_ZONE_CODE": "CA-BC",
                    "TIME_ZONE_DETAILS": "(GMT -08:00) Canada, British Columbia (Pacific Standard Time)"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Time Zone Codes
>
>|DST_SUPPORTED|TIME_ZONE_CODE|TIME_ZONE_DETAILS|
>|---|---|---|
>| 0 | AS | (GMT -11:00) American Samoa |
>| 0 | UM2 | (GMT -11:00) Midway Islands (U.S.) |
>| 0 | NU | (GMT -11:00) Niue |
>| 0 | CK | (GMT -10:00) Cook Islands |
>| 0 | PF2A | (GMT -10:00) French Polynesia, Austral Islands |
>| 0 | PF | (GMT -10:00) French Polynesia, Society Islands (including Tahiti) |
>| 0 | PF2B | (GMT -10:00) French Polynesia, Tuamotu Archipelago |
>| 0 | UM1 | (GMT -10:00) Johnston Atoll (U.S.) |
>| 1 | US-AK1 | (GMT -10:00) United States, Alaska (Aleutian Islands) |
>| 0 | US-HI | (GMT -10:00) United States, Hawaii |
>| 0 | PF1 | (GMT -09:30) French Polynesia, Marquesas Islands |
>| 0 | PF3 | (GMT -09:00) French Polynesia, Gambier Islands |
>| 1 | US-AK | (GMT -09:00) United States, Alaska |
>| 1 | CA-BC | (GMT -08:00) Canada, British Columbia (Pacific Standard Time) |


## Breaking changes from the previous version of this integration - Qualys v2
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
