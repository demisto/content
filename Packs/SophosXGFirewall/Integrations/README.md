On-Premise firewall by Sophos
This integration was integrated and tested with version xx of sophos_firewall
## Configure sophos_firewall on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for sophos_firewall.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server_url | Server URL | True |
| credentials | User Credentials | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sophos-firewall-rule-list
***
List all firewall rules. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicy.Name | String | Name of the rule. | 
| SophosFirewall.SecurityPolicy.Description | String | Description of the rule. | 
| SophosFirewall.SecurityPolicy.Status | String | Status of the rule. | 
| SophosFirewall.SecurityPolicy.PolicyType | String | Policy type of the rule. | 
| SophosFirewall.SecurityPolicy.IPFamily | String | IPv4/IPv6 | 
| SophosFirewall.SecurityPolicy.AttachIdentity | String | Rule attach identity status. | 
| SophosFirewall.SecurityPolicy.Action | String | Current rule action. | 
| SophosFirewall.SecurityPolicy.LogTraffic | Number | Rule traffic logging code. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-rule-add
***
Add a new firewall rule.


#### Base Command

`sophos-firewall-rule-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the new rule. | Required | 
| description | Description of the new rule. | Optional | 
| status | Is the rule enabled or disabled. | Optional | 
| ip_family | Are the IPs v4 or v6. | Optional | 
| position | Should the rule be at the top or bottom of the list? before or after a specific rule? IMPORTANT: If before/after is chosen - provide the position_policy_name pramater. | Required | 
| position_policy_name | The name of the policy that the rule should be created before/after . REQUIRED: When the position is before/after | Optional | 
| policy_type | Type of the new rule (policy). | Required | 
| source_zones | Source zones to add to the rule. | Optional | 
| source_networks | Source networks to add to the rule. | Optional | 
| destination_zones | Destination zones to add to the rule. | Optional | 
| destination_networks | Destination networks to add to the rule. | Optional | 
| services | Destination services to add to the rule. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console | Optional | 
| log_traffic | Enable traffic logging for the policy. | Optional | 
| match_identity | Enable to check whether the specified user/user group from the selected zone is allowed to access the selected service or not. IMPORTANT: when enabling match_identity - members parameter is required. | Optional | 
| show_captive_portal | Select to accept traffic from unknown users. Captive portal page is displayed to the user where the user can login to access the Internet. IMPORTANT: MatchIdentity must be Enabled. PARAMETER OF: UserPolicy | Optional | 
| members | An existing user(s) or group(s) to add to the rule. REQUIRED: when match_identity is enabled.  | Optional | 
| action | Specify action for the rule traffic. | Optional | 
| dscp_marking | Select DSCP Marking to classify flow of packets based on Traffic Shaping policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-rule-update
***
Update an existing firewall rule.


#### Base Command

`sophos-firewall-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the new rule. | Required | 
| description | Description of the new rule. | Optional | 
| status | Is the rule enabled or disabled. | Optional | 
| ip_family | Are the IPs v4 or v6. | Optional | 
| position | Should the rule be at the top or bottom of the list? before or after a specific rule? IMPORTANT: If before/after is chosen - provide the position_policy_name pramater. | Optional | 
| position_policy_name | The name of the policy that the rule should be created before/after . REQUIRED: When the position is before/after | Optional | 
| policy_type | Type of the new rule (policy). | Required | 
| source_zones | Source zones to add to the rule. | Optional | 
| source_networks | Source networks to add to the rule. | Optional | 
| destination_zones | Destination zones to add to the rule. | Optional | 
| destination_networks | Destination networks to add to the rule. | Optional | 
| services | Destination services to add to the rule. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console | Optional | 
| log_traffic | Enable traffic logging for the policy. | Optional | 
| match_identity | Enable to check whether the specified user/user group from the selected zone is allowed to access the selected service or not. IMPORTANT: when enabling match_identity - members parameter is required. | Optional | 
| show_captive_portal | Select to accept traffic from unknown users. Captive portal page is displayed to the user where the user can login to access the Internet. IMPORTANT: MatchIdentity must be Enabled. PARAMETER OF: UserPolicy | Optional | 
| members | An existing user(s) or group(s) to add to the rule. REQUIRED: when match_identity is enabled.  | Optional | 
| action | Specify action for the rule traffic. | Optional | 
| dscp_marking | Select DSCP Marking to classify flow of packets based on Traffic Shaping policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-rule-delete
***
Delete an existing firewall rule or rules.


#### Base Command

`sophos-firewall-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-rule-group-list
***
List all firewall rule groups. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-rule-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicyGroup.Name | String | Name of the group. | 
| SophosFirewall.SecurityPolicyGroup.Description | String | Description of the group. | 
| SophosFirewall.SecurityPolicyGroup.SecurityPolicyList | String | Rules contained inside the group. | 
| SophosFirewall.SecurityPolicyGroup.SourceZones | String | Source zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.DestinationZones | String | Destination zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.PolicyType | Number | Type of the rules in the group. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-rule-group-add
***
Add a new firewall rule group.


#### Base Command

`sophos-firewall-rule-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule group. | Required | 
| description | Description of the rule group. | Optional | 
| policy_type | Type of the rules (policies) inside. | Optional | 
| rules | Rules contained inside the group. | Optional | 
| source_zones | Source zones contained in the group. | Optional | 
| destination_zones | Destination zones contained in the group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-rule-group-update
***
Update an existing firewall rule group.


#### Base Command

`sophos-firewall-rule-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule group. | Required | 
| description | Description of the rule group. | Optional | 
| policy_type | Type of the rules (policies) inside. | Optional | 
| rules | Rules contained inside the group. | Optional | 
| source_zones | Source zones contained in the group. | Optional | 
| destination_zones | Destination zones contained in the group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-rule-group-delete
***
Delete an existing firewall group or groups.


#### Base Command

`sophos-firewall-rule-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule group(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-url-group-list
***
List all URL groups. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-url-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.Description | String | Description of the URL group. | 
| SophosFirewall.WebFilterURLGroup.URL | String | URL contained inside the group. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-url-group-add
***
Add a new URL group.


#### Base Command

`sophos-firewall-url-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group. | Required | 
| description | Description of the group. | Optional | 
| urls | URLs to add to the group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-url-group-update
***
Update an existing URL group.


#### Base Command

`sophos-firewall-url-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group. | Required | 
| description | Description of the group. | Optional | 
| urls | URLs to add to the group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-url-group-delete
***
Delete an existing URL group or groups.


#### Base Command

`sophos-firewall-url-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-list
***
List all IP hosts. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-ip-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | is the host in IPv4 or IPv6. | 
| SophosFirewall.IPHost.HostType | String | Type of the host. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-add
***
Add a new IP host.


#### Base Command

`sophos-firewall-ip-host-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host. | Required | 
| host_type | Type of the host. | Required | 
| ip_family | Is the IP in IPv4 or IPv6. | Optional | 
| ip_address | IP address if IP or network was the chosen type. | Optional | 
| subnet_mask | Subnet mask if network was the chosen type. | Optional | 
| start_ip | Start of the IP range if IPRange was chosen. | Optional | 
| end_ip | End of the IP range if IPRange was chosen. | Optional | 
| ip_addresses | List of IP addresses if IPList was chosen. | Optional | 
| host_group | Select the Host Group to which the Host belongs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-update
***
Update an existing IP host.


#### Base Command

`sophos-firewall-ip-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host. | Required | 
| host_type | Type of the host. | Required | 
| ip_family | Is the IP in IPv4 or IPv6. | Optional | 
| ip_address | IP address if IP or network was the chosen type. | Optional | 
| subnet_mask | Subnet mask if network was the chosen type. | Optional | 
| start_ip | Start of the IP range if IPRange was chosen. | Optional | 
| end_ip | End of the IP range if IPRange was chosen. | Optional | 
| ip_addresses | List of IP addresses if IPList was chosen. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-delete
***
Delete an existing IP host or hosts.


#### Base Command

`sophos-firewall-ip-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-group-list
***
List all IP host groups. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-ip-host-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.Host | String | Host contained inside the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group \(IPv4 / IPv6\) | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-group-add
***
Add a new IP host group.


#### Base Command

`sophos-firewall-ip-host-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group. | Required | 
| description | Description of the IP host group. | Optional | 
| ip_family | Is the IP group in IPv4 or IPv6. | Optional | 
| hosts | IP hosts contained in the group | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-group-update
***
Update an existing IP host group.


#### Base Command

`sophos-firewall-ip-host-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group. | Required | 
| description | Description of the IP host group. | Optional | 
| ip_family | Is the IP group in IPv4 or IPv6. | Optional | 
| hosts | IP hosts contained in the group | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-ip-host-group-delete
***
Delete an existing IP host group or groups.


#### Base Command

`sophos-firewall-ip-host-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-services-list
***
List all firewall services. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-services-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.Services.Name | String | Name of the firewall service. | 
| SophosFirewall.Services.Type | String | Type of the firewall service. | 
| SophosFirewall.Services.ServiceDetails | String | Details about the service. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-services-add
***
Add a new firewall service.


#### Base Command

`sophos-firewall-services-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service. | Required | 
| service_type | Type of service | Required | 
| protocol | Select Protocol for the service if service_type is TCPorUDP | Optional | 
| source_port | Source port if service_type is TCPorUDP | Optional | 
| destination_port | Destination port if service_type is TCPorUDP | Optional | 
| protocol_name | Protocol name if service_type is IP  | Optional | 
| icmp_type | ICMP type if service_type is ICMP | Optional | 
| icmp_code | ICMP code if service_type is ICMP | Optional | 
| icmp_v6_type | ICMPv6 type if service_type is ICMPv6 | Optional | 
| icmp_v6_code | ICMPv6 code if service_type is ICMPv6 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-services-update
***
Update an existing firewall service.


#### Base Command

`sophos-firewall-services-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service. | Required | 
| service_type | Type of service | Required | 
| protocol | Select Protocol for the service if service_type is TCPorUDP | Optional | 
| source_port | Source port if service_type is TCPorUDP | Optional | 
| destination_port | Destination port if service_type is TCPorUDP | Optional | 
| protocol_name | Protocol name if service_type is IP  | Optional | 
| icmp_type | ICMP type if service_type is ICMP | Optional | 
| icmp_code | ICMP code if service_type is ICMP | Optional | 
| icmp_v6_type | ICMPv6 type if service_type is ICMPv6 | Optional | 
| icmp_v6_code | ICMPv6 code if service_type is ICMPv6 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-services-delete
***
Delete an existing firewall service or services.


#### Base Command

`sophos-firewall-services-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-list
***
List all users. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.User.Name | String | Name of the user. | 
| SophosFirewall.User.Username | String | Username of the user. | 
| SophosFirewall.User.Description | String | Description of the user. | 
| SophosFirewall.User.Email | String | Email of the user. | 
| SophosFirewall.User.Group | String | Group of the user. | 
| SophosFirewall.User.UserType | String | User type of the user. | 
| SophosFirewall.User.Status | String | Status of the user. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-add
***
Add a new user.


#### Base Command

`sophos-firewall-user-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | username of the user | Required | 
| name | name of the user | Required | 
| description | description of the user | Optional | 
| email | email of the user | Required | 
| group | group of the user.  | Optional | 
| password | the password of the user. | Required | 
| user_type | the type of the user. | Optional | 
| profile | profile of the admin if user_type is admin. IMPORTANT: you can add more types on the web console | Optional | 
| surfing_quota_policy | Select the Surfing Quota Policy. | Optional | 
| access_time_policy | Select the Access Time Policy | Optional | 
| ssl_vpn_policy | Select SSL VPN policy | Optional | 
| clientless_policy | Select clientlesspolicy policy | Optional | 
| data_transfer_policy | Select the Data Transfer Policy | Optional | 
| simultaneous_logins_global | Enable Simultaneous Logins Global | Optional | 
| schedule_for_appliance_access | Select Schedule for appliance access. IMPORTANT: This option is available only for Administrators | Optional | 
| qos_policy | Select the QoS Policy | Optional | 
| login_restriction | Select login restriction option | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-update
***
Update a user.


#### Base Command

`sophos-firewall-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | username of the user | Required | 
| name | name of the user | Required | 
| description | description of the user | Optional | 
| email | email of the user | Required | 
| group | group of the user.  | Optional | 
| password | the password of the user. | Required | 
| user_type | the type of the user. | Optional | 
| profile | profile of the admin if user_type is admin. IMPORTANT: you can add more types on the web console | Optional | 
| surfing_quota_policy | Select the Surfing Quota Policy. | Optional | 
| access_time_policy | Select the Access Time Policy | Optional | 
| ssl_vpn_policy | Select SSL VPN policy | Optional | 
| clientless_policy | Select clientlesspolicy policy | Optional | 
| data_transfer_policy | Select the Data Transfer Policy | Optional | 
| simultaneous_logins_global | Enable Simultaneous Logins Global | Optional | 
| schedule_for_appliance_access | Select Schedule for appliance access. IMPORTANT: This option is available only for Administrators | Optional | 
| qos_policy | Select the QoS Policy | Optional | 
| login_restriction | Select login restriction option | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-delete
***
Delete an existing user or users.


#### Base Command

`sophos-firewall-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-group-list
***
List all user groups. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-user-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.UserGroup.Name | String | Name of the user group. | 
| SophosFirewall.UserGroup.GroupType | String | Type of the user group. | 
| SophosFirewall.UserGroup.GroupMembers | String | Members of the user group. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-group-add
***
Add new group of users.


#### Base Command

`sophos-firewall-user-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | name of the user group | Required | 
| group_type | the type of the user group. | Optional | 
| surfing_quota_policy | Select the Surfing Quota Policy. | Optional | 
| access_time_policy | Select the Access Time Policy | Optional | 
| ssl_vpn_policy | Select SSL VPN policy | Optional | 
| clientless_policy | Select clientlesspolicy policy | Optional | 
| data_transfer_policy | Select the Data Transfer Policy | Optional | 
| qos_policy | Select the QoS Policy | Optional | 
| login_restriction | Select login restriction option | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-group-update
***
Update an existing group of users.


#### Base Command

`sophos-firewall-user-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | name of the user group | Required | 
| group_type | the type of the user group. | Optional | 
| surfing_quota_policy | Select the Surfing Quota Policy. | Optional | 
| access_time_policy | Select the Access Time Policy | Optional | 
| ssl_vpn_policy | Select SSL VPN policy | Optional | 
| clientless_policy | Select clientlesspolicy policy | Optional | 
| data_transfer_policy | Select the Data Transfer Policy | Optional | 
| qos_policy | Select the QoS Policy | Optional | 
| login_restriction | Select login restriction option | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-user-group-delete
***
Delete an existing group or groups of users.


#### Base Command

`sophos-firewall-user-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-app-policy-list
***
List all app policies. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-app-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Does the policy support microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList | String | Rules details | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-app-policy-add
***
Add a new app policy.


#### Base Command

`sophos-firewall-app-policy-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| micro_app_support | Is microapp support enabled. | Optional | 
| default_action | Default action for the policy. | Optional | 
| select_all | Is the rule a select all rule. | Optional | 
| categories | Categories to add to the rule. | Optional | 
| risks | Risks to add to the rule. | Optional | 
| applications | Applications to add to the rule. | Optional | 
| characteristics | Characteristics to add to the rule. | Optional | 
| technologies | Technologies to add to the rule. | Optional | 
| classifications | Classifications to add to the rule. | Optional | 
| action | Action for the rule. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-app-policy-update
***
Update an existing app policy.


#### Base Command

`sophos-firewall-app-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| micro_app_support | Is microapp support enabled. | Optional | 
| default_action | Default action for the policy. | Optional | 
| select_all | Is the rule a select all rule. | Optional | 
| categories | Categories to add to the rule. | Optional | 
| risks | Risks to add to the rule. | Optional | 
| applications | Applications to add to the rule. | Optional | 
| characteristics | Characteristics to add to the rule. | Optional | 
| technologies | Technologies to add to the rule. | Optional | 
| classifications | Classifications to add to the rule. | Optional | 
| action | Action for the rule. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-app-policy-delete
***
Delete an existing app policy or policies.


#### Base Command

`sophos-firewall-app-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-app-category-list
***
List all app filter categories. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-app-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.appCategory.Name | String | Name of the app category. | 
| SophosFirewall.appCategory.Description | String | Description of the app category. | 
| SophosFirewall.appCategory.QoSPolicy | String | QoS policy of the category. | 
| SophosFirewall.appCategory.BandwidthUsageType | String | Bandwidth usage type of the category. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-app-category-update
***
Update an existing app filter category.


#### Base Command

`sophos-firewall-app-category-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the app category. | Required | 
| qos_policy | QoS policy of the category. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-web-filter-list
***
List all web filter policies. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-web-filter-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5 | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Does the policy report events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Is the file size restriction active. | 
| SophosFirewall.WebFilterPolicy.CategoryList | String | Category list information. | 


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-web-filter-add
***
Add a new web filter policy.


#### Base Command

`sophos-firewall-web-filter-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy | Required | 
| description | Description of the policy. | Optional | 
| default_action | Default action for the policy. | Required | 
| download_file_size_restriction_enabled | Should the max download file size be enabled. | Optional | 
| download_file_size_restriction | Max file size to enable downloading in MB. | Optional | 
| goog_app_domain_list_enabled | Enable to specify domains allowed to access google service | Optional | 
| goog_app_domain_list | Specify domains allowed to access google service. | Optional | 
| youtube_filter_enabled | Enable YouTube Restricted Mode to restrict the content that is accessible. | Optional | 
| youtube_filter_is_strict | Adjust the policy used for YouTube Restricted Mode. | Optional | 
| enforce_safe_search | Enable to block websites containing pornography and explicit sexual content from appearing in the search results of Google, Yahoo, Bing search results. | Optional | 
| enforce_image_licensing | Further limit inappropriate content by enforcing search engine filters for Creative Commons licensed images. | Optional | 
| url_group_names | URL Groups to block\allow\warn\log | Optional | 
| http_action | Choose action for http | Optional | 
| https_action | Choose action for https | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console | Optional | 
| policy_rule_enabled | Enable policy rule | Optional | 
| user_names | Choose users which this rule will apply on | Optional | 
| ccl_names | CCL names. REQUIRED: when ccl_rule_enabled is ON | Optional | 
| ccl_rule_enabled | Enable CCL rule. IMPORTANT: if enabled - ccl_name is requierd. | Optional | 
| follow_http_action | Enable following HTTP action | Optional | 
| enable_reporting | Select to enable reporting of policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-web-filter-update
***
Update an existing web filter policy.


#### Base Command

`sophos-firewall-web-filter-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy | Required | 
| description | Description of the policy. | Optional | 
| default_action | Default action for the policy. | Required | 
| download_file_size_restriction_enabled | Should the max download file size be enabled. | Optional | 
| download_file_size_restriction | Max file size to enable downloading in MB. | Optional | 
| goog_app_domain_list_enabled | Enable to specify domains allowed to access google service | Optional | 
| goog_app_domain_list | Specify domains allowed to access google service. | Optional | 
| youtube_filter_enabled | Enable YouTube Restricted Mode to restrict the content that is accessible. | Optional | 
| youtube_filter_is_strict | Adjust the policy used for YouTube Restricted Mode. | Optional | 
| enforce_safe_search | Enable to block websites containing pornography and explicit sexual content from appearing in the search results of Google, Yahoo, Bing search results. | Optional | 
| enforce_image_licensing | Further limit inappropriate content by enforcing search engine filters for Creative Commons licensed images. | Optional | 
| url_group_names | URL Groups to block\allow\warn\log | Optional | 
| http_action | Choose action for http | Optional | 
| https_action | Choose action for https | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console | Optional | 
| policy_rule_enabled | Enable policy rule | Optional | 
| user_names | Choose users which this rule will apply on | Optional | 
| ccl_names | CCL names. REQUIRED: when ccl_rule_enabled is ON | Optional | 
| ccl_rule_enabled | Enable CCL rule. IMPORTANT: if enabled - ccl_name is requierd. | Optional | 
| follow_http_action | Enable following HTTP action | Optional | 
| enable_reporting | Select to enable reporting of policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output



### sophos-firewall-web-filter-delete
***
Delete an existing web filter policy or policies.


#### Base Command

`sophos-firewall-web-filter-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
``` ```

#### Human Readable Output


