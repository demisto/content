On-Premise firewall by Sophos enables you to manage your firewall, respond to threats, and monitor what’s
happening on your network.
## Configure Sophos Firewall in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server_url | Server URL | True |
| credentials | User Credentials | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sophos-firewall-rule-list
***
Lists all firewall rules. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicy.Name | String | Name of the rule. | 
| SophosFirewall.SecurityPolicy.Description | String | Description of the rule. | 
| SophosFirewall.SecurityPolicy.Status | String | Status of the rule. | 
| SophosFirewall.SecurityPolicy.PolicyType | String | Policy type of the rule. | 
| SophosFirewall.SecurityPolicy.IPFamily | String | IP family of the security policy. Either IPv4 or IPv6. | 
| SophosFirewall.SecurityPolicy.AttachIdentity | String | Rule attach identity status. | 
| SophosFirewall.SecurityPolicy.Action | String | Current rule action. | 
| SophosFirewall.SecurityPolicy.LogTraffic | Number | Rule traffic logging code. | 


#### Command Example
```!sophos-firewall-rule-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicy": [
            {
                "After": {
                    "Name": "[example] Traffic to DMZ"
                },
                "ApplyNAT": "CustomNatPolicy",
                "Description": "This rule was added automatically by SFOS MTA. However you could edit this policy based on network requirement.",
                "DestSecurityHeartbeat": "Disable",
                "IPFamily": "IPv4",
                "IntrusionPrevention": "None",
                "IsDeleted": false,
                "LogTraffic": "Disable",
                "MatchIdentity": "Disable",
                "MinimumDestinationHBPermitted": "No Restriction",
                "MinimumSourceHBPermitted": "No Restriction",
                "Name": "Auto added firewall policy for MTA",
                "OutboundAddress": "MASQ",
                "OverrideGatewayDefaultNATPolicy": "Disable",
                "PolicyType": "PublicNonHTTPPolicy",
                "Position": "After",
                "PublicNonHTTPBasedPolicy": {
                    "ScanIMAP": "Disable",
                    "ScanIMAPS": "Disable",
                    "ScanPOP3": "Disable",
                    "ScanPOP3S": "Disable",
                    "ScanSMTP": "Enable",
                    "ScanSMTPS": "Enable"
                },
                "SourceSecurityHeartbeat": "Disable",
                "Status": "Enable",
                "TrafficShappingPolicy": "None"
            },
            {
                "Action": "Drop",
                "After": {
                    "Name": "[example] Traffic to WAN"
                },
                "Description": "A disabled Firewall rule with the destination zone as DMZ. Such rules would be added to Traffic to DMZ group on the first match basis if user selects automatic grouping option.",
                "DestinationZones": {
                    "Zone": "DMZ"
                },
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "LogTraffic": "Enable",
                "MatchIdentity": "Enable",
                "Name": "[example] Traffic to DMZ",
                "PolicyType": "User",
                "Position": "After",
                "Schedule": "All The Time",
                "ShowCaptivePortal": "Enable",
                "Status": "Disable"
            },
            {
                "Action": "Drop",
                "After": {
                    "Name": "after"
                },
                "Description": "A disabled Firewall rule with the destination zone as WAN. Such rules would be added to Traffic to WAN group on the first match basis if user selects automatic grouping option.",
                "DestinationZones": {
                    "Zone": "WAN"
                },
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "LogTraffic": "Enable",
                "MatchIdentity": "Disable",
                "Name": "[example] Traffic to WAN",
                "PolicyType": "Network",
                "Position": "After",
                "Schedule": "All The Time",
                "Status": "Disable"
            },
            {
                "Action": "Drop",
                "After": {
                    "Name": "Auto added firewall policy for MTA"
                },
                "Description": null,
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "LogTraffic": "Disable",
                "MatchIdentity": "Disable",
                "Name": "[example] Traffic to Internal Zones",
                "PolicyType": "Network",
                "Position": "After",
                "Schedule": "All The Time",
                "Status": "Enable"
            },
            {
                "Action": "Drop",
                "Description": null,
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "LogTraffic": "Disable",
                "MatchIdentity": "Disable",
                "Name": "Blocked IPs",
                "PolicyType": "Network",
                "Position": "Top",
                "Schedule": "All The Time",
                "SourceNetworks": {
                    "Network": "Blocked by Playbook"
                },
                "Status": "Enable"
            },
            {
                "Action": "Drop",
                "After": {
                    "Name": "before"
                },
                "Description": null,
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "LogTraffic": "Disable",
                "MatchIdentity": "Disable",
                "Name": "after",
                "PolicyType": "Network",
                "Position": "After",
                "Schedule": "All The Time",
                "Status": "Enable"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 SecurityPolicy objects out of 8
>|Name|Description|Status|PolicyType|IPFamily|Action|LogTraffic|
>|---|---|---|---|---|---|---|
>| Auto added firewall policy for MTA | This rule was added automatically by SFOS MTA. However you could edit this policy based on network requirement. | Enable | PublicNonHTTPPolicy | IPv4 |  | Disable |
>| [example] Traffic to DMZ | A disabled Firewall rule with the destination zone as DMZ. Such rules would be added to Traffic to DMZ group on the first match basis if user selects automatic grouping option. | Disable | User | IPv4 | Drop | Enable |
>| [example] Traffic to WAN | A disabled Firewall rule with the destination zone as WAN. Such rules would be added to Traffic to WAN group on the first match basis if user selects automatic grouping option. | Disable | Network | IPv4 | Drop | Enable |
>| [example] Traffic to Internal Zones |  | Enable | Network | IPv4 | Drop | Disable |
>| Blocked IPs |  | Enable | Network | IPv4 | Drop | Disable |
>| after |  | Enable | Network | IPv4 | Drop | Disable |


### sophos-firewall-rule-get
***
Gets a single firewall rule by name.


#### Base Command

`sophos-firewall-rule-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicy.Name | String | Name of the rule. | 
| SophosFirewall.SecurityPolicy.Description | String | Description of the rule. | 
| SophosFirewall.SecurityPolicy.Status | String | Status of the rule. | 
| SophosFirewall.SecurityPolicy.PolicyType | String | Policy type of the rule. | 
| SophosFirewall.SecurityPolicy.IPFamily | String | IP family of the security policy. Either IPv4 or IPv6. | 
| SophosFirewall.SecurityPolicy.AttachIdentity | String | Rule attach identity status. | 
| SophosFirewall.SecurityPolicy.Action | String | Current rule action. | 
| SophosFirewall.SecurityPolicy.LogTraffic | Number | Rule traffic logging code. | 


#### Command Example
```!sophos-firewall-rule-get name=user_rule```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicy": {
            "Action": "Drop",
            "After": {
                "Name": "1"
            },
            "Description": null,
            "DestinationZones": {
                "Zone": "LAN"
            },
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "LogTraffic": "Enable",
            "MatchIdentity": "Disable",
            "Name": "user_rule",
            "PolicyType": "Network",
            "Position": "After",
            "Schedule": "All The Time",
            "SourceZones": {
                "Zone": "LAN"
            },
            "Status": "Enable"
        }
    }
}
```

#### Human Readable Output

>### SecurityPolicy Object details
>|Name|Status|PolicyType|IPFamily|Action|LogTraffic|
>|---|---|---|---|---|---|
>| user_rule | Enable | Network | IPv4 | Drop | Enable |


### sophos-firewall-rule-add
***
Adds a new firewall rule.


#### Base Command

`sophos-firewall-rule-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the new rule. | Required | 
| description | Description of the new rule. | Optional | 
| status | Whether the rule is enabled. Possible values: "Enable" and "Disable". Default is "Enable". | Optional | 
| ip_family | The IP family. Possible values: "IPv4" and "IPv6". Default is "IPv4". | Optional | 
| position | Whether the rule should be at the "top" or "bottom" of the list, or "before" or\ \ "after" a specific rule? IMPORTANT: If "before" or "after" is selected, provide the\ \ position_policy_name parameter. | Required | 
| position_policy_name | The name of the policy that the rule should be created before or after. REQUIRED: When the position is "before" or "after". | Optional | 
| policy_type | Type of the new rule (policy). Possible values: "User" and "Network". | Required | 
| source_zones | Source zones to add to the rule. Possible values: "Any", "LAN". "WAN", "VPN", "DMZ", "WiFi". | Optional | 
| source_networks | Source networks to add to the rule. | Optional | 
| destination_zones | Destination zones to add to the rule. Possible values: "Any", "LAN". "WAN", "VPN", "DMZ", "WiFi". | Optional | 
| destination_networks | Destination networks to add to the rule. | Optional | 
| services | Destination services to add to the rule. | Optional | 
| schedule | The schedule for the rule. Possible values: "All the time", "Work hours (5 Day week)", "Work hours (6 Day week)", "All Time on Weekdays", "All Time on Weekends", "All Time on Sunday", "All Days 10:00 to 19:00". IMPORTANT: Creating a new schedule is available from the web console. | Optional | 
| log_traffic | Whether to enable traffic logging for the policy. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| match_identity | Whether to check if the specified user/user group from the\ \ selected zone is allowed to access the selected service. Possible values: "Enable" and "Disable". Default is "Disable". IMPORTANT: When enabling match_identity, the members argument is required. | Optional | 
| show_captive_portal | Whether to accept traffic from unknown users. Captive portal page\ \ is displayed to the user where the user can login to access the Internet.\ \ Possible values: "Enable" and "Disable". Default is "Disable". IMPORTANT: MatchIdentity must be Enabled. PARAMETER OF: UserPolicy. | Optional | 
| members | An existing user(s) or group(s) to add to the rule. REQUIRED when match_identity is enabled.  | Optional | 
| action | Action for the rule traffic. Possible values: "Accept", "Reject", and "Drop". Default is "Drop". | Optional | 
| dscp_marking | The DSCP marking level to classify the flow of packets based on the Traffic Shaping policy. | Optional | 
| primary_gateway | The primary gateway. Applicable only in case of multiple gateways. | Optional | 
| backup_gateway | The backup gateway. Applicable only in case of multiple gateways. | Optional | 
| application_control | The Application Filter policy for the rule. Default is "Allow All". | Optional | 
| application_based_qos_policy | Whether to limit the bandwidth for the applications categorized\ \ under the Application category. This tag is only applicable when\ \ an application_control is selected. Possible values: "Apply" and "Revoke". Default is "Revoke". | Optional | 
| web_filter | The Web Filter policy for the rule. Default is "Allow All". | Optional | 
| web_category_base_qos_policy | Whether to limit the bandwidth for the URLs categorized under the Web\ \ category. This tag is only applicable when any web_filter is defined." Possible values: "Apply" and "Revoke". Default is "Revoke". | Optional | 
| traffic_shaping_policy | The Traffic Shaping policy for the rule. Default is "None". | Optional | 
| scan_http | Whether to enable virus and spam scanning for HTTP protocol. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| scan_https | Whether to enable virus and spam scanning for HTTPS protocol. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| sandstorm | Whether to enable sandstorm analysis. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| block_quick_quic | Whether to enable Google websites to use HTTP/s instead of QUICK QUIC. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| scan_ftp | Whether to enable scanning of FTP traffic. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| data_accounting | Whether to exclude a user's network traffic from data accounting. This option is available only if the parameter "Match rule-based on user identity" is enabled. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| rewrite_source_address | Whether to enable the NAT policy. Possible values: "Enable" and "Disable". Default is "Enable". | Optional | 
| web_filter_internet_scheme | Whether to enable the internet scheme to apply the user-based Web Filter policy for the rule. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| application_control_internet_scheme | Whether to enable the internet scheme to apply user-based Application Filter Policy for the rule. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| override_gateway_default_nat_policy | Whether to override the gateway of the default NAT policy. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| source_security_heartbeat | Whether to enable the source security heartbeat. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| destination_security_heartbeat | Whether to enable the destination security heartbeat. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| outbound_address | The NAT policy to be applied. Default is "MASQ". | Optional | 
| minimum_source_hb_permitted | The minimum source health status permitted. Default is "No Restriction". | Optional | 
| minimum_destination_hb_permitted | The minimum destination health status permitted. Default is "No Restriction". | Optional | 
| intrusion_prevention | The IPS policy for the rule. Default is "generalpolicy". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicy.Name | String | Name of the rule. | 
| SophosFirewall.SecurityPolicy.Description | String | Description of the rule. | 
| SophosFirewall.SecurityPolicy.Status | String | Status of the rule. | 
| SophosFirewall.SecurityPolicy.PolicyType | String | Policy type of the rule. | 
| SophosFirewall.SecurityPolicy.IPFamily | String | IP family of the security policy. Either IPv4 or IPv6. | 
| SophosFirewall.SecurityPolicy.AttachIdentity | String | Rule attach identity status. | 
| SophosFirewall.SecurityPolicy.Action | String | Current rule action. | 
| SophosFirewall.SecurityPolicy.LogTraffic | Number | Rule traffic logging code. | 


#### Command Example
```!sophos-firewall-rule-add name=user_rule action=Accept ip_family=IPv4 log_traffic=Disable policy_type=User position=bottom match_identity=Enable show_captive_portal=Enable destination_zones=LAN members="Guest Group"```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicy": {
            "Action": "Accept",
            "After": {
                "Name": "1"
            },
            "ApplicationBaseQoSPolicy": "Revoke",
            "ApplicationControl": "Allow All",
            "ApplicationControlInternetScheme": "Disable",
            "BackupGateway": null,
            "BlockQuickQuic": "Disable",
            "DSCPMarking": null,
            "DataAccounting": "Disable",
            "Description": null,
            "DestSecurityHeartbeat": "Disable",
            "DestinationZones": {
                "Zone": "LAN"
            },
            "IPFamily": "IPv4",
            "Identity": {
                "Member": "Guest Group"
            },
            "IntrusionPrevention": "generalpolicy",
            "IsDeleted": false,
            "LogTraffic": "Disable",
            "MatchIdentity": "Enable",
            "MinimumDestinationHBPermitted": "No Restriction",
            "MinimumSourceHBPermitted": "No Restriction",
            "Name": "user_rule",
            "OutboundAddress": "MASQ",
            "OverrideGatewayDefaultNATPolicy": "Disable",
            "PolicyType": "User",
            "Position": "After",
            "PrimaryGateway": null,
            "RewriteSourceAddress": "Enable",
            "Sandstorm": "Disable",
            "ScanFTP": "Disable",
            "ScanHTTP": "Disable",
            "ScanHTTPS": "Disable",
            "Schedule": "All The Time",
            "ShowCaptivePortal": "Enable",
            "SourceSecurityHeartbeat": "Disable",
            "Status": "Enable",
            "TrafficShappingPolicy": "None",
            "WebCategoryBaseQoSPolicy": "Revoke",
            "WebFilter": "Allow All",
            "WebFilterInternetScheme": "Disable"
        }
    }
}
```

#### Human Readable Output

>### SecurityPolicy Object details
>|Name|Status|PolicyType|IPFamily|Action|LogTraffic|
>|---|---|---|---|---|---|
>| user_rule | Enable | User | IPv4 | Accept | Disable |

### sophos-firewall-rule-update
***
Updates an existing firewall rule.


#### Base Command

`sophos-firewall-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the new rule. | Required | 
| description | Description of the new rule. | Optional | 
| status | Whether the rule is enabled. Possible values: "Enable" and "Disable". Default is "Enable". | Optional | 
| ip_family | The IP family. Possible values: "IPv4" and "IPv6". Default is "IPv4". | Optional | 
| position | Whether the rule should be at the "top" or "bottom" of the list, or "before" or\ \ "after" a specific rule? IMPORTANT: If "before" or "after" is selected, provide the\ \ position_policy_name parameter. | Optional | 
| position_policy_name | The name of the policy that the rule should be created before or after. REQUIRED: When the position is "before" or "after". | Optional | 
| policy_type | Type of the new rule (policy). Possible values: "User" and "Network". | Optional | 
| source_zones | Source zones to add to the rule. Possible values: "Any", "LAN". "WAN", "VPN", "DMZ", "WiFi". | Optional | 
| source_networks | Source networks to add to the rule. | Optional | 
| destination_zones | Destination zones to add to the rule. Possible values: "Any", "LAN". "WAN", "VPN", "DMZ", "WiFi". | Optional | 
| destination_networks | Destination networks to add to the rule. | Optional | 
| services | Destination services to add to the rule. | Optional | 
| schedule | The schedule for the rule. Possible values: "All the time", "Work hours (5 Day week)", "Work hours (6 Day week)", "All Time on Weekdays", "All Time on Weekends", "All Time on Sunday", "All Days 10:00 to 19:00". IMPORTANT: Creating a new schedule is available in the web console. | Optional | 
| log_traffic | Whether to enable traffic logging for the policy. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| match_identity | Whether to check if the specified user/user group from the\ \ selected zone is allowed to access the selected service. Possible values: "Enable" and "Disable". Default is "Disable". IMPORTANT: When enabling match_identity, the members argument is required. | Optional | 
| show_captive_portal | Whether to accept traffic from unknown users. Captive portal page\ \ is displayed to the user where the user can login to access the Internet.\ \ Possible values: "Enable" and "Disable". Default is "Disable". IMPORTANT: MatchIdentity must be Enabled. PARAMETER OF: UserPolicy. | Optional | 
| members | An existing user(s) or group(s) to add to the rule. REQUIRED  when match_identity is enabled.  | Optional | 
| action | Action for the rule traffic. Possible values: "Accept", "Reject", and "Drop". Default is "Drop". | Optional | 
| dscp_marking | The DSCP marking level to classify the flow of packets based on the Traffic Shaping policy. | Optional | 
| primary_gateway | The primary gateway. Applicable only in case of multiple gateways. | Optional | 
| backup_gateway | The backup gateway. Applicable only in case of multiple gateways. | Optional | 
| application_control | The Application Filter policy for the rule. Default is "Allow All". | Optional | 
| application_based_qos_policy | Whether to limit the bandwidth for the applications categorized\ \ under the Application category. This tag is only applicable when\ \ an application_control is selected. Possible values: "Apply" and "Revoke". Default is "Revoke". | Optional | 
| web_filter | The Web Filter policy for the rule. Default is "Allow All". | Optional | 
| web_category_base_qos_policy | Whether to limit the bandwidth for the URLs categorized under the Web\ \ category. This tag is only applicable when any web_filter is defined." Possible values: "Apply" and "Revoke". Default is "Revoke". | Optional | 
| traffic_shaping_policy | The Traffic Shaping policy for the rule. Default is "None". | Optional | 
| scan_http | Whether to enable virus and spam scanning for HTTP protocol. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| scan_https | Whether to enable virus and spam scanning for HTTPS protocol. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| sandstorm | Whether to enable sandstorm analysis. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| block_quick_quic | Whether to enable Google websites to use HTTP/s instead of QUICK QUIC. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| scan_ftp | Whether to enable scanning of FTP traffic. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| data_accounting | Whether to exclude a user's network traffic from data accounting. This option is available only if the parameter "Match rule-based on user identity" is enabled. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| rewrite_source_address | Whether to enable the NAT policy. Possible values: "Enable" and "Disable". Default is "Enable". | Optional | 
| web_filter_internet_scheme | Whether to enable the internet scheme to apply the user-based Web Filter policy for the rule. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| application_control_internet_scheme | Whether to enable the internet scheme to apply user-based Application Filter Policy for the rule. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| override_gateway_default_nat_policy | Whether to override the gateway of the default NAT policy. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| source_security_heartbeat | Whether to enable the source security heartbeat. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| destination_security_heartbeat | Whether to enable the destination security heartbeat. Possible values: "Enable" and "Disable". Default is "Disable". | Optional | 
| outbound_address | The NAT policy to be applied. Default is "MASQ". | Optional | 
| minimum_source_hb_permitted | The minimum source health status permitted. Default is "No Restriction". | Optional | 
| minimum_destination_hb_permitted | The minimum destination health status permitted. Default is "No Restriction". | Optional | 
| intrusion_prevention | The IPS policy for the rule. Default is "generalpolicy". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicy.Name | String | Name of the rule. | 
| SophosFirewall.SecurityPolicy.Description | String | Description of the rule. | 
| SophosFirewall.SecurityPolicy.Status | String | Status of the rule. | 
| SophosFirewall.SecurityPolicy.PolicyType | String | Policy type of the rule. | 
| SophosFirewall.SecurityPolicy.IPFamily | String | IP family of the security policy. Either IPv4 or IPv6. | 
| SophosFirewall.SecurityPolicy.AttachIdentity | String | Rule attach identity status. | 
| SophosFirewall.SecurityPolicy.Action | String | Current rule action. | 
| SophosFirewall.SecurityPolicy.LogTraffic | Number | Rule traffic logging code. | 


#### Command Example
```!sophos-firewall-rule-update name=user_rule log_traffic=Enable source_zones=LAN```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicy": {
            "Action": "Drop",
            "After": {
                "Name": "1"
            },
            "Description": null,
            "DestinationZones": {
                "Zone": "LAN"
            },
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "LogTraffic": "Enable",
            "MatchIdentity": "Disable",
            "Name": "user_rule",
            "PolicyType": "Network",
            "Position": "After",
            "Schedule": "All The Time",
            "SourceZones": {
                "Zone": "LAN"
            },
            "Status": "Enable"
        }
    }
}
```

#### Human Readable Output

>### SecurityPolicy Object details
>|Name|Status|PolicyType|IPFamily|Action|LogTraffic|
>|---|---|---|---|---|---|
>| user_rule | Enable | Network | IPv4 | Drop | Enable |



### sophos-firewall-rule-delete
***
Deletes an existing firewall rule.


#### Base Command

`sophos-firewall-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicy.Name | String | Name of the rule. | 
| SophosFirewall.SecurityPolicy.IsDeleted | Bool | Whether the rule is deleted. | 


#### Command Example
```!sophos-firewall-rule-delete name=user_rule```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicy": {
            "IsDeleted": true,
            "Name": "user_rule"
        }
    }
}
```

#### Human Readable Output

>### Deleting SecurityPolicy Objects Results
>|Name|IsDeleted|
>|---|---|
>| user_rule | true |



### sophos-firewall-rule-group-list
***
Lists all firewall rule groups. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-rule-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicyGroup.Name | String | Name of the group. | 
| SophosFirewall.SecurityPolicyGroup.Description | String | Description of the group. | 
| SophosFirewall.SecurityPolicyGroup.SecurityPolicyList.SecurityPolicy | String | Rules contained inside the group. | 
| SophosFirewall.SecurityPolicyGroup.SourceZones.Zone | String | Source zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.DestinationZones.Zone | String | Destination zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.PolicyType | Number | Type of the rules in the group. | 


#### Command Example
```!sophos-firewall-rule-group-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicyGroup": [
            {
                "Description": "Inbound traffic to DMZ. Firewall rules with the destination zone as DMZ would be added to this group on the first match basis if user selects automatic grouping option. This is the default group.",
                "DestinationZones": {
                    "Zone": "DMZ"
                },
                "IsDeleted": false,
                "Name": "Traffic to DMZ",
                "Policytype": "Any",
                "SecurityPolicyList": {
                    "SecurityPolicy": "[example] Traffic to DMZ"
                }
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "hi",
                "Policytype": "Any"
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "forunitest",
                "Policytype": "Any"
            },
            {
                "Description": "Outbound traffic to WAN. Firewall rules with the destination zone as WAN would be added to this group on the first match basis if user selects automatic grouping option. This is the default group.",
                "DestinationZones": {
                    "Zone": "WAN"
                },
                "IsDeleted": false,
                "Name": "Traffic to WAN",
                "Policytype": "Any",
                "SecurityPolicyList": {
                    "SecurityPolicy": "[example] Traffic to WAN"
                }
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "unitest",
                "Policytype": "Any"
            },
            {
                "Description": "For testing only",
                "IsDeleted": false,
                "Name": "unitest2",
                "Policytype": "Any"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 SecurityPolicyGroup objects out of 8
>|Name|Description|SecurityPolicyList|DestinationZones|
>|---|---|---|---|
>| Traffic to DMZ | Inbound traffic to DMZ. Firewall rules with the destination zone as DMZ would be added to this group on the first match basis if user selects automatic grouping option. This is the default group. | SecurityPolicy: [example] Traffic to DMZ | Zone: DMZ |
>| hi |  |  |  |
>| forunitest |  |  |  |
>| Traffic to WAN | Outbound traffic to WAN. Firewall rules with the destination zone as WAN would be added to this group on the first match basis if user selects automatic grouping option. This is the default group. | SecurityPolicy: [example] Traffic to WAN | Zone: WAN |
>| unitest |  |  |  |
>| unitest2 | For testing only |  |  |



### sophos-firewall-rule-group-get
***
Gets a single firewall rule group by name.


#### Base Command

`sophos-firewall-rule-group-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall rule group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicyGroup.Name | String | Name of the group. | 
| SophosFirewall.SecurityPolicyGroup.Description | String | Description of the group. | 
| SophosFirewall.SecurityPolicyGroup.SecurityPolicyList.SecurityPolicy | String | Rules contained inside the group. | 
| SophosFirewall.SecurityPolicyGroup.SourceZones.Zone | String | Source zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.DestinationZones.Zone | String | Destination zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.PolicyType | Number | Type of the rules in the group. | 


#### Command Example
```!sophos-firewall-rule-group-get name=rulegroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicyGroup": {
            "Description": "rulegroup for user/network rules",
            "IsDeleted": false,
            "Name": "rulegroup",
            "Policytype": "User/network rule",
            "SecurityPolicyList": {
                "SecurityPolicy": [
                    "network_rule",
                    "user_rule"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### SecurityPolicyGroup Object details
>|Name|Description|SecurityPolicyList|
>|---|---|---|
>| rulegroup | rulegroup for user/network rules | SecurityPolicy: network_rule,<br/>user_rule |



### sophos-firewall-rule-group-add
***
Adds a new firewall rule group.


#### Base Command

`sophos-firewall-rule-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule group. | Required | 
| description | Description of the rule group. | Optional | 
| policy_type | Type of the rules (policies) inside the group. Possible values: "Any", "User/network rule", "User rule", "Business application rule". | Optional | 
| rules | Rules contained in the group. | Optional | 
| source_zones | Source zones contained in the group. Possible values: "Any", "LAN", "WAN", "VPN", "DMZ", "WiFi. | Optional | 
| destination_zones | Destination zones contained in the group. Possible values: "Any", "LAN", "WAN", "VPN", "DMZ", "WiFi. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicyGroup.Name | String | Name of the group. | 
| SophosFirewall.SecurityPolicyGroup.Description | String | Description of the group. | 
| SophosFirewall.SecurityPolicyGroup.SecurityPolicyList.SecurityPolicy | String | Rules contained in the group. | 
| SophosFirewall.SecurityPolicyGroup.SourceZones.Zone | String | Source zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.DestinationZones.Zone | String | Destination zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.PolicyType | Number | Type of the rules in the group. | 


#### Command Example
```!sophos-firewall-rule-group-add name=rulegroup policy_type="User/network rule" rules=user_rule,network_rule```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicyGroup": {
            "Description": null,
            "IsDeleted": false,
            "Name": "rulegroup",
            "Policytype": "User/network rule",
            "SecurityPolicyList": {
                "SecurityPolicy": [
                    "user_rule",
                    "network_rule"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### SecurityPolicyGroup Object details
>|Name|SecurityPolicyList|
>|---|---|
>| rulegroup | SecurityPolicy: user_rule,<br/>network_rule |



### sophos-firewall-rule-group-update
***
Updates an existing firewall rule group.


#### Base Command

`sophos-firewall-rule-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule group. | Required | 
| description | Description of the rule group. | Optional | 
| policy_type | Type of the rules (policies) inside the group. Possible values: "Any", "User/network rule", "User rule", "Business application rule". | Optional | 
| rules | Rules contained in the group. | Optional | 
| source_zones | Source zones contained in the group. Possible values: "Any", "LAN", "WAN", "VPN", "DMZ", "WiFi. | Optional | 
| destination_zones | Destination zones contained in the group. Possible values: "Any", "LAN", "WAN", "VPN", "DMZ", "WiFi. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicyGroup.Name | String | Name of the group. | 
| SophosFirewall.SecurityPolicyGroup.Description | String | Description of the group. | 
| SophosFirewall.SecurityPolicyGroup.SecurityPolicyList.SecurityPolicy | String | Rules contained in the group. | 
| SophosFirewall.SecurityPolicyGroup.SourceZones.Zone | String | Source zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.DestinationZones.Zone | String | Destination zone in the group. | 
| SophosFirewall.SecurityPolicyGroup.PolicyType | Number | Type of the rules in the group. | 


#### Command Example
```!sophos-firewall-rule-group-update name=rulegroup description="rulegroup for user/network rules"```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicyGroup": {
            "Description": "rulegroup for user/network rules",
            "IsDeleted": false,
            "Name": "rulegroup",
            "Policytype": "User/network rule",
            "SecurityPolicyList": {
                "SecurityPolicy": [
                    "network_rule",
                    "user_rule"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### SecurityPolicyGroup Object details
>|Name|Description|SecurityPolicyList|
>|---|---|---|
>| rulegroup | rulegroup for user/network rules | SecurityPolicy: network_rule,<br/>user_rule |


### sophos-firewall-rule-group-delete
***
Deletes an existing firewall group.


#### Base Command

`sophos-firewall-rule-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.SecurityPolicyGroup.Name | String | Name of the group. | 
| SophosFirewall.SecurityPolicyGroup.IsDeleted | Bool | Whether the group is deleted. | 


#### Command Example
```!sophos-firewall-rule-group-delete name=rulegroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "SecurityPolicyGroup": {
            "IsDeleted": true,
            "Name": "rulegroup"
        }
    }
}
```

#### Human Readable Output

>### Deleting SecurityPolicyGroup Objects Results
>|Name|IsDeleted|
>|---|---|
>| rulegroup | true |



### sophos-firewall-url-group-list
***
Lists all URL groups. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-url-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.Description | String | Description of the URL group. | 
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL in the group. | 


#### Command Example
```!sophos-firewall-url-group-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterURLGroup": [
            {
                "Description": "1desc",
                "IsDeleted": false,
                "Name": "1",
                "URLlist": {
                    "URL": [
                        "www.x.com",
                        "www.y.com"
                    ]
                }
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "2",
                "URLlist": {
                    "URL": "www.z.com"
                }
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "google",
                "URLlist": {
                    "URL": "www.google.com"
                }
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "urlgroup1",
                "URLlist": {
                    "URL": "www.blockthisurl.com"
                }
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "forunitest",
                "URLlist": {
                    "URL": "badwebsite.com"
                }
            },
            {
                "Description": null,
                "IsDeleted": false,
                "Name": "forunitest2",
                "URLlist": {
                    "URL": "badwebsite2.com"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 WebFilterURLGroup objects out of 12
>|Name|Description|URLlist|
>|---|---|---|
>| 1 | 1desc | URL: www.x.com,<br/>www.y.com |
>| 2 |  | URL: www.z.com |
>| google |  | URL: www.google.com |
>| urlgroup1 |  | URL: www.blockthisurl.com |
>| forunitest |  | URL: badwebsite.com |
>| forunitest2 |  | URL: badwebsite2.com |



### sophos-firewall-url-group-get
***
Gets a single URL group by name.


#### Base Command

`sophos-firewall-url-group-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.Description | String | Description of the URL group. | 
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL contained in the group. | 


#### Command Example
```!sophos-firewall-url-group-get name=urlgroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterURLGroup": {
            "Description": null,
            "IsDeleted": false,
            "Name": "urlgroup",
            "URLlist": {
                "URL": [
                    "www.example.com",
                    "www.another-example.com"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### WebFilterURLGroup Object details
>|Name|URLlist|
>|---|---|
>| urlgroup | URL: www.example.com,<br/>www.another-example.com |



### sophos-firewall-url-group-add
***
Adds a new URL group.


#### Base Command

`sophos-firewall-url-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group. | Required | 
| description | Description of the group. | Optional | 
| urls | URLs to add to the group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.Description | String | Description of the URL group. | 
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL contained in the group. | 


#### Command Example
```!sophos-firewall-url-group-add name=urlgroup urls=www.example.com```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterURLGroup": {
            "Description": null,
            "IsDeleted": false,
            "Name": "urlgroup",
            "URLlist": {
                "URL": [
                    "www.example.com"
                ]
            }
        }
    }
}
```


### sophos-firewall-url-group-update
***
Updates an existing URL group.


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
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.Description | String | Description of the URL group. | 
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL contained in the group. | 


#### Command Example
```!sophos-firewall-url-group-update name=urlgroup urls=www.another-example.com```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterURLGroup": {
            "Description": null,
            "IsDeleted": false,
            "Name": "urlgroup",
            "URLlist": {
                "URL": [
                    "www.example.com",
                    "www.another-example.com"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### WebFilterURLGroup Object details
>|Name|URLlist|
>|---|---|
>| urlgroup | URL: www.example.com,<br/>www.another-example.com |



### sophos-firewall-url-group-delete
***
Deletes an existing URL group or groups.


#### Base Command

`sophos-firewall-url-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.IsDeleted | Bool | Whether the URL group is deleted. | 


#### Command Example
```!sophos-firewall-url-group-delete name=urlgroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterURLGroup": {
            "IsDeleted": true,
            "Name": "urlgroup"
        }
    }
}
```

#### Human Readable Output

>### Deleting WebFilterURLGroup Objects Results
>|Name|IsDeleted|
>|---|---|
>| urlgroup | true |



### sophos-firewall-ip-host-list
***
Lists all IP hosts. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-ip-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 
| SophosFirewall.IPHost.HostType | String | Type of the host. | 


#### Command Example
```!sophos-firewall-ip-host-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHost": [
            {
                "HostType": "System Host",
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "Name": "##ALL_RW"
            },
            {
                "HostType": "System Host",
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "Name": "##ALL_IPSEC_RW"
            },
            {
                "HostType": "System Host",
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "Name": "##ALL_SSLVPN_RW"
            },
            {
                "HostType": "System Host",
                "IPFamily": "IPv6",
                "IsDeleted": false,
                "Name": "##ALL_RW6"
            },
            {
                "HostType": "System Host",
                "IPFamily": "IPv6",
                "IsDeleted": false,
                "Name": "##ALL_SSLVPN_RW6"
            },
            {
                "HostType": "System Host",
                "IPFamily": "IPv6",
                "IsDeleted": false,
                "Name": "##ALL_IPSEC_RW6"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 IPHost objects out of 13
>|Name|IPFamily|HostType|
>|---|---|---|
>| ##ALL_RW | IPv4 | System Host |
>| ##ALL_IPSEC_RW | IPv4 | System Host |
>| ##ALL_SSLVPN_RW | IPv4 | System Host |
>| ##ALL_RW6 | IPv6 | System Host |
>| ##ALL_SSLVPN_RW6 | IPv6 | System Host |
>| ##ALL_IPSEC_RW6 | IPv6 | System Host |


### sophos-firewall-ip-host-get
***
Gets a single IP host by name.


#### Base Command

`sophos-firewall-ip-host-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 
| SophosFirewall.IPHost.HostType | String | Type of the host. | 


#### Command Example
```!sophos-firewall-ip-host-get name=iphost```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHost": {
            "HostType": "IP",
            "IPAddress": "2.2.2.2",
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "Name": "iphost"
        }
    }
}
```

#### Human Readable Output

>### IPHost Object details
>|Name|IPFamily|HostType|
>|---|---|---|
>| iphost | IPv4 | IP |



### sophos-firewall-ip-host-add
***
Adds a new IP host.


#### Base Command

`sophos-firewall-ip-host-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host. | Required | 
| host_type | Type of the host. Possible values: "IP", "Network", "IPRange", "IPList". | Required | 
| ip_family | The IP family. Possible values: "IPv4" and "IPv6". Default is "IPv4". | Optional | 
| ip_address | IP address if IP or network was the chosen type. | Optional | 
| subnet_mask | Subnet mask if network was the chosen type. | Optional | 
| start_ip | Start of the IP range if IPRange was chosen. | Optional | 
| end_ip | End of the IP range if IPRange was chosen. | Optional | 
| ip_addresses | List of IP addresses if IPList was chosen. | Optional | 
| host_group | Select the host group to which the host belongs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 
| SophosFirewall.IPHost.HostType | String | Type of the host. | 


#### Command Example
```!sophos-firewall-ip-host-add name=iphost host_type=IP ip_address=1.1.1.1```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHost": {
            "HostType": "IP",
            "IPAddress": "1.1.1.1",
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "Name": "iphost"
        }
    }
}
```

#### Human Readable Output

>### IPHost Object details
>|Name|IPFamily|HostType|
>|---|---|---|
>| iphost | IPv4 | IP |



### sophos-firewall-ip-host-update
***
Updates an existing IP host.


#### Base Command

`sophos-firewall-ip-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host. | Required | 
| host_type | Type of the host. Possible values: "IP", "Network", "IPRange", "IPList". | Optional | 
| ip_family | The IP family. Possible values: "IPv4" and "IPv6". Default is "IPv4". | Optional | 
| ip_address | IP address if IP or network was the chosen type. | Optional | 
| subnet_mask | Subnet mask if network was the chosen type. | Optional | 
| start_ip | Start of the IP range if IPRange was chosen. | Optional | 
| end_ip | End of the IP range if IPRange was chosen. | Optional | 
| ip_addresses | List of IP addresses if IPList was chosen. | Optional | 
| host_group | Select the host group to which the host belongs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 
| SophosFirewall.IPHost.HostType | String | Type of the host. | 


#### Command Example
```!sophos-firewall-ip-host-update name=iphost ip_address=2.2.2.2```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHost": {
            "HostType": "IP",
            "IPAddress": "2.2.2.2",
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "Name": "iphost"
        }
    }
}
```

#### Human Readable Output

>### IPHost Object details
>|Name|IPFamily|HostType|
>|---|---|---|
>| iphost | IPv4 | IP |



### sophos-firewall-ip-host-delete
***
Deletes an existing IP host.


#### Base Command

`sophos-firewall-ip-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the host. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IsDeleted | Bool | Whether the IP host is deleted. | 


#### Command Example
```!sophos-firewall-ip-host-delete name=iphost```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHost": {
            "IsDeleted": true,
            "Name": "iphost"
        }
    }
}
```

#### Human Readable Output

>### Deleting IPHost Objects Results
>|Name|IsDeleted|
>|---|---|
>| iphost | true |


### sophos-firewall-ip-host-group-list
***
Lists all IP host groups. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-ip-host-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.HostList.Host | String | Host contained in the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 

#### Command Example
```!sophos-firewall-ip-host-group-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHostGroup": [
            {
                "Description": null,
                "HostList": {
                    "Host": [
                        "1.2.3.4",
                        "8.8.8.8"
                    ]
                },
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "Name": "Blocked by Playbook"
            },
            {
                "Description": "FOR TESTING",
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "Name": "unitest2"
            },
            {
                "Description": null,
                "IPFamily": "IPv4",
                "IsDeleted": false,
                "Name": "Noam-Test"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 3 IPHostGroup objects out of 3
>|Name|Description|IPFamily|HostList|
>|---|---|---|---|
>| Blocked by Playbook |  | IPv4 | Host: 1.2.3.4,<br/>8.8.8.8 |
>| unitest2 | FOR TESTING | IPv4 |  |
>| Noam-Test |  | IPv4 |  |


### sophos-firewall-ip-host-group-get
***
Gets a single IP host group by name.


#### Base Command

`sophos-firewall-ip-host-group-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.HostList.Host | String | Host contained inside the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 


#### Command Example
```!sophos-firewall-ip-host-group-get name=iphostgroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHostGroup": {
            "Description": null,
            "HostList": {
                "Host": "iphost"
            },
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "Name": "iphostgroup"
        }
    }
}
```

#### Human Readable Output

>### IPHostGroup Object details
>|Name|IPFamily|HostList|
>|---|---|---|
>| iphostgroup | IPv4 | Host: iphost |



### sophos-firewall-ip-host-group-add
***
Adds a new IP host group.


#### Base Command

`sophos-firewall-ip-host-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group. | Required | 
| description | Description of the IP host group. | Optional | 
| ip_family | The IP family. Possible values: "IPv4" and "IPv6". | Optional | 
| hosts | IP hosts contained in the group. Must be hosts already existing in the system. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.HostList.Host | String | Host contained in the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 


#### Command Example
```!sophos-firewall-ip-host-group-add name=iphostgroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHostGroup": {
            "Description": null,
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "Name": "iphostgroup"
        }
    }
}
```

#### Human Readable Output

>### IPHostGroup Object details
>|Name|IPFamily|
>|---|---|
>| iphostgroup | IPv4 |



### sophos-firewall-ip-host-group-update
***
Updates an existing IP host group.


#### Base Command

`sophos-firewall-ip-host-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group. | Required | 
| description | Description of the IP host group. | Optional | 
| ip_family | The IP family. Possible values: "IPv4" and "IPv6". | Optional | 
| hosts | IP hosts contained in the group. Must be hosts already existing in the system. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.HostList.Host | String | Host contained inside the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group. Either IPv4 or IPv6. | 


#### Command Example
```!sophos-firewall-ip-host-group-update name=iphostgroup hosts=iphost```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHostGroup": {
            "Description": null,
            "HostList": {
                "Host": "iphost"
            },
            "IPFamily": "IPv4",
            "IsDeleted": false,
            "Name": "iphostgroup"
        }
    }
}
```

#### Human Readable Output

>### IPHostGroup Object details
>|Name|IPFamily|HostList|
>|---|---|---|
>| iphostgroup | IPv4 | Host: iphost |



### sophos-firewall-ip-host-group-delete
***
Deletes an existing IP host group.


#### Base Command

`sophos-firewall-ip-host-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.IsDeleted | Bool | Whether the IP host group is deleted. | 


#### Command Example
```!sophos-firewall-ip-host-group-delete name=iphostgroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "IPHostGroup": {
            "IsDeleted": true,
            "Name": "iphostgroup"
        }
    }
}
```

#### Human Readable Output

>### Deleting IPHostGroup Objects Results
>|Name|IsDeleted|
>|---|---|
>| iphostgroup | true |



### sophos-firewall-services-list
***
Lists all firewall services. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-services-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.Services.Name | String | Name of the firewall service. | 
| SophosFirewall.Services.Type | String | Type of the firewall service. | 
| SophosFirewall.Services.ServiceDetails.ServiceDetail | String | Details about the service. | 


#### Command Example
```!sophos-firewall-services-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "Services": [
            {
                "IsDeleted": false,
                "Name": "AH",
                "ServiceDetails": {
                    "ServiceDetail": {
                        "ProtocolName": "AH"
                    }
                },
                "Type": "IP"
            },
            {
                "IsDeleted": false,
                "Name": "AOL",
                "ServiceDetails": {
                    "ServiceDetail": {
                        "DestinationPort": "5190:5194",
                        "Protocol": "TCP",
                        "SourcePort": "1:65535"
                    }
                },
                "Type": "TCPorUDP"
            },
            {
                "IsDeleted": false,
                "Name": "BGP",
                "ServiceDetails": {
                    "ServiceDetail": {
                        "DestinationPort": "179",
                        "Protocol": "TCP",
                        "SourcePort": "1:65535"
                    }
                },
                "Type": "TCPorUDP"
            },
            {
                "IsDeleted": false,
                "Name": "DHCP",
                "ServiceDetails": {
                    "ServiceDetail": {
                        "DestinationPort": "67:68",
                        "Protocol": "UDP",
                        "SourcePort": "67:68"
                    }
                },
                "Type": "TCPorUDP"
            },
            {
                "IsDeleted": false,
                "Name": "DNS",
                "ServiceDetails": {
                    "ServiceDetail": [
                        {
                            "DestinationPort": "53",
                            "Protocol": "TCP",
                            "SourcePort": "1:65535"
                        },
                        {
                            "DestinationPort": "53",
                            "Protocol": "UDP",
                            "SourcePort": "1:65535"
                        }
                    ]
                },
                "Type": "TCPorUDP"
            },
            {
                "IsDeleted": false,
                "Name": "ESP",
                "ServiceDetails": {
                    "ServiceDetail": {
                        "ProtocolName": "ESP"
                    }
                },
                "Type": "IP"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 Services objects out of 63
>|Name|Type|ServiceDetails|
>|---|---|---|
>| AH | IP | ServiceDetail: {"ProtocolName": "AH"} |
>| AOL | TCPorUDP | ServiceDetail: {"SourcePort": "1:65535", "DestinationPort": "5190:5194", "Protocol": "TCP"} |
>| BGP | TCPorUDP | ServiceDetail: {"SourcePort": "1:65535", "DestinationPort": "179", "Protocol": "TCP"} |
>| DHCP | TCPorUDP | ServiceDetail: {"SourcePort": "67:68", "DestinationPort": "67:68", "Protocol": "UDP"} |
>| DNS | TCPorUDP | ServiceDetail: {'SourcePort': '1:65535', 'DestinationPort': '53', 'Protocol': 'TCP'},<br/>{'SourcePort': '1:65535', 'DestinationPort': '53', 'Protocol': 'UDP'} |
>| ESP | IP | ServiceDetail: {"ProtocolName": "ESP"} |



### sophos-firewall-services-get
***
Gets a single service by name.


#### Base Command

`sophos-firewall-services-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.Services.Name | String | Name of the firewall service. | 
| SophosFirewall.Services.Type | String | Type of the firewall service. | 
| SophosFirewall.Services.ServiceDetails.ServiceDetail | String | Details about the service. | 



#### Command Example
```!sophos-firewall-services-get name=service```

#### Context Example
```json
{
    "SophosFirewall": {
        "Services": {
            "IsDeleted": false,
            "Name": "service",
            "ServiceDetails": {
                "ServiceDetail": [
                    {
                        "ProtocolName": "Compaq-Peer"
                    },
                    {
                        "ProtocolName": "AH"
                    }
                ]
            },
            "Type": "IP"
        }
    }
}
```

#### Human Readable Output

>### Services Object details
>|Name|Type|ServiceDetails|
>|---|---|---|
>| service | IP | ServiceDetail: {'ProtocolName': 'Compaq-Peer'},<br/>{'ProtocolName': 'AH'} |





### sophos-firewall-services-add
***
Adds a new firewall service.


#### Base Command

`sophos-firewall-services-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service. | Required | 
| service_type | Type of service. Possible values: "TCPorUDP", "IP", "ICMP", "ICMPv6". | Required | 
| protocol | The protocol for the service if service_type is TCPorUDP. Possible values: "TCP" and "UDP". | Optional | 
| source_port | Source port if service_type is TCPorUDP. | Optional | 
| destination_port | Destination port if service_type is TCPorUDP. | Optional | 
| protocol_name | Protocol name if service_type is IP. | Optional | 
| icmp_type | ICMP type if service_type is ICMP. | Optional | 
| icmp_code | ICMP code if service_type is ICMP. | Optional | 
| icmp_v6_type | ICMPv6 type if service_type is ICMPv6. | Optional | 
| icmp_v6_code | ICMPv6 code if service_type is ICMPv6. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.Services.Name | String | Name of the firewall service. | 
| SophosFirewall.Services.Type | String | Type of the firewall service. | 
| SophosFirewall.Services.ServiceDetails.ServiceDetail | String | Details about the service. | 


#### Command Example
```!sophos-firewall-services-add name=service service_type=IP protocol_name="Compaq-Peer"```

#### Context Example
```json
{
    "SophosFirewall": {
        "Services": {
            "IsDeleted": false,
            "Name": "service",
            "ServiceDetails": {
                "ServiceDetail": {
                    "ProtocolName": "Compaq-Peer"
                }
            },
            "Type": "IP"
        }
    }
}
```

#### Human Readable Output

>### Services Object details
>|Name|Type|ServiceDetails|
>|---|---|---|
>| service | IP | ServiceDetail: {"ProtocolName": "Compaq-Peer"} |



### sophos-firewall-services-update
***
Updates an existing firewall service.


#### Base Command

`sophos-firewall-services-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service. | Required | 
| service_type | Type of service. Possible values: "TCPorUDP", "IP", "ICMP", "ICMPv6". | Optional | 
| protocol | The protocol for the service if service_type is TCPorUDP. Possible values: "TCP" and "UDP". | Optional | 
| source_port | Source port if service_type is TCPorUDP. | Optional | 
| destination_port | Destination port if service_type is TCPorUDP. | Optional | 
| protocol_name | Protocol name if service_type is IP. | Optional | 
| icmp_type | ICMP type if service_type is ICMP. | Optional | 
| icmp_code | ICMP code if service_type is ICMP. | Optional | 
| icmp_v6_type | ICMPv6 type if service_type is ICMPv6. | Optional | 
| icmp_v6_code | ICMPv6 code if service_type is ICMPv6. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.Services.Name | String | Name of the firewall service. | 
| SophosFirewall.Services.Type | String | Type of the firewall service. | 
| SophosFirewall.Services.ServiceDetails.ServiceDetail | String | Details about the service. | 


#### Command Example
```!sophos-firewall-services-update name=service service_type=IP protocol_name=AH```

#### Context Example
```json
{
    "SophosFirewall": {
        "Services": {
            "IsDeleted": false,
            "Name": "service",
            "ServiceDetails": {
                "ServiceDetail": [
                    {
                        "ProtocolName": "Compaq-Peer"
                    },
                    {
                        "ProtocolName": "AH"
                    }
                ]
            },
            "Type": "IP"
        }
    }
}
```

#### Human Readable Output

>### Services Object details
>|Name|Type|ServiceDetails|
>|---|---|---|
>| service | IP | ServiceDetail: {'ProtocolName': 'Compaq-Peer'},<br/>{'ProtocolName': 'AH'} |




### sophos-firewall-services-delete
***
Deletes an existing firewall service.


#### Base Command

`sophos-firewall-services-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.Services.Name | String | Name of the firewall service. | 
| SophosFirewall.Services.IsDeleted | Bool | Whether the firewall service is deleted. | 


#### Command Example
```!sophos-firewall-services-delete name=service```

#### Context Example
```json
{
    "SophosFirewall": {
        "Services": {
            "IsDeleted": true,
            "Name": "service"
        }
    }
}
```

#### Human Readable Output

>### Deleting Services Objects Results
>|Name|IsDeleted|
>|---|---|
>| service | true |



### sophos-firewall-user-list
***
Lists all users. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.User.Name | String | Name of the user. | 
| SophosFirewall.User.Username | String | Username of the user. | 
| SophosFirewall.User.Description | String | Description of the user. | 
| SophosFirewall.User.EmailList.EmailID | String | Email of the user. | 
| SophosFirewall.User.Group | String | Group of the user. | 
| SophosFirewall.User.UserType | String | User type of the user. | 
| SophosFirewall.User.Status | String | Status of the user. | 


#### Command Example
```!sophos-firewall-user-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "User": [
            {
                "AccessTimePolicy": "Allowed all the time",
                "CISCO": "Disable",
                "ClientlessPolicy": "No Policy Applied",
                "DataTransferPolicy": "100 MB Total Data Transfer policy",
                "Description": null,
                "EmailList": {
                    "EmailID": "test@test.com"
                },
                "Group": "Open Group",
                "IsDeleted": false,
                "IsEncryptCert": "Disable",
                "L2TP": "Disable",
                "LoginRestriction": "UserGroupNode",
                "LoginRestrictionForAppliance": null,
                "MACBinding": "Disable",
                "Name": "user_new",
                "PPTP": "Disable",
                "Password": {
                    "#text": "0488F379742662C337D2FB1BDD1F08D9",
                    "@passwordform": "encrypt"
                },
                "QoSPolicy": "High Guarantee User",
                "QuarantineDigest": "Disable",
                "SSLVPNPolicy": "sg",
                "ScheduleForApplianceAccess": "All The Time",
                "SimultaneousLoginsGlobal": "Enable",
                "Status": "Active",
                "SurfingQuotaPolicy": "Unlimited Internet Access",
                "UserType": "User",
                "Username": "user new"
            },
            {
                "AccessTimePolicy": "Allowed all the time",
                "CISCO": "Disable",
                "ClientlessPolicy": "No Policy Applied",
                "DataTransferPolicy": "100 MB Total Data Transfer policy",
                "Description": "new desc",
                "EmailList": {
                    "EmailID": "test@test.com"
                },
                "Group": "Guest Group",
                "IsDeleted": false,
                "IsEncryptCert": "Disable",
                "L2TP": "Disable",
                "LoginRestriction": "UserGroupNode",
                "LoginRestrictionForAppliance": null,
                "MACBinding": "0",
                "Name": "sg",
                "PPTP": "Disable",
                "Password": {
                    "#text": "ECA5ABF3D68822A1C3C9193F8AAE1522",
                    "@passwordform": "encrypt"
                },
                "Profile": "Administrator",
                "QoSPolicy": "High Guarantee User",
                "QuarantineDigest": "0",
                "SSLVPNPolicy": "No Policy Applied",
                "ScheduleForApplianceAccess": "All The Time",
                "SimultaneousLoginsGlobal": "Enable",
                "Status": "Active",
                "SurfingQuotaPolicy": "Unlimited Internet Access",
                "UserType": "User",
                "Username": "sg1"
            },
            {
                "AccessTimePolicy": "Allowed all the time",
                "CISCO": "Disable",
                "ClientlessPolicy": "No Policy Applied",
                "DataTransferPolicy": "100 MB Total Data Transfer policy",
                "Description": "1",
                "Group": "Guest Group",
                "IsDeleted": false,
                "IsEncryptCert": "Disable",
                "L2TP": "Disable",
                "LoginRestriction": "UserGroupNode",
                "LoginRestrictionForAppliance": null,
                "MACBinding": "0",
                "Name": "1",
                "PPTP": "Disable",
                "Password": {
                    "#text": "A8DFE8F6454F585D404E04435416C95E",
                    "@passwordform": "encrypt"
                },
                "QoSPolicy": "High Guarantee User",
                "QuarantineDigest": "0",
                "SSLVPNPolicy": "No Policy Applied",
                "ScheduleForApplianceAccess": "All The Time",
                "SimultaneousLoginsGlobal": "Enable",
                "Status": "Active",
                "SurfingQuotaPolicy": "Unlimited Internet Access",
                "UserType": "User",
                "Username": "1"
            },
            {
                "AccessTimePolicy": "Allowed all the time",
                "CISCO": "Disable",
                "ClientlessPolicy": "No Policy Applied",
                "DataTransferPolicy": "100 MB Total Data Transfer policy",
                "Description": null,
                "EmailList": {
                    "EmailID": "test@test.test"
                },
                "Group": "Guest Group",
                "IsDeleted": false,
                "IsEncryptCert": "Disable",
                "L2TP": "Disable",
                "LoginRestriction": "UserGroupNode",
                "LoginRestrictionForAppliance": null,
                "MACBinding": "0",
                "Name": "unitest2",
                "PPTP": "Disable",
                "Password": {
                    "#text": "F5A7EFCF49F10328D7198A1968618B38",
                    "@passwordform": "encrypt"
                },
                "QoSPolicy": "High Guarantee User",
                "QuarantineDigest": "Disable",
                "SSLVPNPolicy": "No Policy Applied",
                "ScheduleForApplianceAccess": "All The Time",
                "SimultaneousLoginsGlobal": "Enable",
                "Status": "Active",
                "SurfingQuotaPolicy": "Unlimited Internet Access",
                "UserType": "User",
                "Username": "unitestuser"
            },
            {
                "AccessTimePolicy": "Allowed all the time",
                "CISCO": "Disable",
                "ClientlessPolicy": "No Policy Applied",
                "DataTransferPolicy": "100 MB Total Data Transfer policy",
                "Description": null,
                "EmailList": {
                    "EmailID": "test@test.test"
                },
                "Group": "Guest Group",
                "IsDeleted": false,
                "IsEncryptCert": "Disable",
                "L2TP": "Disable",
                "LoginRestriction": "UserGroupNode",
                "LoginRestrictionForAppliance": null,
                "MACBinding": "0",
                "Name": "unitest3",
                "PPTP": "Disable",
                "Password": {
                    "#text": "F5A7EFCF49F10328D7198A1968618B38",
                    "@passwordform": "encrypt"
                },
                "QoSPolicy": "High Guarantee User",
                "QuarantineDigest": "Disable",
                "SSLVPNPolicy": "No Policy Applied",
                "ScheduleForApplianceAccess": "All The Time",
                "SimultaneousLoginsGlobal": "Enable",
                "Status": "Active",
                "SurfingQuotaPolicy": "Unlimited Internet Access",
                "UserType": "User",
                "Username": "unitestuser2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 User objects out of 8
>|Username|Name|Description|EmailList|Group|UserType|Status|
>|---|---|---|---|---|---|---|
>| user new | user_new |  | EmailID: test@test.com | Open Group | User | Active |
>| sg | sg | This is sg desc | EmailID: test@test.com | Guest Group | Administrator | Active |
>| 1 | 1 | 1 |  | Guest Group | User | Active |
>| sg1 | sg | new desc |  | Guest Group | User | Active |
>| unitestuser | unitest2 |  | EmailID: test@test.test | Guest Group | User | Active |
>| unitestuser2 | unitest3 |  | EmailID: test@test.test | Guest Group | User | Active |



### sophos-firewall-user-get
***
Gets a single user by name.


#### Base Command

`sophos-firewall-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.User.Name | String | Name of the user. | 
| SophosFirewall.User.Username | String | Username of the user. | 
| SophosFirewall.User.Description | String | Description of the user. | 
| SophosFirewall.User.EmailList.EmailID | String | Email of the user. | 
| SophosFirewall.User.Group | String | Group of the user. | 
| SophosFirewall.User.UserType | String | User type of the user. | 
| SophosFirewall.User.Status | String | Status of the user. | 


#### Command Example
```!sophos-firewall-user-get name=user```

#### Context Example
```json
{
    "SophosFirewall": {
        "User": {
            "AccessTimePolicy": "Allowed all the time",
            "CISCO": "Disable",
            "ClientlessPolicy": "No Policy Applied",
            "DataTransferPolicy": "100 MB Total Data Transfer policy",
            "Description": "Description for the user",
            "Group": "Guest Group",
            "IsDeleted": false,
            "IsEncryptCert": "Disable",
            "L2TP": "Disable",
            "LoginRestriction": "UserGroupNode",
            "LoginRestrictionForAppliance": null,
            "MACBinding": "0",
            "Name": "user",
            "PPTP": "Disable",
            "Password": {
                "#text": "A8DFE8F6454F585D404E04435416C95E",
                "@passwordform": "encrypt"
            },
            "QoSPolicy": "High Guarantee User",
            "QuarantineDigest": "0",
            "SSLVPNPolicy": "No Policy Applied",
            "ScheduleForApplianceAccess": "All The Time",
            "SimultaneousLoginsGlobal": "Enable",
            "Status": "Active",
            "SurfingQuotaPolicy": "Unlimited Internet Access",
            "UserType": "User",
            "Username": "user"
        }
    }
}
```

#### Human Readable Output

>### User Object details
>|Username|Name|Description|Group|UserType|Status|
>|---|---|---|---|---|---|
>| user | user | Description for the user | Guest Group | User | Active |



### sophos-firewall-user-add
***
Adds a new user.


#### Base Command

`sophos-firewall-user-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username of the user. | Required | 
| name | Name of the user. | Required | 
| description | Description of the user. | Optional | 
| email | Email of the user. | Required | 
| group | Group of the user. Default is "Guest Group". | Optional | 
| password | The password of the user. | Required | 
| user_type | The type of the user. Possible values: "Administrator" and "User". Default is "User". | Optional | 
| profile | Profile of the administrator if user_type is Administrator. Possible values: "Administrator", "Crypto Admin", "Security Admin", "Audit Admin", "HAProfile". IMPORTANT: You can add more types in the web console. | Optional | 
| surfing_quota_policy | The Surfing Quota policy. Default is "Unlimited Internet Access". | Optional | 
| access_time_policy | The Access Time policy. Default is "Allowed all the time". | Optional | 
| ssl_vpn_policy | The SSL VPN policy. Default is "No Policy Applied". | Optional | 
| clientless_policy | The clientless policy. Default is "No Policy Applied". | Optional | 
| data_transfer_policy | The Data Transfer policy. Default is: "100 MB Total Data Transfer policy". | Optional | 
| simultaneous_logins_global | Whether to enable simultaneous logins global. Possible values: "Enable" and "Disable". Default is "Eanble". | Optional | 
| schedule_for_appliance_access | The schedule for appliance access. Default is "All The Time". IMPORTANT: This option\ \ is available only for Administrators. | Optional | 
| qos_policy | The QoS policy. Default is "High Guarantee User". | Optional | 
| login_restriction | The login restriction option. Possible values: "AnyNode" and "UserGroupNode". Default is "UserGroupNode". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.User.Name | String | Name of the user. | 
| SophosFirewall.User.Username | String | Username of the user. | 
| SophosFirewall.User.Description | String | Description of the user. | 
| SophosFirewall.User.EmailList.EmailID | String | Email of the user. | 
| SophosFirewall.User.Group | String | Group of the user. | 
| SophosFirewall.User.UserType | String | User type of the user. | 
| SophosFirewall.User.Status | String | Status of the user. | 


#### Command Example
```!sophos-firewall-user-add name=user username=user password=1234 email=user@mail.com```

#### Context Example
```json
{
    "SophosFirewall": {
        "User": {
            "AccessTimePolicy": "Allowed all the time",
            "CISCO": "Disable",
            "ClientlessPolicy": "No Policy Applied",
            "DataTransferPolicy": "100 MB Total Data Transfer policy",
            "Description": null,
            "EmailList": {
                "EmailID": "user@mail.com"
            },
            "Group": "Guest Group",
            "IsDeleted": false,
            "IsEncryptCert": "Disable",
            "L2TP": "Disable",
            "LoginRestriction": "UserGroupNode",
            "LoginRestrictionForAppliance": null,
            "MACBinding": "0",
            "Name": "user",
            "PPTP": "Disable",
            "Password": {
                "#text": "A8DFE8F6454F585D404E04435416C95E",
                "@passwordform": "encrypt"
            },
            "QoSPolicy": "High Guarantee User",
            "QuarantineDigest": "Disable",
            "SSLVPNPolicy": "No Policy Applied",
            "ScheduleForApplianceAccess": "All The Time",
            "SimultaneousLoginsGlobal": "Enable",
            "Status": "Active",
            "SurfingQuotaPolicy": "Unlimited Internet Access",
            "UserType": "User",
            "Username": "user"
        }
    }
}
```

#### Human Readable Output

>### User Object details
>|Username|Name|EmailList|Group|UserType|Status|
>|---|---|---|---|---|---|
>| user | user | EmailID: user@mail.com | Guest Group | User | Active |



### sophos-firewall-user-update
***
Updates a user.


#### Base Command

`sophos-firewall-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username of the user. | Required | 
| name | Name of the user. | Required | 
| description | Description of the user. | Optional | 
| email | Email of the user. | Optional | 
| group | Group of the user. Default is "Guest Group". | Optional | 
| password | The password of the user. | Optional | 
| user_type | The type of the user. Possible values: "Administrator" and "User". Default is "User". | Optional | 
| profile | Profile of the administrator if user_type is Administrator. Possible values: "Administrator", "Crypto Admin", "Security Admin", "Audit Admin", "HAProfile". IMPORTANT: You can add more types in the web console. | Optional | 
| surfing_quota_policy | The Surfing Quota policy. Default is "Unlimited Internet Access". | Optional | 
| access_time_policy | The Access Time policy. Default is "Allowed all the time". | Optional | 
| ssl_vpn_policy | The SSL VPN policy. Default is "No Policy Applied". | Optional | 
| clientless_policy | The clientless policy. Default is "No Policy Applied". | Optional | 
| data_transfer_policy | The Data Transfer policy. Default is: "100 MB Total Data Transfer policy". | Optional | 
| simultaneous_logins_global | Whether to enable simultaneous logins global. Possible values: "Enable" and "Disable". Default is "Eanble". | Optional | 
| schedule_for_appliance_access | The schedule for appliance access. Default is "All The Time".IMPORTANT: This option\ \ is available only for Administrators. | Optional | 
| qos_policy | The QoS policy. Default is "High Guarantee User". | Optional | 
| login_restriction | The login restriction option. Possible values: "AnyNode" and "UserGroupNode". Default is "UserGroupNode". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.User.Name | String | Name of the user. | 
| SophosFirewall.User.Username | String | Username of the user. | 
| SophosFirewall.User.Description | String | Description of the user. | 
| SophosFirewall.User.EmailList.EmailID | String | Email of the user. | 
| SophosFirewall.User.Group | String | Group of the user. | 
| SophosFirewall.User.UserType | String | User type of the user. | 
| SophosFirewall.User.Status | String | Status of the user. | 


#### Command Example
```!sophos-firewall-user-update name=user username=user description="Description for the user"```

#### Context Example
```json
{
    "SophosFirewall": {
        "User": {
            "AccessTimePolicy": "Allowed all the time",
            "CISCO": "Disable",
            "ClientlessPolicy": "No Policy Applied",
            "DataTransferPolicy": "100 MB Total Data Transfer policy",
            "Description": "Description for the user",
            "Group": "Guest Group",
            "IsDeleted": false,
            "IsEncryptCert": "Disable",
            "L2TP": "Disable",
            "LoginRestriction": "UserGroupNode",
            "LoginRestrictionForAppliance": null,
            "MACBinding": "0",
            "Name": "user",
            "PPTP": "Disable",
            "Password": {
                "#text": "A8DFE8F6454F585D404E04435416C95E",
                "@passwordform": "encrypt"
            },
            "QoSPolicy": "High Guarantee User",
            "QuarantineDigest": "0",
            "SSLVPNPolicy": "No Policy Applied",
            "ScheduleForApplianceAccess": "All The Time",
            "SimultaneousLoginsGlobal": "Enable",
            "Status": "Active",
            "SurfingQuotaPolicy": "Unlimited Internet Access",
            "UserType": "User",
            "Username": "user"
        }
    }
}
```

#### Human Readable Output

>### User Object details
>|Username|Name|Description|Group|UserType|Status|
>|---|---|---|---|---|---|
>| user | user | Description for the user | Guest Group | User | Active |



### sophos-firewall-user-delete
***
Deletes an existing user.


#### Base Command

`sophos-firewall-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.User.Name | String | Name of the user. | 
| SophosFirewall.User.IsDeleted | Bool | Whether the user is deleted. | 


#### Command Example
```!sophos-firewall-user-delete name=user```

#### Context Example
```json
{
    "SophosFirewall": {
        "User": {
            "IsDeleted": true,
            "Name": "user"
        }
    }
}
```

#### Human Readable Output

>### Deleting User Objects Results
>|Name|IsDeleted|
>|---|---|
>| user | true |



### sophos-firewall-app-policy-list
***
Lists all app policies. IMPORTANT: Listing starst at 0 (not 1)!


#### Base Command

`sophos-firewall-app-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Whether the policy support microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Details of the rule. | 



#### Command Example
```!sophos-firewall-app-policy-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterPolicy": [
            {
                "DefaultAction": "Allow",
                "Description": "Allow All Policy.",
                "IsDeleted": false,
                "MicroAppSupport": "True",
                "Name": "Allow All"
            },
            {
                "DefaultAction": "Allow",
                "Description": "Drops traffic from applications that tunnels other apps, proxy and tunnel apps, and from apps that can bypass firewall policy. These applications allow users to anonymously browse Internet by connecting to servers on the Internet via encrypted SSL tunnels. This, in turn, enables users to bypass network security measures.",
                "IsDeleted": false,
                "MicroAppSupport": "True",
                "Name": "Block filter avoidance apps",
                "RuleList": {
                    "Rule": [
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "test"
                                ]
                            },
                            "CategoryList": {
                                "Category": "Proxy and Tunnel"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "test"
                                ]
                            },
                            "CharacteristicsList": {
                                "Characteristics": "Can bypass firewall policy"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "test"
                                ]
                            },
                            "CharacteristicsList": {
                                "Characteristics": "Tunnels other apps"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        }
                    ]
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 ApplicationFilterPolicy objects out of 12
>|Name|Description|MicroAppSupport|DefaultAction|RuleList|
>|---|---|---|---|---|
>| Allow All | Allow All Policy. | True | Allow |  |
>| Block filter avoidance apps | Drops traffic from applications that tunnels other apps, proxy and tunnel apps, and from apps that can bypass firewall policy. These applications allow users to anonymously browse Internet by connecting to servers on the Internet via encrypted SSL tunnels. This, in turn, enables users to bypass network security measures. | True | Allow | Rule: {'SelectAllRule': 'Enable', 'CategoryList': {'Category': 'Proxy and Tunnel'}, 'SmartFilter': None, 'ApplicationList': {'Application': 'test'}, 'Action': 'Deny', 'Schedule': 'All The Time'} |
>| Block generally unwanted apps | Drops generally unwanted applications traffic. This includes file transfer apps, proxy & tunnel apps, risk prone apps, peer to peer networking (P2P) apps and apps that causes loss of productivity. | True | Allow | Rule: {'SelectAllRule': 'Enable', 'CategoryList': {'Category': 'P2P'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['test']}, 'Action': 'Deny', 'Schedule': 'All The Time'} |
>| Block high risk (Risk Level 4 and 5) apps | Drops traffic that are classified under high risk apps (Risk Level- 4 and 5). | True | Allow | Rule: {'SelectAllRule': 'Enable', 'RiskList': {'Risk': 'High'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['test']}, 'Action': 'Deny', 'Schedule': 'All The Time'} |
>| Block peer to peer (P2P) networking apps | Drops traffic from applications that are categorized as P2P apps. P2P could be a mechanism for distributing Bots, Spywares, Adware, Trojans, Rootkits, Worms and other types of malwares. It is generally advised to have P2P application blocked in your network. | True | Allow | Rule: {"SelectAllRule": "Enable", "CategoryList": {"Category": "P2P"}, "SmartFilter": null, "ApplicationList": {"Application": ["test"]}, "Action": "Deny", "Schedule": "All The Time"} |
>| Block very high risk (Risk Level 5) apps | Drops traffic that are classified under very high risk apps (Risk Level- 5). | True | Allow | Rule: {"SelectAllRule": "Enable", "RiskList": {"Risk": "Very High"}, "SmartFilter": null, "ApplicationList": {"Application": ["test]}, "Action": "Deny", "Schedule": "All The Time"} |





### sophos-firewall-app-policy-get
***
Gets a single app policy by name.


#### Base Command

`sophos-firewall-app-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Does the policy support microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Details of the rule. | 


#### Command Example
```!sophos-firewall-app-policy-get name=apppolicy```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterPolicy": {
            "DefaultAction": "Allow",
            "Description": "Description for app policy object",
            "IsDeleted": false,
            "MicroAppSupport": "True",
            "Name": "apppolicy"
        }
    }
}
```

#### Human Readable Output

>### ApplicationFilterPolicy Object details
>|Name|Description|MicroAppSupport|DefaultAction|
>|---|---|---|---|
>| apppolicy | Description for app policy object | True | Allow |



### sophos-firewall-app-policy-add
***
Adds a new app policy.


#### Base Command

`sophos-firewall-app-policy-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| micro_app_support | Whether microapp support is enabled. Possible values: "true" and "false". | Optional | 
| default_action | Default action for the policy. Possible values: "Allow" and "Deny". | Optional | 
| select_all | Whether to enable the select all rule. Possible values: "Enable" and "Disable". | Optional | 
| categories | Categories to add to the rule. | Optional | 
| risks | Risks to add to the rule. | Optional | 
| applications | Applications to add to the rule. | Optional | 
| characteristics | Characteristics to add to the rule. | Optional | 
| technologies | Technologies to add to the rule. | Optional | 
| classifications | Classifications to add to the rule. | Optional | 
| action | Action for the rule. Possible values: "Allow" and "Deny". | Optional | 
| schedule | The schedule for the rule. Possible values: "All the time", "Work hours (5 Day week)", "Work hours (6 Day week)", "All Time on Weekdays", "All Time on Weekends", "All Time on Sunday", "All Days 10:00 to 19:00". IMPORTANT: Creating a new schedule is available in the web console. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Whether the policy supports microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Details of the rule. | 


#### Command Example
```!sophos-firewall-app-policy-add name=apppolicy```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterPolicy": {
            "DefaultAction": "Allow",
            "Description": null,
            "IsDeleted": false,
            "MicroAppSupport": "True",
            "Name": "apppolicy"
        }
    }
}
```

#### Human Readable Output

>### ApplicationFilterPolicy Object details
>|Name|MicroAppSupport|DefaultAction|
>|---|---|---|
>| apppolicy | True | Allow |



### sophos-firewall-app-policy-update
***
Updates an existing app policy.


#### Base Command

`sophos-firewall-app-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| micro_app_support | Whether microapp support is enabled. Possible values: "true" and "false". | Optional | 
| default_action | Default action for the policy. Possible values: "Allow" and "Deny". | Optional | 
| select_all | Whether to enable the select all rule. Possible values: "Enable" and "Disable". | Optional | 
| categories | Categories to add to the rule. | Optional | 
| risks | Risks to add to the rule. | Optional | 
| applications | Applications to add to the rule. | Optional | 
| characteristics | Characteristics to add to the rule. | Optional | 
| technologies | Technologies to add to the rule. | Optional | 
| classifications | Classifications to add to the rule. | Optional | 
| action | Action for the rule. Possible values: "Allow" and "Deny". | Optional | 
| schedule | The schedule for the rule. Possible values: "All the time", "Work hours (5 Day week)", "Work hours (6 Day week)", "All Time on Weekdays", "All Time on Weekends", "All Time on Sunday", "All Days 10:00 to 19:00". IMPORTANT: Creating a new schedule is available in the web console. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Whether the policy supports microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Details of the rule. | 


#### Command Example
```!sophos-firewall-app-policy-update name=apppolicy description="Description for app policy object"```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterPolicy": {
            "DefaultAction": "Allow",
            "Description": "Description for app policy object",
            "IsDeleted": false,
            "MicroAppSupport": "True",
            "Name": "apppolicy"
        }
    }
}
```

#### Human Readable Output

>### ApplicationFilterPolicy Object details
>|Name|Description|MicroAppSupport|DefaultAction|
>|---|---|---|---|
>| apppolicy | Description for app policy object | True | Allow |



### sophos-firewall-app-policy-delete
***
Deletes an existing app policy.


#### Base Command

`sophos-firewall-app-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.IsDeleted | Bool | Whether the firewall app policy is deleted. | 


#### Command Example
```!sophos-firewall-app-policy-delete name=apppolicy```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterPolicy": {
            "IsDeleted": true,
            "Name": "apppolicy"
        }
    }
}
```

#### Human Readable Output

>### Deleting ApplicationFilterPolicy Objects Results
>|Name|IsDeleted|
>|---|---|
>| apppolicy | true |



### sophos-firewall-app-category-list
***
Lists all app filter categories. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-app-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterCategory.Name | String | Name of the app category. | 
| SophosFirewall.ApplicationFilterCategory.Description | String | Description of the app category. | 
| SophosFirewall.ApplicationFilterCategory.QoSPolicy | String | QoS policy of the category. | 
| SophosFirewall.ApplicationFilterCategory.BandwidthUsageType | String | Bandwidth usage type of the category. | 



#### Command Example
```!sophos-firewall-app-category-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterCategory": [
            {
                "BandwidthUsageType": null,
                "Description": "Conferencing",
                "IsDeleted": false,
                "Name": "Conferencing",
                "QoSPolicy": "None"
            },
            {
                "BandwidthUsageType": null,
                "Description": "Desktop Mail",
                "IsDeleted": false,
                "Name": "Desktop Mail",
                "QoSPolicy": "None"
            },
            {
                "BandwidthUsageType": null,
                "Description": "Database Applications",
                "IsDeleted": false,
                "Name": "Download Applications",
                "QoSPolicy": "None"
            },
            {
                "BandwidthUsageType": null,
                "Description": "E-commerce",
                "IsDeleted": false,
                "Name": "E-commerce",
                "QoSPolicy": "None"
            },
            {
                "BandwidthUsageType": null,
                "Description": "File Transfer",
                "IsDeleted": false,
                "Name": "File Transfer",
                "QoSPolicy": "None"
            },
            {
                "BandwidthUsageType": "Individual",
                "Description": "Gaming Sites and Applications",
                "IsDeleted": false,
                "Name": "Gaming",
                "QoSPolicy": "policy"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 ApplicationFilterCategory objects out of 25
>|Name|Description|QoSPolicy|BandwidthUsageType|
>|---|---|---|---|
>| Conferencing | Conferencing | None |  |
>| Desktop Mail | Desktop Mail | None |  |
>| Download Applications | Database Applications | None |  |
>| E-commerce | E-commerce | None |  |
>| File Transfer | File Transfer | None |  |
>| Gaming | Gaming Sites and Applications | policy | Individual |


### sophos-firewall-app-category-get
***
Gets a single app filter category by name.


#### Base Command

`sophos-firewall-app-category-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the app category. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterCategory.Name | String | Name of the app category. | 
| SophosFirewall.ApplicationFilterCategory.Description | String | Description of the app category. | 
| SophosFirewall.ApplicationFilterCategory.QoSPolicy | String | QoS policy of the category. | 
| SophosFirewall.ApplicationFilterCategory.BandwidthUsageType | String | Bandwidth usage type of the category. | 


#### Command Example
```!sophos-firewall-app-category-get name=Gaming```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterCategory": {
            "BandwidthUsageType": "Individual",
            "Description": "Gaming Sites and Applications",
            "IsDeleted": false,
            "Name": "Gaming",
            "QoSPolicy": "policy"
        }
    }
}
```

#### Human Readable Output

>### ApplicationFilterCategory Object details
>|Name|Description|QoSPolicy|BandwidthUsageType|
>|---|---|---|---|
>| Gaming | Gaming Sites and Applications | policy | Individual |



### sophos-firewall-app-category-update
***
Updates an existing app filter category.


#### Base Command

`sophos-firewall-app-category-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the app category. | Required | 
| description | The description of the category. | Optional | 
| qos_policy | QoS policy of the category. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterCategory.Name | String | Name of the app category. | 
| SophosFirewall.ApplicationFilterCategory.Description | String | Description of the app category. | 
| SophosFirewall.ApplicationFilterCategory.QoSPolicy | String | QoS policy of the category. | 
| SophosFirewall.ApplicationFilterCategory.BandwidthUsageType | String | Bandwidth usage type of the category. | 


#### Command Example
```!sophos-firewall-app-category-update name=Gaming qos_policy=policy```

#### Context Example
```json
{
    "SophosFirewall": {
        "ApplicationFilterCategory": {
            "BandwidthUsageType": "Individual",
            "Description": "Gaming Sites and Applications",
            "IsDeleted": false,
            "Name": "Gaming",
            "QoSPolicy": "policy"
        }
    }
}
```

#### Human Readable Output

>### ApplicationFilterCategory Object details
>|Name|Description|QoSPolicy|BandwidthUsageType|
>|---|---|---|---|
>| Gaming | Gaming Sites and Applications | policy | Individual |



### sophos-firewall-web-filter-list
***
Lists all web filter policies. IMPORTANT: Listing starts at 0 (not 1)!


#### Base Command

`sophos-firewall-web-filter-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | The start index for the rules to list, e.g: 5. Default is "0". | Optional | 
| end | The end index for the rules to list, e.g: 20. Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Whether the policy reports events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Whether the file size restriction is active. | 
| SophosFirewall.WebFilterPolicy.RuleList.Rule | String | Rule list information. | 


#### Command Example
```!sophos-firewall-web-filter-list start=0 end=6```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterPolicy": [
            {
                "DefaultAction": "Allow",
                "Description": "Deny access to web mail and online chat sites",
                "DownloadFileSizeRestriction": "0",
                "DownloadFileSizeRestrictionEnabled": "0",
                "EnableReporting": "Enable",
                "EnforceImageLicensing": "0",
                "EnforceSafeSearch": "0",
                "GoogAppDomainList": null,
                "GoogAppDomainListEnabled": "0",
                "IsDeleted": false,
                "Name": "No Web Mail or Chat",
                "RuleList": {
                    "Rule": [
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Web E-Mail",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Online Chat",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        }
                    ]
                },
                "YoutubeFilterEnabled": "0",
                "YoutubeFilterIsStrict": "0"
            },
            {
                "DefaultAction": "Allow",
                "Description": "Deny access to web mail sites",
                "DownloadFileSizeRestriction": "0",
                "DownloadFileSizeRestrictionEnabled": "0",
                "EnableReporting": "Enable",
                "EnforceImageLicensing": "0",
                "EnforceSafeSearch": "0",
                "GoogAppDomainList": null,
                "GoogAppDomainListEnabled": "0",
                "IsDeleted": false,
                "Name": "No Web Mail",
                "RuleList": {
                    "Rule": {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "Web E-Mail",
                                "type": "WebCategory"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "1",
                        "HTTPAction": "Deny",
                        "HTTPSAction": "Deny",
                        "PolicyRuleEnabled": "1",
                        "Schedule": "All The Time"
                    }
                },
                "YoutubeFilterEnabled": "0",
                "YoutubeFilterIsStrict": "0"
            },
            {
                "DefaultAction": "Allow",
                "Description": "Deny access to online chat sites",
                "DownloadFileSizeRestriction": "0",
                "DownloadFileSizeRestrictionEnabled": "0",
                "EnableReporting": "Enable",
                "EnforceImageLicensing": "0",
                "EnforceSafeSearch": "0",
                "GoogAppDomainList": null,
                "GoogAppDomainListEnabled": "0",
                "IsDeleted": false,
                "Name": "No Online Chat",
                "RuleList": {
                    "Rule": {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "Online Chat",
                                "type": "WebCategory"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "1",
                        "HTTPAction": "Deny",
                        "HTTPSAction": "Deny",
                        "PolicyRuleEnabled": "1",
                        "Schedule": "All The Time"
                    }
                },
                "YoutubeFilterEnabled": "0",
                "YoutubeFilterIsStrict": "0"
            },
            {
                "DefaultAction": "Allow",
                "Description": "Restrict users from uploading content to any site",
                "DownloadFileSizeRestriction": "0",
                "DownloadFileSizeRestrictionEnabled": "0",
                "EnableReporting": "Enable",
                "EnforceImageLicensing": "0",
                "EnforceSafeSearch": "0",
                "GoogAppDomainList": null,
                "GoogAppDomainListEnabled": "0",
                "IsDeleted": false,
                "Name": "No web uploads",
                "RuleList": {
                    "Rule": {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "HTTPUpload",
                                "type": "DynamicCategory"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "1",
                        "HTTPAction": "Deny",
                        "HTTPSAction": "Deny",
                        "PolicyRuleEnabled": "1",
                        "Schedule": "All The Time"
                    }
                },
                "YoutubeFilterEnabled": "0",
                "YoutubeFilterIsStrict": "0"
            },
            {
                "DefaultAction": "Allow",
                "Description": "Deny access to categories most commonly unwanted in professional environments",
                "DownloadFileSizeRestriction": "0",
                "DownloadFileSizeRestrictionEnabled": "0",
                "EnableReporting": "Enable",
                "EnforceImageLicensing": "0",
                "EnforceSafeSearch": "0",
                "GoogAppDomainList": null,
                "GoogAppDomainListEnabled": "0",
                "IsDeleted": false,
                "Name": "Default Workplace Policy",
                "RuleList": {
                    "Rule": [
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Weapons",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Extreme",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Phishing & Fraud",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Militancy & Extremist",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Gambling",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Criminal Activity",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Pro-Suicide & Self-Harm",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Intellectual Piracy",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Marijuana",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Controlled substances",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Legal highs",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Hunting & Fishing",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Anonymizers",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Sexually Explicit",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        },
                        {
                            "CCLRuleEnabled": "0",
                            "CategoryList": {
                                "Category": {
                                    "ID": "Nudity",
                                    "type": "WebCategory"
                                }
                            },
                            "ExceptionList": {
                                "FileTypeCategory": null
                            },
                            "FollowHTTPAction": "1",
                            "HTTPAction": "Deny",
                            "HTTPSAction": "Deny",
                            "PolicyRuleEnabled": "1",
                            "Schedule": "All The Time"
                        }
                    ]
                },
                "YoutubeFilterEnabled": "0",
                "YoutubeFilterIsStrict": "0"
            },
            {
                "DefaultAction": "Allow",
                "Description": "Deny access to sexually explicit sites",
                "DownloadFileSizeRestriction": "0",
                "DownloadFileSizeRestrictionEnabled": "0",
                "EnableReporting": "Enable",
                "EnforceImageLicensing": "0",
                "EnforceSafeSearch": "0",
                "GoogAppDomainList": null,
                "GoogAppDomainListEnabled": "0",
                "IsDeleted": false,
                "Name": "No Explicit Content",
                "RuleList": {
                    "Rule": {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "Sexually Explicit",
                                "type": "WebCategory"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "1",
                        "HTTPAction": "Deny",
                        "HTTPSAction": "Deny",
                        "PolicyRuleEnabled": "1",
                        "Schedule": "All The Time"
                    }
                },
                "YoutubeFilterEnabled": "0",
                "YoutubeFilterIsStrict": "0"
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 0 to 6 WebFilterPolicy objects out of 12
>|Name|Description|DefaultAction|EnableReporting|DownloadFileSizeRestrictionEnabled|DownloadFileSizeRestriction|RuleList|
>|---|---|---|---|---|---|---|
>| No Web Mail or Chat | Deny access to web mail and online chat sites | Allow | Enable | 0 | 0 | Rule: {'CategoryList': {'Category': {'ID': 'Web E-Mail', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Online Chat', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'} |
>| No Web Mail | Deny access to web mail sites | Allow | Enable | 0 | 0 | Rule: {"CategoryList": {"Category": {"ID": "Web E-Mail", "type": "WebCategory"}}, "HTTPAction": "Deny", "HTTPSAction": "Deny", "FollowHTTPAction": "1", "ExceptionList": {"FileTypeCategory": null}, "Schedule": "All The Time", "PolicyRuleEnabled": "1", "CCLRuleEnabled": "0"} |
>| No Online Chat | Deny access to online chat sites | Allow | Enable | 0 | 0 | Rule: {"CategoryList": {"Category": {"ID": "Online Chat", "type": "WebCategory"}}, "HTTPAction": "Deny", "HTTPSAction": "Deny", "FollowHTTPAction": "1", "ExceptionList": {"FileTypeCategory": null}, "Schedule": "All The Time", "PolicyRuleEnabled": "1", "CCLRuleEnabled": "0"} |
>| No web uploads | Restrict users from uploading content to any site | Allow | Enable | 0 | 0 | Rule: {"CategoryList": {"Category": {"ID": "HTTPUpload", "type": "DynamicCategory"}}, "HTTPAction": "Deny", "HTTPSAction": "Deny", "FollowHTTPAction": "1", "ExceptionList": {"FileTypeCategory": null}, "Schedule": "All The Time", "PolicyRuleEnabled": "1", "CCLRuleEnabled": "0"} |
>| Default Workplace Policy | Deny access to categories most commonly unwanted in professional environments | Allow | Enable | 0 | 0 | Rule: {'CategoryList': {'Category': {'ID': 'Weapons', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Extreme', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Phishing & Fraud', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Militancy & Extremist', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Gambling', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Criminal Activity', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Pro-Suicide & Self-Harm', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Intellectual Piracy', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Marijuana', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Controlled substances', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Legal highs', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Hunting & Fishing', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Anonymizers', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Sexually Explicit', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': 'Nudity', 'type': 'WebCategory'}}, 'HTTPAction': 'Deny', 'HTTPSAction': 'Deny', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All The Time', 'PolicyRuleEnabled': '1', 'CCLRuleEnabled': '0'} |
>| No Explicit Content | Deny access to sexually explicit sites | Allow | Enable | 0 | 0 | Rule: {"CategoryList": {"Category": {"ID": "Sexually Explicit", "type": "WebCategory"}}, "HTTPAction": "Deny", "HTTPSAction": "Deny", "FollowHTTPAction": "1", "ExceptionList": {"FileTypeCategory": null}, "Schedule": "All The Time", "PolicyRuleEnabled": "1", "CCLRuleEnabled": "0"} |



### sophos-firewall-web-filter-get
***
Gets a single web filter policy by name.


#### Base Command

`sophos-firewall-web-filter-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Whether the policy reports events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Whether the file size restriction is active. | 
| SophosFirewall.WebFilterPolicy.RuleList.Rule | String | Rule list information. | 


#### Command Example
```!sophos-firewall-web-filter-get name=webfilter```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterPolicy": {
            "DefaultAction": "Allow",
            "Description": "Description for web filter",
            "DownloadFileSizeRestriction": "300",
            "DownloadFileSizeRestrictionEnabled": "1",
            "EnableReporting": "Enable",
            "EnforceImageLicensing": "0",
            "EnforceSafeSearch": "1",
            "GoogAppDomainList": "gmail.com",
            "GoogAppDomainListEnabled": "1",
            "IsDeleted": false,
            "Name": "webfilter",
            "RuleList": {
                "Rule": [
                    {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "Blocked URLs for Default Policy",
                                "type": "URLGroup"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "1",
                        "HTTPAction": "Allow",
                        "HTTPSAction": "Allow",
                        "PolicyRuleEnabled": "0",
                        "Schedule": "All Time on Sunday"
                    },
                    {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "1",
                                "type": "URLGroup"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "0",
                        "HTTPAction": "Allow",
                        "HTTPSAction": "Allow",
                        "PolicyRuleEnabled": "0",
                        "Schedule": "All Time on Sunday"
                    }
                ]
            },
            "YoutubeFilterEnabled": "1",
            "YoutubeFilterIsStrict": "0"
        }
    }
}
```

#### Human Readable Output

>### WebFilterPolicy Object details
>|Name|Description|DefaultAction|EnableReporting|DownloadFileSizeRestrictionEnabled|DownloadFileSizeRestriction|RuleList|
>|---|---|---|---|---|---|---|
>| webfilter | Description for web filter | Allow | Enable | 1 | 300 | Rule: {'CategoryList': {'Category': {'ID': 'Blocked URLs for Default Policy', 'type': 'URLGroup'}}, 'HTTPAction': 'Allow', 'HTTPSAction': 'Allow', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All Time on Sunday', 'PolicyRuleEnabled': '0', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': '1', 'type': 'URLGroup'}}, 'HTTPAction': 'Allow', 'HTTPSAction': 'Allow', 'FollowHTTPAction': '0', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All Time on Sunday', 'PolicyRuleEnabled': '0', 'CCLRuleEnabled': '0'} |



### sophos-firewall-web-filter-add
***
Adds a new web filter policy.


#### Base Command

`sophos-firewall-web-filter-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy | Required | 
| description | Description of the policy. | Optional | 
| default_action | Default action for the policy. Possible values: "Allow" and "Deny". | Required | 
| download_file_size_restriction_enabled | Whether the max download file size is enabled. Possible values: "0" and "1". | Optional | 
| download_file_size_restriction | Maximum file size to enable downloading in MB. | Optional | 
| goog_app_domain_list_enabled | Enable to specify domains allowed to access google service. Possible values: "0" and "1". | Optional | 
| goog_app_domain_list | The domains allowed to access google service. | Optional | 
| youtube_filter_enabled | Whether to enable YouTube Restricted Mode to restrict the content that is accessible. Possible values: "0" and "1". | Optional | 
| youtube_filter_is_strict | Whether to adjust the policy used for YouTube Restricted Mode. Possible values: "0" and "1". | Optional | 
| enforce_safe_search | Enable to block websites containing pornography and explicit sexual content from appearing in the search results of Google, Yahoo, Bing search results. Possible values: "0" and "1". | Optional | 
| enforce_image_licensing | Whether to further limit inappropriate content by enforcing search engine filters for Creative Commons licensed images. Possible values: "0" and "1". | Optional | 
| url_group_names | Comma-separted list of URL groups to block, allow, warn, or log. | Optional | 
| http_action | The HTTP action. Possible values: "Deny", "Allow", "Warn", and "Log". | Optional | 
| https_action | The HTTPs action. Possible values: "Deny", "Allow", "Warn", and "Log". | Optional | 
| schedule | The schedule for the rule. Possible values: "All the time", "Work hours (5 Day week)", "Work hours (6 Day week)", "All Time on Weekdays", "All Time on Weekends", "All Time on Sunday", "All Days 10:00 to 19:00". IMPORTANT: Creating a new schedule is available in the web console. | Optional | 
| policy_rule_enabled | Whether to enable the policy rule. Possible values: "1" and "0". | Optional | 
| user_names | A comma-separated list of users who this rule will apply to. | Optional | 
| ccl_names | A comma-separated list of CCL names. REQUIRED: When ccl_rule_enabled is ON. | Optional | 
| ccl_rule_enabled | Whether to enable the CCL rule. Possible values: "0" and "1". IMPORTANT: If enabled, ccl_name is required. | Optional | 
| follow_http_action | Whether to enable the HTTP action. Possible values: "0" and "1". | Optional | 
| enable_reporting | Whether to enable reporting of the policy. Possible values: "Enable" and "Disable". Default is "Enable". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Whether the policy reports events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Whether the file size restriction is active. | 
| SophosFirewall.WebFilterPolicy.RuleList.Rule | String | Rule list information. | 


#### Command Example
```!sophos-firewall-web-filter-add name=webfilter default_action=Allow enable_reporting=Enable download_file_size_restriction=300 download_file_size_restriction_enabled=1 enforce_image_licensing=1 enforce_safe_search=1 goog_app_domain_list=gmail.com goog_app_domain_list_enabled=1 http_action=Allow https_action=Allow schedule="All Time on Sunday" youtube_filter_enabled=1 youtube_filter_is_strict=1 ccl_rule_enabled=0 follow_http_action=1 policy_rule_enabled=0 url_group_names="Blocked URLs for Default Policy"```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterPolicy": {
            "DefaultAction": "Allow",
            "Description": null,
            "DownloadFileSizeRestriction": "300",
            "DownloadFileSizeRestrictionEnabled": "1",
            "EnableReporting": "Enable",
            "EnforceImageLicensing": "1",
            "EnforceSafeSearch": "1",
            "GoogAppDomainList": "gmail.com",
            "GoogAppDomainListEnabled": "1",
            "IsDeleted": false,
            "Name": "webfilter",
            "RuleList": {
                "Rule": {
                    "CCLRuleEnabled": "0",
                    "CategoryList": {
                        "Category": {
                            "ID": "Blocked URLs for Default Policy",
                            "type": "URLGroup"
                        }
                    },
                    "ExceptionList": {
                        "FileTypeCategory": null
                    },
                    "FollowHTTPAction": "1",
                    "HTTPAction": "Allow",
                    "HTTPSAction": "Allow",
                    "PolicyRuleEnabled": "0",
                    "Schedule": "All Time on Sunday"
                }
            },
            "YoutubeFilterEnabled": "1",
            "YoutubeFilterIsStrict": "1"
        }
    }
}
```

#### Human Readable Output

>### WebFilterPolicy Object details
>|Name|DefaultAction|EnableReporting|DownloadFileSizeRestrictionEnabled|DownloadFileSizeRestriction|RuleList|
>|---|---|---|---|---|---|
>| webfilter | Allow | Enable | 1 | 300 | Rule: {"CategoryList": {"Category": {"ID": "Blocked URLs for Default Policy", "type": "URLGroup"}}, "HTTPAction": "Allow", "HTTPSAction": "Allow", "FollowHTTPAction": "1", "ExceptionList": {"FileTypeCategory": null}, "Schedule": "All Time on Sunday", "PolicyRuleEnabled": "0", "CCLRuleEnabled": "0"} |



### sophos-firewall-web-filter-update
***
Updates an existing web filter policy.


#### Base Command

`sophos-firewall-web-filter-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| default_action | Default action for the policy. Possible values: "Allow" and "Deny". | Required | 
| download_file_size_restriction_enabled | Whether the maximum download file size is enabled. Possible values: "0" and "1". | Optional | 
| download_file_size_restriction | The maximum file size to enable downloading in MB. | Optional | 
| goog_app_domain_list_enabled | Whether to enable specifying domains allowed to access the Google service. Possible values: "0" and "1". | Optional | 
| goog_app_domain_list | Comma-separated list of domains allowed to access google service. | Optional | 
| youtube_filter_enabled | Whether to enable YouTube Restricted Mode to restrict the content that is accessible. Possible values: "0" and "1". | Optional | 
| youtube_filter_is_strict | Whether to adjust the policy used for YouTube Restricted Mode. Possible values: "0" and "1". | Optional | 
| enforce_safe_search | Whether to enable blocking websites containing pornography and explicit sexual content from appearing in the search results of Google, Yahoo, and Bing search results. Possible values: "0" and "1". | Optional | 
| enforce_image_licensing | Whether to further limit inappropriate content by enforcing search engine filters for Creative Commons licensed images. Possible values: "0" and "1". | Optional | 
| url_group_names | Comma-separated list of URL groups to block, allow, warn, or log. | Optional | 
| http_action | The HTTP action. Possible values: "Deny", "Allow", "Warn", and "Log". | Optional | 
| https_action | The HTTPs action. Possible values: "Deny", "Allow", "Warn", and "Log". | Optional | 
| schedule | The schedule for the rule. Possible values: "All the time", "Work hours (5 Day week)", "Work hours (6 Day week)", "All Time on Weekdays", "All Time on Weekends", "All Time on Sunday", "All Days 10:00 to 19:00". IMPORTANT: Creating a new schedule is available in the web console. | Optional | 
| policy_rule_enabled | Whether to enable the policy rule. Possible values: "1" and "0". | Optional | 
| user_names | A comma-separated list of users who this rule will apply to. | Optional | 
| ccl_names | A comma-separated list of CCL names. REQUIRED: when ccl_rule_enabled is ON | Optional | 
| ccl_rule_enabled | Whether to enable the CCL rule. Possible values: "0" and "1". IMPORTANT: If enabled, ccl_name is required. | Optional | 
| follow_http_action | Whether to enable the HTTP action. Possible values: "0" and "1". | Optional | 
| enable_reporting | Whether to enable reporting of the policy. Possible values: "Enable" and "Disable". Default is "Enable". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Whether the policy reports events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Whether the file size restriction is active. | 
| SophosFirewall.WebFilterPolicy.RuleList.Rule | String | Rule list information. | 


#### Command Example
```!sophos-firewall-web-filter-update name=webfilter default_action=Allow enable_reporting=Enable download_file_size_restriction=300 download_file_size_restriction_enabled=1 enforce_image_licensing=0 enforce_safe_search=1 goog_app_domain_list=gmail.com goog_app_domain_list_enabled=1 http_action=Allow https_action=Allow schedule="All Time on Sunday" youtube_filter_enabled=1 youtube_filter_is_strict=0 ccl_rule_enabled=0 follow_http_action=0 policy_rule_enabled=0 url_group_names=1 description="Description for web filter"```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterPolicy": {
            "DefaultAction": "Allow",
            "Description": "Description for web filter",
            "DownloadFileSizeRestriction": "300",
            "DownloadFileSizeRestrictionEnabled": "1",
            "EnableReporting": "Enable",
            "EnforceImageLicensing": "0",
            "EnforceSafeSearch": "1",
            "GoogAppDomainList": "gmail.com",
            "GoogAppDomainListEnabled": "1",
            "IsDeleted": false,
            "Name": "webfilter",
            "RuleList": {
                "Rule": [
                    {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "Blocked URLs for Default Policy",
                                "type": "URLGroup"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "1",
                        "HTTPAction": "Allow",
                        "HTTPSAction": "Allow",
                        "PolicyRuleEnabled": "0",
                        "Schedule": "All Time on Sunday"
                    },
                    {
                        "CCLRuleEnabled": "0",
                        "CategoryList": {
                            "Category": {
                                "ID": "1",
                                "type": "URLGroup"
                            }
                        },
                        "ExceptionList": {
                            "FileTypeCategory": null
                        },
                        "FollowHTTPAction": "0",
                        "HTTPAction": "Allow",
                        "HTTPSAction": "Allow",
                        "PolicyRuleEnabled": "0",
                        "Schedule": "All Time on Sunday"
                    }
                ]
            },
            "YoutubeFilterEnabled": "1",
            "YoutubeFilterIsStrict": "0"
        }
    }
}
```

#### Human Readable Output

>### WebFilterPolicy Object details
>|Name|Description|DefaultAction|EnableReporting|DownloadFileSizeRestrictionEnabled|DownloadFileSizeRestriction|RuleList|
>|---|---|---|---|---|---|---|
>| webfilter | Description for web filter | Allow | Enable | 1 | 300 | Rule: {'CategoryList': {'Category': {'ID': 'Blocked URLs for Default Policy', 'type': 'URLGroup'}}, 'HTTPAction': 'Allow', 'HTTPSAction': 'Allow', 'FollowHTTPAction': '1', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All Time on Sunday', 'PolicyRuleEnabled': '0', 'CCLRuleEnabled': '0'},<br/>{'CategoryList': {'Category': {'ID': '1', 'type': 'URLGroup'}}, 'HTTPAction': 'Allow', 'HTTPSAction': 'Allow', 'FollowHTTPAction': '0', 'ExceptionList': {'FileTypeCategory': None}, 'Schedule': 'All Time on Sunday', 'PolicyRuleEnabled': '0', 'CCLRuleEnabled': '0'} |



### sophos-firewall-web-filter-delete
***
Deletes an existing web filter policy.


#### Base Command

`sophos-firewall-web-filter-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.IsDeleted | Bool | Whether the policy is deleted. | 


#### Command Example
```!sophos-firewall-web-filter-delete name=webfilter```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterPolicy": {
            "IsDeleted": true,
            "Name": "webfilter"
        }
    }
}
```

#### Human Readable Output

>### Deleting WebFilterPolicy Objects Results
>|Name|IsDeleted|
>|---|---|
>| webfilter | true |
