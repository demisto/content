On-Premise firewall by Sophos
This integration was integrated and tested with version xx of sophos_firewall.
Supported Cortex XSOAR versions: 5.0.0 and later.

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
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


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
Get a single firewall rule by name.


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
| SophosFirewall.SecurityPolicy.IPFamily | String | IPv4/IPv6 | 
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
Add a new firewall rule.


#### Base Command

`sophos-firewall-rule-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the new rule. | Required | 
| description | Description of the new rule. | Optional | 
| status | Is the rule enabled or disabled. Possible values are: Enable, Disable. Default is Enable. | Optional | 
| ip_family | Are the IPs v4 or v6. Possible values are: IPv4, IPv6. Default is IPv4. | Optional | 
| position | Should the rule be at the top or bottom of the list? before or after a specific rule? IMPORTANT: If before/after is chosen - provide the position_policy_name pramater. Possible values are: top, bottom, after, before. | Required | 
| position_policy_name | The name of the policy that the rule should be created before/after . REQUIRED: When the position is before/after. | Optional | 
| policy_type | Type of the new rule (policy). Possible values are: User, Network. | Required | 
| source_zones | Source zones to add to the rule. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 
| source_networks | Source networks to add to the rule. | Optional | 
| destination_zones | Destination zones to add to the rule. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 
| destination_networks | Destination networks to add to the rule. | Optional | 
| services | Destination services to add to the rule. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console. Possible values are: All the time, Work hours (5 Day week), Work hours (6 Day week), All Time on Weekdays, All Time on Weekends, All Time on Sunday, All Days 10:00 to 19:00. | Optional | 
| log_traffic | Enable traffic logging for the policy. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| match_identity | Enable to check whether the specified user/user group from the selected zone is allowed to access the selected service or not. IMPORTANT: when enabling match_identity - members parameter is required. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| show_captive_portal | Select to accept traffic from unknown users. Captive portal page is displayed to the user where the user can login to access the Internet. IMPORTANT: MatchIdentity must be Enabled. PARAMETER OF: UserPolicy. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| members | An existing user(s) or group(s) to add to the rule. REQUIRED: when match_identity is enabled. . | Optional | 
| action | Specify action for the rule traffic. Possible values are: Accept, Reject, Drop. Default is Drop. | Optional | 
| dscp_marking | Select DSCP Marking to classify flow of packets based on Traffic Shaping policy. | Optional | 
| primary_gateway | Specify the Primary Gateway. Applicable only in case of Multiple Gateways. | Optional | 
| backup_gateway | Specify the Backup Gateway. Applicable only in case of Multiple Gateways. | Optional | 
| application_control | Select Application Filter Policy for the rule. Default is Allow All. | Optional | 
| application_based_qos_policy | Select to limit the bandwidth for the applications categorized under the Application Category. this tag is only appliacable only when any application_control is selected. Possible values are: Apply, Revoke. Default is Revoke. | Optional | 
| web_filter | Select Web Filter Policy for the rule. Default is Allow All. | Optional | 
| web_category_base_qos_policy | Select to limit bandwidth for the URLs categorized under the Web category. this tag is only appliacable only when any web_filteris selected. Possible values are: Apply, Revoke. Default is Revoke. | Optional | 
| traffic_shapping_policy | Select Traffic Shaping policy for the rule. Default is None. | Optional | 
| scan_http | Select to enable virus and spam scanning for HTTP protocol. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| scan_https | Select to enable virus and spam scanning for HTTPS protocol. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| sandstorm | Select to enable sandstorm analysis. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| block_quick_quic | Ensure Google websites user HTTP/s instead of QUICK QUIC. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| scan_ftp | Enable/Disable scanning of FTP traffic. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| data_accounting | Select to exclude user's network traffic from data accounting. This option is available only if the parameter 'Match rule-based on user identity' is enabled. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| rewrite_source_address | Enable to apply NAT Policy. Possible values are: Enable, Disable. Default is Enable. | Optional | 
| web_filter_internet_scheme | Select internet scheme to apply user based Web Filter Policy for the rule. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| application_control_internet_scheme | Select internet scheme to apply user based Application Filter Policy for the rule. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| override_gateway_default_nat_policy | Enable/Disable overriding gateway of default nat policy. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| source_security_heartbeat | Enable/Disable source security heartbeat. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| destination_security_heartbeat | Enable/Disable destination security heartbeat. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| outbound_address | Select the NAT Policy to be applied. Default is MASQ. | Optional | 
| minimum_source_hb_permitted | Select minimum source HB permitted. Default is No Restriction. | Optional | 
| minimum_destination_hb_permitted | Select minimum destination HB permitted. Default is No Restriction. | Optional | 
| intrusion_prevention | Select IPS policy for the rule. Default is generalpolicy. | Optional | 


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
Update an existing firewall rule.


#### Base Command

`sophos-firewall-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the new rule. | Required | 
| description | Description of the new rule. | Optional | 
| status | Is the rule enabled or disabled. Possible values are: Enable, Disable. Default is Enable. | Optional | 
| ip_family | Are the IPs v4 or v6. Possible values are: IPv4, IPv6. Default is IPv4. | Optional | 
| position | Should the rule be at the top or bottom of the list? before or after a specific rule? IMPORTANT: If before/after is chosen - provide the position_policy_name pramater. Possible values are: top, bottom, after, before. | Optional | 
| position_policy_name | The name of the policy that the rule should be created before/after . REQUIRED: When the position is before/after. | Optional | 
| policy_type | Type of the new rule (policy). Possible values are: User, Network. | Optional | 
| source_zones | Source zones to add to the rule. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 
| source_networks | Source networks to add to the rule. | Optional | 
| destination_zones | Destination zones to add to the rule. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 
| destination_networks | Destination networks to add to the rule. | Optional | 
| services | Destination services to add to the rule. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console. Possible values are: All the time, Work hours (5 Day week), Work hours (6 Day week), All Time on Weekdays, All Time on Weekends, All Time on Sunday, All Days 10:00 to 19:00. | Optional | 
| log_traffic | Enable traffic logging for the policy. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| match_identity | Enable to check whether the specified user/user group from the selected zone is allowed to access the selected service or not. IMPORTANT: when enabling match_identity - members parameter is required. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| show_captive_portal | Select to accept traffic from unknown users. Captive portal page is displayed to the user where the user can login to access the Internet. IMPORTANT: MatchIdentity must be Enabled. PARAMETER OF: UserPolicy. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| members | An existing user(s) or group(s) to add to the rule. REQUIRED: when match_identity is enabled. . | Optional | 
| action | Specify action for the rule traffic. Possible values are: Accept, Reject, Drop. Default is Drop. | Optional | 
| dscp_marking | Select DSCP Marking to classify flow of packets based on Traffic Shaping policy. | Optional | 
| primary_gateway | Specify the Primary Gateway. Applicable only in case of Multiple Gateways. | Optional | 
| backup_gateway | Specify the Backup Gateway. Applicable only in case of Multiple Gateways. | Optional | 
| application_control | Select Application Filter Policy for the rule. Default is Allow All. | Optional | 
| application_based_qos_policy | Select to limit the bandwidth for the applications categorized under the Application Category. this tag is only appliacable only when any application_control is selected. Possible values are: Apply, Revoke. Default is Revoke. | Optional | 
| web_filter | Select Web Filter Policy for the rule. Default is Allow All. | Optional | 
| web_category_base_qos_policy | Select to limit bandwidth for the URLs categorized under the Web category. this tag is only appliacable only when any web_filteris selected. Possible values are: Apply, Revoke. Default is Revoke. | Optional | 
| traffic_shapping_policy | Select Traffic Shaping policy for the rule. Default is None. | Optional | 
| scan_http | Select to enable virus and spam scanning for HTTP protocol. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| scan_https | Select to enable virus and spam scanning for HTTPS protocol. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| sandstorm | Select to enable sandstorm analysis. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| block_quick_quic | Ensure Google websites user HTTP/s instead of QUICK QUIC. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| scan_ftp | Enable/Disable scanning of FTP traffic. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| data_accounting | Select to exclude user's network traffic from data accounting. This option is available only if the parameter 'Match rule-based on user identity' is enabled. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| rewrite_source_address | Enable to apply NAT Policy. Possible values are: Enable, Disable. Default is Enable. | Optional | 
| web_filter_internet_scheme | Select internet scheme to apply user based Web Filter Policy for the rule. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| application_control_internet_scheme | Select internet scheme to apply user based Application Filter Policy for the rule. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| override_gateway_default_nat_policy | Enable/Disable overriding gateway of default nat policy. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| source_security_heartbeat | Enable/Disable source security heartbeat. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| destination_security_heartbeat | Enable/Disable destination security heartbeat. Possible values are: Enable, Disable. Default is Disable. | Optional | 
| outbound_address | Select the NAT Policy to be applied. Default is MASQ. | Optional | 
| minimum_source_hb_permitted | Select minimum source HB permitted. Default is No Restriction. | Optional | 
| minimum_destination_hb_permitted | Select minimum destination HB permitted. Default is No Restriction. | Optional | 
| intrusion_prevention | Select IPS policy for the rule. Default is generalpolicy. | Optional | 


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
Delete an existing firewall rule.


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
| SophosFirewall.SecurityPolicy.IsDeleted | String | Whether or not the rule is deleted. | 


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
List all firewall rule groups. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-rule-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


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
Get a single firewall rule group by name.


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
Add a new firewall rule group.


#### Base Command

`sophos-firewall-rule-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule group. | Required | 
| description | Description of the rule group. | Optional | 
| policy_type | Type of the rules (policies) inside. Possible values are: Any, User/network rule, Network rule, User rule, Business application rule. | Optional | 
| rules | Rules contained inside the group. | Optional | 
| source_zones | Source zones contained in the group. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 
| destination_zones | Destination zones contained in the group. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 


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
Update an existing firewall rule group.


#### Base Command

`sophos-firewall-rule-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the rule group. | Required | 
| description | Description of the rule group. | Optional | 
| policy_type | Type of the rules (policies) inside. Possible values are: Any, User/network rule, Network rule, User rule, Business application rule. | Optional | 
| rules | Rules contained inside the group. | Optional | 
| source_zones | Source zones contained in the group. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 
| destination_zones | Destination zones contained in the group. Possible values are: Any, LAN, WAN, VPN, DMZ, WiFi. | Optional | 


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
Delete an existing firewall group.


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
| SophosFirewall.SecurityPolicyGroup.IsDeleted | String | Whether or not the group is deleted. | 


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
List all URL groups. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-url-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.Description | String | Description of the URL group. | 
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL contained inside the group. | 


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
Get a single URL group by name.


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
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL contained inside the group. | 


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
Add a new URL group.


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
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL contained inside the group. | 


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
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.Description | String | Description of the URL group. | 
| SophosFirewall.WebFilterURLGroup.URLlist.URL | String | URL contained inside the group. | 


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
| SophosFirewall.WebFilterURLGroup.Name | String | Name of the URL group. | 
| SophosFirewall.WebFilterURLGroup.IsDeleted | String | Whether or not the URL group is deleted. | 



#### Command Example
```!sophos-firewall-url-group-delete name=urlgroup```

#### Context Example
```json
{
    "SophosFirewall": {
        "WebFilterURLGroup": {
            "IsDeleted": true,
            "Name": "iphost"
        }
    }
}
```

#### Human Readable Output



### sophos-firewall-ip-host-list
***
List all IP hosts. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-ip-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | is the host in IPv4 or IPv6. | 
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
Get a single IP host by name.


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
| SophosFirewall.IPHost.IPFamily | String | is the host in IPv4 or IPv6. | 
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
Add a new IP host.


#### Base Command

`sophos-firewall-ip-host-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host. | Required | 
| host_type | Type of the host. Possible values are: IP, Network, IPRange, IPList. | Required | 
| ip_family | Is the IP in IPv4 or IPv6. Possible values are: IPv4, IPv6. Default is IPv4. | Optional | 
| ip_address | IP address if IP or network was the chosen type. | Optional | 
| subnet_mask | Subnet mask if network was the chosen type. | Optional | 
| start_ip | Start of the IP range if IPRange was chosen. | Optional | 
| end_ip | End of the IP range if IPRange was chosen. | Optional | 
| ip_addresses | List of IP addresses if IPList was chosen. | Optional | 
| host_group | Select the Host Group to which the Host belongs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | is the host in IPv4 or IPv6. | 
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
Update an existing IP host.


#### Base Command

`sophos-firewall-ip-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host. | Required | 
| host_type | Type of the host. Possible values are: IP, Network, IPRange, IPList. | Optional | 
| ip_family | Is the IP in IPv4 or IPv6. Possible values are: IPv4, IPv6. Default is IPv4. | Optional | 
| ip_address | IP address if IP or network was the chosen type. | Optional | 
| subnet_mask | Subnet mask if network was the chosen type. | Optional | 
| start_ip | Start of the IP range if IPRange was chosen. | Optional | 
| end_ip | End of the IP range if IPRange was chosen. | Optional | 
| ip_addresses | List of IP addresses if IPList was chosen. | Optional | 
| host_group | Select the Host Group to which the Host belongs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHost.Name | String | Name of the IP host. | 
| SophosFirewall.IPHost.IPFamily | String | is the host in IPv4 or IPv6. | 
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
Delete an existing IP host.


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
| SophosFirewall.IPHost.IsDeleted | String | Whether or not the IP host is deleted. | 


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
List all IP host groups. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-ip-host-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.HostList.Host | String | Host contained inside the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group \(IPv4 / IPv6\) | 


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
Get a single IP host group by name.


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
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group \(IPv4 / IPv6\) | 


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
Add a new IP host group.


#### Base Command

`sophos-firewall-ip-host-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group. | Required | 
| description | Description of the IP host group. | Optional | 
| ip_family | Is the IP group in IPv4 or IPv6. Possible values are: IPv4, IPv6. | Optional | 
| hosts | IP hosts contained in the group. Must be hosts already existing in the system. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.HostList.Host | String | Host contained inside the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group \(IPv4 / IPv6\) | 


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
Update an existing IP host group.


#### Base Command

`sophos-firewall-ip-host-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the IP host group. | Required | 
| description | Description of the IP host group. | Optional | 
| ip_family | Is the IP group in IPv4 or IPv6. Possible values are: IPv4, IPv6. | Optional | 
| hosts | IP hosts contained in the group. Must be hosts already existing in the system. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.IPHostGroup.Name | String | Name of the IP host group. | 
| SophosFirewall.IPHostGroup.description | String | Description of the IP host group. | 
| SophosFirewall.IPHostGroup.HostList.Host | String | Host contained inside the host group. | 
| SophosFirewall.IPHostGroup.IPFamily | String | IP family of the host group \(IPv4 / IPv6\) | 


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
Delete an existing IP host group.


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
| SophosFirewall.IPHostGroup.IsDeleted | String | Whether or not the IP host group is deleted. | 


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
List all firewall services. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-services-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


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
Get a single service by name.


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
Add a new firewall service.


#### Base Command

`sophos-firewall-services-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service. | Required | 
| service_type | Type of service. Possible values are: TCPorUDP, IP, ICMP, ICMPv6. | Required | 
| protocol | Select Protocol for the service if service_type is TCPorUDP. Possible values are: TCP, UDP. | Optional | 
| source_port | Source port if service_type is TCPorUDP. | Optional | 
| destination_port | Destination port if service_type is TCPorUDP. | Optional | 
| protocol_name | Protocol name if service_type is IP . Possible values are: HOPOPT, ICMP, IGMPGGP, IP, ST, TCP, CBT, EGP, IGP, BBN-RCC-MON, NVP-II, PUP, ARGUS, EMCON, XNET, CHAOS, UDP, MUX, DCN-MEAS, HMP, PRM, XNS-IDP, TRUNK-1, TRUNK-2, LEAF-1, LEAF-2, RDP, IRTP, ISO-TP4, NETBLT, MFE-NSP, MERIT-INP, DCCP, 3PC, IDPRXTP, DDP, IDPR-CMTP, TP++, IL, IPv6, SDRP, IPv6-Route, IPv6-Frag, IDRP, RSVP, GRE, DSR, BNA, ESP, AH, I-NLSP, SWIPE, NARP, MOBILE, TLSP, SKIP, IPv6-ICMP, IPv6-NoNxt, IPv6-Opts, IPProto61, CFTP, IPProto63, SAT-EXPAK, KRYPTOLAN, RVD, IPPC, IPProto68, SAT-MON, VISA, IPCV, CPNX, CPHB, WSN, PVP, BR-SAT-MON, SUN-ND, WB-MON, WB-EXPAK, ISO-IP, VMTP, SECURE-VMTP, VINES, TTP, NSFNET-IGP, DGP, TCF, EIGRP, OSPFIGP, Sprite-RPC, LARP, MTP, 25, IPIP, MICP, SCC-SP, ETHERIP, ENCAP, IPProto99, GMTP, IFMP, PNNI, PIM, ARIS, SCPS, QNX, A, N, IPComp, SNP, Compaq-Peer, IPX-in-IP, VRRP, PGM, IPProto114, L2TP, DDX, IATP, STP, SRP, UTI, SMP, SM, PTP, ISIS, FIRE, CRTP, CRUDP, SSCOPMCE, IPLT, SPS, PIPE, SCTP, FC, RSVP-E2E-IGNORE, IPProto135, UDPLite, MPLS-in-IP, manet, HIP, Shim6, WESP, ROHC, IPProto143, IPProto144, IPProto145, IPProto146, IPProto147, IPProto148, IPProto149, IPProto150, IPProto151, IPProto152, IPProto153, IPProto154, IPProto155, IPProto156, IPProto157, IPProto158, IPProto159, IPProto160, IPProto161, IPProto162, IPProto163, IPProto164, IPProto165, IPProto166, IPProto167, IPProto168, IPProto169, IPProto170, IPProto171, IPProto172, IPProto173, IPProto174, IPProto175, IPProto176, IPProto177, IPProto178, IPProto179, IPProto180, IPProto181, IPProto182, IPProto183, IPProto184, IPProto185, IPProto186, IPProto187, IPProto188, IPProto189, IPProto190, IPProto191, IPProto192, IPProto193, IPProto194, IPProto195, IPProto196, IPProto197, IPProto198, IPProto199, IPProto200, IPProto201, IPProto202, IPProto203, IPProto204, IPProto205, IPProto206, IPProto207, IPProto208, IPProto209, IPProto210, IPProto211, IPProto212, IPProto213, IPProto214, IPProto215, IPProto216, IPProto217, IPProto218, IPProto219, IPProto220, IPProto221, IPProto222, IPProto223, IPProto224, IPProto225, IPProto226, IPProto227, IPProto228, IPProto229, IPProto230, IPProto231, IPProto232, IPProto233, IPProto234, IPProto235, IPProto236, IPProto237, IPProto238, IPProto239, IPProto240, IPProto241, IPProto242, IPProto243, IPProto244, IPProto245, IPProto246, IPProto247, IPProto248, IPProto249, IPProto250, IPProto251, IPProto252, IPProto253, IPProto254, IPProto255. | Optional | 
| icmp_type | ICMP type if service_type is ICMP. Possible values are: Echo Reply, Destination Unreachable, Source Quench, Redirect, Alternate Host Address, Echo, Router Advertisement, Router Selection, Time Exceeded, Parameter Problem, Timestamp, Timestamp Reply, Information Request, Information Reply, Address Mask Request, Address Mask Reply, Traceroute, Datagram Conversion Error, Mobile Host Redirect, IPv6 Where-Are-You, IPv6 I-Am-Here, Mobile Registration Request, Mobile Registration Reply, Domain Name Request, Domain Name Reply, SKIP, Photuris, Any Type. | Optional | 
| icmp_code | ICMP code if service_type is ICMP. Possible values are: 0, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15. | Optional | 
| icmp_v6_type | ICMPv6 type if service_type is ICMPv6. Possible values are: Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem, Private experimentation, Private experimentation, Echo Request, Echo Reply, Multicast Listener Query, Multicast Listener Report, Multicast Listener Done, Router Solicitation, Router Advertisement, Neighbor Solicitation, Neighbor Advertisement, Redirect Message, Router Renumbering, ICMP Node Information Query, ICMP Node Information Response, Inverse Neighbor Discovery Solicitation Message, Inverse Neighbor Discovery Advertisement Message, Version 2 Multicast Listener Report, Home Agent Address Discovery Request Message, Home Agent Address Discovery Reply Message, Mobile Prefix Solicitation, Mobile Prefix Advertisement, Certification Path Solicitation Message, Certification Path Advertisement Message, ICMP messages utilized by experimental mobility protocols such as Seamoby, Multicast Router Advertisement, Multicast Router Solicitation, Multicast Router Termination, FMIPv6 Messages, RPL Control Message, ILNPv6 Locator Update Message, Duplicate Address Request, Duplicate Address Confirmation, Private experimentation, Private experimentation, Any Type. | Optional | 
| icmp_v6_code | ICMPv6 code if service_type is ICMPv6. Possible values are: 0, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15. | Optional | 


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
Update an existing firewall service.


#### Base Command

`sophos-firewall-services-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the firewall service. | Required | 
| service_type | Type of service. Possible values are: TCPorUDP, IP, ICMP, ICMPv6. | Optional | 
| protocol | Select Protocol for the service if service_type is TCPorUDP. Possible values are: TCP, UDP. | Optional | 
| source_port | Source port if service_type is TCPorUDP. | Optional | 
| destination_port | Destination port if service_type is TCPorUDP. | Optional | 
| protocol_name | Protocol name if service_type is IP . Possible values are: HOPOPT, ICMP, IGMPGGP, IP, ST, TCP, CBT, EGP, IGP, BBN-RCC-MON, NVP-II, PUP, ARGUS, EMCON, XNET, CHAOS, UDP, MUX, DCN-MEAS, HMP, PRM, XNS-IDP, TRUNK-1, TRUNK-2, LEAF-1, LEAF-2, RDP, IRTP, ISO-TP4, NETBLT, MFE-NSP, MERIT-INP, DCCP, 3PC, IDPRXTP, DDP, IDPR-CMTP, TP++, IL, IPv6, SDRP, IPv6-Route, IPv6-Frag, IDRP, RSVP, GRE, DSR, BNA, ESP, AH, I-NLSP, SWIPE, NARP, MOBILE, TLSP, SKIP, IPv6-ICMP, IPv6-NoNxt, IPv6-Opts, IPProto61, CFTP, IPProto63, SAT-EXPAK, KRYPTOLAN, RVD, IPPC, IPProto68, SAT-MON, VISA, IPCV, CPNX, CPHB, WSN, PVP, BR-SAT-MON, SUN-ND, WB-MON, WB-EXPAK, ISO-IP, VMTP, SECURE-VMTP, VINES, TTP, NSFNET-IGP, DGP, TCF, EIGRP, OSPFIGP, Sprite-RPC, LARP, MTP, 25, IPIP, MICP, SCC-SP, ETHERIP, ENCAP, IPProto99, GMTP, IFMP, PNNI, PIM, ARIS, SCPS, QNX, A, N, IPComp, SNP, Compaq-Peer, IPX-in-IP, VRRP, PGM, IPProto114, L2TP, DDX, IATP, STP, SRP, UTI, SMP, SM, PTP, ISIS, FIRE, CRTP, CRUDP, SSCOPMCE, IPLT, SPS, PIPE, SCTP, FC, RSVP-E2E-IGNORE, IPProto135, UDPLite, MPLS-in-IP, manet, HIP, Shim6, WESP, ROHC, IPProto143, IPProto144, IPProto145, IPProto146, IPProto147, IPProto148, IPProto149, IPProto150, IPProto151, IPProto152, IPProto153, IPProto154, IPProto155, IPProto156, IPProto157, IPProto158, IPProto159, IPProto160, IPProto161, IPProto162, IPProto163, IPProto164, IPProto165, IPProto166, IPProto167, IPProto168, IPProto169, IPProto170, IPProto171, IPProto172, IPProto173, IPProto174, IPProto175, IPProto176, IPProto177, IPProto178, IPProto179, IPProto180, IPProto181, IPProto182, IPProto183, IPProto184, IPProto185, IPProto186, IPProto187, IPProto188, IPProto189, IPProto190, IPProto191, IPProto192, IPProto193, IPProto194, IPProto195, IPProto196, IPProto197, IPProto198, IPProto199, IPProto200, IPProto201, IPProto202, IPProto203, IPProto204, IPProto205, IPProto206, IPProto207, IPProto208, IPProto209, IPProto210, IPProto211, IPProto212, IPProto213, IPProto214, IPProto215, IPProto216, IPProto217, IPProto218, IPProto219, IPProto220, IPProto221, IPProto222, IPProto223, IPProto224, IPProto225, IPProto226, IPProto227, IPProto228, IPProto229, IPProto230, IPProto231, IPProto232, IPProto233, IPProto234, IPProto235, IPProto236, IPProto237, IPProto238, IPProto239, IPProto240, IPProto241, IPProto242, IPProto243, IPProto244, IPProto245, IPProto246, IPProto247, IPProto248, IPProto249, IPProto250, IPProto251, IPProto252, IPProto253, IPProto254, IPProto255. | Optional | 
| icmp_type | ICMP type if service_type is ICMP. Possible values are: Echo Reply, Destination Unreachable, Source Quench, Redirect, Alternate Host Address, Echo, Router Advertisement, Router Selection, Time Exceeded, Parameter Problem, Timestamp, Timestamp Reply, Information Request, Information Reply, Address Mask Request, Address Mask Reply, Traceroute, Datagram Conversion Error, Mobile Host Redirect, IPv6 Where-Are-You, IPv6 I-Am-Here, Mobile Registration Request, Mobile Registration Reply, Domain Name Request, Domain Name Reply, SKIP, Photuris, Any Type. | Optional | 
| icmp_code | ICMP code if service_type is ICMP. Possible values are: 0, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15. | Optional | 
| icmp_v6_type | ICMPv6 type if service_type is ICMPv6. Possible values are: Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem, Private experimentation, Private experimentation, Echo Request, Echo Reply, Multicast Listener Query, Multicast Listener Report, Multicast Listener Done, Router Solicitation, Router Advertisement, Neighbor Solicitation, Neighbor Advertisement, Redirect Message, Router Renumbering, ICMP Node Information Query, ICMP Node Information Response, Inverse Neighbor Discovery Solicitation Message, Inverse Neighbor Discovery Advertisement Message, Version 2 Multicast Listener Report, Home Agent Address Discovery Request Message, Home Agent Address Discovery Reply Message, Mobile Prefix Solicitation, Mobile Prefix Advertisement, Certification Path Solicitation Message, Certification Path Advertisement Message, ICMP messages utilized by experimental mobility protocols such as Seamoby, Multicast Router Advertisement, Multicast Router Solicitation, Multicast Router Termination, FMIPv6 Messages, RPL Control Message, ILNPv6 Locator Update Message, Duplicate Address Request, Duplicate Address Confirmation, Private experimentation, Private experimentation, Any Type. | Optional | 
| icmp_v6_code | ICMPv6 code if service_type is ICMPv6. Possible values are: 0, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15. | Optional | 


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
Delete an existing firewall service.


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
| SophosFirewall.Services.IsDeleted | String | Whether or not the firewall service is deleted. | 


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
List all users. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


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
                    "EmailID": "shiratg@qmasters.co"
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
                    "EmailID": "shiratg@qmasters.co"
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
>| user new | user_new |  | EmailID: shiratg@qmasters.co | Open Group | User | Active |
>| sg | sg | This is sg desc | EmailID: shiratg@qmasters.co | Guest Group | Administrator | Active |
>| 1 | 1 | 1 |  | Guest Group | User | Active |
>| sg1 | sg | new desc |  | Guest Group | User | Active |
>| unitestuser | unitest2 |  | EmailID: test@test.test | Guest Group | User | Active |
>| unitestuser2 | unitest3 |  | EmailID: test@test.test | Guest Group | User | Active |


### sophos-firewall-user-get
***
Get a single user by name.


#### Base Command

`sophos-firewall-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | name of the user. | Required | 


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
Add a new user.


#### Base Command

`sophos-firewall-user-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | username of the user. | Required | 
| name | name of the user. | Required | 
| description | description of the user. | Optional | 
| email | email of the user. | Required | 
| group | group of the user. . Default is Guest Group. | Optional | 
| password | the password of the user. | Required | 
| user_type | the type of the user. Possible values are: Administrator, User. Default is User. | Optional | 
| profile | profile of the admin if user_type is admin. IMPORTANT: you can add more types on the web console. Possible values are: Administrator, Crypto Admin, Security Admin, Audit Admin, HAProfile. | Optional | 
| surfing_quota_policy | Select the Surfing Quota Policy. Default is Unlimited Internet Access. | Optional | 
| access_time_policy | Select the Access Time Policy. Default is Allowed all the time. | Optional | 
| ssl_vpn_policy | Select SSL VPN policy. Default is No Policy Applied. | Optional | 
| clientless_policy | Select clientlesspolicy policy. Default is No Policy Applied. | Optional | 
| data_transfer_policy | Select the Data Transfer Policy. Default is 100 MB Total Data Transfer policy. | Optional | 
| simultaneous_logins_global | Enable Simultaneous Logins Global. Possible values are: Enable, Disable. Default is Enable. | Optional | 
| schedule_for_appliance_access | Select Schedule for appliance access. IMPORTANT: This option is available only for Administrators. Default is All The Time. | Optional | 
| qos_policy | Select the QoS Policy. Default is High Guarantee User. | Optional | 
| login_restriction | Select login restriction option. Possible values are: AnyNode, UserGroupNode. Default is UserGroupNode. | Optional | 


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
Update a user.


#### Base Command

`sophos-firewall-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | username of the user. | Required | 
| name | name of the user. | Required | 
| description | description of the user. | Optional | 
| email | email of the user. | Optional | 
| group | group of the user. . Default is Guest Group. | Optional | 
| password | the password of the user. | Optional | 
| user_type | the type of the user. Possible values are: Administrator, User. Default is User. | Optional | 
| profile | profile of the admin if user_type is admin. IMPORTANT: you can add more types on the web console. Possible values are: Administrator, Crypto Admin, Security Admin, Audit Admin, HAProfile. | Optional | 
| surfing_quota_policy | Select the Surfing Quota Policy. Default is Unlimited Internet Access. | Optional | 
| access_time_policy | Select the Access Time Policy. Default is Allowed all the time. | Optional | 
| ssl_vpn_policy | Select SSL VPN policy. Default is No Policy Applied. | Optional | 
| clientless_policy | Select clientlesspolicy policy. Default is No Policy Applied. | Optional | 
| data_transfer_policy | Select the Data Transfer Policy. Default is 100 MB Total Data Transfer policy. | Optional | 
| simultaneous_logins_global | Enable Simultaneous Logins Global. Possible values are: Enable, Disable. Default is Enable. | Optional | 
| schedule_for_appliance_access | Select Schedule for appliance access. IMPORTANT: This option is available only for Administrators. Default is All The Time. | Optional | 
| qos_policy | Select the QoS Policy. Default is High Guarantee User. | Optional | 
| login_restriction | Select login restriction option. Possible values are: AnyNode, UserGroupNode. Default is UserGroupNode. | Optional | 


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
Delete an existing user.


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
| SophosFirewall.User.IsDeleted | String | Whether or not the user is deleted. | 


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
List all app policies. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-app-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Does the policy support microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Rules details | 


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
                                    "Proxyone",
                                    "SecureLine VPN",
                                    "Just Proxy VPN",
                                    "Reindeer VPN",
                                    "Sslbrowser Proxy",
                                    "Tunnelbear Proxy Login",
                                    "Proxy Switcher Proxy",
                                    "Yoga VPN",
                                    "VPN in Touch",
                                    "AOL Desktop",
                                    "Hide.Me",
                                    "Tiger VPN",
                                    "Proxifier Proxy",
                                    "Spinmyass Proxy",
                                    "ProXPN Proxy",
                                    "ItsHidden Proxy",
                                    "Betternet VPN",
                                    "Gtunnel Proxy",
                                    "WebFreer Proxy",
                                    "Nateon Proxy",
                                    "Power VPN",
                                    "Surf-for-free.com",
                                    "Ghostsurf Proxy",
                                    "Fly Proxy",
                                    "Vpntunnel Proxy",
                                    "Super VPN Master",
                                    "UltraVPN",
                                    "SOCK5 Proxy",
                                    "X-VPN",
                                    "Browsec VPN",
                                    "Proxycap Proxy",
                                    "VeePN",
                                    "SumRando",
                                    "TorrentHunter Proxy",
                                    "NetLoop VPN",
                                    "Hot VPN",
                                    "IP-Shield Proxy",
                                    "Hoxx Vpn",
                                    "Opera Off Road Mode",
                                    "Proxmachine Proxy",
                                    "VPN Monster",
                                    "Speedify",
                                    "The Pirate Bay Proxy",
                                    "VPN 360",
                                    "FreeMyBrowser",
                                    "uProxy",
                                    "Netevader Proxy",
                                    "Unclogger VPN",
                                    "Proxy-service.de Proxy",
                                    "Britishproxy.uk Proxy",
                                    "VPN over 443",
                                    "Zero VPN",
                                    "Kproxyagent Proxy",
                                    "Expatshield Proxy",
                                    "The Proxy Bay",
                                    "OpenDoor",
                                    "Snap VPN",
                                    "Ultrasurf Proxy",
                                    "Rxproxy Proxy",
                                    "Proxyway Proxy",
                                    "VyprVPN",
                                    "AppVPN",
                                    "BypassGeo",
                                    "Easy Proxy",
                                    "Ztunnel Proxy",
                                    "Onavo",
                                    "CoralCDN Proxy",
                                    "Office VPN",
                                    "Proton VPN",
                                    "Morphium.info",
                                    "HTTPort Proxy",
                                    "Tweakware VPN",
                                    "QQ VPN",
                                    "Redirection Web-Proxy",
                                    "HOS Proxy",
                                    "Hopster Proxy",
                                    "Dtunnel Proxy",
                                    "VPNium Proxy",
                                    "MeHide.asia",
                                    "FreeVPN Proxy",
                                    "Eagle VPN",
                                    "Glype Proxy",
                                    "Proxeasy Web Proxy",
                                    "HTTP Tunnel Proxy",
                                    "DotVPN",
                                    "Jailbreak VPN",
                                    "OneClickVPN Proxy",
                                    "Photon Flash Player & Browser",
                                    "Mega Proxy",
                                    "VPNMakers Proxy",
                                    "ShadeYouVPN",
                                    "Max-Anonysurf Proxy",
                                    "Proxeasy Proxy",
                                    "Tunnelbear Proxy Data",
                                    "Vedivi-VPN Proxy",
                                    "Private VPN",
                                    "Gapp Proxy",
                                    "Meebo Repeater Proxy",
                                    "Privitize VPN Proxy",
                                    "Tigervpns",
                                    "Cyazyproxy",
                                    "Hexa Tech VPN",
                                    "FinchVPN",
                                    "WiFree Proxy",
                                    "VPN Free",
                                    "Hideman VPN",
                                    "ShellFire VPN",
                                    "ExpressVPN",
                                    "EuropeProxy",
                                    "Hi VPN",
                                    "Frozenway Proxy",
                                    "Auto-Hide IP Proxy",
                                    "Gbridge VPN Proxy",
                                    "DNSCrypt",
                                    "ZPN VPN",
                                    "Skydur Proxy",
                                    "Hide-My-IP Proxy",
                                    "Hotspotshield Proxy",
                                    "Globosurf Proxy",
                                    "Blockless VPN",
                                    "Star VPN",
                                    "SurfEasy VPN",
                                    "RemoboVPN Proxy",
                                    "SSL Proxy Browser",
                                    "TurboVPN",
                                    "Air Proxy",
                                    "VPN Unlimited",
                                    "Astrill VPN",
                                    "Hello VPN",
                                    "SetupVPN",
                                    "ProxyWebsite",
                                    "Camoproxy Proxy",
                                    "TOR VPN",
                                    "Sslpro.org Proxy",
                                    "Bitcoin Proxy",
                                    "Worldcup Proxy",
                                    "Privatix VPN",
                                    "Psiphon Proxy",
                                    "4everproxy Proxy",
                                    "ProxyProxy",
                                    "SkyVPN",
                                    "Btunnel Proxy",
                                    "CProxy Proxy",
                                    "Amaze VPN",
                                    "PrivateSurf.us",
                                    "Real-Hide IP Proxy",
                                    "Wallcooler VPN Proxy",
                                    "England Proxy",
                                    "Gom VPN",
                                    "VPN Master",
                                    "Just Open VPN",
                                    "Tunnelier",
                                    "Bypasstunnel.com",
                                    "Packetix Proxy",
                                    "FastSecureVPN",
                                    "Dynapass Proxy",
                                    "Ctunnel Proxy",
                                    "Suresome Proxy",
                                    "Cyberoam Bypass Chrome Extension",
                                    "SkyEye VPN",
                                    "Circumventor Proxy",
                                    "CantFindMeProxy",
                                    "Kepard Proxy",
                                    "SoftEther VPN",
                                    "VPN Robot",
                                    "StrongVPN",
                                    "K Proxy",
                                    "Proxyfree Web Proxy",
                                    "FreeU Proxy",
                                    "VNN-VPN Proxy",
                                    "MoonVPN",
                                    "MiddleSurf Proxy",
                                    "Super VPN",
                                    "Invisiblenet VPN",
                                    "OpenInternet",
                                    "PHProxy",
                                    "Justproxy Proxy",
                                    "Cloud VPN",
                                    "RusVPN",
                                    "Kongshare Proxy",
                                    "PingTunnel Proxy",
                                    "Hide-IP Browser Proxy",
                                    "Securitykiss Proxy",
                                    "Njutrino Proxy",
                                    "Websurf",
                                    "Idhide Proxy",
                                    "Your-Freedom Proxy",
                                    "Chrome Reduce Data Usage",
                                    "ZenVPN",
                                    "Steganos Online Shield",
                                    "Freegate Proxy",
                                    "Puff Proxy",
                                    "Bypassfw Proxy",
                                    "Easy-Hide IP Proxy",
                                    "Classroom Spy",
                                    "CyberGhost VPN Proxy",
                                    "Simurgh Proxy",
                                    "ZenMate",
                                    "Hola",
                                    "Webproxy",
                                    "Unseen Online VPN",
                                    "Socks2HTTP Proxy",
                                    "Lok5 Proxy",
                                    "SSlunblock Proxy",
                                    "CyberghostVPN Web Proxy",
                                    "Zalmos SSL Web Proxy for Free",
                                    "My-Addr(SSL) Proxy",
                                    "Asproxy Web Proxy",
                                    "VPN 365",
                                    "Lantern",
                                    "HTTP-Tunnel Proxy",
                                    "Tor2Web Proxy",
                                    "Hiddenvillage Proxy",
                                    "Vpndirect Proxy",
                                    "FSecure Freedome VPN",
                                    "Hamachi VPN Streaming",
                                    "TOR Proxy",
                                    "Cocoon",
                                    "PD Proxy",
                                    "UK-Proxy.org.uk Proxy",
                                    "Avoidr Web Proxy",
                                    "Launchwebs Proxy",
                                    "Divavu Proxy",
                                    "I2P Proxy",
                                    "Proxify-Tray Proxy",
                                    "Alkasir Proxy",
                                    "Zelune Proxy",
                                    "Windscribe",
                                    "Proximize Proxy",
                                    "FastVPN",
                                    "SOCK4 Proxy",
                                    "Hide-Your-IP Proxy",
                                    "Aniscartujo Web Proxy",
                                    "Telex",
                                    "Proxysite.com Proxy",
                                    "Manual Proxy Surfing",
                                    "Private Tunnel",
                                    "Spotflux Proxy",
                                    "RealTunnel Proxy",
                                    "Epic Browser",
                                    "Green VPN",
                                    "Surrogofier Proxy",
                                    "GoldenKey VPN",
                                    "Operamini Proxy",
                                    "Mysslproxy Proxy",
                                    "Ninjaproxy.ninja",
                                    "VPN Lighter",
                                    "L2TP VPN",
                                    "uVPN",
                                    "Speedy VPN",
                                    "Toonel",
                                    "Reduh Proxy",
                                    "Anonymox",
                                    "Hide-N-Seek Proxy",
                                    "DashVPN",
                                    "Phantom VPN",
                                    "CrossVPN",
                                    "Tunnel Guru",
                                    "USA IP",
                                    "Total VPN",
                                    "ISAKMP VPN",
                                    "Hammer VPN",
                                    "RPC over HTTP Proxy",
                                    "Speed VPN",
                                    "PP VPN",
                                    "Pingfu Proxy",
                                    "JAP Proxy",
                                    "Private Internet Access VPN",
                                    "Thunder VPN",
                                    "skyZIP",
                                    "Invisible Surfing Proxy",
                                    "Vtunnel Proxy",
                                    "Haitun VPN",
                                    "Tunnello"
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
                                    "Proxyone",
                                    "SecureLine VPN",
                                    "Just Proxy VPN",
                                    "Reindeer VPN",
                                    "Sslbrowser Proxy",
                                    "Tunnelbear Proxy Login",
                                    "VzoChat Messenger",
                                    "Proxy Switcher Proxy",
                                    "Yoga VPN",
                                    "VPN in Touch",
                                    "Hide.Me",
                                    "Tiger VPN",
                                    "Proxifier Proxy",
                                    "Spinmyass Proxy",
                                    "ProXPN Proxy",
                                    "ItsHidden Proxy",
                                    "Betternet VPN",
                                    "Gtunnel Proxy",
                                    "DroidVPN",
                                    "WebFreer Proxy",
                                    "Nateon Proxy",
                                    "Power VPN",
                                    "Surf-for-free.com",
                                    "Ghostsurf Proxy",
                                    "GoBoogy Login P2P",
                                    "Fly Proxy",
                                    "Vpntunnel Proxy",
                                    "Super VPN Master",
                                    "UltraVPN",
                                    "SOCK5 Proxy",
                                    "X-VPN",
                                    "Browsec VPN",
                                    "Proxycap Proxy",
                                    "Schmedley Website",
                                    "VeePN",
                                    "SumRando",
                                    "TorrentHunter Proxy",
                                    "NetLoop VPN",
                                    "Hot VPN",
                                    "IP-Shield Proxy",
                                    "Hoxx Vpn",
                                    "Proxmachine Proxy",
                                    "VPN Monster",
                                    "Speedify",
                                    "The Pirate Bay Proxy",
                                    "VPN 360",
                                    "FreeMyBrowser",
                                    "uProxy",
                                    "Netevader Proxy",
                                    "Unclogger VPN",
                                    "Proxy-service.de Proxy",
                                    "Britishproxy.uk Proxy",
                                    "VPN over 443",
                                    "Zero VPN",
                                    "Kproxyagent Proxy",
                                    "Expatshield Proxy",
                                    "The Proxy Bay",
                                    "OpenDoor",
                                    "Snap VPN",
                                    "Ultrasurf Proxy",
                                    "Rxproxy Proxy",
                                    "Proxyway Proxy",
                                    "VyprVPN",
                                    "AppVPN",
                                    "BypassGeo",
                                    "Ztunnel Proxy",
                                    "CoralCDN Proxy",
                                    "Office VPN",
                                    "Proton VPN",
                                    "Morphium.info",
                                    "HTTPort Proxy",
                                    "Tweakware VPN",
                                    "QQ VPN",
                                    "Redirection Web-Proxy",
                                    "HOS Proxy",
                                    "Hopster Proxy",
                                    "Dtunnel Proxy",
                                    "VPNium Proxy",
                                    "MeHide.asia",
                                    "FreeVPN Proxy",
                                    "Eagle VPN",
                                    "Glype Proxy",
                                    "Proxeasy Web Proxy",
                                    "HTTP Tunnel Proxy",
                                    "DotVPN",
                                    "Jailbreak VPN",
                                    "OneClickVPN Proxy",
                                    "Photon Flash Player & Browser",
                                    "Mega Proxy",
                                    "VPNMakers Proxy",
                                    "ShadeYouVPN",
                                    "Max-Anonysurf Proxy",
                                    "Proxeasy Proxy",
                                    "Tunnelbear Proxy Data",
                                    "Vedivi-VPN Proxy",
                                    "Private VPN",
                                    "Gapp Proxy",
                                    "Meebo Repeater Proxy",
                                    "Privitize VPN Proxy",
                                    "Tigervpns",
                                    "Cyazyproxy",
                                    "Hexa Tech VPN",
                                    "FinchVPN",
                                    "WiFree Proxy",
                                    "VPN Free",
                                    "Hideman VPN",
                                    "ShellFire VPN",
                                    "ExpressVPN",
                                    "EuropeProxy",
                                    "Hi VPN",
                                    "Frozenway Proxy",
                                    "Auto-Hide IP Proxy",
                                    "iSwifter Games Browser",
                                    "Gbridge VPN Proxy",
                                    "DNSCrypt",
                                    "ZPN VPN",
                                    "Skydur Proxy",
                                    "Hide-My-IP Proxy",
                                    "Hotspotshield Proxy",
                                    "Globosurf Proxy",
                                    "Blockless VPN",
                                    "Star VPN",
                                    "RemoboVPN Proxy",
                                    "SSL Proxy Browser",
                                    "TurboVPN",
                                    "Air Proxy",
                                    "VPN Unlimited",
                                    "Astrill VPN",
                                    "Hello VPN",
                                    "SetupVPN",
                                    "ProxyWebsite",
                                    "Camoproxy Proxy",
                                    "TOR VPN",
                                    "Sslpro.org Proxy",
                                    "Bitcoin Proxy",
                                    "Worldcup Proxy",
                                    "Privatix VPN",
                                    "Psiphon Proxy",
                                    "4everproxy Proxy",
                                    "ProxyProxy",
                                    "SkyVPN",
                                    "Btunnel Proxy",
                                    "CProxy Proxy",
                                    "Amaze VPN",
                                    "PrivateSurf.us",
                                    "Real-Hide IP Proxy",
                                    "Wallcooler VPN Proxy",
                                    "England Proxy",
                                    "Gom VPN",
                                    "VPN Master",
                                    "Just Open VPN",
                                    "Tunnelier",
                                    "Bypasstunnel.com",
                                    "Packetix Proxy",
                                    "FastSecureVPN",
                                    "Dynapass Proxy",
                                    "Ctunnel Proxy",
                                    "Suresome Proxy",
                                    "Cyberoam Bypass Chrome Extension",
                                    "SkyEye VPN",
                                    "Circumventor Proxy",
                                    "CantFindMeProxy",
                                    "Kepard Proxy",
                                    "SoftEther VPN",
                                    "VPN Robot",
                                    "Puffin Web Browser",
                                    "K Proxy",
                                    "Proxyfree Web Proxy",
                                    "FreeU Proxy",
                                    "VNN-VPN Proxy",
                                    "MoonVPN",
                                    "MiddleSurf Proxy",
                                    "Super VPN",
                                    "Invisiblenet VPN",
                                    "OpenInternet",
                                    "PHProxy",
                                    "Justproxy Proxy",
                                    "Cloud VPN",
                                    "RusVPN",
                                    "Kongshare Proxy",
                                    "PingTunnel Proxy",
                                    "Hide-IP Browser Proxy",
                                    "Securitykiss Proxy",
                                    "Njutrino Proxy",
                                    "Websurf",
                                    "Idhide Proxy",
                                    "Your-Freedom Proxy",
                                    "Chrome Reduce Data Usage",
                                    "Hideninja VPN",
                                    "ZenVPN",
                                    "Freegate Proxy",
                                    "Puff Proxy",
                                    "Bypassfw Proxy",
                                    "Easy-Hide IP Proxy",
                                    "CyberGhost VPN Proxy",
                                    "Simurgh Proxy",
                                    "ZenMate",
                                    "Hola",
                                    "Webproxy",
                                    "Unseen Online VPN",
                                    "Socks2HTTP Proxy",
                                    "Lok5 Proxy",
                                    "SSlunblock Proxy",
                                    "CyberghostVPN Web Proxy",
                                    "Zalmos SSL Web Proxy for Free",
                                    "My-Addr(SSL) Proxy",
                                    "Asproxy Web Proxy",
                                    "VPN 365",
                                    "Lantern",
                                    "HTTP-Tunnel Proxy",
                                    "Tor2Web Proxy",
                                    "Hiddenvillage Proxy",
                                    "Vpndirect Proxy",
                                    "FSecure Freedome VPN",
                                    "Hamachi VPN Streaming",
                                    "TOR Proxy",
                                    "Cocoon",
                                    "PD Proxy",
                                    "UK-Proxy.org.uk Proxy",
                                    "Avoidr Web Proxy",
                                    "Launchwebs Proxy",
                                    "Divavu Proxy",
                                    "Proxify-Tray Proxy",
                                    "Alkasir Proxy",
                                    "Zelune Proxy",
                                    "Windscribe",
                                    "Proximize Proxy",
                                    "FastVPN",
                                    "Boinc Messenger",
                                    "SOCK4 Proxy",
                                    "Hide-Your-IP Proxy",
                                    "Aniscartujo Web Proxy",
                                    "Telex",
                                    "Proxysite.com Proxy",
                                    "Manual Proxy Surfing",
                                    "Private Tunnel",
                                    "RealTunnel Proxy",
                                    "Green VPN",
                                    "Surrogofier Proxy",
                                    "GoldenKey VPN",
                                    "Operamini Proxy",
                                    "Mysslproxy Proxy",
                                    "Ninjaproxy.ninja",
                                    "VPN Lighter",
                                    "L2TP VPN",
                                    "Speedy VPN",
                                    "Reduh Proxy",
                                    "Anonymox",
                                    "Hide-N-Seek Proxy",
                                    "OpenVPN",
                                    "DashVPN",
                                    "Phantom VPN",
                                    "CrossVPN",
                                    "Tunnel Guru",
                                    "USA IP",
                                    "Total VPN",
                                    "ISAKMP VPN",
                                    "Hammer VPN",
                                    "RPC over HTTP Proxy",
                                    "Speed VPN",
                                    "PP VPN",
                                    "Pingfu Proxy",
                                    "JAP Proxy",
                                    "Private Internet Access VPN",
                                    "Thunder VPN",
                                    "skyZIP",
                                    "Invisible Surfing Proxy",
                                    "Vtunnel Proxy",
                                    "Haitun VPN",
                                    "Tunnello"
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
                                    "Proxyone",
                                    "SecureLine VPN",
                                    "Modbus - Get Comm Event Counter",
                                    "Just Proxy VPN",
                                    "FreeU VOIP",
                                    "Google Chrome Installer",
                                    "Tunnelbear Proxy Login",
                                    "Direct Operate - No Ack",
                                    "Mail-ru Messenger",
                                    "Facebook Pics Upload",
                                    "Yoga VPN",
                                    "Facebook Chat",
                                    "Kaseya Client Connect",
                                    "Supervisory Functions",
                                    "Authentication Request",
                                    "VPN in Touch",
                                    "Rediffbol Messenger",
                                    "ComodoUnite IM",
                                    "Authentication Request - No Ack",
                                    "AOL Desktop",
                                    "Hide.Me",
                                    "Proxifier Proxy",
                                    "NeverMail WebMail",
                                    "PetSociety-Facebook Games",
                                    "Blogger Post Blog",
                                    "ItsHidden Proxy",
                                    "Gtunnel Proxy",
                                    "QQ Messenger",
                                    "DeskShare Remote Access",
                                    "Authentication Challenge",
                                    "Power VPN",
                                    "DAP Download",
                                    "Return Diagnostic Register",
                                    "GoBoogy Login P2P",
                                    "TelTel VOIP",
                                    "AIM Express Messenger",
                                    "Super VPN Master",
                                    "iCAP Business",
                                    "WikiEncyclopedia Android",
                                    "X-VPN",
                                    "Friendfeed Web Login",
                                    "Proxycap Proxy",
                                    "Optimum WebMail",
                                    "VeePN",
                                    "UbuntuOne FileTransfer",
                                    "TripAdvisor Android",
                                    "VNC Web Remote Access",
                                    "Justvoip VOIP",
                                    "Hot VPN",
                                    "DNP3 - Confirm",
                                    "Livedoor Web Login",
                                    "Opera Off Road Mode",
                                    "Clear Counters and Diag. Reg",
                                    "Citrix Receiver",
                                    "Techinline Conferencing",
                                    "Broad. Req. from Autho. Client",
                                    "DNP3 - Delete File",
                                    "Speedify",
                                    "VPN 360",
                                    "RSS Feeds",
                                    "FreeMyBrowser",
                                    "uProxy",
                                    "CafeWorld-Facebook Games",
                                    "SkyFex Conferencing",
                                    "Jabber Protocol",
                                    "TreasureIsle-Facebook Games",
                                    "Tango Android",
                                    "Britishproxy.uk Proxy",
                                    "NDTV Android",
                                    "Facebook Pics Download",
                                    "VPN over 443",
                                    "Zero VPN",
                                    "Plugoo Widget",
                                    "Seasms Messenger",
                                    "Ventrilo VOIP",
                                    "MSN2GO Messenger",
                                    "The Proxy Bay",
                                    "Snap VPN",
                                    "Ultrasurf Proxy",
                                    "Bacnet - AtomicReadFile Service",
                                    "Sina WebMail",
                                    "VyprVPN",
                                    "BypassGeo",
                                    "Meetup Android",
                                    "Seesmic VOIP",
                                    "Easy Proxy",
                                    "Modbus - Write Single Coil",
                                    "Onavo",
                                    "Modbus - Read Discrete Inputs",
                                    "Proton VPN",
                                    "Freeze and Clear-Freeze at Time",
                                    "Morphium.info",
                                    "HTTPort Proxy",
                                    "Modbus - Return Query Data",
                                    "QQ VPN",
                                    "Redirection Web-Proxy",
                                    "Hi5 Website",
                                    "Gtalk Messenger Voice Chat",
                                    "WebRDP Remote Access",
                                    "MeHide.asia",
                                    "Eagle VPN",
                                    "Proxeasy Web Proxy",
                                    "HTTP Tunnel Proxy",
                                    "DotVPN",
                                    "VPNMakers Proxy",
                                    "Enable Unsolicited Responses",
                                    "Max-Anonysurf Proxy",
                                    "Google App Engine",
                                    "Tunnelbear Proxy Data",
                                    "Vedivi-VPN Proxy",
                                    "Etisalat Messenger",
                                    "Kool Web Messenger",
                                    "Private VPN",
                                    "Gree.jp WebMail Login",
                                    "Meebo Repeater",
                                    "Meebo Repeater Proxy",
                                    "DNP3 - Freeze and Clear",
                                    "Tigervpns",
                                    "Return Bus Exception Error Count",
                                    "CodeAnywhere Android",
                                    "FinchVPN",
                                    "Orange Dialer VOIP",
                                    "WiFree Proxy",
                                    "Hideman VPN",
                                    "ShellFire VPN",
                                    "Amazon Iphone",
                                    "EuropeProxy",
                                    "Adobe Connect Conferencing",
                                    "Frozenway Proxy",
                                    "Google Analytic",
                                    "Facebook Applications",
                                    "IAX VOIP",
                                    "X-Fire Messenger",
                                    "BookMyShow Android",
                                    "DNP3 - Activate Configuration",
                                    "ZPN VPN",
                                    "Garena Web Messenger",
                                    "Hotspotshield Proxy",
                                    "Blockless VPN",
                                    "IMO Messenger",
                                    "SurfEasy VPN",
                                    "RemoboVPN Proxy",
                                    "SetupVPN",
                                    "Trillian Messenger",
                                    "DNP3 - Operate",
                                    "Camoproxy Proxy",
                                    "QQ Web Messenger",
                                    "TOR VPN",
                                    "Worldcup Proxy",
                                    "Privatix VPN",
                                    "ICQ Messenger",
                                    "ProxyProxy",
                                    "SkyVPN",
                                    "CProxy Proxy",
                                    "Amaze VPN",
                                    "PrivateSurf.us",
                                    "DirectTV Android",
                                    "Genesys Website",
                                    "Modbus - Mask Write Register",
                                    "Zoho Meeting Conferencing",
                                    "vBuzzer Android",
                                    "Camfrog Messenger",
                                    "Last.FM Client Streaming",
                                    "Gom VPN",
                                    "VPN Master",
                                    "Mail-ru WebMail",
                                    "DNP3 - Warm Restart",
                                    "Baofeng Website",
                                    "PC-Visit Remote Access",
                                    "iTunes Internet",
                                    "Bypasstunnel.com",
                                    "Cold Restart From Autho. Client",
                                    "Dynapass Proxy",
                                    "Zenbe WebMail",
                                    "Cyberoam Bypass Chrome Extension",
                                    "Google Translate Android",
                                    "Fring Android",
                                    "Kepard Proxy",
                                    "Yugma Web Conferencing",
                                    "WLM Voice and Video Chat",
                                    "Modbus - Read FIFO Queue",
                                    "DNP3 - Open File",
                                    "Vyew WebRDP",
                                    "Vsee VOIP",
                                    "Puffin Web Browser",
                                    "StrongVPN",
                                    "Nateon Messenger",
                                    "Instant-t Messenger",
                                    "K Proxy",
                                    "DNP3 - Select",
                                    "FreeU Proxy",
                                    "LinkedIN Compose Webmail",
                                    "Facebook Plugin",
                                    "ICQ2GO Messenger",
                                    "Read/Write Multiple Registers",
                                    "Invisiblenet VPN",
                                    "PC-Anywhere Remote Access",
                                    "Twitter Limited Access",
                                    "Moviefone Android",
                                    "Elluminate Remote Conferencing",
                                    "PHProxy",
                                    "Cloud VPN",
                                    "RusVPN",
                                    "Flickr Website",
                                    "Kongshare Proxy",
                                    "IMPlus Web Messenger",
                                    "Mute P2P",
                                    "Return Slave Message Count",
                                    "Facebook Website",
                                    "PingTunnel Proxy",
                                    "Itunes Update",
                                    "NateMail WebMail",
                                    "Securitykiss Proxy",
                                    "Njutrino Proxy",
                                    "iLoveIM Web Messenger",
                                    "Chrome Reduce Data Usage",
                                    "Kaseya Portal Login",
                                    "Meebo Iphone",
                                    "Hideninja VPN",
                                    "Caihong Messenger",
                                    "Hangame",
                                    "Steganos Online Shield",
                                    "Easy-Hide IP Proxy",
                                    "Classroom Spy",
                                    "TokBox VOIP",
                                    "OoVoo VOIP",
                                    "ZenMate",
                                    "Hola",
                                    "Webproxy",
                                    "LinkedIN Mail Inbox",
                                    "DNP3 - Initialize Data",
                                    "CyberghostVPN Web Proxy",
                                    "Zalmos SSL Web Proxy for Free",
                                    "MSN",
                                    "Lantern",
                                    "Google Location",
                                    "MxiT Android",
                                    "Tor2Web Proxy",
                                    "Bacnet - AtomicWriteFile Service",
                                    "FSecure Freedome VPN",
                                    "DNP3 - Writes",
                                    "TOR Proxy",
                                    "Cocoon",
                                    "PD Proxy",
                                    "LogMeIn Remote Access",
                                    "UK-Proxy.org.uk Proxy",
                                    "Salesforce Web Login",
                                    "LinkedIN Android",
                                    "Windscribe",
                                    "Bacnet - Read Property Multiple",
                                    "Scydo Android",
                                    "WebAgent.Mail-ru Messenger",
                                    "DimDim Website",
                                    "Dameware Mini Remote Access",
                                    "FastVPN",
                                    "ShowMyPC Conferencing",
                                    "Boinc Messenger",
                                    "SOCK4 Proxy",
                                    "GMX WebMail",
                                    "CNN News Android",
                                    "Telex",
                                    "Unconfirmed i-HAVE Service",
                                    "Proxysite.com Proxy",
                                    "ISL Desktop Conferencing",
                                    "ICQ Android",
                                    "Blogger Create Blog",
                                    "RealTunnel Proxy",
                                    "Epic Browser",
                                    "DNP3 - Get File Information",
                                    "Surrogofier Proxy",
                                    "GoldenKey VPN",
                                    "Operamini Proxy",
                                    "E-Bay Android",
                                    "Modbus - Return Slave Busy Count",
                                    "DNP3 - Authenticate File",
                                    "Bacnet - Timesync Service",
                                    "Bacnet Protocol Traffic",
                                    "L2TP VPN",
                                    "DNP3 - Immediate Freeze",
                                    "Modbus - Read Holding Registers",
                                    "Modbus - Get Comm Event Log",
                                    "Phantom VPN",
                                    "AirAIM Messenger",
                                    "DNP3 - Start Application",
                                    "Tunnel Guru",
                                    "USA IP",
                                    "Total VPN",
                                    "Web.De WebMail",
                                    "Metin Game",
                                    "Modbus - Write Multiple Coils",
                                    "Yuuguu Conferencing",
                                    "Hootsuite Web Login",
                                    "Google Translate",
                                    "NateApp Android",
                                    "IEC.60870.5.104 - STARTDT CON",
                                    "Bomgar Remote Conferencing",
                                    "MillionaireCity-Facebook Games",
                                    "JAP Proxy",
                                    "Private Internet Access VPN",
                                    "NetOP Ondemand Conferencing",
                                    "Crossloop Remote Access",
                                    "Return Bus Comm. Error Count",
                                    "Tunnello",
                                    "Google Toolbar",
                                    "LiveMeeting VOIP",
                                    "Reindeer VPN",
                                    "MeeboMe Plugin",
                                    "IEC.60870.5.104 - TESTFR CON",
                                    "Change ASCII Input Delimiter",
                                    "Proxy Switcher Proxy",
                                    "Headcall VOIP",
                                    "Modbus - Write File Record",
                                    "DNP3 - Direct Operate",
                                    "Glide Conferencing",
                                    "Tiger VPN",
                                    "Jabber",
                                    "ScreenStream Remote Access",
                                    "Write Multiple Registers",
                                    "RemotelyAnywhere Remote Access",
                                    "ProXPN Proxy",
                                    "AOL WebMail",
                                    "Betternet VPN",
                                    "Fuel Coupons Android",
                                    "DroidVPN",
                                    "Nateon Proxy",
                                    "Surf-for-free.com",
                                    "Ghostsurf Proxy",
                                    "IEC.60870.5.104 - Single Command",
                                    "Fly Proxy",
                                    "DNP3 - Assign Class",
                                    "UltraVPN",
                                    "Yahoo IM Voice and Video Chat",
                                    "SOCK5 Proxy",
                                    "SumRando",
                                    "TorrentHunter Proxy",
                                    "NetLoop VPN",
                                    "Hoxx Vpn",
                                    "Chikka Web Messenger",
                                    "Mig33 Android",
                                    "Gizmo5 VOIP",
                                    "VPN Monster",
                                    "Fetion Messenger",
                                    "Puffin Academy",
                                    "Propel Accelerator",
                                    "x11 Conferencing",
                                    "Hush WebMail",
                                    "The Pirate Bay Proxy",
                                    "Google Plus Website",
                                    "Digsby Messenger",
                                    "COX WebMail",
                                    "DNP3 - Initialize Application",
                                    "Sightspeed VOIP",
                                    "Unclogger VPN",
                                    "Mail.com WebMail",
                                    "Interrogation Command",
                                    "SugarSync FileTransfer",
                                    "Expatshield Proxy",
                                    "MSN-Way2SMS WebMail",
                                    "Imhaha Web Messenger",
                                    "Camfrog VOIP",
                                    "Line Messenger",
                                    "Proxyway Proxy",
                                    "Clear Overrun Counter and Flag",
                                    "AppVPN",
                                    "Vyew Website",
                                    "Return Bus Char. Overrun Count",
                                    "CoralCDN Proxy",
                                    "Office VPN",
                                    "Modbus - Return Slave NAK Count",
                                    "Eyejot Web Messenger",
                                    "Gtalk Messenger",
                                    "Modbus - Read Input Registers",
                                    "Tweakware VPN",
                                    "HOS Proxy",
                                    "Timbuktu Remote Conferencing",
                                    "Hopster Proxy",
                                    "TalkBox Android",
                                    "VPNium Proxy",
                                    "FreeVPN Proxy",
                                    "AirVideo",
                                    "PalTalk Messenger",
                                    "Mafia Wars-Facebook Games",
                                    "Glype Proxy",
                                    "Mobyler Android",
                                    "Fastmail Webmail",
                                    "Call Of Duty 4 Game",
                                    "Unconfirmed i-AM Service",
                                    "Jailbreak VPN",
                                    "Facebook Video Chat",
                                    "ExchangeRates Android",
                                    "IMVU Messenger",
                                    "OneClickVPN Proxy",
                                    "DNP3 - Abort File",
                                    "Photon Flash Player & Browser",
                                    "Mega Proxy",
                                    "Meebo Website",
                                    "ShadeYouVPN",
                                    "Eroom Website",
                                    "BBC News Android",
                                    "Proxeasy Proxy",
                                    "Odnoklassniki Web Messenger",
                                    "Restart Communications Option",
                                    "QQ WebMail",
                                    "Cyazyproxy",
                                    "Hexa Tech VPN",
                                    "VPN Free",
                                    "ExpressVPN",
                                    "DNP3 - Freeze at Time - No Ack",
                                    "Hi VPN",
                                    "WLM Login",
                                    "Modbus - Read Exception Status",
                                    "Facebook Video Upload",
                                    "Fastviewer Conferencing",
                                    "Auto-Hide IP Proxy",
                                    "DNP3 - Freeze and Clear - No Ack",
                                    "iSwifter Games Browser",
                                    "Read device Identification",
                                    "Gbridge VPN Proxy",
                                    "Timbuktu DesktopMail",
                                    "DNSCrypt",
                                    "Return Bus Message Count",
                                    "LiveMeeting Conferencing",
                                    "Skydur Proxy",
                                    "Hide-My-IP Proxy",
                                    "Globosurf Proxy",
                                    "Star VPN",
                                    "FarmVille-Facebook Games",
                                    "SSL Proxy Browser",
                                    "TurboVPN",
                                    "VPN Unlimited",
                                    "AIM Messenger",
                                    "Bacnet - Read Property",
                                    "Astrill VPN",
                                    "Hello VPN",
                                    "ProxyWebsite",
                                    "RDMPlus Remote Access",
                                    "Palringo Messenger",
                                    "Poker-Facebook Games",
                                    "Bejeweled-Facebook Games",
                                    "Unsolicited Auth. Challenge",
                                    "Bitcoin Proxy",
                                    "DNP3 - Delay Measurement",
                                    "Serv-U Remote Access",
                                    "Bacnet - Reinitializdevice",
                                    "Force Listen Only Mode",
                                    "Google Desktop Application",
                                    "Psiphon Proxy",
                                    "GoChat Android",
                                    "MyGreen-PC Remote Access",
                                    "Real-Hide IP Proxy",
                                    "Daum WebMail",
                                    "PI-Chat Messenger",
                                    "England Proxy",
                                    "Ebuddy Web Messenger",
                                    "Internet Download Manager",
                                    "Qeep Android",
                                    "Lontalk Traffic",
                                    "Just Open VPN",
                                    "Tunnelier",
                                    "IEC.60870.5.104 - STARTDT ACT",
                                    "Packetix Proxy",
                                    "Yahoo Messenger",
                                    "AIM Android",
                                    "FastSecureVPN",
                                    "Suresome Proxy",
                                    "SkyEye VPN",
                                    "Circumventor Proxy",
                                    "Ebuddy Android",
                                    "Unconfirmed who-is Service",
                                    "CantFindMeProxy",
                                    "Yoics Conferencing",
                                    "Modbus - Read Coils",
                                    "Supremo Remote Access",
                                    "SoftEther VPN",
                                    "Ali WangWang Remote Access",
                                    "Session Initiation Protocol",
                                    "VPN Robot",
                                    "MessengerFX",
                                    "DNP3 - Record Current Time",
                                    "Avaya Conferencing",
                                    "DNP3 - Save Configuration",
                                    "LiveGO Messenger",
                                    "VNN-VPN Proxy",
                                    "Device Communication Control",
                                    "R-Exec Remote Access",
                                    "Facebook Message",
                                    "Facebook Games",
                                    "MoonVPN",
                                    "MiddleSurf Proxy",
                                    "Super VPN",
                                    "GaduGadu Web Messenger",
                                    "OpenInternet",
                                    "NetViewer Conferencing",
                                    "Stickam VOIP",
                                    "Flickr Web Upload",
                                    "Jump Desktop Remote Access",
                                    "Garena Messenger",
                                    "Friendster Web Login",
                                    "Facebook Limited Access",
                                    "Hide-IP Browser Proxy",
                                    "Gtalk Android",
                                    "RemoteShell Remote Access",
                                    "Websurf",
                                    "Yahoo WebMail",
                                    "Mikogo Conferencing",
                                    "Your-Freedom Proxy",
                                    "Vyew Web Login",
                                    "AIM Messenger VOIP",
                                    "Gmail WebMail",
                                    "AIM Website",
                                    "DNP3 - Stop Application",
                                    "ZenVPN",
                                    "Netease WebMail",
                                    "Freegate Proxy",
                                    "Google Safebrowsing",
                                    "IEC.60870.5.104 - Double Command",
                                    "Palringo Web Messenger",
                                    "iChat Gtalk",
                                    "Teamsound VOIP",
                                    "CyberGhost VPN Proxy",
                                    "Simurgh Proxy",
                                    "Bacnet - Write Property",
                                    "Modbus - Diagnostics",
                                    "Unseen Online VPN",
                                    "Socks2HTTP Proxy",
                                    "Asproxy Web Proxy",
                                    "DNP3 - Close File",
                                    "Zedge Android",
                                    "VPN 365",
                                    "Chikka Messenger",
                                    "Modbus - Report Slave ID",
                                    "Korea WebMail",
                                    "HTTP-Tunnel Proxy",
                                    "DNP3 - Read",
                                    "TruPhone Android",
                                    "Hamachi VPN Streaming",
                                    "Launchwebs Proxy",
                                    "Google Earth Application",
                                    "I2P Proxy",
                                    "Alkasir Proxy",
                                    "Zelune Proxy",
                                    "Yugma Conferencing",
                                    "Hide-Your-IP Proxy",
                                    "Hyves WebMail",
                                    "FrontierVille-Facebook Games",
                                    "IEC.60870.5.104 - TESTFR ACT",
                                    "Trillian Web Messenger",
                                    "Manual Proxy Surfing",
                                    "Authentication Response",
                                    "Yahoo Messenger Chat",
                                    "VoipTalk VOIP",
                                    "Immediate Freeze - No Ack",
                                    "Private Tunnel",
                                    "Spotflux Proxy",
                                    "TeamViewer Conferencing",
                                    "Serv-U RemoteAccess FileTransfer",
                                    "Outlook.com",
                                    "Green VPN",
                                    "Digg Web Login",
                                    "Android Market",
                                    "Windows Remote Desktop",
                                    "Engadget Android",
                                    "Ninjaproxy.ninja",
                                    "WeBuzz Web Messenger",
                                    "VPN Lighter",
                                    "Synergy Remote Access",
                                    "YahooMail Calendar",
                                    "uVPN",
                                    "Speedy VPN",
                                    "Modbus - Write Single Register",
                                    "Reduh Proxy",
                                    "Soonr Conferencing",
                                    "CB Radio Chat Android",
                                    "Anonymox",
                                    "Hide-N-Seek Proxy",
                                    "OpenVPN",
                                    "DashVPN",
                                    "CrossVPN",
                                    "ISAKMP VPN",
                                    "Google Cache Search",
                                    "Hammer VPN",
                                    "RPC over HTTP Proxy",
                                    "Speed VPN",
                                    "Disable Unsolicited Responses",
                                    "IM+ Android",
                                    "GaduGadu Messenger",
                                    "Spy-Agent Remote Access",
                                    "PP VPN",
                                    "Pingfu Proxy",
                                    "PhoneMyPC Remote Access",
                                    "Thunder VPN",
                                    "MindJolt-Facebook Games",
                                    "skyZIP",
                                    "Invisible Surfing Proxy",
                                    "Vtunnel Proxy",
                                    "Uusee Streaming",
                                    "SCCP VOIP",
                                    "Regulating Step Command",
                                    "Haitun VPN",
                                    "Return Slave No Response Count",
                                    "KiK Messenger Android",
                                    "OpenWebMail"
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
            },
            {
                "DefaultAction": "Allow",
                "Description": "Drops generally unwanted applications traffic. This includes file transfer apps, proxy & tunnel apps, risk prone apps, peer to peer networking (P2P) apps and apps that causes loss of productivity.",
                "IsDeleted": false,
                "MicroAppSupport": "True",
                "Name": "Block generally unwanted apps",
                "RuleList": {
                    "Rule": [
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "VeryCD",
                                    "Piolet Initialization P2P",
                                    "Bearshare P2P",
                                    "Pando P2P",
                                    "DirectConnect P2P",
                                    "Manolito P2P Download",
                                    "Apple-Juice P2P",
                                    "Fileguri P2P",
                                    "Stealthnet P2P",
                                    "Vuze P2P",
                                    "100BAO P2P",
                                    "NapMX Retrieve P2P",
                                    "Peercast P2P",
                                    "Morpheus P2P",
                                    "Miro P2P",
                                    "SoMud",
                                    "QQ Download P2P",
                                    "Ants Initialization P2P",
                                    "Soulseek Download P2P",
                                    "Torrent Clients P2P",
                                    "Imesh P2P",
                                    "Freenet P2P",
                                    "Kugoo Playlist P2P",
                                    "Phex P2P",
                                    "Soulseek Retrieving P2P",
                                    "Mute P2P",
                                    "Winny P2P",
                                    "Piolet FileTransfer P2P",
                                    "MP3 Rocket Download",
                                    "Klite Initiation P2P",
                                    "Flashget P2P",
                                    "Shareaza P2P",
                                    "DC++ Hub List P2P",
                                    "eMule P2P",
                                    "Manolito P2P Search",
                                    "Soul Attempt P2P",
                                    "Ants IRC Connect P2P",
                                    "WinMX P2P",
                                    "GoBoogy Login P2P",
                                    "DC++ Download P2P",
                                    "Napster P2P",
                                    "LimeWire",
                                    "Ares P2P",
                                    "Manolito P2P Connect",
                                    "Tixati P2P",
                                    "Gnutella P2P",
                                    "Manolito P2P GetServer List",
                                    "MediaGet P2P",
                                    "Ants P2P",
                                    "DC++ Connect P2P"
                                ]
                            },
                            "CategoryList": {
                                "Category": "P2P"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "vPorn",
                                    "Telenet.be Web Mail",
                                    "Bitrix24",
                                    "Facebook Pics Upload",
                                    "Mutants: Genetic Galdiators",
                                    "Saavn Android",
                                    "DeskGate",
                                    "Cozycot Website",
                                    "iFood",
                                    "PetSociety-Facebook Games",
                                    "Happyfox",
                                    "Hospitalityclub Website",
                                    "Plurk Website",
                                    "IMO Video Calling",
                                    "Circle of Moms",
                                    "Dailyfx",
                                    "Power VPN",
                                    "Abu Dhabi Taxi",
                                    "Cyworld Website",
                                    "Gapyear Website",
                                    "Java Update",
                                    "Pig & Dragon",
                                    "Pockets - ICICI Bank",
                                    "Marco Polo Video Walkie Talkie",
                                    "DeepL Translator",
                                    "iBabs",
                                    "Librarything Website",
                                    "Friendfeed Web Login",
                                    "Magnatune Audio Streaming",
                                    "Freshbooks",
                                    "Wrike",
                                    "Tiexue",
                                    "Ali Qin Tao",
                                    "Wave Accounting",
                                    "Bing Image Search",
                                    "Cash IT Back",
                                    "Dxy Website",
                                    "WeChat",
                                    "Shutterfly Photo Upload",
                                    "Hatena",
                                    "Jibjab Website",
                                    "Provide Support",
                                    "Motherofporn Video Streaming",
                                    "Lost Bubbles",
                                    "FreeMyBrowser",
                                    "uProxy",
                                    "Ariba",
                                    "Turbobit Download",
                                    "Friendica Website",
                                    "Cnxp BBS",
                                    "Facebook Pics Download",
                                    "Duba Update",
                                    "Facebook Messenger",
                                    "Livestream Website",
                                    "Bubbly",
                                    "BINGO Blitz",
                                    "Infogram",
                                    "Plus7",
                                    "Action VoIP",
                                    "MQTT",
                                    "Nokia Website",
                                    "Nextdoor",
                                    "Help Scout",
                                    "PasteBin",
                                    "Nymgo VoIP Dialer",
                                    "Google Plus Post",
                                    "TechRepublic",
                                    "Bebo Posting",
                                    "Proton VPN",
                                    "MTV Website",
                                    "Internations Website",
                                    "QQ VPN",
                                    "ADP Download Document",
                                    "Redbooth",
                                    "Hi5 Website",
                                    "Zoo Website",
                                    "Facebook Posting",
                                    "Spinjay Website",
                                    "ICUII Web Messenger",
                                    "CNN Video Streaming",
                                    "Blizzard Client",
                                    "DEAD TRIGGER 2",
                                    "Reverbnation Website",
                                    "Rutube Streaming",
                                    "Fotki Website",
                                    "ServiceTitan",
                                    "Apple News",
                                    "Fubar Website",
                                    "Pcperformer Update",
                                    "Train Station",
                                    "Clarin Web Video Streaming",
                                    "Nimbuzz Blackberry Messenger",
                                    "Tigervpns",
                                    "DrTuber",
                                    "NiMO TV",
                                    "Happy Family",
                                    "Daum Cafe",
                                    "SmartFoxServer",
                                    "Facebook Status Update",
                                    "Wer-kennt-wen Website",
                                    "PizzaHut",
                                    "Soulseek Retrieving P2P",
                                    "Your freedom Update",
                                    "CoStar Real Estate Manager",
                                    "Naked Streaming",
                                    "Monster Legends",
                                    "BookMyShow Android",
                                    "ZPN VPN",
                                    "ShareChat",
                                    "TVFPlay",
                                    "Curiouscast",
                                    "Putlocker Download",
                                    "Sage One",
                                    "SurfEasy VPN",
                                    "MotleyFool",
                                    "PVR Cinemas",
                                    "500px",
                                    "Anobii Website",
                                    "LovePhoto FacebookApp",
                                    "My18tube Streaming",
                                    "CryptoCompare",
                                    "NBC News",
                                    "Stagevu Streaming",
                                    "Cmjornal",
                                    "Backblaze Personal Backup",
                                    "LimeWire",
                                    "Blizzard Downloader",
                                    "Chromeriver",
                                    "Omerta",
                                    "Privatix VPN",
                                    "Twitter Website",
                                    "HDpornstar Video Streaming",
                                    "VeryCD",
                                    "Xici",
                                    "Streamaudio Streaming",
                                    "Amaze VPN",
                                    "Plex",
                                    "24chasa",
                                    "Microsoft Media Server Protocol",
                                    "MySpace.cn Website",
                                    "TLVMedia",
                                    "Travellerspoint Website",
                                    "Moneycontrol Markets on Mobile",
                                    "Zattoo Streaming",
                                    "Doodle",
                                    "Qianlong BBS",
                                    "BanaCast",
                                    "Pornerbros Streaming",
                                    "MindBody",
                                    "Care360",
                                    "Five9",
                                    "Kuwo.cn Web Music Streaing",
                                    "Flow Game",
                                    "Zoosk",
                                    "4399.com",
                                    "Meettheboss Video Streaming",
                                    "Square",
                                    "Eporner Video Streaming",
                                    "Fuelmyblog Website",
                                    "Odnoklassniki Android",
                                    "Napster P2P",
                                    "UltraViewer",
                                    "StrongVPN",
                                    "Windows MediaPlayer Update",
                                    "World Of Warcraft Game",
                                    "MTV Asia",
                                    "RealTime Messaging Protocol",
                                    "MyTokri",
                                    "CBC",
                                    "ThisAV",
                                    "JioCinema",
                                    "Social Wars",
                                    "Facebook Like",
                                    "Dol2day Website",
                                    "Pipedrive Download",
                                    "AnyMeeting Connect",
                                    "IDBI Bank Go Mobile",
                                    "8 Ball Pool",
                                    "Cloud VPN",
                                    "Seismic",
                                    "WebEngage",
                                    "PressReader",
                                    "Cookie Jam",
                                    "Soliter Arena",
                                    "MyTeksi",
                                    "Egnyte Download",
                                    "Bubble Witch Saga",
                                    "Hay Day",
                                    "Workday",
                                    "Chrome Reduce Data Usage",
                                    "BlueStacks Cloud Connect",
                                    "Candy Crush Saga",
                                    "ZOL",
                                    "Rubicon Project",
                                    "AvidXchange",
                                    "IBM CXN Cloud Files",
                                    "Imgur",
                                    "Travbuddy Website",
                                    "Ask.fm",
                                    "Webproxy",
                                    "HelloByte Dialer",
                                    "Gather Website",
                                    "Grooveshark Music Streaming",
                                    "YuppTV Streaming",
                                    "Yahoo Groups",
                                    "Playwire",
                                    "Archaeology",
                                    "ULLU Video Streaming",
                                    "Monster Resume Upload",
                                    "Wakoopa Website",
                                    "Transport Stream",
                                    "McAfee Update",
                                    "Cocoon",
                                    "Facebook Commenting",
                                    "Piolet FileTransfer P2P",
                                    "Gamerdna Website",
                                    "163 BBS",
                                    "Safari Escape",
                                    "Timesheets",
                                    "Extreme Road Trip 2",
                                    "BabyCenter",
                                    "Videobash Video Streaming",
                                    "AstroSage Kundli",
                                    "FastVPN",
                                    "Rambler Website",
                                    "Craigslist Android",
                                    "Quantcast",
                                    "LinkedIN Universities Search",
                                    "Kotak Bank Mobile Application",
                                    "LinkedIN Profile Download",
                                    "Airbnb",
                                    "Orgasm Video Streaming",
                                    "MediaGet P2P",
                                    "ICICI Mobile Banking-iMobile",
                                    "MLB",
                                    "GoldenKey VPN",
                                    "Yandex Search",
                                    "Marketland",
                                    "Oracle Sales Cloud",
                                    "Aaj Tak News",
                                    "Raaga Streaming",
                                    "Facebook Chat on YahooMail",
                                    "Pengle",
                                    "Sina Games",
                                    "Times of India",
                                    "Baidu Tieba",
                                    "SnappyTV",
                                    "Elixio Website",
                                    "YouTube Comment",
                                    "TrendMicro SafeSync",
                                    "Bayfiles Upload",
                                    "Real Player Update",
                                    "Shopify App Store",
                                    "Tvtonic Streaming",
                                    "Total VPN",
                                    "LinkedIN Companies",
                                    "Monday",
                                    "SAS OnDemand",
                                    "Reuters",
                                    "Chinaren Club",
                                    "Orbitz",
                                    "Google Allo",
                                    "QuickBooks",
                                    "School-communicator",
                                    "AudioBoom",
                                    "Prezi",
                                    "Putlocker Upload",
                                    "Realnudeart Website",
                                    "Reindeer VPN",
                                    "Bored Website",
                                    "Megapolis",
                                    "Dainik Bhaskar Streaming",
                                    "Comm100",
                                    "Twtkr Search",
                                    "Club Cooee Messenger",
                                    "Tubemate",
                                    "Line Call",
                                    "Axifile File Transfer",
                                    "Rival Kingdoms",
                                    "Bank of Baroda M-Connect",
                                    "Songbird Update",
                                    "Bitshare Download",
                                    "51.COM Games",
                                    "Fan FacebookApp",
                                    "Brightcove Media",
                                    "Quote.com",
                                    "Mixer \u2013 Interactive Streaming",
                                    "Booking",
                                    "SnapBuy",
                                    "TubeMogul",
                                    "Tinder",
                                    "Panda Jam",
                                    "Zendesk",
                                    "Tiger VPN",
                                    "Disaboom Website",
                                    "Egnyte Device List",
                                    "Plustransfer Upload",
                                    "TrialMadness Facebook Game",
                                    "Teachertube",
                                    "Lark",
                                    "Shopify Admin",
                                    "We Heart It Upload",
                                    "Surf-for-free.com",
                                    "MyUniverse",
                                    "Goibibo",
                                    "Blackboard",
                                    "1Fichier Download",
                                    "Diamond Dash",
                                    "UltraVPN",
                                    "Exploroo Website",
                                    "Citrix Online",
                                    "Pinterest Repin",
                                    "SIP Request",
                                    "Lynda.com Video Streaming",
                                    "Hoxx Vpn",
                                    "News UK",
                                    "Quick Base",
                                    "Imlive Streaming",
                                    "Lifehacker",
                                    "CarTrade",
                                    "Wepolls Website",
                                    "XBMC",
                                    "Puffin Academy",
                                    "CityVille",
                                    "We Heart It",
                                    "Google Plus Website",
                                    "OCN Webmail",
                                    "Grono Website",
                                    "Droom",
                                    "Avant Update",
                                    "Tom",
                                    "Ning Website",
                                    "Alphaporno Video Streaming",
                                    "SendMyWay Upload",
                                    "1mg",
                                    "Sun NXT",
                                    "Google Reader Android",
                                    "Runesofmagic Game",
                                    "iConnectHere",
                                    "AppVPN",
                                    "Xing Website",
                                    "Necromanthus Game",
                                    "Audimated Website",
                                    "Peercast P2P",
                                    "Wynk Movies",
                                    "Mendeley Desktop",
                                    "Capsule",
                                    "MySmartPrice",
                                    "Twitter Message",
                                    "Pixlr Apps",
                                    "BBM",
                                    "4Tube Streaming",
                                    "Mafia Wars-Facebook Games",
                                    "Bluebeam",
                                    "Ebutor Distribution",
                                    "Rakuten Viki",
                                    "Asmallworld Website",
                                    "Myopera Website",
                                    "Workbook",
                                    "ShadeYouVPN",
                                    "Line Messenger File Transfer",
                                    "Habbo Website",
                                    "Global TV",
                                    "Rotten Tomatoes",
                                    "VoiceFive",
                                    "iCloud Calender",
                                    "Daum",
                                    "Pandora Music Streaming",
                                    "SoundHound Android",
                                    "Privitize VPN Proxy",
                                    "Tenfold",
                                    "Weibo New Post",
                                    "UserVoice",
                                    "Cyazyproxy",
                                    "Flock Update",
                                    "Google Plus Web Chat",
                                    "Freeonlinegames Website",
                                    "Tappsi",
                                    "Freshsales Upload CSV",
                                    "Epernicus Website",
                                    "Popcap Website",
                                    "Tellagami Share",
                                    "Weebly Website Builder",
                                    "WLM Login",
                                    "Freeridegames Website",
                                    "Dawn",
                                    "Kugoo Playlist P2P",
                                    "CarDekho",
                                    "WhatsCall",
                                    "Itsmy Website",
                                    "Optimax",
                                    "DNSCrypt",
                                    "Crunchyroll Website",
                                    "Royal Story",
                                    "Mail.com Organizer",
                                    "GoToMeeting",
                                    "Shopify Manage Orders",
                                    "Egnyte Delete",
                                    "Airtable",
                                    "FarmVille-Facebook Games",
                                    "TurboVPN",
                                    "Wish",
                                    "AIM Messenger",
                                    "MySpace Website",
                                    "TeamSpeak",
                                    "Hello VPN",
                                    "ProxyWebsite",
                                    "Lojas Americanas",
                                    "Ngopost Website",
                                    "Shopify Manage Products",
                                    "Poker-Facebook Games",
                                    "Marvel Website",
                                    "Bitcoin Proxy",
                                    "Google Desktop Application",
                                    "Litzscore API",
                                    "Pet Rescue Saga",
                                    "Indianpornvideos Streaming",
                                    "Rednet BBS",
                                    "Zshare Upload",
                                    "NapMX Retrieve P2P",
                                    "iTel Mobile Dialer Express",
                                    "Shelfari Website",
                                    "LinkedIN Search",
                                    "VK Message",
                                    "Wordfeud Game",
                                    "Playstation Network",
                                    "Baidu Image",
                                    "Proprofs",
                                    "Wordpress",
                                    "Yahoo Messenger",
                                    "LinkedIN Website",
                                    "Coolmath Games",
                                    "Plock FacebookApp",
                                    "Yebhi",
                                    "SlideShare Upload",
                                    "CantFindMeProxy",
                                    "Phreesia",
                                    "Researchgate Website",
                                    "Tetris Battle",
                                    "Freshdesk",
                                    "OKCupid Android",
                                    "Nexage",
                                    "Brainshark",
                                    "Kakao",
                                    "IBM CXN Cloud Communities",
                                    "Xbox LIVE",
                                    "Smartsheet",
                                    "ChartNexus",
                                    "LinkedIN Messenger File Upload",
                                    "MoonVPN",
                                    "Super VPN",
                                    "The Smurfs & Co",
                                    "Xvideos Streaming",
                                    "PBS Video Streaming",
                                    "Melon Music",
                                    "Egnyte Apps Download",
                                    "Ebaumsworld Video Streaming",
                                    "OpenInternet",
                                    "WhatsApp Video Call",
                                    "Friendster Web Login",
                                    "Facebook Limited Access",
                                    "8Tracks",
                                    "Coursera",
                                    "Vidazoo",
                                    "ShareThis",
                                    "Google Plus Hangouts",
                                    "Real Boxing",
                                    "TaskBucks",
                                    "Twitter Visual Media",
                                    "Ants IRC Connect P2P",
                                    "Getglue Website",
                                    "Social Empires",
                                    "VK Mail",
                                    "Cartoon Network",
                                    "Cricbuzz",
                                    "Ludo King",
                                    "RingCentral Glip",
                                    "Athlinks Website",
                                    "Goober Messenger",
                                    "Last.FM Android",
                                    "HealthKart",
                                    "Tumblr Follow",
                                    "Goodreads Website",
                                    "Elastic.io iPaaS",
                                    "Baidu Video Streaming",
                                    "Break Video Streaming",
                                    "Google Hangout Android App",
                                    "Twillio Communications",
                                    "Gaiaonline Website",
                                    "Wireclub",
                                    "TuneIN Radio Android",
                                    "Zshare Download",
                                    "Espnstar Video Streaming",
                                    "Patientslikeme Website",
                                    "PPLive Streaming",
                                    "Tox",
                                    "Hitpost Android",
                                    "Base",
                                    "Pengyou",
                                    "Yaxi",
                                    "Laposte Web Mail",
                                    "Eyejot",
                                    "Celoxis",
                                    "Aha",
                                    "VPN Lighter",
                                    "51TV",
                                    "Torrent Clients P2P",
                                    "Shopify Dashboard",
                                    "AIM Games",
                                    "The-sphere Website",
                                    "Youpunish Video Streaming",
                                    "Zenga",
                                    "Picasa Update",
                                    "Dropbox File Upload",
                                    "Quick Base Upload",
                                    "Zooworld FacebookApp",
                                    "Hammer VPN",
                                    "Kinja",
                                    "Lokalisten",
                                    "Getright Update",
                                    "Hotstar",
                                    "IndiaTV live",
                                    "Tmall",
                                    "Recharge Done",
                                    "Svtplay Streaming",
                                    "GMX Compose Mail",
                                    "Mail.com Contacts",
                                    "Windows Marketplace",
                                    "NPR Radio Streaming",
                                    "Fame",
                                    "CuteBears FacebookApp",
                                    "Counter Strike",
                                    "HDFC Bank Mobile Banking",
                                    "Whatfix",
                                    "Loom",
                                    "Channel News Asia",
                                    "Blog.com",
                                    "iTrix",
                                    "ZirMed",
                                    "E Entertainment",
                                    "8 Ball Pool - Android",
                                    "Yoga VPN",
                                    "Buyhatke",
                                    "Pipedrive Upload",
                                    "AOL Desktop",
                                    "Tagged Website",
                                    "Hike",
                                    "Aljazeera Audio Streaming",
                                    "Boule & Bill",
                                    "Indeed",
                                    "LivePerson",
                                    "Hide.Me",
                                    "Deer Hunter 2014",
                                    "YieldManager",
                                    "Proxifier Proxy",
                                    "Palnts vs. Zombies Advanture",
                                    "School of Dragons",
                                    "Contract Wars",
                                    "Xanga Website",
                                    "Italki Website",
                                    "Hit It Rich! Casino Slots",
                                    "Lucidpress",
                                    "MySpace Video Streaming",
                                    "MobWars Facebook Game",
                                    "AdvancedMD",
                                    "Oxigen Wallet",
                                    "Insightly",
                                    "Webshots Streaming",
                                    "DailyCartoons Android",
                                    "Submityourflicks Streaming",
                                    "Tixati P2P",
                                    "Line Games and Applications",
                                    "Kite by Zerodha",
                                    "TSheets",
                                    "Scramble Facebook Game",
                                    "IFTTT",
                                    "Kaixin001 Website",
                                    "VeePN",
                                    "Opera Off Road Mode",
                                    "Divan TV",
                                    "OpenX",
                                    "Rocket Fuel Marketing",
                                    "AdnstreamTV Website",
                                    "Tuenti Status Update",
                                    "ILikeMusic Streaming",
                                    "Assembla",
                                    "Clubbox",
                                    "Wooxie Website",
                                    "Yoville Facebook Game",
                                    "Disney City Girl",
                                    "Worldcric",
                                    "The Telegraph",
                                    "Marvel Avengers Alliance Tactics",
                                    "Infusionsoft",
                                    "Reddit",
                                    "1Fichier Upload",
                                    "SongPop",
                                    "Soku Website",
                                    "9gag",
                                    "Ali Quan Niu",
                                    "Bigpoint Game",
                                    "The Washington Post",
                                    "Magnatune Website",
                                    "FileRio Download",
                                    "Guvera",
                                    "Mega Download",
                                    "Xfinity TV",
                                    "Playfire Website",
                                    "Wetpaint",
                                    "YY Voice Messenger",
                                    "YouTube Add to",
                                    "Naaptol",
                                    "Yelp Website",
                                    "IBM CXN Cloud Activities",
                                    "Sexyandfunny Website",
                                    "Docstoc File Transfer",
                                    "Lost Jewels",
                                    "Fluttr",
                                    "JewelPuzzle Facebook Game",
                                    "Status-Net",
                                    "WhatsApp File Transfer",
                                    "People BBS",
                                    "NHK World TV",
                                    "MeHide.asia",
                                    "News Break",
                                    "Eagle VPN",
                                    "Facebook Search",
                                    "Freshsales",
                                    "Whisper",
                                    "ToutApp",
                                    "Ares Chat Room",
                                    "Tata Sky Mobile",
                                    "FreeMovies Android",
                                    "NSDL",
                                    "Etisalat Messenger",
                                    "Smutty Website",
                                    "Chess.com",
                                    "ABC Australia",
                                    "Ircgalleria Website",
                                    "Blauk Website",
                                    "Easynews",
                                    "Morpheus P2P",
                                    "ShellFire VPN",
                                    "SoMud",
                                    "CloudApp",
                                    "Bitshare Upload",
                                    "Hello! magazine",
                                    "Zuzandra Website",
                                    "Pinterest Upload",
                                    "Outreach",
                                    "Fruehstueckstreff Website",
                                    "Stripe",
                                    "Twitter Follow",
                                    "YouTube Share Video",
                                    "nexGTV",
                                    "Blockless VPN",
                                    "Stan",
                                    "Aljazeera Live Streaming",
                                    "CCP Games",
                                    "163 Alumni",
                                    "SBS On Demand",
                                    "TOR VPN",
                                    "XiTi",
                                    "Lokalistens Photo Upload",
                                    "Qip Messenger",
                                    "Stealthnet P2P",
                                    "Topbuzz",
                                    "HTTP Audio Streaming",
                                    "KakaoTalk",
                                    "Cat898 BBS",
                                    "Shopify Manage Customers",
                                    "Sonyliv Video Streaming",
                                    "Vampirefreaks Website",
                                    "iPlay Website",
                                    "iTunes Internet",
                                    "SendSpace",
                                    "Quip",
                                    "HubPages",
                                    "Second Life",
                                    "LinkedIN Posts Search",
                                    "All Player Update",
                                    "Pool Live Tour",
                                    "Angry Birds Friends",
                                    "VidibleTV",
                                    "GetResponse",
                                    "Vidmate",
                                    "Hainei",
                                    "QuickFlix",
                                    "Tweetie",
                                    "My Mail.ru",
                                    "Egnyte Share",
                                    "DAP Update",
                                    "Ladooo-Free Recharge App",
                                    "SVT Play",
                                    "Flickr Website",
                                    "Amazon Prime Streaming",
                                    "Target",
                                    "Blackplanet Website",
                                    "Ludo Star",
                                    "Constant Contact",
                                    "Signal Private Messenger",
                                    "Hideninja VPN",
                                    "Deputy Workforce MGMT",
                                    "Pullbbang Video Streaming",
                                    "LinkedIN Limited Access",
                                    "Bronto",
                                    "Winamax Game",
                                    "TealiumIQ",
                                    "MEO Cloud",
                                    "Bill.com",
                                    "Voillo",
                                    "Totorosa Music Website",
                                    "Duomi Music",
                                    "Leankit",
                                    "Goo Webmail",
                                    "Evernote Webcliper",
                                    "Jelly Glutton",
                                    "Tribe Website",
                                    "Spiegel Online",
                                    "CashBoss",
                                    "MxiT Android",
                                    "GungHo",
                                    "Dropcam",
                                    "FSecure Freedome VPN",
                                    "WeChat Web",
                                    "TOR Proxy",
                                    "Periscope Data",
                                    "Google Video Streaming",
                                    "ZeeTV App",
                                    "CricInfo Android",
                                    "Republic TV",
                                    "Windscribe",
                                    "Sage Intacct",
                                    "LinkedIN Universities",
                                    "Badoo Website",
                                    "Proxysite.com Proxy",
                                    "Fanpop",
                                    "IMDB Streaming",
                                    "Meetup Message",
                                    "Yabuka",
                                    "Gold Dialer",
                                    "DingTalk",
                                    "Kwai App Suite",
                                    "Epic Browser",
                                    "Telenet Webmail",
                                    "TVB Video Streaming",
                                    "Howardforums Website",
                                    "Renren Website",
                                    "Activecollab",
                                    "Ninja Kingdom",
                                    "Uptobox Upload",
                                    "Termwiki Website",
                                    "MSDN",
                                    "Gamespy Game",
                                    "Vevo",
                                    "Fishville FacebookApp",
                                    "USA IP",
                                    "Google Plus Photos",
                                    "Gamehouse",
                                    "Hootsuite Web Login",
                                    "MobileVOIP",
                                    "ChatWork",
                                    "MillionaireCity-Facebook Games",
                                    "WLM WebChat",
                                    "Colors Video Streaming",
                                    "Messages for Web",
                                    "Private Internet Access VPN",
                                    "Twitter Status Update",
                                    "Blog.Com Admin",
                                    "CityVille FacebookApp",
                                    "Tvigle",
                                    "Ants P2P",
                                    "UNO & Friends",
                                    "Dontstayin Website",
                                    "Facebook Blackberry",
                                    "WeChat File Transfer",
                                    "Windows Store",
                                    "Skype",
                                    "Manolito P2P Download",
                                    "Sploder Game",
                                    "Talkbiznow Website",
                                    "Google Plus Comment",
                                    "Skyplayer Streaming",
                                    "iCloud Bookmarks",
                                    "Playboy.tv Streaming",
                                    "Google Groups",
                                    "Telecom Express",
                                    "Hr Website",
                                    "StatCounter",
                                    "Kaixin001 Comment Posting",
                                    "Nugg",
                                    "Egloos Blog Post",
                                    "Blogger Comment",
                                    "Betternet VPN",
                                    "Baidu Music",
                                    "Bingo Bash",
                                    "Brazzers",
                                    "Facebook Graph API",
                                    "Tuenti Photo Upload",
                                    "Bloomberg",
                                    "Docusign",
                                    "Browsec VPN",
                                    "Ap.Archive Streaming",
                                    "Dailywire",
                                    "JB Hi-Fi",
                                    "Costco",
                                    "BigAdda",
                                    "SumRando",
                                    "LiveHelpNow",
                                    "Asianave Website",
                                    "Gogoyoko Website",
                                    "Ning Invite",
                                    "3QSDN Streaming",
                                    "Yahoo News",
                                    "Trombi Website",
                                    "TapCash",
                                    "The Pirate Bay Proxy",
                                    "O2 TU Go",
                                    "Filmow Website",
                                    "Mouthshut Website",
                                    "VGO TV",
                                    "Monster World",
                                    "Line Messenger",
                                    "Word Chums",
                                    "Ontraport",
                                    "Viber Message",
                                    "Delicious Website",
                                    "Pipedrive",
                                    "Craigslist Website",
                                    "Sharefile",
                                    "Soulseek Download P2P",
                                    "Alibaba",
                                    "Tweakware VPN",
                                    "Phex P2P",
                                    "Tumblr Reblog",
                                    "Doom3 Game",
                                    "Movies.com",
                                    "Office Depot",
                                    "Stileproject Video Streaming",
                                    "Slingbox Streaming",
                                    "VPNium Proxy",
                                    "UEFA Video Streaming",
                                    "Care2 Website",
                                    "Pepper Panic Saga",
                                    "OlaCabs",
                                    "Alt News",
                                    "Village Life",
                                    "Fux Video Streaming",
                                    "Listography Website",
                                    "Call Of Duty 4 Game",
                                    "FastTV",
                                    "Xero Upload",
                                    "Pornsharia Video Streaming",
                                    "Rapidgator Download",
                                    "Crocko Upload",
                                    "QQ BBS",
                                    "Dropbox Base",
                                    "MSN Money",
                                    "Cnet Download",
                                    "SurveyGizmo",
                                    "LinkedIN Videos",
                                    "Facebook Events",
                                    "Kongregate Game",
                                    "Fox News",
                                    "Eve Online",
                                    "Airset Access",
                                    "Lybrate",
                                    "Ensight",
                                    "Instagram Visual Media",
                                    "Couchsurfing Website",
                                    "KwMusic App Streaming",
                                    "Backblaze Business Backup",
                                    "Axis Bank Mobile",
                                    "Hexa Tech VPN",
                                    "ShopClues",
                                    "ExpressVPN",
                                    "Ameba Blog Post",
                                    "Comcast",
                                    "Replicon",
                                    "WhatsApp Call",
                                    "Marketo",
                                    "Youjizz",
                                    "Yahoo game",
                                    "8Track Iphone",
                                    "YouTube Subscribe",
                                    "Star VPN",
                                    "NewsNation",
                                    "1Password",
                                    "EarnTalkTime",
                                    "TV3",
                                    "Astrill VPN",
                                    "Fashland Dress UP for Fashion",
                                    "GOMPlayer Update",
                                    "HTTP File Upload",
                                    "Trello",
                                    "SmugMug Upload",
                                    "DoPool",
                                    "Uptobox",
                                    "Trivia Crack",
                                    "Recurly",
                                    "Infibeam",
                                    "ResourceGuru",
                                    "Fandango",
                                    "Real Basketball",
                                    "NetEase Games",
                                    "Mix",
                                    "Silkroad",
                                    "Gyao Streaming",
                                    "Tagoo.ru Music Streaming",
                                    "LinkedIN People Search",
                                    "FastSecureVPN",
                                    "Pornyeah Streaming",
                                    "Highspot",
                                    "BigBasket",
                                    "Manolito P2P Search",
                                    "Backblaze Prefrances",
                                    "ZOVI",
                                    "Zoom Meetings",
                                    "Pokemon Go",
                                    "Soul Attempt P2P",
                                    "Ask Web-Search",
                                    "Dynamics 365",
                                    "Cubby File transfer",
                                    "Wix Media Platform",
                                    "Twitch Video Streaming",
                                    "Amazon Prime Watchlist",
                                    "CastleVille FacebookApp",
                                    "Grammarly",
                                    "Rambler Mail",
                                    "Google Plus Events",
                                    "Friendsreunited Website",
                                    "Meru Cabs",
                                    "Facebook Iphone",
                                    "Facebook Message",
                                    "Embedupload File Transfer",
                                    "Flixwagon Streaming",
                                    "Mediastream",
                                    "Fileguri P2P",
                                    "Bing News",
                                    "WWE Video Streaming",
                                    "Mubi Website",
                                    "UC Browser",
                                    "Mediaget Installer Download",
                                    "Addicting Game",
                                    "Aol Answers",
                                    "Warrior Forum",
                                    "PartnerUp",
                                    "101 Network",
                                    "Backblaze My Shared Files",
                                    "Dlisted",
                                    "Pardot",
                                    "Virb Website",
                                    "Flickr Web Upload",
                                    "WordsWithFriends FacebookApp",
                                    "Yahoo WebChat",
                                    "[24]7.ai",
                                    "HTTP Image",
                                    "Throne Rush",
                                    "Amazon Prime Search",
                                    "Blackline Accounting",
                                    "Flashget P2P",
                                    "Everhour",
                                    "Jobvite",
                                    "Moviesand Video Streaming",
                                    "Tagged Android",
                                    "Chat On",
                                    "Koovs",
                                    "Cabonline",
                                    "Niwota",
                                    "Ajio",
                                    "Aha Video",
                                    "Webex Teams",
                                    "Unseen Online VPN",
                                    "CSR Racing",
                                    "Filmaffinity Website",
                                    "JinWuTuan Game",
                                    "iModules Encompass",
                                    "VPN 365",
                                    "Docebo",
                                    "ppFilm",
                                    "Egnyte Bookmarks",
                                    "Hayu",
                                    "Cornerstone",
                                    "Microsoft Teams",
                                    "Mobsters2 FacebookApp",
                                    "The Weather Channel",
                                    "Passportstamp Website",
                                    "Battlefront Heroes",
                                    "Evernote",
                                    "Skimlinks",
                                    "Rdio Website",
                                    "Zedo",
                                    "Realtor",
                                    "Tv4play Streaming",
                                    "JW Player",
                                    "Douban Website",
                                    "HTTP Video Streaming",
                                    "Userporn Video Streaming",
                                    "Game Center",
                                    "9Jumpin",
                                    "iCloud Photos",
                                    "Airtime",
                                    "ProfileSong FacebookApp",
                                    "FrontierVille-Facebook Games",
                                    "Fark Website",
                                    "Voxer Walkie-Talkie PTT",
                                    "Cam4 Streaming",
                                    "Mysee Website",
                                    "Olive Media",
                                    "Practice Fusion",
                                    "Adobe Reader Update",
                                    "Cilory",
                                    "Green VPN",
                                    "DirectConnect P2P",
                                    "Popsugar",
                                    "iCall",
                                    "Bitbucket",
                                    "Infoseek Webmail",
                                    "Dict.Cn",
                                    "Ninjaproxy.ninja",
                                    "Speedy VPN",
                                    "Voot",
                                    "Indabamusic Website",
                                    "20minutos",
                                    "NicoNico Douga Streaming",
                                    "Foxtel Go",
                                    "TV18 Streaming",
                                    "Bing Safe Search Off",
                                    "Recharge Plan",
                                    "Bebo Website",
                                    "Crictime Video Streaming",
                                    "Clash Of Clans",
                                    "Fuq Website",
                                    "VK Chat",
                                    "Meetup Website",
                                    "Freetv Website",
                                    "Mojang",
                                    "SmugMug",
                                    "Reunion",
                                    "QQ Games",
                                    "Weibo Website",
                                    "Haitun VPN",
                                    "Jurassic Park Builder",
                                    "Steam",
                                    "Opera Update",
                                    "Proxyone",
                                    "Swipe Clock",
                                    "Just Proxy VPN",
                                    "Silverpop",
                                    "Podio",
                                    "YeeYoo",
                                    "Khanwars Game",
                                    "Zalo",
                                    "PUBG Mobile",
                                    "Expedia",
                                    "Xiaonei",
                                    "Saavn Website",
                                    "Stitcher",
                                    "Clips and Pics Website",
                                    "Cooladata",
                                    "VPN in Touch",
                                    "ShareBlast",
                                    "XNXX",
                                    "Wikidot",
                                    "Smule",
                                    "Suburbia",
                                    "RichRelevance",
                                    "Blogger Post Blog",
                                    "ManyCam Update",
                                    "Megavideo",
                                    "Gizmodo",
                                    "Ameba Now",
                                    "Academia Website",
                                    "OwnerIQ Website",
                                    "Top Eleven Be a Football Manager",
                                    "Klipfolio",
                                    "Xero Download",
                                    "Quora",
                                    "ATube Catcher Update",
                                    "W3Schools",
                                    "Super VPN Master",
                                    "iCAP Business",
                                    "Xcar",
                                    "Acuity Scheduling",
                                    "X-VPN",
                                    "SourceForge Download",
                                    "Appsomniacs Games",
                                    "STAR Sports",
                                    "Schmedley Website",
                                    "Chartio",
                                    "Totorosa Media Website",
                                    "Apple-Juice P2P",
                                    "Tuenti Video Search",
                                    "Zooppa Website",
                                    "Zopper",
                                    "Mocospace Website",
                                    "Prosperworks CRM",
                                    "eFolder",
                                    "FreshService",
                                    "SoundCloud Android",
                                    "Wayn Website",
                                    "Happn",
                                    "IBM Connections Cloud",
                                    "Pcloud Download",
                                    "Meinvz Website",
                                    "Slack",
                                    "Work",
                                    "Ngpay",
                                    "Houston Chronicle",
                                    "KanbanFlow",
                                    "IGN",
                                    "Perfspot",
                                    "Britishproxy.uk Proxy",
                                    "NDTV Android",
                                    "VPN over 443",
                                    "Flash Alerts on Call-SMS",
                                    "Dialer Plus",
                                    "Govloop Website",
                                    "OpenDoor",
                                    "Snap VPN",
                                    "Blackberry Appworld",
                                    "Snapdeal",
                                    "Vonage",
                                    "Envato",
                                    "Quick Heal Anti-virus Update",
                                    "Facebook Video Playback",
                                    "Xaxis",
                                    "BypassGeo",
                                    "Dragon City",
                                    "Procore",
                                    "PromoCodeClub",
                                    "Onavo",
                                    "Identica Website",
                                    "Yahoo Search",
                                    "DNS Multiple QNAME",
                                    "Calendly",
                                    "Morphium.info",
                                    "Bigtent",
                                    "Google Plus People",
                                    "Metasploit Update",
                                    "Babycenter Name Search",
                                    "Taobao Aliwangwang Messenger",
                                    "Socialbox FacebookApp",
                                    "Amazon Music",
                                    "Buzznet Website",
                                    "Pivotal Tracker",
                                    "Zimbra",
                                    "MSN Games",
                                    "Wetpussy Streaming",
                                    "Shockwave",
                                    "Miro Update",
                                    "Farm Heroes Saga",
                                    "Taltopia Website",
                                    "Armor Games",
                                    "Uber",
                                    "M3U8 Playlist",
                                    "Manolito P2P GetServer List",
                                    "Experienceproject Website",
                                    "Laibhaari Website",
                                    "Madeena Dailer",
                                    "Chinaren",
                                    "Gett",
                                    "Apple Support",
                                    "FinchVPN",
                                    "Pearls Peril",
                                    "Hideman VPN",
                                    "Stick Run",
                                    "Printvenue",
                                    "Facebook Applications",
                                    "Looker",
                                    "DayTimeTV",
                                    "GoDaddy",
                                    "Nielsen",
                                    "Asana",
                                    "Paychex",
                                    "NeonTV",
                                    "PubMatic Website",
                                    "Mahjong Trails",
                                    "Sciencestage Website",
                                    "LinkedIN Company Search",
                                    "Worldcup Proxy",
                                    "Weibo Microblogging",
                                    "Sbs Netv Streaming",
                                    "Officeally",
                                    "Lastfm Website",
                                    "ProxyProxy",
                                    "SkyVPN",
                                    "Extremesextube Streaming",
                                    "Vudu",
                                    "PrivateSurf.us",
                                    "Airtel Money",
                                    "MangaBlaze",
                                    "EuroSport",
                                    "Autopilot",
                                    "Forever Net",
                                    "Gom VPN",
                                    "VPN Master",
                                    "Yandex Disk",
                                    "Baofeng Website",
                                    "T-Online Webmail",
                                    "Citrix GoToTraining",
                                    "Facebook Post Attachment",
                                    "Scottrade",
                                    "Rapidgator Upload",
                                    "Google Plus Add To Circle",
                                    "Ravelry Website",
                                    "Cyberoam Bypass Chrome Extension",
                                    "Music.com",
                                    "Softonic",
                                    "Applicantpro",
                                    "LiveChat Inc",
                                    "Yugma Web Conferencing",
                                    "MediaDrug",
                                    "Ask Image-Search",
                                    "SadorHappy FacebookApp",
                                    "Puffin Web Browser",
                                    "Notepadplus Update",
                                    "VK Social",
                                    "Tubi TV",
                                    "Super Mario Run",
                                    "Sakshi TV Streaming",
                                    "PaiPai",
                                    "YikYak",
                                    "Flipkart",
                                    "Gfycat",
                                    "Vector",
                                    "RusVPN",
                                    "GOG",
                                    "Clio",
                                    "Facebook Website",
                                    "EpicCare",
                                    "Rediff Website",
                                    "Naver Mail",
                                    "Jiaoyou - QQ",
                                    "ALTBalaji",
                                    "Myheritage Website",
                                    "Tube8 Streaming",
                                    "ZenMate",
                                    "Datadog",
                                    "LinkedIN Mail Inbox",
                                    "Intralinks",
                                    "Shopify",
                                    "Indiatimes Live Streaming",
                                    "MSN",
                                    "Veetle Streaming",
                                    "Youku Streaming",
                                    "Tumblr Blog",
                                    "WildOnes Facebook Game",
                                    "Lantern",
                                    "Pinterest Like",
                                    "Snapchat",
                                    "Winamp Update",
                                    "SIP - TCP",
                                    "FreePaisa",
                                    "TaxiforSure",
                                    "Purevolume Website",
                                    "Youtube Video Search",
                                    "UK-Proxy.org.uk Proxy",
                                    "RadiumOne Marketing",
                                    "Zenox",
                                    "Tumblr Post",
                                    "Sling",
                                    "Egnyte Upload",
                                    "NightClubCity Facebook Game",
                                    "Viper",
                                    "Wattpad Website",
                                    "Yuvutu Streaming",
                                    "The Trade Desk",
                                    "TVN",
                                    "Aljazeera Video Streaming",
                                    "Qzone Website",
                                    "JDownloader",
                                    "Outbrain",
                                    "iPTT",
                                    "Raaga Android",
                                    "YouTube Like/Plus",
                                    "Xim Messenger",
                                    "FaceBook IM on Yahoo Messenger",
                                    "L2TP VPN",
                                    "PayPal",
                                    "Trial Xtreme 3",
                                    "Turbobit Upload",
                                    "Y8 Game",
                                    "Sendspace Upload",
                                    "Certify",
                                    "Euronews",
                                    "Windows Audio Streaming",
                                    "VLC Update",
                                    "Baidu Player",
                                    "Adobe Website Download",
                                    "Free Download Manager",
                                    "Quickplay Videos",
                                    "Car Town",
                                    "Youporn Streaming",
                                    "Backblaze User Restore",
                                    "Viewsurf",
                                    "HelloTV",
                                    "LiveProfile Android",
                                    "Draugiem Website",
                                    "QQ City",
                                    "PerezHilton",
                                    "Google Toolbar",
                                    "Live.ly",
                                    "5460 Net",
                                    "Bubble Safari",
                                    "Papa Pear Saga",
                                    "VzoChat Messenger",
                                    "Yobt Video Streaming",
                                    "Groupon",
                                    "BambooHR",
                                    "Cooliyo",
                                    "Bloomberg BNA",
                                    "Clarizen",
                                    "Cafeland",
                                    "Spiceworks",
                                    "ClickDesk",
                                    "TV Serial - Entertainment News",
                                    "Keyhole Video Login",
                                    "MP3 Rocket Download",
                                    "Linkexpats Website",
                                    "Thiswebsiterules Website",
                                    "Archive.Org",
                                    "Fuel Coupons Android",
                                    "Google Duo",
                                    "Carbonite",
                                    "Qiyi Com Streaming",
                                    "Yoono",
                                    "NinjaSaga FacebookApp",
                                    "Stardoll",
                                    "PremierFootball Facebook Game",
                                    "Lafango Website",
                                    "iCloud",
                                    "Gnutella P2P",
                                    "Flashgames247 Game",
                                    "ONTV Live Streaming",
                                    "WhatsApp Web",
                                    "Fucktube Streaming",
                                    "Google Plus Join Communities",
                                    "Supei",
                                    "SmartRecruiters",
                                    "Humanity",
                                    "Perfspot Pic Upload",
                                    "MoSIP",
                                    "EarthCam Website",
                                    "Zemplus Mobile Dialer",
                                    "Webs.com",
                                    "VK Video Streaming",
                                    "Juice Cubes",
                                    "TED",
                                    "ServiceNow",
                                    "Trivago",
                                    "ClearSlide",
                                    "Plaxo Website",
                                    "Twitter Android",
                                    "Gmail Attachment",
                                    "LinkedIN Job Search",
                                    "Amarujala Streaming",
                                    "Filehippo Update",
                                    "LiveXLive",
                                    "Japan FacebookName",
                                    "Brightalk Play",
                                    "Zello",
                                    "Blokus Game",
                                    "Quick Base Download",
                                    "Pinterest Streaming",
                                    "Bing Videos",
                                    "Zynga Game",
                                    "Treebo Hotels",
                                    "Monday Boards",
                                    "Classmates Website",
                                    "Viu",
                                    "Logo Games",
                                    "Mobogenie",
                                    "Quopn Wallet",
                                    "Youtube Downloader",
                                    "ErosNow",
                                    "Basecamp",
                                    "Splashtop",
                                    "Walmart",
                                    "IBM CXN Cloud Social",
                                    "9News",
                                    "AIM File Transfer",
                                    "Power Bi",
                                    "LivingSocial Android",
                                    "Mylife Website",
                                    "Amobee",
                                    "Domo",
                                    "Dailystrength Website",
                                    "Aleks",
                                    "Bearshare P2P",
                                    "Vyew Website",
                                    "Kobo",
                                    "Nexopia Website",
                                    "Lun",
                                    "Issuu",
                                    "Proxistore",
                                    "TeenPatti",
                                    "Holy Knight",
                                    "Toggl",
                                    "LinkedIN Jobs",
                                    "Periscope",
                                    "Yammer",
                                    "Geni Website",
                                    "Photon Flash Player & Browser",
                                    "LinkedIN Messenger File Download",
                                    "Teamwork",
                                    "Eroom Website",
                                    "Mymfb Website",
                                    "Netlog Website",
                                    "Dashlane",
                                    "Deejay",
                                    "Anaplan",
                                    "SOMA Messanger",
                                    "Opendiary Website",
                                    "xHamster Streaming",
                                    "Neogov HRMS",
                                    "Wikia",
                                    "Madthumb Video Streaming",
                                    "Yobt Website",
                                    "43things Website",
                                    "2shared Download",
                                    "VPN Free",
                                    "Viadeo WebLogin",
                                    "Funshion Streaming",
                                    "Hi VPN",
                                    "Facebook Video Upload",
                                    "Quikr",
                                    "Movenetworks Website",
                                    "Simplecast",
                                    "Usersnap",
                                    "Morningstar",
                                    "iSwifter Games Browser",
                                    "Vigo Video",
                                    "Voodoo Messenger",
                                    "Taringa Website",
                                    "ChefVille",
                                    "Vidio NBA Streaming",
                                    "DangDang",
                                    "Appointment Plus",
                                    "vCita",
                                    "Twitter Discover",
                                    "MakeMyTrip",
                                    "Dcinside",
                                    "Presto",
                                    "Goggles Android",
                                    "Trimble Maps",
                                    "DC++ Download P2P",
                                    "Express.co.uk Streaming",
                                    "Bejeweled-Facebook Games",
                                    "Aastha TV",
                                    "Pluto TV",
                                    "Gmail Android Application",
                                    "123RF",
                                    "Facebook Android",
                                    "Evernote Chat",
                                    "ViewOn",
                                    "2shared Upload",
                                    "Cab4You",
                                    "Texas HoldEm Poker",
                                    "Egnyte Request File",
                                    "Uplay Games",
                                    "LinkedIN Status Update",
                                    "AnyMeeting WebLogin",
                                    "Platinum Dialer",
                                    "Pinterest Website",
                                    "Barablu",
                                    "Mekusharim",
                                    "VHO Website",
                                    "Boxever",
                                    "OLX Android",
                                    "Weeworld Website",
                                    "Bigupload File Transfer",
                                    "Geckoboard",
                                    "Eyejot Video Message",
                                    "Ezyflix TV",
                                    "SoftEther VPN",
                                    "Hubculture Website",
                                    "Faceparty Website",
                                    "Resonate Networks",
                                    "Drunkt Website",
                                    "Monster Busters",
                                    "Ryze Website",
                                    "Warlight",
                                    "Shopcade",
                                    "TicketNew",
                                    "Podchaser",
                                    "Moxtra",
                                    "Rediff Shopping",
                                    "Meetme Website",
                                    "SouthWest",
                                    "Asphalt-8 Airborn",
                                    "Facebook Games",
                                    "Tianya",
                                    "Twitter Notifications",
                                    "Telegram",
                                    "Uptobox Download",
                                    "Aaj Tak",
                                    "Egloos",
                                    "Tuenti Website",
                                    "MediaPlayer Streaming",
                                    "Polldaddy",
                                    "Minus Upload",
                                    "DoubleDown Casino Free Slots",
                                    "Bloomberg Businessweek",
                                    "Monday Invite Members",
                                    "Newton Software",
                                    "Pornjog Video Streaming",
                                    "Real Player",
                                    "ABC Web Player",
                                    "Backblaze My Restore",
                                    "ABC iView",
                                    "Zippyshare",
                                    "Fling",
                                    "Fapdu Video Streaming",
                                    "TealiumIQ Publish Version",
                                    "VeohTV Streaming",
                                    "Iwiw Website",
                                    "Yahoo-Way2SMS",
                                    "Recharge It Now",
                                    "iHeart Radio Streaming",
                                    "Freecharge",
                                    "Naughtyamerica Streaming",
                                    "NFL",
                                    "Namely",
                                    "Mobile Legends",
                                    "Twtkr",
                                    "Jammer Direct",
                                    "Cloob Website",
                                    "Pornhub Streaming",
                                    "Bigo Live",
                                    "CBS Sports",
                                    "Airtel TV",
                                    "Raging Bull Website",
                                    "Miro P2P",
                                    "Baidu Video",
                                    "Paytm Wallet",
                                    "New York Times",
                                    "On24",
                                    "Beam Your Screen",
                                    "Online Soccer Manager",
                                    "Origin Games",
                                    "Slotomania Slot Machines",
                                    "DesiDime",
                                    "News18 Video Streaming",
                                    "utorrentz Update",
                                    "Yahoo Douga Streaming",
                                    "Facebook Blackberry Chat",
                                    "TechRadar",
                                    "Tnaflix Website",
                                    "Webtrends",
                                    "Cricking",
                                    "Axosoft",
                                    "iSolved HCM",
                                    "Manual Proxy Surfing",
                                    "Miniclip Pool Game",
                                    "Spotflux Proxy",
                                    "LinkedIN Groups Search",
                                    "Chinaren Class",
                                    "Swagbucks",
                                    "Backlog",
                                    "Flipboard",
                                    "WebPT",
                                    "SPB TV",
                                    "Fotki Media Upload",
                                    "Hardsextube Streaming",
                                    "Hotels.com",
                                    "QQ Xuanfeng",
                                    "uVPN",
                                    "Audible",
                                    "DouBan FM",
                                    "Jelly Splash",
                                    "Apple Push Notification",
                                    "Tylted Website",
                                    "Anonymox",
                                    "League Of Legends",
                                    "DashVPN",
                                    "Meettheboss Website",
                                    "CrossVPN",
                                    "Mixi",
                                    "ISAKMP VPN",
                                    "Livemocha Website",
                                    "Google Plus Upload",
                                    "Lever",
                                    "IM+ Android",
                                    "Winamp Player Streaming",
                                    "Fancode",
                                    "Tumblr Android",
                                    "PP VPN",
                                    "Hattrick Game",
                                    "CNET",
                                    "StarPlus Video Streaming",
                                    "Pokerstars Online Game",
                                    "Jumpingdog FacebookApp",
                                    "Times of India Videos",
                                    "Thunder VPN",
                                    "MindJolt-Facebook Games",
                                    "Houseparty",
                                    "Studivz Website",
                                    "Invisible Surfing Proxy",
                                    "Renren Music Website",
                                    "LiveAgent",
                                    "Workable",
                                    "Ning Photo Upload",
                                    "SecureLine VPN",
                                    "Sina",
                                    "SuccessFactors",
                                    "Focus Website",
                                    "Wellwer Website",
                                    "Battle-Net",
                                    "Fox Sports",
                                    "Between",
                                    "NDTV Streaming",
                                    "Red Crucible 2",
                                    "Baidu.Hi Games",
                                    "Storage.to Download",
                                    "FunForMobile Android",
                                    "FastRecharge",
                                    "FirstCry",
                                    "QlikSense Cloud",
                                    "BiggestBrain FacebookApp",
                                    "Newegg",
                                    "Egnyte My Links",
                                    "Nejat TV Streaming",
                                    "Amap",
                                    "Payback",
                                    "Google Plus Communities",
                                    "Liveleak Streaming",
                                    "iCloud Photo Stream",
                                    "Apple FaceTime",
                                    "ABC",
                                    "Startv Website",
                                    "Mobaga Town",
                                    "Microsoft NetMeeting",
                                    "Facebook Questions",
                                    "Skyscanner",
                                    "Busuu Website",
                                    "Magicjack",
                                    "Hot VPN",
                                    "Buggle",
                                    "Sprout Social Upload",
                                    "Writeaprisoner Website",
                                    "Sogou",
                                    "Domo File Export",
                                    "KAYAK",
                                    "Lufthansa",
                                    "1CRM",
                                    "Speedify",
                                    "Caringbridge Website",
                                    "Comedycentral Website",
                                    "Dudu",
                                    "VPN 360",
                                    "ReadonTV Streaming",
                                    "Xt3 Website",
                                    "Klite Initiation P2P",
                                    "CafeWorld-Facebook Games",
                                    "TreasureIsle-Facebook Games",
                                    "Myspace Web Mail",
                                    "HeyTell",
                                    "The Proxy Bay",
                                    "Bullhorn",
                                    "Manolito P2P Connect",
                                    "Rakuten",
                                    "Cienradios Streaming",
                                    "Criminal Case",
                                    "Stackoverflow",
                                    "VyprVPN",
                                    "Meetup Android",
                                    "Raptr",
                                    "Tumblr Search",
                                    "100BAO P2P",
                                    "Keyhole TV Streaming",
                                    "Gays Website",
                                    "Connatix",
                                    "Gamespot",
                                    "Foursquare Android",
                                    "Nykaa",
                                    "StreetRace Rivals",
                                    "Ares Retrieve Chat Room",
                                    "GetGuru",
                                    "AliExpress",
                                    "IIFL Markets",
                                    "Bebo WebMail",
                                    "CCleaner Update",
                                    "GQ Website",
                                    "Yesware",
                                    "Red Bull TV",
                                    "DotVPN",
                                    "Time Video Streaming",
                                    "PoolMaster Facebook Game",
                                    "Meetin Website",
                                    "Private VPN",
                                    "Me2day Website",
                                    "Coco Girl",
                                    "Weborama",
                                    "Marvel Avengers Alliance",
                                    "Piolet Initialization P2P",
                                    "IMDB Android",
                                    "Pingsta Website",
                                    "Chargebee",
                                    "Cleartrip",
                                    "Pinterest Board Create",
                                    "Lithium",
                                    "Zoho WebMessenger",
                                    "Xilu",
                                    "EuropeProxy",
                                    "Shadow Fight",
                                    "Facebook Share",
                                    "Hotlist Website",
                                    "Hipfile Upload",
                                    "Baseball Heroes",
                                    "IBM CXN Cloud Meetings",
                                    "Scrabble",
                                    "Tunein",
                                    "Pudding Pop",
                                    "eHarmony",
                                    "Moonactive Games",
                                    "Emol",
                                    "Sohu WebMail",
                                    "Tuenti Weblogin",
                                    "SetupVPN",
                                    "Blogster Website",
                                    "SiteScout",
                                    "Chroma",
                                    "DC++ Connect P2P",
                                    "The Guardian",
                                    "Scispace",
                                    "Bypasstunnel.com",
                                    "LightBox",
                                    "Etsy",
                                    "Scorecard Research",
                                    "Miniclip Games",
                                    "Facebook Login on YahooMail",
                                    "Indane GAS Booking",
                                    "Paytm",
                                    "Netvibes Search Widget",
                                    "51.COM",
                                    "LinkedIN Groups",
                                    "Softpedia",
                                    "Street Racers Online",
                                    "Surikate Website",
                                    "Stickam Website",
                                    "Dailybooth Website",
                                    "Ooyala Streaming",
                                    "Twitter Limited Access",
                                    "Clearcompany",
                                    "Opera Mobile Store",
                                    "The Wall Street Journal",
                                    "Ooyala Video Services",
                                    "WordReference",
                                    "Facebook Like Plugin",
                                    "Wishpond",
                                    "Oyo Rooms",
                                    "Multi Thread File Transfer",
                                    "Meebo Iphone",
                                    "Blizzard",
                                    "Noteworthy Web Messenger",
                                    "Photobucket Streaming",
                                    "Steganos Online Shield",
                                    "Hahaha Website",
                                    "Oracle Taleo",
                                    "VMate",
                                    "Gmail WebChat",
                                    "MobiTV - Watch TV Live",
                                    "Giphy",
                                    "Dhingana Streaming",
                                    "SocialFlow",
                                    "Weread Website",
                                    "Corriere",
                                    "Zalmos SSL Web Proxy for Free",
                                    "Sears Shopping",
                                    "Fomo",
                                    "Blogspot Blog",
                                    "Avataria",
                                    "Mipony Update",
                                    "FileRio Upload",
                                    "PLUS7",
                                    "Xinhuanet Forum",
                                    "Sciencestage Streaming",
                                    "PChome Website",
                                    "Backblaze Locate Computer",
                                    "Airtable CSV Export",
                                    "Ants Initialization P2P",
                                    "Social Calendar",
                                    "Lynda",
                                    "Hirevue",
                                    "Radio Public",
                                    "Mail.com Compose Mail",
                                    "Easy Mobile Recharge",
                                    "GetFeedback",
                                    "Dark Sky",
                                    "51.COM BBS",
                                    "Skype Web",
                                    "Dailyhunt",
                                    "Playlist Website",
                                    "Hatena Message",
                                    "Sailthru",
                                    "SpeakO",
                                    "PokktMobileRecharge",
                                    "Vodafone Play",
                                    "IMO Voice Calling",
                                    "TiKL",
                                    "Cumhuriyet",
                                    "Fish Epic",
                                    "Top Gear",
                                    "SmartAdServer",
                                    "RakNet",
                                    "Blogger Create Blog",
                                    "Recharge Plans",
                                    "Weourfamily Website",
                                    "Egnyte My Tasks",
                                    "Spankbang",
                                    "EA.FIFA Game",
                                    "Vuze P2P",
                                    "Aol Answers - Ask",
                                    "MoneyView:Financial Planning",
                                    "Discord",
                                    "Comment Attachment - Facebook",
                                    "MailChimp",
                                    "HipChat",
                                    "RaidoFM",
                                    "360Buy",
                                    "Sonico Website",
                                    "Redtube Streaming",
                                    "Tumblr Like",
                                    "Undertone",
                                    "CNTV Live Streaming",
                                    "Woome",
                                    "Advogato Website",
                                    "Phantom VPN",
                                    "Kitchen Scramble",
                                    "Music Tube",
                                    "SPC Media",
                                    "Metin Game",
                                    "Ameba Now - New Post",
                                    "Wiser Website",
                                    "VICE",
                                    "NateApp Android",
                                    "Outeverywhere Website",
                                    "Free18",
                                    "Iozeta",
                                    "Family Farm",
                                    "Nice inContact",
                                    "Faces Website",
                                    "Zoo World",
                                    "Farm Epic",
                                    "Pcloud Upload",
                                    "Voonik",
                                    "Global News",
                                    "Qik Streaming",
                                    "Domo File Upload",
                                    "Cirrus Insight",
                                    "Makeoutclub Website",
                                    "Nk Meeting Place",
                                    "TENplay",
                                    "MyTribe Facebook Game",
                                    "Socialvibe Website",
                                    "Fotolog Website",
                                    "Tvnz",
                                    "HBO GO",
                                    "Backblaze Download",
                                    "Mint Iphone",
                                    "Megogo Streaming",
                                    "JungleJewels Facebook Game",
                                    "Ibibo Game",
                                    "Free Fire",
                                    "Pcpop BBS",
                                    "Pet City",
                                    "SurveyMonkey Website",
                                    "Archive.org Video Streaming",
                                    "Jabong",
                                    "Chosenspace Game",
                                    "Jio TV",
                                    "Justcloud File Transfer",
                                    "SlashDot",
                                    "MIRC Messenger",
                                    "Viber Voice",
                                    "Epic TV",
                                    "Radio France Internationale",
                                    "Jiayuan",
                                    "Naszaklasa Website",
                                    "Paylocity",
                                    "Mint",
                                    "TorrentHunter Proxy",
                                    "Ipomo",
                                    "Netsuite",
                                    "Maxim:taxi order",
                                    "CBS News",
                                    "Tikifarm FacebookApp",
                                    "VPN Monster",
                                    "Jajah",
                                    "Fledgewing Website",
                                    "WorkflowMax",
                                    "Datanyze",
                                    "Piksel",
                                    "Jdownloader Update",
                                    "Last.fm Free Downloads",
                                    "Digitalproserver",
                                    "Upwork",
                                    "Livejournal Website",
                                    "Mediamonkey website",
                                    "Proclivity",
                                    "Unclogger VPN",
                                    "PuthiyathalaimuraiTV",
                                    "Cafemom Website",
                                    "Bing Maps",
                                    "Andhra Bank",
                                    "WinMX P2P",
                                    "Ragnarokonline Game",
                                    "Box File Upload",
                                    "IBM DB2",
                                    "Babes Video Streaming",
                                    "AskmeBazaar",
                                    "Ebay Desktop App",
                                    "Roblox Game Play",
                                    "Domo Connectors",
                                    "CNTV Video Streaming",
                                    "Office VPN",
                                    "Bestporntube Streaming",
                                    "GTalk Update",
                                    "Apple Daily",
                                    "Voc",
                                    "Skyrock Website",
                                    "CBox Streaming",
                                    "Hotfile Download",
                                    "MXPlayer Video Streaming",
                                    "Cybozu",
                                    "eMule P2P",
                                    "Agoda",
                                    "Travelocity",
                                    "Sprout Social",
                                    "Facebook Video Chat",
                                    "Tapin Radio",
                                    "HomeShop18",
                                    "BIIP Website",
                                    "Vine",
                                    "Twitter Search",
                                    "Urban Ladder",
                                    "Wynk Music",
                                    "Jetpack Joyride",
                                    "TypingManiac Facebook Game",
                                    "SKY News",
                                    "ETV News",
                                    "Quake Halflife Game",
                                    "Okurin File Transfer",
                                    "Egnyte File Transfer",
                                    "Ubuntu Update Manager",
                                    "Castbox",
                                    "Upfront Advertising",
                                    "Shufuni.tv",
                                    "SongsPk",
                                    "Netvibes My Widget",
                                    "Kiwibox Website",
                                    "Puzzle Charms",
                                    "2CH",
                                    "SpotXchange",
                                    "SSL Proxy Browser",
                                    "Tidal",
                                    "Samsung",
                                    "VPN Unlimited",
                                    "Front",
                                    "Rakuten OverDrive",
                                    "Secret",
                                    "Talkray",
                                    "TaoBao",
                                    "51.com mp3 Streaming",
                                    "Videologygroup Streaming",
                                    "Xinhuanet",
                                    "Smilebox",
                                    "ABP Live",
                                    "ScoreCenter Android",
                                    "England Proxy",
                                    "Neokast Streaming",
                                    "QQ Download P2P",
                                    "Workfront",
                                    "Just Open VPN",
                                    "FileZilla Update",
                                    "MIRC Update",
                                    "Tunnelier",
                                    "Mixwit Website",
                                    "AIM Android",
                                    "Xero",
                                    "Google Plus +1",
                                    "Guilt",
                                    "SkyEye VPN",
                                    "Ebuddy Android",
                                    "Shareaza P2P",
                                    "DC++ Hub List P2P",
                                    "TuneUp Mobile",
                                    "Yourlust Streaming",
                                    "Ace2Three Game",
                                    "SlideShare Download",
                                    "Zhanzuo",
                                    "Deccan Chronicle Video Streaming",
                                    "VPN Robot",
                                    "Viber Media",
                                    "ZEE5",
                                    "Tistory",
                                    "AOL Search",
                                    "Weibo",
                                    "Chaos",
                                    "Shazam Android",
                                    "Crosstv Website",
                                    "Windows Live Games",
                                    "Xogogo Video Streaming",
                                    "Saavn Iphone",
                                    "Fastticket",
                                    "GMX Mail Attachment",
                                    "DoubleVerify",
                                    "Bubble Island",
                                    "Deliveroo",
                                    "Words With Friends",
                                    "SlideShare",
                                    "Mog Website",
                                    "Workamajig",
                                    "StarSport Video Streaming",
                                    "Yahoo Sportacular Android",
                                    "Locanto",
                                    "PPStream Streaming",
                                    "Websurf",
                                    "Channel4 Streaming",
                                    "Hungama",
                                    "DeviantART Website",
                                    "Yepme",
                                    "ZenVPN",
                                    "Godgame",
                                    "Hotfile Upload",
                                    "Pando P2P",
                                    "Frontline Education",
                                    "Wikispaces",
                                    "55bbs",
                                    "Turner.com",
                                    "Bebo WebChat IM",
                                    "Elftown Website",
                                    "SLI Systems",
                                    "Bigfishgames",
                                    "Apple Store",
                                    "Twitter Retweet",
                                    "The Free Dictionary",
                                    "Heart FacebookApp",
                                    "Boxcar",
                                    "Ultipro Services",
                                    "Alkasir Proxy",
                                    "iCloud Contacts",
                                    "Excite Mail",
                                    "Zapier",
                                    "Earn Money",
                                    "Expensify",
                                    "MunduTV Desktop App Streaming",
                                    "Evernote Notebook Share",
                                    "Sohu Club",
                                    "Rhapsody",
                                    "Kaixin001 Status Update",
                                    "Instagram Profile Picture Upload",
                                    "Istream Website",
                                    "Private Tunnel",
                                    "Phuks",
                                    "Lifeknot Website",
                                    "Ares P2P",
                                    "Sharethemusic Website",
                                    "Lagbook Website",
                                    "Kaixin001 Photo Upload",
                                    "FareHarbor",
                                    "DailyMail Streaming",
                                    "OCSP Protocol",
                                    "Bravo TV",
                                    "Brothersoft Website",
                                    "G Suite",
                                    "360quan",
                                    "PandaDoc",
                                    "Partyflock Website",
                                    "Way2sms WebMessenger",
                                    "Freenet P2P",
                                    "Skype Services",
                                    "CB Radio Chat Android",
                                    "Hide-N-Seek Proxy",
                                    "All Recipes Android",
                                    "Google Cache Search",
                                    "Speed VPN",
                                    "SinaTV",
                                    "Datawrapper",
                                    "Yahoo Entertainment",
                                    "Orkut Android",
                                    "Sonar",
                                    "MunduTV Desktop App Login",
                                    "Goodwizz Website",
                                    "FarmVille 2",
                                    "Yahoo Video Streaming",
                                    "AppNana",
                                    "Concur",
                                    "Owler",
                                    "skyZIP",
                                    "iMeet Central",
                                    "PNB mBanking",
                                    "TinyOwl",
                                    "Daxko Operations"
                                ]
                            },
                            "CharacteristicsList": {
                                "Characteristics": "Loss of productivity"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "Sopcast Streaming",
                                    "Sslbrowser Proxy",
                                    "Mail-ru Messenger",
                                    "Storage.to Download",
                                    "AOL Radio Website",
                                    "NeverMail WebMail",
                                    "Weezo",
                                    "Spinmyass Proxy",
                                    "ProXPN Proxy",
                                    "AOL WebMail",
                                    "WhatsApp",
                                    "Gtunnel Proxy",
                                    "DroidVPN",
                                    "Nateon Proxy",
                                    "Ghostsurf Proxy",
                                    "MyDownloader",
                                    "DAP Download",
                                    "GoBoogy Login P2P",
                                    "Fly Proxy",
                                    "Vpntunnel Proxy",
                                    "iCAP Business",
                                    "Tixati P2P",
                                    "Proxycap Proxy",
                                    "RAR File Download",
                                    "QQ Messenger File Transfer",
                                    "SumRando",
                                    "NetLoop VPN",
                                    "Apple-Juice P2P",
                                    "Chikka Web Messenger",
                                    "Livedoor Web Login",
                                    "Akamai Client",
                                    "Mig33 Android",
                                    "Opera Off Road Mode",
                                    "Dl Free Upload Download",
                                    "Quick Player Streaming",
                                    "FileMail WebMail",
                                    "Live Station Streaming",
                                    "Propel Accelerator",
                                    "Yahoo Messenger File Transfer",
                                    "E-Snips Download",
                                    "Digsby Messenger",
                                    "Klite Initiation P2P",
                                    "Sightspeed VOIP",
                                    "Classmates Website",
                                    "Tango Android",
                                    "Tudou Streaming",
                                    "Kproxyagent Proxy",
                                    "Imhaha Web Messenger",
                                    "Rxproxy Proxy",
                                    "Proxyway Proxy",
                                    "iConnectHere",
                                    "Sina WebMail",
                                    "Absolute Computrance",
                                    "VNC Remote Access",
                                    "Ztunnel Proxy",
                                    "Myspace Chat",
                                    "100BAO P2P",
                                    "Peercast P2P",
                                    "Gtalk Messenger",
                                    "HTTPort Proxy",
                                    "Bestporntube Streaming",
                                    "HOS Proxy",
                                    "IP Messenger FileTransfer",
                                    "Multiupload Download",
                                    "Hopster Proxy",
                                    "Citrix ICA",
                                    "TalkBox Android",
                                    "VPNium Proxy",
                                    "FreeVPN Proxy",
                                    "Rapidshare Download",
                                    "PalTalk Messenger",
                                    "Bearshare Download",
                                    "ISPQ Messenger",
                                    "Glype Proxy",
                                    "Mobyler Android",
                                    "Proxeasy Web Proxy",
                                    "HTTP Tunnel Proxy",
                                    "MP3 File Download",
                                    "Jailbreak VPN",
                                    "OneClickVPN Proxy",
                                    "LastPass",
                                    "Mega Proxy",
                                    "VPNMakers Proxy",
                                    "ShadeYouVPN",
                                    "Eroom Website",
                                    "Max-Anonysurf Proxy",
                                    "Proxeasy Proxy",
                                    "Vedivi-VPN Proxy",
                                    "Odnoklassniki Web Messenger",
                                    "Gapp Proxy",
                                    "56.com Streaming",
                                    "xHamster Streaming",
                                    "Lightshot",
                                    "Piolet Initialization P2P",
                                    "HotFile Website",
                                    "SoundHound Android",
                                    "Privitize VPN Proxy",
                                    "CodeAnywhere Android",
                                    "QuickTime Streaming",
                                    "Morpheus P2P",
                                    "Imesh P2P",
                                    "Auto-Hide IP Proxy",
                                    "Timbuktu DesktopMail",
                                    "Sendspace Download",
                                    "Gtalk Messenger FileTransfer",
                                    "Skydur Proxy",
                                    "Hide-My-IP Proxy",
                                    "Globosurf Proxy",
                                    "SurfEasy VPN",
                                    "Avaya Conference FileTransfer",
                                    "WocChat Messenger",
                                    "Trillian Messenger",
                                    "Napster Streaming",
                                    "Camoproxy Proxy",
                                    "ASUS WebStorage",
                                    "IMO-Chat Android",
                                    "QQ Web Messenger",
                                    "NTR Cloud",
                                    "Palringo Messenger",
                                    "Baidu IME",
                                    "Serv-U Remote Access",
                                    "ICQ Messenger",
                                    "DirectTV Android",
                                    "GoChat Android",
                                    "Real-Hide IP Proxy",
                                    "Genesys Website",
                                    "PI-Chat Messenger",
                                    "Ebuddy Web Messenger",
                                    "Internet Download Manager",
                                    "vBuzzer Android",
                                    "QQ Download P2P",
                                    "Mail-ru WebMail",
                                    "Baofeng Website",
                                    "Tunnelier",
                                    "ZIP File Download",
                                    "Packetix Proxy",
                                    "AIM Android",
                                    "Dynapass Proxy",
                                    "Pornerbros Streaming",
                                    "Suresome Proxy",
                                    "Hotline Download",
                                    "Circumventor Proxy",
                                    "Shockwave Based Streaming",
                                    "Datei.to FileTransfer",
                                    "Yourlust Streaming",
                                    "Ace2Three Game",
                                    "Fring Android",
                                    "Limelight Playlist Streaming",
                                    "Eyejot Video Message",
                                    "Soul Attempt P2P",
                                    "Ali WangWang Remote Access",
                                    "OKCupid Android",
                                    "Odnoklassniki Android",
                                    "Napster P2P",
                                    "StrongVPN",
                                    "K Proxy",
                                    "Proxyfree Web Proxy",
                                    "FreeU Proxy",
                                    "VNN-VPN Proxy",
                                    "World Of Warcraft Game",
                                    "R-Exec Remote Access",
                                    "Shazam Android",
                                    "MiddleSurf Proxy",
                                    "Fileguri P2P",
                                    "Invisiblenet VPN",
                                    "Mediaget Installer Download",
                                    "Vidyo",
                                    "Chatroulette Web Messenger",
                                    "GaduGadu Web Messenger",
                                    "AnyMeeting Connect",
                                    "Kongshare Proxy",
                                    "Flickr Web Upload",
                                    "PingTunnel Proxy",
                                    "Squirrelmail WebMail",
                                    "PPStream Streaming",
                                    "Hide-IP Browser Proxy",
                                    "Gtalk Android",
                                    "Megashares Upload",
                                    "Njutrino Proxy",
                                    "iLoveIM Web Messenger",
                                    "Cocstream Download",
                                    "Flashget P2P",
                                    "Jigiy Website",
                                    "Fling",
                                    "Caihong Messenger",
                                    "Netease WebMail",
                                    "Steganos Online Shield",
                                    "Tagged Android",
                                    "Puff Proxy",
                                    "Youdao",
                                    "iChat Gtalk",
                                    "Hulu Website",
                                    "Easy-Hide IP Proxy",
                                    "SinaUC Messenger",
                                    "Windows Live IM FileTransfer",
                                    "Storage.to FileTransfer",
                                    "Tube8 Streaming",
                                    "EXE File Download",
                                    "Live-sync Download",
                                    "Hola",
                                    "Pornhub Streaming",
                                    "Socks2HTTP Proxy",
                                    "Lok5 Proxy",
                                    "CyberghostVPN Web Proxy",
                                    "DAP FTP FileTransfer",
                                    "Zedge Android",
                                    "Yahoo Messenger File Receive",
                                    "Chikka Messenger",
                                    "HTTP-Tunnel Proxy",
                                    "Tor2Web Proxy",
                                    "FileMail Webbased Download",
                                    "Hiddenvillage Proxy",
                                    "Gtalk-Way2SMS",
                                    "TruPhone Android",
                                    "FTP Base",
                                    "Megaupload",
                                    "PD Proxy",
                                    "Baidu Messenger",
                                    "LogMeIn Remote Access",
                                    "CoolTalk Messenger",
                                    "Launchwebs Proxy",
                                    "Piolet FileTransfer P2P",
                                    "I2P Proxy",
                                    "Proxify-Tray Proxy",
                                    "Zelune Proxy",
                                    "Scydo Android",
                                    "WebAgent.Mail-ru Messenger",
                                    "PPLive Streaming",
                                    "Hide-Your-IP Proxy",
                                    "GMX WebMail",
                                    "Trillian Web Messenger",
                                    "Telex",
                                    "Manual Proxy Surfing",
                                    "ISL Desktop Conferencing",
                                    "Yahoo Messenger Chat",
                                    "Firefox Update",
                                    "ICQ Android",
                                    "Yuvutu Streaming",
                                    "RealTunnel Proxy",
                                    "Mediafire Download",
                                    "Surrogofier Proxy",
                                    "Eyejot",
                                    "DirectConnect P2P",
                                    "Operamini Proxy",
                                    "Android Market",
                                    "Engadget Android",
                                    "Raaga Android",
                                    "WeBuzz Web Messenger",
                                    "Badonga Download",
                                    "Yousendit Web Download",
                                    "Redtube Streaming",
                                    "CB Radio Chat Android",
                                    "Octopz Website",
                                    "Anonymox",
                                    "Crash Plan",
                                    "Meebo Messenger FileTransfer",
                                    "AirAIM Messenger",
                                    "Tunnel Guru",
                                    "Bebo Website",
                                    "RPC over HTTP Proxy",
                                    "IM+ Android",
                                    "Metin Game",
                                    "GaduGadu Messenger",
                                    "NateApp Android",
                                    "Spy-Agent Remote Access",
                                    "Timbuktu FileTransfer",
                                    "iBackup Application",
                                    "Orkut Android",
                                    "Pingfu Proxy",
                                    "Pokerstars Online Game",
                                    "SendSpace Android",
                                    "Youporn Streaming",
                                    "Invisible Surfing Proxy",
                                    "Vtunnel Proxy",
                                    "Tunnello",
                                    "Zoho Web Login"
                                ]
                            },
                            "RiskList": {
                                "Risk": "High"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "Proxyone",
                                    "SecureLine VPN",
                                    "Just Proxy VPN",
                                    "Psiphon Proxy",
                                    "ProxyProxy",
                                    "SkyVPN",
                                    "Amaze VPN",
                                    "Stealthnet P2P",
                                    "PrivateSurf.us",
                                    "NapMX Retrieve P2P",
                                    "Proxy Switcher Proxy",
                                    "Yoga VPN",
                                    "England Proxy",
                                    "Gom VPN",
                                    "VPN Master",
                                    "Just Open VPN",
                                    "Hide.Me",
                                    "Bypasstunnel.com",
                                    "Tiger VPN",
                                    "Proxifier Proxy",
                                    "FastSecureVPN",
                                    "MP3 Rocket Download",
                                    "TransferBigFiles Application",
                                    "Cyberoam Bypass Chrome Extension",
                                    "SkyEye VPN",
                                    "ItsHidden Proxy",
                                    "Betternet VPN",
                                    "CantFindMeProxy",
                                    "Shareaza P2P",
                                    "DC++ Hub List P2P",
                                    "Power VPN",
                                    "SoftEther VPN",
                                    "Surf-for-free.com",
                                    "VPN Robot",
                                    "Super VPN Master",
                                    "UltraVPN",
                                    "X-VPN",
                                    "Browsec VPN",
                                    "VeePN",
                                    "TorrentHunter Proxy",
                                    "MoonVPN",
                                    "Hot VPN",
                                    "Super VPN",
                                    "Hoxx Vpn",
                                    "OpenInternet",
                                    "PHProxy",
                                    "VPN Monster",
                                    "Cloud VPN",
                                    "RusVPN",
                                    "Speedify",
                                    "Mute P2P",
                                    "TransferBigFiles Web Download",
                                    "The Pirate Bay Proxy",
                                    "VPN 360",
                                    "NateMail WebMail",
                                    "Securitykiss Proxy",
                                    "Websurf",
                                    "FreeMyBrowser",
                                    "uProxy",
                                    "Your-Freedom Proxy",
                                    "Chrome Reduce Data Usage",
                                    "Unclogger VPN",
                                    "Britishproxy.uk Proxy",
                                    "ZenVPN",
                                    "Freegate Proxy",
                                    "VPN over 443",
                                    "Zero VPN",
                                    "Ants IRC Connect P2P",
                                    "WinMX P2P",
                                    "Classroom Spy",
                                    "Expatshield Proxy",
                                    "The Proxy Bay",
                                    "OpenDoor",
                                    "Snap VPN",
                                    "Ultrasurf Proxy",
                                    "CyberGhost VPN Proxy",
                                    "Simurgh Proxy",
                                    "Webproxy",
                                    "Unseen Online VPN",
                                    "Zalmos SSL Web Proxy for Free",
                                    "VyprVPN",
                                    "AppVPN",
                                    "BypassGeo",
                                    "Bearshare P2P",
                                    "Asproxy Web Proxy",
                                    "Pando P2P",
                                    "Easy Proxy",
                                    "VPN 365",
                                    "Lantern",
                                    "Office VPN",
                                    "Proton VPN",
                                    "Miro P2P",
                                    "Morphium.info",
                                    "Ants Initialization P2P",
                                    "Soulseek Download P2P",
                                    "FSecure Freedome VPN",
                                    "Tweakware VPN",
                                    "QQ VPN",
                                    "Redirection Web-Proxy",
                                    "Phex P2P",
                                    "Hamachi VPN Streaming",
                                    "TOR Proxy",
                                    "Ares Retrieve Chat Room",
                                    "UK-Proxy.org.uk Proxy",
                                    "Winny P2P",
                                    "MeHide.asia",
                                    "Alkasir Proxy",
                                    "Windscribe",
                                    "Eagle VPN",
                                    "eMule P2P",
                                    "FastVPN",
                                    "Boinc Messenger",
                                    "Tableau Public",
                                    "DotVPN",
                                    "Photon Flash Player & Browser",
                                    "Proxysite.com Proxy",
                                    "Ares Chat Room",
                                    "Private Tunnel",
                                    "Ares P2P",
                                    "Private VPN",
                                    "Epic Browser",
                                    "Green VPN",
                                    "GoldenKey VPN",
                                    "Cyazyproxy",
                                    "Hexa Tech VPN",
                                    "FinchVPN",
                                    "Vuze P2P",
                                    "WiFree Proxy",
                                    "Ninjaproxy.ninja",
                                    "VPN Free",
                                    "Hideman VPN",
                                    "VPN Lighter",
                                    "L2TP VPN",
                                    "ShellFire VPN",
                                    "ExpressVPN",
                                    "Speedy VPN",
                                    "Toonel",
                                    "Torrent Clients P2P",
                                    "EuropeProxy",
                                    "Hi VPN",
                                    "Freenet P2P",
                                    "Reduh Proxy",
                                    "Kugoo Playlist P2P",
                                    "Frozenway Proxy",
                                    "Soulseek Retrieving P2P",
                                    "Hide-N-Seek Proxy",
                                    "DashVPN",
                                    "Phantom VPN",
                                    "DNSCrypt",
                                    "CrossVPN",
                                    "USA IP",
                                    "Total VPN",
                                    "ZPN VPN",
                                    "ISAKMP VPN",
                                    "Hammer VPN",
                                    "Speed VPN",
                                    "Hotspotshield Proxy",
                                    "Blockless VPN",
                                    "Star VPN",
                                    "RemoboVPN Proxy",
                                    "SSL Proxy Browser",
                                    "TurboVPN",
                                    "PP VPN",
                                    "VPN Unlimited",
                                    "Astrill VPN",
                                    "Hello VPN",
                                    "SetupVPN",
                                    "JAP Proxy",
                                    "Heatseek Browser",
                                    "ProxyWebsite",
                                    "Private Internet Access VPN",
                                    "DC++ Download P2P",
                                    "Thunder VPN",
                                    "skyZIP",
                                    "TOR VPN",
                                    "Haitun VPN",
                                    "Bitcoin Proxy",
                                    "Worldcup Proxy",
                                    "Privatix VPN",
                                    "Ants P2P",
                                    "DC++ Connect P2P"
                                ]
                            },
                            "RiskList": {
                                "Risk": "Very High"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "Proxyone",
                                    "SecureLine VPN",
                                    "Just Proxy VPN",
                                    "Reindeer VPN",
                                    "Sslbrowser Proxy",
                                    "Tunnelbear Proxy Login",
                                    "Proxy Switcher Proxy",
                                    "Yoga VPN",
                                    "VPN in Touch",
                                    "AOL Desktop",
                                    "Hide.Me",
                                    "Tiger VPN",
                                    "Proxifier Proxy",
                                    "Spinmyass Proxy",
                                    "ProXPN Proxy",
                                    "ItsHidden Proxy",
                                    "Betternet VPN",
                                    "Gtunnel Proxy",
                                    "WebFreer Proxy",
                                    "Nateon Proxy",
                                    "Power VPN",
                                    "Surf-for-free.com",
                                    "Ghostsurf Proxy",
                                    "Fly Proxy",
                                    "Vpntunnel Proxy",
                                    "Super VPN Master",
                                    "UltraVPN",
                                    "SOCK5 Proxy",
                                    "X-VPN",
                                    "Browsec VPN",
                                    "Proxycap Proxy",
                                    "VeePN",
                                    "SumRando",
                                    "TorrentHunter Proxy",
                                    "NetLoop VPN",
                                    "Hot VPN",
                                    "IP-Shield Proxy",
                                    "Hoxx Vpn",
                                    "Opera Off Road Mode",
                                    "Proxmachine Proxy",
                                    "VPN Monster",
                                    "Speedify",
                                    "The Pirate Bay Proxy",
                                    "VPN 360",
                                    "FreeMyBrowser",
                                    "uProxy",
                                    "Netevader Proxy",
                                    "Unclogger VPN",
                                    "Proxy-service.de Proxy",
                                    "Britishproxy.uk Proxy",
                                    "VPN over 443",
                                    "Zero VPN",
                                    "Kproxyagent Proxy",
                                    "Expatshield Proxy",
                                    "The Proxy Bay",
                                    "OpenDoor",
                                    "Snap VPN",
                                    "Ultrasurf Proxy",
                                    "Rxproxy Proxy",
                                    "Proxyway Proxy",
                                    "VyprVPN",
                                    "AppVPN",
                                    "BypassGeo",
                                    "Easy Proxy",
                                    "Ztunnel Proxy",
                                    "Onavo",
                                    "CoralCDN Proxy",
                                    "Office VPN",
                                    "Proton VPN",
                                    "Morphium.info",
                                    "HTTPort Proxy",
                                    "Tweakware VPN",
                                    "QQ VPN",
                                    "Redirection Web-Proxy",
                                    "HOS Proxy",
                                    "Hopster Proxy",
                                    "Dtunnel Proxy",
                                    "VPNium Proxy",
                                    "MeHide.asia",
                                    "FreeVPN Proxy",
                                    "Eagle VPN",
                                    "Glype Proxy",
                                    "Proxeasy Web Proxy",
                                    "HTTP Tunnel Proxy",
                                    "DotVPN",
                                    "Jailbreak VPN",
                                    "OneClickVPN Proxy",
                                    "Photon Flash Player & Browser",
                                    "Mega Proxy",
                                    "VPNMakers Proxy",
                                    "ShadeYouVPN",
                                    "Max-Anonysurf Proxy",
                                    "Proxeasy Proxy",
                                    "Tunnelbear Proxy Data",
                                    "Vedivi-VPN Proxy",
                                    "Private VPN",
                                    "Gapp Proxy",
                                    "Meebo Repeater Proxy",
                                    "Privitize VPN Proxy",
                                    "Tigervpns",
                                    "Cyazyproxy",
                                    "Hexa Tech VPN",
                                    "FinchVPN",
                                    "WiFree Proxy",
                                    "VPN Free",
                                    "Hideman VPN",
                                    "ShellFire VPN",
                                    "ExpressVPN",
                                    "EuropeProxy",
                                    "Hi VPN",
                                    "Frozenway Proxy",
                                    "Auto-Hide IP Proxy",
                                    "Gbridge VPN Proxy",
                                    "DNSCrypt",
                                    "ZPN VPN",
                                    "Skydur Proxy",
                                    "Hide-My-IP Proxy",
                                    "Hotspotshield Proxy",
                                    "Globosurf Proxy",
                                    "Blockless VPN",
                                    "Star VPN",
                                    "SurfEasy VPN",
                                    "RemoboVPN Proxy",
                                    "SSL Proxy Browser",
                                    "TurboVPN",
                                    "Air Proxy",
                                    "VPN Unlimited",
                                    "Astrill VPN",
                                    "Hello VPN",
                                    "SetupVPN",
                                    "ProxyWebsite",
                                    "Camoproxy Proxy",
                                    "TOR VPN",
                                    "Sslpro.org Proxy",
                                    "Bitcoin Proxy",
                                    "Worldcup Proxy",
                                    "Privatix VPN",
                                    "Psiphon Proxy",
                                    "4everproxy Proxy",
                                    "ProxyProxy",
                                    "SkyVPN",
                                    "Btunnel Proxy",
                                    "CProxy Proxy",
                                    "Amaze VPN",
                                    "PrivateSurf.us",
                                    "Real-Hide IP Proxy",
                                    "Wallcooler VPN Proxy",
                                    "England Proxy",
                                    "Gom VPN",
                                    "VPN Master",
                                    "Just Open VPN",
                                    "Tunnelier",
                                    "Bypasstunnel.com",
                                    "Packetix Proxy",
                                    "FastSecureVPN",
                                    "Dynapass Proxy",
                                    "Ctunnel Proxy",
                                    "Suresome Proxy",
                                    "Cyberoam Bypass Chrome Extension",
                                    "SkyEye VPN",
                                    "Circumventor Proxy",
                                    "CantFindMeProxy",
                                    "Kepard Proxy",
                                    "SoftEther VPN",
                                    "VPN Robot",
                                    "StrongVPN",
                                    "K Proxy",
                                    "Proxyfree Web Proxy",
                                    "FreeU Proxy",
                                    "VNN-VPN Proxy",
                                    "MoonVPN",
                                    "MiddleSurf Proxy",
                                    "Super VPN",
                                    "Invisiblenet VPN",
                                    "OpenInternet",
                                    "PHProxy",
                                    "Justproxy Proxy",
                                    "Cloud VPN",
                                    "RusVPN",
                                    "Kongshare Proxy",
                                    "PingTunnel Proxy",
                                    "Hide-IP Browser Proxy",
                                    "Securitykiss Proxy",
                                    "Njutrino Proxy",
                                    "Websurf",
                                    "Idhide Proxy",
                                    "Your-Freedom Proxy",
                                    "Chrome Reduce Data Usage",
                                    "ZenVPN",
                                    "Steganos Online Shield",
                                    "Freegate Proxy",
                                    "Puff Proxy",
                                    "Bypassfw Proxy",
                                    "Easy-Hide IP Proxy",
                                    "Classroom Spy",
                                    "CyberGhost VPN Proxy",
                                    "Simurgh Proxy",
                                    "ZenMate",
                                    "Hola",
                                    "Webproxy",
                                    "Unseen Online VPN",
                                    "Socks2HTTP Proxy",
                                    "Lok5 Proxy",
                                    "SSlunblock Proxy",
                                    "CyberghostVPN Web Proxy",
                                    "Zalmos SSL Web Proxy for Free",
                                    "My-Addr(SSL) Proxy",
                                    "Asproxy Web Proxy",
                                    "VPN 365",
                                    "Lantern",
                                    "HTTP-Tunnel Proxy",
                                    "Tor2Web Proxy",
                                    "Hiddenvillage Proxy",
                                    "Vpndirect Proxy",
                                    "FSecure Freedome VPN",
                                    "Hamachi VPN Streaming",
                                    "TOR Proxy",
                                    "Cocoon",
                                    "PD Proxy",
                                    "UK-Proxy.org.uk Proxy",
                                    "Avoidr Web Proxy",
                                    "Launchwebs Proxy",
                                    "Divavu Proxy",
                                    "I2P Proxy",
                                    "Proxify-Tray Proxy",
                                    "Alkasir Proxy",
                                    "Zelune Proxy",
                                    "Windscribe",
                                    "Proximize Proxy",
                                    "FastVPN",
                                    "SOCK4 Proxy",
                                    "Hide-Your-IP Proxy",
                                    "Aniscartujo Web Proxy",
                                    "Telex",
                                    "Proxysite.com Proxy",
                                    "Manual Proxy Surfing",
                                    "Private Tunnel",
                                    "Spotflux Proxy",
                                    "RealTunnel Proxy",
                                    "Epic Browser",
                                    "Green VPN",
                                    "Surrogofier Proxy",
                                    "GoldenKey VPN",
                                    "Operamini Proxy",
                                    "Mysslproxy Proxy",
                                    "Ninjaproxy.ninja",
                                    "VPN Lighter",
                                    "L2TP VPN",
                                    "uVPN",
                                    "Speedy VPN",
                                    "Toonel",
                                    "Reduh Proxy",
                                    "Anonymox",
                                    "Hide-N-Seek Proxy",
                                    "DashVPN",
                                    "Phantom VPN",
                                    "CrossVPN",
                                    "Tunnel Guru",
                                    "USA IP",
                                    "Total VPN",
                                    "ISAKMP VPN",
                                    "Hammer VPN",
                                    "RPC over HTTP Proxy",
                                    "Speed VPN",
                                    "PP VPN",
                                    "Pingfu Proxy",
                                    "JAP Proxy",
                                    "Private Internet Access VPN",
                                    "Thunder VPN",
                                    "skyZIP",
                                    "Invisible Surfing Proxy",
                                    "Vtunnel Proxy",
                                    "Haitun VPN",
                                    "Tunnello"
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
                                    "Zalo",
                                    "WebDAV",
                                    "Mail-ru Messenger",
                                    "Kaseya Client Connect",
                                    "Rediffbol Messenger",
                                    "Pipedrive Upload",
                                    "Between",
                                    "AOL Desktop",
                                    "Hike",
                                    "DeskGate",
                                    "ShareBlast",
                                    "Fileserver File Transfer",
                                    "Storage.to Download",
                                    "Weezo",
                                    "Dropbox Download",
                                    "QQ Messenger",
                                    "Foxit Reader Update",
                                    "Xero Download",
                                    "Google Street Android",
                                    "DAP Download",
                                    "iCloud Photo Stream",
                                    "TelTel VOIP",
                                    "126 Mail",
                                    "AIM Express Messenger",
                                    "Avast Antivirus Update",
                                    "Tixati P2P",
                                    "WikiEncyclopedia Android",
                                    "Microsoft NetMeeting",
                                    "RAR File Download",
                                    "UbuntuOne FileTransfer",
                                    "TripAdvisor Android",
                                    "Behance Upload",
                                    "Apple-Juice P2P",
                                    "WeTransfer Upload",
                                    "Akamai Client",
                                    "Picasa Website",
                                    "Opera Off Road Mode",
                                    "Citrix Receiver",
                                    "eFolder",
                                    "FileMail WebMail",
                                    "Pcloud Download",
                                    "Clubbox",
                                    "Yahoo Messenger File Transfer",
                                    "File.host File Transfer",
                                    "TransferBigFiles Web Download",
                                    "E-Snips Download",
                                    "GetRight Download",
                                    "SMTP Executable Attachment",
                                    "Klite Initiation P2P",
                                    "Turbobit Download",
                                    "Hyves Messenger",
                                    "Tango Android",
                                    "1Fichier Upload",
                                    "FileRio Download",
                                    "MSN2GO Messenger",
                                    "YY Voice Messenger",
                                    "MQTT",
                                    "Diino File Download",
                                    "Easy Proxy",
                                    "Yourfilehost Download",
                                    "Onavo",
                                    "100BAO P2P",
                                    "DNS Multiple QNAME",
                                    "Foursquare Android",
                                    "Docstoc File Transfer",
                                    "IP Messenger FileTransfer",
                                    "Ares Retrieve Chat Room",
                                    "WhatsApp File Transfer",
                                    "Taobao Aliwangwang Messenger",
                                    "Bebo WebMail",
                                    "Rapidshare Download",
                                    "Zimbra",
                                    "Bearshare Download",
                                    "MP3 File Download",
                                    "AVG Antivirus Update",
                                    "Ares Chat Room",
                                    "Sharepoint Search",
                                    "Uploading File Transfer",
                                    "Kool Web Messenger",
                                    "CloudMe Storage Login",
                                    "Twitter Upload",
                                    "Piolet Initialization P2P",
                                    "Meebo Repeater",
                                    "SquirrelMail Attachment",
                                    "Gigaup File Transfer",
                                    "CodeAnywhere Android",
                                    "Instant Housecall Remote Access",
                                    "iCloud Mail",
                                    "Morpheus P2P",
                                    "SoMud",
                                    "Zoho WebMessenger",
                                    "CloudApp",
                                    "Bitshare Upload",
                                    "Facebook Status Update",
                                    "Zippyshare Download",
                                    "Soulseek Retrieving P2P",
                                    "Hipfile Upload",
                                    "TeamViewer FileTransfer",
                                    "X-Fire Messenger",
                                    "BookMyShow Android",
                                    "Netload File Transfer",
                                    "Gtalk Messenger FileTransfer",
                                    "Putlocker Download",
                                    "Garena Web Messenger",
                                    "IMO Messenger",
                                    "SurfEasy VPN",
                                    "Sohu WebMail",
                                    "4shared File Transfer",
                                    "Trillian Messenger",
                                    "Backblaze",
                                    "Heatseek Browser",
                                    "LimeWire",
                                    "IMO-Chat Android",
                                    "Kaspersky Antivirus Update",
                                    "Microsoft Outlook",
                                    "DC++ Connect P2P",
                                    "Twitter Website",
                                    "MSN Shell Messenger",
                                    "ICQ Messenger",
                                    "Stealthnet P2P",
                                    "Yahoo Webmail File Attach",
                                    "PCVisit.de Remote Access",
                                    "DirectTV Android",
                                    "KakaoTalk",
                                    "Zoho Meeting Conferencing",
                                    "vBuzzer Android",
                                    "Camfrog Messenger",
                                    "WebEx",
                                    "Yandex Disk",
                                    "NakidoFlag File Transfer",
                                    "T-Online Webmail",
                                    "SendSpace",
                                    "Citrix GoToTraining",
                                    "ZIP File Download",
                                    "Copy",
                                    "Rapidgator Upload",
                                    "TransferBigFiles Application",
                                    "Box",
                                    "Hotline Download",
                                    "Fring Android",
                                    "Attix5 Backup",
                                    "Odnoklassniki Android",
                                    "Napster P2P",
                                    "HPE MyRoom",
                                    "Nateon Messenger",
                                    "Instant-t Messenger",
                                    "LifeSize Cloud",
                                    "Zippyshare Upload",
                                    "LinkedIN Compose Webmail",
                                    "My Mail.ru",
                                    "ICQ2GO Messenger",
                                    "Mail.com File Storage",
                                    "HTTP Resume FileTransfer",
                                    "Vidyo",
                                    "Badongo File Download",
                                    "Pipedrive Download",
                                    "Chatroulette Web Messenger",
                                    "AnyMeeting Connect",
                                    "IMPlus Web Messenger",
                                    "Facebook Website",
                                    "iLoveIM Web Messenger",
                                    "Multi Thread File Transfer",
                                    "Cocstream Download",
                                    "Signal Private Messenger",
                                    "Kaseya Portal Login",
                                    "Issuu File Transfer",
                                    "Webex File Transfer",
                                    "Caihong Messenger",
                                    "Divshare File Transfer",
                                    "Hangame",
                                    "Youdao",
                                    "Classroom Spy",
                                    "IMI Messenger",
                                    "IBM CXN Cloud Files",
                                    "Storage.to FileTransfer",
                                    "File2hd Web Download",
                                    "RenRen Messenger",
                                    "Lync",
                                    "MEO Cloud",
                                    "Timbuktu Messenger",
                                    "DAP FTP FileTransfer",
                                    "QQ Remote Access",
                                    "Yahoo Messenger File Receive",
                                    "Goo Webmail",
                                    "FileRio Upload",
                                    "Snapchat",
                                    "TrendMicro AV Update",
                                    "Yahoo Groups",
                                    "Google Location",
                                    "AttachLargeFile Download",
                                    "Filecloud.io",
                                    "MxiT Android",
                                    "Ants Initialization P2P",
                                    "WeChat Web",
                                    "Megaupload",
                                    "Mail.com Compose Mail",
                                    "Piolet FileTransfer P2P",
                                    "Hightail",
                                    "Tumblr Post",
                                    "Salesforce Web Login",
                                    "LinkedIN Android",
                                    "CricInfo Android",
                                    "TwitVid Upload/Download",
                                    "Scydo Android",
                                    "Orange Webmail",
                                    "GMX WebMail",
                                    "CNN News Android",
                                    "TiKL",
                                    "Firefox Update",
                                    "Meetup Message",
                                    "Vchat",
                                    "ICQ Android",
                                    "DingTalk",
                                    "MediaGet P2P",
                                    "WeTransfer Download",
                                    "Mediafire Download",
                                    "Telenet Webmail",
                                    "Depositfiles Download",
                                    "ICU Messenger",
                                    "iPTT",
                                    "E-Bay Android",
                                    "Vuze P2P",
                                    "Raaga Android",
                                    "Discord",
                                    "Comment Attachment - Facebook",
                                    "Turbobit Upload",
                                    "HipChat",
                                    "WeTransfer Base",
                                    "Badonga Download",
                                    "Yousendit Web Download",
                                    "TrendMicro SafeSync",
                                    "Uptobox Upload",
                                    "Bayfiles Upload",
                                    "Meebo Messenger FileTransfer",
                                    "Sendspace Upload",
                                    "AirAIM Messenger",
                                    "NateApp Android",
                                    "Free Download Manager",
                                    "Iozeta",
                                    "Timbuktu FileTransfer",
                                    "iCloud Drive",
                                    "iBackup Application",
                                    "ChatWork",
                                    "OneDrive File Upload",
                                    "Pcloud Upload",
                                    "SnapBucket Android",
                                    "Ants P2P",
                                    "Live.ly",
                                    "Putlocker Upload",
                                    "WeChat File Transfer",
                                    "Skype",
                                    "Manolito P2P Download",
                                    "VzoChat Messenger",
                                    "BlueJeans Conferencing",
                                    "Google Drive File Download",
                                    "Tubemate",
                                    "Axifile File Transfer",
                                    "Bitshare Download",
                                    "Mega",
                                    "MS Essentials AV Update",
                                    "Jabber",
                                    "Plustransfer Upload",
                                    "MP3 Rocket Download",
                                    "AOL WebMail",
                                    "filestube Search",
                                    "Archive.Org",
                                    "EspnCricinfo Android",
                                    "Carbonite",
                                    "MyDownloader",
                                    "1Fichier Download",
                                    "Justcloud File Transfer",
                                    "iCloud",
                                    "Citrix Online",
                                    "WhatsApp Web",
                                    "Eset NoD32 Update",
                                    "Join-Me Conferencing",
                                    "QQ Messenger File Transfer",
                                    "Jumblo VOIP",
                                    "Chikka Web Messenger",
                                    "Mig33 Android",
                                    "Dl Free Upload Download",
                                    "Igoogle-Gtalk",
                                    "1 & 1 Webmail",
                                    "Hovrs Messenger",
                                    "Fetion Messenger",
                                    "Twitter Android",
                                    "Gmail Attachment",
                                    "Box File Download",
                                    "Hush WebMail",
                                    "Google Sky Android",
                                    "Digsby Messenger",
                                    "COX WebMail",
                                    "OCN Webmail",
                                    "Mail.com WebMail",
                                    "Sharepoint",
                                    "Mobogenie",
                                    "WinMX P2P",
                                    "SugarSync FileTransfer",
                                    "SendMyWay Upload",
                                    "Box File Upload",
                                    "MSN-Way2SMS WebMail",
                                    "Imhaha Web Messenger",
                                    "AIM File Transfer",
                                    "TwitPic Upload/Download",
                                    "Viber Message",
                                    "Bearshare P2P",
                                    "Myspace Chat",
                                    "Peercast P2P",
                                    "Google Drive Base",
                                    "Eyejot Web Messenger",
                                    "Mendeley Desktop",
                                    "Gtalk Messenger",
                                    "Soulseek Download P2P",
                                    "Phex P2P",
                                    "Multiupload Download",
                                    "Citrix ICA",
                                    "BBM",
                                    "Eagleget",
                                    "AOL Mail Attachment",
                                    "TalkBox Android",
                                    "Hotfile Download",
                                    "PalTalk Messenger",
                                    "ISPQ Messenger",
                                    "Mobyler Android",
                                    "eMule P2P",
                                    "Fastmail Webmail",
                                    "Tableau Public",
                                    "Scribd File Transfer",
                                    "IMVU Messenger",
                                    "Xero Upload",
                                    "Rapidgator Download",
                                    "LinkedIN Messenger File Download",
                                    "Meebo Website",
                                    "Crocko Upload",
                                    "Line Messenger File Transfer",
                                    "Dropbox Base",
                                    "Odnoklassniki Web Messenger",
                                    "Airset Access",
                                    "BeAnywhere",
                                    "SOMA Messanger",
                                    "Google Drive File Upload",
                                    "Lightshot",
                                    "HotFile Website",
                                    "SoundHound Android",
                                    "2shared Download",
                                    "Okurin File Transfer",
                                    "Egnyte File Transfer",
                                    "Tellagami Share",
                                    "Imesh P2P",
                                    "Kugoo Playlist P2P",
                                    "WhatsCall",
                                    "Comcast",
                                    "Timbuktu DesktopMail",
                                    "Plustransfer Download",
                                    "Sendspace Download",
                                    "LiveMeeting Conferencing",
                                    "Dropsend Download Applications",
                                    "Screen Connect",
                                    "Altools Update",
                                    "Goggles Android",
                                    "Avaya Conference FileTransfer",
                                    "WocChat Messenger",
                                    "Front",
                                    "DC++ Download P2P",
                                    "HTTP File Upload",
                                    "ASUS WebStorage",
                                    "My SharePoint",
                                    "NTR Cloud",
                                    "Palringo Messenger",
                                    "Gmail Android Application",
                                    "Talkray",
                                    "Facebook Android",
                                    "Uptobox",
                                    "2shared Upload",
                                    "Zshare Upload",
                                    "OneDrive Application",
                                    "NapMX Retrieve P2P",
                                    "AnyMeeting WebLogin",
                                    "GoChat Android",
                                    "Daum WebMail",
                                    "OneDrive File Download",
                                    "PI-Chat Messenger",
                                    "Ebuddy Web Messenger",
                                    "Internet Download Manager",
                                    "Qeep Android",
                                    "QQ Download P2P",
                                    "VK Message",
                                    "Sharepoint Calendar",
                                    "Windows Live Website",
                                    "AIM Android",
                                    "GitHub Upload",
                                    "SlideShare Upload",
                                    "Ebuddy Android",
                                    "OLX Android",
                                    "Panda Antivirus Update",
                                    "Shareaza P2P",
                                    "Bigupload File Transfer",
                                    "DC++ Hub List P2P",
                                    "Supremo Remote Access",
                                    "Datei.to FileTransfer",
                                    "IBM Notes",
                                    "Zoom Meetings",
                                    "SlideShare Download",
                                    "Soul Attempt P2P",
                                    "OKCupid Android",
                                    "Viber Media",
                                    "Cubby File transfer",
                                    "MessengerFX",
                                    "Rambler Mail",
                                    "LiveGO Messenger",
                                    "LinkedIN Messenger File Upload",
                                    "Moxtra",
                                    "Shazam Android",
                                    "Embedupload File Transfer",
                                    "Telegram",
                                    "Fileguri P2P",
                                    "Uptobox Download",
                                    "Mediaget Installer Download",
                                    "GMX Mail Attachment",
                                    "Outlook.com File Attach",
                                    "GaduGadu Web Messenger",
                                    "SlideShare",
                                    "Minus Upload",
                                    "Nomadesk Download",
                                    "Garena Messenger",
                                    "Gtalk Android",
                                    "Megashares Upload",
                                    "Yahoo WebMail",
                                    "IP Messenger",
                                    "Flashget P2P",
                                    "Google Plus Hangouts",
                                    "Zippyshare",
                                    "Gmail WebMail",
                                    "Google Safebrowsing",
                                    "Tagged Android",
                                    "Chat On",
                                    "Palringo Web Messenger",
                                    "iChat Gtalk",
                                    "Ants IRC Connect P2P",
                                    "Antivir Antivirus Update",
                                    "Omegle Web Messenger",
                                    "SinaUC Messenger",
                                    "Windows Live IM FileTransfer",
                                    "VK Mail",
                                    "EXE File Download",
                                    "Live-sync Download",
                                    "Alpemix",
                                    "Tortoise SVN",
                                    "Yandex Mail",
                                    "Apt-Get Command",
                                    "Hotfile Upload",
                                    "VirtualBox Update",
                                    "Pando P2P",
                                    "Zedge Android",
                                    "Chikka Messenger",
                                    "Korea WebMail",
                                    "Bebo WebChat IM",
                                    "Microsoft Teams",
                                    "Miro P2P",
                                    "FileMail Webbased Download",
                                    "Filer.cx File Transfer",
                                    "TruPhone Android",
                                    "Bonpoo File Transfer",
                                    "pCloud",
                                    "FTP Base",
                                    "Odrive",
                                    "Baidu Messenger",
                                    "Google Hangout Android App",
                                    "CoolTalk Messenger",
                                    "Winny P2P",
                                    "I2P Proxy",
                                    "Excite Mail",
                                    "TuneIN Radio Android",
                                    "Zshare Download",
                                    "Game Center",
                                    "DaumMaps Android",
                                    "ADrive Web Upload",
                                    "Hyves WebMail",
                                    "TrueConf",
                                    "Trillian Web Messenger",
                                    "Tox",
                                    "Yahoo Messenger Chat",
                                    "Voxer Walkie-Talkie PTT",
                                    "Ares P2P",
                                    "Outlook.com",
                                    "GitHub Download",
                                    "Blogger Android",
                                    "DirectConnect P2P",
                                    "Android Market",
                                    "Engadget Android",
                                    "Brothersoft Website",
                                    "Infoseek Webmail",
                                    "G Suite",
                                    "WeBuzz Web Messenger",
                                    "Fotki Media Upload",
                                    "YahooMail Calendar",
                                    "Nimbuzz IM Update",
                                    "Torrent Clients P2P",
                                    "Filedropper File Transfer",
                                    "Freenet P2P",
                                    "Skype Services",
                                    "CB Radio Chat Android",
                                    "Crash Plan",
                                    "Dropbox File Upload",
                                    "Depositfiles Upload",
                                    "Google Plus Upload",
                                    "IM+ Android",
                                    "Tumblr Android",
                                    "GaduGadu Messenger",
                                    "Spy-Agent Remote Access",
                                    "Orkut Android",
                                    "SendSpace Android",
                                    "Waze Android",
                                    "GMX Compose Mail",
                                    "Sabercathost Upload",
                                    "OneDrive Base"
                                ]
                            },
                            "CharacteristicsList": {
                                "Characteristics": "Transfer files"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "Putlocker Upload",
                                    "WeChat File Transfer",
                                    "2shared Upload",
                                    "Zshare Upload",
                                    "Yahoo Messenger File Receive",
                                    "FileRio Upload",
                                    "Yahoo Webmail File Attach",
                                    "Google Drive File Download",
                                    "Axifile File Transfer",
                                    "Mendeley Desktop",
                                    "Filecloud.io",
                                    "OneDrive File Download",
                                    "Filer.cx File Transfer",
                                    "Docstoc File Transfer",
                                    "Bonpoo File Transfer",
                                    "Mega",
                                    "IP Messenger FileTransfer",
                                    "NakidoFlag File Transfer",
                                    "SendSpace",
                                    "Fileserver File Transfer",
                                    "ZIP File Download",
                                    "Hightail",
                                    "Rapidgator Upload",
                                    "TwitVid Upload/Download",
                                    "SlideShare Upload",
                                    "Bigupload File Transfer",
                                    "We Heart It Upload",
                                    "MP3 File Download",
                                    "Scribd File Transfer",
                                    "SlideShare Download",
                                    "Crocko Upload",
                                    "Line Messenger File Transfer",
                                    "Cubby File transfer",
                                    "Uploading File Transfer",
                                    "Justcloud File Transfer",
                                    "iCloud",
                                    "Serv-U RemoteAccess FileTransfer",
                                    "WeTransfer Download",
                                    "Google Drive File Upload",
                                    "RAR File Download",
                                    "Embedupload File Transfer",
                                    "JDownloader",
                                    "QQ Messenger File Transfer",
                                    "UbuntuOne FileTransfer",
                                    "Gigaup File Transfer",
                                    "Uptobox Download",
                                    "WeTransfer Upload",
                                    "HTTP Resume FileTransfer",
                                    "Fotki Media Upload",
                                    "Outlook.com File Attach",
                                    "Okurin File Transfer",
                                    "Egnyte File Transfer",
                                    "Turbobit Upload",
                                    "WeTransfer Base",
                                    "CloudApp",
                                    "Filedropper File Transfer",
                                    "Bitshare Upload",
                                    "TrendMicro SafeSync",
                                    "Uptobox Upload",
                                    "Minus Upload",
                                    "Bayfiles Upload",
                                    "Hipfile Upload",
                                    "Meebo Messenger FileTransfer",
                                    "Gmail Attachment",
                                    "Clubbox",
                                    "Sendspace Upload",
                                    "File.host File Transfer",
                                    "Yahoo Messenger File Transfer",
                                    "TeamViewer FileTransfer",
                                    "Last.fm Free Downloads",
                                    "Netload File Transfer",
                                    "Gtalk Messenger FileTransfer",
                                    "Megashares Upload",
                                    "Multi Thread File Transfer",
                                    "Issuu File Transfer",
                                    "Zippyshare",
                                    "Webex File Transfer",
                                    "4shared File Transfer",
                                    "Divshare File Transfer",
                                    "Timbuktu FileTransfer",
                                    "1Fichier Upload",
                                    "Avaya Conference FileTransfer",
                                    "SendMyWay Upload",
                                    "SugarSync FileTransfer",
                                    "HTTP File Upload",
                                    "Windows Live IM FileTransfer",
                                    "Mega Download",
                                    "AIM File Transfer",
                                    "EXE File Download",
                                    "Tortoise SVN",
                                    "OneDrive File Upload",
                                    "TwitPic Upload/Download",
                                    "Hotfile Upload",
                                    "Uptobox"
                                ]
                            },
                            "CategoryList": {
                                "Category": "File Transfer"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        }
                    ]
                }
            },
            {
                "DefaultAction": "Allow",
                "Description": "Drops traffic that are classified under high risk apps (Risk Level- 4 and 5).",
                "IsDeleted": false,
                "MicroAppSupport": "True",
                "Name": "Block high risk (Risk Level 4 and 5) apps",
                "RuleList": {
                    "Rule": [
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "Sopcast Streaming",
                                    "Sslbrowser Proxy",
                                    "Mail-ru Messenger",
                                    "Storage.to Download",
                                    "AOL Radio Website",
                                    "NeverMail WebMail",
                                    "Weezo",
                                    "Spinmyass Proxy",
                                    "ProXPN Proxy",
                                    "AOL WebMail",
                                    "WhatsApp",
                                    "Gtunnel Proxy",
                                    "DroidVPN",
                                    "Nateon Proxy",
                                    "Ghostsurf Proxy",
                                    "MyDownloader",
                                    "DAP Download",
                                    "GoBoogy Login P2P",
                                    "Fly Proxy",
                                    "Vpntunnel Proxy",
                                    "iCAP Business",
                                    "Tixati P2P",
                                    "Proxycap Proxy",
                                    "RAR File Download",
                                    "QQ Messenger File Transfer",
                                    "SumRando",
                                    "NetLoop VPN",
                                    "Apple-Juice P2P",
                                    "Chikka Web Messenger",
                                    "Livedoor Web Login",
                                    "Akamai Client",
                                    "Mig33 Android",
                                    "Opera Off Road Mode",
                                    "Dl Free Upload Download",
                                    "Quick Player Streaming",
                                    "FileMail WebMail",
                                    "Live Station Streaming",
                                    "Propel Accelerator",
                                    "Yahoo Messenger File Transfer",
                                    "E-Snips Download",
                                    "Digsby Messenger",
                                    "Klite Initiation P2P",
                                    "Sightspeed VOIP",
                                    "Classmates Website",
                                    "Tango Android",
                                    "Tudou Streaming",
                                    "Kproxyagent Proxy",
                                    "Imhaha Web Messenger",
                                    "Rxproxy Proxy",
                                    "Proxyway Proxy",
                                    "iConnectHere",
                                    "Sina WebMail",
                                    "Absolute Computrance",
                                    "VNC Remote Access",
                                    "Ztunnel Proxy",
                                    "Myspace Chat",
                                    "100BAO P2P",
                                    "Peercast P2P",
                                    "Gtalk Messenger",
                                    "HTTPort Proxy",
                                    "Bestporntube Streaming",
                                    "HOS Proxy",
                                    "IP Messenger FileTransfer",
                                    "Multiupload Download",
                                    "Hopster Proxy",
                                    "Citrix ICA",
                                    "TalkBox Android",
                                    "VPNium Proxy",
                                    "FreeVPN Proxy",
                                    "Rapidshare Download",
                                    "PalTalk Messenger",
                                    "Bearshare Download",
                                    "ISPQ Messenger",
                                    "Glype Proxy",
                                    "Mobyler Android",
                                    "Proxeasy Web Proxy",
                                    "HTTP Tunnel Proxy",
                                    "MP3 File Download",
                                    "Jailbreak VPN",
                                    "OneClickVPN Proxy",
                                    "LastPass",
                                    "Mega Proxy",
                                    "VPNMakers Proxy",
                                    "ShadeYouVPN",
                                    "Eroom Website",
                                    "Max-Anonysurf Proxy",
                                    "Proxeasy Proxy",
                                    "Vedivi-VPN Proxy",
                                    "Odnoklassniki Web Messenger",
                                    "Gapp Proxy",
                                    "56.com Streaming",
                                    "xHamster Streaming",
                                    "Lightshot",
                                    "Piolet Initialization P2P",
                                    "HotFile Website",
                                    "SoundHound Android",
                                    "Privitize VPN Proxy",
                                    "CodeAnywhere Android",
                                    "QuickTime Streaming",
                                    "Morpheus P2P",
                                    "Imesh P2P",
                                    "Auto-Hide IP Proxy",
                                    "Timbuktu DesktopMail",
                                    "Sendspace Download",
                                    "Gtalk Messenger FileTransfer",
                                    "Skydur Proxy",
                                    "Hide-My-IP Proxy",
                                    "Globosurf Proxy",
                                    "SurfEasy VPN",
                                    "Avaya Conference FileTransfer",
                                    "WocChat Messenger",
                                    "Trillian Messenger",
                                    "Napster Streaming",
                                    "Camoproxy Proxy",
                                    "ASUS WebStorage",
                                    "IMO-Chat Android",
                                    "QQ Web Messenger",
                                    "NTR Cloud",
                                    "Palringo Messenger",
                                    "Baidu IME",
                                    "Serv-U Remote Access",
                                    "ICQ Messenger",
                                    "DirectTV Android",
                                    "GoChat Android",
                                    "Real-Hide IP Proxy",
                                    "Genesys Website",
                                    "PI-Chat Messenger",
                                    "Ebuddy Web Messenger",
                                    "Internet Download Manager",
                                    "vBuzzer Android",
                                    "QQ Download P2P",
                                    "Mail-ru WebMail",
                                    "Baofeng Website",
                                    "Tunnelier",
                                    "ZIP File Download",
                                    "Packetix Proxy",
                                    "AIM Android",
                                    "Dynapass Proxy",
                                    "Pornerbros Streaming",
                                    "Suresome Proxy",
                                    "Hotline Download",
                                    "Circumventor Proxy",
                                    "Shockwave Based Streaming",
                                    "Datei.to FileTransfer",
                                    "Yourlust Streaming",
                                    "Ace2Three Game",
                                    "Fring Android",
                                    "Limelight Playlist Streaming",
                                    "Eyejot Video Message",
                                    "Soul Attempt P2P",
                                    "Ali WangWang Remote Access",
                                    "OKCupid Android",
                                    "Odnoklassniki Android",
                                    "Napster P2P",
                                    "StrongVPN",
                                    "K Proxy",
                                    "Proxyfree Web Proxy",
                                    "FreeU Proxy",
                                    "VNN-VPN Proxy",
                                    "World Of Warcraft Game",
                                    "R-Exec Remote Access",
                                    "Shazam Android",
                                    "MiddleSurf Proxy",
                                    "Fileguri P2P",
                                    "Invisiblenet VPN",
                                    "Mediaget Installer Download",
                                    "Vidyo",
                                    "Chatroulette Web Messenger",
                                    "GaduGadu Web Messenger",
                                    "AnyMeeting Connect",
                                    "Kongshare Proxy",
                                    "Flickr Web Upload",
                                    "PingTunnel Proxy",
                                    "Squirrelmail WebMail",
                                    "PPStream Streaming",
                                    "Hide-IP Browser Proxy",
                                    "Gtalk Android",
                                    "Megashares Upload",
                                    "Njutrino Proxy",
                                    "iLoveIM Web Messenger",
                                    "Cocstream Download",
                                    "Flashget P2P",
                                    "Jigiy Website",
                                    "Fling",
                                    "Caihong Messenger",
                                    "Netease WebMail",
                                    "Steganos Online Shield",
                                    "Tagged Android",
                                    "Puff Proxy",
                                    "Youdao",
                                    "iChat Gtalk",
                                    "Hulu Website",
                                    "Easy-Hide IP Proxy",
                                    "SinaUC Messenger",
                                    "Windows Live IM FileTransfer",
                                    "Storage.to FileTransfer",
                                    "Tube8 Streaming",
                                    "EXE File Download",
                                    "Live-sync Download",
                                    "Hola",
                                    "Pornhub Streaming",
                                    "Socks2HTTP Proxy",
                                    "Lok5 Proxy",
                                    "CyberghostVPN Web Proxy",
                                    "DAP FTP FileTransfer",
                                    "Zedge Android",
                                    "Yahoo Messenger File Receive",
                                    "Chikka Messenger",
                                    "HTTP-Tunnel Proxy",
                                    "Tor2Web Proxy",
                                    "FileMail Webbased Download",
                                    "Hiddenvillage Proxy",
                                    "Gtalk-Way2SMS",
                                    "TruPhone Android",
                                    "FTP Base",
                                    "Megaupload",
                                    "PD Proxy",
                                    "Baidu Messenger",
                                    "LogMeIn Remote Access",
                                    "CoolTalk Messenger",
                                    "Launchwebs Proxy",
                                    "Piolet FileTransfer P2P",
                                    "I2P Proxy",
                                    "Proxify-Tray Proxy",
                                    "Zelune Proxy",
                                    "Scydo Android",
                                    "WebAgent.Mail-ru Messenger",
                                    "PPLive Streaming",
                                    "Hide-Your-IP Proxy",
                                    "GMX WebMail",
                                    "Trillian Web Messenger",
                                    "Telex",
                                    "Manual Proxy Surfing",
                                    "ISL Desktop Conferencing",
                                    "Yahoo Messenger Chat",
                                    "Firefox Update",
                                    "ICQ Android",
                                    "Yuvutu Streaming",
                                    "RealTunnel Proxy",
                                    "Mediafire Download",
                                    "Surrogofier Proxy",
                                    "Eyejot",
                                    "DirectConnect P2P",
                                    "Operamini Proxy",
                                    "Android Market",
                                    "Engadget Android",
                                    "Raaga Android",
                                    "WeBuzz Web Messenger",
                                    "Badonga Download",
                                    "Yousendit Web Download",
                                    "Redtube Streaming",
                                    "CB Radio Chat Android",
                                    "Octopz Website",
                                    "Anonymox",
                                    "Crash Plan",
                                    "Meebo Messenger FileTransfer",
                                    "AirAIM Messenger",
                                    "Tunnel Guru",
                                    "Bebo Website",
                                    "RPC over HTTP Proxy",
                                    "IM+ Android",
                                    "Metin Game",
                                    "GaduGadu Messenger",
                                    "NateApp Android",
                                    "Spy-Agent Remote Access",
                                    "Timbuktu FileTransfer",
                                    "iBackup Application",
                                    "Orkut Android",
                                    "Pingfu Proxy",
                                    "Pokerstars Online Game",
                                    "SendSpace Android",
                                    "Youporn Streaming",
                                    "Invisible Surfing Proxy",
                                    "Vtunnel Proxy",
                                    "Tunnello",
                                    "Zoho Web Login"
                                ]
                            },
                            "RiskList": {
                                "Risk": "High"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        },
                        {
                            "Action": "Deny",
                            "ApplicationList": {
                                "Application": [
                                    "Proxyone",
                                    "SecureLine VPN",
                                    "Just Proxy VPN",
                                    "Psiphon Proxy",
                                    "ProxyProxy",
                                    "SkyVPN",
                                    "Amaze VPN",
                                    "Stealthnet P2P",
                                    "PrivateSurf.us",
                                    "NapMX Retrieve P2P",
                                    "Proxy Switcher Proxy",
                                    "Yoga VPN",
                                    "England Proxy",
                                    "Gom VPN",
                                    "VPN Master",
                                    "Just Open VPN",
                                    "Hide.Me",
                                    "Bypasstunnel.com",
                                    "Tiger VPN",
                                    "Proxifier Proxy",
                                    "FastSecureVPN",
                                    "MP3 Rocket Download",
                                    "TransferBigFiles Application",
                                    "Cyberoam Bypass Chrome Extension",
                                    "SkyEye VPN",
                                    "ItsHidden Proxy",
                                    "Betternet VPN",
                                    "CantFindMeProxy",
                                    "Shareaza P2P",
                                    "DC++ Hub List P2P",
                                    "Power VPN",
                                    "SoftEther VPN",
                                    "Surf-for-free.com",
                                    "VPN Robot",
                                    "Super VPN Master",
                                    "UltraVPN",
                                    "X-VPN",
                                    "Browsec VPN",
                                    "VeePN",
                                    "TorrentHunter Proxy",
                                    "MoonVPN",
                                    "Hot VPN",
                                    "Super VPN",
                                    "Hoxx Vpn",
                                    "OpenInternet",
                                    "PHProxy",
                                    "VPN Monster",
                                    "Cloud VPN",
                                    "RusVPN",
                                    "Speedify",
                                    "Mute P2P",
                                    "TransferBigFiles Web Download",
                                    "The Pirate Bay Proxy",
                                    "VPN 360",
                                    "NateMail WebMail",
                                    "Securitykiss Proxy",
                                    "Websurf",
                                    "FreeMyBrowser",
                                    "uProxy",
                                    "Your-Freedom Proxy",
                                    "Chrome Reduce Data Usage",
                                    "Unclogger VPN",
                                    "Britishproxy.uk Proxy",
                                    "ZenVPN",
                                    "Freegate Proxy",
                                    "VPN over 443",
                                    "Zero VPN",
                                    "Ants IRC Connect P2P",
                                    "WinMX P2P",
                                    "Classroom Spy",
                                    "Expatshield Proxy",
                                    "The Proxy Bay",
                                    "OpenDoor",
                                    "Snap VPN",
                                    "Ultrasurf Proxy",
                                    "CyberGhost VPN Proxy",
                                    "Simurgh Proxy",
                                    "Webproxy",
                                    "Unseen Online VPN",
                                    "Zalmos SSL Web Proxy for Free",
                                    "VyprVPN",
                                    "AppVPN",
                                    "BypassGeo",
                                    "Bearshare P2P",
                                    "Asproxy Web Proxy",
                                    "Pando P2P",
                                    "Easy Proxy",
                                    "VPN 365",
                                    "Lantern",
                                    "Office VPN",
                                    "Proton VPN",
                                    "Miro P2P",
                                    "Morphium.info",
                                    "Ants Initialization P2P",
                                    "Soulseek Download P2P",
                                    "FSecure Freedome VPN",
                                    "Tweakware VPN",
                                    "QQ VPN",
                                    "Redirection Web-Proxy",
                                    "Phex P2P",
                                    "Hamachi VPN Streaming",
                                    "TOR Proxy",
                                    "Ares Retrieve Chat Room",
                                    "UK-Proxy.org.uk Proxy",
                                    "Winny P2P",
                                    "MeHide.asia",
                                    "Alkasir Proxy",
                                    "Windscribe",
                                    "Eagle VPN",
                                    "eMule P2P",
                                    "FastVPN",
                                    "Boinc Messenger",
                                    "Tableau Public",
                                    "DotVPN",
                                    "Photon Flash Player & Browser",
                                    "Proxysite.com Proxy",
                                    "Ares Chat Room",
                                    "Private Tunnel",
                                    "Ares P2P",
                                    "Private VPN",
                                    "Epic Browser",
                                    "Green VPN",
                                    "GoldenKey VPN",
                                    "Cyazyproxy",
                                    "Hexa Tech VPN",
                                    "FinchVPN",
                                    "Vuze P2P",
                                    "WiFree Proxy",
                                    "Ninjaproxy.ninja",
                                    "VPN Free",
                                    "Hideman VPN",
                                    "VPN Lighter",
                                    "L2TP VPN",
                                    "ShellFire VPN",
                                    "ExpressVPN",
                                    "Speedy VPN",
                                    "Toonel",
                                    "Torrent Clients P2P",
                                    "EuropeProxy",
                                    "Hi VPN",
                                    "Freenet P2P",
                                    "Reduh Proxy",
                                    "Kugoo Playlist P2P",
                                    "Frozenway Proxy",
                                    "Soulseek Retrieving P2P",
                                    "Hide-N-Seek Proxy",
                                    "DashVPN",
                                    "Phantom VPN",
                                    "DNSCrypt",
                                    "CrossVPN",
                                    "USA IP",
                                    "Total VPN",
                                    "ZPN VPN",
                                    "ISAKMP VPN",
                                    "Hammer VPN",
                                    "Speed VPN",
                                    "Hotspotshield Proxy",
                                    "Blockless VPN",
                                    "Star VPN",
                                    "RemoboVPN Proxy",
                                    "SSL Proxy Browser",
                                    "TurboVPN",
                                    "PP VPN",
                                    "VPN Unlimited",
                                    "Astrill VPN",
                                    "Hello VPN",
                                    "SetupVPN",
                                    "JAP Proxy",
                                    "Heatseek Browser",
                                    "ProxyWebsite",
                                    "Private Internet Access VPN",
                                    "DC++ Download P2P",
                                    "Thunder VPN",
                                    "skyZIP",
                                    "TOR VPN",
                                    "Haitun VPN",
                                    "Bitcoin Proxy",
                                    "Worldcup Proxy",
                                    "Privatix VPN",
                                    "Ants P2P",
                                    "DC++ Connect P2P"
                                ]
                            },
                            "RiskList": {
                                "Risk": "Very High"
                            },
                            "Schedule": "All The Time",
                            "SelectAllRule": "Enable",
                            "SmartFilter": null
                        }
                    ]
                }
            },
            {
                "DefaultAction": "Allow",
                "Description": "Drops traffic from applications that are categorized as P2P apps. P2P could be a mechanism for distributing Bots, Spywares, Adware, Trojans, Rootkits, Worms and other types of malwares. It is generally advised to have P2P application blocked in your network.",
                "IsDeleted": false,
                "MicroAppSupport": "True",
                "Name": "Block peer to peer (P2P) networking apps",
                "RuleList": {
                    "Rule": {
                        "Action": "Deny",
                        "ApplicationList": {
                            "Application": [
                                "VeryCD",
                                "Piolet Initialization P2P",
                                "Bearshare P2P",
                                "Pando P2P",
                                "DirectConnect P2P",
                                "Manolito P2P Download",
                                "Apple-Juice P2P",
                                "Fileguri P2P",
                                "Stealthnet P2P",
                                "Vuze P2P",
                                "100BAO P2P",
                                "NapMX Retrieve P2P",
                                "Peercast P2P",
                                "Morpheus P2P",
                                "Miro P2P",
                                "SoMud",
                                "QQ Download P2P",
                                "Ants Initialization P2P",
                                "Soulseek Download P2P",
                                "Torrent Clients P2P",
                                "Imesh P2P",
                                "Freenet P2P",
                                "Kugoo Playlist P2P",
                                "Phex P2P",
                                "Soulseek Retrieving P2P",
                                "Mute P2P",
                                "Winny P2P",
                                "Piolet FileTransfer P2P",
                                "MP3 Rocket Download",
                                "Klite Initiation P2P",
                                "Flashget P2P",
                                "Shareaza P2P",
                                "DC++ Hub List P2P",
                                "eMule P2P",
                                "Manolito P2P Search",
                                "Soul Attempt P2P",
                                "Ants IRC Connect P2P",
                                "WinMX P2P",
                                "GoBoogy Login P2P",
                                "DC++ Download P2P",
                                "Napster P2P",
                                "LimeWire",
                                "Ares P2P",
                                "Manolito P2P Connect",
                                "Tixati P2P",
                                "Gnutella P2P",
                                "Manolito P2P GetServer List",
                                "MediaGet P2P",
                                "Ants P2P",
                                "DC++ Connect P2P"
                            ]
                        },
                        "CategoryList": {
                            "Category": "P2P"
                        },
                        "Schedule": "All The Time",
                        "SelectAllRule": "Enable",
                        "SmartFilter": null
                    }
                }
            },
            {
                "DefaultAction": "Allow",
                "Description": "Drops traffic that are classified under very high risk apps (Risk Level- 5).",
                "IsDeleted": false,
                "MicroAppSupport": "True",
                "Name": "Block very high risk (Risk Level 5) apps",
                "RuleList": {
                    "Rule": {
                        "Action": "Deny",
                        "ApplicationList": {
                            "Application": [
                                "Proxyone",
                                "SecureLine VPN",
                                "Just Proxy VPN",
                                "Psiphon Proxy",
                                "ProxyProxy",
                                "SkyVPN",
                                "Amaze VPN",
                                "Stealthnet P2P",
                                "PrivateSurf.us",
                                "NapMX Retrieve P2P",
                                "Proxy Switcher Proxy",
                                "Yoga VPN",
                                "England Proxy",
                                "Gom VPN",
                                "VPN Master",
                                "Just Open VPN",
                                "Hide.Me",
                                "Bypasstunnel.com",
                                "Tiger VPN",
                                "Proxifier Proxy",
                                "FastSecureVPN",
                                "MP3 Rocket Download",
                                "TransferBigFiles Application",
                                "Cyberoam Bypass Chrome Extension",
                                "SkyEye VPN",
                                "ItsHidden Proxy",
                                "Betternet VPN",
                                "CantFindMeProxy",
                                "Shareaza P2P",
                                "DC++ Hub List P2P",
                                "Power VPN",
                                "SoftEther VPN",
                                "Surf-for-free.com",
                                "VPN Robot",
                                "Super VPN Master",
                                "UltraVPN",
                                "X-VPN",
                                "Browsec VPN",
                                "VeePN",
                                "TorrentHunter Proxy",
                                "MoonVPN",
                                "Hot VPN",
                                "Super VPN",
                                "Hoxx Vpn",
                                "OpenInternet",
                                "PHProxy",
                                "VPN Monster",
                                "Cloud VPN",
                                "RusVPN",
                                "Speedify",
                                "Mute P2P",
                                "TransferBigFiles Web Download",
                                "The Pirate Bay Proxy",
                                "VPN 360",
                                "NateMail WebMail",
                                "Securitykiss Proxy",
                                "Websurf",
                                "FreeMyBrowser",
                                "uProxy",
                                "Your-Freedom Proxy",
                                "Chrome Reduce Data Usage",
                                "Unclogger VPN",
                                "Britishproxy.uk Proxy",
                                "ZenVPN",
                                "Freegate Proxy",
                                "VPN over 443",
                                "Zero VPN",
                                "Ants IRC Connect P2P",
                                "WinMX P2P",
                                "Classroom Spy",
                                "Expatshield Proxy",
                                "The Proxy Bay",
                                "OpenDoor",
                                "Snap VPN",
                                "Ultrasurf Proxy",
                                "CyberGhost VPN Proxy",
                                "Simurgh Proxy",
                                "Webproxy",
                                "Unseen Online VPN",
                                "Zalmos SSL Web Proxy for Free",
                                "VyprVPN",
                                "AppVPN",
                                "BypassGeo",
                                "Bearshare P2P",
                                "Asproxy Web Proxy",
                                "Pando P2P",
                                "Easy Proxy",
                                "VPN 365",
                                "Lantern",
                                "Office VPN",
                                "Proton VPN",
                                "Miro P2P",
                                "Morphium.info",
                                "Ants Initialization P2P",
                                "Soulseek Download P2P",
                                "FSecure Freedome VPN",
                                "Tweakware VPN",
                                "QQ VPN",
                                "Redirection Web-Proxy",
                                "Phex P2P",
                                "Hamachi VPN Streaming",
                                "TOR Proxy",
                                "Ares Retrieve Chat Room",
                                "UK-Proxy.org.uk Proxy",
                                "Winny P2P",
                                "MeHide.asia",
                                "Alkasir Proxy",
                                "Windscribe",
                                "Eagle VPN",
                                "eMule P2P",
                                "FastVPN",
                                "Boinc Messenger",
                                "Tableau Public",
                                "DotVPN",
                                "Photon Flash Player & Browser",
                                "Proxysite.com Proxy",
                                "Ares Chat Room",
                                "Private Tunnel",
                                "Ares P2P",
                                "Private VPN",
                                "Epic Browser",
                                "Green VPN",
                                "GoldenKey VPN",
                                "Cyazyproxy",
                                "Hexa Tech VPN",
                                "FinchVPN",
                                "Vuze P2P",
                                "WiFree Proxy",
                                "Ninjaproxy.ninja",
                                "VPN Free",
                                "Hideman VPN",
                                "VPN Lighter",
                                "L2TP VPN",
                                "ShellFire VPN",
                                "ExpressVPN",
                                "Speedy VPN",
                                "Toonel",
                                "Torrent Clients P2P",
                                "EuropeProxy",
                                "Hi VPN",
                                "Freenet P2P",
                                "Reduh Proxy",
                                "Kugoo Playlist P2P",
                                "Frozenway Proxy",
                                "Soulseek Retrieving P2P",
                                "Hide-N-Seek Proxy",
                                "DashVPN",
                                "Phantom VPN",
                                "DNSCrypt",
                                "CrossVPN",
                                "USA IP",
                                "Total VPN",
                                "ZPN VPN",
                                "ISAKMP VPN",
                                "Hammer VPN",
                                "Speed VPN",
                                "Hotspotshield Proxy",
                                "Blockless VPN",
                                "Star VPN",
                                "RemoboVPN Proxy",
                                "SSL Proxy Browser",
                                "TurboVPN",
                                "PP VPN",
                                "VPN Unlimited",
                                "Astrill VPN",
                                "Hello VPN",
                                "SetupVPN",
                                "JAP Proxy",
                                "Heatseek Browser",
                                "ProxyWebsite",
                                "Private Internet Access VPN",
                                "DC++ Download P2P",
                                "Thunder VPN",
                                "skyZIP",
                                "TOR VPN",
                                "Haitun VPN",
                                "Bitcoin Proxy",
                                "Worldcup Proxy",
                                "Privatix VPN",
                                "Ants P2P",
                                "DC++ Connect P2P"
                            ]
                        },
                        "RiskList": {
                            "Risk": "Very High"
                        },
                        "Schedule": "All The Time",
                        "SelectAllRule": "Enable",
                        "SmartFilter": null
                    }
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
>| Block filter avoidance apps | Drops traffic from applications that tunnels other apps, proxy and tunnel apps, and from apps that can bypass firewall policy. These applications allow users to anonymously browse Internet by connecting to servers on the Internet via encrypted SSL tunnels. This, in turn, enables users to bypass network security measures. | True | Allow | Rule: {'SelectAllRule': 'Enable', 'CategoryList': {'Category': 'Proxy and Tunnel'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Proxyone', 'SecureLine VPN', 'Just Proxy VPN', 'Reindeer VPN', 'Sslbrowser Proxy', 'Tunnelbear Proxy Login', 'Proxy Switcher Proxy', 'Yoga VPN', 'VPN in Touch', 'AOL Desktop', 'Hide.Me', 'Tiger VPN', 'Proxifier Proxy', 'Spinmyass Proxy', 'ProXPN Proxy', 'ItsHidden Proxy', 'Betternet VPN', 'Gtunnel Proxy', 'WebFreer Proxy', 'Nateon Proxy', 'Power VPN', 'Surf-for-free.com', 'Ghostsurf Proxy', 'Fly Proxy', 'Vpntunnel Proxy', 'Super VPN Master', 'UltraVPN', 'SOCK5 Proxy', 'X-VPN', 'Browsec VPN', 'Proxycap Proxy', 'VeePN', 'SumRando', 'TorrentHunter Proxy', 'NetLoop VPN', 'Hot VPN', 'IP-Shield Proxy', 'Hoxx Vpn', 'Opera Off Road Mode', 'Proxmachine Proxy', 'VPN Monster', 'Speedify', 'The Pirate Bay Proxy', 'VPN 360', 'FreeMyBrowser', 'uProxy', 'Netevader Proxy', 'Unclogger VPN', 'Proxy-service.de Proxy', 'Britishproxy.uk Proxy', 'VPN over 443', 'Zero VPN', 'Kproxyagent Proxy', 'Expatshield Proxy', 'The Proxy Bay', 'OpenDoor', 'Snap VPN', 'Ultrasurf Proxy', 'Rxproxy Proxy', 'Proxyway Proxy', 'VyprVPN', 'AppVPN', 'BypassGeo', 'Easy Proxy', 'Ztunnel Proxy', 'Onavo', 'CoralCDN Proxy', 'Office VPN', 'Proton VPN', 'Morphium.info', 'HTTPort Proxy', 'Tweakware VPN', 'QQ VPN', 'Redirection Web-Proxy', 'HOS Proxy', 'Hopster Proxy', 'Dtunnel Proxy', 'VPNium Proxy', 'MeHide.asia', 'FreeVPN Proxy', 'Eagle VPN', 'Glype Proxy', 'Proxeasy Web Proxy', 'HTTP Tunnel Proxy', 'DotVPN', 'Jailbreak VPN', 'OneClickVPN Proxy', 'Photon Flash Player & Browser', 'Mega Proxy', 'VPNMakers Proxy', 'ShadeYouVPN', 'Max-Anonysurf Proxy', 'Proxeasy Proxy', 'Tunnelbear Proxy Data', 'Vedivi-VPN Proxy', 'Private VPN', 'Gapp Proxy', 'Meebo Repeater Proxy', 'Privitize VPN Proxy', 'Tigervpns', 'Cyazyproxy', 'Hexa Tech VPN', 'FinchVPN', 'WiFree Proxy', 'VPN Free', 'Hideman VPN', 'ShellFire VPN', 'ExpressVPN', 'EuropeProxy', 'Hi VPN', 'Frozenway Proxy', 'Auto-Hide IP Proxy', 'Gbridge VPN Proxy', 'DNSCrypt', 'ZPN VPN', 'Skydur Proxy', 'Hide-My-IP Proxy', 'Hotspotshield Proxy', 'Globosurf Proxy', 'Blockless VPN', 'Star VPN', 'SurfEasy VPN', 'RemoboVPN Proxy', 'SSL Proxy Browser', 'TurboVPN', 'Air Proxy', 'VPN Unlimited', 'Astrill VPN', 'Hello VPN', 'SetupVPN', 'ProxyWebsite', 'Camoproxy Proxy', 'TOR VPN', 'Sslpro.org Proxy', 'Bitcoin Proxy', 'Worldcup Proxy', 'Privatix VPN', 'Psiphon Proxy', '4everproxy Proxy', 'ProxyProxy', 'SkyVPN', 'Btunnel Proxy', 'CProxy Proxy', 'Amaze VPN', 'PrivateSurf.us', 'Real-Hide IP Proxy', 'Wallcooler VPN Proxy', 'England Proxy', 'Gom VPN', 'VPN Master', 'Just Open VPN', 'Tunnelier', 'Bypasstunnel.com', 'Packetix Proxy', 'FastSecureVPN', 'Dynapass Proxy', 'Ctunnel Proxy', 'Suresome Proxy', 'Cyberoam Bypass Chrome Extension', 'SkyEye VPN', 'Circumventor Proxy', 'CantFindMeProxy', 'Kepard Proxy', 'SoftEther VPN', 'VPN Robot', 'StrongVPN', 'K Proxy', 'Proxyfree Web Proxy', 'FreeU Proxy', 'VNN-VPN Proxy', 'MoonVPN', 'MiddleSurf Proxy', 'Super VPN', 'Invisiblenet VPN', 'OpenInternet', 'PHProxy', 'Justproxy Proxy', 'Cloud VPN', 'RusVPN', 'Kongshare Proxy', 'PingTunnel Proxy', 'Hide-IP Browser Proxy', 'Securitykiss Proxy', 'Njutrino Proxy', 'Websurf', 'Idhide Proxy', 'Your-Freedom Proxy', 'Chrome Reduce Data Usage', 'ZenVPN', 'Steganos Online Shield', 'Freegate Proxy', 'Puff Proxy', 'Bypassfw Proxy', 'Easy-Hide IP Proxy', 'Classroom Spy', 'CyberGhost VPN Proxy', 'Simurgh Proxy', 'ZenMate', 'Hola', 'Webproxy', 'Unseen Online VPN', 'Socks2HTTP Proxy', 'Lok5 Proxy', 'SSlunblock Proxy', 'CyberghostVPN Web Proxy', 'Zalmos SSL Web Proxy for Free', 'My-Addr(SSL) Proxy', 'Asproxy Web Proxy', 'VPN 365', 'Lantern', 'HTTP-Tunnel Proxy', 'Tor2Web Proxy', 'Hiddenvillage Proxy', 'Vpndirect Proxy', 'FSecure Freedome VPN', 'Hamachi VPN Streaming', 'TOR Proxy', 'Cocoon', 'PD Proxy', 'UK-Proxy.org.uk Proxy', 'Avoidr Web Proxy', 'Launchwebs Proxy', 'Divavu Proxy', 'I2P Proxy', 'Proxify-Tray Proxy', 'Alkasir Proxy', 'Zelune Proxy', 'Windscribe', 'Proximize Proxy', 'FastVPN', 'SOCK4 Proxy', 'Hide-Your-IP Proxy', 'Aniscartujo Web Proxy', 'Telex', 'Proxysite.com Proxy', 'Manual Proxy Surfing', 'Private Tunnel', 'Spotflux Proxy', 'RealTunnel Proxy', 'Epic Browser', 'Green VPN', 'Surrogofier Proxy', 'GoldenKey VPN', 'Operamini Proxy', 'Mysslproxy Proxy', 'Ninjaproxy.ninja', 'VPN Lighter', 'L2TP VPN', 'uVPN', 'Speedy VPN', 'Toonel', 'Reduh Proxy', 'Anonymox', 'Hide-N-Seek Proxy', 'DashVPN', 'Phantom VPN', 'CrossVPN', 'Tunnel Guru', 'USA IP', 'Total VPN', 'ISAKMP VPN', 'Hammer VPN', 'RPC over HTTP Proxy', 'Speed VPN', 'PP VPN', 'Pingfu Proxy', 'JAP Proxy', 'Private Internet Access VPN', 'Thunder VPN', 'skyZIP', 'Invisible Surfing Proxy', 'Vtunnel Proxy', 'Haitun VPN', 'Tunnello']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'CharacteristicsList': {'Characteristics': 'Can bypass firewall policy'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Proxyone', 'SecureLine VPN', 'Just Proxy VPN', 'Reindeer VPN', 'Sslbrowser Proxy', 'Tunnelbear Proxy Login', 'VzoChat Messenger', 'Proxy Switcher Proxy', 'Yoga VPN', 'VPN in Touch', 'Hide.Me', 'Tiger VPN', 'Proxifier Proxy', 'Spinmyass Proxy', 'ProXPN Proxy', 'ItsHidden Proxy', 'Betternet VPN', 'Gtunnel Proxy', 'DroidVPN', 'WebFreer Proxy', 'Nateon Proxy', 'Power VPN', 'Surf-for-free.com', 'Ghostsurf Proxy', 'GoBoogy Login P2P', 'Fly Proxy', 'Vpntunnel Proxy', 'Super VPN Master', 'UltraVPN', 'SOCK5 Proxy', 'X-VPN', 'Browsec VPN', 'Proxycap Proxy', 'Schmedley Website', 'VeePN', 'SumRando', 'TorrentHunter Proxy', 'NetLoop VPN', 'Hot VPN', 'IP-Shield Proxy', 'Hoxx Vpn', 'Proxmachine Proxy', 'VPN Monster', 'Speedify', 'The Pirate Bay Proxy', 'VPN 360', 'FreeMyBrowser', 'uProxy', 'Netevader Proxy', 'Unclogger VPN', 'Proxy-service.de Proxy', 'Britishproxy.uk Proxy', 'VPN over 443', 'Zero VPN', 'Kproxyagent Proxy', 'Expatshield Proxy', 'The Proxy Bay', 'OpenDoor', 'Snap VPN', 'Ultrasurf Proxy', 'Rxproxy Proxy', 'Proxyway Proxy', 'VyprVPN', 'AppVPN', 'BypassGeo', 'Ztunnel Proxy', 'CoralCDN Proxy', 'Office VPN', 'Proton VPN', 'Morphium.info', 'HTTPort Proxy', 'Tweakware VPN', 'QQ VPN', 'Redirection Web-Proxy', 'HOS Proxy', 'Hopster Proxy', 'Dtunnel Proxy', 'VPNium Proxy', 'MeHide.asia', 'FreeVPN Proxy', 'Eagle VPN', 'Glype Proxy', 'Proxeasy Web Proxy', 'HTTP Tunnel Proxy', 'DotVPN', 'Jailbreak VPN', 'OneClickVPN Proxy', 'Photon Flash Player & Browser', 'Mega Proxy', 'VPNMakers Proxy', 'ShadeYouVPN', 'Max-Anonysurf Proxy', 'Proxeasy Proxy', 'Tunnelbear Proxy Data', 'Vedivi-VPN Proxy', 'Private VPN', 'Gapp Proxy', 'Meebo Repeater Proxy', 'Privitize VPN Proxy', 'Tigervpns', 'Cyazyproxy', 'Hexa Tech VPN', 'FinchVPN', 'WiFree Proxy', 'VPN Free', 'Hideman VPN', 'ShellFire VPN', 'ExpressVPN', 'EuropeProxy', 'Hi VPN', 'Frozenway Proxy', 'Auto-Hide IP Proxy', 'iSwifter Games Browser', 'Gbridge VPN Proxy', 'DNSCrypt', 'ZPN VPN', 'Skydur Proxy', 'Hide-My-IP Proxy', 'Hotspotshield Proxy', 'Globosurf Proxy', 'Blockless VPN', 'Star VPN', 'RemoboVPN Proxy', 'SSL Proxy Browser', 'TurboVPN', 'Air Proxy', 'VPN Unlimited', 'Astrill VPN', 'Hello VPN', 'SetupVPN', 'ProxyWebsite', 'Camoproxy Proxy', 'TOR VPN', 'Sslpro.org Proxy', 'Bitcoin Proxy', 'Worldcup Proxy', 'Privatix VPN', 'Psiphon Proxy', '4everproxy Proxy', 'ProxyProxy', 'SkyVPN', 'Btunnel Proxy', 'CProxy Proxy', 'Amaze VPN', 'PrivateSurf.us', 'Real-Hide IP Proxy', 'Wallcooler VPN Proxy', 'England Proxy', 'Gom VPN', 'VPN Master', 'Just Open VPN', 'Tunnelier', 'Bypasstunnel.com', 'Packetix Proxy', 'FastSecureVPN', 'Dynapass Proxy', 'Ctunnel Proxy', 'Suresome Proxy', 'Cyberoam Bypass Chrome Extension', 'SkyEye VPN', 'Circumventor Proxy', 'CantFindMeProxy', 'Kepard Proxy', 'SoftEther VPN', 'VPN Robot', 'Puffin Web Browser', 'K Proxy', 'Proxyfree Web Proxy', 'FreeU Proxy', 'VNN-VPN Proxy', 'MoonVPN', 'MiddleSurf Proxy', 'Super VPN', 'Invisiblenet VPN', 'OpenInternet', 'PHProxy', 'Justproxy Proxy', 'Cloud VPN', 'RusVPN', 'Kongshare Proxy', 'PingTunnel Proxy', 'Hide-IP Browser Proxy', 'Securitykiss Proxy', 'Njutrino Proxy', 'Websurf', 'Idhide Proxy', 'Your-Freedom Proxy', 'Chrome Reduce Data Usage', 'Hideninja VPN', 'ZenVPN', 'Freegate Proxy', 'Puff Proxy', 'Bypassfw Proxy', 'Easy-Hide IP Proxy', 'CyberGhost VPN Proxy', 'Simurgh Proxy', 'ZenMate', 'Hola', 'Webproxy', 'Unseen Online VPN', 'Socks2HTTP Proxy', 'Lok5 Proxy', 'SSlunblock Proxy', 'CyberghostVPN Web Proxy', 'Zalmos SSL Web Proxy for Free', 'My-Addr(SSL) Proxy', 'Asproxy Web Proxy', 'VPN 365', 'Lantern', 'HTTP-Tunnel Proxy', 'Tor2Web Proxy', 'Hiddenvillage Proxy', 'Vpndirect Proxy', 'FSecure Freedome VPN', 'Hamachi VPN Streaming', 'TOR Proxy', 'Cocoon', 'PD Proxy', 'UK-Proxy.org.uk Proxy', 'Avoidr Web Proxy', 'Launchwebs Proxy', 'Divavu Proxy', 'Proxify-Tray Proxy', 'Alkasir Proxy', 'Zelune Proxy', 'Windscribe', 'Proximize Proxy', 'FastVPN', 'Boinc Messenger', 'SOCK4 Proxy', 'Hide-Your-IP Proxy', 'Aniscartujo Web Proxy', 'Telex', 'Proxysite.com Proxy', 'Manual Proxy Surfing', 'Private Tunnel', 'RealTunnel Proxy', 'Green VPN', 'Surrogofier Proxy', 'GoldenKey VPN', 'Operamini Proxy', 'Mysslproxy Proxy', 'Ninjaproxy.ninja', 'VPN Lighter', 'L2TP VPN', 'Speedy VPN', 'Reduh Proxy', 'Anonymox', 'Hide-N-Seek Proxy', 'OpenVPN', 'DashVPN', 'Phantom VPN', 'CrossVPN', 'Tunnel Guru', 'USA IP', 'Total VPN', 'ISAKMP VPN', 'Hammer VPN', 'RPC over HTTP Proxy', 'Speed VPN', 'PP VPN', 'Pingfu Proxy', 'JAP Proxy', 'Private Internet Access VPN', 'Thunder VPN', 'skyZIP', 'Invisible Surfing Proxy', 'Vtunnel Proxy', 'Haitun VPN', 'Tunnello']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'CharacteristicsList': {'Characteristics': 'Tunnels other apps'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Proxyone', 'SecureLine VPN', 'Modbus - Get Comm Event Counter', 'Just Proxy VPN', 'FreeU VOIP', 'Google Chrome Installer', 'Tunnelbear Proxy Login', 'Direct Operate - No Ack', 'Mail-ru Messenger', 'Facebook Pics Upload', 'Yoga VPN', 'Facebook Chat', 'Kaseya Client Connect', 'Supervisory Functions', 'Authentication Request', 'VPN in Touch', 'Rediffbol Messenger', 'ComodoUnite IM', 'Authentication Request - No Ack', 'AOL Desktop', 'Hide.Me', 'Proxifier Proxy', 'NeverMail WebMail', 'PetSociety-Facebook Games', 'Blogger Post Blog', 'ItsHidden Proxy', 'Gtunnel Proxy', 'QQ Messenger', 'DeskShare Remote Access', 'Authentication Challenge', 'Power VPN', 'DAP Download', 'Return Diagnostic Register', 'GoBoogy Login P2P', 'TelTel VOIP', 'AIM Express Messenger', 'Super VPN Master', 'iCAP Business', 'WikiEncyclopedia Android', 'X-VPN', 'Friendfeed Web Login', 'Proxycap Proxy', 'Optimum WebMail', 'VeePN', 'UbuntuOne FileTransfer', 'TripAdvisor Android', 'VNC Web Remote Access', 'Justvoip VOIP', 'Hot VPN', 'DNP3 - Confirm', 'Livedoor Web Login', 'Opera Off Road Mode', 'Clear Counters and Diag. Reg', 'Citrix Receiver', 'Techinline Conferencing', 'Broad. Req. from Autho. Client', 'DNP3 - Delete File', 'Speedify', 'VPN 360', 'RSS Feeds', 'FreeMyBrowser', 'uProxy', 'CafeWorld-Facebook Games', 'SkyFex Conferencing', 'Jabber Protocol', 'TreasureIsle-Facebook Games', 'Tango Android', 'Britishproxy.uk Proxy', 'NDTV Android', 'Facebook Pics Download', 'VPN over 443', 'Zero VPN', 'Plugoo Widget', 'Seasms Messenger', 'Ventrilo VOIP', 'MSN2GO Messenger', 'The Proxy Bay', 'Snap VPN', 'Ultrasurf Proxy', 'Bacnet - AtomicReadFile Service', 'Sina WebMail', 'VyprVPN', 'BypassGeo', 'Meetup Android', 'Seesmic VOIP', 'Easy Proxy', 'Modbus - Write Single Coil', 'Onavo', 'Modbus - Read Discrete Inputs', 'Proton VPN', 'Freeze and Clear-Freeze at Time', 'Morphium.info', 'HTTPort Proxy', 'Modbus - Return Query Data', 'QQ VPN', 'Redirection Web-Proxy', 'Hi5 Website', 'Gtalk Messenger Voice Chat', 'WebRDP Remote Access', 'MeHide.asia', 'Eagle VPN', 'Proxeasy Web Proxy', 'HTTP Tunnel Proxy', 'DotVPN', 'VPNMakers Proxy', 'Enable Unsolicited Responses', 'Max-Anonysurf Proxy', 'Google App Engine', 'Tunnelbear Proxy Data', 'Vedivi-VPN Proxy', 'Etisalat Messenger', 'Kool Web Messenger', 'Private VPN', 'Gree.jp WebMail Login', 'Meebo Repeater', 'Meebo Repeater Proxy', 'DNP3 - Freeze and Clear', 'Tigervpns', 'Return Bus Exception Error Count', 'CodeAnywhere Android', 'FinchVPN', 'Orange Dialer VOIP', 'WiFree Proxy', 'Hideman VPN', 'ShellFire VPN', 'Amazon Iphone', 'EuropeProxy', 'Adobe Connect Conferencing', 'Frozenway Proxy', 'Google Analytic', 'Facebook Applications', 'IAX VOIP', 'X-Fire Messenger', 'BookMyShow Android', 'DNP3 - Activate Configuration', 'ZPN VPN', 'Garena Web Messenger', 'Hotspotshield Proxy', 'Blockless VPN', 'IMO Messenger', 'SurfEasy VPN', 'RemoboVPN Proxy', 'SetupVPN', 'Trillian Messenger', 'DNP3 - Operate', 'Camoproxy Proxy', 'QQ Web Messenger', 'TOR VPN', 'Worldcup Proxy', 'Privatix VPN', 'ICQ Messenger', 'ProxyProxy', 'SkyVPN', 'CProxy Proxy', 'Amaze VPN', 'PrivateSurf.us', 'DirectTV Android', 'Genesys Website', 'Modbus - Mask Write Register', 'Zoho Meeting Conferencing', 'vBuzzer Android', 'Camfrog Messenger', 'Last.FM Client Streaming', 'Gom VPN', 'VPN Master', 'Mail-ru WebMail', 'DNP3 - Warm Restart', 'Baofeng Website', 'PC-Visit Remote Access', 'iTunes Internet', 'Bypasstunnel.com', 'Cold Restart From Autho. Client', 'Dynapass Proxy', 'Zenbe WebMail', 'Cyberoam Bypass Chrome Extension', 'Google Translate Android', 'Fring Android', 'Kepard Proxy', 'Yugma Web Conferencing', 'WLM Voice and Video Chat', 'Modbus - Read FIFO Queue', 'DNP3 - Open File', 'Vyew WebRDP', 'Vsee VOIP', 'Puffin Web Browser', 'StrongVPN', 'Nateon Messenger', 'Instant-t Messenger', 'K Proxy', 'DNP3 - Select', 'FreeU Proxy', 'LinkedIN Compose Webmail', 'Facebook Plugin', 'ICQ2GO Messenger', 'Read/Write Multiple Registers', 'Invisiblenet VPN', 'PC-Anywhere Remote Access', 'Twitter Limited Access', 'Moviefone Android', 'Elluminate Remote Conferencing', 'PHProxy', 'Cloud VPN', 'RusVPN', 'Flickr Website', 'Kongshare Proxy', 'IMPlus Web Messenger', 'Mute P2P', 'Return Slave Message Count', 'Facebook Website', 'PingTunnel Proxy', 'Itunes Update', 'NateMail WebMail', 'Securitykiss Proxy', 'Njutrino Proxy', 'iLoveIM Web Messenger', 'Chrome Reduce Data Usage', 'Kaseya Portal Login', 'Meebo Iphone', 'Hideninja VPN', 'Caihong Messenger', 'Hangame', 'Steganos Online Shield', 'Easy-Hide IP Proxy', 'Classroom Spy', 'TokBox VOIP', 'OoVoo VOIP', 'ZenMate', 'Hola', 'Webproxy', 'LinkedIN Mail Inbox', 'DNP3 - Initialize Data', 'CyberghostVPN Web Proxy', 'Zalmos SSL Web Proxy for Free', 'MSN', 'Lantern', 'Google Location', 'MxiT Android', 'Tor2Web Proxy', 'Bacnet - AtomicWriteFile Service', 'FSecure Freedome VPN', 'DNP3 - Writes', 'TOR Proxy', 'Cocoon', 'PD Proxy', 'LogMeIn Remote Access', 'UK-Proxy.org.uk Proxy', 'Salesforce Web Login', 'LinkedIN Android', 'Windscribe', 'Bacnet - Read Property Multiple', 'Scydo Android', 'WebAgent.Mail-ru Messenger', 'DimDim Website', 'Dameware Mini Remote Access', 'FastVPN', 'ShowMyPC Conferencing', 'Boinc Messenger', 'SOCK4 Proxy', 'GMX WebMail', 'CNN News Android', 'Telex', 'Unconfirmed i-HAVE Service', 'Proxysite.com Proxy', 'ISL Desktop Conferencing', 'ICQ Android', 'Blogger Create Blog', 'RealTunnel Proxy', 'Epic Browser', 'DNP3 - Get File Information', 'Surrogofier Proxy', 'GoldenKey VPN', 'Operamini Proxy', 'E-Bay Android', 'Modbus - Return Slave Busy Count', 'DNP3 - Authenticate File', 'Bacnet - Timesync Service', 'Bacnet Protocol Traffic', 'L2TP VPN', 'DNP3 - Immediate Freeze', 'Modbus - Read Holding Registers', 'Modbus - Get Comm Event Log', 'Phantom VPN', 'AirAIM Messenger', 'DNP3 - Start Application', 'Tunnel Guru', 'USA IP', 'Total VPN', 'Web.De WebMail', 'Metin Game', 'Modbus - Write Multiple Coils', 'Yuuguu Conferencing', 'Hootsuite Web Login', 'Google Translate', 'NateApp Android', 'IEC.60870.5.104 - STARTDT CON', 'Bomgar Remote Conferencing', 'MillionaireCity-Facebook Games', 'JAP Proxy', 'Private Internet Access VPN', 'NetOP Ondemand Conferencing', 'Crossloop Remote Access', 'Return Bus Comm. Error Count', 'Tunnello', 'Google Toolbar', 'LiveMeeting VOIP', 'Reindeer VPN', 'MeeboMe Plugin', 'IEC.60870.5.104 - TESTFR CON', 'Change ASCII Input Delimiter', 'Proxy Switcher Proxy', 'Headcall VOIP', 'Modbus - Write File Record', 'DNP3 - Direct Operate', 'Glide Conferencing', 'Tiger VPN', 'Jabber', 'ScreenStream Remote Access', 'Write Multiple Registers', 'RemotelyAnywhere Remote Access', 'ProXPN Proxy', 'AOL WebMail', 'Betternet VPN', 'Fuel Coupons Android', 'DroidVPN', 'Nateon Proxy', 'Surf-for-free.com', 'Ghostsurf Proxy', 'IEC.60870.5.104 - Single Command', 'Fly Proxy', 'DNP3 - Assign Class', 'UltraVPN', 'Yahoo IM Voice and Video Chat', 'SOCK5 Proxy', 'SumRando', 'TorrentHunter Proxy', 'NetLoop VPN', 'Hoxx Vpn', 'Chikka Web Messenger', 'Mig33 Android', 'Gizmo5 VOIP', 'VPN Monster', 'Fetion Messenger', 'Puffin Academy', 'Propel Accelerator', 'x11 Conferencing', 'Hush WebMail', 'The Pirate Bay Proxy', 'Google Plus Website', 'Digsby Messenger', 'COX WebMail', 'DNP3 - Initialize Application', 'Sightspeed VOIP', 'Unclogger VPN', 'Mail.com WebMail', 'Interrogation Command', 'SugarSync FileTransfer', 'Expatshield Proxy', 'MSN-Way2SMS WebMail', 'Imhaha Web Messenger', 'Camfrog VOIP', 'Line Messenger', 'Proxyway Proxy', 'Clear Overrun Counter and Flag', 'AppVPN', 'Vyew Website', 'Return Bus Char. Overrun Count', 'CoralCDN Proxy', 'Office VPN', 'Modbus - Return Slave NAK Count', 'Eyejot Web Messenger', 'Gtalk Messenger', 'Modbus - Read Input Registers', 'Tweakware VPN', 'HOS Proxy', 'Timbuktu Remote Conferencing', 'Hopster Proxy', 'TalkBox Android', 'VPNium Proxy', 'FreeVPN Proxy', 'AirVideo', 'PalTalk Messenger', 'Mafia Wars-Facebook Games', 'Glype Proxy', 'Mobyler Android', 'Fastmail Webmail', 'Call Of Duty 4 Game', 'Unconfirmed i-AM Service', 'Jailbreak VPN', 'Facebook Video Chat', 'ExchangeRates Android', 'IMVU Messenger', 'OneClickVPN Proxy', 'DNP3 - Abort File', 'Photon Flash Player & Browser', 'Mega Proxy', 'Meebo Website', 'ShadeYouVPN', 'Eroom Website', 'BBC News Android', 'Proxeasy Proxy', 'Odnoklassniki Web Messenger', 'Restart Communications Option', 'QQ WebMail', 'Cyazyproxy', 'Hexa Tech VPN', 'VPN Free', 'ExpressVPN', 'DNP3 - Freeze at Time - No Ack', 'Hi VPN', 'WLM Login', 'Modbus - Read Exception Status', 'Facebook Video Upload', 'Fastviewer Conferencing', 'Auto-Hide IP Proxy', 'DNP3 - Freeze and Clear - No Ack', 'iSwifter Games Browser', 'Read device Identification', 'Gbridge VPN Proxy', 'Timbuktu DesktopMail', 'DNSCrypt', 'Return Bus Message Count', 'LiveMeeting Conferencing', 'Skydur Proxy', 'Hide-My-IP Proxy', 'Globosurf Proxy', 'Star VPN', 'FarmVille-Facebook Games', 'SSL Proxy Browser', 'TurboVPN', 'VPN Unlimited', 'AIM Messenger', 'Bacnet - Read Property', 'Astrill VPN', 'Hello VPN', 'ProxyWebsite', 'RDMPlus Remote Access', 'Palringo Messenger', 'Poker-Facebook Games', 'Bejeweled-Facebook Games', 'Unsolicited Auth. Challenge', 'Bitcoin Proxy', 'DNP3 - Delay Measurement', 'Serv-U Remote Access', 'Bacnet - Reinitializdevice', 'Force Listen Only Mode', 'Google Desktop Application', 'Psiphon Proxy', 'GoChat Android', 'MyGreen-PC Remote Access', 'Real-Hide IP Proxy', 'Daum WebMail', 'PI-Chat Messenger', 'England Proxy', 'Ebuddy Web Messenger', 'Internet Download Manager', 'Qeep Android', 'Lontalk Traffic', 'Just Open VPN', 'Tunnelier', 'IEC.60870.5.104 - STARTDT ACT', 'Packetix Proxy', 'Yahoo Messenger', 'AIM Android', 'FastSecureVPN', 'Suresome Proxy', 'SkyEye VPN', 'Circumventor Proxy', 'Ebuddy Android', 'Unconfirmed who-is Service', 'CantFindMeProxy', 'Yoics Conferencing', 'Modbus - Read Coils', 'Supremo Remote Access', 'SoftEther VPN', 'Ali WangWang Remote Access', 'Session Initiation Protocol', 'VPN Robot', 'MessengerFX', 'DNP3 - Record Current Time', 'Avaya Conferencing', 'DNP3 - Save Configuration', 'LiveGO Messenger', 'VNN-VPN Proxy', 'Device Communication Control', 'R-Exec Remote Access', 'Facebook Message', 'Facebook Games', 'MoonVPN', 'MiddleSurf Proxy', 'Super VPN', 'GaduGadu Web Messenger', 'OpenInternet', 'NetViewer Conferencing', 'Stickam VOIP', 'Flickr Web Upload', 'Jump Desktop Remote Access', 'Garena Messenger', 'Friendster Web Login', 'Facebook Limited Access', 'Hide-IP Browser Proxy', 'Gtalk Android', 'RemoteShell Remote Access', 'Websurf', 'Yahoo WebMail', 'Mikogo Conferencing', 'Your-Freedom Proxy', 'Vyew Web Login', 'AIM Messenger VOIP', 'Gmail WebMail', 'AIM Website', 'DNP3 - Stop Application', 'ZenVPN', 'Netease WebMail', 'Freegate Proxy', 'Google Safebrowsing', 'IEC.60870.5.104 - Double Command', 'Palringo Web Messenger', 'iChat Gtalk', 'Teamsound VOIP', 'CyberGhost VPN Proxy', 'Simurgh Proxy', 'Bacnet - Write Property', 'Modbus - Diagnostics', 'Unseen Online VPN', 'Socks2HTTP Proxy', 'Asproxy Web Proxy', 'DNP3 - Close File', 'Zedge Android', 'VPN 365', 'Chikka Messenger', 'Modbus - Report Slave ID', 'Korea WebMail', 'HTTP-Tunnel Proxy', 'DNP3 - Read', 'TruPhone Android', 'Hamachi VPN Streaming', 'Launchwebs Proxy', 'Google Earth Application', 'I2P Proxy', 'Alkasir Proxy', 'Zelune Proxy', 'Yugma Conferencing', 'Hide-Your-IP Proxy', 'Hyves WebMail', 'FrontierVille-Facebook Games', 'IEC.60870.5.104 - TESTFR ACT', 'Trillian Web Messenger', 'Manual Proxy Surfing', 'Authentication Response', 'Yahoo Messenger Chat', 'VoipTalk VOIP', 'Immediate Freeze - No Ack', 'Private Tunnel', 'Spotflux Proxy', 'TeamViewer Conferencing', 'Serv-U RemoteAccess FileTransfer', 'Outlook.com', 'Green VPN', 'Digg Web Login', 'Android Market', 'Windows Remote Desktop', 'Engadget Android', 'Ninjaproxy.ninja', 'WeBuzz Web Messenger', 'VPN Lighter', 'Synergy Remote Access', 'YahooMail Calendar', 'uVPN', 'Speedy VPN', 'Modbus - Write Single Register', 'Reduh Proxy', 'Soonr Conferencing', 'CB Radio Chat Android', 'Anonymox', 'Hide-N-Seek Proxy', 'OpenVPN', 'DashVPN', 'CrossVPN', 'ISAKMP VPN', 'Google Cache Search', 'Hammer VPN', 'RPC over HTTP Proxy', 'Speed VPN', 'Disable Unsolicited Responses', 'IM+ Android', 'GaduGadu Messenger', 'Spy-Agent Remote Access', 'PP VPN', 'Pingfu Proxy', 'PhoneMyPC Remote Access', 'Thunder VPN', 'MindJolt-Facebook Games', 'skyZIP', 'Invisible Surfing Proxy', 'Vtunnel Proxy', 'Uusee Streaming', 'SCCP VOIP', 'Regulating Step Command', 'Haitun VPN', 'Return Slave No Response Count', 'KiK Messenger Android', 'OpenWebMail']}, 'Action': 'Deny', 'Schedule': 'All The Time'} |
>| Block generally unwanted apps | Drops generally unwanted applications traffic. This includes file transfer apps, proxy & tunnel apps, risk prone apps, peer to peer networking (P2P) apps and apps that causes loss of productivity. | True | Allow | Rule: {'SelectAllRule': 'Enable', 'CategoryList': {'Category': 'P2P'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['VeryCD', 'Piolet Initialization P2P', 'Bearshare P2P', 'Pando P2P', 'DirectConnect P2P', 'Manolito P2P Download', 'Apple-Juice P2P', 'Fileguri P2P', 'Stealthnet P2P', 'Vuze P2P', '100BAO P2P', 'NapMX Retrieve P2P', 'Peercast P2P', 'Morpheus P2P', 'Miro P2P', 'SoMud', 'QQ Download P2P', 'Ants Initialization P2P', 'Soulseek Download P2P', 'Torrent Clients P2P', 'Imesh P2P', 'Freenet P2P', 'Kugoo Playlist P2P', 'Phex P2P', 'Soulseek Retrieving P2P', 'Mute P2P', 'Winny P2P', 'Piolet FileTransfer P2P', 'MP3 Rocket Download', 'Klite Initiation P2P', 'Flashget P2P', 'Shareaza P2P', 'DC++ Hub List P2P', 'eMule P2P', 'Manolito P2P Search', 'Soul Attempt P2P', 'Ants IRC Connect P2P', 'WinMX P2P', 'GoBoogy Login P2P', 'DC++ Download P2P', 'Napster P2P', 'LimeWire', 'Ares P2P', 'Manolito P2P Connect', 'Tixati P2P', 'Gnutella P2P', 'Manolito P2P GetServer List', 'MediaGet P2P', 'Ants P2P', 'DC++ Connect P2P']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'CharacteristicsList': {'Characteristics': 'Loss of productivity'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['vPorn', 'Telenet.be Web Mail', 'Bitrix24', 'Facebook Pics Upload', 'Mutants: Genetic Galdiators', 'Saavn Android', 'DeskGate', 'Cozycot Website', 'iFood', 'PetSociety-Facebook Games', 'Happyfox', 'Hospitalityclub Website', 'Plurk Website', 'IMO Video Calling', 'Circle of Moms', 'Dailyfx', 'Power VPN', 'Abu Dhabi Taxi', 'Cyworld Website', 'Gapyear Website', 'Java Update', 'Pig & Dragon', 'Pockets - ICICI Bank', 'Marco Polo Video Walkie Talkie', 'DeepL Translator', 'iBabs', 'Librarything Website', 'Friendfeed Web Login', 'Magnatune Audio Streaming', 'Freshbooks', 'Wrike', 'Tiexue', 'Ali Qin Tao', 'Wave Accounting', 'Bing Image Search', 'Cash IT Back', 'Dxy Website', 'WeChat', 'Shutterfly Photo Upload', 'Hatena', 'Jibjab Website', 'Provide Support', 'Motherofporn Video Streaming', 'Lost Bubbles', 'FreeMyBrowser', 'uProxy', 'Ariba', 'Turbobit Download', 'Friendica Website', 'Cnxp BBS', 'Facebook Pics Download', 'Duba Update', 'Facebook Messenger', 'Livestream Website', 'Bubbly', 'BINGO Blitz', 'Infogram', 'Plus7', 'Action VoIP', 'MQTT', 'Nokia Website', 'Nextdoor', 'Help Scout', 'PasteBin', 'Nymgo VoIP Dialer', 'Google Plus Post', 'TechRepublic', 'Bebo Posting', 'Proton VPN', 'MTV Website', 'Internations Website', 'QQ VPN', 'ADP Download Document', 'Redbooth', 'Hi5 Website', 'Zoo Website', 'Facebook Posting', 'Spinjay Website', 'ICUII Web Messenger', 'CNN Video Streaming', 'Blizzard Client', 'DEAD TRIGGER 2', 'Reverbnation Website', 'Rutube Streaming', 'Fotki Website', 'ServiceTitan', 'Apple News', 'Fubar Website', 'Pcperformer Update', 'Train Station', 'Clarin Web Video Streaming', 'Nimbuzz Blackberry Messenger', 'Tigervpns', 'DrTuber', 'NiMO TV', 'Happy Family', 'Daum Cafe', 'SmartFoxServer', 'Facebook Status Update', 'Wer-kennt-wen Website', 'PizzaHut', 'Soulseek Retrieving P2P', 'Your freedom Update', 'CoStar Real Estate Manager', 'Naked Streaming', 'Monster Legends', 'BookMyShow Android', 'ZPN VPN', 'ShareChat', 'TVFPlay', 'Curiouscast', 'Putlocker Download', 'Sage One', 'SurfEasy VPN', 'MotleyFool', 'PVR Cinemas', '500px', 'Anobii Website', 'LovePhoto FacebookApp', 'My18tube Streaming', 'CryptoCompare', 'NBC News', 'Stagevu Streaming', 'Cmjornal', 'Backblaze Personal Backup', 'LimeWire', 'Blizzard Downloader', 'Chromeriver', 'Omerta', 'Privatix VPN', 'Twitter Website', 'HDpornstar Video Streaming', 'VeryCD', 'Xici', 'Streamaudio Streaming', 'Amaze VPN', 'Plex', '24chasa', 'Microsoft Media Server Protocol', 'MySpace.cn Website', 'TLVMedia', 'Travellerspoint Website', 'Moneycontrol Markets on Mobile', 'Zattoo Streaming', 'Doodle', 'Qianlong BBS', 'BanaCast', 'Pornerbros Streaming', 'MindBody', 'Care360', 'Five9', 'Kuwo.cn Web Music Streaing', 'Flow Game', 'Zoosk', '4399.com', 'Meettheboss Video Streaming', 'Square', 'Eporner Video Streaming', 'Fuelmyblog Website', 'Odnoklassniki Android', 'Napster P2P', 'UltraViewer', 'StrongVPN', 'Windows MediaPlayer Update', 'World Of Warcraft Game', 'MTV Asia', 'RealTime Messaging Protocol', 'MyTokri', 'CBC', 'ThisAV', 'JioCinema', 'Social Wars', 'Facebook Like', 'Dol2day Website', 'Pipedrive Download', 'AnyMeeting Connect', 'IDBI Bank Go Mobile', '8 Ball Pool', 'Cloud VPN', 'Seismic', 'WebEngage', 'PressReader', 'Cookie Jam', 'Soliter Arena', 'MyTeksi', 'Egnyte Download', 'Bubble Witch Saga', 'Hay Day', 'Workday', 'Chrome Reduce Data Usage', 'BlueStacks Cloud Connect', 'Candy Crush Saga', 'ZOL', 'Rubicon Project', 'AvidXchange', 'IBM CXN Cloud Files', 'Imgur', 'Travbuddy Website', 'Ask.fm', 'Webproxy', 'HelloByte Dialer', 'Gather Website', 'Grooveshark Music Streaming', 'YuppTV Streaming', 'Yahoo Groups', 'Playwire', 'Archaeology', 'ULLU Video Streaming', 'Monster Resume Upload', 'Wakoopa Website', 'Transport Stream', 'McAfee Update', 'Cocoon', 'Facebook Commenting', 'Piolet FileTransfer P2P', 'Gamerdna Website', '163 BBS', 'Safari Escape', 'Timesheets', 'Extreme Road Trip 2', 'BabyCenter', 'Videobash Video Streaming', 'AstroSage Kundli', 'FastVPN', 'Rambler Website', 'Craigslist Android', 'Quantcast', 'LinkedIN Universities Search', 'Kotak Bank Mobile Application', 'LinkedIN Profile Download', 'Airbnb', 'Orgasm Video Streaming', 'MediaGet P2P', 'ICICI Mobile Banking-iMobile', 'MLB', 'GoldenKey VPN', 'Yandex Search', 'Marketland', 'Oracle Sales Cloud', 'Aaj Tak News', 'Raaga Streaming', 'Facebook Chat on YahooMail', 'Pengle', 'Sina Games', 'Times of India', 'Baidu Tieba', 'SnappyTV', 'Elixio Website', 'YouTube Comment', 'TrendMicro SafeSync', 'Bayfiles Upload', 'Real Player Update', 'Shopify App Store', 'Tvtonic Streaming', 'Total VPN', 'LinkedIN Companies', 'Monday', 'SAS OnDemand', 'Reuters', 'Chinaren Club', 'Orbitz', 'Google Allo', 'QuickBooks', 'School-communicator', 'AudioBoom', 'Prezi', 'Putlocker Upload', 'Realnudeart Website', 'Reindeer VPN', 'Bored Website', 'Megapolis', 'Dainik Bhaskar Streaming', 'Comm100', 'Twtkr Search', 'Club Cooee Messenger', 'Tubemate', 'Line Call', 'Axifile File Transfer', 'Rival Kingdoms', 'Bank of Baroda M-Connect', 'Songbird Update', 'Bitshare Download', '51.COM Games', 'Fan FacebookApp', 'Brightcove Media', 'Quote.com', 'Mixer – Interactive Streaming', 'Booking', 'SnapBuy', 'TubeMogul', 'Tinder', 'Panda Jam', 'Zendesk', 'Tiger VPN', 'Disaboom Website', 'Egnyte Device List', 'Plustransfer Upload', 'TrialMadness Facebook Game', 'Teachertube', 'Lark', 'Shopify Admin', 'We Heart It Upload', 'Surf-for-free.com', 'MyUniverse', 'Goibibo', 'Blackboard', '1Fichier Download', 'Diamond Dash', 'UltraVPN', 'Exploroo Website', 'Citrix Online', 'Pinterest Repin', 'SIP Request', 'Lynda.com Video Streaming', 'Hoxx Vpn', 'News UK', 'Quick Base', 'Imlive Streaming', 'Lifehacker', 'CarTrade', 'Wepolls Website', 'XBMC', 'Puffin Academy', 'CityVille', 'We Heart It', 'Google Plus Website', 'OCN Webmail', 'Grono Website', 'Droom', 'Avant Update', 'Tom', 'Ning Website', 'Alphaporno Video Streaming', 'SendMyWay Upload', '1mg', 'Sun NXT', 'Google Reader Android', 'Runesofmagic Game', 'iConnectHere', 'AppVPN', 'Xing Website', 'Necromanthus Game', 'Audimated Website', 'Peercast P2P', 'Wynk Movies', 'Mendeley Desktop', 'Capsule', 'MySmartPrice', 'Twitter Message', 'Pixlr Apps', 'BBM', '4Tube Streaming', 'Mafia Wars-Facebook Games', 'Bluebeam', 'Ebutor Distribution', 'Rakuten Viki', 'Asmallworld Website', 'Myopera Website', 'Workbook', 'ShadeYouVPN', 'Line Messenger File Transfer', 'Habbo Website', 'Global TV', 'Rotten Tomatoes', 'VoiceFive', 'iCloud Calender', 'Daum', 'Pandora Music Streaming', 'SoundHound Android', 'Privitize VPN Proxy', 'Tenfold', 'Weibo New Post', 'UserVoice', 'Cyazyproxy', 'Flock Update', 'Google Plus Web Chat', 'Freeonlinegames Website', 'Tappsi', 'Freshsales Upload CSV', 'Epernicus Website', 'Popcap Website', 'Tellagami Share', 'Weebly Website Builder', 'WLM Login', 'Freeridegames Website', 'Dawn', 'Kugoo Playlist P2P', 'CarDekho', 'WhatsCall', 'Itsmy Website', 'Optimax', 'DNSCrypt', 'Crunchyroll Website', 'Royal Story', 'Mail.com Organizer', 'GoToMeeting', 'Shopify Manage Orders', 'Egnyte Delete', 'Airtable', 'FarmVille-Facebook Games', 'TurboVPN', 'Wish', 'AIM Messenger', 'MySpace Website', 'TeamSpeak', 'Hello VPN', 'ProxyWebsite', 'Lojas Americanas', 'Ngopost Website', 'Shopify Manage Products', 'Poker-Facebook Games', 'Marvel Website', 'Bitcoin Proxy', 'Google Desktop Application', 'Litzscore API', 'Pet Rescue Saga', 'Indianpornvideos Streaming', 'Rednet BBS', 'Zshare Upload', 'NapMX Retrieve P2P', 'iTel Mobile Dialer Express', 'Shelfari Website', 'LinkedIN Search', 'VK Message', 'Wordfeud Game', 'Playstation Network', 'Baidu Image', 'Proprofs', 'Wordpress', 'Yahoo Messenger', 'LinkedIN Website', 'Coolmath Games', 'Plock FacebookApp', 'Yebhi', 'SlideShare Upload', 'CantFindMeProxy', 'Phreesia', 'Researchgate Website', 'Tetris Battle', 'Freshdesk', 'OKCupid Android', 'Nexage', 'Brainshark', 'Kakao', 'IBM CXN Cloud Communities', 'Xbox LIVE', 'Smartsheet', 'ChartNexus', 'LinkedIN Messenger File Upload', 'MoonVPN', 'Super VPN', 'The Smurfs & Co', 'Xvideos Streaming', 'PBS Video Streaming', 'Melon Music', 'Egnyte Apps Download', 'Ebaumsworld Video Streaming', 'OpenInternet', 'WhatsApp Video Call', 'Friendster Web Login', 'Facebook Limited Access', '8Tracks', 'Coursera', 'Vidazoo', 'ShareThis', 'Google Plus Hangouts', 'Real Boxing', 'TaskBucks', 'Twitter Visual Media', 'Ants IRC Connect P2P', 'Getglue Website', 'Social Empires', 'VK Mail', 'Cartoon Network', 'Cricbuzz', 'Ludo King', 'RingCentral Glip', 'Athlinks Website', 'Goober Messenger', 'Last.FM Android', 'HealthKart', 'Tumblr Follow', 'Goodreads Website', 'Elastic.io iPaaS', 'Baidu Video Streaming', 'Break Video Streaming', 'Google Hangout Android App', 'Twillio Communications', 'Gaiaonline Website', 'Wireclub', 'TuneIN Radio Android', 'Zshare Download', 'Espnstar Video Streaming', 'Patientslikeme Website', 'PPLive Streaming', 'Tox', 'Hitpost Android', 'Base', 'Pengyou', 'Yaxi', 'Laposte Web Mail', 'Eyejot', 'Celoxis', 'Aha', 'VPN Lighter', '51TV', 'Torrent Clients P2P', 'Shopify Dashboard', 'AIM Games', 'The-sphere Website', 'Youpunish Video Streaming', 'Zenga', 'Picasa Update', 'Dropbox File Upload', 'Quick Base Upload', 'Zooworld FacebookApp', 'Hammer VPN', 'Kinja', 'Lokalisten', 'Getright Update', 'Hotstar', 'IndiaTV live', 'Tmall', 'Recharge Done', 'Svtplay Streaming', 'GMX Compose Mail', 'Mail.com Contacts', 'Windows Marketplace', 'NPR Radio Streaming', 'Fame', 'CuteBears FacebookApp', 'Counter Strike', 'HDFC Bank Mobile Banking', 'Whatfix', 'Loom', 'Channel News Asia', 'Blog.com', 'iTrix', 'ZirMed', 'E Entertainment', '8 Ball Pool - Android', 'Yoga VPN', 'Buyhatke', 'Pipedrive Upload', 'AOL Desktop', 'Tagged Website', 'Hike', 'Aljazeera Audio Streaming', 'Boule & Bill', 'Indeed', 'LivePerson', 'Hide.Me', 'Deer Hunter 2014', 'YieldManager', 'Proxifier Proxy', 'Palnts vs. Zombies Advanture', 'School of Dragons', 'Contract Wars', 'Xanga Website', 'Italki Website', 'Hit It Rich! Casino Slots', 'Lucidpress', 'MySpace Video Streaming', 'MobWars Facebook Game', 'AdvancedMD', 'Oxigen Wallet', 'Insightly', 'Webshots Streaming', 'DailyCartoons Android', 'Submityourflicks Streaming', 'Tixati P2P', 'Line Games and Applications', 'Kite by Zerodha', 'TSheets', 'Scramble Facebook Game', 'IFTTT', 'Kaixin001 Website', 'VeePN', 'Opera Off Road Mode', 'Divan TV', 'OpenX', 'Rocket Fuel Marketing', 'AdnstreamTV Website', 'Tuenti Status Update', 'ILikeMusic Streaming', 'Assembla', 'Clubbox', 'Wooxie Website', 'Yoville Facebook Game', 'Disney City Girl', 'Worldcric', 'The Telegraph', 'Marvel Avengers Alliance Tactics', 'Infusionsoft', 'Reddit', '1Fichier Upload', 'SongPop', 'Soku Website', '9gag', 'Ali Quan Niu', 'Bigpoint Game', 'The Washington Post', 'Magnatune Website', 'FileRio Download', 'Guvera', 'Mega Download', 'Xfinity TV', 'Playfire Website', 'Wetpaint', 'YY Voice Messenger', 'YouTube Add to', 'Naaptol', 'Yelp Website', 'IBM CXN Cloud Activities', 'Sexyandfunny Website', 'Docstoc File Transfer', 'Lost Jewels', 'Fluttr', 'JewelPuzzle Facebook Game', 'Status-Net', 'WhatsApp File Transfer', 'People BBS', 'NHK World TV', 'MeHide.asia', 'News Break', 'Eagle VPN', 'Facebook Search', 'Freshsales', 'Whisper', 'ToutApp', 'Ares Chat Room', 'Tata Sky Mobile', 'FreeMovies Android', 'NSDL', 'Etisalat Messenger', 'Smutty Website', 'Chess.com', 'ABC Australia', 'Ircgalleria Website', 'Blauk Website', 'Easynews', 'Morpheus P2P', 'ShellFire VPN', 'SoMud', 'CloudApp', 'Bitshare Upload', 'Hello! magazine', 'Zuzandra Website', 'Pinterest Upload', 'Outreach', 'Fruehstueckstreff Website', 'Stripe', 'Twitter Follow', 'YouTube Share Video', 'nexGTV', 'Blockless VPN', 'Stan', 'Aljazeera Live Streaming', 'CCP Games', '163 Alumni', 'SBS On Demand', 'TOR VPN', 'XiTi', 'Lokalistens Photo Upload', 'Qip Messenger', 'Stealthnet P2P', 'Topbuzz', 'HTTP Audio Streaming', 'KakaoTalk', 'Cat898 BBS', 'Shopify Manage Customers', 'Sonyliv Video Streaming', 'Vampirefreaks Website', 'iPlay Website', 'iTunes Internet', 'SendSpace', 'Quip', 'HubPages', 'Second Life', 'LinkedIN Posts Search', 'All Player Update', 'Pool Live Tour', 'Angry Birds Friends', 'VidibleTV', 'GetResponse', 'Vidmate', 'Hainei', 'QuickFlix', 'Tweetie', 'My Mail.ru', 'Egnyte Share', 'DAP Update', 'Ladooo-Free Recharge App', 'SVT Play', 'Flickr Website', 'Amazon Prime Streaming', 'Target', 'Blackplanet Website', 'Ludo Star', 'Constant Contact', 'Signal Private Messenger', 'Hideninja VPN', 'Deputy Workforce MGMT', 'Pullbbang Video Streaming', 'LinkedIN Limited Access', 'Bronto', 'Winamax Game', 'TealiumIQ', 'MEO Cloud', 'Bill.com', 'Voillo', 'Totorosa Music Website', 'Duomi Music', 'Leankit', 'Goo Webmail', 'Evernote Webcliper', 'Jelly Glutton', 'Tribe Website', 'Spiegel Online', 'CashBoss', 'MxiT Android', 'GungHo', 'Dropcam', 'FSecure Freedome VPN', 'WeChat Web', 'TOR Proxy', 'Periscope Data', 'Google Video Streaming', 'ZeeTV App', 'CricInfo Android', 'Republic TV', 'Windscribe', 'Sage Intacct', 'LinkedIN Universities', 'Badoo Website', 'Proxysite.com Proxy', 'Fanpop', 'IMDB Streaming', 'Meetup Message', 'Yabuka', 'Gold Dialer', 'DingTalk', 'Kwai App Suite', 'Epic Browser', 'Telenet Webmail', 'TVB Video Streaming', 'Howardforums Website', 'Renren Website', 'Activecollab', 'Ninja Kingdom', 'Uptobox Upload', 'Termwiki Website', 'MSDN', 'Gamespy Game', 'Vevo', 'Fishville FacebookApp', 'USA IP', 'Google Plus Photos', 'Gamehouse', 'Hootsuite Web Login', 'MobileVOIP', 'ChatWork', 'MillionaireCity-Facebook Games', 'WLM WebChat', 'Colors Video Streaming', 'Messages for Web', 'Private Internet Access VPN', 'Twitter Status Update', 'Blog.Com Admin', 'CityVille FacebookApp', 'Tvigle', 'Ants P2P', 'UNO & Friends', 'Dontstayin Website', 'Facebook Blackberry', 'WeChat File Transfer', 'Windows Store', 'Skype', 'Manolito P2P Download', 'Sploder Game', 'Talkbiznow Website', 'Google Plus Comment', 'Skyplayer Streaming', 'iCloud Bookmarks', 'Playboy.tv Streaming', 'Google Groups', 'Telecom Express', 'Hr Website', 'StatCounter', 'Kaixin001 Comment Posting', 'Nugg', 'Egloos Blog Post', 'Blogger Comment', 'Betternet VPN', 'Baidu Music', 'Bingo Bash', 'Brazzers', 'Facebook Graph API', 'Tuenti Photo Upload', 'Bloomberg', 'Docusign', 'Browsec VPN', 'Ap.Archive Streaming', 'Dailywire', 'JB Hi-Fi', 'Costco', 'BigAdda', 'SumRando', 'LiveHelpNow', 'Asianave Website', 'Gogoyoko Website', 'Ning Invite', '3QSDN Streaming', 'Yahoo News', 'Trombi Website', 'TapCash', 'The Pirate Bay Proxy', 'O2 TU Go', 'Filmow Website', 'Mouthshut Website', 'VGO TV', 'Monster World', 'Line Messenger', 'Word Chums', 'Ontraport', 'Viber Message', 'Delicious Website', 'Pipedrive', 'Craigslist Website', 'Sharefile', 'Soulseek Download P2P', 'Alibaba', 'Tweakware VPN', 'Phex P2P', 'Tumblr Reblog', 'Doom3 Game', 'Movies.com', 'Office Depot', 'Stileproject Video Streaming', 'Slingbox Streaming', 'VPNium Proxy', 'UEFA Video Streaming', 'Care2 Website', 'Pepper Panic Saga', 'OlaCabs', 'Alt News', 'Village Life', 'Fux Video Streaming', 'Listography Website', 'Call Of Duty 4 Game', 'FastTV', 'Xero Upload', 'Pornsharia Video Streaming', 'Rapidgator Download', 'Crocko Upload', 'QQ BBS', 'Dropbox Base', 'MSN Money', 'Cnet Download', 'SurveyGizmo', 'LinkedIN Videos', 'Facebook Events', 'Kongregate Game', 'Fox News', 'Eve Online', 'Airset Access', 'Lybrate', 'Ensight', 'Instagram Visual Media', 'Couchsurfing Website', 'KwMusic App Streaming', 'Backblaze Business Backup', 'Axis Bank Mobile', 'Hexa Tech VPN', 'ShopClues', 'ExpressVPN', 'Ameba Blog Post', 'Comcast', 'Replicon', 'WhatsApp Call', 'Marketo', 'Youjizz', 'Yahoo game', '8Track Iphone', 'YouTube Subscribe', 'Star VPN', 'NewsNation', '1Password', 'EarnTalkTime', 'TV3', 'Astrill VPN', 'Fashland Dress UP for Fashion', 'GOMPlayer Update', 'HTTP File Upload', 'Trello', 'SmugMug Upload', 'DoPool', 'Uptobox', 'Trivia Crack', 'Recurly', 'Infibeam', 'ResourceGuru', 'Fandango', 'Real Basketball', 'NetEase Games', 'Mix', 'Silkroad', 'Gyao Streaming', 'Tagoo.ru Music Streaming', 'LinkedIN People Search', 'FastSecureVPN', 'Pornyeah Streaming', 'Highspot', 'BigBasket', 'Manolito P2P Search', 'Backblaze Prefrances', 'ZOVI', 'Zoom Meetings', 'Pokemon Go', 'Soul Attempt P2P', 'Ask Web-Search', 'Dynamics 365', 'Cubby File transfer', 'Wix Media Platform', 'Twitch Video Streaming', 'Amazon Prime Watchlist', 'CastleVille FacebookApp', 'Grammarly', 'Rambler Mail', 'Google Plus Events', 'Friendsreunited Website', 'Meru Cabs', 'Facebook Iphone', 'Facebook Message', 'Embedupload File Transfer', 'Flixwagon Streaming', 'Mediastream', 'Fileguri P2P', 'Bing News', 'WWE Video Streaming', 'Mubi Website', 'UC Browser', 'Mediaget Installer Download', 'Addicting Game', 'Aol Answers', 'Warrior Forum', 'PartnerUp', '101 Network', 'Backblaze My Shared Files', 'Dlisted', 'Pardot', 'Virb Website', 'Flickr Web Upload', 'WordsWithFriends FacebookApp', 'Yahoo WebChat', '[24]7.ai', 'HTTP Image', 'Throne Rush', 'Amazon Prime Search', 'Blackline Accounting', 'Flashget P2P', 'Everhour', 'Jobvite', 'Moviesand Video Streaming', 'Tagged Android', 'Chat On', 'Koovs', 'Cabonline', 'Niwota', 'Ajio', 'Aha Video', 'Webex Teams', 'Unseen Online VPN', 'CSR Racing', 'Filmaffinity Website', 'JinWuTuan Game', 'iModules Encompass', 'VPN 365', 'Docebo', 'ppFilm', 'Egnyte Bookmarks', 'Hayu', 'Cornerstone', 'Microsoft Teams', 'Mobsters2 FacebookApp', 'The Weather Channel', 'Passportstamp Website', 'Battlefront Heroes', 'Evernote', 'Skimlinks', 'Rdio Website', 'Zedo', 'Realtor', 'Tv4play Streaming', 'JW Player', 'Douban Website', 'HTTP Video Streaming', 'Userporn Video Streaming', 'Game Center', '9Jumpin', 'iCloud Photos', 'Airtime', 'ProfileSong FacebookApp', 'FrontierVille-Facebook Games', 'Fark Website', 'Voxer Walkie-Talkie PTT', 'Cam4 Streaming', 'Mysee Website', 'Olive Media', 'Practice Fusion', 'Adobe Reader Update', 'Cilory', 'Green VPN', 'DirectConnect P2P', 'Popsugar', 'iCall', 'Bitbucket', 'Infoseek Webmail', 'Dict.Cn', 'Ninjaproxy.ninja', 'Speedy VPN', 'Voot', 'Indabamusic Website', '20minutos', 'NicoNico Douga Streaming', 'Foxtel Go', 'TV18 Streaming', 'Bing Safe Search Off', 'Recharge Plan', 'Bebo Website', 'Crictime Video Streaming', 'Clash Of Clans', 'Fuq Website', 'VK Chat', 'Meetup Website', 'Freetv Website', 'Mojang', 'SmugMug', 'Reunion', 'QQ Games', 'Weibo Website', 'Haitun VPN', 'Jurassic Park Builder', 'Steam', 'Opera Update', 'Proxyone', 'Swipe Clock', 'Just Proxy VPN', 'Silverpop', 'Podio', 'YeeYoo', 'Khanwars Game', 'Zalo', 'PUBG Mobile', 'Expedia', 'Xiaonei', 'Saavn Website', 'Stitcher', 'Clips and Pics Website', 'Cooladata', 'VPN in Touch', 'ShareBlast', 'XNXX', 'Wikidot', 'Smule', 'Suburbia', 'RichRelevance', 'Blogger Post Blog', 'ManyCam Update', 'Megavideo', 'Gizmodo', 'Ameba Now', 'Academia Website', 'OwnerIQ Website', 'Top Eleven Be a Football Manager', 'Klipfolio', 'Xero Download', 'Quora', 'ATube Catcher Update', 'W3Schools', 'Super VPN Master', 'iCAP Business', 'Xcar', 'Acuity Scheduling', 'X-VPN', 'SourceForge Download', 'Appsomniacs Games', 'STAR Sports', 'Schmedley Website', 'Chartio', 'Totorosa Media Website', 'Apple-Juice P2P', 'Tuenti Video Search', 'Zooppa Website', 'Zopper', 'Mocospace Website', 'Prosperworks CRM', 'eFolder', 'FreshService', 'SoundCloud Android', 'Wayn Website', 'Happn', 'IBM Connections Cloud', 'Pcloud Download', 'Meinvz Website', 'Slack', 'Work', 'Ngpay', 'Houston Chronicle', 'KanbanFlow', 'IGN', 'Perfspot', 'Britishproxy.uk Proxy', 'NDTV Android', 'VPN over 443', 'Flash Alerts on Call-SMS', 'Dialer Plus', 'Govloop Website', 'OpenDoor', 'Snap VPN', 'Blackberry Appworld', 'Snapdeal', 'Vonage', 'Envato', 'Quick Heal Anti-virus Update', 'Facebook Video Playback', 'Xaxis', 'BypassGeo', 'Dragon City', 'Procore', 'PromoCodeClub', 'Onavo', 'Identica Website', 'Yahoo Search', 'DNS Multiple QNAME', 'Calendly', 'Morphium.info', 'Bigtent', 'Google Plus People', 'Metasploit Update', 'Babycenter Name Search', 'Taobao Aliwangwang Messenger', 'Socialbox FacebookApp', 'Amazon Music', 'Buzznet Website', 'Pivotal Tracker', 'Zimbra', 'MSN Games', 'Wetpussy Streaming', 'Shockwave', 'Miro Update', 'Farm Heroes Saga', 'Taltopia Website', 'Armor Games', 'Uber', 'M3U8 Playlist', 'Manolito P2P GetServer List', 'Experienceproject Website', 'Laibhaari Website', 'Madeena Dailer', 'Chinaren', 'Gett', 'Apple Support', 'FinchVPN', 'Pearls Peril', 'Hideman VPN', 'Stick Run', 'Printvenue', 'Facebook Applications', 'Looker', 'DayTimeTV', 'GoDaddy', 'Nielsen', 'Asana', 'Paychex', 'NeonTV', 'PubMatic Website', 'Mahjong Trails', 'Sciencestage Website', 'LinkedIN Company Search', 'Worldcup Proxy', 'Weibo Microblogging', 'Sbs Netv Streaming', 'Officeally', 'Lastfm Website', 'ProxyProxy', 'SkyVPN', 'Extremesextube Streaming', 'Vudu', 'PrivateSurf.us', 'Airtel Money', 'MangaBlaze', 'EuroSport', 'Autopilot', 'Forever Net', 'Gom VPN', 'VPN Master', 'Yandex Disk', 'Baofeng Website', 'T-Online Webmail', 'Citrix GoToTraining', 'Facebook Post Attachment', 'Scottrade', 'Rapidgator Upload', 'Google Plus Add To Circle', 'Ravelry Website', 'Cyberoam Bypass Chrome Extension', 'Music.com', 'Softonic', 'Applicantpro', 'LiveChat Inc', 'Yugma Web Conferencing', 'MediaDrug', 'Ask Image-Search', 'SadorHappy FacebookApp', 'Puffin Web Browser', 'Notepadplus Update', 'VK Social', 'Tubi TV', 'Super Mario Run', 'Sakshi TV Streaming', 'PaiPai', 'YikYak', 'Flipkart', 'Gfycat', 'Vector', 'RusVPN', 'GOG', 'Clio', 'Facebook Website', 'EpicCare', 'Rediff Website', 'Naver Mail', 'Jiaoyou - QQ', 'ALTBalaji', 'Myheritage Website', 'Tube8 Streaming', 'ZenMate', 'Datadog', 'LinkedIN Mail Inbox', 'Intralinks', 'Shopify', 'Indiatimes Live Streaming', 'MSN', 'Veetle Streaming', 'Youku Streaming', 'Tumblr Blog', 'WildOnes Facebook Game', 'Lantern', 'Pinterest Like', 'Snapchat', 'Winamp Update', 'SIP - TCP', 'FreePaisa', 'TaxiforSure', 'Purevolume Website', 'Youtube Video Search', 'UK-Proxy.org.uk Proxy', 'RadiumOne Marketing', 'Zenox', 'Tumblr Post', 'Sling', 'Egnyte Upload', 'NightClubCity Facebook Game', 'Viper', 'Wattpad Website', 'Yuvutu Streaming', 'The Trade Desk', 'TVN', 'Aljazeera Video Streaming', 'Qzone Website', 'JDownloader', 'Outbrain', 'iPTT', 'Raaga Android', 'YouTube Like/Plus', 'Xim Messenger', 'FaceBook IM on Yahoo Messenger', 'L2TP VPN', 'PayPal', 'Trial Xtreme 3', 'Turbobit Upload', 'Y8 Game', 'Sendspace Upload', 'Certify', 'Euronews', 'Windows Audio Streaming', 'VLC Update', 'Baidu Player', 'Adobe Website Download', 'Free Download Manager', 'Quickplay Videos', 'Car Town', 'Youporn Streaming', 'Backblaze User Restore', 'Viewsurf', 'HelloTV', 'LiveProfile Android', 'Draugiem Website', 'QQ City', 'PerezHilton', 'Google Toolbar', 'Live.ly', '5460 Net', 'Bubble Safari', 'Papa Pear Saga', 'VzoChat Messenger', 'Yobt Video Streaming', 'Groupon', 'BambooHR', 'Cooliyo', 'Bloomberg BNA', 'Clarizen', 'Cafeland', 'Spiceworks', 'ClickDesk', 'TV Serial - Entertainment News', 'Keyhole Video Login', 'MP3 Rocket Download', 'Linkexpats Website', 'Thiswebsiterules Website', 'Archive.Org', 'Fuel Coupons Android', 'Google Duo', 'Carbonite', 'Qiyi Com Streaming', 'Yoono', 'NinjaSaga FacebookApp', 'Stardoll', 'PremierFootball Facebook Game', 'Lafango Website', 'iCloud', 'Gnutella P2P', 'Flashgames247 Game', 'ONTV Live Streaming', 'WhatsApp Web', 'Fucktube Streaming', 'Google Plus Join Communities', 'Supei', 'SmartRecruiters', 'Humanity', 'Perfspot Pic Upload', 'MoSIP', 'EarthCam Website', 'Zemplus Mobile Dialer', 'Webs.com', 'VK Video Streaming', 'Juice Cubes', 'TED', 'ServiceNow', 'Trivago', 'ClearSlide', 'Plaxo Website', 'Twitter Android', 'Gmail Attachment', 'LinkedIN Job Search', 'Amarujala Streaming', 'Filehippo Update', 'LiveXLive', 'Japan FacebookName', 'Brightalk Play', 'Zello', 'Blokus Game', 'Quick Base Download', 'Pinterest Streaming', 'Bing Videos', 'Zynga Game', 'Treebo Hotels', 'Monday Boards', 'Classmates Website', 'Viu', 'Logo Games', 'Mobogenie', 'Quopn Wallet', 'Youtube Downloader', 'ErosNow', 'Basecamp', 'Splashtop', 'Walmart', 'IBM CXN Cloud Social', '9News', 'AIM File Transfer', 'Power Bi', 'LivingSocial Android', 'Mylife Website', 'Amobee', 'Domo', 'Dailystrength Website', 'Aleks', 'Bearshare P2P', 'Vyew Website', 'Kobo', 'Nexopia Website', 'Lun', 'Issuu', 'Proxistore', 'TeenPatti', 'Holy Knight', 'Toggl', 'LinkedIN Jobs', 'Periscope', 'Yammer', 'Geni Website', 'Photon Flash Player & Browser', 'LinkedIN Messenger File Download', 'Teamwork', 'Eroom Website', 'Mymfb Website', 'Netlog Website', 'Dashlane', 'Deejay', 'Anaplan', 'SOMA Messanger', 'Opendiary Website', 'xHamster Streaming', 'Neogov HRMS', 'Wikia', 'Madthumb Video Streaming', 'Yobt Website', '43things Website', '2shared Download', 'VPN Free', 'Viadeo WebLogin', 'Funshion Streaming', 'Hi VPN', 'Facebook Video Upload', 'Quikr', 'Movenetworks Website', 'Simplecast', 'Usersnap', 'Morningstar', 'iSwifter Games Browser', 'Vigo Video', 'Voodoo Messenger', 'Taringa Website', 'ChefVille', 'Vidio NBA Streaming', 'DangDang', 'Appointment Plus', 'vCita', 'Twitter Discover', 'MakeMyTrip', 'Dcinside', 'Presto', 'Goggles Android', 'Trimble Maps', 'DC++ Download P2P', 'Express.co.uk Streaming', 'Bejeweled-Facebook Games', 'Aastha TV', 'Pluto TV', 'Gmail Android Application', '123RF', 'Facebook Android', 'Evernote Chat', 'ViewOn', '2shared Upload', 'Cab4You', 'Texas HoldEm Poker', 'Egnyte Request File', 'Uplay Games', 'LinkedIN Status Update', 'AnyMeeting WebLogin', 'Platinum Dialer', 'Pinterest Website', 'Barablu', 'Mekusharim', 'VHO Website', 'Boxever', 'OLX Android', 'Weeworld Website', 'Bigupload File Transfer', 'Geckoboard', 'Eyejot Video Message', 'Ezyflix TV', 'SoftEther VPN', 'Hubculture Website', 'Faceparty Website', 'Resonate Networks', 'Drunkt Website', 'Monster Busters', 'Ryze Website', 'Warlight', 'Shopcade', 'TicketNew', 'Podchaser', 'Moxtra', 'Rediff Shopping', 'Meetme Website', 'SouthWest', 'Asphalt-8 Airborn', 'Facebook Games', 'Tianya', 'Twitter Notifications', 'Telegram', 'Uptobox Download', 'Aaj Tak', 'Egloos', 'Tuenti Website', 'MediaPlayer Streaming', 'Polldaddy', 'Minus Upload', 'DoubleDown Casino Free Slots', 'Bloomberg Businessweek', 'Monday Invite Members', 'Newton Software', 'Pornjog Video Streaming', 'Real Player', 'ABC Web Player', 'Backblaze My Restore', 'ABC iView', 'Zippyshare', 'Fling', 'Fapdu Video Streaming', 'TealiumIQ Publish Version', 'VeohTV Streaming', 'Iwiw Website', 'Yahoo-Way2SMS', 'Recharge It Now', 'iHeart Radio Streaming', 'Freecharge', 'Naughtyamerica Streaming', 'NFL', 'Namely', 'Mobile Legends', 'Twtkr', 'Jammer Direct', 'Cloob Website', 'Pornhub Streaming', 'Bigo Live', 'CBS Sports', 'Airtel TV', 'Raging Bull Website', 'Miro P2P', 'Baidu Video', 'Paytm Wallet', 'New York Times', 'On24', 'Beam Your Screen', 'Online Soccer Manager', 'Origin Games', 'Slotomania Slot Machines', 'DesiDime', 'News18 Video Streaming', 'utorrentz Update', 'Yahoo Douga Streaming', 'Facebook Blackberry Chat', 'TechRadar', 'Tnaflix Website', 'Webtrends', 'Cricking', 'Axosoft', 'iSolved HCM', 'Manual Proxy Surfing', 'Miniclip Pool Game', 'Spotflux Proxy', 'LinkedIN Groups Search', 'Chinaren Class', 'Swagbucks', 'Backlog', 'Flipboard', 'WebPT', 'SPB TV', 'Fotki Media Upload', 'Hardsextube Streaming', 'Hotels.com', 'QQ Xuanfeng', 'uVPN', 'Audible', 'DouBan FM', 'Jelly Splash', 'Apple Push Notification', 'Tylted Website', 'Anonymox', 'League Of Legends', 'DashVPN', 'Meettheboss Website', 'CrossVPN', 'Mixi', 'ISAKMP VPN', 'Livemocha Website', 'Google Plus Upload', 'Lever', 'IM+ Android', 'Winamp Player Streaming', 'Fancode', 'Tumblr Android', 'PP VPN', 'Hattrick Game', 'CNET', 'StarPlus Video Streaming', 'Pokerstars Online Game', 'Jumpingdog FacebookApp', 'Times of India Videos', 'Thunder VPN', 'MindJolt-Facebook Games', 'Houseparty', 'Studivz Website', 'Invisible Surfing Proxy', 'Renren Music Website', 'LiveAgent', 'Workable', 'Ning Photo Upload', 'SecureLine VPN', 'Sina', 'SuccessFactors', 'Focus Website', 'Wellwer Website', 'Battle-Net', 'Fox Sports', 'Between', 'NDTV Streaming', 'Red Crucible 2', 'Baidu.Hi Games', 'Storage.to Download', 'FunForMobile Android', 'FastRecharge', 'FirstCry', 'QlikSense Cloud', 'BiggestBrain FacebookApp', 'Newegg', 'Egnyte My Links', 'Nejat TV Streaming', 'Amap', 'Payback', 'Google Plus Communities', 'Liveleak Streaming', 'iCloud Photo Stream', 'Apple FaceTime', 'ABC', 'Startv Website', 'Mobaga Town', 'Microsoft NetMeeting', 'Facebook Questions', 'Skyscanner', 'Busuu Website', 'Magicjack', 'Hot VPN', 'Buggle', 'Sprout Social Upload', 'Writeaprisoner Website', 'Sogou', 'Domo File Export', 'KAYAK', 'Lufthansa', '1CRM', 'Speedify', 'Caringbridge Website', 'Comedycentral Website', 'Dudu', 'VPN 360', 'ReadonTV Streaming', 'Xt3 Website', 'Klite Initiation P2P', 'CafeWorld-Facebook Games', 'TreasureIsle-Facebook Games', 'Myspace Web Mail', 'HeyTell', 'The Proxy Bay', 'Bullhorn', 'Manolito P2P Connect', 'Rakuten', 'Cienradios Streaming', 'Criminal Case', 'Stackoverflow', 'VyprVPN', 'Meetup Android', 'Raptr', 'Tumblr Search', '100BAO P2P', 'Keyhole TV Streaming', 'Gays Website', 'Connatix', 'Gamespot', 'Foursquare Android', 'Nykaa', 'StreetRace Rivals', 'Ares Retrieve Chat Room', 'GetGuru', 'AliExpress', 'IIFL Markets', 'Bebo WebMail', 'CCleaner Update', 'GQ Website', 'Yesware', 'Red Bull TV', 'DotVPN', 'Time Video Streaming', 'PoolMaster Facebook Game', 'Meetin Website', 'Private VPN', 'Me2day Website', 'Coco Girl', 'Weborama', 'Marvel Avengers Alliance', 'Piolet Initialization P2P', 'IMDB Android', 'Pingsta Website', 'Chargebee', 'Cleartrip', 'Pinterest Board Create', 'Lithium', 'Zoho WebMessenger', 'Xilu', 'EuropeProxy', 'Shadow Fight', 'Facebook Share', 'Hotlist Website', 'Hipfile Upload', 'Baseball Heroes', 'IBM CXN Cloud Meetings', 'Scrabble', 'Tunein', 'Pudding Pop', 'eHarmony', 'Moonactive Games', 'Emol', 'Sohu WebMail', 'Tuenti Weblogin', 'SetupVPN', 'Blogster Website', 'SiteScout', 'Chroma', 'DC++ Connect P2P', 'The Guardian', 'Scispace', 'Bypasstunnel.com', 'LightBox', 'Etsy', 'Scorecard Research', 'Miniclip Games', 'Facebook Login on YahooMail', 'Indane GAS Booking', 'Paytm', 'Netvibes Search Widget', '51.COM', 'LinkedIN Groups', 'Softpedia', 'Street Racers Online', 'Surikate Website', 'Stickam Website', 'Dailybooth Website', 'Ooyala Streaming', 'Twitter Limited Access', 'Clearcompany', 'Opera Mobile Store', 'The Wall Street Journal', 'Ooyala Video Services', 'WordReference', 'Facebook Like Plugin', 'Wishpond', 'Oyo Rooms', 'Multi Thread File Transfer', 'Meebo Iphone', 'Blizzard', 'Noteworthy Web Messenger', 'Photobucket Streaming', 'Steganos Online Shield', 'Hahaha Website', 'Oracle Taleo', 'VMate', 'Gmail WebChat', 'MobiTV - Watch TV Live', 'Giphy', 'Dhingana Streaming', 'SocialFlow', 'Weread Website', 'Corriere', 'Zalmos SSL Web Proxy for Free', 'Sears Shopping', 'Fomo', 'Blogspot Blog', 'Avataria', 'Mipony Update', 'FileRio Upload', 'PLUS7', 'Xinhuanet Forum', 'Sciencestage Streaming', 'PChome Website', 'Backblaze Locate Computer', 'Airtable CSV Export', 'Ants Initialization P2P', 'Social Calendar', 'Lynda', 'Hirevue', 'Radio Public', 'Mail.com Compose Mail', 'Easy Mobile Recharge', 'GetFeedback', 'Dark Sky', '51.COM BBS', 'Skype Web', 'Dailyhunt', 'Playlist Website', 'Hatena Message', 'Sailthru', 'SpeakO', 'PokktMobileRecharge', 'Vodafone Play', 'IMO Voice Calling', 'TiKL', 'Cumhuriyet', 'Fish Epic', 'Top Gear', 'SmartAdServer', 'RakNet', 'Blogger Create Blog', 'Recharge Plans', 'Weourfamily Website', 'Egnyte My Tasks', 'Spankbang', 'EA.FIFA Game', 'Vuze P2P', 'Aol Answers - Ask', 'MoneyView:Financial Planning', 'Discord', 'Comment Attachment - Facebook', 'MailChimp', 'HipChat', 'RaidoFM', '360Buy', 'Sonico Website', 'Redtube Streaming', 'Tumblr Like', 'Undertone', 'CNTV Live Streaming', 'Woome', 'Advogato Website', 'Phantom VPN', 'Kitchen Scramble', 'Music Tube', 'SPC Media', 'Metin Game', 'Ameba Now - New Post', 'Wiser Website', 'VICE', 'NateApp Android', 'Outeverywhere Website', 'Free18', 'Iozeta', 'Family Farm', 'Nice inContact', 'Faces Website', 'Zoo World', 'Farm Epic', 'Pcloud Upload', 'Voonik', 'Global News', 'Qik Streaming', 'Domo File Upload', 'Cirrus Insight', 'Makeoutclub Website', 'Nk Meeting Place', 'TENplay', 'MyTribe Facebook Game', 'Socialvibe Website', 'Fotolog Website', 'Tvnz', 'HBO GO', 'Backblaze Download', 'Mint Iphone', 'Megogo Streaming', 'JungleJewels Facebook Game', 'Ibibo Game', 'Free Fire', 'Pcpop BBS', 'Pet City', 'SurveyMonkey Website', 'Archive.org Video Streaming', 'Jabong', 'Chosenspace Game', 'Jio TV', 'Justcloud File Transfer', 'SlashDot', 'MIRC Messenger', 'Viber Voice', 'Epic TV', 'Radio France Internationale', 'Jiayuan', 'Naszaklasa Website', 'Paylocity', 'Mint', 'TorrentHunter Proxy', 'Ipomo', 'Netsuite', 'Maxim:taxi order', 'CBS News', 'Tikifarm FacebookApp', 'VPN Monster', 'Jajah', 'Fledgewing Website', 'WorkflowMax', 'Datanyze', 'Piksel', 'Jdownloader Update', 'Last.fm Free Downloads', 'Digitalproserver', 'Upwork', 'Livejournal Website', 'Mediamonkey website', 'Proclivity', 'Unclogger VPN', 'PuthiyathalaimuraiTV', 'Cafemom Website', 'Bing Maps', 'Andhra Bank', 'WinMX P2P', 'Ragnarokonline Game', 'Box File Upload', 'IBM DB2', 'Babes Video Streaming', 'AskmeBazaar', 'Ebay Desktop App', 'Roblox Game Play', 'Domo Connectors', 'CNTV Video Streaming', 'Office VPN', 'Bestporntube Streaming', 'GTalk Update', 'Apple Daily', 'Voc', 'Skyrock Website', 'CBox Streaming', 'Hotfile Download', 'MXPlayer Video Streaming', 'Cybozu', 'eMule P2P', 'Agoda', 'Travelocity', 'Sprout Social', 'Facebook Video Chat', 'Tapin Radio', 'HomeShop18', 'BIIP Website', 'Vine', 'Twitter Search', 'Urban Ladder', 'Wynk Music', 'Jetpack Joyride', 'TypingManiac Facebook Game', 'SKY News', 'ETV News', 'Quake Halflife Game', 'Okurin File Transfer', 'Egnyte File Transfer', 'Ubuntu Update Manager', 'Castbox', 'Upfront Advertising', 'Shufuni.tv', 'SongsPk', 'Netvibes My Widget', 'Kiwibox Website', 'Puzzle Charms', '2CH', 'SpotXchange', 'SSL Proxy Browser', 'Tidal', 'Samsung', 'VPN Unlimited', 'Front', 'Rakuten OverDrive', 'Secret', 'Talkray', 'TaoBao', '51.com mp3 Streaming', 'Videologygroup Streaming', 'Xinhuanet', 'Smilebox', 'ABP Live', 'ScoreCenter Android', 'England Proxy', 'Neokast Streaming', 'QQ Download P2P', 'Workfront', 'Just Open VPN', 'FileZilla Update', 'MIRC Update', 'Tunnelier', 'Mixwit Website', 'AIM Android', 'Xero', 'Google Plus +1', 'Guilt', 'SkyEye VPN', 'Ebuddy Android', 'Shareaza P2P', 'DC++ Hub List P2P', 'TuneUp Mobile', 'Yourlust Streaming', 'Ace2Three Game', 'SlideShare Download', 'Zhanzuo', 'Deccan Chronicle Video Streaming', 'VPN Robot', 'Viber Media', 'ZEE5', 'Tistory', 'AOL Search', 'Weibo', 'Chaos', 'Shazam Android', 'Crosstv Website', 'Windows Live Games', 'Xogogo Video Streaming', 'Saavn Iphone', 'Fastticket', 'GMX Mail Attachment', 'DoubleVerify', 'Bubble Island', 'Deliveroo', 'Words With Friends', 'SlideShare', 'Mog Website', 'Workamajig', 'StarSport Video Streaming', 'Yahoo Sportacular Android', 'Locanto', 'PPStream Streaming', 'Websurf', 'Channel4 Streaming', 'Hungama', 'DeviantART Website', 'Yepme', 'ZenVPN', 'Godgame', 'Hotfile Upload', 'Pando P2P', 'Frontline Education', 'Wikispaces', '55bbs', 'Turner.com', 'Bebo WebChat IM', 'Elftown Website', 'SLI Systems', 'Bigfishgames', 'Apple Store', 'Twitter Retweet', 'The Free Dictionary', 'Heart FacebookApp', 'Boxcar', 'Ultipro Services', 'Alkasir Proxy', 'iCloud Contacts', 'Excite Mail', 'Zapier', 'Earn Money', 'Expensify', 'MunduTV Desktop App Streaming', 'Evernote Notebook Share', 'Sohu Club', 'Rhapsody', 'Kaixin001 Status Update', 'Instagram Profile Picture Upload', 'Istream Website', 'Private Tunnel', 'Phuks', 'Lifeknot Website', 'Ares P2P', 'Sharethemusic Website', 'Lagbook Website', 'Kaixin001 Photo Upload', 'FareHarbor', 'DailyMail Streaming', 'OCSP Protocol', 'Bravo TV', 'Brothersoft Website', 'G Suite', '360quan', 'PandaDoc', 'Partyflock Website', 'Way2sms WebMessenger', 'Freenet P2P', 'Skype Services', 'CB Radio Chat Android', 'Hide-N-Seek Proxy', 'All Recipes Android', 'Google Cache Search', 'Speed VPN', 'SinaTV', 'Datawrapper', 'Yahoo Entertainment', 'Orkut Android', 'Sonar', 'MunduTV Desktop App Login', 'Goodwizz Website', 'FarmVille 2', 'Yahoo Video Streaming', 'AppNana', 'Concur', 'Owler', 'skyZIP', 'iMeet Central', 'PNB mBanking', 'TinyOwl', 'Daxko Operations']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'RiskList': {'Risk': 'High'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Sopcast Streaming', 'Sslbrowser Proxy', 'Mail-ru Messenger', 'Storage.to Download', 'AOL Radio Website', 'NeverMail WebMail', 'Weezo', 'Spinmyass Proxy', 'ProXPN Proxy', 'AOL WebMail', 'WhatsApp', 'Gtunnel Proxy', 'DroidVPN', 'Nateon Proxy', 'Ghostsurf Proxy', 'MyDownloader', 'DAP Download', 'GoBoogy Login P2P', 'Fly Proxy', 'Vpntunnel Proxy', 'iCAP Business', 'Tixati P2P', 'Proxycap Proxy', 'RAR File Download', 'QQ Messenger File Transfer', 'SumRando', 'NetLoop VPN', 'Apple-Juice P2P', 'Chikka Web Messenger', 'Livedoor Web Login', 'Akamai Client', 'Mig33 Android', 'Opera Off Road Mode', 'Dl Free Upload Download', 'Quick Player Streaming', 'FileMail WebMail', 'Live Station Streaming', 'Propel Accelerator', 'Yahoo Messenger File Transfer', 'E-Snips Download', 'Digsby Messenger', 'Klite Initiation P2P', 'Sightspeed VOIP', 'Classmates Website', 'Tango Android', 'Tudou Streaming', 'Kproxyagent Proxy', 'Imhaha Web Messenger', 'Rxproxy Proxy', 'Proxyway Proxy', 'iConnectHere', 'Sina WebMail', 'Absolute Computrance', 'VNC Remote Access', 'Ztunnel Proxy', 'Myspace Chat', '100BAO P2P', 'Peercast P2P', 'Gtalk Messenger', 'HTTPort Proxy', 'Bestporntube Streaming', 'HOS Proxy', 'IP Messenger FileTransfer', 'Multiupload Download', 'Hopster Proxy', 'Citrix ICA', 'TalkBox Android', 'VPNium Proxy', 'FreeVPN Proxy', 'Rapidshare Download', 'PalTalk Messenger', 'Bearshare Download', 'ISPQ Messenger', 'Glype Proxy', 'Mobyler Android', 'Proxeasy Web Proxy', 'HTTP Tunnel Proxy', 'MP3 File Download', 'Jailbreak VPN', 'OneClickVPN Proxy', 'LastPass', 'Mega Proxy', 'VPNMakers Proxy', 'ShadeYouVPN', 'Eroom Website', 'Max-Anonysurf Proxy', 'Proxeasy Proxy', 'Vedivi-VPN Proxy', 'Odnoklassniki Web Messenger', 'Gapp Proxy', '56.com Streaming', 'xHamster Streaming', 'Lightshot', 'Piolet Initialization P2P', 'HotFile Website', 'SoundHound Android', 'Privitize VPN Proxy', 'CodeAnywhere Android', 'QuickTime Streaming', 'Morpheus P2P', 'Imesh P2P', 'Auto-Hide IP Proxy', 'Timbuktu DesktopMail', 'Sendspace Download', 'Gtalk Messenger FileTransfer', 'Skydur Proxy', 'Hide-My-IP Proxy', 'Globosurf Proxy', 'SurfEasy VPN', 'Avaya Conference FileTransfer', 'WocChat Messenger', 'Trillian Messenger', 'Napster Streaming', 'Camoproxy Proxy', 'ASUS WebStorage', 'IMO-Chat Android', 'QQ Web Messenger', 'NTR Cloud', 'Palringo Messenger', 'Baidu IME', 'Serv-U Remote Access', 'ICQ Messenger', 'DirectTV Android', 'GoChat Android', 'Real-Hide IP Proxy', 'Genesys Website', 'PI-Chat Messenger', 'Ebuddy Web Messenger', 'Internet Download Manager', 'vBuzzer Android', 'QQ Download P2P', 'Mail-ru WebMail', 'Baofeng Website', 'Tunnelier', 'ZIP File Download', 'Packetix Proxy', 'AIM Android', 'Dynapass Proxy', 'Pornerbros Streaming', 'Suresome Proxy', 'Hotline Download', 'Circumventor Proxy', 'Shockwave Based Streaming', 'Datei.to FileTransfer', 'Yourlust Streaming', 'Ace2Three Game', 'Fring Android', 'Limelight Playlist Streaming', 'Eyejot Video Message', 'Soul Attempt P2P', 'Ali WangWang Remote Access', 'OKCupid Android', 'Odnoklassniki Android', 'Napster P2P', 'StrongVPN', 'K Proxy', 'Proxyfree Web Proxy', 'FreeU Proxy', 'VNN-VPN Proxy', 'World Of Warcraft Game', 'R-Exec Remote Access', 'Shazam Android', 'MiddleSurf Proxy', 'Fileguri P2P', 'Invisiblenet VPN', 'Mediaget Installer Download', 'Vidyo', 'Chatroulette Web Messenger', 'GaduGadu Web Messenger', 'AnyMeeting Connect', 'Kongshare Proxy', 'Flickr Web Upload', 'PingTunnel Proxy', 'Squirrelmail WebMail', 'PPStream Streaming', 'Hide-IP Browser Proxy', 'Gtalk Android', 'Megashares Upload', 'Njutrino Proxy', 'iLoveIM Web Messenger', 'Cocstream Download', 'Flashget P2P', 'Jigiy Website', 'Fling', 'Caihong Messenger', 'Netease WebMail', 'Steganos Online Shield', 'Tagged Android', 'Puff Proxy', 'Youdao', 'iChat Gtalk', 'Hulu Website', 'Easy-Hide IP Proxy', 'SinaUC Messenger', 'Windows Live IM FileTransfer', 'Storage.to FileTransfer', 'Tube8 Streaming', 'EXE File Download', 'Live-sync Download', 'Hola', 'Pornhub Streaming', 'Socks2HTTP Proxy', 'Lok5 Proxy', 'CyberghostVPN Web Proxy', 'DAP FTP FileTransfer', 'Zedge Android', 'Yahoo Messenger File Receive', 'Chikka Messenger', 'HTTP-Tunnel Proxy', 'Tor2Web Proxy', 'FileMail Webbased Download', 'Hiddenvillage Proxy', 'Gtalk-Way2SMS', 'TruPhone Android', 'FTP Base', 'Megaupload', 'PD Proxy', 'Baidu Messenger', 'LogMeIn Remote Access', 'CoolTalk Messenger', 'Launchwebs Proxy', 'Piolet FileTransfer P2P', 'I2P Proxy', 'Proxify-Tray Proxy', 'Zelune Proxy', 'Scydo Android', 'WebAgent.Mail-ru Messenger', 'PPLive Streaming', 'Hide-Your-IP Proxy', 'GMX WebMail', 'Trillian Web Messenger', 'Telex', 'Manual Proxy Surfing', 'ISL Desktop Conferencing', 'Yahoo Messenger Chat', 'Firefox Update', 'ICQ Android', 'Yuvutu Streaming', 'RealTunnel Proxy', 'Mediafire Download', 'Surrogofier Proxy', 'Eyejot', 'DirectConnect P2P', 'Operamini Proxy', 'Android Market', 'Engadget Android', 'Raaga Android', 'WeBuzz Web Messenger', 'Badonga Download', 'Yousendit Web Download', 'Redtube Streaming', 'CB Radio Chat Android', 'Octopz Website', 'Anonymox', 'Crash Plan', 'Meebo Messenger FileTransfer', 'AirAIM Messenger', 'Tunnel Guru', 'Bebo Website', 'RPC over HTTP Proxy', 'IM+ Android', 'Metin Game', 'GaduGadu Messenger', 'NateApp Android', 'Spy-Agent Remote Access', 'Timbuktu FileTransfer', 'iBackup Application', 'Orkut Android', 'Pingfu Proxy', 'Pokerstars Online Game', 'SendSpace Android', 'Youporn Streaming', 'Invisible Surfing Proxy', 'Vtunnel Proxy', 'Tunnello', 'Zoho Web Login']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'RiskList': {'Risk': 'Very High'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Proxyone', 'SecureLine VPN', 'Just Proxy VPN', 'Psiphon Proxy', 'ProxyProxy', 'SkyVPN', 'Amaze VPN', 'Stealthnet P2P', 'PrivateSurf.us', 'NapMX Retrieve P2P', 'Proxy Switcher Proxy', 'Yoga VPN', 'England Proxy', 'Gom VPN', 'VPN Master', 'Just Open VPN', 'Hide.Me', 'Bypasstunnel.com', 'Tiger VPN', 'Proxifier Proxy', 'FastSecureVPN', 'MP3 Rocket Download', 'TransferBigFiles Application', 'Cyberoam Bypass Chrome Extension', 'SkyEye VPN', 'ItsHidden Proxy', 'Betternet VPN', 'CantFindMeProxy', 'Shareaza P2P', 'DC++ Hub List P2P', 'Power VPN', 'SoftEther VPN', 'Surf-for-free.com', 'VPN Robot', 'Super VPN Master', 'UltraVPN', 'X-VPN', 'Browsec VPN', 'VeePN', 'TorrentHunter Proxy', 'MoonVPN', 'Hot VPN', 'Super VPN', 'Hoxx Vpn', 'OpenInternet', 'PHProxy', 'VPN Monster', 'Cloud VPN', 'RusVPN', 'Speedify', 'Mute P2P', 'TransferBigFiles Web Download', 'The Pirate Bay Proxy', 'VPN 360', 'NateMail WebMail', 'Securitykiss Proxy', 'Websurf', 'FreeMyBrowser', 'uProxy', 'Your-Freedom Proxy', 'Chrome Reduce Data Usage', 'Unclogger VPN', 'Britishproxy.uk Proxy', 'ZenVPN', 'Freegate Proxy', 'VPN over 443', 'Zero VPN', 'Ants IRC Connect P2P', 'WinMX P2P', 'Classroom Spy', 'Expatshield Proxy', 'The Proxy Bay', 'OpenDoor', 'Snap VPN', 'Ultrasurf Proxy', 'CyberGhost VPN Proxy', 'Simurgh Proxy', 'Webproxy', 'Unseen Online VPN', 'Zalmos SSL Web Proxy for Free', 'VyprVPN', 'AppVPN', 'BypassGeo', 'Bearshare P2P', 'Asproxy Web Proxy', 'Pando P2P', 'Easy Proxy', 'VPN 365', 'Lantern', 'Office VPN', 'Proton VPN', 'Miro P2P', 'Morphium.info', 'Ants Initialization P2P', 'Soulseek Download P2P', 'FSecure Freedome VPN', 'Tweakware VPN', 'QQ VPN', 'Redirection Web-Proxy', 'Phex P2P', 'Hamachi VPN Streaming', 'TOR Proxy', 'Ares Retrieve Chat Room', 'UK-Proxy.org.uk Proxy', 'Winny P2P', 'MeHide.asia', 'Alkasir Proxy', 'Windscribe', 'Eagle VPN', 'eMule P2P', 'FastVPN', 'Boinc Messenger', 'Tableau Public', 'DotVPN', 'Photon Flash Player & Browser', 'Proxysite.com Proxy', 'Ares Chat Room', 'Private Tunnel', 'Ares P2P', 'Private VPN', 'Epic Browser', 'Green VPN', 'GoldenKey VPN', 'Cyazyproxy', 'Hexa Tech VPN', 'FinchVPN', 'Vuze P2P', 'WiFree Proxy', 'Ninjaproxy.ninja', 'VPN Free', 'Hideman VPN', 'VPN Lighter', 'L2TP VPN', 'ShellFire VPN', 'ExpressVPN', 'Speedy VPN', 'Toonel', 'Torrent Clients P2P', 'EuropeProxy', 'Hi VPN', 'Freenet P2P', 'Reduh Proxy', 'Kugoo Playlist P2P', 'Frozenway Proxy', 'Soulseek Retrieving P2P', 'Hide-N-Seek Proxy', 'DashVPN', 'Phantom VPN', 'DNSCrypt', 'CrossVPN', 'USA IP', 'Total VPN', 'ZPN VPN', 'ISAKMP VPN', 'Hammer VPN', 'Speed VPN', 'Hotspotshield Proxy', 'Blockless VPN', 'Star VPN', 'RemoboVPN Proxy', 'SSL Proxy Browser', 'TurboVPN', 'PP VPN', 'VPN Unlimited', 'Astrill VPN', 'Hello VPN', 'SetupVPN', 'JAP Proxy', 'Heatseek Browser', 'ProxyWebsite', 'Private Internet Access VPN', 'DC++ Download P2P', 'Thunder VPN', 'skyZIP', 'TOR VPN', 'Haitun VPN', 'Bitcoin Proxy', 'Worldcup Proxy', 'Privatix VPN', 'Ants P2P', 'DC++ Connect P2P']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'CategoryList': {'Category': 'Proxy and Tunnel'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Proxyone', 'SecureLine VPN', 'Just Proxy VPN', 'Reindeer VPN', 'Sslbrowser Proxy', 'Tunnelbear Proxy Login', 'Proxy Switcher Proxy', 'Yoga VPN', 'VPN in Touch', 'AOL Desktop', 'Hide.Me', 'Tiger VPN', 'Proxifier Proxy', 'Spinmyass Proxy', 'ProXPN Proxy', 'ItsHidden Proxy', 'Betternet VPN', 'Gtunnel Proxy', 'WebFreer Proxy', 'Nateon Proxy', 'Power VPN', 'Surf-for-free.com', 'Ghostsurf Proxy', 'Fly Proxy', 'Vpntunnel Proxy', 'Super VPN Master', 'UltraVPN', 'SOCK5 Proxy', 'X-VPN', 'Browsec VPN', 'Proxycap Proxy', 'VeePN', 'SumRando', 'TorrentHunter Proxy', 'NetLoop VPN', 'Hot VPN', 'IP-Shield Proxy', 'Hoxx Vpn', 'Opera Off Road Mode', 'Proxmachine Proxy', 'VPN Monster', 'Speedify', 'The Pirate Bay Proxy', 'VPN 360', 'FreeMyBrowser', 'uProxy', 'Netevader Proxy', 'Unclogger VPN', 'Proxy-service.de Proxy', 'Britishproxy.uk Proxy', 'VPN over 443', 'Zero VPN', 'Kproxyagent Proxy', 'Expatshield Proxy', 'The Proxy Bay', 'OpenDoor', 'Snap VPN', 'Ultrasurf Proxy', 'Rxproxy Proxy', 'Proxyway Proxy', 'VyprVPN', 'AppVPN', 'BypassGeo', 'Easy Proxy', 'Ztunnel Proxy', 'Onavo', 'CoralCDN Proxy', 'Office VPN', 'Proton VPN', 'Morphium.info', 'HTTPort Proxy', 'Tweakware VPN', 'QQ VPN', 'Redirection Web-Proxy', 'HOS Proxy', 'Hopster Proxy', 'Dtunnel Proxy', 'VPNium Proxy', 'MeHide.asia', 'FreeVPN Proxy', 'Eagle VPN', 'Glype Proxy', 'Proxeasy Web Proxy', 'HTTP Tunnel Proxy', 'DotVPN', 'Jailbreak VPN', 'OneClickVPN Proxy', 'Photon Flash Player & Browser', 'Mega Proxy', 'VPNMakers Proxy', 'ShadeYouVPN', 'Max-Anonysurf Proxy', 'Proxeasy Proxy', 'Tunnelbear Proxy Data', 'Vedivi-VPN Proxy', 'Private VPN', 'Gapp Proxy', 'Meebo Repeater Proxy', 'Privitize VPN Proxy', 'Tigervpns', 'Cyazyproxy', 'Hexa Tech VPN', 'FinchVPN', 'WiFree Proxy', 'VPN Free', 'Hideman VPN', 'ShellFire VPN', 'ExpressVPN', 'EuropeProxy', 'Hi VPN', 'Frozenway Proxy', 'Auto-Hide IP Proxy', 'Gbridge VPN Proxy', 'DNSCrypt', 'ZPN VPN', 'Skydur Proxy', 'Hide-My-IP Proxy', 'Hotspotshield Proxy', 'Globosurf Proxy', 'Blockless VPN', 'Star VPN', 'SurfEasy VPN', 'RemoboVPN Proxy', 'SSL Proxy Browser', 'TurboVPN', 'Air Proxy', 'VPN Unlimited', 'Astrill VPN', 'Hello VPN', 'SetupVPN', 'ProxyWebsite', 'Camoproxy Proxy', 'TOR VPN', 'Sslpro.org Proxy', 'Bitcoin Proxy', 'Worldcup Proxy', 'Privatix VPN', 'Psiphon Proxy', '4everproxy Proxy', 'ProxyProxy', 'SkyVPN', 'Btunnel Proxy', 'CProxy Proxy', 'Amaze VPN', 'PrivateSurf.us', 'Real-Hide IP Proxy', 'Wallcooler VPN Proxy', 'England Proxy', 'Gom VPN', 'VPN Master', 'Just Open VPN', 'Tunnelier', 'Bypasstunnel.com', 'Packetix Proxy', 'FastSecureVPN', 'Dynapass Proxy', 'Ctunnel Proxy', 'Suresome Proxy', 'Cyberoam Bypass Chrome Extension', 'SkyEye VPN', 'Circumventor Proxy', 'CantFindMeProxy', 'Kepard Proxy', 'SoftEther VPN', 'VPN Robot', 'StrongVPN', 'K Proxy', 'Proxyfree Web Proxy', 'FreeU Proxy', 'VNN-VPN Proxy', 'MoonVPN', 'MiddleSurf Proxy', 'Super VPN', 'Invisiblenet VPN', 'OpenInternet', 'PHProxy', 'Justproxy Proxy', 'Cloud VPN', 'RusVPN', 'Kongshare Proxy', 'PingTunnel Proxy', 'Hide-IP Browser Proxy', 'Securitykiss Proxy', 'Njutrino Proxy', 'Websurf', 'Idhide Proxy', 'Your-Freedom Proxy', 'Chrome Reduce Data Usage', 'ZenVPN', 'Steganos Online Shield', 'Freegate Proxy', 'Puff Proxy', 'Bypassfw Proxy', 'Easy-Hide IP Proxy', 'Classroom Spy', 'CyberGhost VPN Proxy', 'Simurgh Proxy', 'ZenMate', 'Hola', 'Webproxy', 'Unseen Online VPN', 'Socks2HTTP Proxy', 'Lok5 Proxy', 'SSlunblock Proxy', 'CyberghostVPN Web Proxy', 'Zalmos SSL Web Proxy for Free', 'My-Addr(SSL) Proxy', 'Asproxy Web Proxy', 'VPN 365', 'Lantern', 'HTTP-Tunnel Proxy', 'Tor2Web Proxy', 'Hiddenvillage Proxy', 'Vpndirect Proxy', 'FSecure Freedome VPN', 'Hamachi VPN Streaming', 'TOR Proxy', 'Cocoon', 'PD Proxy', 'UK-Proxy.org.uk Proxy', 'Avoidr Web Proxy', 'Launchwebs Proxy', 'Divavu Proxy', 'I2P Proxy', 'Proxify-Tray Proxy', 'Alkasir Proxy', 'Zelune Proxy', 'Windscribe', 'Proximize Proxy', 'FastVPN', 'SOCK4 Proxy', 'Hide-Your-IP Proxy', 'Aniscartujo Web Proxy', 'Telex', 'Proxysite.com Proxy', 'Manual Proxy Surfing', 'Private Tunnel', 'Spotflux Proxy', 'RealTunnel Proxy', 'Epic Browser', 'Green VPN', 'Surrogofier Proxy', 'GoldenKey VPN', 'Operamini Proxy', 'Mysslproxy Proxy', 'Ninjaproxy.ninja', 'VPN Lighter', 'L2TP VPN', 'uVPN', 'Speedy VPN', 'Toonel', 'Reduh Proxy', 'Anonymox', 'Hide-N-Seek Proxy', 'DashVPN', 'Phantom VPN', 'CrossVPN', 'Tunnel Guru', 'USA IP', 'Total VPN', 'ISAKMP VPN', 'Hammer VPN', 'RPC over HTTP Proxy', 'Speed VPN', 'PP VPN', 'Pingfu Proxy', 'JAP Proxy', 'Private Internet Access VPN', 'Thunder VPN', 'skyZIP', 'Invisible Surfing Proxy', 'Vtunnel Proxy', 'Haitun VPN', 'Tunnello']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'CharacteristicsList': {'Characteristics': 'Transfer files'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Zalo', 'WebDAV', 'Mail-ru Messenger', 'Kaseya Client Connect', 'Rediffbol Messenger', 'Pipedrive Upload', 'Between', 'AOL Desktop', 'Hike', 'DeskGate', 'ShareBlast', 'Fileserver File Transfer', 'Storage.to Download', 'Weezo', 'Dropbox Download', 'QQ Messenger', 'Foxit Reader Update', 'Xero Download', 'Google Street Android', 'DAP Download', 'iCloud Photo Stream', 'TelTel VOIP', '126 Mail', 'AIM Express Messenger', 'Avast Antivirus Update', 'Tixati P2P', 'WikiEncyclopedia Android', 'Microsoft NetMeeting', 'RAR File Download', 'UbuntuOne FileTransfer', 'TripAdvisor Android', 'Behance Upload', 'Apple-Juice P2P', 'WeTransfer Upload', 'Akamai Client', 'Picasa Website', 'Opera Off Road Mode', 'Citrix Receiver', 'eFolder', 'FileMail WebMail', 'Pcloud Download', 'Clubbox', 'Yahoo Messenger File Transfer', 'File.host File Transfer', 'TransferBigFiles Web Download', 'E-Snips Download', 'GetRight Download', 'SMTP Executable Attachment', 'Klite Initiation P2P', 'Turbobit Download', 'Hyves Messenger', 'Tango Android', '1Fichier Upload', 'FileRio Download', 'MSN2GO Messenger', 'YY Voice Messenger', 'MQTT', 'Diino File Download', 'Easy Proxy', 'Yourfilehost Download', 'Onavo', '100BAO P2P', 'DNS Multiple QNAME', 'Foursquare Android', 'Docstoc File Transfer', 'IP Messenger FileTransfer', 'Ares Retrieve Chat Room', 'WhatsApp File Transfer', 'Taobao Aliwangwang Messenger', 'Bebo WebMail', 'Rapidshare Download', 'Zimbra', 'Bearshare Download', 'MP3 File Download', 'AVG Antivirus Update', 'Ares Chat Room', 'Sharepoint Search', 'Uploading File Transfer', 'Kool Web Messenger', 'CloudMe Storage Login', 'Twitter Upload', 'Piolet Initialization P2P', 'Meebo Repeater', 'SquirrelMail Attachment', 'Gigaup File Transfer', 'CodeAnywhere Android', 'Instant Housecall Remote Access', 'iCloud Mail', 'Morpheus P2P', 'SoMud', 'Zoho WebMessenger', 'CloudApp', 'Bitshare Upload', 'Facebook Status Update', 'Zippyshare Download', 'Soulseek Retrieving P2P', 'Hipfile Upload', 'TeamViewer FileTransfer', 'X-Fire Messenger', 'BookMyShow Android', 'Netload File Transfer', 'Gtalk Messenger FileTransfer', 'Putlocker Download', 'Garena Web Messenger', 'IMO Messenger', 'SurfEasy VPN', 'Sohu WebMail', '4shared File Transfer', 'Trillian Messenger', 'Backblaze', 'Heatseek Browser', 'LimeWire', 'IMO-Chat Android', 'Kaspersky Antivirus Update', 'Microsoft Outlook', 'DC++ Connect P2P', 'Twitter Website', 'MSN Shell Messenger', 'ICQ Messenger', 'Stealthnet P2P', 'Yahoo Webmail File Attach', 'PCVisit.de Remote Access', 'DirectTV Android', 'KakaoTalk', 'Zoho Meeting Conferencing', 'vBuzzer Android', 'Camfrog Messenger', 'WebEx', 'Yandex Disk', 'NakidoFlag File Transfer', 'T-Online Webmail', 'SendSpace', 'Citrix GoToTraining', 'ZIP File Download', 'Copy', 'Rapidgator Upload', 'TransferBigFiles Application', 'Box', 'Hotline Download', 'Fring Android', 'Attix5 Backup', 'Odnoklassniki Android', 'Napster P2P', 'HPE MyRoom', 'Nateon Messenger', 'Instant-t Messenger', 'LifeSize Cloud', 'Zippyshare Upload', 'LinkedIN Compose Webmail', 'My Mail.ru', 'ICQ2GO Messenger', 'Mail.com File Storage', 'HTTP Resume FileTransfer', 'Vidyo', 'Badongo File Download', 'Pipedrive Download', 'Chatroulette Web Messenger', 'AnyMeeting Connect', 'IMPlus Web Messenger', 'Facebook Website', 'iLoveIM Web Messenger', 'Multi Thread File Transfer', 'Cocstream Download', 'Signal Private Messenger', 'Kaseya Portal Login', 'Issuu File Transfer', 'Webex File Transfer', 'Caihong Messenger', 'Divshare File Transfer', 'Hangame', 'Youdao', 'Classroom Spy', 'IMI Messenger', 'IBM CXN Cloud Files', 'Storage.to FileTransfer', 'File2hd Web Download', 'RenRen Messenger', 'Lync', 'MEO Cloud', 'Timbuktu Messenger', 'DAP FTP FileTransfer', 'QQ Remote Access', 'Yahoo Messenger File Receive', 'Goo Webmail', 'FileRio Upload', 'Snapchat', 'TrendMicro AV Update', 'Yahoo Groups', 'Google Location', 'AttachLargeFile Download', 'Filecloud.io', 'MxiT Android', 'Ants Initialization P2P', 'WeChat Web', 'Megaupload', 'Mail.com Compose Mail', 'Piolet FileTransfer P2P', 'Hightail', 'Tumblr Post', 'Salesforce Web Login', 'LinkedIN Android', 'CricInfo Android', 'TwitVid Upload/Download', 'Scydo Android', 'Orange Webmail', 'GMX WebMail', 'CNN News Android', 'TiKL', 'Firefox Update', 'Meetup Message', 'Vchat', 'ICQ Android', 'DingTalk', 'MediaGet P2P', 'WeTransfer Download', 'Mediafire Download', 'Telenet Webmail', 'Depositfiles Download', 'ICU Messenger', 'iPTT', 'E-Bay Android', 'Vuze P2P', 'Raaga Android', 'Discord', 'Comment Attachment - Facebook', 'Turbobit Upload', 'HipChat', 'WeTransfer Base', 'Badonga Download', 'Yousendit Web Download', 'TrendMicro SafeSync', 'Uptobox Upload', 'Bayfiles Upload', 'Meebo Messenger FileTransfer', 'Sendspace Upload', 'AirAIM Messenger', 'NateApp Android', 'Free Download Manager', 'Iozeta', 'Timbuktu FileTransfer', 'iCloud Drive', 'iBackup Application', 'ChatWork', 'OneDrive File Upload', 'Pcloud Upload', 'SnapBucket Android', 'Ants P2P', 'Live.ly', 'Putlocker Upload', 'WeChat File Transfer', 'Skype', 'Manolito P2P Download', 'VzoChat Messenger', 'BlueJeans Conferencing', 'Google Drive File Download', 'Tubemate', 'Axifile File Transfer', 'Bitshare Download', 'Mega', 'MS Essentials AV Update', 'Jabber', 'Plustransfer Upload', 'MP3 Rocket Download', 'AOL WebMail', 'filestube Search', 'Archive.Org', 'EspnCricinfo Android', 'Carbonite', 'MyDownloader', '1Fichier Download', 'Justcloud File Transfer', 'iCloud', 'Citrix Online', 'WhatsApp Web', 'Eset NoD32 Update', 'Join-Me Conferencing', 'QQ Messenger File Transfer', 'Jumblo VOIP', 'Chikka Web Messenger', 'Mig33 Android', 'Dl Free Upload Download', 'Igoogle-Gtalk', '1 & 1 Webmail', 'Hovrs Messenger', 'Fetion Messenger', 'Twitter Android', 'Gmail Attachment', 'Box File Download', 'Hush WebMail', 'Google Sky Android', 'Digsby Messenger', 'COX WebMail', 'OCN Webmail', 'Mail.com WebMail', 'Sharepoint', 'Mobogenie', 'WinMX P2P', 'SugarSync FileTransfer', 'SendMyWay Upload', 'Box File Upload', 'MSN-Way2SMS WebMail', 'Imhaha Web Messenger', 'AIM File Transfer', 'TwitPic Upload/Download', 'Viber Message', 'Bearshare P2P', 'Myspace Chat', 'Peercast P2P', 'Google Drive Base', 'Eyejot Web Messenger', 'Mendeley Desktop', 'Gtalk Messenger', 'Soulseek Download P2P', 'Phex P2P', 'Multiupload Download', 'Citrix ICA', 'BBM', 'Eagleget', 'AOL Mail Attachment', 'TalkBox Android', 'Hotfile Download', 'PalTalk Messenger', 'ISPQ Messenger', 'Mobyler Android', 'eMule P2P', 'Fastmail Webmail', 'Tableau Public', 'Scribd File Transfer', 'IMVU Messenger', 'Xero Upload', 'Rapidgator Download', 'LinkedIN Messenger File Download', 'Meebo Website', 'Crocko Upload', 'Line Messenger File Transfer', 'Dropbox Base', 'Odnoklassniki Web Messenger', 'Airset Access', 'BeAnywhere', 'SOMA Messanger', 'Google Drive File Upload', 'Lightshot', 'HotFile Website', 'SoundHound Android', '2shared Download', 'Okurin File Transfer', 'Egnyte File Transfer', 'Tellagami Share', 'Imesh P2P', 'Kugoo Playlist P2P', 'WhatsCall', 'Comcast', 'Timbuktu DesktopMail', 'Plustransfer Download', 'Sendspace Download', 'LiveMeeting Conferencing', 'Dropsend Download Applications', 'Screen Connect', 'Altools Update', 'Goggles Android', 'Avaya Conference FileTransfer', 'WocChat Messenger', 'Front', 'DC++ Download P2P', 'HTTP File Upload', 'ASUS WebStorage', 'My SharePoint', 'NTR Cloud', 'Palringo Messenger', 'Gmail Android Application', 'Talkray', 'Facebook Android', 'Uptobox', '2shared Upload', 'Zshare Upload', 'OneDrive Application', 'NapMX Retrieve P2P', 'AnyMeeting WebLogin', 'GoChat Android', 'Daum WebMail', 'OneDrive File Download', 'PI-Chat Messenger', 'Ebuddy Web Messenger', 'Internet Download Manager', 'Qeep Android', 'QQ Download P2P', 'VK Message', 'Sharepoint Calendar', 'Windows Live Website', 'AIM Android', 'GitHub Upload', 'SlideShare Upload', 'Ebuddy Android', 'OLX Android', 'Panda Antivirus Update', 'Shareaza P2P', 'Bigupload File Transfer', 'DC++ Hub List P2P', 'Supremo Remote Access', 'Datei.to FileTransfer', 'IBM Notes', 'Zoom Meetings', 'SlideShare Download', 'Soul Attempt P2P', 'OKCupid Android', 'Viber Media', 'Cubby File transfer', 'MessengerFX', 'Rambler Mail', 'LiveGO Messenger', 'LinkedIN Messenger File Upload', 'Moxtra', 'Shazam Android', 'Embedupload File Transfer', 'Telegram', 'Fileguri P2P', 'Uptobox Download', 'Mediaget Installer Download', 'GMX Mail Attachment', 'Outlook.com File Attach', 'GaduGadu Web Messenger', 'SlideShare', 'Minus Upload', 'Nomadesk Download', 'Garena Messenger', 'Gtalk Android', 'Megashares Upload', 'Yahoo WebMail', 'IP Messenger', 'Flashget P2P', 'Google Plus Hangouts', 'Zippyshare', 'Gmail WebMail', 'Google Safebrowsing', 'Tagged Android', 'Chat On', 'Palringo Web Messenger', 'iChat Gtalk', 'Ants IRC Connect P2P', 'Antivir Antivirus Update', 'Omegle Web Messenger', 'SinaUC Messenger', 'Windows Live IM FileTransfer', 'VK Mail', 'EXE File Download', 'Live-sync Download', 'Alpemix', 'Tortoise SVN', 'Yandex Mail', 'Apt-Get Command', 'Hotfile Upload', 'VirtualBox Update', 'Pando P2P', 'Zedge Android', 'Chikka Messenger', 'Korea WebMail', 'Bebo WebChat IM', 'Microsoft Teams', 'Miro P2P', 'FileMail Webbased Download', 'Filer.cx File Transfer', 'TruPhone Android', 'Bonpoo File Transfer', 'pCloud', 'FTP Base', 'Odrive', 'Baidu Messenger', 'Google Hangout Android App', 'CoolTalk Messenger', 'Winny P2P', 'I2P Proxy', 'Excite Mail', 'TuneIN Radio Android', 'Zshare Download', 'Game Center', 'DaumMaps Android', 'ADrive Web Upload', 'Hyves WebMail', 'TrueConf', 'Trillian Web Messenger', 'Tox', 'Yahoo Messenger Chat', 'Voxer Walkie-Talkie PTT', 'Ares P2P', 'Outlook.com', 'GitHub Download', 'Blogger Android', 'DirectConnect P2P', 'Android Market', 'Engadget Android', 'Brothersoft Website', 'Infoseek Webmail', 'G Suite', 'WeBuzz Web Messenger', 'Fotki Media Upload', 'YahooMail Calendar', 'Nimbuzz IM Update', 'Torrent Clients P2P', 'Filedropper File Transfer', 'Freenet P2P', 'Skype Services', 'CB Radio Chat Android', 'Crash Plan', 'Dropbox File Upload', 'Depositfiles Upload', 'Google Plus Upload', 'IM+ Android', 'Tumblr Android', 'GaduGadu Messenger', 'Spy-Agent Remote Access', 'Orkut Android', 'SendSpace Android', 'Waze Android', 'GMX Compose Mail', 'Sabercathost Upload', 'OneDrive Base']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'CategoryList': {'Category': 'File Transfer'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Putlocker Upload', 'WeChat File Transfer', '2shared Upload', 'Zshare Upload', 'Yahoo Messenger File Receive', 'FileRio Upload', 'Yahoo Webmail File Attach', 'Google Drive File Download', 'Axifile File Transfer', 'Mendeley Desktop', 'Filecloud.io', 'OneDrive File Download', 'Filer.cx File Transfer', 'Docstoc File Transfer', 'Bonpoo File Transfer', 'Mega', 'IP Messenger FileTransfer', 'NakidoFlag File Transfer', 'SendSpace', 'Fileserver File Transfer', 'ZIP File Download', 'Hightail', 'Rapidgator Upload', 'TwitVid Upload/Download', 'SlideShare Upload', 'Bigupload File Transfer', 'We Heart It Upload', 'MP3 File Download', 'Scribd File Transfer', 'SlideShare Download', 'Crocko Upload', 'Line Messenger File Transfer', 'Cubby File transfer', 'Uploading File Transfer', 'Justcloud File Transfer', 'iCloud', 'Serv-U RemoteAccess FileTransfer', 'WeTransfer Download', 'Google Drive File Upload', 'RAR File Download', 'Embedupload File Transfer', 'JDownloader', 'QQ Messenger File Transfer', 'UbuntuOne FileTransfer', 'Gigaup File Transfer', 'Uptobox Download', 'WeTransfer Upload', 'HTTP Resume FileTransfer', 'Fotki Media Upload', 'Outlook.com File Attach', 'Okurin File Transfer', 'Egnyte File Transfer', 'Turbobit Upload', 'WeTransfer Base', 'CloudApp', 'Filedropper File Transfer', 'Bitshare Upload', 'TrendMicro SafeSync', 'Uptobox Upload', 'Minus Upload', 'Bayfiles Upload', 'Hipfile Upload', 'Meebo Messenger FileTransfer', 'Gmail Attachment', 'Clubbox', 'Sendspace Upload', 'File.host File Transfer', 'Yahoo Messenger File Transfer', 'TeamViewer FileTransfer', 'Last.fm Free Downloads', 'Netload File Transfer', 'Gtalk Messenger FileTransfer', 'Megashares Upload', 'Multi Thread File Transfer', 'Issuu File Transfer', 'Zippyshare', 'Webex File Transfer', '4shared File Transfer', 'Divshare File Transfer', 'Timbuktu FileTransfer', '1Fichier Upload', 'Avaya Conference FileTransfer', 'SendMyWay Upload', 'SugarSync FileTransfer', 'HTTP File Upload', 'Windows Live IM FileTransfer', 'Mega Download', 'AIM File Transfer', 'EXE File Download', 'Tortoise SVN', 'OneDrive File Upload', 'TwitPic Upload/Download', 'Hotfile Upload', 'Uptobox']}, 'Action': 'Deny', 'Schedule': 'All The Time'} |
>| Block high risk (Risk Level 4 and 5) apps | Drops traffic that are classified under high risk apps (Risk Level- 4 and 5). | True | Allow | Rule: {'SelectAllRule': 'Enable', 'RiskList': {'Risk': 'High'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Sopcast Streaming', 'Sslbrowser Proxy', 'Mail-ru Messenger', 'Storage.to Download', 'AOL Radio Website', 'NeverMail WebMail', 'Weezo', 'Spinmyass Proxy', 'ProXPN Proxy', 'AOL WebMail', 'WhatsApp', 'Gtunnel Proxy', 'DroidVPN', 'Nateon Proxy', 'Ghostsurf Proxy', 'MyDownloader', 'DAP Download', 'GoBoogy Login P2P', 'Fly Proxy', 'Vpntunnel Proxy', 'iCAP Business', 'Tixati P2P', 'Proxycap Proxy', 'RAR File Download', 'QQ Messenger File Transfer', 'SumRando', 'NetLoop VPN', 'Apple-Juice P2P', 'Chikka Web Messenger', 'Livedoor Web Login', 'Akamai Client', 'Mig33 Android', 'Opera Off Road Mode', 'Dl Free Upload Download', 'Quick Player Streaming', 'FileMail WebMail', 'Live Station Streaming', 'Propel Accelerator', 'Yahoo Messenger File Transfer', 'E-Snips Download', 'Digsby Messenger', 'Klite Initiation P2P', 'Sightspeed VOIP', 'Classmates Website', 'Tango Android', 'Tudou Streaming', 'Kproxyagent Proxy', 'Imhaha Web Messenger', 'Rxproxy Proxy', 'Proxyway Proxy', 'iConnectHere', 'Sina WebMail', 'Absolute Computrance', 'VNC Remote Access', 'Ztunnel Proxy', 'Myspace Chat', '100BAO P2P', 'Peercast P2P', 'Gtalk Messenger', 'HTTPort Proxy', 'Bestporntube Streaming', 'HOS Proxy', 'IP Messenger FileTransfer', 'Multiupload Download', 'Hopster Proxy', 'Citrix ICA', 'TalkBox Android', 'VPNium Proxy', 'FreeVPN Proxy', 'Rapidshare Download', 'PalTalk Messenger', 'Bearshare Download', 'ISPQ Messenger', 'Glype Proxy', 'Mobyler Android', 'Proxeasy Web Proxy', 'HTTP Tunnel Proxy', 'MP3 File Download', 'Jailbreak VPN', 'OneClickVPN Proxy', 'LastPass', 'Mega Proxy', 'VPNMakers Proxy', 'ShadeYouVPN', 'Eroom Website', 'Max-Anonysurf Proxy', 'Proxeasy Proxy', 'Vedivi-VPN Proxy', 'Odnoklassniki Web Messenger', 'Gapp Proxy', '56.com Streaming', 'xHamster Streaming', 'Lightshot', 'Piolet Initialization P2P', 'HotFile Website', 'SoundHound Android', 'Privitize VPN Proxy', 'CodeAnywhere Android', 'QuickTime Streaming', 'Morpheus P2P', 'Imesh P2P', 'Auto-Hide IP Proxy', 'Timbuktu DesktopMail', 'Sendspace Download', 'Gtalk Messenger FileTransfer', 'Skydur Proxy', 'Hide-My-IP Proxy', 'Globosurf Proxy', 'SurfEasy VPN', 'Avaya Conference FileTransfer', 'WocChat Messenger', 'Trillian Messenger', 'Napster Streaming', 'Camoproxy Proxy', 'ASUS WebStorage', 'IMO-Chat Android', 'QQ Web Messenger', 'NTR Cloud', 'Palringo Messenger', 'Baidu IME', 'Serv-U Remote Access', 'ICQ Messenger', 'DirectTV Android', 'GoChat Android', 'Real-Hide IP Proxy', 'Genesys Website', 'PI-Chat Messenger', 'Ebuddy Web Messenger', 'Internet Download Manager', 'vBuzzer Android', 'QQ Download P2P', 'Mail-ru WebMail', 'Baofeng Website', 'Tunnelier', 'ZIP File Download', 'Packetix Proxy', 'AIM Android', 'Dynapass Proxy', 'Pornerbros Streaming', 'Suresome Proxy', 'Hotline Download', 'Circumventor Proxy', 'Shockwave Based Streaming', 'Datei.to FileTransfer', 'Yourlust Streaming', 'Ace2Three Game', 'Fring Android', 'Limelight Playlist Streaming', 'Eyejot Video Message', 'Soul Attempt P2P', 'Ali WangWang Remote Access', 'OKCupid Android', 'Odnoklassniki Android', 'Napster P2P', 'StrongVPN', 'K Proxy', 'Proxyfree Web Proxy', 'FreeU Proxy', 'VNN-VPN Proxy', 'World Of Warcraft Game', 'R-Exec Remote Access', 'Shazam Android', 'MiddleSurf Proxy', 'Fileguri P2P', 'Invisiblenet VPN', 'Mediaget Installer Download', 'Vidyo', 'Chatroulette Web Messenger', 'GaduGadu Web Messenger', 'AnyMeeting Connect', 'Kongshare Proxy', 'Flickr Web Upload', 'PingTunnel Proxy', 'Squirrelmail WebMail', 'PPStream Streaming', 'Hide-IP Browser Proxy', 'Gtalk Android', 'Megashares Upload', 'Njutrino Proxy', 'iLoveIM Web Messenger', 'Cocstream Download', 'Flashget P2P', 'Jigiy Website', 'Fling', 'Caihong Messenger', 'Netease WebMail', 'Steganos Online Shield', 'Tagged Android', 'Puff Proxy', 'Youdao', 'iChat Gtalk', 'Hulu Website', 'Easy-Hide IP Proxy', 'SinaUC Messenger', 'Windows Live IM FileTransfer', 'Storage.to FileTransfer', 'Tube8 Streaming', 'EXE File Download', 'Live-sync Download', 'Hola', 'Pornhub Streaming', 'Socks2HTTP Proxy', 'Lok5 Proxy', 'CyberghostVPN Web Proxy', 'DAP FTP FileTransfer', 'Zedge Android', 'Yahoo Messenger File Receive', 'Chikka Messenger', 'HTTP-Tunnel Proxy', 'Tor2Web Proxy', 'FileMail Webbased Download', 'Hiddenvillage Proxy', 'Gtalk-Way2SMS', 'TruPhone Android', 'FTP Base', 'Megaupload', 'PD Proxy', 'Baidu Messenger', 'LogMeIn Remote Access', 'CoolTalk Messenger', 'Launchwebs Proxy', 'Piolet FileTransfer P2P', 'I2P Proxy', 'Proxify-Tray Proxy', 'Zelune Proxy', 'Scydo Android', 'WebAgent.Mail-ru Messenger', 'PPLive Streaming', 'Hide-Your-IP Proxy', 'GMX WebMail', 'Trillian Web Messenger', 'Telex', 'Manual Proxy Surfing', 'ISL Desktop Conferencing', 'Yahoo Messenger Chat', 'Firefox Update', 'ICQ Android', 'Yuvutu Streaming', 'RealTunnel Proxy', 'Mediafire Download', 'Surrogofier Proxy', 'Eyejot', 'DirectConnect P2P', 'Operamini Proxy', 'Android Market', 'Engadget Android', 'Raaga Android', 'WeBuzz Web Messenger', 'Badonga Download', 'Yousendit Web Download', 'Redtube Streaming', 'CB Radio Chat Android', 'Octopz Website', 'Anonymox', 'Crash Plan', 'Meebo Messenger FileTransfer', 'AirAIM Messenger', 'Tunnel Guru', 'Bebo Website', 'RPC over HTTP Proxy', 'IM+ Android', 'Metin Game', 'GaduGadu Messenger', 'NateApp Android', 'Spy-Agent Remote Access', 'Timbuktu FileTransfer', 'iBackup Application', 'Orkut Android', 'Pingfu Proxy', 'Pokerstars Online Game', 'SendSpace Android', 'Youporn Streaming', 'Invisible Surfing Proxy', 'Vtunnel Proxy', 'Tunnello', 'Zoho Web Login']}, 'Action': 'Deny', 'Schedule': 'All The Time'},<br/>{'SelectAllRule': 'Enable', 'RiskList': {'Risk': 'Very High'}, 'SmartFilter': None, 'ApplicationList': {'Application': ['Proxyone', 'SecureLine VPN', 'Just Proxy VPN', 'Psiphon Proxy', 'ProxyProxy', 'SkyVPN', 'Amaze VPN', 'Stealthnet P2P', 'PrivateSurf.us', 'NapMX Retrieve P2P', 'Proxy Switcher Proxy', 'Yoga VPN', 'England Proxy', 'Gom VPN', 'VPN Master', 'Just Open VPN', 'Hide.Me', 'Bypasstunnel.com', 'Tiger VPN', 'Proxifier Proxy', 'FastSecureVPN', 'MP3 Rocket Download', 'TransferBigFiles Application', 'Cyberoam Bypass Chrome Extension', 'SkyEye VPN', 'ItsHidden Proxy', 'Betternet VPN', 'CantFindMeProxy', 'Shareaza P2P', 'DC++ Hub List P2P', 'Power VPN', 'SoftEther VPN', 'Surf-for-free.com', 'VPN Robot', 'Super VPN Master', 'UltraVPN', 'X-VPN', 'Browsec VPN', 'VeePN', 'TorrentHunter Proxy', 'MoonVPN', 'Hot VPN', 'Super VPN', 'Hoxx Vpn', 'OpenInternet', 'PHProxy', 'VPN Monster', 'Cloud VPN', 'RusVPN', 'Speedify', 'Mute P2P', 'TransferBigFiles Web Download', 'The Pirate Bay Proxy', 'VPN 360', 'NateMail WebMail', 'Securitykiss Proxy', 'Websurf', 'FreeMyBrowser', 'uProxy', 'Your-Freedom Proxy', 'Chrome Reduce Data Usage', 'Unclogger VPN', 'Britishproxy.uk Proxy', 'ZenVPN', 'Freegate Proxy', 'VPN over 443', 'Zero VPN', 'Ants IRC Connect P2P', 'WinMX P2P', 'Classroom Spy', 'Expatshield Proxy', 'The Proxy Bay', 'OpenDoor', 'Snap VPN', 'Ultrasurf Proxy', 'CyberGhost VPN Proxy', 'Simurgh Proxy', 'Webproxy', 'Unseen Online VPN', 'Zalmos SSL Web Proxy for Free', 'VyprVPN', 'AppVPN', 'BypassGeo', 'Bearshare P2P', 'Asproxy Web Proxy', 'Pando P2P', 'Easy Proxy', 'VPN 365', 'Lantern', 'Office VPN', 'Proton VPN', 'Miro P2P', 'Morphium.info', 'Ants Initialization P2P', 'Soulseek Download P2P', 'FSecure Freedome VPN', 'Tweakware VPN', 'QQ VPN', 'Redirection Web-Proxy', 'Phex P2P', 'Hamachi VPN Streaming', 'TOR Proxy', 'Ares Retrieve Chat Room', 'UK-Proxy.org.uk Proxy', 'Winny P2P', 'MeHide.asia', 'Alkasir Proxy', 'Windscribe', 'Eagle VPN', 'eMule P2P', 'FastVPN', 'Boinc Messenger', 'Tableau Public', 'DotVPN', 'Photon Flash Player & Browser', 'Proxysite.com Proxy', 'Ares Chat Room', 'Private Tunnel', 'Ares P2P', 'Private VPN', 'Epic Browser', 'Green VPN', 'GoldenKey VPN', 'Cyazyproxy', 'Hexa Tech VPN', 'FinchVPN', 'Vuze P2P', 'WiFree Proxy', 'Ninjaproxy.ninja', 'VPN Free', 'Hideman VPN', 'VPN Lighter', 'L2TP VPN', 'ShellFire VPN', 'ExpressVPN', 'Speedy VPN', 'Toonel', 'Torrent Clients P2P', 'EuropeProxy', 'Hi VPN', 'Freenet P2P', 'Reduh Proxy', 'Kugoo Playlist P2P', 'Frozenway Proxy', 'Soulseek Retrieving P2P', 'Hide-N-Seek Proxy', 'DashVPN', 'Phantom VPN', 'DNSCrypt', 'CrossVPN', 'USA IP', 'Total VPN', 'ZPN VPN', 'ISAKMP VPN', 'Hammer VPN', 'Speed VPN', 'Hotspotshield Proxy', 'Blockless VPN', 'Star VPN', 'RemoboVPN Proxy', 'SSL Proxy Browser', 'TurboVPN', 'PP VPN', 'VPN Unlimited', 'Astrill VPN', 'Hello VPN', 'SetupVPN', 'JAP Proxy', 'Heatseek Browser', 'ProxyWebsite', 'Private Internet Access VPN', 'DC++ Download P2P', 'Thunder VPN', 'skyZIP', 'TOR VPN', 'Haitun VPN', 'Bitcoin Proxy', 'Worldcup Proxy', 'Privatix VPN', 'Ants P2P', 'DC++ Connect P2P']}, 'Action': 'Deny', 'Schedule': 'All The Time'} |
>| Block peer to peer (P2P) networking apps | Drops traffic from applications that are categorized as P2P apps. P2P could be a mechanism for distributing Bots, Spywares, Adware, Trojans, Rootkits, Worms and other types of malwares. It is generally advised to have P2P application blocked in your network. | True | Allow | Rule: {"SelectAllRule": "Enable", "CategoryList": {"Category": "P2P"}, "SmartFilter": null, "ApplicationList": {"Application": ["VeryCD", "Piolet Initialization P2P", "Bearshare P2P", "Pando P2P", "DirectConnect P2P", "Manolito P2P Download", "Apple-Juice P2P", "Fileguri P2P", "Stealthnet P2P", "Vuze P2P", "100BAO P2P", "NapMX Retrieve P2P", "Peercast P2P", "Morpheus P2P", "Miro P2P", "SoMud", "QQ Download P2P", "Ants Initialization P2P", "Soulseek Download P2P", "Torrent Clients P2P", "Imesh P2P", "Freenet P2P", "Kugoo Playlist P2P", "Phex P2P", "Soulseek Retrieving P2P", "Mute P2P", "Winny P2P", "Piolet FileTransfer P2P", "MP3 Rocket Download", "Klite Initiation P2P", "Flashget P2P", "Shareaza P2P", "DC++ Hub List P2P", "eMule P2P", "Manolito P2P Search", "Soul Attempt P2P", "Ants IRC Connect P2P", "WinMX P2P", "GoBoogy Login P2P", "DC++ Download P2P", "Napster P2P", "LimeWire", "Ares P2P", "Manolito P2P Connect", "Tixati P2P", "Gnutella P2P", "Manolito P2P GetServer List", "MediaGet P2P", "Ants P2P", "DC++ Connect P2P"]}, "Action": "Deny", "Schedule": "All The Time"} |
>| Block very high risk (Risk Level 5) apps | Drops traffic that are classified under very high risk apps (Risk Level- 5). | True | Allow | Rule: {"SelectAllRule": "Enable", "RiskList": {"Risk": "Very High"}, "SmartFilter": null, "ApplicationList": {"Application": ["Proxyone", "SecureLine VPN", "Just Proxy VPN", "Psiphon Proxy", "ProxyProxy", "SkyVPN", "Amaze VPN", "Stealthnet P2P", "PrivateSurf.us", "NapMX Retrieve P2P", "Proxy Switcher Proxy", "Yoga VPN", "England Proxy", "Gom VPN", "VPN Master", "Just Open VPN", "Hide.Me", "Bypasstunnel.com", "Tiger VPN", "Proxifier Proxy", "FastSecureVPN", "MP3 Rocket Download", "TransferBigFiles Application", "Cyberoam Bypass Chrome Extension", "SkyEye VPN", "ItsHidden Proxy", "Betternet VPN", "CantFindMeProxy", "Shareaza P2P", "DC++ Hub List P2P", "Power VPN", "SoftEther VPN", "Surf-for-free.com", "VPN Robot", "Super VPN Master", "UltraVPN", "X-VPN", "Browsec VPN", "VeePN", "TorrentHunter Proxy", "MoonVPN", "Hot VPN", "Super VPN", "Hoxx Vpn", "OpenInternet", "PHProxy", "VPN Monster", "Cloud VPN", "RusVPN", "Speedify", "Mute P2P", "TransferBigFiles Web Download", "The Pirate Bay Proxy", "VPN 360", "NateMail WebMail", "Securitykiss Proxy", "Websurf", "FreeMyBrowser", "uProxy", "Your-Freedom Proxy", "Chrome Reduce Data Usage", "Unclogger VPN", "Britishproxy.uk Proxy", "ZenVPN", "Freegate Proxy", "VPN over 443", "Zero VPN", "Ants IRC Connect P2P", "WinMX P2P", "Classroom Spy", "Expatshield Proxy", "The Proxy Bay", "OpenDoor", "Snap VPN", "Ultrasurf Proxy", "CyberGhost VPN Proxy", "Simurgh Proxy", "Webproxy", "Unseen Online VPN", "Zalmos SSL Web Proxy for Free", "VyprVPN", "AppVPN", "BypassGeo", "Bearshare P2P", "Asproxy Web Proxy", "Pando P2P", "Easy Proxy", "VPN 365", "Lantern", "Office VPN", "Proton VPN", "Miro P2P", "Morphium.info", "Ants Initialization P2P", "Soulseek Download P2P", "FSecure Freedome VPN", "Tweakware VPN", "QQ VPN", "Redirection Web-Proxy", "Phex P2P", "Hamachi VPN Streaming", "TOR Proxy", "Ares Retrieve Chat Room", "UK-Proxy.org.uk Proxy", "Winny P2P", "MeHide.asia", "Alkasir Proxy", "Windscribe", "Eagle VPN", "eMule P2P", "FastVPN", "Boinc Messenger", "Tableau Public", "DotVPN", "Photon Flash Player & Browser", "Proxysite.com Proxy", "Ares Chat Room", "Private Tunnel", "Ares P2P", "Private VPN", "Epic Browser", "Green VPN", "GoldenKey VPN", "Cyazyproxy", "Hexa Tech VPN", "FinchVPN", "Vuze P2P", "WiFree Proxy", "Ninjaproxy.ninja", "VPN Free", "Hideman VPN", "VPN Lighter", "L2TP VPN", "ShellFire VPN", "ExpressVPN", "Speedy VPN", "Toonel", "Torrent Clients P2P", "EuropeProxy", "Hi VPN", "Freenet P2P", "Reduh Proxy", "Kugoo Playlist P2P", "Frozenway Proxy", "Soulseek Retrieving P2P", "Hide-N-Seek Proxy", "DashVPN", "Phantom VPN", "DNSCrypt", "CrossVPN", "USA IP", "Total VPN", "ZPN VPN", "ISAKMP VPN", "Hammer VPN", "Speed VPN", "Hotspotshield Proxy", "Blockless VPN", "Star VPN", "RemoboVPN Proxy", "SSL Proxy Browser", "TurboVPN", "PP VPN", "VPN Unlimited", "Astrill VPN", "Hello VPN", "SetupVPN", "JAP Proxy", "Heatseek Browser", "ProxyWebsite", "Private Internet Access VPN", "DC++ Download P2P", "Thunder VPN", "skyZIP", "TOR VPN", "Haitun VPN", "Bitcoin Proxy", "Worldcup Proxy", "Privatix VPN", "Ants P2P", "DC++ Connect P2P"]}, "Action": "Deny", "Schedule": "All The Time"} |


### sophos-firewall-app-policy-get
***
Get a single app policy by name.


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
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Rules details | 


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
Add a new app policy.


#### Base Command

`sophos-firewall-app-policy-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| micro_app_support | Is microapp support enabled. Possible values are: true, false. | Optional | 
| default_action | Default action for the policy. Possible values are: Allow, Deny. | Optional | 
| select_all | Is the rule a select all rule. Possible values are: Enable, Disable. | Optional | 
| categories | Categories to add to the rule. | Optional | 
| risks | Risks to add to the rule. | Optional | 
| applications | Applications to add to the rule. | Optional | 
| characteristics | Characteristics to add to the rule. | Optional | 
| technologies | Technologies to add to the rule. | Optional | 
| classifications | Classifications to add to the rule. | Optional | 
| action | Action for the rule. Possible values are: Allow, Deny. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console. Possible values are: All the time, Work hours (5 Day week), Work hours (6 Day week), All Time on Weekdays, All Time on Weekends, All Time on Sunday, All Days 10:00 to 19:00. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Does the policy support microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Rules details | 


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
Update an existing app policy.


#### Base Command

`sophos-firewall-app-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| micro_app_support | Is microapp support enabled. Possible values are: true, false. | Optional | 
| default_action | Default action for the policy. Possible values are: Allow, Deny. | Optional | 
| select_all | Is the rule a select all rule. Possible values are: Enable, Disable. | Optional | 
| categories | Categories to add to the rule. | Optional | 
| risks | Risks to add to the rule. | Optional | 
| applications | Applications to add to the rule. | Optional | 
| characteristics | Characteristics to add to the rule. | Optional | 
| technologies | Technologies to add to the rule. | Optional | 
| classifications | Classifications to add to the rule. | Optional | 
| action | Action for the rule. Possible values are: Allow, Deny. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console. Possible values are: All the time, Work hours (5 Day week), Work hours (6 Day week), All Time on Weekdays, All Time on Weekends, All Time on Sunday, All Days 10:00 to 19:00. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.ApplicationFilterPolicy.Name | String | Name of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.Description | String | Description of the firewall app policy. | 
| SophosFirewall.ApplicationFilterPolicy.MicroAppSupport | String | Does the policy support microapps. | 
| SophosFirewall.ApplicationFilterPolicy.DefaultAction | String | Default action the policy executes. | 
| SophosFirewall.ApplicationFilterPolicy.RuleList.Rule | String | Rules details | 


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
Delete an existing app policy.


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
| SophosFirewall.ApplicationFilterPolicy.IsDeleted | String | Whether or not the firewall app policy is deleted. | 


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
List all app filter categories. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-app-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


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
Get a single app filter category by name.


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
Update an existing app filter category.


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
List all web filter policies. IMPORTANT: listing start at 0 (not 1!)


#### Base Command

`sophos-firewall-web-filter-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Provide the start index for the rules you would like to list. e.g: 5. Default is 0. | Optional | 
| end | Provide the end index for the rules you would like to list. e.g: 20. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Does the policy report events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Is the file size restriction active. | 
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
Get a single web filter policy by name.


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
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Does the policy report events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Is the file size restriction active. | 
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
Add a new web filter policy.


#### Base Command

`sophos-firewall-web-filter-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| default_action | Default action for the policy. Possible values are: Allow, Deny. | Required | 
| download_file_size_restriction_enabled | Should the max download file size be enabled. Possible values are: 0, 1. | Optional | 
| download_file_size_restriction | Max file size to enable downloading in MB. | Optional | 
| goog_app_domain_list_enabled | Enable to specify domains allowed to access google service. Possible values are: 0, 1. | Optional | 
| goog_app_domain_list | Specify domains allowed to access google service. | Optional | 
| youtube_filter_enabled | Enable YouTube Restricted Mode to restrict the content that is accessible. Possible values are: 0, 1. | Optional | 
| youtube_filter_is_strict | Adjust the policy used for YouTube Restricted Mode. Possible values are: 0, 1. | Optional | 
| enforce_safe_search | Enable to block websites containing pornography and explicit sexual content from appearing in the search results of Google, Yahoo, Bing search results. Possible values are: 0, 1. | Optional | 
| enforce_image_licensing | Further limit inappropriate content by enforcing search engine filters for Creative Commons licensed images. Possible values are: 0, 1. | Optional | 
| url_group_names | URL Groups to block\allow\warn\log. | Optional | 
| http_action | Choose action for http. Possible values are: Deny, Allow, Warn, Log. | Optional | 
| https_action | Choose action for https. Possible values are: Deny, Allow, Warn, Log. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console. Possible values are: All the time, Work hours (5 Day week), Work hours (6 Day week), All Time on Weekdays, All Time on Weekends, All Time on Sunday, All Days 10:00 to 19:00. | Optional | 
| policy_rule_enabled | Enable policy rule. Possible values are: 1, 0. | Optional | 
| user_names | Choose users which this rule will apply on. | Optional | 
| ccl_names | CCL names. REQUIRED: when ccl_rule_enabled is ON. | Optional | 
| ccl_rule_enabled | Enable CCL rule. IMPORTANT: if enabled - ccl_name is requierd. Possible values are: 1, 0. | Optional | 
| follow_http_action | Enable following HTTP action. Possible values are: 1, 0. | Optional | 
| enable_reporting | Select to enable reporting of policy. Possible values are: Enable, Disable. Default is Enable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Does the policy report events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Is the file size restriction active. | 
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
Update an existing web filter policy.


#### Base Command

`sophos-firewall-web-filter-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the policy. | Required | 
| description | Description of the policy. | Optional | 
| default_action | Default action for the policy. Possible values are: Allow, Deny. | Required | 
| download_file_size_restriction_enabled | Should the max download file size be enabled. Possible values are: 0, 1. | Optional | 
| download_file_size_restriction | Max file size to enable downloading in MB. | Optional | 
| goog_app_domain_list_enabled | Enable to specify domains allowed to access google service. Possible values are: 0, 1. | Optional | 
| goog_app_domain_list | Specify domains allowed to access google service. | Optional | 
| youtube_filter_enabled | Enable YouTube Restricted Mode to restrict the content that is accessible. Possible values are: 0, 1. | Optional | 
| youtube_filter_is_strict | Adjust the policy used for YouTube Restricted Mode. Possible values are: 0, 1. | Optional | 
| enforce_safe_search | Enable to block websites containing pornography and explicit sexual content from appearing in the search results of Google, Yahoo, Bing search results. Possible values are: 0, 1. | Optional | 
| enforce_image_licensing | Further limit inappropriate content by enforcing search engine filters for Creative Commons licensed images. Possible values are: 0, 1. | Optional | 
| url_group_names | URL Groups to block\allow\warn\log. | Optional | 
| http_action | Choose action for http. Possible values are: Deny, Allow, Warn, Log. | Optional | 
| https_action | Choose action for https. Possible values are: Deny, Allow, Warn, Log. | Optional | 
| schedule | Select Schedule for the Rule. IMPORTANT: Creating a new schedule is available on web console. Possible values are: All the time, Work hours (5 Day week), Work hours (6 Day week), All Time on Weekdays, All Time on Weekends, All Time on Sunday, All Days 10:00 to 19:00. | Optional | 
| policy_rule_enabled | Enable policy rule. Possible values are: 1, 0. | Optional | 
| user_names | Choose users which this rule will apply on. | Optional | 
| ccl_names | CCL names. REQUIRED: when ccl_rule_enabled is ON. | Optional | 
| ccl_rule_enabled | Enable CCL rule. IMPORTANT: if enabled - ccl_name is requierd. Possible values are: 1, 0. | Optional | 
| follow_http_action | Enable following HTTP action. Possible values are: 1, 0. | Optional | 
| enable_reporting | Select to enable reporting of policy. Possible values are: Enable, Disable. Default is Enable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosFirewall.WebFilterPolicy.Name | String | Name of the policy. | 
| SophosFirewall.WebFilterPolicy.DefaultAction | String | Default action for the web filter policy. | 
| SophosFirewall.WebFilterPolicy.Description | String | Description of the rule. | 
| SophosFirewall.WebFilterPolicy.EnableReporting | String | Does the policy report events. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestriction | Number | Maximum file size that can be downloaded. | 
| SophosFirewall.WebFilterPolicy.DownloadFileSizeRestrictionEnabled | String | Is the file size restriction active. | 
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
Delete an existing web filter policy.


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
| SophosFirewall.WebFilterPolicy.IsDeleted | String | Whether or not the policy was deleted. | 


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

