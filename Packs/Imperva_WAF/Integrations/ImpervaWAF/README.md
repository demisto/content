Use the Imperva WAF integration to manage IP groups and Web security policies in Imperva WAF.
This integration was integrated and tested with version 14.2 of Imperva WAF and based on Imperva On-Premises WAF (SecureSphere) REST API.
## Configure Imperva WAF in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### imperva-waf-ip-group-list
***
Get a list of existing IP Group names.


#### Base Command

`imperva-waf-ip-group-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.IpGroup.Name | String | The name of the IP Group | 


#### Command Example
```!imperva-waf-ip-group-list```

#### Context Example
```
{
    "ImpervaWAF": {
        "IpGroup": [
            {
                "Name": "All Search Engines"
            },
            {
                "Name": "FireEye Trusted Appliances"
            },
            {
                "Name": "Bad IP Adresses"
            },
            {
                "Name": "Google IP Addresses"
            }
        ]
    }
}
```

#### Human Readable Output

>### IP groups
>|Name|
>|---|
>| All Search Engines |
>| FireEye Trusted Appliances |
>| Bad IP Adresses |
>| Google IP Addresses |


### imperva-waf-ip-group-list-entries
***
Get a list of the entries in the requested IP group.


#### Base Command

`imperva-waf-ip-group-list-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip-group-name | The name of the IP Group | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.IpGroup.Entries.Type | String | Type of address \(Single, range or network\) | 
| ImpervaWAF.IpGroup.Entries.CidrMask | Number | Network significant bits | 
| ImpervaWAF.IpGroup.Entries.NetworkAddress | String | Network address | 
| ImpervaWAF.IpGroup.Entries.IpAddressTo | String | End IP address | 
| ImpervaWAF.IpGroup.Entries.IpAddressFrom | String | Start IP address | 


#### Command Example
```!imperva-waf-ip-group-list-entries ip-group-name=`Google IP Addresses````

#### Context Example
```
{
    "ImpervaWAF": {
        "IpGroup": {
            "Entries": [
                {
                    "CidrMask": null,
                    "IpAddressFrom": "1.2.3.4",
                    "IpAddressTo": "2.3.4.5",
                    "NetworkAddress": null,
                    "Type": "range"
                },
                {
                    "CidrMask": null,
                    "IpAddressFrom": "1.2.3.4",
                    "IpAddressTo": "2.3.4.5",
                    "NetworkAddress": null,
                    "Type": "range"
                },
                {
                    "CidrMask": null,
                    "IpAddressFrom": "2.3.4.5",
                    "IpAddressTo": "2.3.4.5",
                    "NetworkAddress": null,
                    "Type": "range"
                }
            ],
            "Name": "Google IP Addresses"
        }
    }
}
```

#### Human Readable Output

>### IP group entries for Google IP Addresses
>|Type|IpAddressFrom|IpAddressTo|
>|---|---|---|
>| range | 1.2.3.4 | 2.3.4.5 |
>| range | 1.2.3.4 | 2.3.4.5 |
>| range | 1.2.3.4 | 2.3.4.5 |


### imperva-waf-ip-group-remove-entries
***
Remove all the entries from an IP Group indicated by group name.


#### Base Command

`imperva-waf-ip-group-remove-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip-group-name | The name of the IP Group | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!imperva-waf-ip-group-remove-entries ip-group-name=`test_policy````

#### Context Example
```
{}
```

#### Human Readable Output

>The IP group test_policy is now empty

### imperva-waf-sites-list
***
Returns a list of the names of all sites in the system.


#### Base Command

`imperva-waf-sites-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.Site.Name | String | The name of the site | 


#### Command Example
```!imperva-waf-sites-list```

#### Context Example
```
{
    "ImpervaWAF": {
        "Site": {
            "Name": "Default Site"
        }
    }
}
```

#### Human Readable Output

>### All sites in the system
>|Name|
>|---|
>| Default Site |


### imperva-waf-server-group-list
***
Returns a list of all server group names under the site.


#### Base Command

`imperva-waf-server-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site-name | The name of the site | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.ServerGroup.Name | String | The name of the server group | 
| ImpervaWAF.ServerGroup.SiteName | String | The name of the parent site of the server groups to access | 


#### Command Example
```!imperva-waf-server-group-list site-name=`Default Site````

#### Context Example
```
{
    "ImpervaWAF": {
        "ServerGroup": {
            "Name": "Tel Aviv",
            "SiteName": "Default Site"
        }
    }
}
```

#### Human Readable Output

>### Server groups in Default Site
>|Name|SiteName|
>|---|---|
>| Tel Aviv | Default Site |


### imperva-waf-server-group-list-policies
***
Get server groups applied web security policies.


#### Base Command

`imperva-waf-server-group-list-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site-name | Site name | Required | 
| server-group-name | Server group name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.SecurityPolicy.PolicyName | String | Policy Name | 
| ImpervaWAF.SecurityPolicy.PolicyType | String | Policy type | 
| ImpervaWAF.SecurityPolicy.ServerGroup | String | Server group name | 
| ImpervaWAF.SecurityPolicy.SiteName | String | Site name | 
| ImpervaWAF.SecurityPolicy.System | Boolean | FI policy | 


#### Command Example
```!imperva-waf-server-group-list-policies site-name=`Default Site` server-group-name=`Tel Aviv````

#### Context Example
```
{
    "ImpervaWAF": {
        "SecurityPolicy": [
            {
                "PolicyName": "Network Protocol Violations Policy",
                "PolicyType": "NetworkProtocolViolations",
                "ServerGroup": "Tel Aviv",
                "SiteName": "Default Site",
                "System": true
            },
            {
                "PolicyName": "Firewall Policy",
                "PolicyType": "Firewall",
                "ServerGroup": "Tel Aviv",
                "SiteName": "Default Site",
                "System": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Policies for Tel Aviv
>|PolicyName|PolicyType|ServerGroup|SiteName|System|
>|---|---|---|---|---|
>| Network Protocol Violations Policy | NetworkProtocolViolations | Tel Aviv | Default Site | true |
>| Firewall Policy | Firewall | Tel Aviv | Default Site | true |


### imperva-waf-web-service-custom-policy-list
***
Returns a list of names of all Web Application Custom Policies in the system.


#### Base Command

`imperva-waf-web-service-custom-policy-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.CustomWebPolicy.Name | String | The name of the policy  | 


#### Command Example
```!imperva-waf-web-service-custom-policy-list```

#### Context Example
```
{
    "ImpervaWAF": {
        "CustomWebPolicy": [
            {
                "Name": "HTML Injection"
            },
            {
                "Name": "OS Commands injection"
            },
            {
                "Name": "Malicious File Upload"
            },
            {
                "Name": "ThreatRadar - Emergency - GET Requests"
            },
            {
                "Name": "ThreatRadar - Emergency - POST Requests"
            },
            {
                "Name": "ThreatRadar - Emergency - Authenticated Sessions"
            },
            {
                "Name": "Sensitive Error Messages Leakage"
            }
        ]
    }
}
```

#### Human Readable Output

>### Custom web policies
>|Name|
>|---|
>| HTML Injection |
>| OS Commands injection |
>| Malicious File Upload |
>| ThreatRadar - Emergency - GET Requests |
>| ThreatRadar - Emergency - POST Requests |
>| ThreatRadar - Emergency - Authenticated Sessions |
>| ThreatRadar - Emergency - Authenticated Sessions |
>| Sensitive Error Messages Leakage |


### imperva-waf-web-service-custom-policy-get
***
Returns a Web Application Custom Policy indicated by policy name.


#### Base Command

`imperva-waf-web-service-custom-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The name of the policy  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.CustomWebPolicy.Enabled | Boolean | Whether the policy is enabled | 
| ImpervaWAF.CustomWebPolicy.FollowedAction | String | Name of the Action Set | 
| ImpervaWAF.CustomWebPolicy.Name | String | The name of the policy | 
| ImpervaWAF.CustomWebPolicy.OneAlertPerSession | Boolean | Indicates whether to allow only one alert to be created for every web session | 
| ImpervaWAF.CustomWebPolicy.DisplayResponsePage | Boolean | Indicates whether to show response page in alerts | 
| ImpervaWAF.CustomWebPolicy.Action | String | Policy Action | 
| ImpervaWAF.CustomWebPolicy.Severity | String | Alert Severity | 
| ImpervaWAF.CustomWebPolicy.ApplyTo.serverGroupName | String | Name of the server group to apply | 
| ImpervaWAF.CustomWebPolicy.ApplyTo.siteName | String | Name of the site to apply | 
| ImpervaWAF.CustomWebPolicy.ApplyTo.webServiceName | String | Name of the web service to apply | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.operation | String | Match operation for values | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.type | String | Match Criterion name | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.ipGroups.Group name | String | Name of IP Group to search in | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.userDefined.IP Address | String | IP address to search in | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.values.country | String | Country name to match | 


#### Command Example
```!imperva-waf-web-service-custom-policy-get policy-name=`Suspicious File Extension Access````

#### Context Example
```
{
    "ImpervaWAF": {
        "CustomWebPolicy": {
            "Action": "none",
            "ApplyTo": [
                {
                    "serverGroupName": "Tel Aviv",
                    "siteName": "Default Site",
                    "webServiceName": "Orders"
                }
            ],
            "DisplayResponsePage": false,
            "Enabled": true,
            "FollowedAction": null,
            "MatchCriteria": [
                {
                    "operation": "atLeastOne",
                    "type": "httpRequestFileExtension",
                    "values": [
                        ".swp",
                        ".sqlite",
                        ".pem",
                        ".bp",
                        ".conf",
                        ".der",
                        ".ini",
                        ".git",
                        ".db",
                        ".svn",
                        ".core",
                        ".DS_Store",
                        ".raw",
                        ".dmp",
                        ".log",
                        ".pkcs12",
                        ".bak",
                        ".pfx.p12"
                    ]
                }
            ],
            "Name": "Suspicious File Extension Access",
            "OneAlertPerSession": false,
            "Severity": "high"
        }
    }
}
```

#### Human Readable Output

>### Policy data for Suspicious File Extension Access
>|Action|DisplayResponsePage|Enabled|Name|OneAlertPerSession|Severity|
>|---|---|---|---|---|---|
>| none | false | true | Suspicious File Extension Access | false | high |
>
>
>### Services to apply the policy to
>|serverGroupName|siteName|webServiceName|
>|---|---|---|
>| Tel Aviv | Default Site | Orders |


### imperva-waf-ip-group-create
***
Create an IP Group.


#### Base Command

`imperva-waf-ip-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group-name | Group name to create | Required | 
| entry-type | Type of address (Single, range or network) | Required | 
| ip-address-from | Start IP address, Mandatory for types: single, range | Optional | 
| ip-address-to | End IP address, Mandatory for type: range | Optional | 
| network-address | Network address, Mandatory for type: network | Optional | 
| cidr-mask | Network significant bits, Mandatory for type: network | Optional | 
| json-entries | List of entries values in json format, e.g. [{"type":"single","ipAddressFrom":"1.2.3.4"}] | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.IpGroup.Name | String | The name of the IP Group | 


#### Command Example
```!imperva-waf-ip-group-create group-name=`test_policy` entry-type=range ip-address-from=127.0.0.1 ip-address-to=127.0.0.2```

#### Context Example
```
{
    "ImpervaWAF": {
        "IpGroup": {
            "Name": "test_policy"
        }
    }
}
```

#### Human Readable Output

>Group test_policy created successfully

### imperva-waf-ip-group-update-entries
***
Add or remove rows in an IP Group indicated by ip Group Name.


#### Base Command

`imperva-waf-ip-group-update-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group-name | Group name to update | Required | 
| entry-type | Type of address (Single, range or network) | Required | 
| ip-address-from | Start IP address, Mandatory for types: single, range | Optional | 
| ip-address-to | End IP address, Mandatory for type: range | Optional | 
| network-address | Network address, Mandatory for type: network | Optional | 
| cidr-mask | Network significant bits, Mandatory for type: network | Optional | 
| operation | Operation to apply on the entry | Required | 
| json-entries | List of entries values in json format, e.g. [{"operation":"add","type":"single","ipAddressFrom":"1.2.3.4"}] | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!imperva-waf-ip-group-update-entries group-name=test_policy entry-type=range ip-address-from=10.0.0.1 ip-address-to=10.0.0.2 operation=add```

#### Context Example
```
{}
```

#### Human Readable Output

>Group test_policy updated successfully

### imperva-waf-ip-group-delete
***
Delete a IP Group indicated by group name.


#### Base Command

`imperva-waf-ip-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group-name | Group name to delete | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!imperva-waf-ip-group-delete group-name=test_policy```

#### Context Example
```
{}
```

#### Human Readable Output

>Group test_policy deleted successfully

### imperva-waf-web-service-custom-policy-create
***
Create a Web Service Custom Policy.


#### Base Command

`imperva-waf-web-service-custom-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The name of the policy to create | Required | 
| enabled | Whether the policy is enabled, Default: True | Optional | 
| severity | Alert Severity, Default: medium | Optional | 
| action | Policy Action, Default: none | Optional | 
| followed-action | Name of the Action Set | Optional | 
| one-alert-per-session | Indicates whether to allow only one alert to be created for every web session, Default: False | Optional | 
| display-response-page | Indicates whether to show the response page in alerts, Default: False | Optional | 
| site-name-to-apply | Name of the site to apply | Required | 
| server-group-name-to-apply | Name of the server group to apply | Required | 
| web-service-name-to-apply | Name of the web service to apply | Required | 
| geo-location-criteria-operation | Match operation for Source Geolocation  | Optional | 
| ip-groups | Comma separated list of names of IP Groups to search in | Optional | 
| ip-addresses | Comma separated list of IP addresses to search in | Optional | 
| country-names | Comma separated list of country names to search in, mandatory when geo-location-criteria-operation is set  | Optional | 
| ip-addresses-criteria-operation | Match operation for Source IP addresses  | Optional | 
| match-criteria-json | List of match criteria in json format, e.g. [{"type": "sourceIpAddresses","operation": "atLeastOne","userDefined": ["1.2.3.4"]}] | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ImpervaWAF.CustomWebPolicy.Enabled | Boolean | Indicates whether the policy is enabled. | 
| ImpervaWAF.CustomWebPolicy.FollowedAction | String | The name of the action set. | 
| ImpervaWAF.CustomWebPolicy.Name | String | The name of the policy. | 
| ImpervaWAF.CustomWebPolicy.OneAlertPerSession | Boolean | Indicates whether to allow only one alert to be created for every web session. | 
| ImpervaWAF.CustomWebPolicy.DisplayResponsePage | Boolean | Indicates whether to show the response page in the alerts. | 
| ImpervaWAF.CustomWebPolicy.Action | String | The custom web policy action. | 
| ImpervaWAF.CustomWebPolicy.Severity | String | The custom web policy alert severity. | 
| ImpervaWAF.CustomWebPolicy.ApplyTo.serverGroupName | String | The name of the server group to apply. | 
| ImpervaWAF.CustomWebPolicy.ApplyTo.siteName | String | The name of the site to apply. | 
| ImpervaWAF.CustomWebPolicy.ApplyTo.webServiceName | String | The name of the web service to apply. | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.operation | String | The match operation for values. | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.type | String | The match criterion name. | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.ipGroups.Group name | String | The name of the IP group in which to search. | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.userDefined.IP Address | String | The IP address in which to search. | 
| ImpervaWAF.CustomWebPolicy.MatchCriteria.values.country | String | Country name to match. | 


#### Command Example
```!imperva-waf-web-service-custom-policy-create policy-name=test_policy server-group-name-to-apply=`Tel Aviv` site-name-to-apply=`Default Site` web-service-name-to-apply=Orders followed-action=`Long IP Block````

#### Context Example
```
{}
```

#### Human Readable Output

>Policy test_policy created successfully

### imperva-waf-web-service-custom-policy-update
***
Update a Web Service Custom Policy.


#### Base Command

`imperva-waf-web-service-custom-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The name of the policy to update | Required | 
| enabled | Whether the policy is enabled | Optional | 
| severity | Alert Severity | Optional | 
| action | Policy Action | Optional | 
| followed-action | Name of the Action Set | Optional | 
| one-alert-per-session | Indicates whether to allow only one alert to be created for every web session | Optional | 
| display-response-page | Indicates whether to show the response page in alerts | Optional | 
| site-name-to-apply | Name of the site to apply | Optional | 
| server-group-name-to-apply | Name of the server group to apply | Optional | 
| web-service-name-to-apply | Name of the web service to apply | Optional | 
| geo-location-criteria-operation | Match operation for Source Geolocation | Optional | 
| ip-groups | Comma separated list of names of IP Groups to search in | Optional | 
| ip-addresses | Comma separated list of IP addresses to search in | Optional | 
| country-names | Comma separated list of country names to search in, mandatory when geo-location-criteria-operation is set | Optional | 
| ip-addresses-criteria-operation | Match operation for Source IP addresses | Optional | 
| apply-operation | Operation to apply | Optional | 
| match-criteria-json | List of match criteria in json format, e.g. [{"type":"sourceIpAddresses","operation":"atLeastOne","userDefined":["1.2.3.4"]}] | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!imperva-waf-web-service-custom-policy-update policy-name=test_policy enabled=False```

#### Context Example
```
{}
```

#### Human Readable Output

>Policy test_policy updated successfully

### imperva-waf-web-service-custom-policy-delete
***
Delete a Web Service Custom Policy indicated by policy name.


#### Base Command

`imperva-waf-web-service-custom-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The name of the policy to delete | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!imperva-waf-web-service-custom-policy-delete policy-name=`test_policy````

#### Context Example
```
{}
```

#### Human Readable Output

>Policy test_policy deleted successfully