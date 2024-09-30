Automate your AppID Adoption by using this integration together with your Palo Alto Networks Next-Generation Firewall or Panorama.
This integration was integrated and tested with version 8 up to version 10.1.6 and version 10.2.0 of PAN-OS Policy Optimizer.
Moved to beta due to the lack of a formal API.

## Configure PAN-OS Policy Optimizer (Beta) in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://192.168.0.1:443) | True |
| Username | True |
| Password | True |
| Vsys - Firewall instances only | False |
| Device Group - Panorama instances only | False |
| PAN-OS Version (The exact version, e.g., 10.1.4, 1.1, 9) | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### pan-os-po-get-stats

***
Gets the Policy Optimizer statistics.

#### Base Command

`pan-os-po-get-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| position | Whether to get pre-rules statistics or post-rules statistics. 'pre' for pre rules, 'post' for post-rules. Only for Panorama instances. Possible values are: pre, post. Default is pre. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.Stats.no_app_specified | Number | Number of rules with no apps specified. | 
| PanOS.PolicyOptimizer.Stats.unused | Number | Number of unused security policies. | 
| PanOS.PolicyOptimizer.Stats.unused_apps | Number | Number of unused apps in security policies. | 
| PanOS.PolicyOptimizer.Stats.unused_in_30_days | Number | Number of unused security policies in 30 days. | 
| PanOS.PolicyOptimizer.Stats.unused_in_90_days | Number | Number of unused security policies in 90 days. | 


#### Command Example
```!pan-os-po-get-stats```

#### Context Example
```json
{
    "PanOS": {
        "PolicyOptimizer": {
            "Stats": {
                "no_app_specified": "1",
                "unused": "8",
                "unused_apps": "0",
                "unused_in_30_days": "13",
                "unused_in_90_days": "12"
            }
        }
    }
}
```

#### Human Readable Output

>### Policy Optimizer Statistics:
>|@name|text|
>|---|---|
>| no_app_specified | 1 |
>| unused_apps | 0 |
>| unused_in_30_days | 13 |
>| unused_in_90_days | 12 |
>| unused | 8 |


### pan-os-po-no-apps

***
Shows all security policies with no apps specified.

#### Base Command

`pan-os-po-no-apps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| position | Whether to get pre-rules with no apps or post-rules with no apps. 'pre' for pre rules, 'post' for post-rules. Only for Panorama instances. Possible values are: pre, post. Default is pre. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.NoApps | Unknown | Contains information about the rules that have no apps specified. For example, Source and Destination. | 


#### Command Example
```!pan-os-po-no-apps```

#### Context Example
```json
{
    "PanOS": {
        "PolicyOptimizer": {
            "NoApps": {
                "@__recordInfo": "{\"permission\":\"readonly\",\"xpathId\":\"panorama\",\"vsysName\":\"vsys1\",\"position\":\"pre\"}",
                "@loc": "Lab-Devices",
                "@name": "pano_rule",
                "@panorama": "true",
                "@uuid": "uuid",
                "action": "allow",
                "application": {
                    "member": [
                        "any"
                    ]
                },
                "apps-allowed-count": "0",
                "apps-seen-count": "72",
                "bytes": "84800223916",
                "category": {
                    "member": [
                        "any"
                    ]
                },
                "days-no-new-app-count": "193",
                "description": "a test rule for the move function",
                "destination": {
                    "member": [
                        "any"
                    ]
                },
                "first-hit-timestamp": "1602403843",
                "from": {
                    "member": [
                        "any"
                    ]
                },
                "hip-profiles": {
                    "member": [
                        "any"
                    ]
                },
                "hit-count": "32193134",
                "last-app-seen-since-count": "193",
                "last-hit-timestamp": "1602468975",
                "last-reset-timestamp": "0",
                "rule-creation-timestamp": "1575916248",
                "rule-modification-timestamp": "1614045009",
                "service": {
                    "member": [
                        "application-default"
                    ]
                },
                "source": {
                    "member": [
                        "any"
                    ]
                },
                "source-user": {
                    "member": [
                        "any"
                    ]
                },
                "to": {
                    "member": [
                        "any"
                    ]
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Policy Optimizer No App Specified:
>|@name|@uuid|action|description|source|destination|
>|---|---|---|---|---|---|
>| pano_rule | uuid | allow | a test rule for the move function | member: any | member: any |



### pan-os-po-unused-apps

***
Gets the unused apps.

#### Base Command

`pan-os-po-unused-apps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| position | Whether to get pre-rules unused apps or post-rules unused apps. 'pre' for pre rules, 'post' for post-rules. Only for Panorama instances. Possible values are: pre, post. Default is pre. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.UnusedApps | String | Shows all security rules with unused apps. | 

### pan-os-po-get-rules

***
Gets unused, used, or any rules.

#### Base Command

`pan-os-po-get-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeframe | The time frame in days to show the unused rules. Default is 30. | Optional | 
| usage | Rule usage type to filter by. Can be Unused, Used, or Any. Possible values are: Unused, Used, Any. Default is Unused. | Optional | 
| exclude | Whether to exclude rules reset during the last x days, where x is the value defined in the timeframe argument. It will not exclude rules by default. Possible values are: false, true. Default is false. | Optional | 
| position | Whether to get pre-rules, post-rules or both. 'pre' for pre rules, 'post' for post-rules, only for panorama instances. Possible values are: pre, post, both. Default is both. | Optional | 
| rule_type | Which type of rules to query. Possible values are: security, nat, qos, pbf, decryption, tunnel-inspect, application-override, authentication, dos, sdwan. Default is security. | Optional | 
| limit | The maximum number of rules to return. Default is 200. | Optional | 
| page_size | The amount of items to return in each paginated call. Can only be a value of up to 200. Default is 200. | Optional | 
| page | A specific pagination page to get items from. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.UnusedRules | String | Shows all unused security rules. | 
| PanOS.PolicyOptimizer.AnyRules | String | Shows all security rules. | 
| PanOS.PolicyOptimizer.UsedRules | String | Shows all used security rules. | 


#### Command Example
```!pan-os-po-get-rules usage=Any```

#### Context Example
```json
{
    "PanOS": {
        "PolicyOptimizer": {
            "AnyRules": [
                {
                    "@__recordInfo": "{\"permission\":\"readonly\",\"xpathId\":\"panorama\",\"vsysName\":\"vsys1\",\"position\":\"pre\"}",
                    "@loc": "Lab-Devices",
                    "@name": "tip rule",
                    "@panorama": "true",
                    "@uuid": "uuid",
                    "action": "allow",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "category": {
                        "member": [
                            "any"
                        ]
                    },
                    "days-no-new-app-count": [],
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hip-profiles": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "rule-creation-timestamp": "1575925916",
                    "rule-modification-timestamp": "1614045009",
                    "service": {
                        "member": [
                            "application-default"
                        ]
                    },
                    "source": {
                        "member": [
                            "tip"
                        ]
                    },
                    "source-user": {
                        "member": [
                            "any"
                        ]
                    },
                    "to": {
                        "member": [
                            "any"
                        ]
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### PolicyOptimizer AnyRules:
>|@name|@uuid|action|description|source|destination|
>|---|---|---|---|---|---|
>| tip rule | uuid | allow |  | member: tip | member: any |


### pan-os-po-app-and-usage

***
Gets the app usage statistics for a specific security rule.

#### Base Command

`pan-os-po-app-and-usage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_uuid | The UUID of the security rule. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.AppsAndUsage | Unknown | Shows detailed app usage statistics for specific security rules. | 


#### Command Example
```!pan-os-po-app-and-usage rule_uuid=uuid```

#### Human Readable Output

>Rule with UUID:{uuid} does not use apps.

### pan-os-get-dag

***
Gets a specific dynamic address group.

#### Base Command

`pan-os-get-dag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dag | Dynamic address group name. | Required | 

#### Context Output

There is no context output for this command.