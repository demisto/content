Automate your AppID Adoption by using this integration together with your Palo Alto Networks Next-Generation Firewall or Panorama.
This integration was integrated and tested with version 8 up to version 10.1.6 and version 10.2.0 of PAN-OS Policy Optimizer.
Moved to beta due to the lack of a formal API.

## Configure PAN-OS Policy Optimizer (Beta) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PAN-OS Policy Optimizer (Beta).
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### pan-os-po-get-stats

***
Gets the Policy Optimizer statistics.

#### Base Command

`pan-os-po-get-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| position | Whether to get pre-rules statistics, post-rules statistics. 'pre' for pre rules, 'post' for post-rules, only for panorama instances. Possible values are: pre, post. Default is pre. | Optional | 

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
```!pan-os-po-get-stats```
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
>| new_apps_detected | yes |
>| unused_in_30_days | 3 |
>| unused_in_90_days | 3 |
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
| position | Whether to get pre-rules, post-rules. 'pre' for pre rules, 'post' for post-rules, only for panorama instances. Possible values are: pre, post. Default is pre. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PanOS.PolicyOptimizer.NoApps | Unknown | Contains information about the rules that have no apps specified. For example, Source and Destination. | 

#### Command example
```!pan-os-po-no-apps```
#### Context Example
```json
{
    "PanOS": {
        "PolicyOptimizer": {
            "NoApps": [
                {
                    "@__recordInfo": "{\"permission\":\"readonly\",\"xpathId\":\"panorama\",\"vsysName\":\"vsys1\",\"position\":\"pre\"}",
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
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "log-start": "yes",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "profile-setting": {
                        "profiles": {
                            "spyware": {
                                "member": [
                                    "Tap"
                                ]
                            },
                            "virus": {
                                "member": [
                                    "Tap"
                                ]
                            },
                            "vulnerability": {
                                "member": [
                                    "test-do-not-delete"
                                ]
                            }
                        }
                    },
                    "qos": {
                        "marking": {
                            "ip-precedence": "cs2"
                        }
                    },
                    "rule-creation-timestamp": "1669113453",
                    "rule-modification-timestamp": "1688644363",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "192.168.1.60",
                            "192.168.1.68",
                            "192.168.1.69"
                        ]
                    },
                    "source-hip": {
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-2b2673c5",
                    "@uuid": "d539af24-6156-4f1c-b9fb-be9a00f55901",
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
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "destination-hip": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "profile-setting": {
                        "profiles": {
                            "spyware": {
                                "member": [
                                    "test-dont-delete"
                                ]
                            },
                            "url-filtering": {
                                "member": [
                                    "Test for Elia"
                                ]
                            },
                            "virus": {
                                "member": [
                                    "Tap"
                                ]
                            },
                            "vulnerability": {
                                "member": [
                                    "test-do-not-delete"
                                ]
                            }
                        }
                    },
                    "rule-creation-timestamp": "1669113453",
                    "rule-modification-timestamp": "1676451430",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "192.168.1.69"
                        ]
                    },
                    "source-hip": {
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-03da261a",
                    "@uuid": "5e08e1bb-d2ab-4921-9d55-9957c123777a",
                    "action": "allow",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "any",
                    "destination": {
                        "member": [
                            "192.168.1.255",
                            "2.2.2.2"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1669113453",
                    "rule-modification-timestamp": "1669113453",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "192.168.1.69"
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-649d28f9",
                    "@uuid": "9dd4484f-2d55-4bff-bb0f-b08408975220",
                    "action": "allow",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1669113453",
                    "rule-modification-timestamp": "1669113453",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "1.1.1.1"
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-05a7b898",
                    "@uuid": "42a768d0-ebda-4d9f-ab8f-27bc0d20f357",
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
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "destination-hip": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "profile-setting": {
                        "profiles": {
                            "spyware": {
                                "member": [
                                    "test"
                                ]
                            },
                            "url-filtering": {
                                "member": [
                                    "default"
                                ]
                            },
                            "virus": {
                                "member": [
                                    "Tap"
                                ]
                            },
                            "vulnerability": {
                                "member": [
                                    "test-do-not-delete"
                                ]
                            }
                        }
                    },
                    "rule-creation-timestamp": "1669113453",
                    "rule-modification-timestamp": "1688644363",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "1.1.1.1",
                            "192.168.1.69"
                        ]
                    },
                    "source-hip": {
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "test-do-not-delete",
                    "@uuid": "d3c43d2e-fac7-4052-9e5b-17fed601abd9",
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
                    "description": "sdfdf",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "destination-hip": {
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
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "profile-setting": {
                        "profiles": {
                            "spyware": {
                                "member": [
                                    "test-dont-delete"
                                ]
                            },
                            "virus": {
                                "member": [
                                    "Tap"
                                ]
                            },
                            "vulnerability": {
                                "member": [
                                    "test-do-not-delete"
                                ]
                            }
                        }
                    },
                    "rule-creation-timestamp": "1676451430",
                    "rule-modification-timestamp": "1676451430",
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
                    "source-hip": {
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-e435c6b4",
                    "@uuid": "e2e924a3-578a-415b-8c63-fef1de7bb76a",
                    "action": "deny",
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
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "destination-hip": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "1688679305",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "794522",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "1690268399",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "profile-setting": {
                        "profiles": []
                    },
                    "rule-creation-timestamp": "1688644363",
                    "rule-modification-timestamp": "1688644363",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "any"
                        ]
                    },
                    "source-hip": {
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "block_bad_application",
                    "@uuid": "4c0d6d7c-9991-4340-9b9c-dd139a34acf5",
                    "action": "allow",
                    "application": {
                        "member": [
                            "fortnite"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "do not play at work",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1688644363",
                    "rule-modification-timestamp": "1688644363",
                    "service": {
                        "member": [
                            "any"
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
                    "tag": {
                        "member": [
                            "danil_test"
                        ]
                    },
                    "to": {
                        "member": [
                            "any"
                        ]
                    }
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-29c43421",
                    "@uuid": "18e7e41f-219a-492f-bfe7-c166fac1f3da",
                    "action": "allow",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1688644363",
                    "rule-modification-timestamp": "1688644363",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "any"
                        ]
                    },
                    "to": {
                        "member": [
                            "any"
                        ]
                    }
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-54f0f718",
                    "@uuid": "147a6fb5-b2ab-41af-a9ea-cfe639fe89ec",
                    "action": "drop",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1689241866",
                    "rule-modification-timestamp": "1689241866",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "any"
                        ]
                    },
                    "tag": [],
                    "to": {
                        "member": [
                            "any"
                        ]
                    }
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "demisto-5ca1b8ed",
                    "@uuid": "6e3ffa4b-9454-4f26-bd1c-7481b00da290",
                    "action": "allow",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1689241866",
                    "rule-modification-timestamp": "1689241866",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "any"
                        ]
                    },
                    "tag": [],
                    "to": {
                        "member": [
                            "any"
                        ]
                    }
                },
                {
                    "@__recordInfo": "{\"permission\":\"readwrite\",\"xpathId\":\"vsys\",\"vsysName\":\"vsys1\",\"position\":\"main\"}",
                    "@name": "michaltest",
                    "@uuid": "50901929-e740-46ba-9445-c4aac50ab1d9",
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
                    "destination-hip": {
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
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "rule-creation-timestamp": "1689241866",
                    "rule-modification-timestamp": "1689242166",
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
                    "source-hip": {
                        "member": [
                            "any"
                        ]
                    },
                    "source-user": {
                        "member": [
                            "any"
                        ]
                    },
                    "tag": [],
                    "to": {
                        "member": [
                            "any"
                        ]
                    }
                },
                {
                    "@__recordInfo": "{\"permission\":\"readonly\",\"xpathId\":\"panorama\",\"vsysName\":\"vsys1\",\"position\":\"post\"}",
                    "@loc": "SA_FWs",
                    "@name": "demisto-2b2e9e73",
                    "@panorama": "true",
                    "@uuid": "79310671-9d19-4b0b-a77d-70cc335b7756",
                    "action": "drop",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "any",
                    "destination": {
                        "member": [
                            "any"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1669113453",
                    "rule-modification-timestamp": "1689521856",
                    "service": {
                        "member": [
                            "service-https"
                        ]
                    },
                    "source": {
                        "member": [
                            "192.168.1.1"
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readonly\",\"xpathId\":\"panorama\",\"vsysName\":\"vsys1\",\"position\":\"post\"}",
                    "@loc": "SA_FWs",
                    "@name": "demisto-c6c9535b",
                    "@panorama": "true",
                    "@uuid": "c760fbd7-8cd9-41f8-a5a2-019611234636",
                    "action": "drop",
                    "application": {
                        "member": [
                            "any"
                        ]
                    },
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "description": "any",
                    "destination": {
                        "member": [
                            "0.0.0.0"
                        ]
                    },
                    "disabled": "no",
                    "first-hit-timestamp": "0",
                    "from": {
                        "member": [
                            "any"
                        ]
                    },
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "negate-destination": "no",
                    "negate-source": "no",
                    "option": {
                        "disable-server-response-inspection": "no"
                    },
                    "rule-creation-timestamp": "1669113453",
                    "rule-modification-timestamp": "1689521856",
                    "service": {
                        "member": [
                            "any"
                        ]
                    },
                    "source": {
                        "member": [
                            "8.8.8.8"
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
                },
                {
                    "@__recordInfo": "{\"permission\":\"readonly\",\"xpathId\":\"predefined\",\"position\":\"default-security-rule\"}",
                    "@name": "intrazone-default",
                    "@uuid": "11111111-1111-1111-1111-111111111111",
                    "action": "allow",
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "first-hit-timestamp": "0",
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "log-end": "no",
                    "log-start": "no",
                    "rule-creation-timestamp": "1689521994",
                    "rule-modification-timestamp": "1689521994"
                },
                {
                    "@__recordInfo": "{\"permission\":\"readonly\",\"xpathId\":\"predefined\",\"position\":\"default-security-rule\"}",
                    "@name": "interzone-default",
                    "@uuid": "22222222-2222-2222-2222-222222222222",
                    "action": "deny",
                    "apps-allowed-count": "0",
                    "apps-seen-count": "0",
                    "bytes": "0",
                    "days-no-new-app-count": [],
                    "first-hit-timestamp": "0",
                    "hit-count": "0",
                    "last-app-seen-since-count": [],
                    "last-hit-timestamp": "0",
                    "last-reset-timestamp": "0",
                    "log-end": "no",
                    "log-start": "no",
                    "rule-creation-timestamp": "1689521994",
                    "rule-modification-timestamp": "1689521994"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### PolicyOptimizer Any-security-rules:
>|@name|@uuid|action|description|source|destination|
>|---|---|---|---|---|---|
>| demisto-2b2e9e73 | 79310671-9d19-4b0b-a77d-70cc335b7756 | drop | any | member: 192.168.1.1 | member: any |
>| demisto-c6c9535b | c760fbd7-8cd9-41f8-a5a2-019611234636 | drop | any | member: 8.8.8.8 | member: 0.0.0.0 |
>| tomertest | c7b643e4-c352-4695-9d1c-455cdf37f281 | allow | any | member: 1.1.1.1 | member: 192.168.1.69 |
>| Allow rule | 6305c948-ef98-4ed4-8d9c-aa7c1757957b | drop |  | member: 192.168.1.69 | member: 8.8.8.8 |
>| block rule | 5dbf79a1-fe98-4f64-aa39-d2da3c005a7f | drop |  | member: 1.1.1.1,<br/>8.8.4.4,<br/>8.8.8.8 | member: 192.168.1.69,<br/>192.168.1.70 |
>| log forwarding - DO NOT REMOVE OR MODIFY | b817149f-7dc8-41dd-88d9-704a830c28ff | allow |  | member: any | member: any |
>| demisto-b8bdcd28 | 3b528a4c-79c2-4370-9a25-a426a446da2e | drop | any | member: 1.1.1.1,<br/>8.8.8.8 | member: 192.168.1.60,<br/>192.168.1.65 |


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

#### Command example
```!pan-os-po-app-and-usage rule_uuid=4083c547-51b2-4f69-952b-5bbc50ddafde```
#### Context Example
```json
{
    "PanOS": {
        "PolicyOptimizer": {
            "AppsAndUsage": [
                {
                    "@name": "Tap",
                    "@uuid": "4083c547-51b2-4f69-952b-5bbc50ddafde",
                    "apps-allowed-count": "0",
                    "apps-seen": {
                        "entry": [
                            {
                                "application": "capwap",
                                "bytes": "0",
                                "first-seen": "1684566000",
                                "last-seen": "1684566000"
                            },
                            {
                                "application": "cgiproxy",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1685257200"
                            },
                            {
                                "application": "dns-base",
                                "bytes": "11183665",
                                "first-seen": "1676880000",
                                "last-seen": "1690268400"
                            },
                            {
                                "application": "hamachi",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "http-proxy",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "ldap",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "llmnr",
                                "bytes": "538450",
                                "first-seen": "1676880000",
                                "last-seen": "1690268400"
                            },
                            {
                                "application": "ms-rdp",
                                "bytes": "458",
                                "first-seen": "1676880000",
                                "last-seen": "1688540400"
                            },
                            {
                                "application": "mssql-db-unencrypted",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "ntp-base",
                                "bytes": "470700",
                                "first-seen": "1676880000",
                                "last-seen": "1688972400"
                            },
                            {
                                "application": "ntp-non-rfc",
                                "bytes": "1350990",
                                "first-seen": "1676966400",
                                "last-seen": "1688972400"
                            },
                            {
                                "application": "outlook-web",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "sap",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "sip",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "smtp-base",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "snmp-base",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "soap",
                                "bytes": "316167",
                                "first-seen": "1676880000",
                                "last-seen": "1689750000"
                            },
                            {
                                "application": "ssh",
                                "bytes": "15132087",
                                "first-seen": "1677052800",
                                "last-seen": "1690268400"
                            },
                            {
                                "application": "ssl",
                                "bytes": "135058094005",
                                "first-seen": "1676880000",
                                "last-seen": "1690268400"
                            },
                            {
                                "application": "stun",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "symantec-endpoint-manager",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "syslog",
                                "bytes": "8667219",
                                "first-seen": "1678690800",
                                "last-seen": "1690268400"
                            },
                            {
                                "application": "t.120",
                                "bytes": "0",
                                "first-seen": "1680159600",
                                "last-seen": "1680159600"
                            },
                            {
                                "application": "teredo",
                                "bytes": "14821084",
                                "first-seen": "1676880000",
                                "last-seen": "1690268400"
                            },
                            {
                                "application": "tftp",
                                "bytes": "0",
                                "first-seen": "1678089600",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "traceroute",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "vmware",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "vnc-http",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "web-browsing",
                                "bytes": "213916542",
                                "first-seen": "1676880000",
                                "last-seen": "1690268400"
                            },
                            {
                                "application": "webdav",
                                "bytes": "0",
                                "first-seen": "1678003200",
                                "last-seen": "1686207600"
                            },
                            {
                                "application": "websocket",
                                "bytes": "0",
                                "first-seen": "1678690800",
                                "last-seen": "1678690800"
                            },
                            {
                                "application": "ws-discovery",
                                "bytes": "83080",
                                "first-seen": "1676880000",
                                "last-seen": "1689145200"
                            }
                        ]
                    },
                    "days-no-new-app-count": "66",
                    "last-app-seen-since-count": "0"
                },
                    "days-no-new-app-count": "117",
                    "last-app-seen-since-count": "0"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Policy Optimizer Apps and Usage:
>|@name|@uuid|apps-allowed-count|apps-seen|days-no-new-app-count|last-app-seen-since-count|
>|---|---|---|---|---|---|
>| Tap | 4083c547-51b2-4f69-952b-5bbc50ddafde | 0 | entry: {'application': 'capwap', 'bytes': '0', 'first-seen': '1673251200', 'last-seen': '1684566000'},<br/>{'application': 'cgiproxy', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'cti-camp-base', 'bytes': '0', 'first-seen': '1672128000', 'last-seen': '1675324800'},<br/>{'application': 'df1-base', 'bytes': '0', 'first-seen': '1675324800', 'last-seen': '1675929600'},<br/>{'application': 'dns-base', 'bytes': '11616572', 'first-seen': '1669104000', 'last-seen': '1690268400'},<br/>{'application': 'echonet-lite-base', 'bytes': '0', 'first-seen': '1669190400', 'last-seen': '1672128000'},<br/>{'application': 'hamachi', 'bytes': '0', 'first-seen': '1676361600', 'last-seen': '1686207600'},<br/>{'application': 'http-proxy', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'ldap', 'bytes': '0', 'first-seen': '1676361600', 'last-seen': '1686207600'},<br/>{'application': 'llmnr', 'bytes': '550748', 'first-seen': '1670745600', 'last-seen': '1690268400'},<br/>{'application': 'lontalk-base', 'bytes': '0', 'first-seen': '1676534400', 'last-seen': '1676534400'},<br/>{'application': 'ms-rdp', 'bytes': '458', 'first-seen': '1669104000', 'last-seen': '1688540400'},<br/>{'application': 'mssql-db-unencrypted', 'bytes': '0', 'first-seen': '1671955200', 'last-seen': '1686207600'},<br/>{'application': 'ntp', 'bytes': '0', 'first-seen': '1669104000', 'last-seen': '1676534400'},<br/>{'application': 'ntp-base', 'bytes': '511290', 'first-seen': '1676534400', 'last-seen': '1688972400'},<br/>{'application': 'ntp-non-rfc', 'bytes': '1471590', 'first-seen': '1671955200', 'last-seen': '1686207600'},<br/>{'application': 'snmp-base', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'soap', 'bytes': '316167', 'first-seen':  '1669104000', 'last-seen': '1690268400'},<br/>{'application': 'ssl', 'bytes': '14589324827', 'first-seen': '1669104000', 'last-seen': '1690268400'},<br/>{'application': 'stun', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'symantec-endpoint-manager', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'syslog', 'bytes': '8897364', 'first-seen': '1671955200', 'last-seen': '1690268400'},<br/>{'application': 't.120', 'bytes': '0', 'first-seen': '1680159600', 'last-seen': '1680159600'},<br/>{'application': 'teredo', 'bytes': '15052376', 'first-seen': '1669104000', 'last-seen': '1690268400'},<br/>{'application': 'tftp', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'traceroute', 'bytes': '0', 'first-seen': '1678003200', 'last-seen': '1686207600'},<br/>{'application': 'vmware', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'vnc-http', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'web-browsing', 'bytes': '238536649', 'first-seen': '1669104000', 'last-seen': '1690268400'},<br/>{'application': 'webdav', 'bytes': '0', 'first-seen': '1676448000', 'last-seen': '1686207600'},<br/>{'application': 'websocket', 'bytes': '0', 'first-seen': '1677052800', 'last-seen': '1678690800'},<br/>{'application': 'ws-discovery', 'bytes': '83080', 'first-seen': '1669536000', 'last-seen': '1689145200'} | 117 | 0 |


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

#### Command Example
``` ```

#### Human Readable Output


