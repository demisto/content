Forcepoint Data Loss Prevention (DLP) enables businesses to discover, classify, monitor, and protect data intuitively with zero friction to the user experience. Audit behavior in real-time with Risk-Adaptive Protection to stop data loss before it occurs.
This integration was integrated and tested with version xx of ForcePointDLP.

## Configure ForcePoint DLP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ForcePoint DLP.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://192.168.0.1) |  | True |
    | Port |  | True |
    | Username |  | True |
    | Password |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | First fetch timestamp | Timestamp in ISO format or &lt;number&gt; &lt;time unit&gt;, e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | True |
    | Maximum incidents per fetch |  | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### forcepoint-dlp-get-events

***
Gets events from Forcepoint DLP.

#### Base Command

`forcepoint-dlp-get-events`

#### Input

| **Argument Name**  | **Description**                                                                                                                      | **Default** | **Required** |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------|-------------|--------------|
| limit              | The number of events to return.                                                                                                      | 10          | Optional     |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. | false       | Required     |

#### Context Output

There is no context output for this command.


### fp-dlp-policy-list

***
List the names of all enabled policies displayed in the 'Manage DLP and Discovery Policies' section.

#### Base Command

`fp-dlp-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Specifies the type of policies to retrieve, such as DLP or DISCOVERY. Possible values are: DLP, DISCOVERY. Default is DLP. | Optional |
| all_results | Indicates whether to retrieve all results by overriding the default limit. Use 'true' to fetch all results or 'false' to respect the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. If 'all_results' is set to true, this field is ignored. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointDlp.Policy.name | String | The name of the enabled policy. |

#### Command example
```!fp-dlp-policy-list```
#### Context Example
```json
{
    "ForcepointDlp": {
        "Policy": [
            {
                "name": "Email DLP Policy"
            },
            {
                "name": "Web DLP Policy"
            },
            {
                "name": "cvxcvx"
            },
            {
                "name": "hard"
            },
            {
                "name": "CV and Resume in English"
            },
            {
                "name": "Private Keys"
            },
            {
                "name": "Problem Gambling"
            },
            {
                "name": "South Africa POPI"
            },
            {
                "name": "Security Software Files"
            },
            {
                "name": "Self CV or Resume Distribution"
            },
            {
                "name": "South Africa ECT Act"
            },
            {
                "name": "Senegal PII"
            },
            {
                "name": "South Africa PII"
            },
            {
                "name": "Acceptable Use - Obscenities and Racism"
            },
            {
                "name": "Smart Power Grids or SCADA"
            },
            {
                "name": "License Keys"
            },
            {
                "name": "Suspected Mail to Self"
            },
            {
                "name": "Suspected Malicious Dissemination"
            },
            {
                "name": "Bids and Tenders"
            },
            {
                "name": "Location coordinates"
            },
            {
                "name": "Business and Technical Drawings Files"
            },
            {
                "name": "Confidential Warning"
            },
            {
                "name": "Confidential Warning (Arabic)"
            },
            {
                "name": "Suspected Malware Communication Detection"
            },
            {
                "name": "Uganda PII"
            },
            {
                "name": "CV and Resume in French"
            },
            {
                "name": "Mergers and acquisitions"
            },
            {
                "name": "Credit Cards"
            },
            {
                "name": "Credit Cards for Printer Agent"
            },
            {
                "name": "Credit Card Magnetic Strips"
            },
            {
                "name": "Database Dumps or Backup Files"
            },
            {
                "name": "Database Files"
            },
            {
                "name": "Unknown File Formats Over Time"
            },
            {
                "name": "Cyber Bullying and Self Destructive Patterns"
            },
            {
                "name": "User Traffic Over Time"
            },
            {
                "name": "Digitally Signed PDF Files"
            },
            {
                "name": "Data Sent During Unusual Hours"
            },
            {
                "name": "Deep Web URLs"
            },
            {
                "name": "Email to Competitors"
            },
            {
                "name": "Email Addresses"
            },
            {
                "name": "Encrypted Files"
            },
            {
                "name": "Disgruntled Employee"
            },
            {
                "name": "Nigeria PII"
            },
            {
                "name": "Password Dissemination"
            },
            {
                "name": "Password files"
            },
            {
                "name": "Petroleum and Gas-Sensitive Information"
            },
            {
                "name": "PCI"
            },
            {
                "name": "PCI Audit"
            },
            {
                "name": "Files Containing Macros"
            },
            {
                "name": "beni"
            }
        ]
    }
}
```

#### Human Readable Output

>### Policies List:
>|Name|
>|---|
>| Email DLP Policy |
>| Web DLP Policy |
>| cvxcvx |
>| hard |
>| CV and Resume in English |
>| Private Keys |
>| Problem Gambling |
>| South Africa POPI |
>| Security Software Files |
>| Self CV or Resume Distribution |
>| South Africa ECT Act |
>| Senegal PII |
>| South Africa PII |
>| Acceptable Use - Obscenities and Racism |
>| Smart Power Grids or SCADA |
>| License Keys |
>| Suspected Mail to Self |
>| Suspected Malicious Dissemination |
>| Bids and Tenders |
>| Location coordinates |
>| Business and Technical Drawings Files |
>| Confidential Warning |
>| Confidential Warning (Arabic) |
>| Suspected Malware Communication Detection |
>| Uganda PII |
>| CV and Resume in French |
>| Mergers and acquisitions |
>| Credit Cards |
>| Credit Cards for Printer Agent |
>| Credit Card Magnetic Strips |
>| Database Dumps or Backup Files |
>| Database Files |
>| Unknown File Formats Over Time |
>| Cyber Bullying and Self Destructive Patterns |
>| User Traffic Over Time |
>| Digitally Signed PDF Files |
>| Data Sent During Unusual Hours |
>| Deep Web URLs |
>| Email to Competitors |
>| Email Addresses |
>| Encrypted Files |
>| Disgruntled Employee |
>| Nigeria PII |
>| Password Dissemination |
>| Password files |
>| Petroleum and Gas-Sensitive Information |
>| PCI |
>| PCI Audit |
>| Files Containing Macros |
>| beni |


### fp-dlp-policy-rule-list

***
List the details of policy rules and classifiers, including condition properties.

#### Base Command

`fp-dlp-policy-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy for which rules will be retrieved. Use `fp-dlp-policy-list` to obtain the required policy names. | Required |
| all_results | Indicates whether to retrieve all results by overriding the default limit. Use 'true' to fetch all results or 'false' to respect the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. If 'all_results' is set to true, this field is ignored. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointDlp.Policy.dlp_version | String | The version of Forcepoint Security Manager. |
| ForcepointDlp.Policy.policy_name | String | The name of the policy. |
| ForcepointDlp.Policy.enabled | String | Indicates whether the policy is enabled. |
| ForcepointDlp.Policy.predefined_policy | String | Indicates whether the policy is predefined or custom. |
| ForcepointDlp.Policy.description | String | The description of the policy. |
| ForcepointDlp.Policy.policy_level | Number | The priority level of the policy, determining its execution order. |
| ForcepointDlp.Policy.policy_level_data_type | String | The data type associated with the policy level. |
| ForcepointDlp.Policy.Rule.rule_name | String | The name of the policy rule. |
| ForcepointDlp.Policy.Rule.enabled | String | Indicates whether the rule is enabled. |
| ForcepointDlp.Policy.Rule.parts_count_type | String | Defines how matches within a transaction are evaluated to trigger an incident. |
| ForcepointDlp.Policy.Rule.condition_relation_type | String | Specifies the condition relationship to trigger the rule: all conditions, at least one condition, or a custom relationship. |
| ForcepointDlp.Policy.Rule.Classifier.classifier_name | String | The name of the classifier. |
| ForcepointDlp.Policy.Rule.Classifier.predefined | String | Indicates whether the classifier is predefined. |
| ForcepointDlp.Policy.Rule.Classifier.position | Number | The position of the classifier in the rule conditions. |
| ForcepointDlp.Policy.Rule.Classifier.threshold_type | String | The type of threshold used for the classifier. |
| ForcepointDlp.Policy.Rule.Classifier.threshold_value_from | Number | The starting threshold value for the classifier. |
| ForcepointDlp.Policy.Rule.Classifier.threshold_calculate_type | String | Defines how the classifier's threshold is calculated. |
| ForcepointDlp.Policy.Rule.Classifier.threshold_value_to | Number | The ending threshold value for the classifier. |

#### Command example
```!fp-dlp-policy-rule-list policy_name=new_policy_4```
#### Context Example
```json
{
    "ForcepointDlp": {
        "Policy": {
            "Rule": [
                {
                    "Classifier": [
                        {
                            "classifier_name": "test",
                            "position": 1,
                            "predefined": "false",
                            "threshold_calculate_type": "ALL",
                            "threshold_type": "CHECK_GREATER_THAN",
                            "threshold_value_from": 1
                        }
                    ],
                    "condition_relation_type": "AND",
                    "enabled": "true",
                    "parts_count_type": "CROSS_COUNT",
                    "rule_name": "new_rule_2"
                }
            ],
            "description": "test",
            "dlp_version": "10.2.0",
            "enabled": "true",
            "policy_level": 1,
            "policy_level_data_type": "NETWORKING",
            "policy_name": "new_policy_4",
            "predefined_policy": "false"
        }
    }
}
```

#### Human Readable Output

>### Rule `new_rule_2` Classifier `test`:
>|Predefined|Position|Threshold Type|Threshold Value From|Threshold Calculate Type|
>|---|---|---|---|---|
>| false | 1 | CHECK_GREATER_THAN | 1 | ALL |


### fp-dlp-rule-exception-list

***
List all exception rules associated with policies, including detailed information about conditions and classifiers.

#### Base Command

`fp-dlp-rule-exception-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| all_results | Indicates whether all results should be retrieved, overriding the default limit. Use 'true' to retrieve all or 'false' for default limits. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| type | Specifies the type of policies to retrieve. Possible values are: DLP, DISCOVERY. Default is DLP. | Optional |
| policy_name | Name of the policy for which exception rules will be retrieved. Use `fp-dlp-policy-list` to obtain the required policy names. | Optional |
| rule_name | Name of the specific rule to retrieve exceptions. When using this argument, `policy_name` is required. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointDlp.PolicyException.policy_name | String | The name of the policy. |
| ForcepointDlp.PolicyException.rule_name | String | The name of the policy rule. |
| ForcepointDlp.PolicyException.exception_rule_names | String | The names of the exception rules for the policy. |
| ForcepointDlp.PolicyException.policy_type | String | The type of the policy, such as DLP. |
| ForcepointDlp.PolicyException.exception_rule_name | String | The name of the exception rule. |
| ForcepointDlp.PolicyException.RuleException.enabled | String | Indicates whether the exception rule is enabled. |
| ForcepointDlp.PolicyException.RuleException.description | String | The description of the exception rule. |
| ForcepointDlp.PolicyException.RuleException.display_description | String | A user-facing description of the exception rule. |
| ForcepointDlp.PolicyException.RuleException.condition_enabled | String | Indicates whether the condition for the exception rule is enabled. |
| ForcepointDlp.PolicyException.RuleException.source_enabled | String | Indicates whether the source condition is enabled for the exception rule. |
| ForcepointDlp.PolicyException.RuleException.destination_enabled | String | Indicates whether the destination condition is enabled for the exception rule. |
| ForcepointDlp.PolicyException.RuleException.parts_count_type | String | Specifies how matches within a transaction are evaluated to trigger an exception rule. |
| ForcepointDlp.PolicyException.RuleException.condition_relation_type | String | Defines the condition relation type for the exception rule \(e.g., AND or OR\). |
| ForcepointDlp.PolicyException.RuleException.classifiers | Unknown | The classifiers used in the exception rule. |
| ForcepointDlp.PolicyException.RuleException.classifier_name | String | The name of the classifier. |
| ForcepointDlp.PolicyException.RuleException.predefined | String | Indicates whether the classifier is predefined. |
| ForcepointDlp.PolicyException.RuleException.position | Number | The position of the classifier in the rule conditions. |
| ForcepointDlp.PolicyException.RuleException.threshold_type | String | The type of threshold used for the classifier. |
| ForcepointDlp.PolicyException.RuleException.threshold_value_from | Number | The starting threshold value for the classifier. |
| ForcepointDlp.PolicyException.RuleException.threshold_calculate_type | String | Defines how the classifier's threshold is calculated. |

#### Command example
```!fp-dlp-rule-exception-list```
#### Context Example
```json
{
    "ForcepointDlp": {
        "PolicyException": [
            {
                "exception_rule_names": [
                    "test-exception"
                ],
                "policy_name": "test-policy",
                "rule_name": "test-rule"
            },
            {
                "exception_rule_names": [
                    "blebla"
                ],
                "policy_name": "hard4",
                "rule_name": "beni5555"
            },
            {
                "exception_rule_names": [
                    "test_exception"
                ],
                "policy_name": "new_policy_3",
                "rule_name": "new_rule_2"
            },
            {
                "exception_rule_names": [
                    "test_exception"
                ],
                "policy_name": "new_policy_4",
                "rule_name": "new_rule_2"
            },
            {
                "exception_rule_names": [
                    "test_exception"
                ],
                "policy_name": "new_policy_2",
                "rule_name": "new_rule_2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Exception Rules List:
>|Policy Name|Rule Name|Exception Rule Names|
>|---|---|---|
>| test-policy | test-rule | test-exception |
>| hard4 | beni5555 | blebla |
>| new_policy_3 | new_rule_2 | test_exception |
>| new_policy_4 | new_rule_2 | test_exception |
>| new_policy_2 | new_rule_2 | test_exception |


### fp-dlp-rule-severity-action-get

***
Retrieve details of rule severity and corresponding action properties for a specified policy.

#### Base Command

`fp-dlp-rule-severity-action-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy for which rule severity and action details will be retrieved. Use `fp-dlp-policy-list` to obtain the required policy names. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointDlp.SeverityActionRule.policy_name | String | The name of the policy. |
| ForcepointDlp.SeverityActionRule.Rule.rule_name | String | The name of the policy rule. |
| ForcepointDlp.SeverityActionRule.Rule.type | String | The rule type defines when to trigger an incident. |
| ForcepointDlp.SeverityActionRule.Rule.max_matches | String | Defines the maximum number of matches to trigger an action. |
| ForcepointDlp.SeverityActionRule.Rule.ClassifierDetail.selected | String | Whether the classifier is selected. |
| ForcepointDlp.SeverityActionRule.Rule.ClassifierDetail.number_of_matches | Number | The number of matches with the classifier. |
| ForcepointDlp.SeverityActionRule.Rule.ClassifierDetail.severity_type | String | The severity level of the classifier. |
| ForcepointDlp.SeverityActionRule.Rule.ClassifierDetail.dup_severity_type | String | The severity level of the classifier. |
| ForcepointDlp.SeverityActionRule.Rule.ClassifierDetail.action_plan | String | The action plan when there is a match. |
| ForcepointDlp.SeverityActionRule.Rule.risk_adaptive_protection_enabled | String | Whether risk adaptive protection is enabled. |

#### Command example
```!fp-dlp-rule-severity-action-get policy_name=new_policy_4```
#### Context Example
```json
{
    "ForcepointDlp": {
        "SeverityActionRule": {
            "Rule": [
                {
                    "ClassifierDetail": [
                        {
                            "action_plan": "test",
                            "dup_severity_type": "MEDIUM",
                            "number_of_matches": 0,
                            "selected": "true",
                            "severity_type": "MEDIUM"
                        },
                        {
                            "action_plan": "test",
                            "dup_severity_type": "LOW",
                            "number_of_matches": 1,
                            "selected": "true",
                            "severity_type": "LOW"
                        },
                        {
                            "action_plan": "test",
                            "dup_severity_type": "MEDIUM",
                            "number_of_matches": 3,
                            "selected": "false",
                            "severity_type": "MEDIUM"
                        }
                    ],
                    "max_matches": "GREATEST_NUMBER",
                    "risk_adaptive_protection_enabled": "false",
                    "rule_name": "new_rule_2",
                    "type": "EVERY_MATCHED_CONDITION"
                }
            ],
            "policy_name": "new_policy_4"
        }
    }
}
```

#### Human Readable Output

>### Policy `new_policy_4` Rule `new_rule_2` Severity and Actions:
>Max matches: GREATEST_NUMBER
>|Number Of Matches|Selected|Action Plan|
>|---|---|---|
>| 0 | true | test |
>| 1 | true | test |
>| 3 | false | test |


### fp-dlp-rule-source-destination-get

***
Retrieve the source and destination details of rules associated with a specified policy.

#### Base Command

`fp-dlp-rule-source-destination-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to retrieve source and destination details. Use `fp-dlp-policy-list` to obtain the required policy names. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointDlp.SourceDestinationRule.policy_name | Unknown | The name of the policy. |
| ForcepointDlp.SourceDestinationRule.Rule.rule_name | String | The name of the policy rule. |
| ForcepointDlp.SourceDestinationRule.Rule.Source.endpoint_channel_machine_type | String | The source machine type. |
| ForcepointDlp.SourceDestinationRule.Rule.Source.endpoint_connection_type | String | The network location of the endpoint machines to analyze. |
| ForcepointDlp.SourceDestinationRule.Rule.Source.Resource.resource_name | String | The name of the resource. |
| ForcepointDlp.SourceDestinationRule.Rule.Source.Resource.type | String | The type of the resource \(for example, computers\). |
| ForcepointDlp.SourceDestinationRule.Rule.Source.Resource.include | String | Indicates whether the resource is included or excluded |
| ForcepointDlp.SourceDestinationRule.Rule.Destination.email_monitor_directions | String | Specifies the email traffic directions to monitor: inbound, outbound, internal, or all. |
| ForcepointDlp.SourceDestinationRule.Rule.Destination.Channel.channel_type | String | The type of the channel. |
| ForcepointDlp.SourceDestinationRule.Rule.Destination.Channel.enabled | String | Indicates whether the resource is enabled. |
| ForcepointDlp.SourceDestinationRule.Rule.Destination.Channel.user_operations | String | A user operation to monitor, such as file uploading, downloading, or external file-sharing. |
| ForcepointDlp.SourceDestinationRule.Rule.Destination.Channel.Resource.resource_name | String | The name of the resource. |
| ForcepointDlp.SourceDestinationRule.Rule.Destination.Channel.Resource.type | String | The type of the resource \(for example, computers\). |
| ForcepointDlp.SourceDestinationRule.Rule.Destination.Channel.Resource.include | String | Indicates whether the resource is included or excluded. |

#### Command example
```!fp-dlp-rule-source-destination-get policy_name=new_policy_4```
#### Context Example
```json
{
    "ForcepointDlp": {
        "SourceDestinationRule": {
            "Rule": [
                {
                    "Destination": {
                        "Channel": [
                            {
                                "channel_type": "FONE_ZTNA",
                                "enabled": "false"
                            },
                            {
                                "channel_type": "ENDPOINT_REMOVABLE_MEDIA",
                                "enabled": "true"
                            },
                            {
                                "channel_type": "EFSS",
                                "enabled": "false"
                            },
                            {
                                "channel_type": "EMAIL",
                                "enabled": "true"
                            },
                            {
                                "Resources": [
                                    {
                                        "include": "false",
                                        "resource_name": "Excluded Resources",
                                        "type": "BUSINESS_UNIT"
                                    }
                                ],
                                "channel_type": "HTTPS",
                                "enabled": "true"
                            },
                            {
                                "channel_type": "MOBILE_AIRSYNC",
                                "enabled": "false"
                            },
                            {
                                "channel_type": "NETWORK_PRINTING",
                                "enabled": "true"
                            },
                            {
                                "Resources": [
                                    {
                                        "include": "false",
                                        "resource_name": "Excluded Resources",
                                        "type": "BUSINESS_UNIT"
                                    }
                                ],
                                "channel_type": "GENERIC_TEXT",
                                "enabled": "true"
                            },
                            {
                                "Resources": [
                                    {
                                        "include": "false",
                                        "resource_name": "Excluded Resources",
                                        "type": "BUSINESS_UNIT"
                                    }
                                ],
                                "channel_type": "ENDPOINT_HTTPS",
                                "enabled": "true"
                            },
                            {
                                "channel_type": "ENDPOINT_APPLICATION",
                                "enabled": "false"
                            },
                            {
                                "Resources": [
                                    {
                                        "include": "false",
                                        "resource_name": "Excluded Resources",
                                        "type": "BUSINESS_UNIT"
                                    }
                                ],
                                "channel_type": "HTTP",
                                "enabled": "true"
                            },
                            {
                                "channel_type": "CASB_NEAR_REAL_TIME",
                                "enabled": "false"
                            },
                            {
                                "channel_type": "CASB_REAL_TIME",
                                "enabled": "false"
                            },
                            {
                                "Resources": [
                                    {
                                        "include": "false",
                                        "resource_name": "Excluded Resources",
                                        "type": "BUSINESS_UNIT"
                                    }
                                ],
                                "channel_type": "ENDPOINT_HTTP",
                                "enabled": "true"
                            },
                            {
                                "Resources": [
                                    {
                                        "include": "false",
                                        "resource_name": "Excluded Resources",
                                        "type": "BUSINESS_UNIT"
                                    }
                                ],
                                "channel_type": "FTP",
                                "enabled": "true"
                            },
                            {
                                "channel_type": "ENDPOINT_PRINTING",
                                "enabled": "true"
                            },
                            {
                                "Resources": [
                                    {
                                        "include": "false",
                                        "resource_name": "Excluded Resources",
                                        "type": "BUSINESS_UNIT"
                                    }
                                ],
                                "channel_type": "IM",
                                "enabled": "true"
                            },
                            {
                                "channel_type": "ENDPOINT_LAN",
                                "enabled": "false"
                            },
                            {
                                "channel_type": "ENDPOINT_EMAIL",
                                "enabled": "true"
                            }
                        ],
                        "email_monitor_directions": [
                            "INCOMING"
                        ]
                    },
                    "Source": {
                        "endpoint_channel_machine_type": "ALL_MACHINES",
                        "endpoint_connection_type": "ANYWARE"
                    },
                    "rule_name": "new_rule_2"
                }
            ],
            "policy_name": "new_policy_4"
        }
    }
}
```

#### Human Readable Output

>### Policy `new_policy_4` Source and Destination Rules Details:
>|Rule Name|Source Endpoint Channel Machine Type|Source Endpoint Connection Type|Destination Email Monitor Directions|
>|---|---|---|---|
>| new_rule_2 | ALL_MACHINES | ANYWARE | INCOMING |


### fp-dlp-rule-create

***
Create a new rule in a specified DLP policy with a single classifier. To add more classifiers, use the `fp-dlp-rule-update` command or provide a JSON configuration file via the `entry_id` argument. If the specified policy does not exist, it will be created automatically. If the rule already exists, use the `fp-dlp-rule-update` command.

#### Base Command

`fp-dlp-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dlp_version | The DLP version to use. Required when not using `entry_id``. Use `fp-dlp-policy-rule-list` to retrieve the DLP version. | Optional |
| policy_name | The name of the policy where the rule will be created. Use `fp-dlp-policy-list` to obtain the required policy names or define a new policy name. Not existed policy will automatically created. Required when not using `entry_id`. | Required |
| policy_enabled | Indicates whether the policy is enabled. Put attention - if set to false, the policy will disappear from the the existing policies and you will have to enable it in the product. Possible values are: true, false. Default is true. | Optional |
| predefined_policy | Specifies if the policy is predefined. Possible values are: true, false. | Optional |
| policy_description | The description of the policy. | Optional |
| policy_level | The priority level of the policy. Required when not using `entry_id`. | Optional |
| policy_data_type | The data type associated with the policy level. | Optional |
| rule_name | The name of the rule to be created. In case the rule is already exists, use the update command. Required when not using `entry_id`. | Required |
| rule_enabled | Indicates whether the rule is enabled. Possible values are: true, false. Default is true. | Optional |
| rule_parts_count_type | Defines how matches within a transaction are evaluated to trigger the rule. Required when not using `entry_id`. Possible values are: CROSS_COUNT, INTERNAL_COUNT. | Optional |
| rule_condition_relation_type | Specifies the condition relationship to trigger the rule. Required when not using `entry_id`. Possible values are: AND, OR. | Optional |
| classifier_name | The name of the classifier in Forcepoint DLP. Required when not using `entry_id`. | Optional |
| classifier_predefined | Specifies if the classifier is predefined. Required when not using `entry_id`. Possible values are: true, false. | Optional |
| classifier_position | The position of the classifier in the rule conditions. Required when not using `entry_id`. | Optional |
| classifier_threshold_type | Classifier threshold type. Required when not using `entry_id`. Possible values are: CHECK_EMPTY, CHECK_GREATER_THAN, CHECK_IN_RANGE. | Optional |
| classifier_threshold_value_from | Threshold first parameter. Required when not using `entry_id` and when classifier_threshold_type is `CHECK_IN_RANGE` or `CHECK_GREATER_THAN`. | Optional |
| classifier_threshold_value_to | Threshold first parameter. Required when not using `entry_id` and when classifier_threshold_type is `CHECK_IN_RANGE`. | Optional |
| classifier_threshold_calculate_type | Defines how the classifier's threshold is calculated. Required when not using `entry_id`. Possible values are: UNIQUE, ALL. | Optional |
| entry_id | Entry ID of a JSON file to pass the configuration instead of using the command inputs. Use `fp-dlp-policy-rule-list` to retrive examples for the payload to provide. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fp-dlp-rule-create policy_name=new_policy_4 rule_name=new_rule_2 classifier_name=test classifier_position=1 classifier_predefined=false classifier_threshold_calculate_type=ALL classifier_threshold_type=CHECK_GREATER_THAN classifier_threshold_value_from=1 dlp_version=10.2.0 policy_enabled=true predefined_policy=false rule_enabled=true rule_condition_relation_type=AND rule_parts_count_type=CROSS_COUNT policy_level=1 policy_data_type=NETWORKING```
#### Human Readable Output

>Rule `new_rule_2` was successfully created in policy 'new_policy_4'.

### fp-dlp-rule-update

***
Update an existing rule in a specific DLP policy or create a classifier within it. To add/ update more classifiers, use this command multiple times (with diffrent position to add or existing position to update). or provide a JSON configuration file via the `entry_id` argument, which overrides all classifiers. If the policy does not exist, it will be created. If the classifier does not exist in the rule, it will be added. Use the `fp-dlp-rule-create` command to create a rule if it does not exist.

#### Base Command

`fp-dlp-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dlp_version | The DLP version to use. Required when not using `entry_id`. Use `fp-dlp-policy-rule-list` to retrieve the DLP version. | Optional |
| policy_name | The name of the policy where the rule will be updated. Use `fp-dlp-policy-list` to obtain the required policy names. | Required |
| rule_name | The name of the rule that will be updated. Use `fp-dlp-policy-rule-list` to obtain the required rule names. | Required |
| policy_enabled | Indicates whether the policy is enabled.. Put attention - if set to false, the policy will disappear from the the existing policies and you will have to enable it in the product. Possible values are: true, false. | Optional |
| predefined_policy | Specifies if the policy is predefined. Possible values are: true, false. | Optional |
| policy_description | The description of the policy. | Optional |
| policy_level | The priority level of the policy. | Optional |
| policy_data_type | The data type associated with the policy level. | Optional |
| rule_enabled | Indicates whether the rule is enabled. Possible values are: true, false. | Optional |
| rule_parts_count_type | Defines how matches within a transaction are evaluated to trigger the rule. Possible values are: CROSS_COUNT, INTERNAL_COUNT. | Optional |
| rule_condition_relation_type | Specifies the condition relationship to trigger the rule. Possible values are: AND, OR. | Optional |
| classifier_name | The name of the classifier in Forcepoint DLP. | Optional |
| classifier_predefined | Specifies if the classifier is predefined. Possible values are: true, false. | Optional |
| classifier_position | The position of the classifier in the rule conditions. | Optional |
| classifier_threshold_type | Classifier threshold type. Possible values are: CHECK_EMPTY, CHECK_GREATER_THAN, CHECK_IN_RANGE. | Optional |
| classifier_threshold_value_from | Threshold first parameter. Mandatory when classifier_threshold_type is `CHECK_IN_RANGE` or `CHECK_GREATER_THAN`. | Optional |
| classifier_threshold_value_to | Threshold first parameter. Required when not using entry_id and when classifier_threshold_type is CHECK_IN_RANGE. | Optional |
| classifier_threshold_calculate_type | Defines how the classifier's threshold is calculated. Possible values are: UNIQUE, ALL. | Optional |
| entry_id | Entry ID of a JSON file to pass the configuration instead of using the command inputs. Use `fp-dlp-policy-rule-list` to retrive examples for the payload to provide. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fp-dlp-rule-update policy_name=new_policy_4 rule_name=new_rule_2 policy_description=test```
#### Human Readable Output

>Rule `new_rule_2` was successfully updated in policy 'new_policy_4'.

### fp-dlp-rule-severity-action-update

***
Update the severity actions for a rule in a specific DLP policy. To add more classifiers, use this command multiple times or provide a JSON configuration file via the `entry_id` argument to override all classifiers. A maximum of 3 classifiers is allowed. Use the `override_classifier_number_of_matches` argument to specify which classifier to update based on its number of matches.

#### Base Command

`fp-dlp-rule-severity-action-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy where the rules will be updated. Use `fp-dlp-policy-list` to obtain the required policy names. | Required |
| rule_name | The name of the rule to be updated. Use `fp-dlp-policy-rule-list` to obtain the required rule names. Required when not using `entry_id`. | Required |
| rule_type | The type of the rule. Required when not using `entry_id`. Possible values are: CUMULATIVE_CONDITION, EVERY_MATCHED_CONDITION. | Optional |
| rule_count_type | The type of the matches to count. Required when rule_type is CUMULATIVE_CONDITION. Required when not using `entry_id`. Possible values are: MATCHES, UNIQUE_MATCHES, EVENTS. | Optional |
| rule_count_period | The period of the matches to count. Required when rule_type is CUMULATIVE_CONDITION. Required when not using `entry_id`. Possible values are: FIVE_MINUTES, FIFTEEN_MINUTES, ONE_HOUR, FOUR_HOUR, EIGHT_HOURS, TWENTY_FOUR_HOURS. | Optional |
| rule_rate_match_period | The match type (for example, transactions) will accumulate until the rate declines for the specified duration. Required when rule_type is CUMULATIVE_CONDITION. Required when not using `entry_id`. Possible values are: FIVE_MINUTES, FIFTEEN_MINUTES, ONE_HOUR, FOUR_HOUR, EIGHT_HOURS, TWENTY_FOUR_HOURS. | Optional |
| rule_max_matches | Matches are calculated as the X matched conditions. Required when not using `entry_id`. Possible values are: GREATEST_NUMBER, SUM_ALL. | Optional |
| classifier_selected | Indicates if the classifier is selected. Required when not using `entry_id`. Possible values are: true, false. | Optional |
| classifier_number_of_matches | The number of matches for the classifier. In case therer is no classifier with this number of matches, use `override_classifier_number_of_matches` to override classifier. Required when not using `entry_id`. | Optional |
| override_classifier_number_of_matches | The number of matches classifier to override. | Optional |
| classifier_severity_type | The severity type of the classifier. Required when not using `entry_id`. Possible values are: LOW, MEDIUM, HIGH. | Optional |
| classifier_action_plan | The action plan associated with the classifier. There are predefined values (such as `Audit Only`, `Block All`, `Audit and Notify`, `Drop Email Attachment`, `Audit Without Forensis`, `Block Without Forencis`) and defined by user action plans. Required when not using `entry_id`. | Optional |
| entry_id | Entry ID of a JSON file to pass the configuration instead of using the command inputs. Use `fp-dlp-rule-severity-action-get` to retrive examples for the payload to provide. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fp-dlp-rule-severity-action-update policy_name=new_policy_4 rule_name=new_rule_2 classifier_number_of_matches=1 classifier_action_plan=test classifier_selected=true classifier_severity_type=LOW override_classifier_number_of_matches=2```
#### Human Readable Output

>Severity actions for Rule `new_rule_2` in policy 'new_policy_4' was successfully updated.

### fp-dlp-rule-source-destination-update

***
Update the source and destination settings for a rule in a specific DLP policy. You can pass configuration data via parameters to update one channel and resource, or provide a JSON configuration file via the `entry_id` argument to override all channels.

#### Base Command

`fp-dlp-rule-source-destination-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy where the rules will be updated. Use `fp-dlp-policy-list` to obtain the required policy names. | Required |
| rule_name | The name of the rule to be updated. Use `fp-dlp-policy-rule-list` to obtain the required rule names. | Required |
| rule_source_endpoint_channel_machine_type | The type of endpoint machine. Possible values are: ALL_MACHINES, ALL_MACHINES_EXCEPT_LAPTOPS, LAPTOPS_ONLY. | Optional |
| rule_source_endpoint_connection_type | The type of endpoint connection. Possible values are: NONE, ANYWARE, CONNECTED_TO_CORPORATE_NETWORK, NOT_CONNECTED_TO_CORPORATE_NETWORK. | Optional |
| rule_destination_email_monitor_directions | Email monitor directions. Possible values are: INCOMING, OUTGOING, INTERNAL. | Optional |
| channel_type | The type of the channel. Possible values are: EMAIL, ENDPOINT_EMAIL, FTP, IM, HTTP, HTTPS, GENERIC_TEXT, ENDPOINT_HTTP, ENDPOINT_HTTPS, NETWORK_PRINTING, ENDPOINT_PRINTING, ENDPOINT_APPLICATION, ENDPOINT_REMOVABLE_MEDIA, ENDPOINT_LAN, MOBILE_AIRSYNC, EFSS, CASB_REAL_TIME, CASB_NEAR_REAL_TIME. | Optional |
| channel_enabled | Indicates whether the channel is enabled. Possible values are: true, false. | Optional |
| resource_name | The name of the resource. | Optional |
| resource_type | The type of the resource. Possible values are: DIRECTORY_ENTRY_USER, DIRECTORY_ENTRY_GROUP, DIRECTORY_ENTRY_OU, CUSTOM_USER, NETWORK, CUSTOM_COMPUTER, DOMAIN, BUSINESS_UNIT, APPLICATION_GROUP, ONLINE_APPLICATION_GROUP, PRINTER, DEVICE, COUNTRY, URL_CATEGORY, CLOUD_APPLICATION. | Optional |
| resource_include | Indicates whether the resource is included. Possible values are: true, false. | Optional |
| entry_id | Entry ID of a JSON file to pass the configuration instead of using the command inputs. Use `fp-dlp-rule-source-destination-get` to retrive examples for the payload to provide. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fp-dlp-rule-source-destination-update policy_name=new_policy_4 rule_name=new_rule_2 rule_source_endpoint_channel_machine_type=ALL_MACHINES rule_destination_email_monitor_directions=INCOMING```
#### Human Readable Output

>Source and destination for Rule `new_rule_2` in policy 'new_policy_4' was successfully updated.

### fp-dlp-rule-exception-create

***
Create an exception rule for a specified parent rule and policy type. To add more classifiers, use this command multiple times or provide a JSON configuration file via the `entry_id` argument to override all classifiers.

#### Base Command

`fp-dlp-rule-exception-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_policy_name | The name of the parent policy that holds the rule. Use `fp-dlp-policy-list` to obtain the required policy names. | Required |
| parent_rule_name | The name of the parent rule that holds exception rules. Use `fp-dlp-policy-rule-list` to obtain the required rule names. | Required |
| policy_type | The type of the policy. Possible values are: DLP, DISCOVERY. Default is DLP. | Optional |
| exception_rule_name | The name of the exception rule that will be created. | Optional |
| enabled | Indicates whether the exception rule is enabled. Possible values are: true, false. | Optional |
| description | A description of the exception rule. | Optional |
| parts_count_type | The parts count type of the exception rule. Possible values are: CROSS_COUNT, INTERNAL_COUNT. | Optional |
| condition_relation_type | The condition relation type of the exception rule. Possible values are: AND, OR, CUSTOMIZED. | Optional |
| condition_enabled | Indicates whether the condition is enabled. Possible values are: true, false. | Optional |
| source_enabled | Indicates whether the source condition is enabled (only for DLP policy type). Possible values are: true, false. | Optional |
| destination_enabled | Indicates whether the destination condition is enabled (only for DLP policy type). Possible values are: true, false. | Optional |
| classifier_name | The name of the classifier. | Optional |
| classifier_predefined | Indicates if the classifier is predefined. Possible values are: true, false. | Optional |
| classifier_position | The position of the classifier inside the condition. | Optional |
| classifier_threshold_type | The threshold type for the classifier. Possible values are: CHECK_EMPTY, CHECK_GREATER_THAN, CHECK_IN_RANGE. | Optional |
| classifier_threshold_value_from | The first threshold value for CHECK_IN_RANGE or CHECK_GREATER_THAN. | Optional |
| classifier_threshold_value_to | Threshold first parameter. Required when not using `entry_id` and when classifier_threshold_type is `CHECK_IN_RANGE`. | Optional |
| classifier_threshold_calculate_type | How the threshold is calculated. Possible values are: UNIQUE, ALL. | Optional |
| severity_classifier_max_matches | The method for calculating matches. Possible values are: GREATEST_NUMBER, SUM_ALL. | Optional |
| severity_classifier_selected | Indicates whether the classifier detail is selected. Possible values are: true, false. | Optional |
| severity_classifier_number_of_matches | The number of matches for the classifier detail. | Optional |
| severity_classifier_severity_type | The severity type for the classifier detail. Possible values are: LOW, MEDIUM, HIGH. | Optional |
| severity_classifier_action_plan | The action plan for the classifier detail. There are predefined values (such as `Audit Only`, `Block All`, `Audit and Notify`, `Drop Email Attachment`, `Audit Without Forensis`, `Block Without Forencis`) and defined by user action plans. | Optional |
| entry_id | Entry ID of a JSON file to pass the configuration instead of using the command inputs. Use `fp-dlp-rule-exception-list` to retrieve examples for the payload to provide. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fp-dlp-rule-exception-create parent_policy_name=new_policy_4 parent_rule_name=new_rule_2 description=test destination_enabled=false source_enabled=false condition_enabled=true classifier_name=test classifier_position=1 classifier_predefined=false classifier_threshold_calculate_type=ALL classifier_threshold_type=CHECK_GREATER_THAN classifier_threshold_value_from=1 severity_classifier_action_plan=test severity_classifier_max_matches=SUM_ALL severity_classifier_number_of_matches=1 severity_classifier_severity_type=LOW severity_classifier_selected=true enabled=true parts_count_type=CROSS_COUNT condition_relation_type=AND exception_rule_name=test_exception```
#### Human Readable Output

>Exception rule 'test_exception' was successfully created in rule 'new_rule_2' under policy 'new_policy_4'.

### fp-dlp-rule-exception-update

***
Update an existing exception rule for a specified parent rule and policy type. To add/ update more classifiers, use this command multiple times (with diffrent position to add or existing position to update) or provide a JSON configuration file via the `entry_id` argument to override all classifiers.

#### Base Command

`fp-dlp-rule-exception-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_policy_name | The name of the parent policy that holds the rule. Use fp-dlp-policy-list to obtain the required policy names. | Required |
| parent_rule_name | The name of the parent rule that holds exception rules. Use fp-dlp-policy-rule-list to obtain the required rule names. | Required |
| policy_type | The type of the policy. Possible values are: DLP, DISCOVERY. Default is DLP. | Optional |
| exception_rule_name | The name of the exception rule that will be updated. Use 'forcepoint-dlp-get-rule-exception' to obtain the required exception rule names. | Optional |
| enabled | Indicates whether the exception rule is enabled. Possible values are: true, false. | Optional |
| description | A description of the exception rule. | Optional |
| parts_count_type | The parts count type of the exception rule. Possible values are: CROSS_COUNT, INTERNAL_COUNT. | Optional |
| condition_relation_type | The condition relation type of the exception rule. Possible values are: AND, OR, CUSTOMIZED. | Optional |
| condition_enabled | Indicates whether the condition is enabled. Possible values are: true, false. | Optional |
| source_enabled | Indicates whether the source condition is enabled (only for DLP policy type). Possible values are: true, false. | Optional |
| destination_enabled | Indicates whether the destination condition is enabled (only for DLP policy type). Possible values are: true, false. | Optional |
| classifier_name | The name of the classifier. | Optional |
| classifier_predefined | Indicates if the classifier is predefined. Possible values are: true, false. | Optional |
| classifier_position | The position of the classifier inside the condition. | Optional |
| classifier_threshold_type | The threshold type for the classifier. Possible values are: CHECK_EMPTY, CHECK_GREATER_THAN, CHECK_IN_RANGE. | Optional |
| classifier_threshold_value_from | The first threshold value for `CHECK_IN_RANGE` or `CHECK_GREATER_THAN`. | Optional |
| classifier_threshold_value_to | Threshold first parameter. Required when not using `entry_id` and when classifier_threshold_type is `CHECK_IN_RANGE`. | Optional |
| classifier_threshold_calculate_type | How the threshold is calculated. Possible values are: UNIQUE, ALL. | Optional |
| severity_classifier_max_matches | The method for calculating matches. Possible values are: GREATEST_NUMBER, SUM_ALL. | Optional |
| severity_classifier_selected | Indicates whether the classifier detail is selected. Possible values are: true, false. | Optional |
| severity_classifier_number_of_matches | The number of matches for the classifier. In case therer is no classifier with this number of matches, use override_severity_classifier_number_of_matches to override classifier. Required when not using `entry_id`. | Optional |
| override_severity_classifier_number_of_matches | The number of matches classifier to override. Required when not using `entry_id`. | Optional |
| severity_classifier_severity_type | The severity type for the classifier detail. Possible values are: LOW, MEDIUM, HIGH. | Optional |
| severity_classifier_action_plan | The action plan for the classifier detail. There are predefined values (such as `Audit Only`, `Block All`, `Audit and Notify`, `Drop Email Attachment`, `Audit Without Forensis`, `Block Without Forencis`) and defined by user action plans. | Optional |
| entry_id | Entry ID of a JSON file to pass the configuration instead of using the command inputs. Use `fp-dlp-rule-exception-list` to retrieve examples for the payload to provide. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fp-dlp-rule-exception-update parent_policy_name=new_policy_4 parent_rule_name=new_rule_2 exception_rule_name=test_exception description=test2```
#### Human Readable Output

>Exception rule 'test_exception' was successfully updated in rule 'new_rule_2' under policy 'new_policy_4'.

### fp-dlp-incident-list

***
Retrieve a list of incidents based on specified filters.

#### Base Command

`fp-dlp-incident-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of incidents to retrieve. Possible values are: INCIDENTS, DISCOVERY. Default is INCIDENTS. | Optional |
| ids | Comma separated array of incident IDs to retrieve. For example, 131069,131066. | Optional |
| from_date | Start date for the incident search. Timestamp in ISO format or &lt;number&gt; &lt;time unit&gt;, e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | Required |
| to_date | End date for the incident search. Timestamp in ISO format or &lt;number&gt; &lt;time unit&gt;, e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. Default is now. | Optional |
| status | The status of incidents to filter. Possible values are: NEW, IN_PROCESS, CLOSE, FALSE_POSITIVE, ESCALATED. | Optional |
| all_results | Indicates whether to retrieve all results by overriding the default limit. Use 'true' to fetch all results or 'false' to respect the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. If 'all_results' is set to true, this field is ignored. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ForcepointDlp.Incident.id | Number | Unique identifier for the incident. |
| ForcepointDlp.Incident.severity | String | Severity level of the incident. |
| ForcepointDlp.Incident.action | String | Action taken on the incident. |
| ForcepointDlp.Incident.status | String | Current status of the incident. |
| ForcepointDlp.Incident.Source.ip_address | String | Source IP address associated with the incident. |
| ForcepointDlp.Incident.history | Array | History of the incident with task details. |
| ForcepointDlp.Incident.event_id | String | Unique event identifier associated with the incident. |
| ForcepointDlp.Incident.maximum_matches | Number | Maximum matches in the incident. |
| ForcepointDlp.Incident.transaction_size | Number | Size of the transaction triggering the incident. |
| ForcepointDlp.Incident.analyzed_by | String | Policy engine or tool that analyzed the incident. |
| ForcepointDlp.Incident.event_time | String | Time the event was recorded. |
| ForcepointDlp.Incident.incident_time | String | Time the incident was identified. |
| ForcepointDlp.Incident.channel | String | Communication channel associated with the incident. |
| ForcepointDlp.Incident.policies | String | Policies associated with the incident. |
| ForcepointDlp.Incident.detected_by | String | Detection tool or method. |
| ForcepointDlp.Incident.details | String | Detailed information about the incident. |
| ForcepointDlp.Incident.violation_triggers | Array | Array of violation triggers, including classifiers, policy name, and rule name. |

#### Command example
```!fp-dlp-incident-list from_date="2022-01-01T00:00:00.000Z" limit=1```
#### Context Example
```json
{
    "ForcepointDlp": {
        "Incident": {
            "Source": {
                "ip_address": "192.168.30.215"
            },
            "ViolationTriggers": [
                {
                    "Classifiers": [
                        {
                            "classifier_name": "PizzaTestKeyword (Key Phrase)",
                            "number_matches": 1
                        }
                    ],
                    "policy_name": "Test",
                    "rule_name": "Test-Rule"
                }
            ],
            "action": "BLOCKED",
            "analyzed_by": "Policy Engine  fp-wcg-wcg",
            "assigned_to": "admin",
            "channel": "HTTPS",
            "destination": "dlptest.com",
            "details": "https://dlptest.com/https-post/",
            "detected_by": "Forcepoint Content Gateway Server on fp-wcg-wcg",
            "event_id": "2612565687635980284",
            "event_time": "13/11/2024 17:33:53",
            "history": [
                {
                    "admin_name": "dlpapi",
                    "task_name": "Incident tagged. New tag: custom taasdasdg",
                    "update_time": "27/01/2025 15:35:57"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Incident tagged. New tag: custom tag",
                    "update_time": "27/01/2025 15:35:54"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Incident tagged. New tag: custom tag",
                    "update_time": "27/01/2025 15:35:53"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Incident tagged. New tag: custom tag",
                    "update_time": "27/01/2025 15:35:52"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Incident tagged. New tag: custom tag",
                    "update_time": "20/01/2025 13:07:44"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Changed incident assignment from Unassigned to admin ",
                    "update_time": "20/01/2025 12:48:18"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Changed incident severity from Medium to High",
                    "update_time": "20/01/2025 12:47:15"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Incident tagged. New tag: 123",
                    "update_time": "20/01/2025 12:47:03"
                },
                {
                    "admin_name": "dlpapi",
                    "task_name": "Incident tagged. New tag: custom tag",
                    "update_time": "20/01/2025 12:46:20"
                },
                {
                    "admin_name": "system",
                    "task_name": "Detected and recorded incident",
                    "update_time": "13/11/2024 17:34:08"
                }
            ],
            "id": 131069,
            "ignored_incidents": false,
            "incident_time": "13/11/2024 17:34:06",
            "maximum_matches": 1,
            "partition_index": 20241113,
            "policies": "Test",
            "released_incident": false,
            "severity": "HIGH",
            "status": "New",
            "tag": "custom taasdasdg",
            "transaction_size": 98
        }
    }
}
```

#### Human Readable Output

>### Incidents List:
>|Id|Event Id|Severity|Action|Status|Event Time|Channel|Tag|Assigned To|
>|---|---|---|---|---|---|---|---|---|
>| 131069 | 2612565687635980284 | HIGH | BLOCKED | New | 13/11/2024 17:33:53 | HTTPS | custom taasdasdg | admin |


### fp-dlp-incident-update

***
Update an incident's attributes such as status, severity, assignment, comments, tags, release flag, or false positive indication.

#### Base Command

`fp-dlp-incident-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | A list of event IDs to update. Use the 'fp-dlp-incident-get' command to retrieve incident IDs. | Required |
| type | The type of incidents to retrieve. Possible values are: INCIDENTS, DISCOVERY. Default is INCIDENTS. | Optional |
| status | The status to update for the specified incidents. Possible values are: NEW, IN_PROCESS, CLOSE, FALSE_POSITIVE, ESCALATED. | Optional |
| comment | A comment to attach to the specified incidents. | Optional |
| assign | The user to assign the specified incidents to. Provide 'admin' or the username of the assignee. | Optional |
| tag | Tag to assign to the specified incidents. | Optional |
| severity | The severity level to update for the specified incidents. Possible values are: HIGH, MEDIUM, LOW. | Optional |
| release | The release flag to update for the specified incidents. | Optional |
| false_positive | Flag to indicate whether the specified incidents are false positives. Possible values are: true, false. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fp-dlp-incident-update event_ids=2612565687635980284 severity=HIGH```
#### Human Readable Output

>Incidents was successfully updated.

### get-modified-remote-data

***
Gets the list of incidents that were modified since the last update time. Note that this method is here for debugging purposes. The get-modified-remote-data command is used as part of a Mirroring feature, which is available from version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Optional |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Get remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ticket ID. | Required |
| lastUpdate | Retrieve entries that were created after lastUpdate. | Required |

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Returns the list of fields for an incident type.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### update-remote-system

***
Updates the remote incident or detection with local incident or detection changes. This method is only used for debugging purposes and will not update the current incident or detection.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and ForcePoint DLP corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and ForcePoint DLP.
