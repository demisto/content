# WizDefend Integration

Agentless cloud security platform for detecting and addressing cloud issues, detections, and threats.

## Configure WizDefend on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WizDefend.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Required** |
| --- | --- |
| Service Account ID | True |
| Authentication Endpoint | True |
| API Endpoint | True |
| First fetch timestamp (maximum 5 days) | False |
| Max Detections to Fetch | False |
| Minimum detection severity to fetch | False |
| Type of detections to fetch | False |
| Detection cloud account or cloud organization to fetch | False |
| Detection platforms to fetch | False |
| Cloud event origin to fetch | False |
| Use system proxy settings | False |
| Fetch incidents | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### wiz-get-detections

***
Retrieve Wiz security detections based on specified filters.

#### Base Command

`wiz-get-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| creation_minutes_back | Time window in minutes to retrieve detections (range 10-600). Default is 10. | Optional |
| type | Type of detections to fetch. Possible values are: GENERATED THREAT, DID NOT GENERATE THREAT. Default is GENERATED THREAT. | Optional |
| issue_id | The internal Wiz Issue ID of the Detections. | Optional |
| cloud_account_or_cloud_organization | Detection cloud account or cloud organization to fetch. | Optional |
| origin | Cloud event origin. You can insert multiple cloud event origins in this format ORIGIN1,ORIGIN2 etc... | Optional |
| platform | Get Detections for cloud platform. You can insert multiple platforms in this format PLATFORM1,PLATFORM2 etc... | Optional |
| resource_id | Filter detections by specific resource ID. | Optional |
| severity | Get Detections of a specific severity and above. Possible values are: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL. | Optional |
| rule_match_id | Filter detections by rule match ID (requires valid UUID format). | Optional |
| rule_match_name | Filter detections by matching rule name. | Optional |
| project | Filter Detections by project. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Detections.entitySnapshot | String | All resource details. |
| Wiz.Manager.Detections.createdAt | String | Detection created at. |
| Wiz.Manager.Detections.id | String | Wiz Detection ID. |
| Wiz.Manager.Detections.url | String | Wiz Detection URL. |
| Wiz.Manager.Detections.severity | String | Wiz Detection severity. |
| Wiz.Manager.Detections.status | String | Wiz Detection status. |

### wiz-get-detection

***
Retrieve detailed information about a specific Wiz detection by ID.

#### Base Command

`wiz-get-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Wiz internal detection ID to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Detection.id | String | Detection ID in Wiz. |
| Wiz.Manager.Detection.severity | String | Detection severity. |
| Wiz.Manager.Detection.description | String | Detection description. |
| Wiz.Manager.Detection.createdAt | Date | Detection creation time. |
| Wiz.Manager.Detection.resources | String | Related resources. |
| Wiz.Manager.Detection.url | String | URL to the Wiz Detection in the Wiz console. |

### wiz-get-threat

***
Retrieve detailed information about a specific Wiz threat by issue ID.

#### Base Command

`wiz-get-threat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Wiz internal issue ID to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Threat.id | String | Threat ID in Wiz. |
| Wiz.Manager.Threat.severity | String | Threat severity. |
| Wiz.Manager.Threat.description | String | Threat description. |
| Wiz.Manager.Threat.createdAt | Date | Threat creation time. |
| Wiz.Manager.Threat.resources | String | Related resources. |
| Wiz.Manager.Threat.url | String | URL to the Wiz Threat in the Wiz console. |

### wiz-get-threats

***
Retrieve Wiz threats based on specified filters.

#### Base Command

`wiz-get-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| creation_days_back | Time window in days to retrieve threats (range 1-30). Default is 5. | Optional |
| cloud_account_or_cloud_organization | Threat cloud account or cloud organization to fetch. | Optional |
| platform | Get Threats for cloud platform. You can insert multiple platforms in this format PLATFORM1,PLATFORM2 etc... | Optional |
| resource_id | Filter threats by specific resource ID. | Optional |
| severity | Minimum threat severity to fetch. Possible values are: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL. | Optional |
| status | Filter threats by status (e.g., OPEN, IN_PROGRESS). Possible values are: OPEN, IN_PROGRESS, RESOLVED, REJECTED. Default is OPEN, IN_PROGRESS. | Optional |
| origin | Cloud event origin. You can insert multiple cloud event origins in this format ORIGIN1,ORIGIN2 etc... | Optional |
| project | Filter Threats by project. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Threats.entitySnapshot | String | All resource details. |
| Wiz.Manager.Threats.createdAt | String | Threat created at. |
| Wiz.Manager.Threats.id | String | Wiz Threat ID. |
| Wiz.Manager.Threats.url | String | Wiz Threat URL. |
| Wiz.Manager.Threats.severity | String | Wiz Threat severity. |
| Wiz.Manager.Threats.status | String | Wiz Threat status. |

## Known Limitations

- Maximum fetch limit is 1000 detections per run
- XSOAR fetch process has a 5-minute timeout

## Troubleshooting

If you encounter issues:

1. Verify your Service Account credentials are correct
2. Ensure the Authentication and API endpoints are accessible
3. Check that your Wiz account has the necessary permissions
4. Review the integration logs for detailed error messages