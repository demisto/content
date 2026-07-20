Integrate with Palo Alto Networks Prisma AIRs for AI security capabilities including runtime scanning, red teaming, model security, and DLP configuration.
This integration was integrated and tested with the Palo Alto Networks - Prisma AIRs AI Security API as of June 2026.

## Configure Palo Alto Networks - Prisma AIRs AI Security in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Client ID |  | True |
| API Client Secret |  | True |
| Tenant Services Group ID | Default Tenant Services Group ID to use for API calls. Example: 1234567890. | True |
| Runtime API Key | Runtime API Key for Prisma AIRs Scanner API. This is used exclusively for runtime scanning operations and is different from the OAuth2 Client ID/Secret used for management operations. | True |
| Scanner API Base URL | Scanner API base URL for runtime scanning operations. Default is US region. For other regions: EU: https://service-de.api.aisecurity.paloaltonetworks.com, IN: https://service-in.api.aisecurity.paloaltonetworks.com, SG: https://service-sg.api.aisecurity.paloaltonetworks.com. This must match the region selected during deployment profile creation. | False |
| DLP API Base URL | DLP API base URL for DLP management operations \(dictionaries, patterns, filtering profiles\). Default is the global DLP endpoint. Change only if using a regional or custom DLP endpoint. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### prisma-airs-runtime-scan

***
Scan a single prompt against a security profile for AI security threats.

#### Base Command

`prisma-airs-runtime-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The name of the security profile to use for scanning. | Required |
| prompt | The prompt text to scan. | Required |
| response | Optional response text to scan alongside the prompt. | Optional |
| tr_id | Unique identifier string for correlating the prompt and response transactions. Returned in the scan response. | Optional |
| session_id | Unique identifier string for tracking sessions. Returned in the scan response. | Optional |
| app_name | AI application requesting the content scan. | Optional |
| app_user | End user using the AI application. | Optional |
| ai_model | AI model serving the AI application. | Optional |
| user_ip | End user IP address using the AI application. | Optional |
| agent_id | Agent identifier for metadata tracking. | Optional |
| agent_version | Agent version for metadata tracking. | Optional |
| agent_arn | Agent ARN for metadata tracking. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RuntimeScan.scan_id | String | Unique scan identifier. |
| PrismaAIRs.RuntimeScan.report_id | String | Report identifier for this scan. |
| PrismaAIRs.RuntimeScan.tr_id | String | Transaction ID passed in the request and returned in the response. |
| PrismaAIRs.RuntimeScan.session_id | String | Session ID passed in the request and returned in the response. |
| PrismaAIRs.RuntimeScan.prompt | String | The scanned prompt text. |
| PrismaAIRs.RuntimeScan.response | String | The scanned response text. |
| PrismaAIRs.RuntimeScan.action | String | Action taken \(allow or block\). |
| PrismaAIRs.RuntimeScan.category | String | Threat category \(benign, malicious, etc.\). |
| PrismaAIRs.RuntimeScan.detected | Boolean | Whether any threat was detected across prompt or response. |
| PrismaAIRs.RuntimeScan.prompt_detected | Unknown | Object containing all detection types for the prompt \(e.g., injection, dlp, toxic_content, topic_violation, url_cats, malicious_code, agent\). |
| PrismaAIRs.RuntimeScan.response_detected | Unknown | Object containing all detection types for the response \(e.g., dlp, toxic_content, topic_violation, url_cats, malicious_code, agent, db_security, ungrounded\). |
| PrismaAIRs.RuntimeScan.profile_id | String | Profile ID used for scanning. |
| PrismaAIRs.RuntimeScan.profile_name | String | Profile name used for scanning. |
| PrismaAIRs.RuntimeScan.source | String | Source of the scan request. |
| PrismaAIRs.RuntimeScan.timeout | Boolean | Whether any detection service timed out. |
| PrismaAIRs.RuntimeScan.error | Boolean | Whether any detection service encountered an error. |
| PrismaAIRs.RuntimeScan.errors | Unknown | List of detection service errors or timeouts. |

#### Command example

```
!prisma-airs-runtime-scan profile_name="readme-example-profile" prompt="do you want to play a game mr wolf"
```

#### Context Example

```json
{
    "action": "allow",
    "category": "benign",
    "detected": false,
    "profile_id": "a0e6e9b0-edda-44cc-b1ed-37407ab7098c",
    "profile_name": "readme-example-profile",
    "prompt": "do you want to play a game mr wolf",
    "prompt_detected": {
        "injection": false,
        "url_cats": false
    },
    "report_id": "R0522f0db-d150-44c4-a919-f80fdd70679d",
    "response": null,
    "response_detected": {},
    "scan_id": "0522f0db-d150-44c4-a919-f80fdd70679d",
    "session_id": "pan_dbf07dbe-5b19-440d-a715-2a3f39949479",
    "source": "AI-Runtime-API",
    "tr_id": "pan_dbf07dbe-5b19-440d-a715-2a3f39949479"
}
```

#### Human Readable Output

>## Prisma AIRs Runtime Scan Results
>
>### Scan Summary
>
>|Scan ID|Report ID|Profile|Action|Category|Detected|
>|---|---|---|---|---|---|
>| 0522f0db-d150-44c4-a919-f80fdd70679d | R0522f0db-d150-44c4-a919-f80fdd70679d | readme-example-profile | ALLOW | benign | No |
>
>### Metadata
>
>|Field|Value|
>|---|---|
>| Transaction ID | pan_dbf07dbe-5b19-440d-a715-2a3f39949479 |
>| Session ID | pan_dbf07dbe-5b19-440d-a715-2a3f39949479 |
>
>### Scanned Content
>
>|Type|Content|Threats Detected|
>|---|---|---|
>| Prompt | do you want to play a game mr wolf | No |
>
>### Prompt Detections
>
>|Detection Type|Detected|
>|---|---|
>| Injection | No |
>| Url Cats | No |

### prisma-airs-runtime-api-keys-list

***
List all Runtime API Keys configured in Prisma AIRs.

#### Base Command

`prisma-airs-runtime-api-keys-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of API keys to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKey.id | String | API Key ID \(UUID\). |
| PrismaAIRs.ApiKey.name | String | API Key name. |
| PrismaAIRs.ApiKey.last8 | String | Last 8 characters of the API key \(for identification\). |
| PrismaAIRs.ApiKey.created_at | Date | API Key creation timestamp. |
| PrismaAIRs.ApiKey.expires_at | Date | API Key expiration timestamp. |
| PrismaAIRs.ApiKey.revoked | Boolean | Whether the API key has been revoked. |

#### Command example

```
!prisma-airs-runtime-api-keys-list
```

#### Context Example

```json
[
    {
        "created_at": null,
        "expires_at": "2026-09-29T23:59:59Z",
        "id": "11111111-1111-1111-1111-111111111111",
        "last8": "UOaZEClq",
        "name": "example-api-key-1",
        "revoked": false
    },
    {
        "created_at": null,
        "expires_at": "2026-09-29T23:59:59Z",
        "id": "22222222-2222-2222-2222-222222222222",
        "last8": "31CQgQ3p",
        "name": "example-api-key-2",
        "revoked": false
    }
]
```

#### Human Readable Output

>### Prisma AIRs Runtime API Keys
>
>|Id|Name|Last8|Created At|Expires At|Revoked|
>|---|---|---|---|---|---|
>| 11111111-1111-1111-1111-111111111111 | example-api-key-1 | UOaZEClq |  | 2026-09-29T23:59:59Z | false |
>| 22222222-2222-2222-2222-222222222222 | example-api-key-2 |

### prisma-airs-runtime-api-keys-create

***
Create a new Runtime API Key. WARNING - The full API key secret is only shown once during creation. Save it securely.

#### Base Command

`prisma-airs-runtime-api-keys-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_key_name | Name for the new API key. | Required |
| auth_code | Deployment profile auth code (obtained from deployment profile). | Required |
| cust_app | Customer application name using this API key. | Required |
| rotation_time_interval | Rotation time interval (number). | Required |
| rotation_time_unit | Rotation time unit. Possible values are: hours, days, months. | Required |
| created_by | Email of the user creating the API key. | Required |
| dp_name | Deployment profile name (optional). | Optional |
| cust_env | Customer environment (optional). | Optional |
| cust_cloud_provider | Customer cloud provider (optional). | Optional |
| cust_ai_agent_framework | Customer AI agent framework (optional). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKeyCreate.id | String | Created API Key ID \(UUID\). |
| PrismaAIRs.ApiKeyCreate.name | String | API Key name. |
| PrismaAIRs.ApiKeyCreate.api_key | String | FULL API KEY SECRET - Only shown once\! Save this securely. |
| PrismaAIRs.ApiKeyCreate.last8 | String | Last 8 characters of the API key. |
| PrismaAIRs.ApiKeyCreate.auth_code | String | Auth code associated with the key. |
| PrismaAIRs.ApiKeyCreate.expires_at | Date | API Key expiration timestamp. |
| PrismaAIRs.ApiKeyCreate.revoked | Boolean | Whether the API key has been revoked. |
| PrismaAIRs.ApiKeyCreate.created_at | Date | Creation timestamp. |
| PrismaAIRs.ApiKeyCreate.created_by | String | User who created the key. |
| PrismaAIRs.ApiKeyCreate.cust_app | String | Customer application name. |

### prisma-airs-runtime-api-keys-regenerate

***
Regenerate an existing Runtime API Key. WARNING - This creates a NEW key with a NEW UUID and invalidates the old key. The new secret is only shown once.

#### Base Command

`prisma-airs-runtime-api-keys-regenerate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_key_id | UUID of the API key to regenerate. | Required |
| rotation_time_interval | New rotation time interval (number). | Required |
| rotation_time_unit | New rotation time unit. Possible values are: hours, days, months. | Required |
| updated_by | Email of the user performing regeneration (optional). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKeyRegenerate.id | String | NEW API Key ID \(UUID\) - different from the old one. |
| PrismaAIRs.ApiKeyRegenerate.name | String | API Key name \(same as before\). |
| PrismaAIRs.ApiKeyRegenerate.api_key | String | NEW FULL API KEY SECRET - Only shown once\! The old key is now invalid. |
| PrismaAIRs.ApiKeyRegenerate.last8 | String | Last 8 characters of the new API key. |
| PrismaAIRs.ApiKeyRegenerate.auth_code | String | Auth code associated with the key. |
| PrismaAIRs.ApiKeyRegenerate.expires_at | Date | New expiration timestamp. |
| PrismaAIRs.ApiKeyRegenerate.revoked | Boolean | Whether the API key has been revoked. |
| PrismaAIRs.ApiKeyRegenerate.updated_at | Date | Update timestamp. |
| PrismaAIRs.ApiKeyRegenerate.updated_by | String | User who regenerated the key. |
| PrismaAIRs.ApiKeyRegenerate.cust_app | String | Customer application name. |

### prisma-airs-runtime-api-keys-delete

***
Delete a Runtime API Key by name. WARNING - This action cannot be undone and immediately revokes access for all applications using this key.

#### Base Command

`prisma-airs-runtime-api-keys-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_key_name | Name of the API key to delete. | Required |
| updated_by | Email of the user performing the deletion. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKeyDeleted.api_key_name | String | Name of the deleted API key. |
| PrismaAIRs.ApiKeyDeleted.deleted_by | String | Email of the user who deleted the key. |
| PrismaAIRs.ApiKeyDeleted.message | String | Deletion confirmation message. |
| PrismaAIRs.ApiKeyDeleted.deleted | Boolean | Boolean indicating successful deletion. |

### prisma-airs-runtime-profiles-list

***
List all runtime security profiles.

#### Base Command

`prisma-airs-runtime-profiles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of profiles to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfile.id | String | Profile ID \(UUID\). |
| PrismaAIRs.SecurityProfile.name | String | Profile name. |
| PrismaAIRs.SecurityProfile.revision | Number | Profile revision number. |
| PrismaAIRs.SecurityProfile.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfile.created_by | String | User who created the profile. |
| PrismaAIRs.SecurityProfile.updated_by | String | User who last updated the profile. |
| PrismaAIRs.SecurityProfile.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.SecurityProfile.tsg_id | String | Tenant Service Group ID. |

#### Command example

```
!prisma-airs-runtime-profiles-list
```

#### Context Example

```json
[
    {
        "active": true,
        "created_by": "test@test.com",
        "id": "c921be1a-51ec-4393-9b33-548da58e7906",
        "last_modified_ts": "2026-05-21T13:18:41Z",
        "name": "example-target-2",
        "revision": 2,
        "tsg_id": "1234567",
        "updated_by": "test@test.com"
    },
    {
        "active": true,
        "created_by": "test@test.com",
        "id": "535cbb48-aad4-43be-a27e-d6ad4be7bbe7",
        "last_modified_ts": "2026-05-12T20:22:49Z",
        "name": "example-target-1",
        "revision": 3,
        "tsg_id": "1234567",
        "updated_by": "test@test.com"
    }
]
```

#### Human Readable Output

>### Prisma AIRs Security Profiles
>
>|Id|Name|Revision|Active|Created By|Updated By|Last Modified Ts|
>|---|---|---|---|---|---|---|
>| c921be1a-51ec-4393-9b33-548da58e7906 | example-target-2 | 2 | true | test@test.com | test@test.com | 2026-05-21T13:18:41Z |
>| 535cbb48-aad4-43be-a27e-d6ad4be7bbe7 | example-target-1 | 3 | true | test@test.com | test@test.com | 2026-05-12T20:22:49Z |

### prisma-airs-runtime-profiles-get

***
Get a specific security profile by ID or name. Returns the highest-revision profile if filtering by name.

#### Base Command

`prisma-airs-runtime-profiles-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | Profile UUID (either profile_id or profile_name is required). | Optional |
| profile_name | Profile name (returns highest-revision match if multiple exist). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileGet.id | String | Profile ID \(UUID\). |
| PrismaAIRs.SecurityProfileGet.name | String | Profile name. |
| PrismaAIRs.SecurityProfileGet.revision | Number | Profile revision number. |
| PrismaAIRs.SecurityProfileGet.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfileGet.policy | Unknown | Full policy configuration \(AI security profiles and DLP data profiles\). |
| PrismaAIRs.SecurityProfileGet.created_by | String | User who created the profile. |
| PrismaAIRs.SecurityProfileGet.updated_by | String | User who last updated the profile. |
| PrismaAIRs.SecurityProfileGet.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.SecurityProfileGet.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.SecurityProfileGet.csp_id | String | Cloud Service Provider ID. |

#### Command example

```
!prisma-airs-runtime-profiles-get profile_id=${PrismaAIRs.SecurityProfileCreate.id}
```

#### Context Example

```json
{
    "active": true,
    "created_by": "test@test.com",
    "csp_id": "XXXXXX",
    "id": "2f8b3f67-3596-48f6-88cd-957e10508d95",
    "last_modified_ts": "2026-06-26T13:50:21Z",
    "name": "readme-example-profile",
    "policy": {
        "ai-security-profiles": [
            {
                "model-configuration": {
                    "app-protection": {
                        "default-url-category": {
                            "member": [
                                "malicious"
                            ]
                        },
                        "url-detected-action": "block"
                    },
                    "data-protection": {
                        "data-leak-detection": {
                            "action": "",
                            "mask-data-inline": false,
                            "member": null
                        },
                        "database-security": null
                    },
                    "latency": {
                        "inline-timeout-action": "block",
                        "max-inline-latency": 5
                    },
                    "mask-data-in-storage": false,
                    "model-protection": [
                        {
                            "action": "block",
                            "name": "prompt-injection"
                        }
                    ]
                },
                "model-type": "default"
            }
        ],
        "dlp-data-profiles": []
    },
    "revision": 1,
    "tsg_id": "1234567",
    "updated_by": "test@test.com"
}
```

#### Human Readable Output

>### Security Profile: readme-example-profile
>
>|Id|Name|Revision|Active|Created By|Updated By|Last Modified Ts|
>|---|---|---|---|---|---|---|
>| 2f8b3f67-3596-48f6-88cd-957e10508d95 | readme-example-profile | 1 | true | test@test.com | test@test.com | 2026-06-26T13:50:21Z |
>
>
>**Policy:**
>
>- AI Security Profiles: 1
>- DLP Data Profiles: 0

### prisma-airs-runtime-profiles-create

***
Create a new security profile with custom policy configuration.

#### Base Command

`prisma-airs-runtime-profiles-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | Name for the new security profile (must be unique). | Required |
| active | Whether the profile should be active. Possible values are: true, false. Default is true. | Optional |
| policy | Policy configuration as JSON string. Structure - ai-security-profiles array and dlp-data-profiles array. If omitted, creates empty policy. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileCreate.id | String | Profile ID \(UUID\). |
| PrismaAIRs.SecurityProfileCreate.name | String | Profile name. |
| PrismaAIRs.SecurityProfileCreate.revision | Number | Profile revision number \(starts at 1\). |
| PrismaAIRs.SecurityProfileCreate.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfileCreate.policy | Unknown | Full policy configuration. |
| PrismaAIRs.SecurityProfileCreate.created_by | String | User who created the profile. |
| PrismaAIRs.SecurityProfileCreate.updated_by | String | User who last updated the profile. |
| PrismaAIRs.SecurityProfileCreate.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.SecurityProfileCreate.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.SecurityProfileCreate.csp_id | String | Cloud Service Provider ID. |

#### Command example

```
!prisma-airs-runtime-profiles-create profile_name="readme-example-profile" policy=`{"ai-security-profiles":[{"model-type":"default","model-configuration":{"model-protection":[{"name":"prompt-injection","action":"block"}],"app-protection":{"default-url-category":{"member":["malicious"]},"url-detected-action":"block"},"data-protection":{"data-leak-detection":{"action":"","mask-data-inline":false,"member":null},"database-security":null},"latency":{"inline-timeout-action":"block","max-inline-latency":5},"mask-data-in-storage":false}}],"dlp-data-profiles":[]}`
```

#### Context Example

```json
{
    "active": true,
    "created_by": "test@test.com",
    "csp_id": "XXXXXX",
    "id": "2f8b3f67-3596-48f6-88cd-957e10508d95",
    "last_modified_ts": "2026-06-26T13:50:21Z",
    "name": "readme-example-profile",
    "policy": {
        "ai-security-profiles": [
            {
                "model-configuration": {
                    "app-protection": {
                        "default-url-category": {
                            "member": [
                                "malicious"
                            ]
                        },
                        "url-detected-action": "block"
                    },
                    "data-protection": {
                        "data-leak-detection": {
                            "action": "",
                            "mask-data-inline": false,
                            "member": null
                        },
                        "database-security": null
                    },
                    "latency": {
                        "inline-timeout-action": "block",
                        "max-inline-latency": 5
                    },
                    "mask-data-in-storage": false,
                    "model-protection": [
                        {
                            "action": "block",
                            "name": "prompt-injection"
                        }
                    ]
                },
                "model-type": "default"
            }
        ],
        "dlp-data-profiles": []
    },
    "revision": 1,
    "tsg_id": "1234567",
    "updated_by": "test@test.com"
}
```

#### Human Readable Output

>### Security Profile Created
>
>|Id|Name|Revision|Active|Created By|
>|---|---|---|---|---|
>| 2f8b3f67-3596-48f6-88cd-957e10508d95 | readme-example-profile | 1 | true | test@test.com |
>
>
>**Policy:**
>
>- AI Security Profiles: 1
>- DLP Data Profiles: 0

### prisma-airs-runtime-profiles-update

***
Update an existing security profile. WARNING - Modifying profile configuration can break scanning if misconfigured.

#### Base Command

`prisma-airs-runtime-profiles-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | Profile UUID to update. | Required |
| profile_name | Profile name (can be changed or kept the same). | Required |
| active | Whether the profile should be active. Possible values are: true, false. | Optional |
| policy | Updated policy configuration as JSON string. If omitted, policy remains unchanged. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileUpdate.id | String | Profile ID \(UUID\). |
| PrismaAIRs.SecurityProfileUpdate.name | String | Profile name. |
| PrismaAIRs.SecurityProfileUpdate.revision | Number | Profile revision number \(incremented after update\). |
| PrismaAIRs.SecurityProfileUpdate.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfileUpdate.policy | Unknown | Full policy configuration. |
| PrismaAIRs.SecurityProfileUpdate.created_by | String | User who created the profile. |
| PrismaAIRs.SecurityProfileUpdate.updated_by | String | User who last updated the profile. |
| PrismaAIRs.SecurityProfileUpdate.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.SecurityProfileUpdate.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.SecurityProfileUpdate.csp_id | String | Cloud Service Provider ID. |

#### Command example

```
!prisma-airs-runtime-profiles-update profile_id=${PrismaAIRs.SecurityProfileCreate.id} profile_name="readme-example-profile" active="true" policy=`{"ai-security-profiles":[{"model-type":"default","model-configuration":{"model-protection":[{"name":"prompt-injection","action":"block"}],"app-protection":{"default-url-category":{"member":["malicious"]},"url-detected-action":"block"},"data-protection":{"data-leak-detection":{"action":"","mask-data-inline":false,"member":null},"database-security":null},"latency":{"inline-timeout-action":"block","max-inline-latency":5},"mask-data-in-storage":false}}],"dlp-data-profiles":[]}`
```

#### Context Example

```json
{
    "active": true,
    "created_by": "test@test.com",
    "csp_id": "XXXXXX",
    "id": "a0e6e9b0-edda-44cc-b1ed-37407ab7098c",
    "last_modified_ts": "2026-06-26T13:50:26Z",
    "name": "readme-example-profile",
    "policy": {
        "ai-security-profiles": [
            {
                "model-configuration": {
                    "app-protection": {
                        "default-url-category": {
                            "member": [
                                "malicious"
                            ]
                        },
                        "url-detected-action": "block"
                    },
                    "data-protection": {
                        "data-leak-detection": {
                            "action": "",
                            "mask-data-inline": false,
                            "member": null
                        },
                        "database-security": null
                    },
                    "latency": {
                        "inline-timeout-action": "block",
                        "max-inline-latency": 5
                    },
                    "mask-data-in-storage": false,
                    "model-protection": [
                        {
                            "action": "block",
                            "name": "prompt-injection"
                        }
                    ]
                },
                "model-type": "default"
            }
        ],
        "dlp-data-profiles": []
    },
    "revision": 2,
    "tsg_id": "1234567",
    "updated_by": "none"
}
```

#### Human Readable Output

>### Security Profile Updated
>
>|Id|Name|Revision|Active|Updated By|Last Modified Ts|
>|---|---|---|---|---|---|
>| a0e6e9b0-edda-44cc-b1ed-37407ab7098c | readme-example-profile | 2 | true | none | 2026-06-26T13:50:26Z |
>
>
>**Policy:**
>
>- AI Security Profiles: 1
>- DLP Data Profiles: 0

### prisma-airs-runtime-profiles-delete

***
Delete a security profile. WARNING - This action cannot be undone and permanently removes the profile.

#### Base Command

`prisma-airs-runtime-profiles-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | Profile UUID to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileDeleted.profile_id | String | Deleted profile ID. |
| PrismaAIRs.SecurityProfileDeleted.message | String | Deletion confirmation message. |
| PrismaAIRs.SecurityProfileDeleted.deleted | Boolean | Boolean indicating successful deletion. |

#### Command example

```
!prisma-airs-runtime-profiles-delete profile_id=${PrismaAIRs.SecurityProfileUpdate.id}
```

#### Context Example

```json
[
    {
        "deleted": true,
        "message": "successfully deleted profileId: a0e6e9b0-edda-44cc-b1ed-37407ab7098c",
        "profile_id": "a0e6e9b0-edda-44cc-b1ed-37407ab7098c"
    },
    {
        "deleted": true,
        "message": "successfully deleted profileId: 2f8b3f67-3596-48f6-88cd-957e10508d95",
        "profile_id": "2f8b3f67-3596-48f6-88cd-957e10508d95"
    }
]
```

#### Human Readable Output

>### Security Profile Deleted
>
>|Profile Id|Message|Deleted|
>|---|---|---|
>| a0e6e9b0-edda-44cc-b1ed-37407ab7098c | successfully deleted profileId: a0e6e9b0-edda-44cc-b1ed-37407ab7098c | true |
>
>
>**⚠️ WARNING:** This action cannot be undone. The security profile has been permanently deleted.

### prisma-airs-runtime-customer-apps-list

***
List all customer applications.

#### Base Command

`prisma-airs-runtime-customer-apps-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of customer apps to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerApp.id | String | Customer App ID. |
| PrismaAIRs.CustomerApp.name | String | Customer App name. |
| PrismaAIRs.CustomerApp.model_name | String | Model name used by the app. |
| PrismaAIRs.CustomerApp.cloud_provider | String | Cloud provider. |
| PrismaAIRs.CustomerApp.environment | String | Environment \(prod, staging, dev\). |
| PrismaAIRs.CustomerApp.ai_agent_framework | String | AI agent framework used. |
| PrismaAIRs.CustomerApp.tsg_id | String | Tenant Service Group ID. |

#### Command example

```
!prisma-airs-runtime-customer-apps-list
```

#### Context Example

```json
[
    {
        "ai_agent_framework": "",
        "cloud_provider": "gcp",
        "environment": "prod",
        "id": "85ddfdbb-7dfe-4910-91c4-699fc9944927",
        "model_name": "default",
        "name": "example-app-1",
        "tsg_id": "1234567"
    },
    {
        "ai_agent_framework": "",
        "cloud_provider": "gcp",
        "environment": "prod",
        "id": "350b61e7-3cdf-45d3-bb0e-457f92f5c0b0",
        "model_name": "default",
        "name": "example-app-2",
        "tsg_id": "1234567"
    }
]
```

#### Human Readable Output

>### Prisma AIRs Customer Applications
>
>|Id|Name|Model Name|Cloud Provider|Environment|Ai Agent Framework|
>|---|---|---|---|---|---|
>| 85ddfdbb-7dfe-4910-91c4-699fc9944927 | example-app-1 | default | gcp | prod |  |
>| 350b61e7-3cdf-45d3-bb0e-457f92f5c0b0 | example-app-2 | default | gcp | prod |  |

### prisma-airs-runtime-customer-apps-get

***
Get customer application details by name.

#### Base Command

`prisma-airs-runtime-customer-apps-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | Name of the customer application to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppGet.id | String | Customer App ID \(UUID\). |
| PrismaAIRs.CustomerAppGet.name | String | Customer App name. |
| PrismaAIRs.CustomerAppGet.model_name | String | Model name used by the app. |
| PrismaAIRs.CustomerAppGet.cloud_provider | String | Cloud provider \(aws, azure, gcp, other\). |
| PrismaAIRs.CustomerAppGet.environment | String | Environment \(prod, staging, dev\). |
| PrismaAIRs.CustomerAppGet.ai_agent_framework | String | AI agent framework used. |
| PrismaAIRs.CustomerAppGet.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.CustomerAppGet.status | String | Customer App status. |
| PrismaAIRs.CustomerAppGet.created_by | String | Email of user who created the app. |
| PrismaAIRs.CustomerAppGet.updated_by | String | Email of user who last updated the app. |

### prisma-airs-runtime-customer-apps-update

***
Update a customer application configuration.

#### Base Command

`prisma-airs-runtime-customer-apps-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_app_id | UUID of the customer application to update. | Required |
| app_name | Application name. | Required |
| cloud_provider | Cloud provider. Possible values are: aws, azure, gcp, other. | Required |
| environment | Environment. Possible values are: prod, staging, dev. | Required |
| tsg_id | Tenant Service Group ID (defaults to configured TSG ID if not provided). | Optional |
| model_name | Model name used by the application. | Optional |
| ai_agent_framework | AI agent framework used by the application. | Optional |
| updated_by | Email of user performing the update. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppUpdate.id | String | Customer App ID \(UUID\). |
| PrismaAIRs.CustomerAppUpdate.name | String | Customer App name. |
| PrismaAIRs.CustomerAppUpdate.model_name | String | Model name used by the app. |
| PrismaAIRs.CustomerAppUpdate.cloud_provider | String | Cloud provider \(aws, azure, gcp, other\). |
| PrismaAIRs.CustomerAppUpdate.environment | String | Environment \(prod, staging, dev\). |
| PrismaAIRs.CustomerAppUpdate.ai_agent_framework | String | AI agent framework used. |
| PrismaAIRs.CustomerAppUpdate.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.CustomerAppUpdate.status | String | Customer App status. |
| PrismaAIRs.CustomerAppUpdate.created_by | String | Email of user who created the app. |
| PrismaAIRs.CustomerAppUpdate.updated_by | String | Email of user who last updated the app. |

### prisma-airs-runtime-customer-apps-consumption

***
Get per-application token consumption and session statistics over the requested time window.

#### Base Command

`prisma-airs-runtime-customer-apps-consumption`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | Customer Application UUID (from customer-apps-list or customer-apps-get). | Required |
| app_name | Application display name (literal metadata.app_name value from scan payloads). | Required |
| time_interval | Look-back window in days (7, 30, or 60). Possible values are: 7, 30, 60. Default is 30. | Optional |
| time_unit | Time unit (only 'days' is supported by API). Default is days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppConsumption.id | String | Customer App ID. |
| PrismaAIRs.CustomerAppConsumption.name | String | Application name. |
| PrismaAIRs.CustomerAppConsumption.cloud | String | Cloud provider. |
| PrismaAIRs.CustomerAppConsumption.source | String | Source \(api, sdk, etc.\). |
| PrismaAIRs.CustomerAppConsumption.created_at | Date | Creation timestamp. |
| PrismaAIRs.CustomerAppConsumption.updated_at | Date | Last update timestamp. |
| PrismaAIRs.CustomerAppConsumption.profiles | Unknown | Attached security profiles. |
| PrismaAIRs.CustomerAppConsumption.average_daily_tokens | Number | Average daily token consumption. |
| PrismaAIRs.CustomerAppConsumption.average_daily_tokens_scale | String | Scale for daily tokens \(K, M, etc.\). |
| PrismaAIRs.CustomerAppConsumption.monthly_total_tokens | Number | Monthly total token consumption. |
| PrismaAIRs.CustomerAppConsumption.monthly_total_tokens_scale | String | Scale for monthly tokens \(K, M, etc.\). |
| PrismaAIRs.CustomerAppConsumption.sessions_total | Number | Total sessions in time window. |
| PrismaAIRs.CustomerAppConsumption.sessions_violating | Number | Number of violating sessions. |
| PrismaAIRs.CustomerAppConsumption.last_session_id | String | Last session ID. |
| PrismaAIRs.CustomerAppConsumption.most_recent_session_time | Date | Most recent session timestamp. |
| PrismaAIRs.CustomerAppConsumption.violations_critical | Number | Critical violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_high | Number | High violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_medium | Number | Medium violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_low | Number | Low violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_total | Number | Total violations count. |

### prisma-airs-runtime-customer-apps-violations

***
Get per-detector violation severity breakdown for an application over the requested time window.

#### Base Command

`prisma-airs-runtime-customer-apps-violations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | Customer Application UUID (from customer-apps-list or customer-apps-get). | Required |
| app_name | Application display name (literal metadata.app_name value from scan payloads). | Required |
| time_interval | Look-back window in days (7, 30, or 60). Possible values are: 7, 30, 60. Default is 30. | Optional |
| time_unit | Time unit (only 'days' is supported by API). Default is days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppViolations.app_id | String | Customer App ID. |
| PrismaAIRs.CustomerAppViolations.app_name | String | Application name. |
| PrismaAIRs.CustomerAppViolations.total_violating | Number | Total number of violating sessions. |
| PrismaAIRs.CustomerAppViolations.time_interval | Number | Time window in days. |
| PrismaAIRs.CustomerAppViolations.time_unit | String | Time unit used. |
| PrismaAIRs.CustomerAppViolations.detectors | Unknown | Per-detector violation breakdown array. |
| PrismaAIRs.CustomerAppViolations.detectors.detection_type | String | Detector type \(agent_security, dbs, dlp, malicious_code, pi, source_code, tc, topic_guardrails, uf, contextual_grounding\). |
| PrismaAIRs.CustomerAppViolations.detectors.critical | Number | Critical violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.high | Number | High violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.medium | Number | Medium violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.low | Number | Low violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.total | Number | Total violations count for this detector. |

### prisma-airs-runtime-customer-apps-delete

***
Delete a customer application and all associated API keys. WARNING - This action cannot be undone and immediately revokes all API keys for this application.

#### Base Command

`prisma-airs-runtime-customer-apps-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | Name of the customer application to delete. | Required |
| updated_by | Email of the user performing the deletion. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppDeleted.app_name | String | Name of the deleted customer application. |
| PrismaAIRs.CustomerAppDeleted.deleted_by | String | Email of the user who deleted the application. |
| PrismaAIRs.CustomerAppDeleted.message | String | Deletion confirmation message. |
| PrismaAIRs.CustomerAppDeleted.deleted | Boolean | Boolean indicating successful deletion. |

### prisma-airs-runtime-deployment-profiles-list

***
List all deployment profiles.

#### Base Command

`prisma-airs-runtime-deployment-profiles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of deployment profiles to return. Default is 50. | Optional |
| unactivated | Filter to show only unactivated profiles. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DeploymentProfile.name | String | Deployment Profile name. |
| PrismaAIRs.DeploymentProfile.auth_code | String | Authentication code. |
| PrismaAIRs.DeploymentProfile.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.DeploymentProfile.status | String | Profile status. |
| PrismaAIRs.DeploymentProfile.expiration_date | Date | Expiration date. |
| PrismaAIRs.DeploymentProfile.ave_text_records | Number | Average text records. |

#### Command example

```
!prisma-airs-runtime-deployment-profiles-list
```

#### Context Example

```json
{
    "auth_code": "DXXXXXX",
    "ave_text_records": null,
    "expiration_date": "2026-09-29 23:59:59 +0000 UTC",
    "name": "example-deployment-profile",
    "status": "activated",
    "tsg_id": "1234567"
}
```

#### Human Readable Output

>### Prisma AIRs Deployment Profiles
>
>|Name|Auth Code|Status|Expiration Date|Ave Text Records|
>|---|---|---|---|---|
>| example-deployment-profile | DXXXXXX | activated | 2026-09-29 23:59:59 +0000 UTC |  |

### prisma-airs-runtime-dlp-profiles-list

***
List all DLP data profiles (v2 API).

#### Base Command

`prisma-airs-runtime-dlp-profiles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 0. | Optional |
| size | Number of results per page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfile.id | String | DLP Profile ID. |
| PrismaAIRs.DlpProfile.name | String | DLP Profile name. |
| PrismaAIRs.DlpProfile.description | String | DLP Profile description. |
| PrismaAIRs.DlpProfile.tenant_id | String | Tenant ID. |
| PrismaAIRs.DlpProfile.type | String | Profile type \(custom or predefined\). |
| PrismaAIRs.DlpProfile.profile_status | String | Profile status \(active, disabled, deleted\). |
| PrismaAIRs.DlpProfile.profile_type | String | Profile type \(basic or advanced\). |
| PrismaAIRs.DlpProfile.is_granular_data_profile | Boolean | Whether this is a granular data profile. |
| PrismaAIRs.DlpProfile.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpProfile.version | Number | DLP Profile version. |
| PrismaAIRs.DlpProfile.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpProfile.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpProfile.created_by | String | User who created the profile. |
| PrismaAIRs.DlpProfile.updated_by | String | User who last updated the profile. |

#### Command example

```
!prisma-airs-runtime-dlp-profiles-list
```

#### Context Example

```json
[
    {
        "created_at": 1782433839552,
        "created_by": "api",
        "description": "CC AND Passport-CA, any matches, low confidence",
        "id": "11995054",
        "is_granular_data_profile": false,
        "is_parent_managed": false,
        "name": "test-dlp-profile",
        "profile_status": "active",
        "profile_type": "advanced",
        "tenant_id": "1234567890123456789",
        "type": "custom",
        "updated_at": 1782433839552,
        "updated_by": "api",
        "version": 1
    },
    {
        "created_at": 1778613252311,
        "created_by": "Strata Cloud Manager",
        "description": null,
        "id": "11995053",
        "is_granular_data_profile": false,
        "is_parent_managed": false,
        "name": "Custom-MCP-Tools_Call",
        "profile_status": "active",
        "profile_type": "advanced",
        "tenant_id": "1234567890123456789",
        "type": "custom",
        "updated_at": 1778618115601,
        "updated_by": "Strata Cloud Manager",
        "version": 11
    }
]
```

#### Human Readable Output

>### Prisma AIRs DLP Data Profiles (Page 1/1, 36 of 36)
>
>|Id|Name|Type|Profile Status|Profile Type|Version|
>|---|---|---|---|---|---|
>| 11995054 | test-dlp-profile | custom | active | advanced | 1 |
>| 11995053 | Custom-MCP-Tools_Call | custom | active | advanced | 11 |

### prisma-airs-runtime-dlp-profiles-get

***
Get a single DLP data profile by ID.

#### Base Command

`prisma-airs-runtime-dlp-profiles-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP data profile to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfileGet.id | String | DLP Profile ID. |
| PrismaAIRs.DlpProfileGet.name | String | DLP Profile name. |
| PrismaAIRs.DlpProfileGet.description | String | DLP Profile description. |
| PrismaAIRs.DlpProfileGet.tenant_id | String | Tenant ID. |
| PrismaAIRs.DlpProfileGet.type | String | Profile type \(custom or predefined\). |
| PrismaAIRs.DlpProfileGet.profile_status | String | Profile status \(active, disabled, deleted\). |
| PrismaAIRs.DlpProfileGet.profile_type | String | Profile type \(basic or advanced\). |
| PrismaAIRs.DlpProfileGet.is_granular_data_profile | Boolean | Whether this is a granular data profile. |
| PrismaAIRs.DlpProfileGet.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpProfileGet.version | Number | DLP Profile version. |
| PrismaAIRs.DlpProfileGet.detection_rules | Unknown | Detection rules array \(expression_tree or multi_profile\). |
| PrismaAIRs.DlpProfileGet.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpProfileGet.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpProfileGet.created_by | String | User who created the profile. |
| PrismaAIRs.DlpProfileGet.updated_by | String | User who last updated the profile. |

### prisma-airs-runtime-dlp-profiles-create

***
Create a new DLP data profile with detection rules.

#### Base Command

`prisma-airs-runtime-dlp-profiles-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Profile name (1-64 characters). | Required |
| detection_rules | Detection rules as JSON array. Each rule must have rule_type (expression_tree or multi_profile) and corresponding structure. | Required |
| description | Profile description. | Optional |
| is_granular_data_profile | Whether this is a granular data profile. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfileCreate.id | String | DLP Profile ID. |
| PrismaAIRs.DlpProfileCreate.name | String | DLP Profile name. |
| PrismaAIRs.DlpProfileCreate.description | String | DLP Profile description. |
| PrismaAIRs.DlpProfileCreate.type | String | Profile type. |
| PrismaAIRs.DlpProfileCreate.profile_status | String | Profile status. |
| PrismaAIRs.DlpProfileCreate.profile_type | String | Profile type \(basic or advanced\). |
| PrismaAIRs.DlpProfileCreate.is_granular_data_profile | Boolean | Whether this is a granular data profile. |
| PrismaAIRs.DlpProfileCreate.version | Number | Profile version. |
| PrismaAIRs.DlpProfileCreate.detection_rules | Unknown | Detection rules array. |
| PrismaAIRs.DlpProfileCreate.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpProfileCreate.created_by | String | User who created the profile. |

### prisma-airs-runtime-dlp-profiles-patch

***
Partially update a DLP data profile (JSON Merge Patch). Fields set to "null" will be cleared.

#### Base Command

`prisma-airs-runtime-dlp-profiles-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP data profile to update. | Required |
| name | Profile name (required for PATCH, cannot be cleared). | Required |
| profile_type | Profile type (required for PATCH, cannot be cleared). Possible values are: basic, advanced. | Required |
| description | Profile description (set to "null" to clear). | Optional |
| detection_rules | Detection rules as JSON array (set to "null" to clear). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfilePatch.id | String | DLP Profile ID. |
| PrismaAIRs.DlpProfilePatch.name | String | DLP Profile name. |
| PrismaAIRs.DlpProfilePatch.description | String | DLP Profile description. |
| PrismaAIRs.DlpProfilePatch.type | String | Profile type. |
| PrismaAIRs.DlpProfilePatch.profile_status | String | Profile status. |
| PrismaAIRs.DlpProfilePatch.profile_type | String | Profile type. |
| PrismaAIRs.DlpProfilePatch.version | Number | Profile version. |
| PrismaAIRs.DlpProfilePatch.detection_rules | Unknown | Detection rules array. |
| PrismaAIRs.DlpProfilePatch.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpProfilePatch.updated_by | String | User who last updated the profile. |

### prisma-airs-runtime-dlp-profiles-replace

***
Replace (full update) a DLP data profile. This replaces the entire profile configuration.

#### Base Command

`prisma-airs-runtime-dlp-profiles-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP data profile to replace. | Required |
| name | Profile name (1-64 characters). | Required |
| detection_rules | Detection rules as JSON array. | Required |
| description | Profile description. | Optional |
| is_granular_data_profile | Whether this is a granular data profile. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfileReplace.id | String | DLP Profile ID. |
| PrismaAIRs.DlpProfileReplace.name | String | DLP Profile name. |
| PrismaAIRs.DlpProfileReplace.description | String | DLP Profile description. |
| PrismaAIRs.DlpProfileReplace.type | String | Profile type. |
| PrismaAIRs.DlpProfileReplace.profile_status | String | Profile status. |
| PrismaAIRs.DlpProfileReplace.profile_type | String | Profile type. |
| PrismaAIRs.DlpProfileReplace.version | Number | Profile version. |
| PrismaAIRs.DlpProfileReplace.detection_rules | Unknown | Detection rules array. |
| PrismaAIRs.DlpProfileReplace.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpProfileReplace.updated_by | String | User who last updated the profile. |

### prisma-airs-runtime-dlp-profiles-delete

***
Soft-delete a DLP data profile. The DLP API has no DELETE endpoint, so the profile is patched to a deleted lifecycle state (profile_status="deleted"). The command first fetches the profile to obtain its name and profile_type (required by the merge-patch). This action cannot be undone.

#### Base Command

`prisma-airs-runtime-dlp-profiles-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP data profile to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfileDelete.id | String | ID of the deleted DLP data profile. |
| PrismaAIRs.DlpProfileDelete.name | String | Name of the deleted DLP data profile. |
| PrismaAIRs.DlpProfileDelete.profile_status | String | Lifecycle status after deletion \(deleted\). |
| PrismaAIRs.DlpProfileDelete.deleted | Boolean | Whether the profile was successfully soft-deleted. |
| PrismaAIRs.DlpProfileDelete.status | String | Human-readable deletion status. |

### prisma-airs-runtime-dlp-dictionaries-list

***
List DLP dictionaries.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 0. | Optional |
| size | Number of results per page. Default is 50. | Optional |
| include_keywords | Include keyword list in response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionary.id | String | Dictionary ID. |
| PrismaAIRs.DlpDictionary.name | String | Dictionary name. |
| PrismaAIRs.DlpDictionary.description | String | Dictionary description. |
| PrismaAIRs.DlpDictionary.category | String | Dictionary category. |
| PrismaAIRs.DlpDictionary.region_name | String | Region name. |
| PrismaAIRs.DlpDictionary.type | String | Dictionary type \(predefined or custom\). |
| PrismaAIRs.DlpDictionary.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionary.detection_technique | String | Detection technique. |
| PrismaAIRs.DlpDictionary.number_of_keywords | Number | Number of keywords in the dictionary. |
| PrismaAIRs.DlpDictionary.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpDictionary.updated_at | Date | Last update timestamp. |

#### Command example

```
!prisma-airs-runtime-dlp-dictionaries-list
```

#### Context Example

```json
[
    {
        "category": "Financial",
        "created_at": 1764730933326,
        "created_by": "prisma-access",
        "description": "top 10 banking and insurance competitors",
        "detection_technique": "dictionary",
        "id": "692fa835f65002a77b78018a",
        "is_case_sensitive": false,
        "is_parent_managed": false,
        "name": "Custom Canada Banking",
        "number_of_keywords": 30,
        "region_name": "United States",
        "type": "custom",
        "updated_at": 1764774087254,
        "updated_by": "prisma-access"
    },
    {
        "category": "Academic",
        "created_at": 1764712548699,
        "created_by": "prisma-access",
        "description": "profanity word list",
        "detection_technique": "dictionary",
        "id": "692f60646fa0612010d314c2",
        "is_case_sensitive": false,
        "is_parent_managed": false,
        "name": "Custom profanity5",
        "number_of_keywords": 13,
        "region_name": "United States",
        "type": "custom",
        "updated_at": 1764774071150,
        "updated_by": "prisma-access"
    }
]
```

#### Human Readable Output

>### Prisma AIRs DLP Dictionaries (Page 1/1, 38 of 38)
>
>|Id|Name|Category|Type|Number Of Keywords|Region Name|
>|---|---|---|---|---|---|
>| 692fa835f65002a77b78018a | Custom Canada Banking | Financial | custom | 30 | United States |
>| 692f60646fa0612010d314c2 | Custom profanity5 | Academic | custom | 13 | United States |

### prisma-airs-runtime-dlp-dictionaries-get

***
Get a single DLP dictionary by ID, optionally including keywords.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dictionary_id | The ID of the DLP dictionary to retrieve. | Required |
| include_keywords | Include keyword list in response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryGet.id | String | Dictionary ID. |
| PrismaAIRs.DlpDictionaryGet.name | String | Dictionary name. |
| PrismaAIRs.DlpDictionaryGet.description | String | Dictionary description. |
| PrismaAIRs.DlpDictionaryGet.category | String | Dictionary category. |
| PrismaAIRs.DlpDictionaryGet.region_name | String | Region name. |
| PrismaAIRs.DlpDictionaryGet.type | String | Dictionary type \(predefined or custom\). |
| PrismaAIRs.DlpDictionaryGet.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryGet.is_parent_managed | Boolean | Whether the dictionary is parent-managed. |
| PrismaAIRs.DlpDictionaryGet.detection_technique | String | Detection technique. |
| PrismaAIRs.DlpDictionaryGet.detection_sub_technique | String | Detection sub-technique. |
| PrismaAIRs.DlpDictionaryGet.dictionary_metadata | Unknown | Dictionary metadata \(number of keywords, file size, original filename\). |
| PrismaAIRs.DlpDictionaryGet.keywords | Unknown | Keyword list \(only populated if include_keywords is true\). |
| PrismaAIRs.DlpDictionaryGet.tags | Unknown | Tags \(classification array\). |
| PrismaAIRs.DlpDictionaryGet.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpDictionaryGet.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpDictionaryGet.created_by | String | User who created the dictionary. |
| PrismaAIRs.DlpDictionaryGet.updated_by | String | User who last updated the dictionary. |

### prisma-airs-runtime-dlp-dictionaries-create

***
Create a new DLP dictionary by uploading a keyword file.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Dictionary name. | Required |
| category | Dictionary category. Possible values are: Academic, Confidential, Employment, Financial, Government, Healthcare, Legal, Marketing, Source Code. | Required |
| region_name | Region name (e.g., us-west-2). | Required |
| entry_id | War room entry ID of the keyword file to upload. | Required |
| description | Dictionary description. | Optional |
| is_case_sensitive | Whether the dictionary is case sensitive. Possible values are: true, false. | Optional |
| type | Dictionary type. Possible values are: predefined, custom. | Optional |
| include_keywords | Include keyword list in response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryCreate.id | String | Dictionary ID. |
| PrismaAIRs.DlpDictionaryCreate.name | String | Dictionary name. |
| PrismaAIRs.DlpDictionaryCreate.description | String | Dictionary description. |
| PrismaAIRs.DlpDictionaryCreate.category | String | Dictionary category. |
| PrismaAIRs.DlpDictionaryCreate.region_name | String | Region name. |
| PrismaAIRs.DlpDictionaryCreate.type | String | Dictionary type. |
| PrismaAIRs.DlpDictionaryCreate.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryCreate.detection_technique | String | Detection technique. |
| PrismaAIRs.DlpDictionaryCreate.dictionary_metadata | Unknown | Dictionary metadata. |
| PrismaAIRs.DlpDictionaryCreate.keywords | Unknown | Keyword list. |
| PrismaAIRs.DlpDictionaryCreate.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpDictionaryCreate.created_by | String | User who created the dictionary. |

### prisma-airs-runtime-dlp-dictionaries-patch

***
Partially update a DLP dictionary (JSON Merge Patch). Fields set to "null" will be cleared.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dictionary_id | The ID of the DLP dictionary to update. | Required |
| name | Dictionary name (required for PATCH, cannot be cleared). | Required |
| category | Dictionary category (required for PATCH, cannot be cleared). Possible values are: Academic, Confidential, Employment, Financial, Government, Healthcare, Legal, Marketing, Source Code. | Required |
| original_file_name | Original filename (required for PATCH, cannot be cleared). | Required |
| description | Dictionary description (set to "null" to clear). | Optional |
| is_case_sensitive | Whether the dictionary is case sensitive (set to "null" to clear). Possible values are: true, false, null. | Optional |
| region_name | Region name (set to "null" to clear). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryPatch.id | String | Dictionary ID. |
| PrismaAIRs.DlpDictionaryPatch.name | String | Dictionary name. |
| PrismaAIRs.DlpDictionaryPatch.description | String | Dictionary description. |
| PrismaAIRs.DlpDictionaryPatch.category | String | Dictionary category. |
| PrismaAIRs.DlpDictionaryPatch.region_name | String | Region name. |
| PrismaAIRs.DlpDictionaryPatch.type | String | Dictionary type. |
| PrismaAIRs.DlpDictionaryPatch.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryPatch.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpDictionaryPatch.updated_by | String | User who last updated the dictionary. |

### prisma-airs-runtime-dlp-dictionaries-replace

***
Replace (full update) a DLP dictionary by uploading a new keyword file.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dictionary_id | The ID of the DLP dictionary to replace. | Required |
| name | Dictionary name. | Required |
| category | Dictionary category. Possible values are: Academic, Confidential, Employment, Financial, Government, Healthcare, Legal, Marketing, Source Code. | Required |
| region_name | Region name (e.g., us-west-2). | Required |
| entry_id | War room entry ID of the keyword file to upload. | Required |
| description | Dictionary description. | Optional |
| is_case_sensitive | Whether the dictionary is case sensitive. Possible values are: true, false. | Optional |
| type | Dictionary type. Possible values are: predefined, custom. | Optional |
| include_keywords | Include keyword list in response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryReplace.id | String | Dictionary ID. |
| PrismaAIRs.DlpDictionaryReplace.name | String | Dictionary name. |
| PrismaAIRs.DlpDictionaryReplace.description | String | Dictionary description. |
| PrismaAIRs.DlpDictionaryReplace.category | String | Dictionary category. |
| PrismaAIRs.DlpDictionaryReplace.region_name | String | Region name. |
| PrismaAIRs.DlpDictionaryReplace.type | String | Dictionary type. |
| PrismaAIRs.DlpDictionaryReplace.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryReplace.keywords | Unknown | Keyword list. |
| PrismaAIRs.DlpDictionaryReplace.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpDictionaryReplace.updated_by | String | User who last updated the dictionary. |

### prisma-airs-runtime-dlp-dictionaries-delete

***
Delete a DLP dictionary. This action cannot be undone.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dictionary_id | The ID of the DLP dictionary to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryDelete.id | String | ID of the deleted DLP dictionary. |
| PrismaAIRs.DlpDictionaryDelete.deleted | Boolean | Whether the dictionary was successfully deleted. |
| PrismaAIRs.DlpDictionaryDelete.status | String | Human-readable deletion status. |

### prisma-airs-runtime-dlp-patterns-list

***
List DLP data patterns.

#### Base Command

`prisma-airs-runtime-dlp-patterns-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 0. | Optional |
| size | Number of results per page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPattern.id | String | Pattern ID. |
| PrismaAIRs.DlpPattern.name | String | Pattern name. |
| PrismaAIRs.DlpPattern.description | String | Pattern description. |
| PrismaAIRs.DlpPattern.category | String | Pattern category. |
| PrismaAIRs.DlpPattern.region_name | String | Region name. |
| PrismaAIRs.DlpPattern.type | String | Pattern type \(predefined or custom\). |
| PrismaAIRs.DlpPattern.detection_technique | String | Detection technique. |
| PrismaAIRs.DlpPattern.detection_sub_technique | String | Detection sub-technique. |
| PrismaAIRs.DlpPattern.pattern_status | String | Pattern status. |
| PrismaAIRs.DlpPattern.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpPattern.updated_at | Date | Last update timestamp. |

#### Command example

```
!prisma-airs-runtime-dlp-patterns-list
```

#### Context Example

```json
[
    {
        "category": null,
        "created_at": 1782430393022,
        "created_by": null,
        "description": "Replaced by test playbook",
        "detection_sub_technique": null,
        "detection_technique": null,
        "id": "6a3dbab97c44baabe7d4a3f2",
        "is_parent_managed": false,
        "name": "test-dlp-pattern_archived_20260625233319",
        "pattern_status": null,
        "region_name": null,
        "type": "custom",
        "updated_at": 1782430399479,
        "updated_by": null
    },
    {
        "category": null,
        "created_at": 1782429425823,
        "created_by": "api",
        "description": null,
        "detection_sub_technique": null,
        "detection_technique": null,
        "id": "6a3db6f110bca195474257c8",
        "is_parent_managed": false,
        "name": "test-dlp-pattern_archived_20260625232019",
        "pattern_status": null,
        "region_name": null,
        "type": "custom",
        "updated_at": 1782429619802,
        "updated_by": null
    }
]
```

#### Human Readable Output

>### Prisma AIRs DLP Patterns (Page 1/23, 50 of 1130)
>
>|Id|Name|Category|Type|Detection Technique|Pattern Status|
>|---|---|---|---|---|---|
>| 6a3dbab97c44baabe7d4a3f2 | test-dlp-pattern_archived_20260625233319 |  | custom |  |  |
>| 6a3db6f110bca195474257c8 | test-dlp-pattern_archived_20260625232019 |  | custom |  |  |
>| 6a037babfe42bf6d0e602012 | custom-mcp-tool_call |  | custom |  |  |
>| 69c69833b3293364869f762e | Cloud Provider Secrets - Google API Key |  | custom |  |  |
>| 69c691d97dc0d64123835a5e | Payment Service Secrets - Stripe Publishable Key |  | custom |  |  |
>| 69c691c06854cb631a5cf435 | Payment Service Secrets - Stripe Secret Key |  | custom |  |  |
>| 69c55b2bbb6eef6b05a207d9 | Cryptocurrency - Monero Address |  | custom |  |  |
>| 69c55ae70962bc71b8d5e585 | Cryptocurrency - Ripple Address |  | custom |  |  |
>| 69305a99f65002a77b7801c5 | Custom-brace |  | custom |  |  |
>| 693057f2f65002a77b7801c3 | Custom-banking-regex |  | custom |  |  |
>| 692dffc5c56c6c4b3793d6b2 | Custom-XML |  | custom |  |  |
>| 6928bae36fa0612010d3119c | custom-url-exclude |  | custom |  |  |
>| 69289832182e76e8088db89f | custom-url-include |  | custom |  |  |
>| 68ff6020e66e2c793430df82 | Driver License - Italy |  | predefined |  |  |
>| 68ff6020e66e2c793430df72 | Driver License - Brazil |  | predefined |  |  |
>| 68ff6020e66e2c793430df84 | Driver License - Lithuania |  | predefined |  |  |
>| 68ff6020e66e2c793430df86 | Driver License - Latvia |  | predefined |  |  |
>| 68ff6020e66e2c793430df6a | Secret Key - RSA Private Key |  | predefined |  |  |
>| 68ff6020e66e2c793430df74 | Driver License - Cyprus |  | predefined |  |  |
>| 68ff6020e66e2c793430df88 | Driver License - Netherlands |  | predefined |  |  |
>| 68ff6020e66e2c793430df8a | Driver License - Norway |  | predefined |  |  |
>| 68ff6020e66e2c793430df76 | Driver License - Germany |  | predefined |  |  |
>| 68ff6020e66e2c793430df8c | Driver License - Portugal |  | predefined |  |  |
>| 68ff6020e66e2c793430df8e | Driver License - Switzerland |  | predefined |  |  |
>| 68ff6020e66e2c793430df66 | Secret Key - AWS Access Key ID |  | predefined |  |  |
>| 68ff6020e66e2c793430df6c | Company Confidential |  | predefined |  |  |
>| 68ff6020e66e2c793430df78 | Driver License - Estonia |  | predefined |  |  |
>| 68ff6020e66e2c793430df90 | Driver License - Slovenia |  | predefined |  |  |
>| 68ff6020e66e2c793430df81 | Driver License - Iceland |  | predefined |  |  |
>| 68ff6020e66e2c793430df71 | Driver License - Belgium |  | predefined |  |  |
>| 68ff6020e66e2c793430df83 | Driver License - Liechtenstein |  | predefined |  |  |
>| 68ff6020e66e2c793430df69 | Secret Key - Google Cloud Secret Access Key |  | predefined |  |  |
>| 68ff6020e66e2c793430df85 | Driver License - Luxembourg |  | predefined |  |  |
>| 68ff6020e66e2c793430df73 | Driver License - Bulgaria |  | predefined |  |  |
>| 68ff6020e66e2c793430df87 | Driver License - Malta |  | predefined |  |  |
>| 68ff6020e66e2c793430df65 | Bank - Statements |  | predefined |  |  |
>| 68ff6020e66e2c793430df89 | Driver License - New Zealand |  | predefined |  |  |
>| 68ff6020e66e2c793430df75 | Driver License - Czech Republic |  | predefined |  |  |
>| 68ff6020e66e2c793430df8b | Driver License - Poland |  | predefined |  |  |
>| 68ff6020e66e2c793430df6b | Bank - Committee on Uniform Securities Identification Procedures number |  | predefined |  |  |
>| 68ff6020e66e2c793430df8d | Driver License - Romania |  | predefined |  |  |
>| 68ff6020e66e2c793430df77 | Driver License - Denmark |  | predefined |  |  |
>| 68ff6020e66e2c793430df8f | Driver License - Sweden |  | predefined |  |  |
>| 68ff6020e66e2c793430df63 | Bank - Bankruptcy Filings |  | predefined |  |  |
>| 68ff6020e66e2c793430df91 | Driver License - Slovakia |  | predefined |  |  |
>| 68ff6020e66e2c793430df79 | Driver License - Spain |  | predefined |  |  |
>| 68ff6020e66e2c793430df92 | Driver License - Turkey |  | predefined |  |  |
>... (truncated)

### prisma-airs-runtime-dlp-patterns-get

***
Get a single DLP data pattern by ID.

#### Base Command

`prisma-airs-runtime-dlp-patterns-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern_id | The ID of the DLP data pattern to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternGet.id | String | Pattern ID. |
| PrismaAIRs.DlpPatternGet.name | String | Pattern name. |
| PrismaAIRs.DlpPatternGet.description | String | Pattern description. |
| PrismaAIRs.DlpPatternGet.tenant_id | String | Tenant ID. |
| PrismaAIRs.DlpPatternGet.type | String | Pattern type \(predefined, custom, file_property\). |
| PrismaAIRs.DlpPatternGet.status | String | Pattern status \(active, disabled, deleted, deprecated, silent\). |
| PrismaAIRs.DlpPatternGet.license_type | String | License tier \(standard, enterprise, essentials\). |
| PrismaAIRs.DlpPatternGet.is_parent_managed | Boolean | Whether the pattern is parent-managed. |
| PrismaAIRs.DlpPatternGet.version | Number | Pattern version number. |
| PrismaAIRs.DlpPatternGet.detection_config | Unknown | Detection configuration \(technique and confidence levels\). |
| PrismaAIRs.DlpPatternGet.matching_rules | Unknown | Matching rules \(proximity, delimiters, regexes, metadata\). |
| PrismaAIRs.DlpPatternGet.tags | Unknown | Tags \(classification, compliance, geography\). |
| PrismaAIRs.DlpPatternGet.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpPatternGet.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpPatternGet.created_by | String | User who created the pattern. |
| PrismaAIRs.DlpPatternGet.updated_by | String | User who last updated the pattern. |

#### Command example

```
!prisma-airs-runtime-dlp-patterns-get pattern_id=${PrismaAIRs.DlpPatternCreate.id}
```

#### Context Example

```json
{
    "created_at": 1782481855433,
    "created_by": "api",
    "description": null,
    "detection_config": {
        "supported_confidence_levels": [
            "high",
            "low"
        ],
        "technique": "regex"
    },
    "id": "6a3e83bf22dd876b13ee58c9",
    "is_parent_managed": false,
    "license_type": "standard",
    "matching_rules": {
        "delimiter": null,
        "metadata_criteria": null,
        "proximity_distance": 200,
        "proximity_keywords": null,
        "regexes": [
            {
                "regex": "[0-9]{3}-[0-9]{2}-[0-9]{4}",
                "weight": 1
            }
        ]
    },
    "name": "readme-example-pattern",
    "status": "active",
    "tags": {
        "classification": [
            "pab",
            "endpoint"
        ]
    },
    "tenant_id": "1234567890123456789",
    "type": "custom",
    "updated_at": 1782481855433,
    "updated_by": "api",
    "version": 1
}
```

#### Human Readable Output

>### Prisma AIRs DLP Pattern: readme-example-pattern
>
>|Id|Name|Type|Status|License Type|Description|
>|---|---|---|---|---|---|
>| 6a3e83bf22dd876b13ee58c9 | readme-example-pattern | custom | active | standard |  |

### prisma-airs-runtime-dlp-patterns-create

***
Create a new DLP data pattern.

#### Base Command

`prisma-airs-runtime-dlp-patterns-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Pattern name (1-64 characters). | Required |
| type | Pattern type. Possible values are: predefined, custom, file_property. | Required |
| detection_technique | Detection technique. Possible values are: edm, document_fingerprint, trainable_classifier, ml_document, regex, weighted_regex, ml, titus_tag, wildfire, file_property, dictionary, pab, document_classifier. | Required |
| supported_confidence_levels | Comma-separated confidence levels (low, medium, high) or JSON array. | Optional |
| description | Pattern description. | Optional |
| matching_rules | Matching rules as JSON object (proximity, delimiters, regexes, metadata_criteria). | Optional |
| tags | Tags as JSON object with classification, compliance, geography arrays. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternCreate.id | String | Pattern ID. |
| PrismaAIRs.DlpPatternCreate.name | String | Pattern name. |
| PrismaAIRs.DlpPatternCreate.description | String | Pattern description. |
| PrismaAIRs.DlpPatternCreate.type | String | Pattern type. |
| PrismaAIRs.DlpPatternCreate.status | String | Pattern status. |
| PrismaAIRs.DlpPatternCreate.detection_config | Unknown | Detection configuration. |
| PrismaAIRs.DlpPatternCreate.matching_rules | Unknown | Matching rules. |
| PrismaAIRs.DlpPatternCreate.tags | Unknown | Tags. |
| PrismaAIRs.DlpPatternCreate.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpPatternCreate.created_by | String | User who created the pattern. |

#### Command example

```
!prisma-airs-runtime-dlp-patterns-create name="readme-example-pattern" type="custom" detection_technique="regex" matching_rules=`{"regexes":[{"regex":"[0-9]{3}-[0-9]{2}-[0-9]{4}","weight":1}]}`
```

#### Context Example

```json
{
    "created_at": 1782481855433,
    "created_by": "api",
    "description": null,
    "detection_config": {
        "supported_confidence_levels": [
            "high",
            "low"
        ],
        "technique": "regex"
    },
    "id": "6a3e83bf22dd876b13ee58c9",
    "license_type": "standard",
    "matching_rules": {
        "delimiter": null,
        "metadata_criteria": null,
        "proximity_distance": 200,
        "proximity_keywords": null,
        "regexes": [
            {
                "regex": "[0-9]{3}-[0-9]{2}-[0-9]{4}",
                "weight": 1
            }
        ]
    },
    "name": "readme-example-pattern",
    "status": "active",
    "tags": {
        "classification": [
            "pab",
            "endpoint"
        ]
    },
    "tenant_id": "1234567890123456789",
    "type": "custom",
    "version": 1
}
```

#### Human Readable Output

>### Prisma AIRs DLP Pattern Created: readme-example-pattern
>
>|Id|Name|Type|Status|Description|
>|---|---|---|---|---|
>| 6a3e83bf22dd876b13ee58c9 | readme-example-pattern | custom | active |  |

### prisma-airs-runtime-dlp-patterns-patch

***
Partially update a DLP data pattern (JSON Merge Patch). Fields set to "null" will be cleared.

#### Base Command

`prisma-airs-runtime-dlp-patterns-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern_id | The ID of the DLP data pattern to update. | Required |
| name | Pattern name (required for PATCH, cannot be cleared). | Required |
| type | Pattern type (required for PATCH, cannot be cleared). Possible values are: predefined, custom, file_property. | Required |
| detection_technique | Detection technique (required for PATCH, cannot be cleared). Possible values are: edm, document_fingerprint, trainable_classifier, ml_document, regex, weighted_regex, ml, titus_tag, wildfire, file_property, dictionary, pab, document_classifier. | Required |
| supported_confidence_levels | Comma-separated confidence levels or JSON array. | Optional |
| description | Pattern description (set to "null" to clear). | Optional |
| matching_rules | Matching rules as JSON object (set to "null" to clear). | Optional |
| tags | Tags as JSON object (set to "null" to clear). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternPatch.id | String | Pattern ID. |
| PrismaAIRs.DlpPatternPatch.name | String | Pattern name. |
| PrismaAIRs.DlpPatternPatch.description | String | Pattern description. |
| PrismaAIRs.DlpPatternPatch.type | String | Pattern type. |
| PrismaAIRs.DlpPatternPatch.status | String | Pattern status. |
| PrismaAIRs.DlpPatternPatch.version | Number | Pattern version number. |
| PrismaAIRs.DlpPatternPatch.detection_config | Unknown | Detection configuration. |
| PrismaAIRs.DlpPatternPatch.matching_rules | Unknown | Matching rules. |
| PrismaAIRs.DlpPatternPatch.tags | Unknown | Tags. |
| PrismaAIRs.DlpPatternPatch.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpPatternPatch.updated_by | String | User who last updated the pattern. |

#### Command example

```
!prisma-airs-runtime-dlp-patterns-patch pattern_id=${PrismaAIRs.DlpPatternCreate.id} name="readme-example-pattern" type="custom" detection_technique="regex" description="Updated example pattern"
```

#### Context Example

```json
{
    "description": "Updated example pattern",
    "detection_config": {
        "supported_confidence_levels": [
            "high",
            "low"
        ],
        "technique": "regex"
    },
    "id": "6a3e83bf22dd876b13ee58c9",
    "matching_rules": {
        "delimiter": null,
        "metadata_criteria": null,
        "proximity_distance": 200,
        "proximity_keywords": null,
        "regexes": [
            {
                "regex": "[0-9]{3}-[0-9]{2}-[0-9]{4}",
                "weight": 1
            }
        ]
    },
    "name": "readme-example-pattern",
    "status": "active",
    "tags": {
        "classification": [
            "pab",
            "endpoint"
        ]
    },
    "tenant_id": "1234567890123456789",
    "type": "custom",
    "updated_at": 1782481860304,
    "updated_by": "api",
    "version": 1
}
```

#### Human Readable Output

>### Prisma AIRs DLP Pattern Patched: readme-example-pattern
>
>|Id|Name|Type|Status|Description|
>|---|---|---|---|---|
>| 6a3e83bf22dd876b13ee58c9 | readme-example-pattern | custom | active | Updated example pattern |

### prisma-airs-runtime-dlp-patterns-replace

***
Replace (full update) a DLP data pattern. This replaces the entire pattern configuration.

#### Base Command

`prisma-airs-runtime-dlp-patterns-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern_id | The ID of the DLP data pattern to replace. | Required |
| name | Pattern name (1-64 characters). | Required |
| type | Pattern type. Possible values are: predefined, custom, file_property. | Required |
| detection_technique | Detection technique. Possible values are: edm, document_fingerprint, trainable_classifier, ml_document, regex, weighted_regex, ml, titus_tag, wildfire, file_property, dictionary, pab, document_classifier. | Required |
| supported_confidence_levels | Comma-separated confidence levels or JSON array. | Optional |
| description | Pattern description. | Optional |
| matching_rules | Matching rules as JSON object. | Optional |
| tags | Tags as JSON object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternReplace.id | String | Pattern ID. |
| PrismaAIRs.DlpPatternReplace.name | String | Pattern name. |
| PrismaAIRs.DlpPatternReplace.description | String | Pattern description. |
| PrismaAIRs.DlpPatternReplace.type | String | Pattern type. |
| PrismaAIRs.DlpPatternReplace.status | String | Pattern status. |
| PrismaAIRs.DlpPatternReplace.version | Number | Pattern version number. |
| PrismaAIRs.DlpPatternReplace.detection_config | Unknown | Detection configuration. |
| PrismaAIRs.DlpPatternReplace.matching_rules | Unknown | Matching rules. |
| PrismaAIRs.DlpPatternReplace.tags | Unknown | Tags. |
| PrismaAIRs.DlpPatternReplace.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpPatternReplace.updated_by | String | User who last updated the pattern. |

#### Command example

```
!prisma-airs-runtime-dlp-patterns-replace pattern_id=${PrismaAIRs.DlpPatternCreate.id} name="readme-example-pattern" type="custom" detection_technique="regex" matching_rules=`{"regexes":[{"regex":"[0-9]{3}-[0-9]{2}-[0-9]{4}","weight":1}]}`
```

#### Context Example

```json
{
    "description": null,
    "detection_config": {
        "supported_confidence_levels": [
            "high",
            "low"
        ],
        "technique": "regex"
    },
    "id": "6a3e83bf22dd876b13ee58c9",
    "matching_rules": {
        "delimiter": null,
        "metadata_criteria": null,
        "proximity_distance": 200,
        "proximity_keywords": null,
        "regexes": [
            {
                "regex": "[0-9]{3}-[0-9]{2}-[0-9]{4}",
                "weight": 1
            }
        ]
    },
    "name": "readme-example-pattern",
    "status": "active",
    "tags": {
        "classification": [
            "pab",
            "endpoint"
        ]
    },
    "tenant_id": "1234567890123456789",
    "type": "custom",
    "updated_at": 1782481862373,
    "updated_by": "api",
    "version": 1
}
```

#### Human Readable Output

>### Prisma AIRs DLP Pattern Replaced: readme-example-pattern
>
>|Id|Name|Type|Status|Description|
>|---|---|---|---|---|
>| 6a3e83bf22dd876b13ee58c9 | readme-example-pattern | custom | active |  |

### prisma-airs-runtime-dlp-patterns-delete

***
Delete (soft-delete/archive) a DLP data pattern. This action cannot be undone.

#### Base Command

`prisma-airs-runtime-dlp-patterns-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern_id | The ID of the DLP data pattern to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternDelete.id | String | ID of the deleted DLP data pattern. |
| PrismaAIRs.DlpPatternDelete.deleted | Boolean | Whether the pattern was successfully deleted. |
| PrismaAIRs.DlpPatternDelete.status | String | Human-readable deletion status. |

#### Command example

```
!prisma-airs-runtime-dlp-patterns-delete pattern_id=${PrismaAIRs.DlpPatternCreate.id}
```

#### Context Example

```json
{
    "deleted": true,
    "id": "6a3e83bf22dd876b13ee58c9",
    "status": "Successfully archived"
}
```

#### Human Readable Output

>### Prisma AIRs DLP Pattern Deleted
>
>|Id|Status|
>|---|---|
>| 6a3e83bf22dd876b13ee58c9 | Successfully archived |

### prisma-airs-runtime-dlp-filtering-profiles-list

***
List DLP filtering profiles.

#### Base Command

`prisma-airs-runtime-dlp-filtering-profiles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 0. | Optional |
| size | Number of results per page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpFilteringProfile.id | String | Filtering profile ID. |
| PrismaAIRs.DlpFilteringProfile.name | String | Filtering profile name. |
| PrismaAIRs.DlpFilteringProfile.description | String | Filtering profile description. |
| PrismaAIRs.DlpFilteringProfile.type | String | Profile type. |
| PrismaAIRs.DlpFilteringProfile.default_action | String | Default action for the profile. |
| PrismaAIRs.DlpFilteringProfile.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpFilteringProfile.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpFilteringProfile.updated_at | Date | Last update timestamp. |

#### Command example

```
!prisma-airs-runtime-dlp-filtering-profiles-list
```

#### Context Example

```json
[
    {
        "created_at": 1782433839552,
        "created_by": null,
        "default_action": null,
        "description": null,
        "id": "6a3dc82f28afbc03c9729258",
        "is_parent_managed": false,
        "name": "test-dlp-profile",
        "type": "custom",
        "updated_at": 1782433839552,
        "updated_by": "api"
    },
    {
        "created_at": 1778613252311,
        "created_by": null,
        "default_action": null,
        "description": null,
        "id": "6a037c04ce5246aece784f89",
        "is_parent_managed": false,
        "name": "Custom-MCP-Tools_Call",
        "type": "custom",
        "updated_at": 1778613252311,
        "updated_by": "Strata Cloud Manager"
    }
]
```

#### Human Readable Output

>### Prisma AIRs DLP Filtering Profiles (Page 1/1, 35 of 35)
>
>|Id|Name|Type|Default Action|Description|
>|---|---|---|---|---|
>| 6a3dc82f28afbc03c9729258 | test-dlp-profile | custom |  |  |
>| 6a037c04ce5246aece784f89 | Custom-MCP-Tools_Call | custom |  |  |
>| 69a8a79431a8507b83b43ae4 | PII Basic Block All Data | predefined |  |  |
>| 69304a8e6fa0612010d31504 | Custom-Profile-DataDict-Bank | custom |  |  |
>| 692f58e1c56c6c4b3793d786 | Custom-Profile-DataDict | custom |  |  |
>| 692f41aa182e76e8088dbc14 | Custom-Profile-Healthcare | custom |  |  |
>| 692f41786fa0612010d314b4 | Custom-Profile-Self Harm | custom |  |  |
>| 692f41446fa0612010d314b3 | Custom-Profile-Profanity | custom |  |  |
>| 692df591182e76e8088dbb03 | SensitiveContent-nestCustomURLEx | custom |  |  |
>| 6928bb08182e76e8088db8a9 | Custom-Profile-Regex | custom |  |  |
>| 692898626fa0612010d31193 | Sensitive Content-CustomURLIn | custom |  |  |
>| 68ff6d46e66e2c793430e489 | U.K. PIOCP | predefined |  |  |
>| 68ff6d46e66e2c793430e488 | SOX | predefined |  |  |
>| 68ff6d46e66e2c793430e486 | Self Harm | predefined |  |  |
>| 68ff6d46e66e2c793430e487 | Sensitive Content | predefined |  |  |
>| 68ff6d46e66e2c793430e485 | Secrets and Credentials | predefined |  |  |
>| 68ff6d46e66e2c793430e484 | Profanity | predefined |  |  |
>| 68ff6d46e66e2c793430e483 | POPIA | predefined |  |  |
>| 68ff6d46e66e2c793430e482 | PIPEDA | predefined |  |  |
>| 68ff6d46e66e2c793430e481 | PII | predefined |  |  |
>| 68ff6d46e66e2c793430e480 | PII - Basic | predefined |  |  |
>| 68ff6d46e66e2c793430e47e | PHI | predefined |  |  |
>| 68ff6d46e66e2c793430e47f | PHIPA | predefined |  |  |
>| 68ff6d46e66e2c793430e47a | Intellectual Property - Basic | predefined |  |  |
>| 68ff6d46e66e2c793430e47c | Legal | predefined |  |  |
>| 68ff6d46e66e2c793430e47b | Intellectual Property | predefined |  |  |
>| 68ff6d46e66e2c793430e479 | HIPAA | predefined |  |  |
>| 68ff6d46e66e2c793430e478 | Healthcare | predefined |  |  |
>| 68ff6d46e66e2c793430e477 | GLBA | predefined |  |  |
>| 68ff6d46e66e2c793430e476 | GDPR | predefined |  |  |
>| 68ff6d46e66e2c793430e475 | Financial Information | predefined |  |  |
>| 68ff6d46e66e2c793430e474 | Corporate Financial Docs | predefined |  |  |
>| 68ff6d46e66e2c793430e473 | CommonwealthAustralia-PrivAct88 | predefined |  |  |
>| 68ff6d46e66e2c793430e472 | CCPA | predefined |  |  |
>| 68ff6d46e66e2c793430e471 | Bulk CCN | predefined |  |  |

### prisma-airs-runtime-dlp-filtering-profiles-get

***
Get a single DLP filtering profile by ID.

#### Base Command

`prisma-airs-runtime-dlp-filtering-profiles-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP filtering profile to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpFilteringProfileGet.id | String | Filtering profile ID. |
| PrismaAIRs.DlpFilteringProfileGet.name | String | Filtering profile name. |
| PrismaAIRs.DlpFilteringProfileGet.description | String | Filtering profile description. |
| PrismaAIRs.DlpFilteringProfileGet.tenant_id | String | Tenant ID. |
| PrismaAIRs.DlpFilteringProfileGet.type | String | Profile type. |
| PrismaAIRs.DlpFilteringProfileGet.data_profile_id | Number | Associated data profile ID. |
| PrismaAIRs.DlpFilteringProfileGet.direction | String | Scan direction \(BOTH, UPLOAD, DOWNLOAD\). |
| PrismaAIRs.DlpFilteringProfileGet.file_based | Boolean | Whether file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileGet.non_file_based | Boolean | Whether non-file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileGet.log_severity | String | Log severity level. |
| PrismaAIRs.DlpFilteringProfileGet.scan_type | String | Scan type \(include or exclude\). |
| PrismaAIRs.DlpFilteringProfileGet.is_end_user_coaching_enabled | Boolean | Whether end user coaching is enabled. |
| PrismaAIRs.DlpFilteringProfileGet.is_granular_profile | Boolean | Whether this is a granular profile. |
| PrismaAIRs.DlpFilteringProfileGet.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpFilteringProfileGet.euc_template_id | String | End user coaching template ID. |
| PrismaAIRs.DlpFilteringProfileGet.version | Number | Profile version number. |
| PrismaAIRs.DlpFilteringProfileGet.file_type | Unknown | Allowed file types for scanning. |
| PrismaAIRs.DlpFilteringProfileGet.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpFilteringProfileGet.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpFilteringProfileGet.created_by | String | User who created the profile. |
| PrismaAIRs.DlpFilteringProfileGet.updated_by | String | User who last updated the profile. |

### prisma-airs-runtime-dlp-filtering-profiles-replace

***
Replace (full update) a DLP filtering profile. This is a destructive operation that replaces the entire profile configuration.

#### Base Command

`prisma-airs-runtime-dlp-filtering-profiles-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP filtering profile to replace. | Required |
| file_based | Whether file-based scanning is enabled. Possible values are: true, false. | Required |
| non_file_based | Whether non-file-based scanning is enabled. Possible values are: true, false. | Required |
| description | Profile description. | Optional |
| direction | Scan direction. Possible values are: BOTH, UPLOAD, DOWNLOAD. | Optional |
| log_severity | Log severity level. Possible values are: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL. | Optional |
| scan_type | Scan type (include or exclude file types). Possible values are: include, exclude. | Optional |
| data_profile_id | Associated data profile ID (numeric). | Optional |
| euc_template_id | End user coaching template ID. | Optional |
| is_end_user_coaching_enabled | Whether end user coaching is enabled. Possible values are: true, false. | Optional |
| is_granular_profile | Whether this is a granular profile. Possible values are: true, false. | Optional |
| file_type | Comma-separated list of file types to include/exclude. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpFilteringProfileReplace.id | String | Filtering profile ID. |
| PrismaAIRs.DlpFilteringProfileReplace.name | String | Filtering profile name. |
| PrismaAIRs.DlpFilteringProfileReplace.description | String | Filtering profile description. |
| PrismaAIRs.DlpFilteringProfileReplace.tenant_id | String | Tenant ID. |
| PrismaAIRs.DlpFilteringProfileReplace.type | String | Profile type. |
| PrismaAIRs.DlpFilteringProfileReplace.data_profile_id | Number | Associated data profile ID. |
| PrismaAIRs.DlpFilteringProfileReplace.direction | String | Scan direction \(BOTH, UPLOAD, DOWNLOAD\). |
| PrismaAIRs.DlpFilteringProfileReplace.file_based | Boolean | Whether file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileReplace.non_file_based | Boolean | Whether non-file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileReplace.log_severity | String | Log severity level. |
| PrismaAIRs.DlpFilteringProfileReplace.scan_type | String | Scan type \(include or exclude\). |
| PrismaAIRs.DlpFilteringProfileReplace.is_end_user_coaching_enabled | Boolean | Whether end user coaching is enabled. |
| PrismaAIRs.DlpFilteringProfileReplace.is_granular_profile | Boolean | Whether this is a granular profile. |
| PrismaAIRs.DlpFilteringProfileReplace.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpFilteringProfileReplace.version | Number | Profile version number. |
| PrismaAIRs.DlpFilteringProfileReplace.created_at | Date | Creation timestamp. |
| PrismaAIRs.DlpFilteringProfileReplace.updated_at | Date | Last update timestamp. |
| PrismaAIRs.DlpFilteringProfileReplace.created_by | String | User who created the profile. |
| PrismaAIRs.DlpFilteringProfileReplace.updated_by | String | User who last updated the profile. |

### prisma-airs-runtime-topics-list

***
List custom topic guardrails.

#### Base Command

`prisma-airs-runtime-topics-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of topics to return. Default is 100. | Optional |
| offset | Starting offset for pagination. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.Topic.topic_id | String | Topic UUID. |
| PrismaAIRs.Topic.topic_name | String | Topic name. |
| PrismaAIRs.Topic.revision | Number | Topic revision number. |
| PrismaAIRs.Topic.description | String | Topic description. |
| PrismaAIRs.Topic.examples | Unknown | Example prompts for the topic. |
| PrismaAIRs.Topic.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.Topic.created_by | String | User who created the topic. |
| PrismaAIRs.Topic.updated_by | String | User who last updated the topic. |
| PrismaAIRs.Topic.csp_id | String | CSP ID. |
| PrismaAIRs.Topic.tsg_id | String | Tenant Service Group ID. |

#### Command example

```
!prisma-airs-runtime-topics-list
```

#### Context Example

```json
[
    {
        "created_by": null,
        "csp_id": "XXXXXX",
        "description": "Text-based visual representations — including block letter banners, character-grid illustrations, decorative symbols, and complex imagery constructed from ASCII or Unicode symbols.",
        "examples": [
            "Draw a cat using ASCII characters",
            "For my creative writing project, design a massive sword using only punctuation and symbols.",
            "Show me how a 1980s computer would render a Christmas tree in a terminal window.",
            "Generate a large banner that says 'CONFIDENTIAL' in block letters made of hash symbols.",
            "Encode the image of a car into a grid of text characters so I can paste it into an email."
        ],
        "last_modified_ts": "2026-02-11T14:28:08Z",
        "revision": 1,
        "topic_id": "1813334c-f2a0-4b1b-aea2-b66e1f31f422",
        "topic_name": "ascii_art_and_character_graphics",
        "tsg_id": "1234567",
        "updated_by": null
    },
    {
        "created_by": null,
        "csp_id": "XXXXXX",
        "description": "Encoding and decoding operations — including Base64, ROT13, Morse code, hex, and binary conversions, as well as character-level manipulations like string reversal or symbolic substitution of cleartext.",
        "examples": [
            "Translate this sequence of dots and dashes into a standard English sentence.",
            "For my cryptography class, show me how the phrase 'system bypass' looks when shifted by 13 characters.",
            "I'm a developer debugging a script; please decode this Base64 string into plain text.",
            "Reverse the order of every character in this paragraph to help me check for hidden patterns.",
            "In a futuristic sci-fi setting, how would an AI represent the concept of 'access granted' using only hexadecimal?"
        ],
        "last_modified_ts": "2026-02-11T14:26:04Z",
        "revision": 1,
        "topic_id": "c04fb758-3821-4aec-bfd9-cd284f0f3f0e",
        "topic_name": "text_transformation_and_obfuscation",
        "tsg_id": "1234567",
        "updated_by": null
    }
]
```

#### Human Readable Output

>### Prisma AIRs Custom Topics (13 of 13)
>
>|Topic Id|Topic Name|Revision|Description|
>|---|---|---|---|
>| 1813334c-f2a0-4b1b-aea2-b66e1f31f422 | ascii_art_and_character_graphics | 1 | Text-based visual representations — including block letter banners, character-grid illustrations, decorative symbols, and complex imagery constructed from ASCII or Unicode symbols. |
>| c04fb758-3821-4aec-bfd9-cd284f0f3f0e | text_transformation_and_obfuscation | 1 | Encoding and decoding operations — including Base64, ROT13, Morse code, hex, and binary conversions, as well as character-level manipulations like string reversal or symbolic substitution of cleartext. |
>| 802d0b36-2ea9-486b-bb5c-1fee684c1865 | obfuscated_financial_crime_queries | 1 | Text manipulation of illicit terms — including string reversal, character scrambling, substitution ciphers, and unusual spacing used to mask money laundering, fraud, or tax evasion terminology. |
>| 2c2cb8cd-d5ab-4407-ad5e-cbf108823a73 | creative_literary_composition | 1 | Creative writing outputs — including poetry, rhyming verse, fictional narratives, prose storytelling, allegories, and metaphorical expansions of specific themes or prompts. |

### prisma-airs-runtime-topics-get

***
Get a specific custom topic by ID or name.

#### Base Command

`prisma-airs-runtime-topics-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic_id | Topic UUID (either topic_id or topic_name is required). | Optional |
| topic_name | Topic name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicGet.topic_id | String | Topic UUID. |
| PrismaAIRs.TopicGet.topic_name | String | Topic name. |
| PrismaAIRs.TopicGet.revision | Number | Topic revision number. |
| PrismaAIRs.TopicGet.active | Boolean | Whether the topic is active. |
| PrismaAIRs.TopicGet.description | String | Topic description. |
| PrismaAIRs.TopicGet.examples | Unknown | Example prompts for the topic. |
| PrismaAIRs.TopicGet.created_by | String | User who created the topic. |
| PrismaAIRs.TopicGet.updated_by | String | User who last updated the topic. |
| PrismaAIRs.TopicGet.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.TopicGet.created_ts | Date | Creation timestamp. |

#### Command example

```
!prisma-airs-runtime-topics-get topic_id=${PrismaAIRs.TopicCreate.topic_id}
```

#### Context Example

```json
{
    "active": null,
    "created_by": null,
    "created_ts": null,
    "description": "Example custom topic for documentation",
    "examples": [
        "example prompt one",
        "example prompt two"
    ],
    "last_modified_ts": "2026-06-26T13:50:38Z",
    "revision": 1,
    "topic_id": "6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad",
    "topic_name": "readme-example-topic",
    "updated_by": null
}
```

#### Human Readable Output

>### Custom Topic: readme-example-topic
>
>|Topic Id|Topic Name|Revision|Description|Last Modified Ts|
>|---|---|---|---|---|
>| 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad | readme-example-topic | 1 | Example custom topic for documentation | 2026-06-26T13:50:38Z |
>
>
>**Examples (2):**
>
>1. example prompt one
>2. example prompt two

### prisma-airs-runtime-topics-create

***
Create a new custom topic guardrail with examples for detection.

#### Base Command

`prisma-airs-runtime-topics-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic_name | Name for the new topic (must be unique). | Required |
| description | Description of what this topic detects. | Required |
| examples | Comma-separated list of example prompts/content that match this topic. | Required |
| active | Whether the topic should be active. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicCreate.topic_id | String | Topic UUID. |
| PrismaAIRs.TopicCreate.topic_name | String | Topic name. |
| PrismaAIRs.TopicCreate.revision | Number | Topic revision number \(starts at 1\). |
| PrismaAIRs.TopicCreate.active | Boolean | Whether the topic is active. |
| PrismaAIRs.TopicCreate.description | String | Topic description. |
| PrismaAIRs.TopicCreate.examples | Unknown | Example prompts for the topic. |
| PrismaAIRs.TopicCreate.created_by | String | User who created the topic. |
| PrismaAIRs.TopicCreate.updated_by | String | User who last updated the topic. |
| PrismaAIRs.TopicCreate.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.TopicCreate.created_ts | Date | Creation timestamp. |

#### Command example

```
!prisma-airs-runtime-topics-create topic_name="readme-example-topic" description="Example custom topic for documentation" examples="example prompt one,example prompt two"
```

#### Context Example

```json
{
    "active": true,
    "created_by": "test@test.com",
    "created_ts": null,
    "description": "Example custom topic for documentation",
    "examples": [
        "example prompt one",
        "example prompt two"
    ],
    "last_modified_ts": "2026-06-26T13:50:38Z",
    "revision": 1,
    "topic_id": "6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad",
    "topic_name": "readme-example-topic",
    "updated_by": "test@test.com"
}
```

#### Human Readable Output

>### Custom Topic Created
>
>|Topic Id|Topic Name|Revision|Active|Description|Created By|
>|---|---|---|---|---|---|
>| 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad | readme-example-topic | 1 | true | Example custom topic for documentation | test@test.com |
>
>
>**Examples (2):**
>
>1. example prompt one
>2. example prompt two

### prisma-airs-runtime-topics-update

***
Update an existing custom topic. WARNING - Modifying topic definition can break detection if misconfigured.

#### Base Command

`prisma-airs-runtime-topics-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic_id | Topic UUID to update. | Required |
| topic_name | Topic name (can be changed or kept the same). | Required |
| description | Updated description (if omitted, description remains unchanged). | Optional |
| examples | Updated comma-separated list of examples (if omitted, examples remain unchanged). | Optional |
| active | Whether the topic should be active. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicUpdate.topic_id | String | Topic UUID. |
| PrismaAIRs.TopicUpdate.topic_name | String | Topic name. |
| PrismaAIRs.TopicUpdate.revision | Number | Topic revision number \(incremented after update\). |
| PrismaAIRs.TopicUpdate.active | Boolean | Whether the topic is active. |
| PrismaAIRs.TopicUpdate.description | String | Topic description. |
| PrismaAIRs.TopicUpdate.examples | Unknown | Example prompts for the topic. |
| PrismaAIRs.TopicUpdate.created_by | String | User who created the topic. |
| PrismaAIRs.TopicUpdate.updated_by | String | User who last updated the topic. |
| PrismaAIRs.TopicUpdate.last_modified_ts | Date | Last modification timestamp. |
| PrismaAIRs.TopicUpdate.created_ts | Date | Creation timestamp. |

#### Command example

```
!prisma-airs-runtime-topics-update topic_id=${PrismaAIRs.TopicCreate.topic_id} topic_name="readme-example-topic" description="Updated example custom topic"
```

#### Context Example

```json
{
    "active": true,
    "created_by": "test@test.com",
    "created_ts": null,
    "description": "Updated example custom topic",
    "examples": [],
    "last_modified_ts": null,
    "revision": 2,
    "topic_id": "6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad",
    "topic_name": "readme-example-topic",
    "updated_by": "none"
}
```

#### Human Readable Output

>### Custom Topic Updated
>
>|Topic Id|Topic Name|Revision|Active|Description|Updated By|
>|---|---|---|---|---|---|
>| 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad | readme-example-topic | 2 | true | Updated example custom topic | none |

### prisma-airs-runtime-topics-delete

***
Delete a custom topic. WARNING - This action cannot be undone. Fails if topic is referenced by any security profile.

#### Base Command

`prisma-airs-runtime-topics-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic_id | Topic UUID to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicDeleted.topic_id | String | Deleted topic ID. |
| PrismaAIRs.TopicDeleted.message | String | Deletion confirmation message. |
| PrismaAIRs.TopicDeleted.deleted | Boolean | Boolean indicating successful deletion. |

#### Command example

```
!prisma-airs-runtime-topics-delete topic_id=${PrismaAIRs.TopicCreate.topic_id}
```

#### Context Example

```json
{
    "deleted": true,
    "message": "successfully deleted topicId: 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad",
    "topic_id": "6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad"
}
```

#### Human Readable Output

>### Custom Topic Deleted
>
>|Topic Id|Message|Deleted|
>|---|---|---|
>| 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad | successfully deleted topicId: 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad | true |
>
>
>**⚠️ WARNING:** This action cannot be undone. The custom topic has been permanently deleted.

### prisma-airs-runtime-topics-apply

***
Apply a topic to a security profile (additive - preserves existing topics). This command orchestrates multiple API calls to assign a custom topic to a profile's topic-guardrails configuration.

#### Base Command

`prisma-airs-runtime-topics-apply`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | Security profile name to apply the topic to. | Required |
| topic_name | Topic name to apply. The topic must already exist (create with prisma-airs-runtime-topics-create). | Required |
| action | Topic action. 'block' = block prompts matching this topic. 'allow' = allow prompts matching this topic. Default is 'block'. Possible values are: allow, block. Default is block. | Optional |
| guardrail_action | Guardrail-level default action. 'block' = block all unless explicitly allowed (requires allow topics). 'allow' = allow all unless explicitly blocked (only block topics needed). Default is 'block'. Possible values are: allow, block. Default is block. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicApplied.profile_name | String | Security profile name. |
| PrismaAIRs.TopicApplied.profile_id | String | Security profile UUID. |
| PrismaAIRs.TopicApplied.topic_name | String | Topic name that was applied. |
| PrismaAIRs.TopicApplied.topic_id | String | Topic UUID. |
| PrismaAIRs.TopicApplied.topic_revision | Number | Topic revision number \(pinned to ensure consistent detection\). |
| PrismaAIRs.TopicApplied.action | String | Topic action \(allow or block\). |
| PrismaAIRs.TopicApplied.guardrail_action | String | Guardrail-level default action. |
| PrismaAIRs.TopicApplied.applied | Boolean | Boolean indicating successful application. |

### prisma-airs-runtime-bulk-scan

***
Perform bulk scanning of multiple prompts.

#### Base Command

`prisma-airs-runtime-bulk-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | Security profile name to use for scanning. | Required |
| prompts_csv | CSV content with prompts to scan (must include 'prompt' column header, or use newline-separated format). | Required |
| session_id | Optional session ID for grouping scans in AIRS dashboard. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.BulkScan.profile_name | String | Security profile used. |
| PrismaAIRs.BulkScan.session_id | String | Session ID. |
| PrismaAIRs.BulkScan.total | Number | Total prompts scanned. |
| PrismaAIRs.BulkScan.blocked | Number | Number of prompts blocked. |
| PrismaAIRs.BulkScan.allowed | Number | Number of prompts allowed. |
| PrismaAIRs.BulkScan.errors | Number | Number of scan errors. |
| PrismaAIRs.BulkScan.results | Unknown | Array of individual scan results. |

### prisma-airs-model-security-scans-list

***
List all model security scans.

#### Base Command

`prisma-airs-model-security-scans-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of scans to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityScan.uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityScan.model_uri | String | Model URI that was scanned. |
| PrismaAIRs.ModelSecurityScan.eval_outcome | String | Evaluation outcome \(ALLOWED, BLOCKED\). |
| PrismaAIRs.ModelSecurityScan.source_type | String | Source type \(HUGGING_FACE, LOCAL, etc.\). |
| PrismaAIRs.ModelSecurityScan.security_group_uuid | String | Security group UUID. |
| PrismaAIRs.ModelSecurityScan.security_group_name | String | Security group name. |
| PrismaAIRs.ModelSecurityScan.scan_origin | String | Scan origin. |
| PrismaAIRs.ModelSecurityScan.created_at | Date | Creation timestamp. |
| PrismaAIRs.ModelSecurityScan.updated_at | Date | Last update timestamp. |
| PrismaAIRs.ModelSecurityScan.created_by | String | User who created the scan. |

#### Command example

```
!prisma-airs-model-security-scans-list
```

#### Context Example

```json
[
    {
        "created_at": "2026-05-15T13:05:53.684091Z",
        "created_by": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "eval_outcome": "ERROR",
        "model_uri": "https://huggingface.co/Open-OSS/privacy-filter",
        "scan_origin": "MODEL_SECURITY_FRONTEND",
        "security_group_name": "Default HUGGING_FACE",
        "security_group_uuid": "1cd2d272-41c6-4cab-948a-28bf55a24029",
        "source_type": "HUGGING_FACE",
        "updated_at": "2026-05-15T13:05:53.754042Z",
        "uuid": "66ef8a34-a975-44c7-b629-7881981d6c77"
    },
    {
        "created_at": "2026-03-30T20:55:25.690604Z",
        "created_by": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "eval_outcome": "BLOCKED",
        "model_uri": "https://huggingface.co/Qwen/Qwen3-0.6B-GGUF",
        "scan_origin": "HUGGING_FACE",
        "security_group_name": "Default HUGGING_FACE",
        "security_group_uuid": "1cd2d272-41c6-4cab-948a-28bf55a24029",
        "source_type": "HUGGING_FACE",
        "updated_at": "2026-03-30T20:55:25.944593Z",
        "uuid": "c493d943-0d5e-4246-a1ea-f7bf9bed656f"
    }
]
```

#### Human Readable Output

>### Prisma AIRs Model Security Scans
>
>|Uuid|Model Uri|Eval Outcome|Source Type|Security Group Name|Created At|
>|---|---|---|---|---|---|
>| 66ef8a34-a975-44c7-b629-7881981d6c77 | https://huggingface.co/Open-OSS/privacy-filter | ERROR | HUGGING_FACE | Default HUGGING_FACE | 2026-05-15T13:05:53.684091Z |
>| c493d943-0d5e-4246-a1ea-f7bf9bed656f | https://huggingface.co/Qwen/Qwen3-0.6B-GGUF | BLOCKED | HUGGING_FACE | Default HUGGING_FACE | 2026-03-30T20:55:25.690604Z |

### prisma-airs-model-security-scans-create

***
Create a new model security scan to check a model for supply chain security issues. Scan is asynchronous - use scans-get to poll for completion.

#### Base Command

`prisma-airs-model-security-scans-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model_uri | Model URI (HuggingFace URL like https://huggingface.co/microsoft/DialoGPT-medium or local path). | Required |
| security_group_uuid | Security group UUID to use for scanning. | Required |
| scan_origin | Scan origin identifier. Possible values are: MODEL_SECURITY_SDK, MODEL_SECURITY_API, MODEL_SECURITY_FRONTEND, HUGGING_FACE. Default is MODEL_SECURITY_API. | Optional |
| model_name | Model name (optional metadata). | Optional |
| model_author | Model author (optional metadata). | Optional |
| model_version | Model version (optional metadata). | Optional |
| labels | Labels to tag the scan, as a JSON array of key/value objects, e.g. \[{"key": "env", "value": "prod"}, {"key": "team", "value": "ml"}\]. Keys (\<=128 chars) and values (\<=256 chars) must match ^\[a-zA-Z0-9_-\]+$. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityScanCreate.uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityScanCreate.labels | Unknown | Labels (key/value pairs) applied to the scan. |
| PrismaAIRs.ModelSecurityScanCreate.model_uri | String | Model URI that was scanned. |
| PrismaAIRs.ModelSecurityScanCreate.security_group_uuid | String | Security group UUID used for scanning. |
| PrismaAIRs.ModelSecurityScanCreate.security_group_name | String | Security group name. |
| PrismaAIRs.ModelSecurityScanCreate.scan_origin | String | Scan origin. |
| PrismaAIRs.ModelSecurityScanCreate.eval_outcome | String | Evaluation outcome \(PENDING initially, then ALLOWED/BLOCKED\). |
| PrismaAIRs.ModelSecurityScanCreate.source_type | String | Model source type. |
| PrismaAIRs.ModelSecurityScanCreate.owner | String | Scan owner. |
| PrismaAIRs.ModelSecurityScanCreate.created_at | Date | Creation timestamp. |
| PrismaAIRs.ModelSecurityScanCreate.updated_at | Date | Last update timestamp. |
| PrismaAIRs.ModelSecurityScanCreate.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityScanCreate.rules_passed | Number | Number of rules that passed. |
| PrismaAIRs.ModelSecurityScanCreate.rules_failed | Number | Number of rules that failed. |
| PrismaAIRs.ModelSecurityScanCreate.total_rules | Number | Total number of rules evaluated. |

### prisma-airs-model-security-scans-get

***
Get model security scan status and results. Use this to poll scan completion after scans-create.

#### Base Command

`prisma-airs-model-security-scans-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Scan UUID to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityScanGet.uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityScanGet.model_uri | String | Model URI that was scanned. |
| PrismaAIRs.ModelSecurityScanGet.security_group_uuid | String | Security group UUID used for scanning. |
| PrismaAIRs.ModelSecurityScanGet.security_group_name | String | Security group name. |
| PrismaAIRs.ModelSecurityScanGet.scan_origin | String | Scan origin. |
| PrismaAIRs.ModelSecurityScanGet.eval_outcome | String | Evaluation outcome \(PENDING/ALLOWED/BLOCKED\). |
| PrismaAIRs.ModelSecurityScanGet.source_type | String | Model source type. |
| PrismaAIRs.ModelSecurityScanGet.owner | String | Scan owner. |
| PrismaAIRs.ModelSecurityScanGet.created_at | Date | Creation timestamp. |
| PrismaAIRs.ModelSecurityScanGet.updated_at | Date | Last update timestamp. |
| PrismaAIRs.ModelSecurityScanGet.created_by | String | User who created the scan. |
| PrismaAIRs.ModelSecurityScanGet.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityScanGet.model_version_uuid | String | Model version UUID. |
| PrismaAIRs.ModelSecurityScanGet.enabled_rule_count_snapshot | Number | Snapshot of enabled rules count at scan time. |
| PrismaAIRs.ModelSecurityScanGet.scanner_version | String | Scanner version used. |
| PrismaAIRs.ModelSecurityScanGet.time_started | Date | Scan start time. |
| PrismaAIRs.ModelSecurityScanGet.total_files_scanned | Number | Total files scanned. |
| PrismaAIRs.ModelSecurityScanGet.total_files_skipped | Number | Total files skipped. |
| PrismaAIRs.ModelSecurityScanGet.rules_passed | Number | Number of rules that passed. |
| PrismaAIRs.ModelSecurityScanGet.rules_failed | Number | Number of rules that failed. |
| PrismaAIRs.ModelSecurityScanGet.total_rules | Number | Total number of rules evaluated. |
| PrismaAIRs.ModelSecurityScanGet.error_code | String | Error code if scan failed. |
| PrismaAIRs.ModelSecurityScanGet.error_message | String | Error message if scan failed. |
| PrismaAIRs.ModelSecurityScanGet.model_formats | Unknown | Model file formats detected. |

### prisma-airs-model-security-scans-violations

***
Get rule violations for a model security scan. Shows detailed information about which security rules failed and why.

#### Base Command

`prisma-airs-model-security-scans-violations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Scan UUID to retrieve violations for. | Required |
| limit | Maximum number of violations to return. Default is 50. | Optional |
| offset | Offset for pagination. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityViolation.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityViolation.violations.uuid | String | Violation UUID. |
| PrismaAIRs.ModelSecurityViolation.violations.rule_name | String | Security rule name that failed. |
| PrismaAIRs.ModelSecurityViolation.violations.rule_description | String | Security rule description. |
| PrismaAIRs.ModelSecurityViolation.violations.description | String | Violation description. |
| PrismaAIRs.ModelSecurityViolation.violations.rule_instance_state | String | Rule instance state \(BLOCKING/ALLOWING\). |
| PrismaAIRs.ModelSecurityViolation.violations.file | String | File path where violation was found. |
| PrismaAIRs.ModelSecurityViolation.violations.threat | String | Threat type. |
| PrismaAIRs.ModelSecurityViolation.violations.threat_description | String | Threat description. |
| PrismaAIRs.ModelSecurityViolation.violations.module | String | Module where threat was found. |
| PrismaAIRs.ModelSecurityViolation.violations.operator | String | Operator involved in violation. |
| PrismaAIRs.ModelSecurityViolation.violations.hash | String | Hash of the violating file. |
| PrismaAIRs.ModelSecurityViolation.violations.rule_instance_uuid | String | Rule instance UUID. |
| PrismaAIRs.ModelSecurityViolation.violations.created_at | Date | Violation creation timestamp. |
| PrismaAIRs.ModelSecurityViolation.violations.updated_at | Date | Violation last update timestamp. |
| PrismaAIRs.ModelSecurityViolation.violations.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityViolation.total_items | Number | Total number of violations available. |
| PrismaAIRs.ModelSecurityViolation.limit | Number | Limit used for pagination. |
| PrismaAIRs.ModelSecurityViolation.offset | Number | Offset used for pagination. |

### prisma-airs-model-security-labels-keys

***
Get distinct label keys across all model security scans. Use for discovering available labels for filtering/organization.

#### Base Command

`prisma-airs-model-security-labels-keys`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of label keys to return. Default is 50. | Optional |
| offset | Offset for pagination. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelKeys.keys | Unknown | List of distinct label keys. |
| PrismaAIRs.ModelSecurityLabelKeys.total_items | Number | Total number of label keys available. |
| PrismaAIRs.ModelSecurityLabelKeys.limit | Number | Limit used for pagination. |
| PrismaAIRs.ModelSecurityLabelKeys.offset | Number | Offset used for pagination. |

#### Command example

```
!prisma-airs-model-security-labels-keys
```

#### Context Example

```json
{
    "keys": [
        "env"
    ],
    "limit": 50,
    "offset": 0,
    "total_items": 1
}
```

#### Human Readable Output

>### Model Security Label Keys
>
>|Key|
>|---|
>| env |
>
>
>**Total Keys:** 1 (showing 1-1 of 1)

### prisma-airs-model-security-labels-values

***
Get distinct values for a specific label key across all model security scans. Use to discover what values exist for a given label.

#### Base Command

`prisma-airs-model-security-labels-values`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Label key to get values for. | Required |
| limit | Maximum number of label values to return. Default is 50. | Optional |
| offset | Offset for pagination. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelValues.key | String | Label key. |
| PrismaAIRs.ModelSecurityLabelValues.values | Unknown | List of distinct label values. |
| PrismaAIRs.ModelSecurityLabelValues.total_items | Number | Total number of label values available. |
| PrismaAIRs.ModelSecurityLabelValues.limit | Number | Limit used for pagination. |
| PrismaAIRs.ModelSecurityLabelValues.offset | Number | Offset used for pagination. |

### prisma-airs-model-security-labels-add

***
Add labels to a model security scan for organization and filtering. Labels are key-value pairs.

#### Base Command

`prisma-airs-model-security-labels-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | Scan UUID to add labels to. | Required |
| labels | Labels to add as JSON array (e.g., '[{"key":"env","value":"prod"}]'). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelsAdd.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityLabelsAdd.labels_added | Unknown | Labels that were added. |
| PrismaAIRs.ModelSecurityLabelsAdd.success | Boolean | Whether the operation succeeded. |

### prisma-airs-model-security-labels-set

***
Set labels on a model security scan, replacing all existing labels. Use this to completely update scan labels.

#### Base Command

`prisma-airs-model-security-labels-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | Scan UUID to set labels on. | Required |
| labels | Labels to set as JSON array (e.g., '[{"key":"env","value":"staging"}]'). Replaces all existing labels. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelsSet.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityLabelsSet.labels_set | Unknown | Labels that were set. |
| PrismaAIRs.ModelSecurityLabelsSet.success | Boolean | Whether the operation succeeded. |

### prisma-airs-model-security-labels-delete

***
Delete labels from a model security scan by key. Removes specific labels while preserving others.

#### Base Command

`prisma-airs-model-security-labels-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | Scan UUID to delete labels from. | Required |
| keys | Label keys to delete as comma-separated string (e.g., "env,team") or JSON array. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityLabelsDelete.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityLabelsDelete.keys_deleted | Unknown | Label keys that were deleted. |
| PrismaAIRs.ModelSecurityLabelsDelete.success | Boolean | Whether the operation succeeded. |

### prisma-airs-model-security-scans-evaluation

***
Get a single rule evaluation by UUID. Retrieves detailed information about how a specific rule was evaluated during a scan.

#### Base Command

`prisma-airs-model-security-scans-evaluation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Evaluation UUID to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityEvaluation.uuid | String | Evaluation UUID. |
| PrismaAIRs.ModelSecurityEvaluation.scan_uuid | String | Scan UUID this evaluation belongs to. |
| PrismaAIRs.ModelSecurityEvaluation.rule_instance_uuid | String | Rule instance UUID. |
| PrismaAIRs.ModelSecurityEvaluation.rule_name | String | Security rule name. |
| PrismaAIRs.ModelSecurityEvaluation.rule_description | String | Security rule description. |
| PrismaAIRs.ModelSecurityEvaluation.result | String | Evaluation result \(PASSED/FAILED/ERROR\). |
| PrismaAIRs.ModelSecurityEvaluation.violation_count | Number | Number of violations found. |
| PrismaAIRs.ModelSecurityEvaluation.rule_instance_state | String | Rule instance state \(BLOCKING/ALLOWING/DISABLED\). |
| PrismaAIRs.ModelSecurityEvaluation.created_at | Date | Evaluation creation timestamp. |
| PrismaAIRs.ModelSecurityEvaluation.updated_at | Date | Evaluation last update timestamp. |
| PrismaAIRs.ModelSecurityEvaluation.tsg_id | String | Tenant Service Group ID. |

### prisma-airs-model-security-scans-violation

***
Get a single violation by UUID. Retrieves detailed information about a specific security rule violation found during a scan.

#### Base Command

`prisma-airs-model-security-scans-violation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Violation UUID to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityViolationDetail.uuid | String | Violation UUID. |
| PrismaAIRs.ModelSecurityViolationDetail.rule_name | String | Security rule name that failed. |
| PrismaAIRs.ModelSecurityViolationDetail.rule_description | String | Security rule description. |
| PrismaAIRs.ModelSecurityViolationDetail.description | String | Violation description. |
| PrismaAIRs.ModelSecurityViolationDetail.rule_instance_state | String | Rule instance state \(BLOCKING/ALLOWING\). |
| PrismaAIRs.ModelSecurityViolationDetail.file | String | File path where violation was found. |
| PrismaAIRs.ModelSecurityViolationDetail.threat | String | Threat type. |
| PrismaAIRs.ModelSecurityViolationDetail.threat_description | String | Threat description. |
| PrismaAIRs.ModelSecurityViolationDetail.module | String | Module where threat was found. |
| PrismaAIRs.ModelSecurityViolationDetail.operator | String | Operator involved in violation. |
| PrismaAIRs.ModelSecurityViolationDetail.hash | String | Hash of the violating file. |
| PrismaAIRs.ModelSecurityViolationDetail.rule_instance_uuid | String | Rule instance UUID. |
| PrismaAIRs.ModelSecurityViolationDetail.created_at | Date | Violation creation timestamp. |
| PrismaAIRs.ModelSecurityViolationDetail.updated_at | Date | Violation last update timestamp. |
| PrismaAIRs.ModelSecurityViolationDetail.tsg_id | String | Tenant Service Group ID. |

### prisma-airs-model-security-scans-files

***
Get files for a scan. Lists all files that were scanned within a model, showing file structure and scan results.

#### Base Command

`prisma-airs-model-security-scans-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | Scan UUID to retrieve files for. | Required |
| limit | Maximum number of files to return. Default is 50. | Optional |
| offset | Offset for pagination. Default is 0. | Optional |
| sort_field | Sort by field (path, type). | Optional |
| sort_dir | Sort direction (asc, desc). | Optional |
| type | Filter by file type (FILE, DIRECTORY). | Optional |
| result | Filter by scan result (SUCCESS, FAILURE). | Optional |
| query_path | Filter files by path prefix (default '/'). Default is /. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityFiles.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityFiles.files.uuid | String | File entry UUID. |
| PrismaAIRs.ModelSecurityFiles.files.path | String | File path within model. |
| PrismaAIRs.ModelSecurityFiles.files.parent_path | String | Parent directory path. |
| PrismaAIRs.ModelSecurityFiles.files.type | String | File type \(FILE, DIRECTORY\). |
| PrismaAIRs.ModelSecurityFiles.files.result | String | Scan result \(SUCCESS, FAILURE\). |
| PrismaAIRs.ModelSecurityFiles.files.model_version_uuid | String | Model version UUID. |
| PrismaAIRs.ModelSecurityFiles.files.blob_id | String | Blob storage identifier. |
| PrismaAIRs.ModelSecurityFiles.files.formats | Unknown | Model formats detected. |
| PrismaAIRs.ModelSecurityFiles.files.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityFiles.files.created_at | Date | File entry creation timestamp. |
| PrismaAIRs.ModelSecurityFiles.files.updated_at | Date | File entry last update timestamp. |
| PrismaAIRs.ModelSecurityFiles.files.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityFiles.total_items | Number | Total number of files available. |
| PrismaAIRs.ModelSecurityFiles.limit | Number | Limit used for pagination. |
| PrismaAIRs.ModelSecurityFiles.offset | Number | Offset used for pagination. |

### prisma-airs-model-security-scans-evaluations

***
Get rule evaluations for a scan. Lists all rule evaluations showing which security rules passed, failed, or had errors.

#### Base Command

`prisma-airs-model-security-scans-evaluations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_uuid | Scan UUID to retrieve evaluations for. | Required |
| limit | Maximum number of evaluations to return. Default is 50. | Optional |
| offset | Offset for pagination. Default is 0. | Optional |
| sort_field | Sort by field (created_at, updated_at). | Optional |
| sort_order | Sort order (asc, desc). | Optional |
| result | Filter by evaluation result (PASSED, FAILED, ERROR). | Optional |
| rule_instance_uuid | Filter by specific rule instance UUID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityEvaluations.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.uuid | String | Rule evaluation UUID. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.scan_uuid | String | Scan UUID. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_name | String | Security rule name \(e.g., Pickle Scan, Malware Scan\). |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.result | String | Evaluation result \(PASSED, FAILED, ERROR\). |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.violation_count | Number | Number of violations detected by this rule. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_instance_state | String | Rule instance state \(BLOCKING, MONITORING\). |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_instance_uuid | String | Rule instance UUID that performed the evaluation. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.rule_description | String | Rule description. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.created_at | Date | Evaluation creation timestamp. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.updated_at | Date | Evaluation last update timestamp. |
| PrismaAIRs.ModelSecurityEvaluations.evaluations.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityEvaluations.total_items | Number | Total number of evaluations available. |
| PrismaAIRs.ModelSecurityEvaluations.limit | Number | Limit used for pagination. |
| PrismaAIRs.ModelSecurityEvaluations.offset | Number | Offset used for pagination. |

### prisma-airs-model-security-groups-list

***
List all model security groups.

#### Base Command

`prisma-airs-model-security-groups-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of security groups to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroup.uuid | String | Security group UUID. |
| PrismaAIRs.ModelSecurityGroup.name | String | Security group name. |
| PrismaAIRs.ModelSecurityGroup.description | String | Security group description. |
| PrismaAIRs.ModelSecurityGroup.source_type | String | Source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). |
| PrismaAIRs.ModelSecurityGroup.state | String | Group state \(ACTIVE, PENDING\). |
| PrismaAIRs.ModelSecurityGroup.is_tombstone | Boolean | Whether the group is marked for deletion. |
| PrismaAIRs.ModelSecurityGroup.created_at | Date | Creation timestamp. |
| PrismaAIRs.ModelSecurityGroup.updated_at | Date | Last update timestamp. |
| PrismaAIRs.ModelSecurityGroup.tsg_id | String | Tenant Service Group ID. |

#### Command example

```
!prisma-airs-model-security-groups-list
```

#### Context Example

```json
[
    {
        "created_at": "2026-06-24T13:06:37.975736Z",
        "description": "Auto-created default security group for LOCAL models\n",
        "is_tombstone": false,
        "name": "Default LOCAL",
        "source_type": "LOCAL",
        "state": "ACTIVE",
        "tsg_id": "1234567",
        "updated_at": "2026-06-24T13:06:38.103511Z",
        "uuid": "6ef0e183-8ac3-4976-b553-919ce50ba9ad"
    },
    {
        "created_at": "2026-06-24T13:06:17.284947Z",
        "description": "Auto-created default security group for HUGGING_FACE models\n",
        "is_tombstone": false,
        "name": "Default HUGGING_FACE",
        "source_type": "HUGGING_FACE",
        "state": "ACTIVE",
        "tsg_id": "1234567",
        "updated_at": "2026-06-24T13:06:17.453421Z",
        "uuid": "18a33c25-30c6-45c0-84a3-1e7641c813e8"
    }
]
```

#### Human Readable Output

>### Prisma AIRs Model Security Groups
>
>|Uuid|Name|Source Type|State|Created At|
>|---|---|---|---|---|
>| 6ef0e183-8ac3-4976-b553-919ce50ba9ad | Default LOCAL | LOCAL | ACTIVE | 2026-06-24T13:06:37.975736Z |
>| 18a33c25-30c6-45c0-84a3-1e7641c813e8 | Default HUGGING_FACE | HUGGING_FACE | ACTIVE | 2026-06-24T13:06:17.284947Z |
>| 0c55c0b0-257c-40a0-9b75-e27d79633be6 | Default GCS | GCS | ACTIVE | 2026-06-24T13:05:35.831440Z |
>| 9d4f7ad8-66d3-4214-89cf-a3a80282c1e2 | Default S3 | S3 | ACTIVE | 2026-06-24T13:04:52.018948Z |
>| 201a2411-1be1-40a1-8929-0265aede20f6 | Default AZURE | AZURE | ACTIVE | 2026-06-24T13:04:34.245928Z |

### prisma-airs-model-security-groups-get

***
Get model security group details by UUID.

#### Base Command

`prisma-airs-model-security-groups-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Security group UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupGet.uuid | String | Security group UUID. |
| PrismaAIRs.ModelSecurityGroupGet.name | String | Security group name. |
| PrismaAIRs.ModelSecurityGroupGet.description | String | Security group description. |
| PrismaAIRs.ModelSecurityGroupGet.source_type | String | Source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). |
| PrismaAIRs.ModelSecurityGroupGet.state | String | Group state \(ACTIVE, PENDING\). |
| PrismaAIRs.ModelSecurityGroupGet.is_tombstone | Boolean | Whether the group is marked for deletion. |
| PrismaAIRs.ModelSecurityGroupGet.created_at | Date | Creation timestamp. |
| PrismaAIRs.ModelSecurityGroupGet.updated_at | Date | Last update timestamp. |
| PrismaAIRs.ModelSecurityGroupGet.tsg_id | String | Tenant Service Group ID. |

### prisma-airs-model-security-groups-create

***
Create a new model security group for scanning models from a specific source type.

#### Base Command

`prisma-airs-model-security-groups-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Security group name. | Required |
| source_type | Model source type. Possible values are: HUGGING_FACE, LOCAL, S3, GCS, AZURE. | Required |
| description | Security group description. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupAdd.uuid | String | UUID of the created security group. |
| PrismaAIRs.ModelSecurityGroupAdd.name | String | Name of the created security group. |
| PrismaAIRs.ModelSecurityGroupAdd.description | String | Description of the created security group. |
| PrismaAIRs.ModelSecurityGroupAdd.source_type | String | Source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). |
| PrismaAIRs.ModelSecurityGroupAdd.state | String | Group state \(PENDING initially, becomes ACTIVE after configuration\). |
| PrismaAIRs.ModelSecurityGroupAdd.is_tombstone | Boolean | Whether the group is marked for deletion. |
| PrismaAIRs.ModelSecurityGroupAdd.created_at | Date | Creation timestamp. |
| PrismaAIRs.ModelSecurityGroupAdd.updated_at | Date | Last update timestamp. |
| PrismaAIRs.ModelSecurityGroupAdd.tsg_id | String | Tenant Service Group ID. |

### prisma-airs-model-security-groups-delete

***
Delete a security group. Removes a security group that is no longer needed.

#### Base Command

`prisma-airs-model-security-groups-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Security group UUID to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupDelete.uuid | String | UUID of deleted security group. |
| PrismaAIRs.ModelSecurityGroupDelete.deleted | Boolean | Whether the deletion succeeded. |

### prisma-airs-model-security-groups-update

***
Update an existing security group. Updates the name and/or description of a security group.

#### Base Command

`prisma-airs-model-security-groups-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Security group UUID to update. | Required |
| name | New name for the security group. | Optional |
| description | New description for the security group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityGroupUpdate.uuid | String | UUID of the updated security group. |
| PrismaAIRs.ModelSecurityGroupUpdate.name | String | Updated security group name. |
| PrismaAIRs.ModelSecurityGroupUpdate.description | String | Updated security group description. |
| PrismaAIRs.ModelSecurityGroupUpdate.source_type | String | Model source type \(HUGGING_FACE, LOCAL, S3, GCS, AZURE\). |
| PrismaAIRs.ModelSecurityGroupUpdate.state | String | Group state after update. |
| PrismaAIRs.ModelSecurityGroupUpdate.is_tombstone | Boolean | Whether the group is marked for deletion. |
| PrismaAIRs.ModelSecurityGroupUpdate.created_at | Date | Creation timestamp. |
| PrismaAIRs.ModelSecurityGroupUpdate.updated_at | Date | Last update timestamp. |
| PrismaAIRs.ModelSecurityGroupUpdate.tsg_id | String | Tenant Service Group ID. |

### prisma-airs-model-security-rules-list

***
List all model security rules.

#### Base Command

`prisma-airs-model-security-rules-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of security rules to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRule.uuid | String | Security rule UUID. |
| PrismaAIRs.ModelSecurityRule.name | String | Security rule name. |
| PrismaAIRs.ModelSecurityRule.description | String | Security rule description. |
| PrismaAIRs.ModelSecurityRule.rule_type | String | Rule type \(ARTIFACT, METADATA\). |
| PrismaAIRs.ModelSecurityRule.compatible_sources | Unknown | Compatible source types for this rule. |
| PrismaAIRs.ModelSecurityRule.default_state | String | Default state \(DISABLED, ALLOWING, BLOCKING\). |

#### Command example

```
!prisma-airs-model-security-rules-list
```

#### Context Example

```json
[
    {
        "compatible_sources": [
            "ALL"
        ],
        "default_state": "BLOCKING",
        "description": "Model artifacts should only contain known safe TensorFlow operators",
        "name": "Known Framework Operators Check",
        "rule_type": "ARTIFACT",
        "uuid": "550e8400-e29b-41d4-a716-44665544000b"
    },
    {
        "compatible_sources": [
            "HUGGING_FACE"
        ],
        "default_state": "BLOCKING",
        "description": "Models should have a license",
        "name": "License Exists",
        "rule_type": "METADATA",
        "uuid": "550e8400-e29b-41d4-a716-446655440006"
    }
]
```

#### Human Readable Output

>### Prisma AIRs Model Security Rules
>
>|Uuid|Name|Rule Type|Default State|
>|---|---|---|---|
>| 550e8400-e29b-41d4-a716-44665544000b | Known Framework Operators Check | ARTIFACT | BLOCKING |
>| 550e8400-e29b-41d4-a716-446655440006 | License Exists | METADATA | BLOCKING |

### prisma-airs-model-security-rules-get

***
Get model security rule details by UUID. Returns full rule definition including description, remediation steps, and editable fields.

#### Base Command

`prisma-airs-model-security-rules-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Rule UUID to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleGet.uuid | String | Rule UUID. |
| PrismaAIRs.ModelSecurityRuleGet.name | String | Rule name. |
| PrismaAIRs.ModelSecurityRuleGet.description | String | Rule description. |
| PrismaAIRs.ModelSecurityRuleGet.rule_type | String | Rule type \(ARTIFACT, METADATA, etc\). |
| PrismaAIRs.ModelSecurityRuleGet.compatible_sources | Unknown | Compatible source types for this rule. |
| PrismaAIRs.ModelSecurityRuleGet.default_state | String | Default state \(DISABLED, ALLOWING, BLOCKING\). |
| PrismaAIRs.ModelSecurityRuleGet.remediation_description | String | Remediation description. |
| PrismaAIRs.ModelSecurityRuleGet.remediation_steps | Unknown | Remediation steps. |
| PrismaAIRs.ModelSecurityRuleGet.remediation_url | String | Remediation reference URL. |
| PrismaAIRs.ModelSecurityRuleGet.editable_fields | Unknown | Editable fields configuration. |
| PrismaAIRs.ModelSecurityRuleGet.constant_values | Unknown | Constant values for this rule. |
| PrismaAIRs.ModelSecurityRuleGet.default_values | Unknown | Default values for editable fields. |

### prisma-airs-model-security-rule-instances-list

***
List rule instances for a security group. Rule instances are rules that have been applied to a security group with specific state (DISABLED/ALLOWING/BLOCKING) and optional field customizations.

#### Base Command

`prisma-airs-model-security-rule-instances-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_uuid | Security group UUID to list rule instances for. | Required |
| limit | Maximum number of rule instances to return. Default is 50. | Optional |
| offset | Offset for pagination. Default is 0. | Optional |
| security_rule_uuid | Filter by specific security rule UUID. | Optional |
| state | Filter by rule state. Possible values are: DISABLED, ALLOWING, BLOCKING. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleInstance.security_group_uuid | String | Security group UUID. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.uuid | String | Rule instance UUID. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.security_group_uuid | String | Security group UUID this instance belongs to. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.security_rule_uuid | String | Security rule UUID. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.state | String | Rule instance state \(DISABLED/ALLOWING/BLOCKING\). |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.rule_name | String | Security rule name. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.rule_type | String | Security rule type. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.rule_description | String | Security rule description. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.created_at | Date | Rule instance creation timestamp. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.updated_at | Date | Rule instance last update timestamp. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityRuleInstance.rule_instances.field_values | Unknown | Custom field values for this rule instance. |
| PrismaAIRs.ModelSecurityRuleInstance.total_items | Number | Total number of rule instances available. |
| PrismaAIRs.ModelSecurityRuleInstance.limit | Number | Limit used for pagination. |
| PrismaAIRs.ModelSecurityRuleInstance.offset | Number | Offset used for pagination. |

### prisma-airs-model-security-rule-instances-update

***
Update a rule instance within a security group. Use this to enable/disable rules or customize rule field values.

#### Base Command

`prisma-airs-model-security-rule-instances-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_uuid | Security group UUID. | Required |
| rule_instance_uuid | Rule instance UUID to update. | Required |
| state | New state for the rule instance. Possible values are: DISABLED, ALLOWING, BLOCKING. | Optional |
| field_values | Custom field values as JSON string. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.uuid | String | Rule instance UUID. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.security_group_uuid | String | Security group UUID this instance belongs to. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.security_rule_uuid | String | Security rule UUID. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.state | String | Rule instance state \(DISABLED/ALLOWING/BLOCKING\). |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.rule_name | String | Security rule name. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.rule_type | String | Security rule type. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.rule_description | String | Security rule description. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.created_at | Date | Rule instance creation timestamp. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.updated_at | Date | Rule instance last update timestamp. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityRuleInstanceUpdate.field_values | Unknown | Custom field values for this rule instance. |

### prisma-airs-model-security-rule-instances-get

***
Get a single rule instance within a security group. Retrieves detailed configuration of a specific rule instance.

#### Base Command

`prisma-airs-model-security-rule-instances-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_uuid | Security group UUID. | Required |
| rule_instance_uuid | Rule instance UUID to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ModelSecurityRuleInstanceGet.uuid | String | Rule instance UUID. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.security_group_uuid | String | Security group UUID this instance belongs to. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.security_rule_uuid | String | Security rule UUID. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.state | String | Rule instance state \(DISABLED/ALLOWING/BLOCKING\). |
| PrismaAIRs.ModelSecurityRuleInstanceGet.rule_name | String | Security rule name. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.rule_type | String | Security rule type. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.rule_description | String | Security rule description. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.created_at | Date | Rule instance creation timestamp. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.updated_at | Date | Rule instance last update timestamp. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.ModelSecurityRuleInstanceGet.field_values | Unknown | Custom field values for this rule instance. |

### prisma-airs-redteam-targets-list

***
List all Red Team targets.

#### Base Command

`prisma-airs-redteam-targets-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of targets to return. Default is 50. | Optional |
| target_type | Filter by target type (e.g., API, UI, MOBILE). | Optional |
| status | Filter by target status (e.g., READY, VALIDATING, FAILED). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTarget.uuid | String | Target UUID. |
| PrismaAIRs.RedTeamTarget.name | String | Target name. |
| PrismaAIRs.RedTeamTarget.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.RedTeamTarget.status | String | Target status. |
| PrismaAIRs.RedTeamTarget.active | Boolean | Whether the target is active. |
| PrismaAIRs.RedTeamTarget.validated | Boolean | Whether the target has been validated. |
| PrismaAIRs.RedTeamTarget.created_at | Date | Creation timestamp. |
| PrismaAIRs.RedTeamTarget.updated_at | Date | Last update timestamp. |
| PrismaAIRs.RedTeamTarget.description | String | Target description. |
| PrismaAIRs.RedTeamTarget.target_type | String | Target type. |
| PrismaAIRs.RedTeamTarget.connection_type | String | Connection type. |
| PrismaAIRs.RedTeamTarget.auth_type | String | Authentication type. |

#### Command example

```
!prisma-airs-redteam-targets-list
```

#### Context Example

```json
[
    {
        "active": true,
        "api_endpoint_type": "PRIVATE",
        "auth_type": null,
        "connection_type": "CUSTOM",
        "created_at": "2026-05-29T14:45:35.612826Z",
        "created_by_user_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "description": "",
        "name": "example-app-3",
        "response_mode": "REST",
        "session_supported": false,
        "status": "ACTIVE",
        "target_type": "APPLICATION",
        "tsg_id": "1234567",
        "updated_at": "2026-06-18T08:48:37.181752Z",
        "updated_by_user_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "uuid": "c5503ac6-321c-4ae0-bf0b-3dc81907972a",
        "validated": true
    },
    {
        "active": true,
        "api_endpoint_type": "PRIVATE",
        "auth_type": null,
        "connection_type": "CUSTOM",
        "created_at": "2026-05-08T18:50:08.580115Z",
        "created_by_user_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "description": "",
        "name": "example-app-4",
        "response_mode": "REST",
        "session_supported": false,
        "status": "ACTIVE",
        "target_type": "APPLICATION",
        "tsg_id": "1234567",
        "updated_at": "2026-06-18T08:48:36.480068Z",
        "updated_by_user_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "uuid": "8ecef265-89db-4f75-a322-2853f068647d",
        "validated": true
    }
]
```

#### Human Readable Output

>### Prisma AIRs Red Team Targets
>
>|Uuid|Name|Target Type|Status|Active|Validated|Created At|
>|---|---|---|---|---|---|---|
>| c5503ac6-321c-4ae0-bf0b-3dc81907972a | example-app-3 | APPLICATION | ACTIVE | true | true | 2026-05-29T14:45:35.612826Z |
>| 8ecef265-89db-4f75-a322-2853f068647d | example-app-4 | APPLICATION | ACTIVE | true | true | 2026-05-08T18:50:08.580115Z |

### prisma-airs-redteam-targets-create

***
Create a new Red Team target.

#### Base Command

`prisma-airs-redteam-targets-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Target name. | Required |
| description | Target description. | Optional |
| target_type | Target type (e.g., APPLICATION, AGENT, MODEL). | Optional |
| connection_type | Connection type (e.g., REST, STREAMING, WEBSOCKET). | Optional |
| api_endpoint_type | API endpoint accessibility (PUBLIC, PRIVATE, NETWORK_BROKER). | Optional |
| response_mode | Response mode (REST, STREAMING). | Optional |
| session_supported | Whether the target supports sessions (true/false). | Optional |
| connection_params | Connection parameters as JSON string. | Optional |
| validate | Validate target connectivity before creating (true/false). Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetCreate.uuid | String | Target UUID. |
| PrismaAIRs.RedTeamTargetCreate.name | String | Target name. |
| PrismaAIRs.RedTeamTargetCreate.status | String | Target status. |
| PrismaAIRs.RedTeamTargetCreate.active | Boolean | Whether the target is active. |
| PrismaAIRs.RedTeamTargetCreate.validated | Boolean | Whether the target has been validated. |
| PrismaAIRs.RedTeamTargetCreate.created_at | Date | Creation timestamp. |

### prisma-airs-redteam-targets-get

***
Get Red Team target details by UUID.

#### Base Command

`prisma-airs-redteam-targets-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Target UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetGet.uuid | String | Target UUID. |
| PrismaAIRs.RedTeamTargetGet.name | String | Target name. |
| PrismaAIRs.RedTeamTargetGet.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.RedTeamTargetGet.status | String | Target status. |
| PrismaAIRs.RedTeamTargetGet.active | Boolean | Whether the target is active. |
| PrismaAIRs.RedTeamTargetGet.validated | Boolean | Whether the target has been validated. |
| PrismaAIRs.RedTeamTargetGet.target_type | String | Target type. |
| PrismaAIRs.RedTeamTargetGet.connection_type | String | Connection type. |
| PrismaAIRs.RedTeamTargetGet.profiling_status | String | Profiling status. |
| PrismaAIRs.RedTeamTargetGet.target_metadata | Unknown | Target metadata object with probe results. |
| PrismaAIRs.RedTeamTargetGet.target_background | Unknown | Target background context. |
| PrismaAIRs.RedTeamTargetGet.additional_context | Unknown | Additional target context. |

### prisma-airs-redteam-targets-update

***
Update an existing Red Team target.

#### Base Command

`prisma-airs-redteam-targets-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Target UUID. | Required |
| name | New target name. | Optional |
| description | New target description. | Optional |
| target_type | New target type. | Optional |
| connection_type | New connection type. | Optional |
| connection_params | New connection parameters as JSON string. | Optional |
| validate | Validate target connectivity after update (true/false). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetUpdate.uuid | String | Target UUID. |
| PrismaAIRs.RedTeamTargetUpdate.name | String | Target name. |
| PrismaAIRs.RedTeamTargetUpdate.status | String | Target status. |
| PrismaAIRs.RedTeamTargetUpdate.updated_at | Date | Last update timestamp. |

### prisma-airs-redteam-targets-delete

***
Delete a Red Team target.

#### Base Command

`prisma-airs-redteam-targets-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Target UUID to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetDelete.uuid | String | Deleted target UUID. |
| PrismaAIRs.RedTeamTargetDelete.message | String | Deletion confirmation message. |
| PrismaAIRs.RedTeamTargetDelete.status | Number | HTTP status code. |

### prisma-airs-redteam-targets-probe

***
Probe a Red Team target to validate connectivity and gather profiling data.

#### Base Command

`prisma-airs-redteam-targets-probe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Target name. | Required |
| uuid | Existing target UUID (optional, for probing existing targets). | Optional |
| description | Target description. | Optional |
| target_type | Target type. | Optional |
| connection_type | Connection type. | Optional |
| connection_params | Connection parameters as JSON string. | Optional |
| probe_fields | Comma-separated list of fields to probe (e.g., "multi_turn,rate_limit,content_filter"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetProbe.uuid | String | Target UUID. |
| PrismaAIRs.RedTeamTargetProbe.name | String | Target name. |
| PrismaAIRs.RedTeamTargetProbe.status | String | Target status after probing. |
| PrismaAIRs.RedTeamTargetProbe.validated | Boolean | Whether the target was validated. |
| PrismaAIRs.RedTeamTargetProbe.profiling_status | String | Profiling status. |
| PrismaAIRs.RedTeamTargetProbe.multi_turn_supported | Boolean | Whether multi-turn conversation is supported. |
| PrismaAIRs.RedTeamTargetProbe.rate_limit_enabled | Boolean | Whether rate limiting is enabled. |
| PrismaAIRs.RedTeamTargetProbe.content_filter_enabled | Boolean | Whether content filtering is enabled. |
| PrismaAIRs.RedTeamTargetProbe.target_metadata | Unknown | Full probe results metadata. |

### prisma-airs-redteam-targets-profile

***
Get Red Team target profile (background, context, profiling status). View detailed profiling information including background context and AI-generated fields.

#### Base Command

`prisma-airs-redteam-targets-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_uuid | Target UUID to retrieve profile for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetProfile.target_id | String | Target ID. |
| PrismaAIRs.RedTeamTargetProfile.target_version | Number | Target version number. |
| PrismaAIRs.RedTeamTargetProfile.status | String | Target status. |
| PrismaAIRs.RedTeamTargetProfile.profiling_status | String | Profiling status. |
| PrismaAIRs.RedTeamTargetProfile.target_background | Unknown | Target background information \(industry, use case, etc.\). |
| PrismaAIRs.RedTeamTargetProfile.additional_context | Unknown | Additional context \(model details, languages, etc.\). |
| PrismaAIRs.RedTeamTargetProfile.ai_generated_fields | Unknown | AI-generated fields from profiling. |
| PrismaAIRs.RedTeamTargetProfile.other_details | Unknown | Other profile details. |

### prisma-airs-redteam-targets-update-profile

***
Update Red Team target profile (background and additional context). Modify target background information or add additional context like model details and supported languages.

#### Base Command

`prisma-airs-redteam-targets-update-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_uuid | Target UUID to update. | Required |
| target_background | Target background as JSON string. Example: {"industry": "Healthcare", "use_case": "Patient Support Chatbot"}. | Optional |
| additional_context | Additional context as JSON string. Example: {"base_model": "GPT-4", "languages_supported": ["en", "es"]}. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetUpdateProfile.uuid | String | Target UUID. |
| PrismaAIRs.RedTeamTargetUpdateProfile.name | String | Target name. |
| PrismaAIRs.RedTeamTargetUpdateProfile.status | String | Target status. |
| PrismaAIRs.RedTeamTargetUpdateProfile.active | Boolean | Whether the target is active. |
| PrismaAIRs.RedTeamTargetUpdateProfile.validated | Boolean | Whether the target is validated. |
| PrismaAIRs.RedTeamTargetUpdateProfile.updated_at | String | Last update timestamp. |
| PrismaAIRs.RedTeamTargetUpdateProfile.target_background | Unknown | Updated target background. |
| PrismaAIRs.RedTeamTargetUpdateProfile.additional_context | Unknown | Updated additional context. |

### prisma-airs-redteam-targets-metadata

***
Get Red Team target field metadata. Returns field definitions (types, requirements, constraints) for all available target configuration fields. Useful for understanding what fields can be configured when creating or updating targets.

#### Base Command

`prisma-airs-redteam-targets-metadata`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamTargetMetadata | Unknown | Field metadata dictionary with field definitions. |

### prisma-airs-redteam-scan-create

***
Create a new Red Team scan job. This command submits the scan and returns immediately without polling. Use prisma-airs-redteam-scan-get to check status.

#### Base Command

`prisma-airs-redteam-scan-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Scan name for identification. | Required |
| target_uuid | UUID of the target to scan. | Required |
| job_type | Scan type - STATIC (attack library), DYNAMIC (agent-driven), or CUSTOM (prompt sets). Possible values are: STATIC, DYNAMIC, CUSTOM. Default is STATIC. | Optional |
| categories | JSON object for category filtering (STATIC scans only). Example: {"category": {"subcategory": true}}. Empty {} means all categories. | Optional |
| stream_breadth | Parallel agents per goal (DYNAMIC scans only). Default is 6. Default is 6. | Optional |
| stream_depth | Maximum conversation turns per goal (DYNAMIC scans only). Default is 10. Default is 10. | Optional |
| attack_goals | JSON array of attack goal strings (DYNAMIC scans only). Example: ["Extract PII", "Bypass content filter"]. | Optional |
| custom_prompt_sets | Comma-separated list of prompt set UUIDs (CUSTOM scans only). Required for CUSTOM type. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamScanCreate.uuid | String | Created scan job UUID. |
| PrismaAIRs.RedTeamScanCreate.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.RedTeamScanCreate.name | String | Scan name. |
| PrismaAIRs.RedTeamScanCreate.job_type | String | Job type \(STATIC, DYNAMIC, CUSTOM\). |
| PrismaAIRs.RedTeamScanCreate.status | String | Initial scan status \(typically QUEUED\). |
| PrismaAIRs.RedTeamScanCreate.target_id | String | Target UUID being scanned. |
| PrismaAIRs.RedTeamScanCreate.target_type | String | Target type. |
| PrismaAIRs.RedTeamScanCreate.total | Number | Total number of attacks in the scan. |
| PrismaAIRs.RedTeamScanCreate.completed | Number | Number of completed attacks \(initially 0\). |
| PrismaAIRs.RedTeamScanCreate.score | Number | Risk score \(null until scan completes\). |
| PrismaAIRs.RedTeamScanCreate.asr | Number | Attack Success Rate \(null until scan completes\). |
| PrismaAIRs.RedTeamScanCreate.created_at | Date | Creation timestamp. |
| PrismaAIRs.RedTeamScanCreate.updated_at | Date | Last update timestamp. |
| PrismaAIRs.RedTeamScanCreate.version | Number | Scan version. |
| PrismaAIRs.RedTeamScanCreate.job_metadata | Unknown | Job metadata containing scan configuration. |

### prisma-airs-redteam-scans-list

***
List all Red Team scans.

#### Base Command

`prisma-airs-redteam-scans-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of scans to return. Default is 50. | Optional |
| job_type | Filter by job type (e.g., STATIC, DYNAMIC, CUSTOM). | Optional |
| status | Filter by scan status (e.g., COMPLETED, RUNNING, FAILED). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamScan.uuid | String | Scan UUID. |
| PrismaAIRs.RedTeamScan.tsg_id | String | Tenant Service Group ID. |
| PrismaAIRs.RedTeamScan.job_type | String | Job type \(STATIC, DYNAMIC, CUSTOM\). |
| PrismaAIRs.RedTeamScan.status | String | Scan status. |
| PrismaAIRs.RedTeamScan.created_at | Date | Creation timestamp. |
| PrismaAIRs.RedTeamScan.updated_at | Date | Last update timestamp. |
| PrismaAIRs.RedTeamScan.target_uuid | String | Target UUID being scanned. |
| PrismaAIRs.RedTeamScan.target_name | String | Target name being scanned. |
| PrismaAIRs.RedTeamScan.started_at | Date | Scan start timestamp. |
| PrismaAIRs.RedTeamScan.completed_at | Date | Scan completion timestamp. |
| PrismaAIRs.RedTeamScan.progress | Number | Scan progress percentage. |
| PrismaAIRs.RedTeamScan.total_prompts | Number | Total number of prompts in the scan. |
| PrismaAIRs.RedTeamScan.completed_prompts | Number | Number of completed prompts. |
| PrismaAIRs.RedTeamScan.failed_prompts | Number | Number of failed prompts. |
| PrismaAIRs.RedTeamScan.error_message | String | Error message if scan failed. |

#### Command example

```
!prisma-airs-redteam-scans-list
```

#### Context Example

```json
[
    {
        "completed_at": null,
        "completed_prompts": null,
        "created_at": "2026-06-25T20:38:45.952083Z",
        "error_message": null,
        "failed_prompts": null,
        "job_type": "STATIC",
        "progress": null,
        "started_at": null,
        "status": "COMPLETED",
        "target_name": null,
        "target_uuid": null,
        "total_prompts": null,
        "tsg_id": "1234567",
        "updated_at": "2026-06-25T23:46:48.539865Z",
        "uuid": "61bac5ed-86a0-434e-bea9-79a191327e72"
    },
    {
        "completed_at": null,
        "completed_prompts": null,
        "created_at": "2026-06-22T20:01:00.197521Z",
        "error_message": null,
        "failed_prompts": null,
        "job_type": "STATIC",
        "progress": null,
        "started_at": null,
        "status": "COMPLETED",
        "target_name": null,
        "target_uuid": null,
        "total_prompts": null,
        "tsg_id": "1234567",
        "updated_at": "2026-06-22T20:17:23.809673Z",
        "uuid": "86c3cef3-768d-4438-9550-6a2188173369"
    }
]
```

#### Human Readable Output

>### Prisma AIRs Red Team Scans
>
>|Uuid|Job Type|Status|Target Name|Progress|Created At|
>|---|---|---|---|---|---|
>| 61bac5ed-86a0-434e-bea9-79a191327e72 | STATIC | COMPLETED |  |  | 2026-06-25T20:38:45.952083Z |
>| 86c3cef3-768d-4438-9550-6a2188173369 | STATIC | COMPLETED |  |  | 2026-06-22T20:01:00.197521Z |

### prisma-airs-redteam-scan-get

***
Get Red Team scan status and details by job ID.

#### Base Command

`prisma-airs-redteam-scan-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The scan job UUID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamScanGet.uuid | String | Scan UUID. |
| PrismaAIRs.RedTeamScanGet.name | String | Scan name. |
| PrismaAIRs.RedTeamScanGet.job_type | String | Job type \(STATIC, DYNAMIC, CUSTOM\). |
| PrismaAIRs.RedTeamScanGet.status | String | Scan status \(QUEUED, RUNNING, COMPLETED, FAILED, ABORTED\). |
| PrismaAIRs.RedTeamScanGet.target_id | String | Target UUID being scanned. |
| PrismaAIRs.RedTeamScanGet.target_name | String | Target name being scanned. |
| PrismaAIRs.RedTeamScanGet.total | Number | Total number of attacks in the scan. |
| PrismaAIRs.RedTeamScanGet.completed | Number | Number of completed attacks. |
| PrismaAIRs.RedTeamScanGet.score | Number | Risk score \(0-100\). |
| PrismaAIRs.RedTeamScanGet.asr | Number | Attack Success Rate \(ASR\) percentage. |
| PrismaAIRs.RedTeamScanGet.progress | String | Progress string \(e.g., "150/200"\). |
| PrismaAIRs.RedTeamScanGet.progress_percentage | Number | Progress percentage. |
| PrismaAIRs.RedTeamScanGet.created_at | Date | Creation timestamp. |
| PrismaAIRs.RedTeamScanGet.started_at | Date | Start timestamp. |
| PrismaAIRs.RedTeamScanGet.completed_at | Date | Completion timestamp. |

### prisma-airs-redteam-scan-abort

***
Abort a running Red Team scan.

#### Base Command

`prisma-airs-redteam-scan-abort`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The scan job UUID to abort. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamScanAbort.job_id | String | The aborted job UUID. |
| PrismaAIRs.RedTeamScanAbort.message | String | Abort confirmation message. |

### prisma-airs-redteam-categories-list

***
List all Red Team attack categories and subcategories.

#### Base Command

`prisma-airs-redteam-categories-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamCategory.id | String | Category ID \(e.g., SECURITY, SAFETY, COMPLIANCE, BRAND\). |
| PrismaAIRs.RedTeamCategory.display_name | String | Category display name. |
| PrismaAIRs.RedTeamCategory.description | String | Category description. |
| PrismaAIRs.RedTeamCategory.preselect | Boolean | Whether this category is preselected by default. |
| PrismaAIRs.RedTeamCategory.sub_category_count | Number | Number of subcategories. |
| PrismaAIRs.RedTeamCategory.sub_categories | Unknown | Array of subcategory objects. |

#### Command example

```
!prisma-airs-redteam-categories-list
```

#### Context Example

```json
[
    {
        "description": "Select categories for adversarial testing of security vulnerabilities and potential exploits.",
        "display_name": "Security",
        "id": "SECURITY",
        "preselect": true,
        "sub_categories": [
            {
                "active": true,
                "description": "Adversarial suffix attacks",
                "display_name": "Adversarial Suffix",
                "id": "ADVERSARIAL_SUFFIX",
                "preselect": true
            },
            {
                "active": true,
                "description": "Evasion techniques",
                "display_name": "Evasion",
                "id": "EVASION",
                "preselect": true
            },
            {
                "active": true,
                "description": "Indirect prompt injection attacks",
                "display_name": "Indirect Prompt Injection",
                "id": "INDIRECT_PROMPT_INJECTION",
                "preselect": false
            },
            {
                "active": true,
                "description": "Jailbreak attempts",
                "display_name": "Jailbreak",
                "id": "JAILBREAK",
                "preselect": true
            },
            {
                "active": false,
                "description": "Multi-turn conversation exploits",
                "display_name": "Multi-turn",
                "id": "MULTI_TURN",
                "preselect": false
            },
            {
                "active": true,
                "description": "Direct prompt injection attacks",
                "display_name": "Prompt Injection",
                "id": "PROMPT_INJECTION",
                "preselect": true
            },
            {
                "active": true,
                "description": "Remote code execution attempts",
                "display_name": "Remote Code Execution",
                "id": "REMOTE_CODE_EXECUTION",
                "preselect": true
            },
            {
                "active": true,
                "description": "System prompt extraction",
                "display_name": "System Prompt leak",
                "id": "SYSTEM_PROMPT_LEAK",
                "preselect": true
            },
            {
                "active": true,
                "description": "Tool information leakage",
                "display_name": "Tool Leak",
                "id": "TOOL_LEAK",
                "preselect": false
            },
            {
                "active": true,
                "description": "Malware generation requests",
                "display_name": "Malware Generation",
                "id": "MALWARE_GENERATION",
                "preselect": true
            }
        ],
        "sub_category_count": 10
    },
    {
        "description": "Select categories for testing harmful or toxic content and ethical misuse scenarios.",
        "display_name": "Safety",
        "id": "SAFETY",
        "preselect": true,
        "sub_categories": [
            {
                "active": true,
                "description": "Bias-related content",
                "display_name": "Bias",
                "id": "BIAS",
                "preselect": true
            },
            {
                "active": true,
                "description": "Chemical, Biological, Radiological, Nuclear content",
                "display_name": "CBRN",
                "id": "CBRN",
                "preselect": true
            },
            {
                "active": true,
                "description": "Cybercrime-related content",
                "display_name": "Cybercrime",
                "id": "CYBERCRIME",
                "preselect": true
            },
            {
                "active": true,
                "description": "Drug-related content",
                "display_name": "Drugs",
                "id": "DRUGS",
                "preselect": true
            },
            {
                "active": true,
         
... (truncated)
```

#### Human Readable Output

>### Red Team Attack Categories
>
>|Id|Display Name|Description|Sub Category Count|
>|---|---|---|---|
>| SECURITY | Security | Select categories for adversarial testing of security vulnerabilities and potential exploits. | 10 |
>| SAFETY | Safety | Select categories for testing harmful or toxic content and ethical misuse scenarios. | 10 |
>| BRAND | Brand Reputation | Select categories for testing off-brand content. | 4 |
>| COMPLIANCE | Compliance | Select framework to understand compliance across security and safety standards. | 4 |

### prisma-airs-redteam-report-get

***
Get Red Team scan report with attack results and recommendations.

#### Base Command

`prisma-airs-redteam-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The scan job UUID. | Required |
| job_type | The job type (STATIC, DYNAMIC, CUSTOM). Defaults to STATIC. Default is STATIC. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamReport.job_id | String | Scan job UUID. |
| PrismaAIRs.RedTeamReport.job_type | String | Job type \(STATIC, DYNAMIC, CUSTOM\). |
| PrismaAIRs.RedTeamReport.score | Number | Risk score \(0-100\). |
| PrismaAIRs.RedTeamReport.asr | Number | Attack Success Rate \(ASR\) percentage. |
| PrismaAIRs.RedTeamReport.total_attacks | Number | Total number of attacks. |
| PrismaAIRs.RedTeamReport.successful_attacks | Number | Number of successful attacks. |
| PrismaAIRs.RedTeamReport.failed_attacks | Number | Number of failed attacks. |
| PrismaAIRs.RedTeamReport.severity_breakdown | Unknown | Array of severity statistics. |
| PrismaAIRs.RedTeamReport.category_reports | Unknown | Array of category-level reports. |
| PrismaAIRs.RedTeamReport.report_summary | String | Executive summary of findings. |
| PrismaAIRs.RedTeamReport.total_goals | Number | Total goals \(Dynamic scans only\). |
| PrismaAIRs.RedTeamReport.goals_achieved | Number | Goals achieved \(Dynamic scans only\). |
| PrismaAIRs.RedTeamReport.total_threats | Number | Total threats detected \(Dynamic scans only\). |

### prisma-airs-redteam-eula-status

***
Get Red Team EULA acceptance status.

#### Base Command

`prisma-airs-redteam-eula-status`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamEula.uuid | String | EULA record UUID. |
| PrismaAIRs.RedTeamEula.is_accepted | Boolean | Whether the EULA is accepted. |
| PrismaAIRs.RedTeamEula.accepted_at | Date | Timestamp when EULA was accepted. |
| PrismaAIRs.RedTeamEula.accepted_by_user_id | String | User ID who accepted the EULA. |

#### Command example

```
!prisma-airs-redteam-eula-status
```

#### Context Example

```json
{
    "accepted_at": "2025-10-31T12:56:37.659000Z",
    "accepted_by_user_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
    "is_accepted": true,
    "uuid": "b6b335cf-2109-45a9-a685-7c5f42838371"
}
```

#### Human Readable Output

>## Red Team EULA Status
>
>**Status:** Accepted
>
>**Accepted At:** 2025-10-31T12:56:37.659000Z
>
>**Accepted By:** 59087f43-bd63-4d7d-940d-2ff5dd9382b3

### prisma-airs-redteam-eula-content

***
Get Red Team EULA content (full legal text).

#### Base Command

`prisma-airs-redteam-eula-content`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamEulaContent.content | String | Full EULA text content. |
| PrismaAIRs.RedTeamEulaContent.content_length | Number | Length of EULA content in characters. |

#### Command example

```
!prisma-airs-redteam-eula-content
```

#### Context Example

```json
{
    "content": "## END USER LICENSE AGREEMENT\n\n---\n\n**THIS END USER LICENSE AGREEMENT (“Agreement”) GOVERNS THE USE OF PALO ALTO\nNETWORKS PRODUCTS (as that term “Product” is defined below).**\n\nTHIS IS A LEGAL AGREEMENT BETWEEN YOU (REFERRED TO HEREIN AS “ **CUSTOMER** ” or “ **END\nUSER** ”) 
... (truncated)
```

#### Human Readable Output

>## Red Team EULA Content
>
>**Length:** 42002 characters
>
>**Content Preview:**
>
>```
>## END USER LICENSE AGREEMENT
>
>---
>
>**THIS END USER LICENSE AGREEMENT (“Agreement”) GOVERNS THE USE OF PALO ALTO
>NETWORKS PRODUCTS (as that term “Product” is defined below).**
>
>THIS IS A LEGAL AGREEMENT BETWEEN YOU (REFERRED TO HEREIN AS “ **CUSTOMER** ” or “ **END
>USER** ”) AND (A) PALO ALTO NETWORKS, INC., 3000 TANNERY WAY, SANTA CLARA, CALIFORNIA
>
>... (truncated, 41002 more characters)
>
>Full content available in context output.
>```

### prisma-airs-redteam-eula-accept

***
Accept the Red Team EULA (required before running scans).

#### Base Command

`prisma-airs-redteam-eula-accept`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accepted_at | Optional timestamp for acceptance (ISO 8601 format). If not provided, server time is used. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamEula.uuid | String | EULA record UUID. |
| PrismaAIRs.RedTeamEula.is_accepted | Boolean | Whether the EULA is accepted. |
| PrismaAIRs.RedTeamEula.accepted_at | Date | Timestamp when EULA was accepted. |
| PrismaAIRs.RedTeamEula.accepted_by_user_id | String | User ID who accepted the EULA. |

### prisma-airs-redteam-prompts-create

***
Create a new prompt in a Red Team prompt set for custom attack scenarios.

#### Base Command

`prisma-airs-redteam-prompts-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt_set_uuid | UUID of the prompt set to add the prompt to. | Required |
| prompt | The prompt text to create. | Required |
| goal | Optional custom goal for the prompt. | Optional |
| properties | Optional JSON object with additional properties for the prompt. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptCreate.uuid | String | UUID of the created prompt. |
| PrismaAIRs.RedTeamPromptCreate.prompt | String | The prompt text. |
| PrismaAIRs.RedTeamPromptCreate.user_defined_goal | Boolean | Whether the prompt has a user-defined goal. |
| PrismaAIRs.RedTeamPromptCreate.status | String | Status of the prompt \(e.g., READY, PENDING\). |
| PrismaAIRs.RedTeamPromptCreate.active | Boolean | Whether the prompt is active. |
| PrismaAIRs.RedTeamPromptCreate.prompt_set_id | String | UUID of the prompt set this prompt belongs to. |
| PrismaAIRs.RedTeamPromptCreate.created_at | Date | Timestamp when the prompt was created. |
| PrismaAIRs.RedTeamPromptCreate.updated_at | Date | Timestamp when the prompt was last updated. |
| PrismaAIRs.RedTeamPromptCreate.goal | Unknown | Optional custom goal for the prompt. |
| PrismaAIRs.RedTeamPromptCreate.properties | Unknown | Optional additional properties for the prompt. |

### prisma-airs-redteam-prompts-list

***
List prompts in a Red Team prompt set.

#### Base Command

`prisma-airs-redteam-prompts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt_set_uuid | UUID of the prompt set to list prompts from. | Required |
| limit | Maximum number of prompts to return (default 50). | Optional |
| skip | Number of prompts to skip for pagination. | Optional |
| search | Free-text search filter for prompt text. | Optional |
| status | Filter by prompt status (e.g., READY, PENDING). | Optional |
| active | Filter by active status (true or false). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPrompts.uuid | String | UUID of the prompt. |
| PrismaAIRs.RedTeamPrompts.prompt | String | The prompt text. |
| PrismaAIRs.RedTeamPrompts.user_defined_goal | Boolean | Whether the prompt has a user-defined goal. |
| PrismaAIRs.RedTeamPrompts.status | String | Status of the prompt. |
| PrismaAIRs.RedTeamPrompts.active | Boolean | Whether the prompt is active. |
| PrismaAIRs.RedTeamPrompts.created_at | Date | Timestamp when the prompt was created. |
| PrismaAIRs.RedTeamPrompts.updated_at | Date | Timestamp when the prompt was last updated. |
| PrismaAIRs.RedTeamPrompts.goal | Unknown | Optional custom goal for the prompt. |
| PrismaAIRs.RedTeamPrompts.properties | Unknown | Optional additional properties for the prompt. |

### prisma-airs-redteam-prompts-get

***
Get details of a specific prompt in a Red Team prompt set.

#### Base Command

`prisma-airs-redteam-prompts-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt_set_uuid | UUID of the prompt set containing the prompt. | Required |
| prompt_uuid | UUID of the prompt to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptGet.uuid | String | UUID of the prompt. |
| PrismaAIRs.RedTeamPromptGet.prompt | String | The prompt text. |
| PrismaAIRs.RedTeamPromptGet.user_defined_goal | Boolean | Whether the prompt has a user-defined goal. |
| PrismaAIRs.RedTeamPromptGet.status | String | Status of the prompt. |
| PrismaAIRs.RedTeamPromptGet.active | Boolean | Whether the prompt is active. |
| PrismaAIRs.RedTeamPromptGet.prompt_set_id | String | UUID of the prompt set this prompt belongs to. |
| PrismaAIRs.RedTeamPromptGet.created_at | Date | Timestamp when the prompt was created. |
| PrismaAIRs.RedTeamPromptGet.updated_at | Date | Timestamp when the prompt was last updated. |
| PrismaAIRs.RedTeamPromptGet.goal | Unknown | Optional custom goal for the prompt. |
| PrismaAIRs.RedTeamPromptGet.properties | Unknown | Optional additional properties for the prompt. |
| PrismaAIRs.RedTeamPromptGet.property_assignments | Unknown | Optional property assignments for the prompt. |
| PrismaAIRs.RedTeamPromptGet.detector_category | Unknown | Optional detector category for the prompt. |
| PrismaAIRs.RedTeamPromptGet.severity | Unknown | Optional severity level for the prompt. |
| PrismaAIRs.RedTeamPromptGet.extra_info | Unknown | Optional extra information about the prompt. |

### prisma-airs-redteam-prompts-update

***
Update an existing prompt in a Red Team prompt set.

#### Base Command

`prisma-airs-redteam-prompts-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt_set_uuid | UUID of the prompt set containing the prompt. | Required |
| prompt_uuid | UUID of the prompt to update. | Required |
| prompt | Updated prompt text. | Optional |
| goal | Updated custom goal. | Optional |
| properties | Updated properties JSON object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptUpdate.uuid | String | UUID of the updated prompt. |
| PrismaAIRs.RedTeamPromptUpdate.prompt | String | The updated prompt text. |
| PrismaAIRs.RedTeamPromptUpdate.user_defined_goal | Boolean | Whether the prompt has a user-defined goal. |
| PrismaAIRs.RedTeamPromptUpdate.status | String | Status of the prompt. |
| PrismaAIRs.RedTeamPromptUpdate.active | Boolean | Whether the prompt is active. |
| PrismaAIRs.RedTeamPromptUpdate.prompt_set_id | String | UUID of the prompt set this prompt belongs to. |
| PrismaAIRs.RedTeamPromptUpdate.created_at | Date | Timestamp when the prompt was created. |
| PrismaAIRs.RedTeamPromptUpdate.updated_at | Date | Timestamp when the prompt was last updated. |
| PrismaAIRs.RedTeamPromptUpdate.goal | Unknown | Optional custom goal for the prompt. |
| PrismaAIRs.RedTeamPromptUpdate.properties | Unknown | Optional additional properties for the prompt. |

### prisma-airs-redteam-prompts-delete

***
Delete a prompt from a Red Team prompt set.

#### Base Command

`prisma-airs-redteam-prompts-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt_set_uuid | UUID of the prompt set containing the prompt. | Required |
| prompt_uuid | UUID of the prompt to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptDeleted.prompt_uuid | String | UUID of the deleted prompt. |
| PrismaAIRs.RedTeamPromptDeleted.prompt_set_uuid | String | UUID of the prompt set. |
| PrismaAIRs.RedTeamPromptDeleted.status | String | Deletion status. |
| PrismaAIRs.RedTeamPromptDeleted.message | String | Optional deletion message. |

### prisma-airs-redteam-prompt-sets-create

***
Create a new Red Team prompt set for organizing custom attack prompts.

#### Base Command

`prisma-airs-redteam-prompt-sets-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the prompt set. | Required |
| description | Description of the prompt set. | Optional |
| property_names | Comma-separated list of custom property names for the prompt set (e.g., "category,severity"). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptSetCreate.uuid | String | UUID of the created prompt set. |
| PrismaAIRs.RedTeamPromptSetCreate.name | String | Name of the prompt set. |
| PrismaAIRs.RedTeamPromptSetCreate.active | Boolean | Whether the prompt set is active. |
| PrismaAIRs.RedTeamPromptSetCreate.archive | Boolean | Whether the prompt set is archived. |
| PrismaAIRs.RedTeamPromptSetCreate.status | String | Status of the prompt set \(e.g., READY, PENDING\). |
| PrismaAIRs.RedTeamPromptSetCreate.created_at | Date | Timestamp when the prompt set was created. |
| PrismaAIRs.RedTeamPromptSetCreate.updated_at | Date | Timestamp when the prompt set was last updated. |
| PrismaAIRs.RedTeamPromptSetCreate.description | Unknown | Description of the prompt set. |
| PrismaAIRs.RedTeamPromptSetCreate.property_names | Unknown | Array of custom property names. |
| PrismaAIRs.RedTeamPromptSetCreate.properties | Unknown | Array of property definitions. |
| PrismaAIRs.RedTeamPromptSetCreate.stats | Unknown | Statistics about the prompt set. |
| PrismaAIRs.RedTeamPromptSetCreate.version | Unknown | Version information. |
| PrismaAIRs.RedTeamPromptSetCreate.created_by_user_id | Unknown | User ID who created the prompt set. |
| PrismaAIRs.RedTeamPromptSetCreate.updated_by_user_id | Unknown | User ID who last updated the prompt set. |

### prisma-airs-redteam-prompt-sets-list

***
List Red Team prompt sets for custom attack scenarios.

#### Base Command

`prisma-airs-redteam-prompt-sets-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of prompt sets to return (default 50). | Optional |
| skip | Number of prompt sets to skip for pagination. | Optional |
| search | Free-text search filter for prompt set names/descriptions. | Optional |
| status | Filter by prompt set status (e.g., READY, PENDING). | Optional |
| active | Filter by active status (true or false). | Optional |
| archive | Filter by archive status (true or false). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptSets.uuid | String | UUID of the prompt set. |
| PrismaAIRs.RedTeamPromptSets.name | String | Name of the prompt set. |
| PrismaAIRs.RedTeamPromptSets.active | Boolean | Whether the prompt set is active. |
| PrismaAIRs.RedTeamPromptSets.archive | Boolean | Whether the prompt set is archived. |
| PrismaAIRs.RedTeamPromptSets.status | String | Status of the prompt set. |
| PrismaAIRs.RedTeamPromptSets.created_at | Date | Timestamp when created. |
| PrismaAIRs.RedTeamPromptSets.updated_at | Date | Timestamp when last updated. |
| PrismaAIRs.RedTeamPromptSets.description | Unknown | Description of the prompt set. |
| PrismaAIRs.RedTeamPromptSets.property_names | Unknown | Array of custom property names. |
| PrismaAIRs.RedTeamPromptSets.stats | Unknown | Statistics about the prompt set. |
| PrismaAIRs.RedTeamPromptSets.created_by_user_id | Unknown | User ID who created the prompt set. |

#### Command example

```
!prisma-airs-redteam-prompt-sets-list
```

#### Context Example

```json
[
    {
        "active": true,
        "archive": false,
        "created_at": "2026-05-08T18:31:07.121412Z",
        "created_by_user_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "description": "https://github.com/scthornton/prompt-database",
        "name": "prompt-database-gt8",
        "property_names": [
            "Semantic Category",
            "Complexity"
        ],
        "stats": {
            "active_prompts": 250,
            "failed_prompts": 0,
            "inactive_prompts": 0,
            "total_prompts": 250,
            "validation_prompts": 0
        },
        "status": "VALIDATED",
        "updated_at": "2026-05-08T18:32:06.656700Z",
        "uuid": "adf6e1bd-61f1-4e57-9650-b40f26b981cb"
    },
    {
        "active": true,
        "archive": false,
        "created_at": "2025-12-14T01:04:00.293326Z",
        "created_by_user_id": "59087f43-bd63-4d7d-940d-2ff5dd9382b3",
        "name": "Customer1-AttackSet-Dec12",
        "property_names": [
            "Semantic Category",
            "Severity"
        ],
        "stats": {
            "active_prompts": 17,
            "failed_prompts": 0,
            "inactive_prompts": 0,
            "total_prompts": 17,
            "validation_prompts": 0
        },
        "status": "VALIDATED",
        "updated_at": "2025-12-14T01:34:46.863454Z",
        "uuid": "73eea776-ecbf-4a5d-9098-a37744441fca"
    }
]
```

#### Human Readable Output

>## Red Team Prompt Sets (Total: 6)
>
>| UUID | Name | Status | Active | Archive | Description |
>|------|------|--------|--------|---------|-------------|
>| adf6e1bd-61f1-4e57-9650-b40f26b981cb | prompt-database-gt8 | VALIDATED | True | False | https://github.com/scthornton/... |
>| 73eea776-ecbf-4a5d-9098-a37744441fca | Customer1-AttackSet-Dec12 | VALIDATED | True | False | N/A |
>| f9f8cd22-22b9-4754-8656-15b2e51b6952 | HarmBench | VALIDATED | True | False | https://github.com/centerforai... |
>| 06d2a36e-49ac-4712-b7ca-e87e4ba9d9fe | Customer1-AttackSet-HateAndFairness | VALIDATED | True | False | N/A |
>| a9731c3a-f989-40ff-8a7b-efadaf4a490b | Customer1-AttackSet-EnterpriseReputation | VALIDATED | True | False | N/A |
>| 84364729-1dc6-498a-a7d0-d26c4d5cf697 | Customer1-AttackSet-Sexual | VALIDATED | True | False | N/A |

### prisma-airs-redteam-prompt-sets-get

***
Get details of a specific Red Team prompt set.

#### Base Command

`prisma-airs-redteam-prompt-sets-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the prompt set to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptSetGet.uuid | String | UUID of the prompt set. |
| PrismaAIRs.RedTeamPromptSetGet.name | String | Name of the prompt set. |
| PrismaAIRs.RedTeamPromptSetGet.active | Boolean | Whether the prompt set is active. |
| PrismaAIRs.RedTeamPromptSetGet.archive | Boolean | Whether the prompt set is archived. |
| PrismaAIRs.RedTeamPromptSetGet.status | String | Status of the prompt set. |
| PrismaAIRs.RedTeamPromptSetGet.created_at | Date | Timestamp when created. |
| PrismaAIRs.RedTeamPromptSetGet.updated_at | Date | Timestamp when last updated. |
| PrismaAIRs.RedTeamPromptSetGet.description | Unknown | Description of the prompt set. |
| PrismaAIRs.RedTeamPromptSetGet.property_names | Unknown | Array of custom property names. |
| PrismaAIRs.RedTeamPromptSetGet.properties | Unknown | Array of property definitions. |
| PrismaAIRs.RedTeamPromptSetGet.stats | Unknown | Statistics about the prompt set. |
| PrismaAIRs.RedTeamPromptSetGet.extra_info | Unknown | Additional information. |
| PrismaAIRs.RedTeamPromptSetGet.version | Unknown | Version information. |
| PrismaAIRs.RedTeamPromptSetGet.created_by_user_id | Unknown | User ID who created the prompt set. |
| PrismaAIRs.RedTeamPromptSetGet.updated_by_user_id | Unknown | User ID who last updated the prompt set. |

### prisma-airs-redteam-prompt-sets-update

***
Update an existing Red Team prompt set.

#### Base Command

`prisma-airs-redteam-prompt-sets-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the prompt set to update. | Required |
| name | Updated name of the prompt set. | Optional |
| description | Updated description. | Optional |
| property_names | Updated comma-separated list of custom property names. | Optional |
| archive | Updated archive status (true or false). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptSetUpdate.uuid | String | UUID of the updated prompt set. |
| PrismaAIRs.RedTeamPromptSetUpdate.name | String | Name of the prompt set. |
| PrismaAIRs.RedTeamPromptSetUpdate.active | Boolean | Whether the prompt set is active. |
| PrismaAIRs.RedTeamPromptSetUpdate.archive | Boolean | Whether the prompt set is archived. |
| PrismaAIRs.RedTeamPromptSetUpdate.status | String | Status of the prompt set. |
| PrismaAIRs.RedTeamPromptSetUpdate.created_at | Date | Timestamp when created. |
| PrismaAIRs.RedTeamPromptSetUpdate.updated_at | Date | Timestamp when last updated. |
| PrismaAIRs.RedTeamPromptSetUpdate.description | Unknown | Description of the prompt set. |
| PrismaAIRs.RedTeamPromptSetUpdate.property_names | Unknown | Array of custom property names. |
| PrismaAIRs.RedTeamPromptSetUpdate.properties | Unknown | Array of property definitions. |
| PrismaAIRs.RedTeamPromptSetUpdate.stats | Unknown | Statistics about the prompt set. |
| PrismaAIRs.RedTeamPromptSetUpdate.version | Unknown | Version information. |
| PrismaAIRs.RedTeamPromptSetUpdate.updated_by_user_id | Unknown | User ID who last updated the prompt set. |

### prisma-airs-redteam-prompt-sets-archive

***
Archive or unarchive a Red Team prompt set.

#### Base Command

`prisma-airs-redteam-prompt-sets-archive`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the prompt set to archive/unarchive. | Required |
| archive | Archive status - true to archive, false to unarchive. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptSetArchive.uuid | String | UUID of the prompt set. |
| PrismaAIRs.RedTeamPromptSetArchive.name | String | Name of the prompt set. |
| PrismaAIRs.RedTeamPromptSetArchive.active | Boolean | Whether the prompt set is active. |
| PrismaAIRs.RedTeamPromptSetArchive.archive | Boolean | Whether the prompt set is archived. |
| PrismaAIRs.RedTeamPromptSetArchive.status | String | Status of the prompt set. |
| PrismaAIRs.RedTeamPromptSetArchive.created_at | Date | Timestamp when created. |
| PrismaAIRs.RedTeamPromptSetArchive.updated_at | Date | Timestamp when last updated. |
| PrismaAIRs.RedTeamPromptSetArchive.description | Unknown | Description of the prompt set. |
| PrismaAIRs.RedTeamPromptSetArchive.property_names | Unknown | Array of custom property names. |
| PrismaAIRs.RedTeamPromptSetArchive.properties | Unknown | Array of property definitions. |
| PrismaAIRs.RedTeamPromptSetArchive.stats | Unknown | Statistics about the prompt set. |
| PrismaAIRs.RedTeamPromptSetArchive.version | Unknown | Version information. |

### prisma-airs-redteam-registry-credentials-get

***
Get or create Red Team registry credentials for pulling scanner container images from the Prisma AIRs registry.

#### Base Command

`prisma-airs-redteam-registry-credentials-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamRegistryCredentials.token | String | Registry access token for authenticating with the container registry. |
| PrismaAIRs.RedTeamRegistryCredentials.expiry | Date | Token expiry timestamp \(ISO 8601 format\). |

### prisma-airs-redteam-prompt-sets-download

***
Download CSV template for a Red Team prompt set. The template includes header row and sample data for bulk prompt uploads.

#### Base Command

`prisma-airs-redteam-prompt-sets-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the prompt set to download the template for. | Required |

#### Context Output

There is no context output for this command.

### prisma-airs-redteam-prompt-sets-upload

***
Upload CSV file with prompts to a Red Team prompt set. CSV must have 'prompt' and 'goal' columns (goal is optional).

#### Base Command

`prisma-airs-redteam-prompt-sets-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the prompt set to upload prompts to. | Required |
| entryID | Entry ID of the CSV file from the war room to upload. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RedTeamPromptSetUpload.message | String | Response message from the upload operation. |
| PrismaAIRs.RedTeamPromptSetUpload.status | Number | HTTP status code of the upload operation. |
| PrismaAIRs.RedTeamPromptSetUpload.prompt_set_uuid | String | UUID of the prompt set that was uploaded to. |
| PrismaAIRs.RedTeamPromptSetUpload.file_name | String | Name of the uploaded CSV file. |
