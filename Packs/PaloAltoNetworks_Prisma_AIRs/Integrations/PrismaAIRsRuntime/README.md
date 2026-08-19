Integrate with Palo Alto Networks Prisma AIRs for AI security capabilities including runtime scanning, red teaming, model security, and DLP configuration.
This integration was integrated and tested with version xx of Palo Alto Networks Prisma AIRS - AI Runtime Security.

## Configure Palo Alto Networks Prisma AIRS - AI Runtime Security in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Client ID |  | True |
| API Client Secret |  | True |
| Runtime API Key | Runtime API Key for Prisma AIRs Scanner API. This is used exclusively for runtime scanning operations and is different from the OAuth2 Client ID/Secret used for management operations. | True |
| Tenant Services Group ID | Default Tenant Services Group ID to use for API calls. Example: 1234567890. | True |
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
| response | The optional response text to scan alongside the prompt. | Optional |
| tr_id | The unique identifier string for correlating the prompt and response transactions. Returned in the scan response. | Optional |
| session_id | The unique identifier string for tracking sessions. Returned in the scan response. | Optional |
| app_name | The AI application requesting the content scan. | Optional |
| app_user | The end user using the AI application. | Optional |
| ai_model | The AI model serving the AI application. | Optional |
| user_ip | The end user IP address using the AI application. | Optional |
| agent_id | The agent identifier for metadata tracking. | Optional |
| agent_version | The agent version for metadata tracking. | Optional |
| agent_arn | The agent ARN for metadata tracking. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RuntimeScan.scan_id | String | The unique scan identifier. |
| PrismaAIRs.RuntimeScan.report_id | String | The report identifier for this scan. |
| PrismaAIRs.RuntimeScan.tr_id | String | The transaction ID passed in the request and returned in the response. |
| PrismaAIRs.RuntimeScan.session_id | String | The session ID passed in the request and returned in the response. |
| PrismaAIRs.RuntimeScan.prompt | String | The scanned prompt text. |
| PrismaAIRs.RuntimeScan.response | String | The scanned response text. |
| PrismaAIRs.RuntimeScan.action | String | The action taken \(allow or block\). |
| PrismaAIRs.RuntimeScan.category | String | The threat category \(benign, malicious, etc.\). |
| PrismaAIRs.RuntimeScan.detected | Boolean | Whether any threat was detected across prompt or response. |
| PrismaAIRs.RuntimeScan.prompt_detected | Unknown | The object containing all detection types for the prompt \(e.g., injection, dlp, toxic_content, topic_violation, url_cats, malicious_code, agent\). |
| PrismaAIRs.RuntimeScan.response_detected | Unknown | The object containing all detection types for the response \(e.g., dlp, toxic_content, topic_violation, url_cats, malicious_code, agent, db_security, ungrounded\). |
| PrismaAIRs.RuntimeScan.profile_id | String | The profile ID used for scanning. |
| PrismaAIRs.RuntimeScan.profile_name | String | The profile name used for scanning. |
| PrismaAIRs.RuntimeScan.source | String | The source of the scan request. |
| PrismaAIRs.RuntimeScan.timeout | Boolean | Whether any detection service timed out. |
| PrismaAIRs.RuntimeScan.error | Boolean | Whether any detection service encountered an error. |
| PrismaAIRs.RuntimeScan.errors | Unknown | The list of detection service errors or timeouts. |

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
| limit | The maximum number of API keys to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKey.id | String | The API Key ID \(UUID\). |
| PrismaAIRs.ApiKey.name | String | The API Key name. |
| PrismaAIRs.ApiKey.last8 | String | The last 8 characters of the API key \(for identification\). |
| PrismaAIRs.ApiKey.created_at | Date | The API Key creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.ApiKey.expires_at | Date | The API Key expiration timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
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
| api_key_name | The name for the new API key. | Required |
| auth_code | The deployment profile auth code (obtained from deployment profile). | Required |
| cust_app | The customer application name using this API key. | Required |
| rotation_time_interval | The rotation time interval (number). | Required |
| rotation_time_unit | The rotation time unit. Possible values are: hours, days, months. | Required |
| created_by | The email of the user creating the API key. | Required |
| dp_name | The deployment profile name (optional). | Optional |
| cust_env | The customer environment (e.g., production, staging). The underlying customer app record mandates an environment value; omitting it causes the API to return "Error inserting/updating customer app record", so this argument is required. | Required |
| cust_cloud_provider | The customer cloud provider (e.g., aws, gcp, azure). The underlying customer app record mandates a cloud provider value; omitting it causes the API to return "Error inserting/updating customer app record", so this argument is required. | Required |
| cust_ai_agent_framework | The customer AI agent framework (optional). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKeyCreate.id | String | The created API Key ID \(UUID\). |
| PrismaAIRs.ApiKeyCreate.name | String | The API Key name. |
| PrismaAIRs.ApiKeyCreate.api_key | String | The FULL API KEY SECRET - Only shown once\! Save this securely. |
| PrismaAIRs.ApiKeyCreate.last8 | String | The last 8 characters of the API key. |
| PrismaAIRs.ApiKeyCreate.auth_code | String | The auth code associated with the key. |
| PrismaAIRs.ApiKeyCreate.expires_at | Date | The API Key expiration timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.ApiKeyCreate.revoked | Boolean | Whether the API key has been revoked. |
| PrismaAIRs.ApiKeyCreate.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.ApiKeyCreate.created_by | String | The user who created the key. |
| PrismaAIRs.ApiKeyCreate.cust_app | String | The customer application name. |

### prisma-airs-runtime-api-keys-regenerate

***
Regenerate an existing Runtime API Key. WARNING - This creates a NEW key with a NEW UUID and invalidates the old key. The new secret is only shown once.

#### Base Command

`prisma-airs-runtime-api-keys-regenerate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_key_id | The UUID of the API key to regenerate. | Required |
| rotation_time_interval | The new rotation time interval (number). | Required |
| rotation_time_unit | The new rotation time unit. Possible values are: hours, days, months. | Required |
| updated_by | The email of the user performing regeneration (optional). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKeyRegenerate.id | String | The NEW API Key ID \(UUID\) - different from the old one. |
| PrismaAIRs.ApiKeyRegenerate.name | String | The API Key name \(same as before\). |
| PrismaAIRs.ApiKeyRegenerate.api_key | String | The NEW FULL API KEY SECRET - Only shown once\! The old key is now invalid. |
| PrismaAIRs.ApiKeyRegenerate.last8 | String | The last 8 characters of the new API key. |
| PrismaAIRs.ApiKeyRegenerate.auth_code | String | The auth code associated with the key. |
| PrismaAIRs.ApiKeyRegenerate.expires_at | Date | The new expiration timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.ApiKeyRegenerate.revoked | Boolean | Whether the API key has been revoked. |
| PrismaAIRs.ApiKeyRegenerate.updated_at | Date | The update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.ApiKeyRegenerate.updated_by | String | The user who regenerated the key. |
| PrismaAIRs.ApiKeyRegenerate.cust_app | String | The customer application name. |

### prisma-airs-runtime-api-keys-delete

***
Delete a Runtime API Key by name. WARNING - This action cannot be undone and immediately revokes access for all applications using this key.

#### Base Command

`prisma-airs-runtime-api-keys-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_key_name | The name of the API key to delete. | Required |
| updated_by | The email of the user performing the deletion. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.ApiKeyDeleted.api_key_name | String | The name of the deleted API key. |
| PrismaAIRs.ApiKeyDeleted.deleted_by | String | The email of the user who deleted the key. |
| PrismaAIRs.ApiKeyDeleted.message | String | The deletion confirmation message. |
| PrismaAIRs.ApiKeyDeleted.deleted | Boolean | The boolean indicating successful deletion. |

### prisma-airs-runtime-profiles-list

***
List all runtime security profiles.

#### Base Command

`prisma-airs-runtime-profiles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of profiles to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfile.id | String | The profile ID \(UUID\). |
| PrismaAIRs.SecurityProfile.name | String | The profile name. |
| PrismaAIRs.SecurityProfile.revision | Number | The profile revision number. |
| PrismaAIRs.SecurityProfile.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfile.created_by | String | The user who created the profile. |
| PrismaAIRs.SecurityProfile.updated_by | String | The user who last updated the profile. |
| PrismaAIRs.SecurityProfile.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.SecurityProfile.tsg_id | String | The tenant Service Group ID. |

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
| profile_id | The profile UUID (either profile_id or profile_name is required). | Optional |
| profile_name | The profile name (returns highest-revision match if multiple exist). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileGet.id | String | The profile ID \(UUID\). |
| PrismaAIRs.SecurityProfileGet.name | String | The profile name. |
| PrismaAIRs.SecurityProfileGet.revision | Number | The profile revision number. |
| PrismaAIRs.SecurityProfileGet.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfileGet.policy | Unknown | The full policy configuration \(AI security profiles and DLP data profiles\). |
| PrismaAIRs.SecurityProfileGet.created_by | String | The user who created the profile. |
| PrismaAIRs.SecurityProfileGet.updated_by | String | The user who last updated the profile. |
| PrismaAIRs.SecurityProfileGet.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.SecurityProfileGet.tsg_id | String | The tenant Service Group ID. |
| PrismaAIRs.SecurityProfileGet.csp_id | String | The cloud Service Provider ID. |

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
| profile_name | The name for the new security profile (must be unique). | Required |
| active | Whether the profile should be active. Possible values are: true, false. Default is true. | Optional |
| policy | The policy configuration as JSON string. Structure - ai-security-profiles array and dlp-data-profiles array. If omitted, creates empty policy. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileCreate.id | String | The profile ID \(UUID\). |
| PrismaAIRs.SecurityProfileCreate.name | String | The profile name. |
| PrismaAIRs.SecurityProfileCreate.revision | Number | The profile revision number \(starts at 1\). |
| PrismaAIRs.SecurityProfileCreate.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfileCreate.policy | Unknown | The full policy configuration. |
| PrismaAIRs.SecurityProfileCreate.created_by | String | The user who created the profile. |
| PrismaAIRs.SecurityProfileCreate.updated_by | String | The user who last updated the profile. |
| PrismaAIRs.SecurityProfileCreate.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.SecurityProfileCreate.tsg_id | String | The tenant Service Group ID. |
| PrismaAIRs.SecurityProfileCreate.csp_id | String | The cloud Service Provider ID. |

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
| profile_id | The profile UUID to update. | Required |
| profile_name | The profile name (can be changed or kept the same). | Required |
| active | Whether the profile should be active. Possible values are: true, false. | Optional |
| policy | The updated policy configuration as JSON string. If omitted, policy remains unchanged. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileUpdate.id | String | The profile ID \(UUID\). |
| PrismaAIRs.SecurityProfileUpdate.name | String | The profile name. |
| PrismaAIRs.SecurityProfileUpdate.revision | Number | The profile revision number \(incremented after update\). |
| PrismaAIRs.SecurityProfileUpdate.active | Boolean | Whether the profile is active. |
| PrismaAIRs.SecurityProfileUpdate.policy | Unknown | The full policy configuration. |
| PrismaAIRs.SecurityProfileUpdate.created_by | String | The user who created the profile. |
| PrismaAIRs.SecurityProfileUpdate.updated_by | String | The user who last updated the profile. |
| PrismaAIRs.SecurityProfileUpdate.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.SecurityProfileUpdate.tsg_id | String | The tenant Service Group ID. |
| PrismaAIRs.SecurityProfileUpdate.csp_id | String | The cloud Service Provider ID. |

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
| profile_id | The profile UUID to delete. | Required |
| force | Whether to force-delete the profile, bypassing safety checks. Requires updated_by. Possible values are: true, false. Default is false. | Optional |
| updated_by | The email of the user performing the deletion. Required when force is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.SecurityProfileDeleted.profile_id | String | The deleted profile ID. |
| PrismaAIRs.SecurityProfileDeleted.message | String | The deletion confirmation message. |
| PrismaAIRs.SecurityProfileDeleted.deleted | Boolean | The boolean indicating successful deletion. |
| PrismaAIRs.SecurityProfileDeleted.force | Boolean | Whether the profile was force-deleted. |

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
>|Profile Id|Message|Deleted|Force|
>|---|---|---|---|
>| a0e6e9b0-edda-44cc-b1ed-37407ab7098c | successfully deleted profileId: a0e6e9b0-edda-44cc-b1ed-37407ab7098c | true | false |
>
>
>**⚠️ WARNING:** This action cannot be undone. The security profile has been permanently deleted.

#### Command example (force-delete)

```
!prisma-airs-runtime-profiles-delete profile_id="96f9d6c1-1613-40db-bcca-74aeb3ff6ba1" force="true" updated_by="admin@example.com"
```

#### Human Readable Output (force-delete)

>### Security Profile Force-Deleted
>
>|Profile Id|Message|Deleted|Force|
>|---|---|---|---|
>| 96f9d6c1-1613-40db-bcca-74aeb3ff6ba1 | successfully force deleted profileId: 96f9d6c1-1613-40db-bcca-74aeb3ff6ba1 | true | true |
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
| limit | The maximum number of customer apps to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerApp.id | String | The customer App ID. |
| PrismaAIRs.CustomerApp.name | String | The customer App name. |
| PrismaAIRs.CustomerApp.model_name | String | The model name used by the app. |
| PrismaAIRs.CustomerApp.cloud_provider | String | The cloud provider. |
| PrismaAIRs.CustomerApp.environment | String | The environment \(prod, staging, dev\). |
| PrismaAIRs.CustomerApp.ai_agent_framework | String | The AI agent framework used. |
| PrismaAIRs.CustomerApp.tsg_id | String | The tenant Service Group ID. |

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
| app_name | The name of the customer application to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppGet.id | String | The customer App ID \(UUID\). |
| PrismaAIRs.CustomerAppGet.name | String | The customer App name. |
| PrismaAIRs.CustomerAppGet.model_name | String | The model name used by the app. |
| PrismaAIRs.CustomerAppGet.cloud_provider | String | The cloud provider \(aws, azure, gcp, other\). |
| PrismaAIRs.CustomerAppGet.environment | String | The environment \(prod, staging, dev\). |
| PrismaAIRs.CustomerAppGet.ai_agent_framework | String | The AI agent framework used. |
| PrismaAIRs.CustomerAppGet.tsg_id | String | The tenant Service Group ID. |
| PrismaAIRs.CustomerAppGet.status | String | The customer App status. |
| PrismaAIRs.CustomerAppGet.created_by | String | The email of user who created the app. |
| PrismaAIRs.CustomerAppGet.updated_by | String | The email of user who last updated the app. |

### prisma-airs-runtime-customer-apps-update

***
Update a customer application configuration.

#### Base Command

`prisma-airs-runtime-customer-apps-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_app_id | The UUID of the customer application to update. | Required |
| app_name | The application name. | Required |
| cloud_provider | The cloud provider. Possible values are: aws, azure, gcp, other. | Required |
| environment | The environment. Possible values are: prod, staging, dev. | Required |
| tsg_id | The tenant Service Group ID. If not provided, the configured TSG ID is used. | Optional |
| model_name | The model name used by the application. | Optional |
| ai_agent_framework | The AI agent framework used by the application. | Optional |
| updated_by | The email of user performing the update. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppUpdate.id | String | The customer App ID \(UUID\). |
| PrismaAIRs.CustomerAppUpdate.name | String | The customer App name. |
| PrismaAIRs.CustomerAppUpdate.model_name | String | The model name used by the app. |
| PrismaAIRs.CustomerAppUpdate.cloud_provider | String | The cloud provider \(aws, azure, gcp, other\). |
| PrismaAIRs.CustomerAppUpdate.environment | String | The environment \(prod, staging, dev\). |
| PrismaAIRs.CustomerAppUpdate.ai_agent_framework | String | The AI agent framework used. |
| PrismaAIRs.CustomerAppUpdate.tsg_id | String | The tenant Service Group ID. |
| PrismaAIRs.CustomerAppUpdate.status | String | The customer App status. |
| PrismaAIRs.CustomerAppUpdate.created_by | String | The email of user who created the app. |
| PrismaAIRs.CustomerAppUpdate.updated_by | String | The email of user who last updated the app. |

### prisma-airs-runtime-customer-apps-consumption

***
Get per-application token consumption and session statistics over the requested time window.

#### Base Command

`prisma-airs-runtime-customer-apps-consumption`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | The customer Application UUID (from customer-apps-list or customer-apps-get). | Required |
| app_name | The application display name (literal metadata.app_name value from scan payloads). | Required |
| time_interval | The look-back window in days (7, 30, or 60). Possible values are: 7, 30, 60. Default is 30. | Optional |
| time_unit | The time unit (only 'days' is supported by API). Default is days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppConsumption.id | String | The customer App ID. |
| PrismaAIRs.CustomerAppConsumption.name | String | The application name. |
| PrismaAIRs.CustomerAppConsumption.cloud | String | The cloud provider. |
| PrismaAIRs.CustomerAppConsumption.source | String | The source \(api, sdk, etc.\). |
| PrismaAIRs.CustomerAppConsumption.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.CustomerAppConsumption.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.CustomerAppConsumption.profiles | Unknown | The attached security profiles. |
| PrismaAIRs.CustomerAppConsumption.average_daily_tokens | Number | The average daily token consumption. |
| PrismaAIRs.CustomerAppConsumption.average_daily_tokens_scale | String | The scale for daily tokens \(K, M, etc.\). |
| PrismaAIRs.CustomerAppConsumption.monthly_total_tokens | Number | The monthly total token consumption. |
| PrismaAIRs.CustomerAppConsumption.monthly_total_tokens_scale | String | The scale for monthly tokens \(K, M, etc.\). |
| PrismaAIRs.CustomerAppConsumption.sessions_total | Number | The total sessions in time window. |
| PrismaAIRs.CustomerAppConsumption.sessions_violating | Number | The number of violating sessions. |
| PrismaAIRs.CustomerAppConsumption.last_session_id | String | The last session ID. |
| PrismaAIRs.CustomerAppConsumption.most_recent_session_time | Date | The most recent session timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.CustomerAppConsumption.violations_critical | Number | The critical violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_high | Number | The high violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_medium | Number | The medium violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_low | Number | The low violations count. |
| PrismaAIRs.CustomerAppConsumption.violations_total | Number | The total violations count. |

### prisma-airs-runtime-customer-apps-violations

***
Get per-detector violation severity breakdown for an application over the requested time window.

#### Base Command

`prisma-airs-runtime-customer-apps-violations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | The customer Application UUID (from customer-apps-list or customer-apps-get). | Required |
| app_name | The application display name (literal metadata.app_name value from scan payloads). | Required |
| time_interval | The look-back window in days (7, 30, or 60). Possible values are: 7, 30, 60. Default is 30. | Optional |
| time_unit | The time unit (only 'days' is supported by API). Default is days. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppViolations.app_id | String | The customer App ID. |
| PrismaAIRs.CustomerAppViolations.app_name | String | The application name. |
| PrismaAIRs.CustomerAppViolations.total_violating | Number | The total number of violating sessions. |
| PrismaAIRs.CustomerAppViolations.time_interval | Number | The time window in days. |
| PrismaAIRs.CustomerAppViolations.time_unit | String | The time unit used. |
| PrismaAIRs.CustomerAppViolations.detectors | Unknown | The per-detector violation breakdown array. |
| PrismaAIRs.CustomerAppViolations.detectors.detection_type | String | The detector type \(agent_security, dbs, dlp, malicious_code, pi, source_code, tc, topic_guardrails, uf, contextual_grounding\). |
| PrismaAIRs.CustomerAppViolations.detectors.critical | Number | The critical violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.high | Number | The high violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.medium | Number | The medium violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.low | Number | The low violations count for this detector. |
| PrismaAIRs.CustomerAppViolations.detectors.total | Number | The total violations count for this detector. |

### prisma-airs-runtime-customer-apps-delete

***
Delete a customer application and all associated API keys. WARNING - This action cannot be undone and immediately revokes all API keys for this application.

#### Base Command

`prisma-airs-runtime-customer-apps-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_name | The name of the customer application to delete. | Required |
| updated_by | The email of the user performing the deletion. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.CustomerAppDeleted.app_name | String | The name of the deleted customer application. |
| PrismaAIRs.CustomerAppDeleted.deleted_by | String | The email of the user who deleted the application. |
| PrismaAIRs.CustomerAppDeleted.message | String | The deletion confirmation message. |
| PrismaAIRs.CustomerAppDeleted.deleted | Boolean | The boolean indicating successful deletion. |

### prisma-airs-runtime-deployment-profiles-list

***
List all deployment profiles.

#### Base Command

`prisma-airs-runtime-deployment-profiles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of deployment profiles to return. Default is 50. | Optional |
| unactivated | Whether to show only unactivated profiles. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DeploymentProfile.name | String | The deployment Profile name. |
| PrismaAIRs.DeploymentProfile.auth_code | String | The authentication code. |
| PrismaAIRs.DeploymentProfile.tsg_id | String | The tenant Service Group ID. |
| PrismaAIRs.DeploymentProfile.status | String | The profile status. |
| PrismaAIRs.DeploymentProfile.expiration_date | Date | The expiration date in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DeploymentProfile.ave_text_records | Number | The average text records. |

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
| page | The page number for pagination. Default is 0. | Optional |
| size | The number of results per page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfile.id | String | The DLP Profile ID. |
| PrismaAIRs.DlpProfile.name | String | The DLP Profile name. |
| PrismaAIRs.DlpProfile.description | String | The DLP Profile description. |
| PrismaAIRs.DlpProfile.tenant_id | String | The tenant ID. |
| PrismaAIRs.DlpProfile.type | String | The profile type \(custom or predefined\). |
| PrismaAIRs.DlpProfile.profile_status | String | The profile status \(active, disabled, deleted\). |
| PrismaAIRs.DlpProfile.profile_type | String | The profile type \(basic or advanced\). |
| PrismaAIRs.DlpProfile.is_granular_data_profile | Boolean | Whether this is a granular data profile. |
| PrismaAIRs.DlpProfile.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpProfile.version | Number | The DLP Profile version. |
| PrismaAIRs.DlpProfile.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpProfile.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpProfile.created_by | String | The user who created the profile. |
| PrismaAIRs.DlpProfile.updated_by | String | The user who last updated the profile. |

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
| PrismaAIRs.DlpProfileGet.id | String | The DLP Profile ID. |
| PrismaAIRs.DlpProfileGet.name | String | The DLP Profile name. |
| PrismaAIRs.DlpProfileGet.description | String | The DLP Profile description. |
| PrismaAIRs.DlpProfileGet.tenant_id | String | The tenant ID. |
| PrismaAIRs.DlpProfileGet.type | String | The profile type \(custom or predefined\). |
| PrismaAIRs.DlpProfileGet.profile_status | String | The profile status \(active, disabled, deleted\). |
| PrismaAIRs.DlpProfileGet.profile_type | String | The profile type \(basic or advanced\). |
| PrismaAIRs.DlpProfileGet.is_granular_data_profile | Boolean | Whether this is a granular data profile. |
| PrismaAIRs.DlpProfileGet.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpProfileGet.version | Number | The DLP Profile version. |
| PrismaAIRs.DlpProfileGet.detection_rules | Unknown | The detection rules array \(expression_tree or multi_profile\). |
| PrismaAIRs.DlpProfileGet.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpProfileGet.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpProfileGet.created_by | String | The user who created the profile. |
| PrismaAIRs.DlpProfileGet.updated_by | String | The user who last updated the profile. |

### prisma-airs-runtime-dlp-profiles-create

***
Create a new DLP data profile with detection rules.

#### Base Command

`prisma-airs-runtime-dlp-profiles-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The profile name (1-64 characters). | Required |
| detection_rules | The detection rules as JSON array. Each rule must have rule_type (expression_tree or multi_profile) and corresponding structure. | Required |
| description | The profile description. | Optional |
| is_granular_data_profile | Whether this is a granular data profile. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfileCreate.id | String | The DLP Profile ID. |
| PrismaAIRs.DlpProfileCreate.name | String | The DLP Profile name. |
| PrismaAIRs.DlpProfileCreate.description | String | The DLP Profile description. |
| PrismaAIRs.DlpProfileCreate.type | String | The profile type. |
| PrismaAIRs.DlpProfileCreate.profile_status | String | The profile status. |
| PrismaAIRs.DlpProfileCreate.profile_type | String | The profile type \(basic or advanced\). |
| PrismaAIRs.DlpProfileCreate.is_granular_data_profile | Boolean | Whether this is a granular data profile. |
| PrismaAIRs.DlpProfileCreate.version | Number | The profile version. |
| PrismaAIRs.DlpProfileCreate.detection_rules | Unknown | The detection rules array. |
| PrismaAIRs.DlpProfileCreate.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpProfileCreate.created_by | String | The user who created the profile. |

### prisma-airs-runtime-dlp-profiles-patch

***
Partially update a DLP data profile (JSON Merge Patch). Fields set to "null" will be cleared.

#### Base Command

`prisma-airs-runtime-dlp-profiles-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP data profile to update. | Required |
| name | The profile name (required for PATCH, cannot be cleared). | Required |
| profile_type | The profile type (required for PATCH, cannot be cleared). Possible values are: basic, advanced. | Required |
| description | The profile description (set to "null" to clear). | Optional |
| detection_rules | The detection rules as JSON array (set to "null" to clear). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfilePatch.id | String | The DLP Profile ID. |
| PrismaAIRs.DlpProfilePatch.name | String | The DLP Profile name. |
| PrismaAIRs.DlpProfilePatch.description | String | The DLP Profile description. |
| PrismaAIRs.DlpProfilePatch.type | String | The profile type. |
| PrismaAIRs.DlpProfilePatch.profile_status | String | The profile status. |
| PrismaAIRs.DlpProfilePatch.profile_type | String | The profile type. |
| PrismaAIRs.DlpProfilePatch.version | Number | The profile version. |
| PrismaAIRs.DlpProfilePatch.detection_rules | Unknown | The detection rules array. |
| PrismaAIRs.DlpProfilePatch.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpProfilePatch.updated_by | String | The user who last updated the profile. |

### prisma-airs-runtime-dlp-profiles-replace

***
Replace (full update) a DLP data profile. This replaces the entire profile configuration.

#### Base Command

`prisma-airs-runtime-dlp-profiles-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | The ID of the DLP data profile to replace. | Required |
| name | The profile name (1-64 characters). | Required |
| detection_rules | The detection rules as JSON array. | Required |
| description | The profile description. | Optional |
| is_granular_data_profile | Whether this is a granular data profile. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpProfileReplace.id | String | The DLP Profile ID. |
| PrismaAIRs.DlpProfileReplace.name | String | The DLP Profile name. |
| PrismaAIRs.DlpProfileReplace.description | String | The DLP Profile description. |
| PrismaAIRs.DlpProfileReplace.type | String | The profile type. |
| PrismaAIRs.DlpProfileReplace.profile_status | String | The profile status. |
| PrismaAIRs.DlpProfileReplace.profile_type | String | The profile type. |
| PrismaAIRs.DlpProfileReplace.version | Number | The profile version. |
| PrismaAIRs.DlpProfileReplace.detection_rules | Unknown | The detection rules array. |
| PrismaAIRs.DlpProfileReplace.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpProfileReplace.updated_by | String | The user who last updated the profile. |

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
| PrismaAIRs.DlpProfileDelete.id | String | The ID of the deleted DLP data profile. |
| PrismaAIRs.DlpProfileDelete.name | String | The name of the deleted DLP data profile. |
| PrismaAIRs.DlpProfileDelete.profile_status | String | The lifecycle status after deletion \(deleted\). |
| PrismaAIRs.DlpProfileDelete.deleted | Boolean | Whether the profile was successfully soft-deleted. |
| PrismaAIRs.DlpProfileDelete.status | String | The human-readable deletion status. |

### prisma-airs-runtime-dlp-dictionaries-list

***
List DLP dictionaries.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number for pagination. Default is 0. | Optional |
| size | The number of results per page. Default is 50. | Optional |
| include_keywords | Whether to include the keyword list in the response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionary.id | String | The dictionary ID. |
| PrismaAIRs.DlpDictionary.name | String | The dictionary name. |
| PrismaAIRs.DlpDictionary.description | String | The dictionary description. |
| PrismaAIRs.DlpDictionary.category | String | The dictionary category. |
| PrismaAIRs.DlpDictionary.region_name | String | The region name. |
| PrismaAIRs.DlpDictionary.type | String | The dictionary type \(predefined or custom\). |
| PrismaAIRs.DlpDictionary.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionary.detection_technique | String | The detection technique. |
| PrismaAIRs.DlpDictionary.number_of_keywords | Number | The number of keywords in the dictionary. |
| PrismaAIRs.DlpDictionary.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpDictionary.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |

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
| include_keywords | Whether to include the keyword list in the response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryGet.id | String | The dictionary ID. |
| PrismaAIRs.DlpDictionaryGet.name | String | The dictionary name. |
| PrismaAIRs.DlpDictionaryGet.description | String | The dictionary description. |
| PrismaAIRs.DlpDictionaryGet.category | String | The dictionary category. |
| PrismaAIRs.DlpDictionaryGet.region_name | String | The region name. |
| PrismaAIRs.DlpDictionaryGet.type | String | The dictionary type \(predefined or custom\). |
| PrismaAIRs.DlpDictionaryGet.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryGet.is_parent_managed | Boolean | Whether the dictionary is parent-managed. |
| PrismaAIRs.DlpDictionaryGet.detection_technique | String | The detection technique. |
| PrismaAIRs.DlpDictionaryGet.detection_sub_technique | String | The detection sub-technique. |
| PrismaAIRs.DlpDictionaryGet.dictionary_metadata | Unknown | The dictionary metadata \(number of keywords, file size, original filename\). |
| PrismaAIRs.DlpDictionaryGet.keywords | Unknown | The keyword list \(only populated if include_keywords is true\). |
| PrismaAIRs.DlpDictionaryGet.tags | Unknown | The tags \(classification array\). |
| PrismaAIRs.DlpDictionaryGet.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpDictionaryGet.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpDictionaryGet.created_by | String | The user who created the dictionary. |
| PrismaAIRs.DlpDictionaryGet.updated_by | String | The user who last updated the dictionary. |

### prisma-airs-runtime-dlp-dictionaries-create

***
Create a new DLP dictionary by uploading a keyword file.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The dictionary name. | Required |
| category | The dictionary category. Possible values are: Academic, Confidential, Employment, Financial, Government, Healthcare, Legal, Marketing, Source Code. | Required |
| region_name | The region name (e.g., us-west-2). | Required |
| entry_id | The war room entry ID of the keyword file to upload. | Required |
| description | The dictionary description. | Optional |
| is_case_sensitive | Whether the dictionary is case sensitive. Possible values are: true, false. | Optional |
| type | The dictionary type. Possible values are: predefined, custom. | Optional |
| include_keywords | Whether to include the keyword list in the response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryCreate.id | String | The dictionary ID. |
| PrismaAIRs.DlpDictionaryCreate.name | String | The dictionary name. |
| PrismaAIRs.DlpDictionaryCreate.description | String | The dictionary description. |
| PrismaAIRs.DlpDictionaryCreate.category | String | The dictionary category. |
| PrismaAIRs.DlpDictionaryCreate.region_name | String | The region name. |
| PrismaAIRs.DlpDictionaryCreate.type | String | The dictionary type. |
| PrismaAIRs.DlpDictionaryCreate.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryCreate.detection_technique | String | The detection technique. |
| PrismaAIRs.DlpDictionaryCreate.dictionary_metadata | Unknown | The dictionary metadata. |
| PrismaAIRs.DlpDictionaryCreate.keywords | Unknown | The keyword list. |
| PrismaAIRs.DlpDictionaryCreate.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpDictionaryCreate.created_by | String | The user who created the dictionary. |

### prisma-airs-runtime-dlp-dictionaries-patch

***
Partially update a DLP dictionary (JSON Merge Patch). Fields set to "null" will be cleared.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-patch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dictionary_id | The ID of the DLP dictionary to update. | Required |
| name | The dictionary name (required for PATCH, cannot be cleared). | Required |
| category | The dictionary category (required for PATCH, cannot be cleared). Possible values are: Academic, Confidential, Employment, Financial, Government, Healthcare, Legal, Marketing, Source Code. | Required |
| original_file_name | The original filename (required for PATCH, cannot be cleared). | Required |
| description | The dictionary description (set to "null" to clear). | Optional |
| is_case_sensitive | Whether the dictionary is case sensitive (set to "null" to clear). Possible values are: true, false, null. | Optional |
| region_name | The region name (set to "null" to clear). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryPatch.id | String | The dictionary ID. |
| PrismaAIRs.DlpDictionaryPatch.name | String | The dictionary name. |
| PrismaAIRs.DlpDictionaryPatch.description | String | The dictionary description. |
| PrismaAIRs.DlpDictionaryPatch.category | String | The dictionary category. |
| PrismaAIRs.DlpDictionaryPatch.region_name | String | The region name. |
| PrismaAIRs.DlpDictionaryPatch.type | String | The dictionary type. |
| PrismaAIRs.DlpDictionaryPatch.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryPatch.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpDictionaryPatch.updated_by | String | The user who last updated the dictionary. |

### prisma-airs-runtime-dlp-dictionaries-replace

***
Replace (full update) a DLP dictionary by uploading a new keyword file.

#### Base Command

`prisma-airs-runtime-dlp-dictionaries-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dictionary_id | The ID of the DLP dictionary to replace. | Required |
| name | The dictionary name. | Required |
| category | The dictionary category. Possible values are: Academic, Confidential, Employment, Financial, Government, Healthcare, Legal, Marketing, Source Code. | Required |
| region_name | The region name (e.g., us-west-2). | Required |
| entry_id | The war room entry ID of the keyword file to upload. | Required |
| description | The dictionary description. | Optional |
| is_case_sensitive | Whether the dictionary is case sensitive. Possible values are: true, false. | Optional |
| type | The dictionary type. Possible values are: predefined, custom. | Optional |
| include_keywords | Whether to include the keyword list in the response. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpDictionaryReplace.id | String | The dictionary ID. |
| PrismaAIRs.DlpDictionaryReplace.name | String | The dictionary name. |
| PrismaAIRs.DlpDictionaryReplace.description | String | The dictionary description. |
| PrismaAIRs.DlpDictionaryReplace.category | String | The dictionary category. |
| PrismaAIRs.DlpDictionaryReplace.region_name | String | The region name. |
| PrismaAIRs.DlpDictionaryReplace.type | String | The dictionary type. |
| PrismaAIRs.DlpDictionaryReplace.is_case_sensitive | Boolean | Whether the dictionary is case sensitive. |
| PrismaAIRs.DlpDictionaryReplace.keywords | Unknown | The keyword list. |
| PrismaAIRs.DlpDictionaryReplace.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpDictionaryReplace.updated_by | String | The user who last updated the dictionary. |

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
| PrismaAIRs.DlpDictionaryDelete.id | String | The ID of the deleted DLP dictionary. |
| PrismaAIRs.DlpDictionaryDelete.deleted | Boolean | Whether the dictionary was successfully deleted. |
| PrismaAIRs.DlpDictionaryDelete.status | String | The human-readable deletion status. |

### prisma-airs-runtime-dlp-patterns-list

***
List DLP data patterns.

#### Base Command

`prisma-airs-runtime-dlp-patterns-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number for pagination. Default is 0. | Optional |
| size | The number of results per page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPattern.id | String | The pattern ID. |
| PrismaAIRs.DlpPattern.name | String | The pattern name. |
| PrismaAIRs.DlpPattern.description | String | The pattern description. |
| PrismaAIRs.DlpPattern.category | String | The pattern category. |
| PrismaAIRs.DlpPattern.region_name | String | The region name. |
| PrismaAIRs.DlpPattern.type | String | The pattern type \(predefined or custom\). |
| PrismaAIRs.DlpPattern.detection_technique | String | The detection technique. |
| PrismaAIRs.DlpPattern.detection_sub_technique | String | The detection sub-technique. |
| PrismaAIRs.DlpPattern.pattern_status | String | The pattern status. |
| PrismaAIRs.DlpPattern.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpPattern.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |

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
| PrismaAIRs.DlpPatternGet.id | String | The pattern ID. |
| PrismaAIRs.DlpPatternGet.name | String | The pattern name. |
| PrismaAIRs.DlpPatternGet.description | String | The pattern description. |
| PrismaAIRs.DlpPatternGet.tenant_id | String | The tenant ID. |
| PrismaAIRs.DlpPatternGet.type | String | The pattern type \(predefined, custom, file_property\). |
| PrismaAIRs.DlpPatternGet.status | String | The pattern status \(active, disabled, deleted, deprecated, silent\). |
| PrismaAIRs.DlpPatternGet.license_type | String | The license tier \(standard, enterprise, essentials\). |
| PrismaAIRs.DlpPatternGet.is_parent_managed | Boolean | Whether the pattern is parent-managed. |
| PrismaAIRs.DlpPatternGet.version | Number | The pattern version number. |
| PrismaAIRs.DlpPatternGet.detection_config | Unknown | The detection configuration \(technique and confidence levels\). |
| PrismaAIRs.DlpPatternGet.matching_rules | Unknown | The matching rules \(proximity, delimiters, regexes, metadata\). |
| PrismaAIRs.DlpPatternGet.tags | Unknown | The tags \(classification, compliance, geography\). |
| PrismaAIRs.DlpPatternGet.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpPatternGet.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpPatternGet.created_by | String | The user who created the pattern. |
| PrismaAIRs.DlpPatternGet.updated_by | String | The user who last updated the pattern. |

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
| name | The pattern name (1-64 characters). | Required |
| type | The pattern type. Possible values are: predefined, custom, file_property. | Required |
| detection_technique | The detection technique. Possible values are: edm, document_fingerprint, trainable_classifier, ml_document, regex, weighted_regex, ml, titus_tag, wildfire, file_property, dictionary, pab, document_classifier. | Required |
| supported_confidence_levels | A comma-separated list of confidence levels (low, medium, high). Alternatively, a JSON array. | Optional |
| description | The pattern description. | Optional |
| matching_rules | The matching rules as JSON object (proximity, delimiters, regexes, metadata_criteria). | Optional |
| tags | The tags as JSON object with classification, compliance, geography arrays. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternCreate.id | String | The pattern ID. |
| PrismaAIRs.DlpPatternCreate.name | String | The pattern name. |
| PrismaAIRs.DlpPatternCreate.description | String | The pattern description. |
| PrismaAIRs.DlpPatternCreate.type | String | The pattern type. |
| PrismaAIRs.DlpPatternCreate.status | String | The pattern status. |
| PrismaAIRs.DlpPatternCreate.detection_config | Unknown | The detection configuration. |
| PrismaAIRs.DlpPatternCreate.matching_rules | Unknown | The matching rules. |
| PrismaAIRs.DlpPatternCreate.tags | Unknown | The tags. |
| PrismaAIRs.DlpPatternCreate.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpPatternCreate.created_by | String | The user who created the pattern. |

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
| name | The pattern name (required for PATCH, cannot be cleared). | Required |
| type | The pattern type (required for PATCH, cannot be cleared). Possible values are: predefined, custom, file_property. | Required |
| detection_technique | The detection technique (required for PATCH, cannot be cleared). Possible values are: edm, document_fingerprint, trainable_classifier, ml_document, regex, weighted_regex, ml, titus_tag, wildfire, file_property, dictionary, pab, document_classifier. | Required |
| supported_confidence_levels | A comma-separated list of confidence levels (low, medium, high). Alternatively, a JSON array. | Optional |
| description | The pattern description (set to "null" to clear). | Optional |
| matching_rules | The matching rules as JSON object (set to "null" to clear). | Optional |
| tags | The tags as JSON object (set to "null" to clear). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternPatch.id | String | The pattern ID. |
| PrismaAIRs.DlpPatternPatch.name | String | The pattern name. |
| PrismaAIRs.DlpPatternPatch.description | String | The pattern description. |
| PrismaAIRs.DlpPatternPatch.type | String | The pattern type. |
| PrismaAIRs.DlpPatternPatch.status | String | The pattern status. |
| PrismaAIRs.DlpPatternPatch.version | Number | The pattern version number. |
| PrismaAIRs.DlpPatternPatch.detection_config | Unknown | The detection configuration. |
| PrismaAIRs.DlpPatternPatch.matching_rules | Unknown | The matching rules. |
| PrismaAIRs.DlpPatternPatch.tags | Unknown | The tags. |
| PrismaAIRs.DlpPatternPatch.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpPatternPatch.updated_by | String | The user who last updated the pattern. |

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
| name | The pattern name (1-64 characters). | Required |
| type | The pattern type. Possible values are: predefined, custom, file_property. | Required |
| detection_technique | The detection technique. Possible values are: edm, document_fingerprint, trainable_classifier, ml_document, regex, weighted_regex, ml, titus_tag, wildfire, file_property, dictionary, pab, document_classifier. | Required |
| supported_confidence_levels | A comma-separated list of confidence levels (low, medium, high). Alternatively, a JSON array. | Optional |
| description | The pattern description. | Optional |
| matching_rules | The matching rules as JSON object. | Optional |
| tags | The tags as JSON object. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpPatternReplace.id | String | The pattern ID. |
| PrismaAIRs.DlpPatternReplace.name | String | The pattern name. |
| PrismaAIRs.DlpPatternReplace.description | String | The pattern description. |
| PrismaAIRs.DlpPatternReplace.type | String | The pattern type. |
| PrismaAIRs.DlpPatternReplace.status | String | The pattern status. |
| PrismaAIRs.DlpPatternReplace.version | Number | The pattern version number. |
| PrismaAIRs.DlpPatternReplace.detection_config | Unknown | The detection configuration. |
| PrismaAIRs.DlpPatternReplace.matching_rules | Unknown | The matching rules. |
| PrismaAIRs.DlpPatternReplace.tags | Unknown | The tags. |
| PrismaAIRs.DlpPatternReplace.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpPatternReplace.updated_by | String | The user who last updated the pattern. |

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
| PrismaAIRs.DlpPatternDelete.id | String | The ID of the deleted DLP data pattern. |
| PrismaAIRs.DlpPatternDelete.deleted | Boolean | Whether the pattern was successfully deleted. |
| PrismaAIRs.DlpPatternDelete.status | String | The human-readable deletion status. |

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
| page | The page number for pagination. Default is 0. | Optional |
| size | The number of results per page. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpFilteringProfile.id | String | The filtering profile ID. |
| PrismaAIRs.DlpFilteringProfile.name | String | The filtering profile name. |
| PrismaAIRs.DlpFilteringProfile.description | String | The filtering profile description. |
| PrismaAIRs.DlpFilteringProfile.type | String | The profile type. |
| PrismaAIRs.DlpFilteringProfile.default_action | String | The default action for the profile. |
| PrismaAIRs.DlpFilteringProfile.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpFilteringProfile.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpFilteringProfile.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |

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
| PrismaAIRs.DlpFilteringProfileGet.id | String | The filtering profile ID. |
| PrismaAIRs.DlpFilteringProfileGet.name | String | The filtering profile name. |
| PrismaAIRs.DlpFilteringProfileGet.description | String | The filtering profile description. |
| PrismaAIRs.DlpFilteringProfileGet.tenant_id | String | The tenant ID. |
| PrismaAIRs.DlpFilteringProfileGet.type | String | The profile type. |
| PrismaAIRs.DlpFilteringProfileGet.data_profile_id | Number | The associated data profile ID. |
| PrismaAIRs.DlpFilteringProfileGet.direction | String | The scan direction \(BOTH, UPLOAD, DOWNLOAD\). |
| PrismaAIRs.DlpFilteringProfileGet.file_based | Boolean | Whether file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileGet.non_file_based | Boolean | Whether non-file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileGet.log_severity | String | The log severity level. |
| PrismaAIRs.DlpFilteringProfileGet.scan_type | String | The scan type \(include or exclude\). |
| PrismaAIRs.DlpFilteringProfileGet.is_end_user_coaching_enabled | Boolean | Whether end user coaching is enabled. |
| PrismaAIRs.DlpFilteringProfileGet.is_granular_profile | Boolean | Whether this is a granular profile. |
| PrismaAIRs.DlpFilteringProfileGet.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpFilteringProfileGet.euc_template_id | String | The end user coaching template ID. |
| PrismaAIRs.DlpFilteringProfileGet.version | Number | The profile version number. |
| PrismaAIRs.DlpFilteringProfileGet.file_type | Unknown | The allowed file types for scanning. |
| PrismaAIRs.DlpFilteringProfileGet.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpFilteringProfileGet.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpFilteringProfileGet.created_by | String | The user who created the profile. |
| PrismaAIRs.DlpFilteringProfileGet.updated_by | String | The user who last updated the profile. |

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
| description | The profile description. | Optional |
| direction | The scan direction. Possible values are: BOTH, UPLOAD, DOWNLOAD. | Optional |
| log_severity | The log severity level. Possible values are: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL. | Optional |
| scan_type | The scan type (include or exclude file types). Possible values are: include, exclude. | Optional |
| data_profile_id | The associated data profile ID (numeric). | Optional |
| euc_template_id | The end user coaching template ID. | Optional |
| is_end_user_coaching_enabled | Whether end user coaching is enabled. Possible values are: true, false. | Optional |
| is_granular_profile | Whether this is a granular profile. Possible values are: true, false. | Optional |
| file_type | A comma-separated list of file types to include or exclude. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.DlpFilteringProfileReplace.id | String | The filtering profile ID. |
| PrismaAIRs.DlpFilteringProfileReplace.name | String | The filtering profile name. |
| PrismaAIRs.DlpFilteringProfileReplace.description | String | The filtering profile description. |
| PrismaAIRs.DlpFilteringProfileReplace.tenant_id | String | The tenant ID. |
| PrismaAIRs.DlpFilteringProfileReplace.type | String | The profile type. |
| PrismaAIRs.DlpFilteringProfileReplace.data_profile_id | Number | The associated data profile ID. |
| PrismaAIRs.DlpFilteringProfileReplace.direction | String | The scan direction \(BOTH, UPLOAD, DOWNLOAD\). |
| PrismaAIRs.DlpFilteringProfileReplace.file_based | Boolean | Whether file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileReplace.non_file_based | Boolean | Whether non-file-based scanning is enabled. |
| PrismaAIRs.DlpFilteringProfileReplace.log_severity | String | The log severity level. |
| PrismaAIRs.DlpFilteringProfileReplace.scan_type | String | The scan type \(include or exclude\). |
| PrismaAIRs.DlpFilteringProfileReplace.is_end_user_coaching_enabled | Boolean | Whether end user coaching is enabled. |
| PrismaAIRs.DlpFilteringProfileReplace.is_granular_profile | Boolean | Whether this is a granular profile. |
| PrismaAIRs.DlpFilteringProfileReplace.is_parent_managed | Boolean | Whether the profile is parent-managed. |
| PrismaAIRs.DlpFilteringProfileReplace.version | Number | The profile version number. |
| PrismaAIRs.DlpFilteringProfileReplace.created_at | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpFilteringProfileReplace.updated_at | Date | The last update timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.DlpFilteringProfileReplace.created_by | String | The user who created the profile. |
| PrismaAIRs.DlpFilteringProfileReplace.updated_by | String | The user who last updated the profile. |

### prisma-airs-runtime-topics-list

***
List custom topic guardrails.

#### Base Command

`prisma-airs-runtime-topics-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of topics to return. Default is 100. | Optional |
| offset | The starting offset for pagination. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.Topic.topic_id | String | The topic UUID. |
| PrismaAIRs.Topic.topic_name | String | The topic name. |
| PrismaAIRs.Topic.revision | Number | The topic revision number. |
| PrismaAIRs.Topic.description | String | The topic description. |
| PrismaAIRs.Topic.examples | Unknown | The example prompts for the topic. |
| PrismaAIRs.Topic.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.Topic.created_by | String | The user who created the topic. |
| PrismaAIRs.Topic.updated_by | String | The user who last updated the topic. |
| PrismaAIRs.Topic.csp_id | String | The CSP ID. |
| PrismaAIRs.Topic.tsg_id | String | The tenant Service Group ID. |

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
| topic_id | The topic UUID (either topic_id or topic_name is required). | Optional |
| topic_name | The topic name. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicGet.topic_id | String | The topic UUID. |
| PrismaAIRs.TopicGet.topic_name | String | The topic name. |
| PrismaAIRs.TopicGet.revision | Number | The topic revision number. |
| PrismaAIRs.TopicGet.active | Boolean | Whether the topic is active. |
| PrismaAIRs.TopicGet.description | String | The topic description. |
| PrismaAIRs.TopicGet.examples | Unknown | The example prompts for the topic. |
| PrismaAIRs.TopicGet.created_by | String | The user who created the topic. |
| PrismaAIRs.TopicGet.updated_by | String | The user who last updated the topic. |
| PrismaAIRs.TopicGet.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.TopicGet.created_ts | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |

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
| topic_name | The name for the new topic (must be unique). | Required |
| description | The description of what this topic detects. | Required |
| examples | A comma-separated list of example prompts/content that match this topic. | Required |
| active | Whether the topic should be active. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicCreate.topic_id | String | The topic UUID. |
| PrismaAIRs.TopicCreate.topic_name | String | The topic name. |
| PrismaAIRs.TopicCreate.revision | Number | The topic revision number \(starts at 1\). |
| PrismaAIRs.TopicCreate.active | Boolean | Whether the topic is active. |
| PrismaAIRs.TopicCreate.description | String | The topic description. |
| PrismaAIRs.TopicCreate.examples | Unknown | The example prompts for the topic. |
| PrismaAIRs.TopicCreate.created_by | String | The user who created the topic. |
| PrismaAIRs.TopicCreate.updated_by | String | The user who last updated the topic. |
| PrismaAIRs.TopicCreate.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.TopicCreate.created_ts | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |

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
| topic_id | The topic UUID to update. | Required |
| topic_name | The topic name (can be changed or kept the same). | Required |
| description | The updated description (if omitted, description remains unchanged). | Optional |
| examples | An updated comma-separated list of examples (if omitted, examples remain unchanged). | Optional |
| active | Whether the topic should be active. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicUpdate.topic_id | String | The topic UUID. |
| PrismaAIRs.TopicUpdate.topic_name | String | The topic name. |
| PrismaAIRs.TopicUpdate.revision | Number | The topic revision number \(incremented after update\). |
| PrismaAIRs.TopicUpdate.active | Boolean | Whether the topic is active. |
| PrismaAIRs.TopicUpdate.description | String | The topic description. |
| PrismaAIRs.TopicUpdate.examples | Unknown | The example prompts for the topic. |
| PrismaAIRs.TopicUpdate.created_by | String | The user who created the topic. |
| PrismaAIRs.TopicUpdate.updated_by | String | The user who last updated the topic. |
| PrismaAIRs.TopicUpdate.last_modified_ts | Date | The last modification timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |
| PrismaAIRs.TopicUpdate.created_ts | Date | The creation timestamp in ISO 8601 format (e.g., 2024-01-15T12:34:56Z). |

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
Delete a custom topic. WARNING - This action cannot be undone. Fails if topic is referenced by any security profile (use force to override).

> **Note:** The force-delete endpoint (`.../topic/force/{id}`) currently returns HTTP 403 (`Access denied`) on tenants where the OAuth client has not been granted the force-delete permission. Regular delete and the force request path are both validated; force-delete succeeds once the tenant grants the permission.

#### Base Command

`prisma-airs-runtime-topics-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic_id | The topic UUID to delete. | Required |
| force | Whether to force-delete the topic, removing it from any referencing profiles. Possible values are: true, false. Default is false. | Optional |
| updated_by | The email of the user performing the deletion. Optional for force-delete. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicDeleted.topic_id | String | The deleted topic ID. |
| PrismaAIRs.TopicDeleted.message | String | The deletion confirmation message. |
| PrismaAIRs.TopicDeleted.deleted | Boolean | The boolean indicating successful deletion. |
| PrismaAIRs.TopicDeleted.force | Boolean | Whether the topic was force-deleted. |

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
>|Topic Id|Message|Deleted|Force|
>|---|---|---|---|
>| 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad | successfully deleted topicId: 6d62aa1f-4457-4eb5-afb1-7cde3d3bc0ad | true | false |
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
| profile_name | The security profile name to apply the topic to. | Required |
| topic_name | The topic name to apply. The topic must already exist (create with prisma-airs-runtime-topics-create). | Required |
| action | The topic action. 'block' = block prompts matching this topic. 'allow' = allow prompts matching this topic. Possible values are: allow, block. Default is block. | Optional |
| guardrail_action | The guardrail-level default action. 'block' = block all unless explicitly allowed (requires allow topics). 'allow' = allow all unless explicitly blocked (only block topics needed). Possible values are: allow, block. Default is block. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.TopicApplied.profile_name | String | The security profile name. |
| PrismaAIRs.TopicApplied.profile_id | String | The security profile UUID. |
| PrismaAIRs.TopicApplied.topic_name | String | The topic name that was applied. |
| PrismaAIRs.TopicApplied.topic_id | String | The topic UUID. |
| PrismaAIRs.TopicApplied.topic_revision | Number | The topic revision number \(pinned to ensure consistent detection\). |
| PrismaAIRs.TopicApplied.action | String | The topic action \(allow or block\). |
| PrismaAIRs.TopicApplied.guardrail_action | String | The guardrail-level default action. |
| PrismaAIRs.TopicApplied.applied | Boolean | The boolean indicating successful application. |

### prisma-airs-runtime-bulk-scan

***
Perform bulk scanning of multiple prompts.

#### Base Command

`prisma-airs-runtime-bulk-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | The security profile name to use for scanning. | Required |
| prompts_csv | The CSV content with prompts to scan (must include 'prompt' column header, or use newline-separated format). | Required |
| session_id | The optional session ID for grouping scans in AIRS dashboard. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.BulkScan.profile_name | String | The security profile used. |
| PrismaAIRs.BulkScan.session_id | String | The session ID. |
| PrismaAIRs.BulkScan.total | Number | The total prompts scanned. |
| PrismaAIRs.BulkScan.blocked | Number | The number of prompts blocked. |
| PrismaAIRs.BulkScan.allowed | Number | The number of prompts allowed. |
| PrismaAIRs.BulkScan.errors | Number | The number of scan errors. |
| PrismaAIRs.BulkScan.results | Unknown | The array of individual scan results. |

