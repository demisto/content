# Palo Alto Networks - Prisma AIRs AI Security

Integrate with Palo Alto Networks Prisma AIRs for AI security capabilities including runtime scanning, red teaming, model security, and DLP configuration.

## Configure Palo Alto Networks - Prisma AIRs AI Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks - Prisma AIRs AI Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Strata Cloud Manager API URL (default: <https://api.sase.paloaltonetworks.com>) - This is a global endpoint and does not require regional configuration | True |
    | API Client ID | OAuth2 client ID from Strata Cloud Manager | True |
    | API Client Secret | OAuth2 client secret | True |
    | Tenant Services Group ID | Your Prisma SASE TSG ID (example: 1234567890) | True |
    | Runtime API Key | API key for Prisma AIRs Scanner API (runtime scanning operations only) | True |
    | Scanner API Region | Region for Scanner API: US, EU (Germany), IN (India), or SG (Singapore) - Must match your deployment profile region | True |
    | Trust any certificate (not secure) | Trust any certificate (not recommended for production) | False |
    | Use system proxy settings | Use XSOAR proxy configuration | False |

4. Click **Test** to validate the connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaAIRs.RuntimeScan.prompt | String | The scanned prompt text. |
| PrismaAIRs.RuntimeScan.response | String | The scanned response text. |
| PrismaAIRs.RuntimeScan.detected | Boolean | Whether a threat was detected. |
| PrismaAIRs.RuntimeScan.topic_violation | Boolean | Whether a topic violation was detected. |
| PrismaAIRs.RuntimeScan.injection | Boolean | Whether prompt injection was detected. |
| PrismaAIRs.RuntimeScan.toxic_content | Boolean | Whether toxic content was detected. |
| PrismaAIRs.RuntimeScan.dlp | Boolean | Whether DLP violations were detected. |

#### Command example

```!prisma-airs-runtime-scan profile_name="production-profile" prompt="What is the capital of France?"```

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
| PrismaAIRs.ApiKey.id | String | API Key ID (UUID). |
| PrismaAIRs.ApiKey.name | String | API Key name. |
| PrismaAIRs.ApiKey.last8 | String | Last 8 characters of the API key (for identification). |
| PrismaAIRs.ApiKey.created_at | Date | API Key creation timestamp. |
| PrismaAIRs.ApiKey.expires_at | Date | API Key expiration timestamp. |

#### Command example

```!prisma-airs-runtime-api-keys-list limit=10```

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
| PrismaAIRs.SecurityProfile.id | String | Profile ID. |
| PrismaAIRs.SecurityProfile.name | String | Profile name. |
| PrismaAIRs.SecurityProfile.active | Boolean | Whether the profile is active. |

#### Command example

```!prisma-airs-runtime-profiles-list limit=10```

## Additional Information

### Authentication

This integration uses two authentication methods:

1. **OAuth2 (Management API)**: Used for Strata Cloud Manager API calls (profile management, configuration)
   - Create an OAuth2 client in Strata Cloud Manager
   - Assign appropriate permissions for Prisma AIRs API access
   - The SCM API endpoint (`api.sase.paloaltonetworks.com`) is global and works for all regions

2. **Runtime API Key (Scanner API)**: Used exclusively for runtime scanning operations
   - Generate a Runtime API Key in Strata Cloud Manager (AI Security > API Applications > Manage > API Keys)
   - This is NOT the same as the OAuth2 Client ID/Secret
   - The Scanner API has regional endpoints that must match your deployment profile region

### Regional Endpoints

**Important**: Only the Scanner API requires regional configuration.

- **Strata Cloud Manager API** (management operations): `https://api.sase.paloaltonetworks.com` - **Global endpoint, no regional selection needed**
- **Scanner API** (runtime scanning): Regional endpoints based on deployment profile:
  - **US**: `https://service.api.aisecurity.paloaltonetworks.com`
  - **EU (Germany)**: `https://service-de.api.aisecurity.paloaltonetworks.com`
  - **IN (India)**: `https://service-in.api.aisecurity.paloaltonetworks.com`
  - **SG (Singapore)**: `https://service-sg.api.aisecurity.paloaltonetworks.com`

Select the Scanner API Region that matches where your Prisma AIRs deployment profile was created.

### API Rate Limiting

Prisma AIRs API has rate limits. For bulk scanning operations, the integration implements appropriate throttling to avoid exceeding limits.

## Known Limitations

- This is the initial release (v0.1.0) with basic runtime scanning and profile management
- Additional commands for Red Team and Model Security features will be added in future releases

## Troubleshooting

### Connection Test Fails

- Verify your Client ID and Secret are correct
- Ensure the TSG ID matches your Prisma SASE tenant
- Check network connectivity to api.sase.paloaltonetworks.com

### Authentication Errors

- Verify OAuth2 credentials have not expired
- Ensure the service account has appropriate Prisma AIRs permissions

## Support

For support, please contact Palo Alto Networks support or visit the [Cortex XSOAR portal](https://www.paloaltonetworks.com/cortex).
