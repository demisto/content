# Palo Alto Networks - Prisma AIRS AI Security

Integrate with Palo Alto Networks Prisma AIRS for comprehensive AI security capabilities.

## What does this pack do?

The Prisma AIRS AI Security pack provides integration with Palo Alto Networks' AI security portfolio, enabling organizations to:

- **Runtime Scanning**: Scan prompts and responses against security profiles for AI threats
- **Red Team Operations**: Execute adversarial testing with static, dynamic, and custom attack modes
- **AI Supply Chain Security**: Manage ML model supply chain security with security groups and rules
- **DLP Configuration**: Configure and manage data loss prevention filtering profiles and patterns
- **Security Profile Management**: Create and manage AI security profiles with topic-based guardrails

## Key Features

### Runtime AI Security

- Single prompt and bulk scanning capabilities
- Detection of topic violations, prompt injection, toxic content, and DLP violations
- CSV export of scan results for analysis
- Session-based scan grouping for tracking

### Red Team Testing

- Static attack library scanning
- Dynamic agent-driven adversarial testing
- Custom prompt set management
- Comprehensive attack reporting with ASR metrics

### AI Supply Chain Security

- Security group management for model sources (Local, S3, GCS, Azure, Hugging Face)
- Security rule configuration and enforcement
- Model scan tracking and violation reporting
- Label-based organization

### Data Loss Prevention

- DLP filtering profile configuration
- Pattern and dictionary management
- Profile-based data protection policies
- Multipart file upload support

## Pack Components

### Integrations

- **Palo Alto Networks - Prisma AIRS AI Security**: Main integration providing all AI security capabilities

### Configuration

The integration requires:

- **Server URL**: Strata Cloud Manager API URL (default: <https://api.sase.paloaltonetworks.com>)
- **API Client ID**: OAuth2 client ID from Strata Cloud Manager
- **API Client Secret**: OAuth2 client secret
- **Tenant Services Group ID**: Your Prisma SASE TSG ID

## Getting Started

1. Configure API credentials in Strata Cloud Manager
2. Install the Prisma AIRS AI Security pack
3. Configure the integration with your credentials
4. Test connectivity using the Test button
5. Start using AI security commands in your playbooks

## Known Limitations

The following DLP configuration operations are currently constrained by the upstream Prisma AIRS DLP API (`https://api.dlp.paloaltonetworks.com`). The integration sends spec-compliant requests; the limitations are server-side:

- **DLP data-profile update/delete** (`prisma-airs-runtime-dlp-profiles-patch` / `-replace` / `-delete`): The DLP API exposes no `DELETE` endpoint for data profiles, and `PATCH`/`PUT` currently return `HTTP 500` for every well-formed request (verified against the SDK/spec-compliant body; the server returns a bare `Internal Server Error` with no validation detail, so this is a server-side defect rather than an input-format issue). As a result, data profiles can be listed, created, and retrieved, but not updated or removed via the API. Delete is implemented as a soft-delete (`profile_status: "deleted"` via merge-patch), which the API does not yet accept. Note also that a profile **archived via the Strata Cloud Manager UI** keeps its original name reserved (the archived record is hidden from `list` but still holds the name), so re-creating a profile with that name returns `HTTP 409 Conflict`. There is **no public API to restore/un-archive a profile** (the UI "restore" action has no API equivalent — `profile_status` is not writable via patch and no restore endpoint exists), so a name freed only by UI restore cannot be reused via the API.
- **DLP data-pattern delete while referenced** (`prisma-airs-runtime-dlp-patterns-delete`): Deleting a pattern works normally (`HTTP 204`, soft-delete/archive) **unless** the pattern is still referenced by an active data profile, in which case the API returns `HTTP 400`. Because data-profile delete is blocked (above), a pattern referenced by a profile cannot currently be freed for deletion. Remove the pattern from the profile's detection rules first where possible.
- **Custom pattern + custom profile cleanup deadlock (UI-only workaround):** These two limitations combine into a lifecycle deadlock. A custom pattern cannot be archived while it is referenced by a profile (`HTTP 400`), and a data profile cannot have empty detection rules — so a custom profile that references only a custom pattern locks both from cleanup via the API. The normal escape (swap the custom pattern out for a predefined pattern such as `Driver License - Ireland`, then archive the freed pattern) **requires modifying the profile's detection rules, which is a `PATCH`/`PUT` and returns `HTTP 500`** (verified live). As a result this cleanup can currently only be performed in the **Strata Cloud Manager UI** (which uses internal endpoints), not through the API/integration. Until the upstream profile-mutation `500` is fixed, any test that creates a custom-pattern-referencing custom profile will leave both artifacts orphaned; clean them up manually in the UI by editing the profile to reference a predefined pattern, then archiving the custom pattern and the profile.
- **DLP data-profile name length** (`prisma-airs-runtime-dlp-profiles-create`): the DLP API rejects a data-profile `name` longer than **32 characters** with a bare `HTTP 400 Bad Request` (no validation detail). Note that the OpenAPI spec (`DataProfiles.yaml`, `AdvancedDataProfileRequest.name`) documents `maxLength: 64`, but the server enforces a stricter 32-character limit — keep profile names at or under 32 characters. This limit applies only to data profiles; pattern and dictionary names are not affected.

The `list`, `create`, and `get` operations for dictionaries, patterns, and data profiles work as expected, as do all DLP **pattern** and **dictionary** CRUD operations (pattern/dictionary delete return `HTTP 204`). Note: DLP dictionary `create`/`replace` require a valid tenant `region_name` label (e.g. `United States`); an AWS-style code such as `us-west-2` returns `HTTP 400`.

## Support

For support, please contact Palo Alto Networks support or visit the [Cortex portal](https://www.paloaltonetworks.com/cortex).

## Additional Information

- **Support Level**: Community
- **Author**: Eric Partington
- **Categories**: Cloud Security
- **Supported Modules**: cloud_runtime_security, Cortex XSIAM, cloud
