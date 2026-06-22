# Palo Alto Networks - Prisma AIRs AI Security

Integrate with Palo Alto Networks Prisma AIRs for comprehensive AI security capabilities.

## What does this pack do?

The Prisma AIRs AI Security pack provides integration with Palo Alto Networks' AI security portfolio, enabling organizations to:

- **Runtime Scanning**: Scan prompts and responses against security profiles for AI threats
- **Red Team Operations**: Execute adversarial testing with static, dynamic, and custom attack modes
- **Model Security**: Manage ML model supply chain security with security groups and rules
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

### Model Security

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

- **Palo Alto Networks - Prisma AIRs AI Security**: Main integration providing all AI security capabilities

### Configuration

The integration requires:

- **Server URL**: Strata Cloud Manager API URL (default: <https://api.sase.paloaltonetworks.com>)
- **API Client ID**: OAuth2 client ID from Strata Cloud Manager
- **API Client Secret**: OAuth2 client secret
- **Tenant Services Group ID**: Your Prisma SASE TSG ID

## Getting Started

1. Configure API credentials in Strata Cloud Manager
2. Install the Prisma AIRs AI Security pack
3. Configure the integration with your credentials
4. Test connectivity using the Test button
5. Start using AI security commands in your playbooks

## Support

For support, please contact Palo Alto Networks support or visit the [Cortex XSOAR portal](https://www.paloaltonetworks.com/cortex).

## Additional Information

- **Support Level**: XSOAR Official Support
- **Author**: Cortex XSOAR
- **Categories**: Cloud Security, CI/CD
- **Supported Modules**: cloud_runtime_security, xsiam, cloud
