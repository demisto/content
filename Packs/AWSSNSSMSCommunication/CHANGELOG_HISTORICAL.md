# AWS SNS SMS Communication Integration - Historical Changelog
## Date Range: January 6, 2026 (Initial Release) to January 7, 2026

## Summary
**Versions Released:** 1.0.0 → 1.0.8 (9 versions)
**Development Phase:** Initial development and core feature implementation
**Branch:** feature/aws-sns-sqs-sms-integration

## Version-by-Version Changes

### v1.0.0 - Initial Release (January 6, 2026)
**Git Commit:** 3c4ad1a83d - Add AWS SNS SMS Communication integration v1.0.0

**Core Features:**
- AWS SNS SMS sending via send-notification command (originally `aws-sns-sms-send-notification`)
- AWS SQS long-running polling for SMS replies
- Entitlement system for interactive two-way communication
- Reply code management for concurrent conversations
- Integration context storage for entitlement tracking
- TTL-based cleanup of expired entitlements (default 24 hours)
- AWS authentication using Access Keys

**Architecture:**
- Python integration using boto3 library
- Long-running execution pattern for continuous SQS polling
- Integration with XSOAR entitlement system via `demisto.handleEntitlementForUser()`
- Automatic reply code generation for multi-conversation support

**Commands:**
- `send-notification`: Send SMS with optional entitlement support
- Outputs: MessageId, PhoneNumber, Entitlement, ReplyCode

### v1.0.1 - Visual Identity (January 6, 2026)
**Git Commit:** cebcd1f8f2 - Bump AWS SNS SMS Communication to v1.0.1

**Changes:**
- Added integration icon (AWSSNSSMSCommunication_image.png)
- Improved marketplace visual identification

### v1.0.2 - Metadata Update (January 6, 2026)
**Git Commit:** 2e5641bcab - Update author and add community support notice

**Changes:**
- Updated pack author to Maciej Drobniuch
- Added community support disclaimer to README
- Clarified support model for custom integration

### v1.0.3 - AWS Authentication Expansion (January 6, 2026)
**Git Commit:** 9be26be0db - Add Role ARN support and AWS authentication improvements

**Major Enhancement:**
Completely redesigned AWS authentication to support multiple patterns matching official AWS integrations:

1. **Role ARN only** - STS AssumeRole without access keys
2. **Access Key + Role ARN** - Assume role with provided credentials
3. **Access Key only** - Direct authentication with IAM user
4. **Default credentials** - EC2 instance role or environment variables

**New Configuration Parameters:**
- `roleArn`: IAM role ARN for STS AssumeRole
- `roleSessionName`: Session name for assumed role
- `sessionDuration`: Role session duration (default 900 seconds)
- `timeout`: API timeout configuration
- `retries`: Maximum retry attempts (default 5, max 10)
- `sts_regional_endpoint`: AWS STS endpoint type (legacy/regional)
- `proxy`: System proxy settings support
- `insecure`: SSL certificate trust option

**Technical Impact:**
- Follows AWSApiModule patterns from official XSOAR AWS integrations
- Enables deployment in restricted AWS environments (IAM roles)
- Improves security by supporting temporary credentials

### v1.0.4 - Ask Task Integration (January 6, 2026)
**Git Commit:** ccb66938da - Rename command to send-notification for Ask task compatibility

**Breaking Change:**
- Renamed command: `aws-sns-sms-send-notification` → `send-notification`

**Impact:**
- Integration now appears in XSOAR Ask task communication channel options
- Works alongside Slack and Teams for playbook data collection
- Enables SMS as a first-class communication method in conditional asks

**Use Case:**
```
Playbook Ask Task Communication Channels:
- Slack (SlackV3)
- Microsoft Teams
- AWS SNS SMS Communication (NEW)
```

### v1.0.5 - Marketplace Optimization (January 6, 2026)
**Git Commit:** 7f12c3b535 - Add messaging and communication tags, update category

**Changes:**
- Category updated: → "Messaging and Conferencing"
- Added integration tags: messaging, communication, sms
- Updated pack keywords for better discoverability
- Improved marketplace description

**Benefit:**
- Better categorization alongside Slack/Teams/Email integrations
- Improved search visibility in XSOAR Marketplace

### v1.0.6 - Version Tracking (January 6, 2026)
**Git Commit:** d315f6bd78 - Add version tracking and changelog to integration code

**Changes:**
- Added `INTEGRATION_VERSION` constant to Python code
- Added changelog comments in code header
- Version now visible in integration logs and debugging

**Example:**
```python
# VERSION: 1.0.6
# CHANGELOG: v1.0.6 - Added version tracking...
INTEGRATION_VERSION = "1.0.6"
```

### v1.0.7 - Docker Image Fix (January 6, 2026)
**Git Commit:** 77d3e887b1 - Update Docker image to boto3py3:1.0.0.115129

**Fix:**
- Updated Docker image to demisto/boto3py3:1.0.0.115129
- Resolved "manifest not found" error preventing integration execution
- Ensures boto3 library availability for AWS SDK operations

### v1.0.8 - SMSAskUser Script (January 7, 2026)
**Git Commit:** cfbd8035cd - Add SMSAskUser automation script

**New Component:**
Added SMSAskUser automation script mirroring SlackAskUser functionality

**Purpose:**
- Simplifies Ask task integration with SMS
- Automatically creates entitlements
- Formats messages with reply options
- Supports task closure based on SMS responses

**Usage:**
```python
!SMSAskUser phone="+1234567890" message="Approve incident?" option1="Yes" option2="No" task="${currentTaskId}"
```

**Script Flow:**
1. Creates entitlement via `addEntitlement` command
2. Formats message: "Question - Reply option1 or option2: GUID@incident|task"
3. Calls `send-notification` command
4. Integration extracts GUID, generates reply codes
5. User replies with code
6. Task resumes with chosen option

## Key Milestones

### Initial Development (v1.0.0)
- Complete two-way SMS integration with SNS/SQS
- Entitlement system implementation
- Reply code generation for concurrent conversations
- Long-running execution architecture

### Authentication & Configuration (v1.0.3)
- Enterprise-grade AWS authentication patterns
- Support for IAM roles and temporary credentials
- Configurable timeouts and retry logic

### XSOAR Integration (v1.0.4, v1.0.8)
- Ask task compatibility via command rename
- SMSAskUser script for simplified playbook usage
- Full parity with Slack/Teams communication channels

### Stability & Production Readiness (v1.0.7)
- Docker image fix for deployment reliability
- Version tracking for debugging
- Marketplace optimization

## Technical Architecture Summary

**AWS Services Used:**
- **AWS SNS**: SMS sending via `publish()` API
- **AWS SQS**: SMS reply receiving via long-running `receive_message()` polling
- **AWS STS**: Temporary credential management via `assume_role()`

**XSOAR Integration Points:**
- `demisto.handleEntitlementForUser()`: Task resumption
- `addEntitlement` command: Entitlement creation
- Integration context: State management
- Long-running execution: Background polling

**Key Design Patterns:**
- Entitlement GUID extraction from message text
- Reply code generation (4-digit random codes)
- Concurrent conversation tracking (phone → entitlements mapping)
- TTL-based cleanup (default 24 hours)

## Git Statistics

**Commits:** 13 commits (includes documentation commits)
**Integration Commits:** 9 version releases
**Lines of Code:** ~527 lines (main integration)
**Files Modified:**
- AWSSNSSMSCommunication.py (main integration)
- AWSSNSSMSCommunication.yml (configuration)
- pack_metadata.json (version tracking)
- ReleaseNotes/*.md (9 files)
- README.md (pack documentation)
- SMSAskUser.py + SMSAskUser.yml (automation script)

**Development Timeline:**
- January 6, 2026: v1.0.0 - v1.0.7 (7 versions, initial development)
- January 7, 2026: v1.0.8 (SMSAskUser script addition)

## Known Issues at End of v1.0.8

### AWS Two-Way SMS Configuration
**Status:** Outbound SMS working, inbound SMS not functioning

**Issue:**
- SMS messages sent successfully via SNS
- Recipients receive messages but replies don't reach SQS queue
- SMS sender shows as alphanumeric ID (not phone number)
- Two-way SMS requires dedicated Long Code or 10DLC number

**Action Required:**
- Request dedicated phone number from AWS SNS
- Configure number for two-way messaging
- Subscribe SQS queue to SNS topic for incoming messages
- Update integration to specify `OriginationNumber` parameter

## Deployment Status

**Branch Status:** feature/aws-sns-sqs-sms-integration
**Deployment Environment:** Development (beta.csirt-dev.cfadevelop.com)
**Integration Instance:** aws_sqs_sms (requires AWS credentials configuration)
**Pack Location:** Packs/AWSSNSSMSCommunication/

**Next Phase:** Versions 1.0.9+ (January 8, 2026) focus on bug fixes, documentation improvements, and Ask task clarification
