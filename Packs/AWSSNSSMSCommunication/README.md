# AWS SNS SMS Communication Pack

This pack enables interactive two-way SMS communication within Cortex XSOAR playbooks using AWS SNS and SQS.

## What Does This Pack Do?

- Send SMS notifications to users via AWS SNS
- Receive SMS replies via AWS SQS polling
- Manage concurrent conversations with unique reply codes (random 4-digit or simple sequential 1, 2, 3...)
- Integrate with XSOAR's entitlement system for conditional playbook tasks
- Automatically clean up expired entitlements

## Pack Contents

### Integrations

- **AWS SNS SMS Communication** - Long-running integration for sending and receiving SMS messages with entitlement support

## Use Cases

- Incident response authorization via SMS
- Security alerts with user confirmation
- Multi-factor authentication (MFA) and out-of-band verification
- Escalation management with SMS-based decisions

## Requirements

- AWS account with SNS and SQS enabled
- AWS IAM credentials with SNS publish and SQS receive permissions
- Configured SQS queue to receive SMS replies from SNS

## Setup

1. Install the pack
2. Configure AWS SNS and SQS (see integration README for details)
3. Create an integration instance with your AWS credentials
4. Enable long-running execution
5. Use in playbooks with conditional ask tasks

## Support

This is a community-supported pack. As a standalone pack, it receives community support only. For issues, feature requests, or contributions, please contact the pack author or submit issues through the appropriate channels.

**Author:** Maciej Drobniuch

## Additional Information

For detailed configuration and usage instructions, see the integration documentation.
