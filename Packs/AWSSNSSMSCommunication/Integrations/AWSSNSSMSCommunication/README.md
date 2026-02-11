# AWS SNS SMS Communication

## Overview

The AWS SNS SMS Communication integration enables interactive two-way SMS communication within Cortex XSOAR playbooks. It leverages AWS Simple Notification Service (SNS) for sending SMS messages and AWS Simple Queue Service (SQS) for receiving user replies, with sophisticated entitlement management to support concurrent conversations.

### Key Features

- **Interactive SMS Messaging**: Send questions to users via SMS and receive their responses
- **Entitlement Support**: Full integration with XSOAR's entitlement system for conditional playbook tasks
- **Reply Code Management**: Automatically manages unique reply codes for concurrent conversations with the same user
- **Reply Code Modes**: Choose between random 4-digit codes or simple sequential numbers (1, 2, 3...) for simpler UX
- **Reply Feedback SMS**: Sends confirmation when reply is processed or lists available codes for unrecognized replies
- **Long-Running Execution**: Continuous polling of SQS queue for incoming SMS replies
- **Automatic Cleanup**: TTL-based expiration of old entitlements
- **Concurrent Conversation Handling**: Support multiple active questions to the same phone number

## Ask Task Integration

### Method 1: Built-in XSOAR Ask Tasks (Works but Not Ideal for SMS)

Built-in XSOAR Ask tasks work with this integration but provide a suboptimal user experience for SMS.

**How it works:**
- Ask tasks send SMS with clickable URLs: `"Approve? Yes (https://...) No (https://...)"`
- User clicks the URL in the SMS
- Phone browser opens with a web form
- User responds through the browser
- Response is processed through XSOAR's web interface (not through SMS reply)

**Limitations:**
- User must leave SMS app and use browser
- Requires internet connection and browser interaction
- No native SMS reply experience

### Method 2: SMSAskUser Script (Recommended for Native SMS Experience)

The **SMSAskUser** automation script (included in this pack) provides a native SMS experience with reply codes.

**How it works:**
1. SMSAskUser creates entitlement GUID before sending SMS
2. Formats message as: `"Question - Reply option1 or option2: GUID@incident|task"`
3. Integration extracts options and GUID, generates reply codes
4. User receives SMS (random mode): `"Approve this incident?\nYes (1234) or No (5678)"`
   Or (sequential mode): `"Approve this incident?\nYes (1) or No (2)"`
5. User replies with code: `"1234"` or `"1"`
6. Integration maps code -> option -> entitlement -> task resumption

**Advantages:**
- Native SMS reply experience
- No browser required
- Works offline (user can reply anytime)
- Better user experience for SMS channel

**Direct Command Usage:**

```
!SMSAskUser phone="+1234567890" message="Approve incident?" option1="Yes" option2="No" task="${currentTaskId}"
```

## Use Cases

- **Incident Response Authorization**: Request approval from stakeholders via SMS
- **Security Alerts**: Send alerts and gather user responses for threat validation
- **MFA/OOB Verification**: Out-of-band verification via SMS
- **Escalation Management**: SMS-based decision making in critical incidents

## Configuration

### Prerequisites

1. **AWS Account** with SNS and SQS services enabled
2. **SNS Topic** configured for SMS messaging
3. **SQS Queue** configured to receive SMS replies from SNS
4. **AWS IAM User** with appropriate permissions:
   - `sns:Publish` - Send SMS messages
   - `sqs:ReceiveMessage` - Poll SQS queue
   - `sqs:DeleteMessage` - Remove processed messages
   - `sqs:GetQueueAttributes` - Validate queue configuration

### AWS Setup

#### Step 1: Create SQS Queue for SMS Replies

```bash
aws sqs create-queue --queue-name xsoar-sms-replies --attributes VisibilityTimeout=30
```

#### Step 2: Subscribe SQS Queue to SNS

AWS SNS can forward incoming SMS replies to an SQS queue. Configure SNS to publish to your SQS queue:

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789:your-topic \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:123456789:xsoar-sms-replies
```

#### Step 3: Update SQS Queue Policy

Allow SNS to send messages to your SQS queue:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "sns.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:123456789:xsoar-sms-replies",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:sns:us-east-1:123456789:your-topic"
        }
      }
    }
  ]
}
```

### Integration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| AWS Access Key ID | Yes | - | AWS IAM user access key |
| AWS Secret Access Key | Yes | - | AWS IAM user secret key |
| AWS Default Region | Yes | us-east-1 | AWS region for SNS/SQS services |
| SQS Queue URL | Yes | - | Full URL of SQS queue receiving SMS replies |
| Poll Interval (seconds) | No | 10 | How often to poll SQS for new messages |
| Entitlement TTL (hours) | No | 24 | Time before unanswered entitlements expire |
| Reply Code Mode | No | random | Code style: "random" (4-digit codes) or "sequential" (1, 2, 3...) |
| Long Running Instance | No | true | Enable continuous SQS polling |
| Enable Reply Feedback SMS | No | true | Send confirmation SMS when user replies |
| Success Message Template | No | {reply_code} - Thank you for your response! | Customizable success message. Variables: {reply_code}, {chosen_option}, {phone_number} |

## Commands

### send-notification

Send an SMS notification with optional entitlement support for interactive messaging.

**Note:** Use the `SMSAskUser` script instead of calling this command directly for Ask-style questions.

#### Input

| Argument | Required | Description |
|----------|----------|-------------|
| to | Yes | Destination phone number in E.164 format (e.g., +12345678900) |
| message | Yes | Message text. For Ask-style questions, use SMSAskUser script. |

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| AWS.SNS.SMS.MessageId | String | The message ID returned by SNS |
| AWS.SNS.SMS.PhoneNumber | String | The destination phone number |
| AWS.SNS.SMS.Entitlement | String | The entitlement GUID if present |
| AWS.SNS.SMS.ReplyCode | String | The reply code assigned to this message |

#### Command Example

```
# Simple notification (no reply expected)
!send-notification to="+12345678900" message="Incident #123 has been created"

# For interactive questions, use SMSAskUser script instead:
!SMSAskUser phone="+12345678900" message="Approve incident?" option1="Yes" option2="No"
```

### aws-sns-sms-list-entitlements

List all active entitlements with phone numbers, reply codes, and status.

Useful for debugging and monitoring active SMS conversations.

#### Input

| Argument | Required | Description |
|----------|----------|-------------|
| phone_number | No | Filter by specific phone number |
| show_answered | No | Include answered entitlements (default: false) |

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| AWS.SNS.SMS.Entitlement.EntitlementID | String | The entitlement ID (GUID@incident\|task) |
| AWS.SNS.SMS.Entitlement.PhoneNumber | String | The phone number |
| AWS.SNS.SMS.Entitlement.ReplyCodes | String | Reply codes for this entitlement |
| AWS.SNS.SMS.Entitlement.Message | String | The message sent (truncated) |
| AWS.SNS.SMS.Entitlement.AgeHours | Number | Hours since creation |
| AWS.SNS.SMS.Entitlement.Answered | Boolean | Whether answered |

#### Command Example

```
# List all active entitlements
!aws-sns-sms-list-entitlements

# List for specific phone number
!aws-sns-sms-list-entitlements phone_number="+12345678900"

# Include answered entitlements
!aws-sns-sms-list-entitlements show_answered=true
```

### aws-sns-sms-inject-reply

**[TEST/DEBUG COMMAND]** Inject a simulated SMS reply for testing entitlement processing without actual SQS messages.

Bypasses AWS infrastructure to test the integration's reply handling logic.

#### Input

| Argument | Required | Description |
|----------|----------|-------------|
| phone_number | Yes | Phone number to simulate reply from (must match active entitlement) |
| reply_code | Yes | Reply code from the SMS (e.g., 1234 in random mode, or 1 in sequential mode) |

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| AWS.SNS.SMS.TestReply.Success | Boolean | Whether test succeeded |
| AWS.SNS.SMS.TestReply.ChosenOption | String | The option mapped from reply code |
| AWS.SNS.SMS.TestReply.EntitlementGUID | String | The entitlement GUID processed |
| AWS.SNS.SMS.TestReply.Error | String | Error message if failed |

#### Command Example

```
# Test a reply with code 1234
!aws-sns-sms-inject-reply phone_number="+12345678900" reply_code="1234"
```

**Testing Workflow:**
1. Send SMS using SMSAskUser script
2. List entitlements to see generated codes: `!aws-sns-sms-list-entitlements`
3. Simulate reply: `!aws-sns-sms-inject-reply phone_number="..." reply_code="1234"`
4. Verify task resumed in playbook

## Reply Feedback

The integration provides automatic feedback to users when they send SMS replies, improving the user experience by confirming whether their response was processed.

### Success Feedback

When a user's reply code is successfully matched and processed:

- **Default message**: `"1234 - Thank you for your response!"`
- **Customizable** via the Success Message Template parameter
- **Available variables**: `{reply_code}`, `{chosen_option}`, `{phone_number}`

**Example custom messages:**
- `"Response received: {chosen_option}"`
- `"{reply_code} confirmed - you selected {chosen_option}"`

### Failure Feedback

When a user sends an unrecognized reply (wrong code or format), and they have active questions pending:

- **Default message**: `"We couldn't process your response. Please respond with one of the available reply codes: Yes (1234), No (5678)"`
- Lists ALL available codes for that phone number's active questions
- Only sent if the phone number has active (unanswered) entitlements

**Note:** If the user sends a reply but has no active questions, no failure message is sent (prevents spam).

### Disabling Feedback

To disable automatic feedback SMS, set **Enable Reply Feedback SMS** to `false` in the integration configuration.

## How It Works

### Reply Code System

The integration manages unique reply codes for each option to handle concurrent conversations. Two modes are available via the **Reply Code Mode** configuration parameter:

#### Random Mode (Default)

Generates random 4-digit codes for each option:

1. **SMSAskUser Script**: Formats message as `"Question - Reply option1 or option2: GUID@incident|task"`
2. **Integration Parsing**: Extracts options ("Yes", "No") and entitlement GUID
3. **Code Generation**: Creates unique 4-digit code for EACH option: "Yes" -> "1234", "No" -> "5678"
4. **SMS Formatting**: Sends `"Question\nYes (1234) or No (5678)"`
5. **Reply Processing**: User replies with "1234", integration maps to "Yes"

#### Sequential Mode

Uses simple incrementing numbers (1, 2, 3...) across all active questions for a simpler user experience:

```
Q1: Did you do the thing?
    Yes (1) or No (2)

Q2: Did you do the other thing?
    Yes (3) or No (4)

Q3: Did you do the last thing?
    Yes (5) or No (6)
```

- Numbers increment across all active questions for a phone number
- When a question is answered, its numbers become available for reuse
- Simpler for end users -- just reply with a single digit

#### Multiple Concurrent Questions

Both modes support multiple active questions to the same phone number:
- Each option across ALL questions gets a unique code
- Integration tracks all code-to-option mappings in context

**Reply Processing Flow:**
1. User replies with code (e.g., "1234" or "1")
2. Integration validates the code is numeric
3. Finds matching entitlement and mapped option
4. Calls `demisto.handleEntitlementForUser(incident_id, guid, phone, "Yes", task_id)`
5. Playbook task resumes with user's choice

### Complete Entitlement Flow

```
1. Playbook calls SMSAskUser script
2. SMSAskUser creates entitlement: demisto.addEntitlement()
3. SMSAskUser formats message: "Question - Reply Yes or No: GUID@incident|task"
4. SMSAskUser calls send-notification with formatted message
5. Integration extracts: question="Question", options=["Yes", "No"], guid="GUID@incident|task"
6. Integration generates codes: {"1234": "Yes", "5678": "No"}
7. Integration saves mapping: phone + codes + entitlement to context
8. Integration sends SMS via SNS: "Question\nYes (1234) or No (5678)"
9. User receives SMS and replies: "1234"
10. AWS routes reply to SQS queue (via SNS subscription)
11. Long-running execution polls SQS, receives message
12. Integration extracts reply code: "1234"
13. Integration finds matching entitlement and option: "Yes"
14. Integration calls: demisto.handleEntitlementForUser(incident, guid, phone, "Yes", task)
15. XSOAR resumes playbook task with "Yes" response
16. Integration marks entitlement as answered
```

### State Management

The integration uses XSOAR's integration context to store:

- Active entitlements (not yet answered)
- Phone number mappings
- Reply codes
- Timestamps for TTL-based cleanup

### Automatic Cleanup

Every hour, the long-running process removes entitlements older than the configured TTL (default 24 hours). This prevents the integration context from growing indefinitely.

## Troubleshooting

### SMS Not Received

- Verify the phone number is in E.164 format (+12345678900)
- Check AWS SNS sending limits and quotas
- Confirm SNS topic has SMS permissions
- Verify AWS credentials have `sns:Publish` permission

### Replies Not Processed

- Verify SQS queue URL is correct
- Check SQS queue policy allows SNS to publish
- Confirm long-running instance is enabled and running
- Check integration logs for errors: `demisto.debug()` output

### Entitlement Not Found

- Verify the entitlement GUID is in the message
- Check reply code matches the sent message
- Confirm entitlement hasn't expired (default 24h TTL)
- Review integration context for active entitlements

### Multiple Active Conversations

This is expected behavior! The integration supports multiple concurrent questions to the same phone number by assigning unique reply codes to each question.

## Limitations

- AWS SNS SMS has regional restrictions and country-specific regulations
- SQS polling interval affects response time (default 10 seconds)
- Reply codes are 4 digits in random mode (10,000 combinations) or sequential numbers in sequential mode
- Integration context size limits may apply for very high volumes

## Version History

### 1.0.38 (2026-02-11)
- Updated integration description and README documentation for Reply Code Mode feature

### 1.0.37 (2026-02-11)
- Added **Reply Code Mode** configuration parameter:
  - **random** (default): 4-digit reply codes (existing behavior)
  - **sequential**: Simple incrementing numbers (1, 2, 3...) for simpler UX
- Sequential mode assigns next available number, skipping codes in use
- Reply code validation now accepts any numeric code (supports both modes)

### 1.0.33 (2026-01-19)
- Added **SMS Reply Feedback** feature for improved user experience:
  - Success feedback: Sends confirmation SMS when reply is processed
  - Failure feedback: Lists available reply codes for unrecognized replies
- New configuration parameters: Enable Reply Feedback SMS, Success Message Template
- Customizable success message with variables: {reply_code}, {chosen_option}, {phone_number}

### 1.0.18 (2026-01-08)
- Added comprehensive detailed description to integration YAML
- Beautified SMSAskUser script with versioning, comments, and docstrings
- Updated README with critical Ask task documentation

### 1.0.17 (2026-01-08)
- Added `aws-sns-sms-inject-reply` test command for debugging without SQS

### 1.0.16 (2026-01-08)
- **REMOVED non-functional URL decoding** for built-in Ask tasks
- Clarified SMSAskUser is ONLY supported method for Ask-style SMS
- Updated documentation to explain why built-in Ask tasks don't work

### 1.0.15 (2026-01-08)
- DEPRECATED: Attempted URL decoding (does not work)

### 1.0.14 (2026-01-08)
- Added SMSAskUser automation script format support
- Parse "Question - Reply option1 or option2: GUID@incident|task" format

### 1.0.13 (2026-01-08)
- **BREAKING CHANGE**: Redesigned reply code system
- Each option now has unique 4-digit code (e.g., "Yes (1234) or No (5678)")
- Enables multiple concurrent questions to same phone number
- Updated entitlement storage to use codes_to_options mappings

### 1.0.12 (2026-01-08)
- Fixed Ask task integration with URL cleaning

### 1.0.11 (2026-01-08)
- Added `aws-sns-sms-list-entitlements` command
- Comprehensive debug logging throughout integration

### 1.0.10 (2026-01-08)
- Changed test-module to use SQS get_queue_attributes

### 1.0.9 (2026-01-08)
- Fixed test-module by removing unsupported MaxItems parameter

### 1.0.8 (2026-01-06)
- Added SMSAskUser automation script

### 1.0.7 (2026-01-06)
- Updated Docker image to demisto/boto3py3:1.0.0.115129

### 1.0.6 (2026-01-06)
- Added version tracking and changelog to integration Python code

### 1.0.5 (2026-01-06)
- Added messaging/communication tags
- Updated category to "Messaging and Conferencing"

### 1.0.4 (2026-01-06)
- Renamed command to "send-notification" for Ask task compatibility

### 1.0.3 (2026-01-06)
- Added Role ARN authentication
- Added timeout/retries configuration
- Added STS regional endpoints support

### 1.0.2 (2026-01-06)
- Updated author and community support notice

### 1.0.1 (2026-01-06)
- Added integration image

### 1.0.0 (2026-01-06)
- Initial release
- SNS SMS sending with entitlement support
- SQS reply polling with long-running execution
- Reply code management for concurrent conversations
- Automatic TTL-based cleanup
