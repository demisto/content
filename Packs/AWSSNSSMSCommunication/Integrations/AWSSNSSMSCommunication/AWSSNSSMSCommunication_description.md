# AWS SNS SMS Communication

## Overview

The AWS SNS SMS Communication integration enables interactive two-way SMS communication within Cortex XSOAR playbooks. It leverages AWS Simple Notification Service (SNS) for sending SMS messages and AWS Simple Queue Service (SQS) for receiving user replies, with sophisticated entitlement management to support concurrent conversations.

### Key Features

- **Interactive SMS Messaging**: Send questions to users via SMS and receive their responses
- **Entitlement Support**: Full integration with XSOAR's entitlement system for conditional playbook tasks
- **Reply Code Management**: Automatically manages unique reply codes for concurrent conversations with the same user
- **Configurable Reply Feedback**: Independent control over success and failure SMS responses
- **Customizable Messages**: Templates for both success and failure feedback with variable substitution
- **Long-Running Execution**: Continuous polling of SQS queue for incoming SMS replies
- **Automatic Cleanup**: TTL-based expiration of old entitlements
- **Concurrent Conversation Handling**: Support multiple active questions to the same phone number
- **Automatic Credential Refresh**: Prevents AWS token expiration during long-running execution

## Ask Task Integration

### Method 1: Built-in XSOAR Ask Tasks (Works but Not Ideal for SMS)

Built-in XSOAR Ask tasks work with this integration but provide a suboptimal user experience for SMS.

**How it works:**
- Ask tasks send SMS with clickable URLs: "Approve? Yes (https://...) No (https://...)"
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
2. Formats message as: "Question - Reply option1 or option2: GUID@incident|task"
3. Integration extracts options and GUID, generates reply codes
4. User receives SMS: "Approve this incident?\nYes (1234) or No (5678)"
5. User replies with code: "1234"
6. Integration maps: 1234 to "Yes" to entitlement to task resumption

**Advantages:**
- Native SMS reply experience
- No browser required
- Works offline (user can reply anytime)
- Better user experience for SMS channel

**Direct Command Usage:**

```
!SMSAskUser phone="+1234567890" message="Approve incident?" option1="Yes" option2="No" task="${currentTaskId}"
```

**With 3-4 Options:**

```
!SMSAskUser phone="+1234567890" message="Select priority" option1="Critical" option2="High" option3="Medium" option4="Low" task="${currentTaskId}"
```

## Commands

### send-notification

Send an SMS notification with optional entitlement support for interactive messaging.

**Note:** Use the SMSAskUser script instead of calling this command directly for Ask-style questions.

**Arguments:**
- `to` (required): Destination phone number in E.164 format (e.g., +12345678900)
- `message` (required): Message text. For Ask-style questions, use SMSAskUser script.

**Context Output:**
- `AWS.SNS.SMS.MessageId`: The message ID returned by SNS
- `AWS.SNS.SMS.PhoneNumber`: The destination phone number
- `AWS.SNS.SMS.Entitlement`: The entitlement GUID if present
- `AWS.SNS.SMS.CodesToOptions`: Mapping of reply codes to options

### aws-sns-sms-list-entitlements

List all active entitlements with phone numbers, reply codes, and status. Useful for debugging and monitoring active SMS conversations.

**Arguments:**
- `phone_number` (optional): Filter by specific phone number
- `show_answered` (optional): Include answered entitlements (default: false)

**Context Output:**
- `AWS.SNS.SMS.Entitlement.EntitlementID`: The entitlement ID (GUID@incident|task)
- `AWS.SNS.SMS.Entitlement.PhoneNumber`: The phone number
- `AWS.SNS.SMS.Entitlement.ReplyCodes`: Reply codes for this entitlement
- `AWS.SNS.SMS.Entitlement.Message`: The message sent (truncated)
- `AWS.SNS.SMS.Entitlement.AgeHours`: Hours since creation
- `AWS.SNS.SMS.Entitlement.Answered`: Whether answered

**Command Example:**
```
!aws-sns-sms-list-entitlements
!aws-sns-sms-list-entitlements phone_number="+12345678900"
!aws-sns-sms-list-entitlements show_answered=true
```

### aws-sns-sms-inject-reply

**[TEST/DEBUG COMMAND]** Inject a simulated SMS reply for testing entitlement processing without actual SQS messages. Bypasses AWS infrastructure to test the integration's reply handling logic.

**Arguments:**
- `phone_number` (required): Phone number to simulate reply from (must match active entitlement)
- `reply_code` (required): 4-digit reply code from the SMS (e.g., 1234)

**Context Output:**
- `AWS.SNS.SMS.TestReply.Success`: Whether test succeeded
- `AWS.SNS.SMS.TestReply.ChosenOption`: The option mapped from reply code
- `AWS.SNS.SMS.TestReply.EntitlementGUID`: The entitlement GUID processed
- `AWS.SNS.SMS.TestReply.Error`: Error message if failed

**Command Example:**
```
!aws-sns-sms-inject-reply phone_number="+12345678900" reply_code="1234"
```

**Testing Workflow:**
1. Send SMS using SMSAskUser script
2. List entitlements to see generated codes: `!aws-sns-sms-list-entitlements`
3. Simulate reply: `!aws-sns-sms-inject-reply phone_number="..." reply_code="1234"`
4. Verify task resumed in playbook

## Configuration

### Prerequisites

1. **AWS Account** with SNS and SQS services enabled
2. **SNS Topic** configured for SMS messaging
3. **SQS Queue** configured to receive SMS replies from SNS
4. **AWS IAM User or Role** with appropriate permissions:
   - sns:Publish - Send SMS messages
   - sqs:ReceiveMessage - Poll SQS queue
   - sqs:DeleteMessage - Remove processed messages
   - sqs:GetQueueAttributes - Validate queue configuration
   - sts:AssumeRole - If using Role ARN authentication

### Integration Parameters

#### AWS Authentication

The integration supports multiple authentication methods:

1. **Role ARN only**: Uses STS AssumeRole without access keys (for EC2/Lambda with instance roles)
2. **Access Key + Role ARN**: Assumes role using provided credentials
3. **Access Key only**: Direct authentication with IAM user credentials
4. **Default credentials**: Uses EC2 instance role or environment variables

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| AWS Default Region | Yes | us-east-1 | AWS region for SNS/SQS services |
| Role Arn | No | - | IAM role ARN for STS AssumeRole |
| Role Session Name | No | - | Name for the assumed role session |
| Role Session Duration | No | 900 | Duration in seconds for role session (credentials auto-refresh at 80%) |
| Access Key / Secret Key | No | - | AWS IAM user credentials |

#### SQS Configuration

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| SQS Queue URL | Yes | - | Full URL of SQS queue receiving SMS replies |
| Poll Interval | No | 10 | Seconds between SQS polling requests |

#### Entitlement Settings

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| Entitlement TTL | No | 24 | Hours before unanswered entitlements expire |
| Long Running Instance | No | true | Enable continuous SQS polling |

#### Reply Feedback Settings

Control whether and how the integration sends feedback SMS to users when they reply.

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| Enable Success Feedback SMS | No | true | Send confirmation when reply is successfully processed |
| Enable Failure Feedback SMS | No | true | Send available codes when reply is unrecognized |
| Success Message Template | No | "{reply_code} - Thank you for your response!" | Customizable success message |
| Failure Message Template | No | "We couldn't process your response. Please reply with one of these codes: {available_codes}" | Customizable failure message |

**Success Message Variables:**
- `{reply_code}` - The code the user sent
- `{chosen_option}` - The option name (e.g., "Yes", "No")
- `{phone_number}` - The user's phone number

**Failure Message Variables:**
- `{available_codes}` - List of valid codes and options (e.g., "Yes (1234), No (5678)")
- `{phone_number}` - The user's phone number

#### Other Settings

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| Timeout | No | 60 | API timeout in seconds |
| Retries | No | 5 | Maximum retry attempts (max 10) |
| AWS STS Regional Endpoints | No | legacy | STS endpoint type (legacy/regional) |
| Use system proxy settings | No | false | Route traffic through system proxy |
| Trust any certificate | No | false | Skip SSL certificate verification |

## Reply Feedback

The integration provides automatic feedback to users when they send SMS replies. Success and failure feedback can be enabled or disabled independently.

### Success Feedback

When a user's reply code is successfully matched and processed:
- Confirms the response was received and processed
- Default message: "{reply_code} - Thank you for your response!"
- Customizable via the **Success Message Template** parameter
- Enable/disable via **Enable Success Feedback SMS** parameter

**Use cases for disabling:**
- Reduce SMS costs when confirmation is unnecessary
- User already knows they sent a reply
- Prefer silent processing

### Failure Feedback

When a user sends an unrecognized reply (wrong code or invalid format):
- Lists ALL available codes for that phone number's active questions
- Only sent if the phone number has active (unanswered) entitlements
- Default message: "We couldn't process your response. Please reply with one of these codes: {available_codes}"
- Customizable via the **Failure Message Template** parameter
- Enable/disable via **Enable Failure Feedback SMS** parameter

**Use cases for disabling:**
- Reduce SMS costs
- Prevent spam to wrong-number texts
- Handle failures through other channels

### Configuration Examples

**Enable both (default):**
- Success Feedback: Enabled
- Failure Feedback: Enabled

**Confirmation only (no failure help):**
- Success Feedback: Enabled
- Failure Feedback: Disabled

**Help on failure only (silent success):**
- Success Feedback: Disabled
- Failure Feedback: Enabled

**Silent mode (no feedback):**
- Success Feedback: Disabled
- Failure Feedback: Disabled

## How It Works

### Reply Code System

The integration automatically manages unique 4-digit reply codes for each option to handle concurrent conversations:

**How Reply Codes Are Generated:**

1. **SMSAskUser Script**: Formats message as "Question - Reply option1 or option2: GUID@incident|task"
2. **Integration Parsing**: Extracts options ("Yes", "No") and entitlement GUID from message
3. **Code Generation**: Creates unique 4-digit code for EACH option: Option "Yes" becomes code "1234", Option "No" becomes code "5678"
4. **SMS Formatting**: Sends "Question\nYes (1234) or No (5678)"
5. **Reply Processing**: User replies with just "1234", integration maps 1234 to "Yes" to entitlement

**Multiple Concurrent Questions:**
- Each option across ALL questions gets a unique code
- Supports many active questions to same phone number simultaneously
- Integration tracks all code-to-option mappings in context

**Reply Processing Flow:**
1. User replies with 4-digit code (e.g., "1234")
2. Integration validates code format
3. Finds matching entitlement and mapped option
4. Calls demisto.handleEntitlementForUser
5. Playbook task resumes with user's choice
6. Sends feedback SMS based on configuration

### Automatic Credential Refresh

When using Role ARN authentication with temporary credentials:
- Credentials are automatically refreshed at 80% of session duration
- Default session duration is 900 seconds (15 minutes)
- Refresh happens at 720 seconds (12 minutes) by default
- Prevents "ExpiredToken" errors during long-running execution

## Troubleshooting

### SMS Not Received
- Verify the phone number is in E.164 format (+12345678900)
- Check AWS SNS sending limits and quotas
- Confirm SNS topic has SMS permissions
- Verify AWS credentials have sns:Publish permission

### Replies Not Processed
- Verify SQS queue URL is correct
- Check SQS queue policy allows SNS to publish
- Confirm long-running instance is enabled and running
- Check integration logs for errors

### Entitlement Not Found
- Verify the entitlement GUID is in the message
- Check reply code matches the sent message
- Confirm entitlement hasn't expired (default 24h TTL)
- Review integration context for active entitlements

### Token Expiration Errors
- Check Role Session Duration setting
- Verify IAM role trust policy allows the integration
- Review logs for credential refresh messages

### Feedback SMS Not Sent
- Check if the relevant feedback toggle is enabled
- Verify AWS credentials have sns:Publish permission
- Check logs for send_feedback_sms errors
