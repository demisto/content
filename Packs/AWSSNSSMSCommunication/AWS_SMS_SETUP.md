# AWS SNS SMS Two-Way Communication Setup Guide

## Overview

This guide explains how to configure AWS SNS and SQS for two-way SMS communication with the AWS SNS SMS Communication integration.

## Prerequisites

- AWS Account with SNS and SQS permissions
- Phone number(s) to send/receive SMS

## Architecture

```
User's Phone <--SMS--> AWS SNS <--> SQS Queue <--> XSOAR Integration
```

1. **Outbound**: XSOAR sends SMS via SNS.publish()
2. **Inbound**: User replies via SMS -> AWS routes to SNS -> SNS publishes to SQS -> XSOAR polls SQS

## Step-by-Step Setup

### Step 1: Enable SNS for Two-Way SMS

AWS SNS requires configuration to receive incoming SMS messages. By default, SNS only supports sending SMS.

#### Option A: Using SNS Long Codes (Recommended for US)

1. Go to AWS SNS Console
2. Navigate to **Text messaging (SMS)** -> **Phone numbers**
3. Request a dedicated **Long Code** or **10DLC** number
4. Configure the number to forward incoming messages to an SNS topic

**Cost**: Long codes ~$1-2/month, 10DLC ~$8-15/month

#### Option B: Using Twilio/Third-Party Bridge

If AWS SNS doesn't support two-way SMS in your region:

1. Use a service like Twilio for incoming SMS
2. Configure Twilio webhook to publish to your SQS queue
3. Use AWS SNS only for outbound messages

### Step 2: Create SQS Queue

```bash
# Create the queue
aws sqs create-queue \
  --queue-name XSOAR-SMS-Replies \
  --attributes VisibilityTimeout=30

# Get the queue URL and ARN
aws sqs get-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT_ID/XSOAR-SMS-Replies \
  --attribute-names QueueArn
```

**Save the Queue URL** - you'll need it for XSOAR configuration.

### Step 3: Create SNS Topic for Incoming SMS

```bash
# Create SNS topic for incoming SMS
aws sns create-topic --name XSOAR-Incoming-SMS

# Get the topic ARN
aws sns list-topics | grep XSOAR-Incoming-SMS
```

### Step 4: Subscribe SQS to SNS Topic

```bash
# Subscribe SQS queue to SNS topic
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:XSOAR-Incoming-SMS \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:us-east-1:YOUR_ACCOUNT_ID:XSOAR-SMS-Replies
```

### Step 5: Update SQS Queue Policy

The SQS queue needs permission to receive messages from SNS:

```bash
# Create policy file: sqs-policy.json
cat > sqs-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "sns.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:YOUR_ACCOUNT_ID:XSOAR-SMS-Replies",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:XSOAR-Incoming-SMS"
        }
      }
    }
  ]
}
EOF

# Apply the policy
aws sqs set-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT_ID/XSOAR-SMS-Replies \
  --attributes file://sqs-policy.json
```

### Step 6: Configure SNS to Route Incoming SMS

**CRITICAL**: This step depends on your AWS SNS setup:

#### If using Long Code/10DLC:

1. In SNS Console, go to your phone number settings
2. Under **Incoming messages**, select your SNS topic: `XSOAR-Incoming-SMS`
3. AWS will automatically publish incoming SMS to this topic

#### If using SNS SMS Two-Way Setup:

AWS publishes incoming SMS replies in this format to your SNS topic:

```json
{
  "originationNumber": "+12345678900",
  "destinationNumber": "+10987654321",
  "messageBody": "User's reply text",
  "messageKeyword": "KEYWORD",
  "inboundMessageId": "...",
  "previousPublishedMessageId": "..."
}
```

### Step 7: Create IAM Role for XSOAR

```bash
# Create trust policy: xsoar-trust-policy.json
cat > xsoar-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_XSOAR_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name XSOAR-SMS-Integration \
  --assume-role-policy-document file://xsoar-trust-policy.json

# Create permissions policy: xsoar-permissions.json
cat > xsoar-permissions.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish",
        "sns:GetSMSAttributes",
        "sns:SetSMSAttributes"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ],
      "Resource": "arn:aws:sqs:us-east-1:YOUR_ACCOUNT_ID:XSOAR-SMS-Replies"
    }
  ]
}
EOF

# Attach permissions
aws iam put-role-policy \
  --role-name XSOAR-SMS-Integration \
  --policy-name XSOAR-SMS-Permissions \
  --policy-document file://xsoar-permissions.json

# Get the Role ARN
aws iam get-role --role-name XSOAR-SMS-Integration --query 'Role.Arn'
```

### Step 8: Configure XSOAR Integration Instance

In XSOAR, create an integration instance with:

- **AWS Default Region**: `us-east-1` (or your region)
- **Role Arn**: `arn:aws:iam::YOUR_ACCOUNT_ID:role/XSOAR-SMS-Integration`
- **Role Session Name**: `xsoar-sms-session`
- **Role Session Duration**: `900` (15 minutes)
- **Access Key** / **Secret Key**: Your AWS credentials (to assume the role)
- **SQS Queue URL**: `https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT_ID/XSOAR-SMS-Replies`
- **Long Running Instance**: `true`

## Testing

### Test 1: Send SMS

```
!aws-sns-sms-send-notification to="+12345678900" message="Test message"
```

You should receive the SMS on your phone.

### Test 2: Verify SQS Queue

Send an SMS reply from your phone, then check SQS:

```bash
aws sqs receive-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT_ID/XSOAR-SMS-Replies \
  --max-number-of-messages 10
```

If you see messages, AWS routing is working!

### Test 3: Check XSOAR Integration Logs

In XSOAR:
1. Go to Settings > Servers & Services
2. Find your integration instance
3. Click "Test" to verify connectivity
4. Check logs for SQS polling activity

## Troubleshooting

### No Messages in SQS

**Symptoms**: SMS sent successfully, reply sent from phone, but SQS queue is empty.

**Possible Causes**:
1. **SNS not configured for two-way SMS**
   - Verify you have a Long Code or 10DLC number
   - Check incoming message settings point to your SNS topic

2. **SNS topic not subscribed to SQS**
   - Run: `aws sns list-subscriptions-by-topic --topic-arn YOUR_TOPIC_ARN`
   - Should show your SQS queue as a subscriber

3. **SQS policy doesn't allow SNS**
   - Check queue policy allows SNS to send messages
   - Verify the source ARN matches your SNS topic

4. **Regional mismatch**
   - Ensure SNS topic, SQS queue, and XSOAR are all in the same region

### SQS Credentials Not Working

**Symptoms**: fetch-incidents shows `"credentials": null` in logs.

**Solution**: Configure the integration with proper credentials:
- Either provide Access Key/Secret Key
- Or configure Role ARN with proper AssumeRole permissions

### Messages Received but Not Processed

**Symptoms**: Messages in SQS but XSOAR doesn't process them.

**Possible Causes**:
1. **Message format mismatch**
   - Integration expects SNS message format
   - Check if messages are wrapped in SNS notification envelope

2. **Long-running integration not started**
   - Verify the integration instance is running
   - Check "Long Running Instance" is enabled

3. **Phone number format mismatch**
   - Ensure reply codes match the sent entitlement
   - Check phone number format consistency

## AWS SNS SMS Limitations

### Regional Availability

Two-way SMS is **NOT available in all regions**. As of 2026:

- **Supported**: US, Canada (with Long Codes or 10DLC)
- **Limited**: EU (requires special setup)
- **Not Supported**: Most other regions

### Message Format

Incoming SMS from AWS SNS arrives as:
```json
{
  "Type": "Notification",
  "Message": "{\"originationNumber\":\"+12345678900\",\"messageBody\":\"reply text\",...}"
}
```

The integration must parse the nested JSON.

### Costs

- **Outbound SMS**: $0.00645/message (US)
- **Inbound SMS**: Free (if using Long Code)
- **Long Code**: ~$1-2/month
- **10DLC**: ~$8-15/month + registration fees
- **SQS**: $0.40 per million requests

## Alternative: Third-Party Bridge

If AWS SNS two-way SMS isn't available in your region, use this pattern:

```
Outbound: XSOAR -> AWS SNS -> User's Phone
Inbound: User's Phone -> Twilio -> AWS Lambda -> SQS -> XSOAR
```

Lambda function example:
```python
import boto3
import json

sqs = boto3.client('sqs')
QUEUE_URL = 'https://sqs.us-east-1.amazonaws.com/ACCOUNT/XSOAR-SMS-Replies'

def lambda_handler(event, context):
    # Twilio webhook sends form data
    from_number = event['From']
    body = event['Body']

    # Format as SNS message
    message = {
        "Type": "Notification",
        "Message": json.dumps({
            "originationNumber": from_number,
            "messageBody": body
        })
    }

    # Send to SQS
    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message)
    )

    return {'statusCode': 200}
```

## Summary

The AWS SNS SMS Communication integration is now configured with:
- ✅ Role ARN authentication (matching AWS SNS/SQS integrations)
- ✅ Proper timeout and retry configuration
- ✅ STS regional endpoint support
- ✅ Long-running SQS polling
- ✅ Entitlement management with reply codes

**Next Steps:**
1. Configure AWS SNS for two-way SMS (if not already done)
2. Verify SQS queue receives incoming SMS
3. Test the integration with a playbook
