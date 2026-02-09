Ask a user a question via SMS and expect a response.

This automation script simplifies sending SMS questions with entitlements by:
- Creating an entitlement automatically
- Formatting the message with reply options
- Sending the SMS via the send-notification command
- Supporting task closure based on user response

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | sms, messaging |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| phone | The phone number to send SMS to in E.164 format (e.g., +12345678900) | Required |
| message | The message to ask the user | Required |
| option1 | First option for a user reply. Default is "yes". | Optional |
| option2 | Second option for the user reply. Default is "no". | Optional |
| task | Which task should we close with the reply. If none then no playbook tasks will be closed. | Optional |
| replyEntriesTag | Tag to add on SMS reply entries | Optional |
| persistent | Indicates whether to use one-time entitlement or a persistent one. Default is false. | Optional |

## Outputs

---
There are no outputs for this script.

## Example

Send an SMS asking for approval:

```
!SMSAskUser phone="+12345678900" message="Approve incident #123?" option1="approve" option2="deny" task="approval_task"
```

This will send an SMS with the message:
```
Approve incident #123? - Reply approve or deny: {entitlement}@{incident_id}|approval_task
```

## Notes

- The script uses the send-notification command from the AWS SNS SMS Communication integration
- The integration automatically handles reply code generation for concurrent conversations
- Replies are matched to entitlements and the specified task is closed with the user's response
