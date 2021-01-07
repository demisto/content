Asks a user a question via email and process the reply directly into the investigation.

## Setup

Demisto can use email responses within the system, e.g. when an external user's approval is required. To do this, you will create an email template with multiple choice options (e.g. Reply "Yes" if you approve and "No" if you do not).

**Before starting you will need to configure an integration capable for sending and receiving emails. Such as: Mail Listener v2 and Mail Sender (New), GMail, EWS O365, Microsoft Graph Mail Single User.**

The user who receives the mail will respond accordingly and when an answer is received, it will trigger a task to handle the response.
This is a two step task. The first, is to send an email asking the user for information. The second step, is to receive the answer and trigger a process of handling it in Demisto.

The outgoing email contains a token that will be used when the user responds to the email. According to the token, the response will be directed to the relevant incident.

### Step 1 - Sending an email
Add the EmailAskUser script and set as follows:
* Email – the email address the message is sent to.
* Message – The email message.
* Option 1 – The first option to choose from.
* Option 2 – The second option to choose from.
* Subject -  The email subject.
* Task – The ID of the task in the playbook, to trigger when a reply is received. The task ID is found when you look at the task and as represented as #<number> on the task. The task ID is located in the lower-left corner of the task. You can also use a task *tag* (see Example below).

### Step 2 - A conditional task
Add a conditional task to receive the reply from the email. This task is triggered when a reply from the email is received according to its task ID that is set as the Task parameter in the EmailAskUser script (see above).

Add condition options, such as:
* Condition 1 – Yes
* Condition 2 – No

Then add Case Yes and set the input as Option 1 and Case No and set the input as Option 2.

## Example
An example arrangement for EmailAskUser task is as below:

![image](https://user-images.githubusercontent.com/54623333/99517136-efc5b480-2986-11eb-879c-a0a88923c4b9.png)


There needs to be a manual conditional task *after* the EmailAskUser Task - It is this task that is referenced as "task" in the EmailAskUser parameters.

It is good practice to tag the wait task as shown:

![image](https://user-images.githubusercontent.com/54623333/99517219-0409b180-2987-11eb-9aa4-7e96b2a12238.png)


The tag you choose (in this case "Await") can be used in lieu of the task id in the task field of the EmailAskUser Task:


![image](https://user-images.githubusercontent.com/54623333/99517256-0f5cdd00-2987-11eb-8a1f-1dc41d166b42.png)



## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | email |
| Demisto Version | 4.0.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| email | The email of the user to ask. |
| subject | The subject for the email. |
| message | The message sent to the user you are going to ask. |
| option1 | The first option for a user reply.The default is "yes". |
| option2 | The second option for the user reply. The default is "no". |
| additionalOptions | The comma delimited list of additional options if there are more than 2. |
| task | Which task the reply will close. If none, then no playbook tasks will be closed. |
| roles | Send mail to all users of these roles (a CSV list). |
| attachIds | The attachments. |
| bodyType | The type of email body to send. Can be, "text" or "HTML". |
| replyAddress | The reply address for the html links. |
| replyEntriesTag | The tag to add on email reply entries. |
| persistent | Whether to use one-time entitlement or a persistent one. |
| retries | How many times to try and create an entitlement in case of a failure. |
| cc | The CC email address. |
| bcc | The BCC email address. |
| playbookTaskID | The subplaybook ID, use `${currentPlaybookID}` to get from the context, `all` to complete all tasks from all plabooks |

## Outputs
---
There are no outputs for this script.


## Prerequisites
---
Requires an instance of one of the available email integrations.


