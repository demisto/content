Create a calendar invite using the given playbook inputs and send it to the provided recipient using send-mail.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* iCalEntryCreate

### Commands

* send-mail

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| calendar_event_recipient | The email address of the recipient |  | Required |
| title | The title for the even |  | Required |
| start_date | The start date in the format YYYY/MM/DD |  | Required |
| start_time | The start time in the format HH:MM |  | Required |
| start_time_zone | The time zone of the start date/time | Europe/Berlin | Optional |
| end_date | The end date in the format YYYY/MM/DD |  | Required |
| end_time | The end time in the format HH:MM |  | Required |
| end_time_zone | The time zone of the end date/time | Europe/Berlin | Optional |
| description | An optional description for the event |  | Optional |
| url | An optional URL to be added to the event. In case none is provided, the script will try to determine the URL of the incident to create a direct link |  | Optional |
| uid | Optional argument allowing to override the email UID. Use in case the invite may need to be updated. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Create and send calendar invite](../doc_files/Create_and_send_calendar_invite.png)
