Get the user feedback on a blocked file, whether it is false or true positive and if an exemption is needed.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

DLP - Get User Feedback via Email

### Integrations

Palo_Alto_Networks_Enterprise_DLP

### Scripts

* Set
* SetAndHandleEmpty
* DlpAskFeedback

### Commands

* pan-dlp-get-report
* setIncident
* pan-dlp-exemption-eligible
* pan-dlp-update-incident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| UserDisplayName | The display name of the user. |  | Optional |
| MessageApp | Choose the application to communicate with the users.<br/>Available options:<br/>- Slack <br/>- Microsoft Teams |  | Optional |
| SendMailInstance | The name of the instance to be used when executing the "send-mail" command in the playbook. In case it will be empty, all available instances will be used \(default\). |  | Optional |
| UserEmail | The user email address. |  | Optional |
| Detections | Detected violation snippets. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| UserRequestedExemption | Whether the user requested exemption or not. | unknown |

## Playbook Image

---

![DLP - Get User Feedback](../doc_files/DLP_-_Get_User_Feedback.png)
