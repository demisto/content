## **Azure Credentials Rotation Playbook**

### **IAM Remediation**
Protect your identity and access management:
- **Reset Password**: Resets the user password to halt any unauthorized access.

- **Revoke Session**: Terminates current active sessions to ensure the malicious actor is locked out.

- **Combo Action**: Resets the password and terminates all active sessions.

### **Service Principal Remediation**
Guard your applications:
- **Password Regeneration**: Generate a new password for the service principal, making sure the old one becomes obsolete.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* GeneratePassword

### Commands

* msgraph-user-session-revoke
* msgraph-apps-service-principal-get
* msgraph-apps-service-principal-lock-configuration
* msgraph-apps-service-principal-unlock-configuration
* msgraph-apps-service-principal-password-add
* msgraph-user-update

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IAMRemediationType | The response playbook provides the following remediation actions using MSGraph Users:<br/><br/>Reset: By entering "Reset" in the input, the playbook will execute password reset.<br/><br/>Revoke: By entering "Revoke" in the input, the playbook will revoke the user's session.<br/><br/>ALL: By entering "ALL" in the input, the playbook will execute the reset password and revoke session tasks. |  | Optional |
| appID | This is the unique application \(client\) ID of the application. |  | Optional |
| objectID | This is the unique ID of the service principal object associated with the application. |  | Optional |
| userID | The user ID or user principal name. |  | Optional |
| identityType | The type of identity involved. Usually mapped to incident field named 'cloudidentitytype'.<br/>e.g.<br/>IAM,APPLICATION |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MSGraphUser | The Microsoft Graph Users information. | unknown |
| MSGraphApplication | The Microsoft Graph Application information. | unknown |

## Playbook Image

---

![Cloud Credentials Rotation - Azure](../doc_files/Cloud_Credentials_Rotation_-_Azure.png)
