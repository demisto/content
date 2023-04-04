This playbook resets the password of an Active Directory or Okta user. The process is as follows:
1. A user requests a password reset using a chatbot on Slack or on Microsoft Teams.
2. The playbook optionally seeks approval to reset the user's password from the relevant stakeholder, or from the user's manager.
3. If the reset was approved, the playbook optionally verifies the user using 2-factor authentication, from the user's available 2FA methods on Okta.
4. If the reset is verified, a new password will be created while meeting the complexity requirements of the organization.
5. The user's password will be reset and set to the newly generated password. The user will be forced to change their password on next login.
6. The new user's password will be placed inside a password-protected ZIP (protected by a different password).
7. The encrypted ZIP file that contains the new password for the user will be sent to the user via email. 
8. The password for the ZIP file that contains the new user's password, will be sent to the requesting user through Slack or Teams.

This playbook is intended for use with Slack or Teams. In order to use it, please make sure that you have a classifier and mapper in place. The classifier should create a Reset User Password via Chatbot incident, while the mapper should map the email of the user to the Reporter Email Address field.
This playbook assumes that the user requesting the password reset has the same email in Slack / Teams, and in Active Directory / Okta.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Active Directory - Get User Manager Details

### Integrations

This playbook does not use any integrations.

### Scripts

* IAMInitADUser
* IAMInitOktaUser
* GeneratePassword

### Commands

* closeInvestigation
* send-mail
* setIncident
* okta-verify-push-factor
* okta-get-user-factors
* ad-get-user
* send-notification
* okta-get-user

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PasswordMaxDigits | The maximum number of digits in the generated password. If no value is specified, a value of 10 will be used. | 4 | Optional |
| PasswordMaxLowercase | Maximum number of lower case characters to include in password. If no value is specified, a value of 10 will be used. | 4 | Optional |
| PasswordMaxSymbols | Maximum number of symbols to include in password. If no value is specified, a value of 10 will be used. | 4 | Optional |
| PasswordMaxUppercase | Maximum number of upper case characters to include in password. If no value is specified, a value of 10 will be used. | 4 | Optional |
| PasswordMinDigits | Minimum number of digits to include in password. If no value is specified, a value of 0 will be used. | 2 | Optional |
| PasswordMinLowercase | Minimum number of lower case characters to include in password. If no value is specified, a value of 0 will be used. | 2 | Optional |
| PasswordMinSymbols | Minimum number of symbols to include in password. If no value is specified, a value of 0 will be used. | 2 | Optional |
| PasswordMinUppercase | Minimum number of upper case characters to include in password. If no value is specified, a value of 0 will be used. | 2 | Optional |
| ConfirmationTarget | Optional - determines who will approve or disapprove the password reset. Possible values are: no value specified, email address of the user that will confirm the reset, or "Manager".<br/><br/>If no value is specified - approval will not be required when resetting the password.<br/><br/>If the value of "Manager" is specified - the user's manager email will be retrieved from Active Directory, and an approval email will be sent to the manager to allow or decline the password reset.<br/><br/>If an email is specified  - an approval email will be sent to the email specified to allow or decline the password reset. | Manager | Optional |
| ConfirmationEmailSubject | Optional - applicable only if the "ConfirmationTarget" input is not blank.<br/>The subject of the email that will be sent to approve or disapprove the password reset. This email would be sent to the user's manager, IT staff or anyone else specified. | Action Required - User Password Reset | Optional |
| ConfirmationEmailBody | Optional - applicable only if the "ConfirmationTarget" input is not empty.<br/>The body of the email that will be sent to approve or disapprove the password reset. This email would be sent to the user's manager, IT staff or anyone else specified. | User [PLACEHOLDER] asked to reset their password.<br/>Please allow or decline the password reset. | Optional |
| TargetProduct | Determines where the user password will be reset. Some organizations provision the data from Okta to Active Directory, so they may choose to reset the password in Okta instead of Active Directory.<br/>Possible values are \(choose one\):<br/>- Active Directory<br/>- Okta | Okta | Optional |
| Require2FA | Whether to require that the user authenticates using an available authentication method.<br/>Currently, this only supports the Extra Verification methods available in Okta \(Okta Verify, SMS, Security Question or Google Authenticator\). | True | Optional |
| UserEmailSubject | The subject of the email with the password that will be sent to the user. | Password Reset | Optional |
| UserEmailBody | The body of the email with the password that will be sent to the user. Note: the password will not be included in the email body, but in a protected ZIP file instead. | Following your request to reset your password, we've changed your password to a new temporary password.<br/>After logging in, you will be required to change the password to a new one.<br/>You can find the password in the ZIP file attached to this email. The password to the ZIP file was sent to you in a direct message on Slack or on Teams. | Optional |
| ZipPasswordMessage | The message that will be sent to the user on Slack/Teams after their password was reset. The value of this input will be appended to the beginning of the the ZIP password that will be sent in the following manner:<br/>"The zip file password is: \[zip_password_will_be_here\]".<br/><br/>Note: there is no need to actually write the placeholder for the ZIP password. It will simply appear after your message.<br/> | Following your request to reset your password, we've sent you an email with the new password. The password is protected inside an encrypted ZIP file.<br/>The password to the ZIP file is:  | Optional |
| ResetNotApprovedEmailSubject | The subject of the email that will be sent to the requesting user in case the reset was disapproved or could not be approved. | Password Reset Not Approved | Optional |
| ResetNotApprovedEmailBody | The body of the email that will be sent to the requesting user in case the reset was not approved or could not be approved. | Your request for a password reset could not be approved or was disapproved. Please contact helpdesk for assistance with resetting your password.<br/><br/>If you did not ask to reset your password, please change your password immediately and report the incident. | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Reset User Password via Chatbot](../doc_files/Reset_User_Password_via_Chatbot.png)
