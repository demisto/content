Generates a password and sets the password for an Okta user.
Enables the account.
Sends an email to the user with the account information.
This script is running the `send-mail` command, make sure there is a mail sender integration configured.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | IAM, Utility, Okta |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name**      | **Description**                                                                                                                                           |
|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| pwdGenerationScript    | The password generator script.                                                                                                                            |
| username               | The Okta username of the user.                                                                                                                            |
| displayname            | The display name of the employee.                                                                                                                         |
| temporary_password     | When true, you'll need to change the password in the next login.                                                                                                             |
| to_email               | The email address that the password will be sent to.                                                                                                      |
| inc_id                 | The incident ID.                                                                                                                                          |
| email_subject          | The subject of the email sent to IT.                                                                                                                      |
| email_body             | The body of the email sent to IT.                                                                                                                         |
| ZipProtectWithPassword | The password to protect the zip file that contains the generated password. if not provided, the generated password will be send in the body of the email. |
| min_lcase              | Minimum number of lower case characters to include in password. Used with the GeneratePassword script \(leave empty if using another script\).            |
| max_lcase              | Maximum number of lower case characters to include in password. Used with the GeneratePassword script \(leave empty if using another script\).            |
| min_ucase              | Minimum number of upper case characters to include in password. Used with the GeneratePassword script \(leave empty if using another script\).            |
| max_ucase              | Maximum number of upper case characters to include in password. Used with the GeneratePassword script \(leave empty if using another script\).            |
| min_digits             | Minimum number of digits to include in password. Used with the GeneratePassword script \(leave empty if using another script\).                           |
| max_digits             | Maximum number of digits to include in password. Used with the GeneratePassword script \(leave empty if using another script\).                           |
| min_symbols            | Minimum number of symbols to include in password. Used with the GeneratePassword script \(leave empty if using another script\).                          |
| max_symbols            | Maximum number of symbols to include in password. Used with the GeneratePassword script \(leave empty if using another script\).                          |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IAM.InitOktaUser.success | True if the Okta user was successfully activated, false otherwise. | Boolean |
| IAM.InitOktaUser.sentMail | True if the mail containing the information about the user activation and its auto-generated password was successfully sent to IT, false otherwise. | Boolean |
| IAM.InitOktaUser.errorDetails | The error details, if exists. | String |
| IAM.InitOktaUser.sendMailError | The error received from send-mail command, if exists. | String |
