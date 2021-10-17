- Generates a password.
- Sets an Active Directory user account with this password.
- Enables the account if enable_user argument is set to "true".
- Sends a notification email to the emails specified in the notification_emails_list.
- Sends an email to the manager (unless the user is an acquisition hire).
This script is running `send-mail` command, please make sure there is a matching Integration configurated.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | IAM, active directory, Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| pwdGenerationScript | The password generator script. |
| sAMAccountName | The sAMAccountName of the employee. |
| user_profile | The user profile data. |
| enable_user | Whether or not to enable the user. |
| manager_email_template_list_name | An HTML template of the manager email body to be sent. Placeholders should be of the form $\{USER_FIELD\}, where USER_FIELD is either "sAMAccountName", "password" or any existing User Profile incident field in CLI form, e.g. "displayname". |
| notification_email_addresses | A comma-separated list of email addresses that should recieve the notification email. |
| notification_email_template_list_name | An HTML template of the notification email body to be sent. Placeholders should be of the form $\{USER_FIELD\}, where USER_FIELD is either "sAMAccountName", "password" or any existing User Profile incident field in CLI form, e.g. "displayname". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IAM.Vendor.action | The script name. | String |
| IAM.Vendor.success | True if the Active Directory user was successfully activated, false otherwise. | Boolean |
| IAM.Vendor.errorMessage | The error details, if exists. | String |
| IAM.Vendor.brand | Name of the integration used in this script. | String |

#### Command Example
```
!IAMInitADUser user_profile="{\"city\":\"Santa Clara\",\"costcenter\":\"IoT - PM\",\"costcentercode\":\"651116\",\"countryname\":\"United States Of America\",\"department\":\"Enterprise R\\u0026D:FWaaP\",\"displayname\":\"test 126\",\"email\":\"test126@paloaltonetworks.com\",\"employeeid\":\"270145\",\"employeetype\":\"Regular\",\"employmentstatus\":\"\",\"givenname\":\"test\",\"hiredate\":\"10/10/2021\",\"jobcode\":\"5225\",\"jobfamily\":\"Product Management\",\"jobfunction\":\"Product Management Function\",\"lastdayofwork\":\"02/15/2032\",\"leadership\":\"No\",\"location\":\"Office - USA - CA - Headquarters\",\"locationregion\":\"Americas\",\"manageremailaddress\":\"test@test.com\",\"orglevel1\":\"marketing\",\"orglevel2\":\"field marketing\",\"orglevel3\":\"field marketing test\",\"personalemail\":\"test6@testing.com\",\"prehireflag\":\"True\",\"rehiredemployee\":\"No\",\"sourceoftruth\":\"Workday IAM\",\"sourcepriority\":1,\"state\":\"California\",\"streetaddress\":\"3000 Tannery Way\",\"surname\":\"126\",\"terminationdate\":\"02/15/2032\",\"title\":\"Product Line Manager\",\"username\":\"test126@paloaltonetworks.com\",\"zipcode\":\"95054\"}" notification_email_addresses=test@example.com,test2@example.com sAMAccountName=test126 enable_user=false manager_email_template_list_name=email-template-new-hire-manager
```

#### Context Example
```
{
    "IAM": {
        "Vendor": {
            "action": "IAMInitADUser",
            "brand": "Active Directory Query v2",
            "success": true
        }
    }
}
```

#### Human Readable Output
Successfully initiated user test126 in disabled mode.