Signum password expiry notification.
## Configure Signum in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Signum URL, in the format https://signmum.keyfactorsaas.com | True |
| Username | True |
| Password | True |
| verify certificate | False |
| Use system proxy | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### signum-list-domain-users

***
List domain users by domain ID.
#### Base Command

`signum-list-domain-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Identification of the domain for which to list the users.  Default is 1. | Required | 
| simple_view | If "True", strip off prefixes, such as "{urn:.*}" and "{http://.*}", from each dictionary key name. Possible values are: True, False. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Signum.ListDomainUsers | unknown | The result of the signum-list-domain-users command. | 