This is the ClickSend integration for make a phonecall from XSOAR  made by Trustnet

## Configure ClickSend in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Api Key | You'll find your api key here: <https://dashboard.clicksend.com/account/subaccounts> | True |
| Username | You'll find your username here: <https://dashboard.clicksend.com/account/subaccounts> | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### clicksend-text-to-voice

***
Make phone call with you own text. Example: !clicksend-text-to-voice Message="Hi im here" phoneNumber=+972501234567 require_input=False voice=male

#### Base Command

`clicksend-text-to-voice`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| phoneNumber | Phone Number  Example: +972501234567. | Required | 
| Message | Message Body. | Required | 
| require_input | If you want that the person will need to input. Possible values are: False, True. | Required | 
| voice | You Can choose either Male or Female. Possible values are: male, female. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Voice.MSG.id | unknown | Message ID | 
| Voice.MSG.responseCode | unknown | Response Code | 
| Voice.MSG.responseMsg | unknown | Response MSG | 

### clicksend-voice-history

***
Your calls history Example: !clicksend-voice-history

#### Base Command

`clicksend-voice-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Voice.History | unknown | Your Calls History | 