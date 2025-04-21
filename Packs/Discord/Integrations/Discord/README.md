This is the Discord integration for sending Messages from XSOAR to Discord  server made by Trustnet
## Configure Discord in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Api Key | You'll find your api key in BOT section -&amp;gt; Reset Token | True |
| Channel ID | You'll find your channel id by click on your channle then "Copy Channel ID" | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### discord-send-message

***
Send message to your channel

#### Base Command

`discord-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Enter your text. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Discord.Message.id | unknown | Message ID | 
| Discord.Message.content | unknown | Content | 
| Discord.Message.channel_id | unknown | Channel ID | 

### discord-get-message

***
Get message details

#### Base Command

`discord-get-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | Right click on message then "Copy Message ID". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Discord.Details.id | unknown | Message ID | 
| Discord.Details.content | unknown | Message Content | 
| Discord.Details.channel_id | unknown | Message Channel ID | 
| Discord.Details.author.id | unknown | Message Author ID | 
| Discord.Details.author.username | unknown | Message Author User Name | 