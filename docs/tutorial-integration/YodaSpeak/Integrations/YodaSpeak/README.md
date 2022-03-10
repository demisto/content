An integration to translate English to Yodish.

## Configure YodaSpeak on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for YodaSpeak.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL of the service |  | True |
    | API Key | The API Key to use for connection | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### yoda-speak-translate
***
Use this command to translate English text.


#### Base Command

`yoda-speak-translate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | The English text to translate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| YodaSpeak.Translation | String | The translated text, in Yodish. | 
| YodaSpeak.Original | String | The original \(English\) text we translated. | 


#### Command Example
``` !yoda-speak-translate text="this is some sentence for translation."```

#### Human Readable Output

### Yoda Says...
|Original|Translation|
|---|---|
| this is some sentence for translation. | Some sentence for translation, this is. |

