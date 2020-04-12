This is the Hello World integration for getting started.
The integration is a sample integration to quickly get you started.
It demonstrates how to build an integration using the recommended `Client` class architecture.

## Configure HelloWorld on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HelloWorld.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL (e.g., https://example.net) | True |
| credentials | Username | True |
| isFetch | Fetch incidents. | False |
| incidentType | Incident type. | False |
| insecure | Trust any certificate (not secure). | False |
| proxy | Use system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### helloworld-say-hello
***
Hello command - prints hello to the specified name


##### Base Command

`helloworld-say-hello`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name hello to.  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello **something** here. | 

