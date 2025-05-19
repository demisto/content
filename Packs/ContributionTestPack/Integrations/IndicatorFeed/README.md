This is the Hello World integration for getting started.
## Configure Indicator Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://example.net) |  | True |
| Username |  | True |
| Password |  | True |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Is Feed Incremental |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
|  |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### helloworld-say-hello

***
Hello command - prints hello to anyone

#### Base Command

`helloworld-say-hello`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here | 
