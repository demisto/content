This integration can monitor EDLs by emailing the content of an EDL as a zipped file to a specified user at a defined interval, and/or simply monitor the EDL for availability and email the user if the EDL is not available
## Configure EDL Monitor on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EDL Monitor.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | EDL IP or URL (e.g. http://xsoarserver.com:10009 or https://xsoarserver.com/instance/execute/instance_name) |  | True |
    | Incident type |  | False |
    | EDL username |  | False |
    | EDL password |  | False |
    | Timeout: | Timeout \(in seconds\) for how long to wait for EDL response before detecting as down \(default 2 minutes\) | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | Monitor contents?  (Set false to monitor EDL availability only) | If true, this will email the contents of the EDL at the set interval to the configured emailTo user.  Set false to monitor only for EDL availability, and email the user if the EDL is found to be unavailable at the configured interval | False |
    | Incidents Fetch Interval | Set this to the polling interval you want between checks to the EDL \(in minutes, default 60 min\) | False |
    | Email To: | Who to email the current EDL contents to \(email address\) | True |
    | Email server: |  | False |
    | Email username |  | False |
    | Email password |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### helloworld-say-hello

***
Hello command - prints hello to anyone.

#### Base Command

`helloworld-say-hello`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here. | 
