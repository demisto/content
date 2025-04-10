ExtraHop Reveal(x) is a network detection and response solution that provides complete visibility of network communications at enterprise scale, real-time threat detections backed by machine learning, and guided investigation workflows that simplify response.


## Configure an instance for ExtraHop Reveal(x)

### How to create REST API Credentials:
* You must have system and access administration privileges.
1. Log in to RevealX 360.
2. Click the System Settings icon - at the top right of the page and then click All Administration.
3. Click API Access.
4. Click Create Credentials.
5. In the Name field, type a name for the credentials.
6. In the Privileges field, specify a privilege level for the credentials. The privilege level determines which actions can be performed with the credential. Do not grant more privileges to REST API credentials than needed because it can create a security risk. For example, applications that only retrieve metrics should not be granted credentials that grant administrative privileges. For more information about each privilege level, see User privileges. 
* Note: System and Access Administration privileges are similar to Full write privileges and allow the credentials to connect sensors and Trace appliances to RevealX 360.*
7. In the Packet Access field, specify whether you can retrieve packets and session keys with the credentials.
8. Click Save. The Copy REST API Credentials pane appears.
9. Under ID, click Copy to Clipboard and save the ID to your local machine.
10. Under Secret, click Copy to Clipboard and save the secret to your local machine.
11. Click Done.


## Configure ExtraHop Reveal(x) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| Client Id | The client ID generated on your ExtraHop system that is required for authentication if connecting to ExtraHop Reveal\(x\) 360. | True |
| Client Secret | The client secret generated on your ExtraHop system that is required for authentication if connecting to ExtraHop Reveal\(x\) 360. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Maximum number of events per fetch | Defines the maximum number of audits events per fetch cycle. Default value: 25000. | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### revealx-get-events

***
Retrieves a list of audit logs events from the Extrahop RevealX instance.

#### Base Command

`revealx-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| max_events | Returns no more than the specified number of detections. | Optional | 

#### Context Output

There is no context output for this command.
