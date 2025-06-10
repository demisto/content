<~XSIAM>
 # Extrahop RevealX
 ## Overview
ExtraHop RevealX 360 is a cloud-based security platform that provides comprehensive visibility and advanced threat detection across your network. It helps organizations quickly identify and respond to security threats in hybrid and multi-cloud environments. By leveraging machine learning and behavioral analytics, RevealX 360 monitors network traffic to spot suspicious activities and potential risks in real time.

## This pack includes:
- Rest API log collection for detection logs
- Modeling Rules for detection logs

## Configure an instance for ExtraHop Reveal(x)

### How to create REST API Credentials:
* You must have system and access administration privileges.
1. Log in to RevealX 360.
2. Click the **System Settings** icon - at the top right of the page and then click All Administration.
3. Click **API Access**.
4. Click **Create Credentials**.
5. In the Name field, type a name for the credentials.
6. In the Privileges field, specify a privilege level for the credentials. The privilege level determines which actions can be performed with the credential. Do not grant more privileges to REST API credentials than needed because it can create a security risk. For example, applications that only retrieve metrics should not be granted credentials that grant administrative privileges. For more information about each privilege level, see User privileges. 
* Note: System and Access Administration privileges are similar to Full write privileges and allow the credentials to connect sensors and Trace appliances to RevealX 360.*
7. In the Packet Access field, specify whether you can retrieve packets and session keys with the credentials.
8. Click **Save**. The Copy REST API Credentials pane appears.
9. Under ID, click **Copy to Clipboard** and save the ID to your local machine.
10. Under Secret, click **Copy to Clipboard** and save the secret to your local machine.
11. Click **Done**.

For more information, see the following guide [here](https://docs.extrahop.com/current/rx360-rest-api/)

## Configure ExtraHop Reveal(x) in Cortex XSIAM


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
Retrieves a list of audit log events from the Extrahop RevealX instance.

#### Base Command

`revealx-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| max_events | Returns no more than the specified number of detections. | Optional | 

#### Context Output

There is no context output for this command.

</~XSIAM>

ExtraHop Reveal(x) for Cortex XSOAR is a network detection and response solution that provides complete visibility of network communications at enterprise scale, real-time threat detections backed by machine learning, and guided investigation workflows that simplify response.

##### What does this integration do?

This integration enables the following investigative tasks and workflows in Cortex XSOAR as an automated response to ExtraHop Reveal(x) detections:

- Create a Cortex XSOAR incident in real-time when a Reveal(x) detection identifies malicious or non-compliant behavior on your network.
- Leverage Reveal(x) playbooks to respond with thousands of security actions that accelerate automated investigation and remediation.
- Send real-time queries to Reveal(x) through the ExtraHop REST API that enable you to search for specific devices, network peers, active protocols, records, and packets that are part of your investigation.
- Track tickets in Reveal(x) that link detections to your Cortex XSOAR investigation.

The following figures show an example of an ExtraHop Reveal(x) detection and the resulting playbook workflows in Cortex XSOAR.

![ExtraHop detection card](doc_files/ExtraHop_Detection_CVE-2019-0708_BlueKeep.png)

*Figure 1. Reveal(x) detection card for CVE-2019-0708 RDP Exploit Attempt*

![Cortex XSOAR playbook: ExtraHop Default](doc_files/ExtraHop_-_Default.png)

*Figure 2. Reveal(x) Default playbook to set up ticket tracking and run the BlueKeep playbook*

![Cortex XSOAR playbook: ExtraHop CVE-2019-0708 BlueKeep](doc_files/ExtraHop_-_CVE-2019-0708_BlueKeep.png)

*Figure 3. Reveal(x) CVE-2019-0708 BlueKeep playbook to automate detailed network investigation*
