
This playbook is part of the Content Management pack.

## Usage
This playbook checks for any available content updates for selected installed content packs and notifies users via e-mail or Slack. 
It also contains an auto-update flow that lets users decide via playbook inputs or communication tasks if they want to trigger an auto-update process to install all updates that were found.

## Triggers
The content update flow can be triggered in one of the following ways.
- Manually trigger by:
    1) Creating a new incident with the type **Content Update Manager**.
    2) Inserting the pack names you want to check and update.
    3) Inserting one of the following: Email/ Slack username/ Slack channel to get notified in the process and choose whether to trigger the auto-update flow.
- Configure a Cortex XSOAR job using [Jobs](https://xsoar.pan.dev/docs/incidents/incident-jobs#create-a-job).

## Configuration & Dependencies
 
- GetServerURL pack - This is a mandatory dependency for the **Content Update Manager** playbook to run properly. You must install the GetServerURL pack through the XSOAR marketplace. No further configuration is required for this pack.
- Demisto REST API - This is a mandatory dependency for the **Content Update Manager** playbook to run properly. 
- Send Notifications - Configure an email gateway integration or the Slack messaging integration to get notifications about the content update process.

### Sub-playbooks
**Content Version Check** - This playbook is a part of the **Content Update Manager** playbook flow, and it checks whether the installed content is updated to its latest version.

### Integrations
- Demisto REST API
- Scripts
- GetServerURL
- CollectPacksData
- MarketplacePackInstaller

### Commands
- demisto-api-get
- Set
- setIncident
- closeInvestigation
  
 
## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| notificationemail | Provides semi-colon delimited e-mail addresses for the new content notifications. Note: You must have an installed and configured integration that supports the send-mail command. | incident.contentupdatemanageremail | Optional |
| slackuser | Provides a Slack username for the new content notifications. Note: You must have an installed and configured Slack integration. | incident.contentupdatemanagerslackusername | Optional |
| slackchannel | Provides a Slack channel for the new content notifications. Note: You must have an installed and configured Slack integration. Also, make sure the Cortex XSOAR application has access to this channel. | incident.contentupdatemanagerslackchannel | Optional |
| packs | A CSV of packs to monitor. | incident.contentupdatemanagerpackselection | Required |
| auto_update | Establishes whether to automatically update the content packs if there are available updates or wait for an analyst's approval or the manual update process. Specify 'Yes' for auto-update or 'No' for manual update. | No default value | Optional |

 
## Playbook Outputs
There are no outputs for this playbook.

## Playbook Image
![image](https://github.com/demisto/content/raw/ec6fdf6bc123841f8ba688e6d7e21072327f0d9c/Packs/XSOARContentUpdateNotifications/doc_files/Content_Update_Manager.png?raw=true)