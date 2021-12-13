
This Playbook is part of the Content Management pack.

## Usage
Use this playbook to check to see if there are any content updates available for chosen installed content packs, and notify users via e-mail or Slack. The playbook contains an auto-update flow that allows users to decide whether they want to install all updates that were found.

## Triggers
- Manual Incident Creation - Set up a `Content Update Manager` incident to trigger the flow manually:
    1) Create a new incident with the type  `Content Update Manager`.
    2) Insert the pack names of the packs you want to check and update.
    3) Insert one of the following: Email/ Slack username/ Slack channel to get notified in the process and choose whether to trigger the auto-update flow.

- This playbook can be used as an XSOAR job to help users track marketplace pack updates and install them regularly. Configure a job using ###documentation link.

## Configuration & Dependencies
 
- GetServerURL pack - This is a mandatory dependency for the Content Update Manager playbook to run properly. You must install the GetServerURL pack through the XSOAR marketplace. No further configuration is required for this pack.
- Demisto REST API - This is a mandatory dependency for the Content Update Manager playbook to run properly. 
- Send Notifications - Configure an Email Gateway integration or the Slack messaging integration to get notifications about the content update process.

### Sub-playbooks
Content Version Check - This playbook is a part of the "Content Update Manager" playbook flow, and it checks whether the installed content is updated to it's latest version.

### Integrations
Demisto REST API
Scripts
GetServerURL
CollectPacksData
MarketplacePackInstaller
Commands
'demisto-api-get'
Set
setIncident
closeInvestigation
 
 
 
## Playbook Inputs
 ---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| notificationemail | Provide semi-colon delimited e-mail addresses that will be used for the new content notifications. You will require an integration installed and configured that supports the send-mail command. | incident.contentupdatemanageremail | Optional |
| slackuser | Provide a Slack username to which the notifications will be sent to. You will require Slack integration to be installed and configured. | incident.contentupdatemanagerslackusername | Optional |
| slackchannel | Provide a Slack channel to which the notifications will be sent to. You will require Slack integration to be installed and configured. Also, ensure that the XSOAR application has access to this channel. | incident.contentupdatemanagerslackchannel | Optional |
| packs | A CSV of packs to monitor. | incident.contentupdatemanagerpackselection | Required |
| auto_update | This will establish whether the content packs will be updated automatically if there are available updates or wait for an analyst's approval or manual update process. | Specify 'Yes' for auto-update or 'No' for manual update. | Optional |

 
## Playbook Outputs
 ---

There are no outputs for this playbook.

## Playbook Image
