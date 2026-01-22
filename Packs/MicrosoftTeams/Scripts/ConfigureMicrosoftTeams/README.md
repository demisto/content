Configures Microsoft Teams integration by refreshing the bot installation in a team and setting up the XSOAR integration instance.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | microsoftteams, configuration |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* setIntegration
* addEntitlement

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| tenant_id | The Azure AD Tenant ID. If not provided, uses a default value. |
| client_id | The Azure AD Application \(Client\) ID. If not provided, uses a default value. |
| client_secret | The Azure AD Application Client Secret. If not provided, uses a default value. |
| team_id | The Microsoft Teams Team ID where the bot will be installed. If not provided, uses a default value. |
| bot_app_id | The Bot Application ID to install in the team. If not provided, uses a default value. |
| instance_name | The name of the Microsoft Teams integration instance to configure. Default is "MS_Teams_Instance". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ConfigureMicrosoftTeams.Status | The status of the configuration operation. | String |
| ConfigureMicrosoftTeams.TeamID | The Team ID where the bot was installed. | String |
| ConfigureMicrosoftTeams.InstanceName | The name of the configured integration instance. | String |

## Usage

---

The ConfigureMicrosoftTeams script automates the configuration of Microsoft Teams integration in XSOAR. It performs the following operations:

1. **Obtains Access Token**: Authenticates with Microsoft Graph API using the provided Azure AD credentials.
2. **Searches for Existing Bot**: Checks if the bot is already installed in the specified team.
3. **Removes Old Installation**: If the bot is already installed, it removes the existing installation to ensure a clean setup.
4. **Reinstalls Bot**: Installs the bot application in the Microsoft Teams team.
5. **Configures XSOAR Integration**: Sets up the Microsoft Teams integration instance in XSOAR with the provided credentials.

### Example Usage

To use `ConfigureMicrosoftTeams` in a playbook or manually:

1. Run the script with the required Azure AD and Teams parameters:
   * `tenant_id`: Your Azure AD Tenant ID
   * `client_id`: Your Azure AD Application (Client) ID
   * `client_secret`: Your Azure AD Application Client Secret
   * `team_id`: The Microsoft Teams Team ID where you want to install the bot
   * `bot_app_id`: The Bot Application ID to install
   * `instance_name`: (Optional) The name for your integration instance

2. The script will automatically:
   * Refresh the bot installation in the specified team
   * Configure the Microsoft Teams integration instance in XSOAR
   * Return the status of the operation

### Prerequisites

* Azure AD application with appropriate permissions for Microsoft Graph API
* Microsoft Teams bot application registered in Azure
* Team ID where the bot should be installed
* Appropriate permissions in XSOAR to configure integrations

## Notes

---

* The script includes default values for testing purposes. In production, always provide your own credentials.
* The script waits 5 seconds after removing an existing bot installation to allow Microsoft's systems to synchronize before reinstalling.
* All operations are logged using `demisto.debug()` for troubleshooting purposes.
* The client secret is marked as a secret parameter and will be masked in logs.
