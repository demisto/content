# Guide: migrating from Recorded Future Intelligence pack

This guide describes how to migrate from the **Recorded Future Intelligence** content pack to the **Recorded Future** content pack.

This new pack contains the **Recorded Future Alerts** integration. This has incident fetching functionality and commands for working with alerts.

## Migrating incident fetching
If you are fetching incidents with the **Recorded Future Intelligence** pack, you can migrate to this pack by:

1. Install the **Recorded Future** content pack
2. Instantiate the **Recorded Future Alerts** integration and configure it to create incidents
3. De-activate incident fetching in the **Recorded Future v2** integration settings
4. De-activate incident fetching in the **Recorded Future - Playbook Alerts** integration settings

This is how your set-up can look once you are done:


#### Recorded Future Intelligence pack
| Integration name                  | Instantiate? | Fetch incidents?  |
|-----------------------------------|--------------|-------------------|
| Recorded Future v2                | ✅            | ❌                 |
| Recorded Future - Playbook Alerts | ❌            | ❌                 |

#### Recorded Future pack 
| Integration name                  | Instantiate? | Fetch incidents?  |
|-----------------------------------|--------------|-------------------|
| Recorded Future Alerts            |  ✅           | ✅                 |


Notes on the old **Recorded Future v2** integration:
- This integration provides enrichment commands, so you can keep it instantiated for this purpose.
- The alert commands in this integration are now deprecated in favour of commands in this content pack.

Notes on the old **Recorded Future - Playbook Alerts** integration:
- This integration is now deprecated. The alert fetching functionality as well as all commands have been moved to this content pack.
- If you do not have playbooks using the `recordedfuture-playbook-alert-*` commands, you do not need to instantiate this.


## Migrating playbooks
The **Recorded Future** content pack introduces new incident types that are all prefixed with “RF”.

1. If you have playbooks tied to the old incident types: these will need to be migrated to the new incident types. See [Incident type comparison](#incident-type-comparison) below.
2. If your playbooks are using any `recordedfuture-alert-*` commands: You are recommended to replace the commands with `rf-alert-*` commands. See [Command migration guide](#command-migration-guide) below.
3. If your playbooks are using any `recordedfuture-playbook-alert-*` commands: You are recommended to replace the commands with `rf-alert-*` commands. See [Command migration guide](#command-migration-guide) below.
    1. This will allow you to delete your instance(s) of the **Recorded Future - Playbook Alerts** integration


## Incident type comparison

Here are the old “Recorded Future” incident types and how they correspond to the new “RF” incident types:

| Recorded Future Intelligence pack                     | Recorded Future pack                        |
|-------------------------------------------------------|---------------------------------------------|
| Recorded Future Alert                                 | RF Classic Alert                            |
 | Recorded Future Leaked Credential Monitoring          | RF Classic Alert                            |
 | Recorded Future New Critical or Pre NVD Vulnerability | RF Classic Alert                            |
 | Recorded Future Potential Typosquat                   | RF Classic Alert                            |
 | Recorded Future Playbook Alert                        | RF Playbook Alert                           |
 | Recorded Future Code Repo Leakage                     | RF Data Leakage on Code Repo Playbook Alert |
 | Recorded Future Domain Abuse                          | RF Domain Abuse Playbook Alert              |
 | Recorded Future Vulnerability                         | RF Vulnerability Playbook Alert             |
 | -                                                     | RF Facility Risk Playbook Alert             |
 | -                                                     | RF Third-Party Cyber Playbook Alert         |

## Command migration guide
The following commands from the **Recorded Future v2** integration are now marked as deprecated, and can be replaced with new commands:


| Recorded Future v2 command      | Recorded Future Alerts command                                                                                                   |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `recordedfuture-alert-rules`      | `rf-alert-rules`                                                                                                                   |
| `recordedfuture-alert-set-note`   | `rf-alert-update`                                                                                                                  |
| `recordedfuture-alert-set-status` | `rf-alert-update`                                                                                                                  |
| `recordedfuture-alerts`           | `rf-alerts`                                                                                                                        |
| `recordedfuture-single-alert`      | (this command is no longer needed - when an alert is fetched as an incident, all relevant data is added to the incident context) |

The following commands from the **Recorded Future - Playbook Alerts** integration are now marked as deprecated, and can be replaced with new commands:

| Recorded Future - Playbook Alerts command | Recorded Future Alerts command                                                                                                   |
|-------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|  
| `recordedfuture-playbook-alerts-search`     | `rf-alerts`                                                                                                                        | 
| `recordedfuture-playbook-alerts-update`     | `rf-alert-update`                                                                                                                  | 
| `recordedfuture-playbook-alerts-details`    | (this command is no longer needed - when an alert is fetched as an incident, all relevant data is added to the incident context) |
