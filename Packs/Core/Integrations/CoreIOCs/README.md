# Deprecation Notice

As part of our ongoing commitment to platform performance, reliability, and standardization, the four integrations and commands within the "Core" pack listed below will be officially deprecated in mid-January 2027:

- Indicators detection (Cortex Core - IOC)
- Investigation & Response (Cortex Core - IR)
- XQL Query Engine
- Cortex Platform - Core

## What this means for you

- **Existing custom playbooks:** Automations and playbooks currently using commands from these integrations will continue to function as expected. No existing workflows will abruptly break upon deprecation. We recommend migrating them to the native Cortex built-in commands, which offer higher execution performance and unified platform syntax.
- **Out-of-the-box Cortex playbooks:** All out-of-the-box playbooks shipped with the platform will be updated by Palo Alto Networks to use built-in commands natively. No action is required on your part for uncustomized, standard playbooks.
- **Maintenance and support:** Following the deprecation date, these integrations will no longer receive feature updates, enhancements, or bug fixes.

For detailed command-by-command replacement mappings and usage examples, please refer to the [Cortex Built-In Commands Guide](https://cortex-docs.paloaltonetworks.com/cortex-commands-guide).

## Command mapping

The following table maps each command in this integration to its Cortex built-in command. Argument names and output paths can differ between a command and its built-in replacement, so review the built-in command's arguments before migrating. See the [Cortex Built-In Commands Guide](https://cortex-docs.paloaltonetworks.com/cortex-commands-guide) for details.

| Deprecated command | Built-in command | Category |
|---|---|---|
| `core-iocs-push` | `pushIOCs` | indicators |
| `core-iocs-enable` | `enableIOCs` | indicators |
| `core-iocs-disable` | `disableIOCs` | indicators |

The Cortex Core - IOCs integration uses the Cortex API for detection and response, by natively integrating network, endpoint, and cloud data to stop sophisticated attacks.

## Configure Indicators detection

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cortex XDR Severity | Map the severity of each indicator that will be synced to Cortex. | True |
| Tags | Supports CSV values. | False |
| Sync Query | The query used to collect indicators to sync from Cortex. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### core-iocs-sync

***
Sync your IOC with Cortex and delete the previous version.

#### Base Command

`core-iocs-sync`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstTime | For first sync, set to true.<br/>(do NOT run this twice!). Possible values are: true, false. Default is false. | Optional |

#### Context Output

There is no context output for this command.

### core-iocs-push

***
Push modified IOCs to Cortex.

#### Base Command

`core-iocs-push`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | IOCs to push. leave empty to push all recently modified IOCs.the indicators. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!core-iocs-push indicator='test.com'```

#### Human Readable Output

>push done.

### core-iocs-set-sync-time

***
Set sync time manually (Do not use this command unless you unredstandard the consequences).

#### Base Command

`core-iocs-set-sync-time`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time | The time of the file creation (use UTC time zone). | Required |

#### Context Output

There is no context output for this command.

### core-iocs-create-sync-file

***
Creates the sync file for the manual process. Run this command when instructed by the Cortex support team.

#### Base Command

`core-iocs-create-sync-file`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### core-iocs-enable

***
Enables IOCs in the Cortex tenant.

> **Note:** This command applies only to TIM-managed indicators (indicators that were synced/pushed to the Cortex tenant by this integration). Enabling an indicator not managed by TIM has no effect.

#### Base Command

`core-iocs-enable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to enable. Only TIM-managed indicators can be enabled; indicators from other sources are not affected. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!core-iocs-enable indicator=1.1.1.1```

#### Human Readable Output

>indicators 1.1.1.1 enabled.

### core-iocs-disable

***
Disables IOCs in the Cortex tenant.

> **Note:** This command applies only to TIM-managed indicators (indicators that were synced/pushed to the Cortex tenant by this integration). Disabling an indicator not managed by TIM has no effect.

#### Base Command

`core-iocs-disable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to disable. Only TIM-managed indicators can be disabled; indicators from other sources are not affected. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!core-iocs-disable indicator=22.22.22.22```

#### Human Readable Output

>indicators 22.22.22.22 disabled.
