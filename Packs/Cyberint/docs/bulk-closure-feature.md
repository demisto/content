# Bulk Closure of Check Point Exposure Management Incidents in XSOAR

## Overview

The Check Point Exposure Management integration now supports bulk closure of incidents directly from Cortex XSOAR. This feature allows security analysts to efficiently close multiple Check Point Exposure Management alerts in a single operation, significantly reducing the time required for incident management workflows.

## Key Features

### 1. Bulk Status Updates

The `cyberint-alerts-status-update` command supports updating multiple alerts simultaneously by providing a comma-separated list of alert reference IDs.

**Supported Status Transitions:**
- `open` - Reopen alerts
- `acknowledged` - Mark alerts as acknowledged
- `closed` - Close alerts (requires a closure reason)

### 2. User-Friendly Closure Reasons

When closing alerts, you can now select from human-readable closure reasons:

| Display Value | Description |
|--------------|-------------|
| Resolved | The threat has been successfully mitigated |
| No Longer a Threat | The alert is no longer considered a security risk |
| Irrelevant Alert Subtype | The alert type does not apply to your organization |
| False Positive | The alert was incorrectly identified as a threat |
| Other | Custom reason (requires description) |

### 3. Bi-directional Mirroring Support

When mirroring is enabled, closing incidents in XSOAR automatically closes the corresponding alerts in Cyberint, and vice versa.

## Usage

### Command: cyberint-alerts-status-update

#### Basic Syntax

```
!cyberint-alerts-status-update alert_ref_ids=<ref_ids> status=<status> [closure_reason=<reason>] [closure_reason_description=<description>]
```

#### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `alert_ref_ids` | Yes | Comma-separated list of alert reference IDs |
| `status` | Yes | Target status: `open`, `acknowledged`, or `closed` |
| `closure_reason` | Conditional | Required when status is `closed`. Options: `Resolved`, `No Longer a Threat`, `Irrelevant Alert Subtype`, `False Positive`, `Other` |
| `closure_reason_description` | Conditional | Required when closure_reason is `Other`. Free text description |

### Examples

#### Close a Single Alert

```
!cyberint-alerts-status-update alert_ref_ids="ARG-123" status="closed" closure_reason="Resolved"
```

#### Bulk Close Multiple Alerts

```
!cyberint-alerts-status-update alert_ref_ids="ARG-123,ARG-124,ARG-125,ARG-126" status="closed" closure_reason="False Positive"
```

#### Close with Custom Reason

```
!cyberint-alerts-status-update alert_ref_ids="ARG-123,ARG-124" status="closed" closure_reason="Other" closure_reason_description="Duplicate of existing incident INC-456"
```

#### Bulk Acknowledge Alerts

```
!cyberint-alerts-status-update alert_ref_ids="ARG-200,ARG-201,ARG-202" status="acknowledged"
```

## Integration Configuration for Mirroring

To enable automatic closure synchronization between XSOAR and Check Point Exposure Management:

1. Navigate to **Settings** > **Integrations** > **Servers & Services**
2. Find and edit your Check Point Exposure Management integration instance
3. Configure the following parameters:

| Parameter | Description |
|-----------|-------------|
| **Incident Mirroring Direction** | Select `Incoming And Outgoing` for bi-directional sync |
| **Close Mirrored XSOAR Incident** | Enable to auto-close XSOAR incidents when Check Point Exposure Management alerts are closed |
| **Close Mirrored Check Point Exposure Management Alert** | Enable to auto-close Check Point Exposure Management alerts when XSOAR incidents are closed |

## Incident Fields

When an incident is closed, the following fields are populated:

| Field Name | Description |
|------------|-------------|
| **Cyberint Alert Close Reason** | The selected closure reason |
| **Cyberint Closure Reason Description** | Additional description (when "Other" is selected) |
| **Cyberint Status** | Current status of the alert |

## Playbook Integration

You can incorporate bulk closure into your playbooks using the following task configuration:

```yaml
- id: bulk_close_cyberint_alerts
  name: Close Check Point Exposure Management Alerts
  script: cyberint-alerts-status-update
  arguments:
    alert_ref_ids: ${incident.cyberintalertrefids}
    status: closed
    closure_reason: Resolved
```

## Best Practices

1. **Use Bulk Operations Wisely**: Group related alerts that share the same closure reason for efficient bulk closure.

2. **Provide Descriptions**: When using "Other" as a closure reason, always provide a meaningful description for audit purposes.

3. **Enable Mirroring**: For seamless workflow, enable bi-directional mirroring to keep XSOAR and Check Point Exposure Management in sync.

4. **Verify Before Closing**: Use `cyberint-alerts-fetch` to review alerts before bulk closure to ensure you're closing the correct incidents.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "You must supply a closure reason" error | Ensure `closure_reason` parameter is provided when setting status to `closed` |
| "You must supply a closure_reason_description" error | When using `Other` as closure reason, provide the `closure_reason_description` parameter |
| Alerts not syncing to Check Point Exposure Management | Verify that "Close Mirrored Check Point Exposure Management Alert" is enabled in the integration configuration |
| Changes not reflected in XSOAR | Verify that "Close Mirrored XSOAR Incident" is enabled and mirroring direction includes "Incoming" |

## Release Information

This feature was introduced in **Check Point Exposure Management Pack version 1.3.0**.
