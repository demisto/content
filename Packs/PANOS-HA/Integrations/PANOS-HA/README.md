# PAN-OS High Availability (HA) Integration

## Overview

This integration provides comprehensive management and orchestration of High Availability (HA) features on Palo Alto Networks Firewalls and Panorama. It supports automated failover workflows, HA configuration with validation, state management, and disaster recovery operations.

## Key Features

- **Interface Validation**: Automatically validates that HA interfaces exist before configuration
- **HA State Management**: Monitor and control HA state (active/passive/suspended)
- **Configuration Synchronization**: Force config and session synchronization between HA peers
- **Automated Failover Support**: Commands designed for automated failover orchestration workflows
- **Panorama HA Support**: Manage HA on both firewalls and Panorama appliances

## Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| Hostname or IP Address | Yes | Management IP address or hostname of the PAN-OS device |
| API Key | Yes | API key with sufficient permissions (Superuser role recommended) |
| Device Type | Yes | Either `Firewall` or `Panorama` |
| VSYS | No | Virtual System name (e.g., vsys1) if using multi-vsys |
| Trust any certificate | No | Check for self-signed certificates (not recommended for production) |

## Commands

### Operational Commands (No Commit Required)

#### panos-ha-get-state

Retrieves the current live HA state of a firewall pair.

**Arguments:** None

**Example:**
```
!panos-ha-get-state
```

**Outputs:**
- PANOS-HA.State.enabled - Whether HA is enabled
- PANOS-HA.State.mode - HA mode (active-passive)
- PANOS-HA.State.local-info.state - Local device state (active/passive/suspended)
- PANOS-HA.State.peer-info.state - Peer device state
- PANOS-HA.State.peer-info.conn-status - Peer connection status

---

#### panos-ha-suspend-peer

Suspends the local firewall, forcing failover to the peer. Use for planned maintenance.

**Arguments:** None

**Example:**
```
!panos-ha-suspend-peer
```

---

#### panos-ha-make-peer-functional

Brings a suspended or passive firewall back to functional state.

**Arguments:** None

**Example:**
```
!panos-ha-make-peer-functional
```

---

#### panos-ha-sync-config

Manually forces configuration synchronization from active to passive peer.

**Arguments:** None

**Example:**
```
!panos-ha-sync-config
```

---

#### panos-ha-sync-state

Manually forces session state synchronization from active to passive peer.

**Arguments:** None

**Example:**
```
!panos-ha-sync-state
```

---

### Configuration Commands (Require Commit)

#### panos-ha-get-config

Retrieves the saved HA configuration from a firewall.

**Arguments:** None

**Example:**
```
!panos-ha-get-config
```

**Outputs:**
- PANOS-HA.Config.enabled - Whether HA is enabled
- PANOS-HA.Config.group-id - HA Group ID
- PANOS-HA.Config.peer.ip - Peer IP address
- PANOS-HA.Config.interfaces.ha1.port - HA1 interface port
- PANOS-HA.Config.interfaces.ha2.port - HA2 interface port

---

#### panos-ha-configure

Configures High Availability on a firewall with automatic interface validation.

**CRITICAL:** This command validates that all specified HA interfaces exist on the device before attempting configuration. If any interface is missing, the command will fail with a clear error message listing the missing interfaces.

**Arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| group_id | No | 1 | HA Group ID (1-255) |
| peer_ip | Yes | - | Peer firewall's primary HA1 control link IP |
| peer_ip_backup | No | - | Peer firewall's backup HA1 control link IP |
| passive_link_state | No | auto | Link state of passive device (auto/shutdown) |
| ha1_port | No | - | Primary control link interface (e.g., ha1-a, ethernet1/1) |
| ha1_ip_address | No | - | IP address for HA1 interface |
| ha1_netmask | No | - | Netmask for HA1 interface |
| ha1_backup_port | No | - | Backup control link interface |
| ha1_backup_ip_address | No | - | IP address for HA1 backup interface |
| ha1_backup_netmask | No | - | Netmask for HA1 backup interface |
| ha2_port | No | - | Data link interface for session sync |
| ha2_ip_address | No | - | IP address for HA2 interface |
| ha2_netmask | No | - | Netmask for HA2 interface |
| commit | No | false | Commit configuration immediately |
| force_sync | No | false | Force config sync after commit (requires commit=true) |

**Example:**
```
!panos-ha-configure peer_ip=192.168.26.102 ha1_port=ha1-a ha1_ip_address=192.168.26.101 ha1_netmask=255.255.255.252 ha2_port=ha2-a ha2_ip_address=192.168.27.101 ha2_netmask=255.255.255.252 commit=true
```

---

#### panos-ha-enable

Enables HA functionality on a firewall (requires existing HA configuration).

**Arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| commit | No | false | Commit configuration immediately |

**Example:**
```
!panos-ha-enable commit=true
```

---

#### panos-ha-disable

Disables HA functionality on a firewall (removes device from HA pair).

**Arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| commit | No | false | Commit configuration immediately |

**Example:**
```
!panos-ha-disable commit=true
```

---

### Interface Validation Commands (New in v1.0.0)

#### panos-ha-list-interfaces

Lists all available network interfaces on the firewall. Use this command before configuring HA to identify valid interface names.

**Arguments:** None

**Example:**
```
!panos-ha-list-interfaces
```

**Outputs:**
- PANOS-HA.AvailableInterfaces.Hostname - Firewall hostname
- PANOS-HA.AvailableInterfaces.InterfaceCount - Total number of interfaces
- PANOS-HA.AvailableInterfaces.Interfaces - List of interface names

---

#### panos-ha-validate-interfaces

Validates that specified interfaces exist on the firewall before attempting HA configuration. Critical for preventing configuration errors in automated workflows.

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| interfaces | Yes | Comma-separated list of interface names (e.g., "ha1-a,ha2-a,ethernet1/1") |

**Example:**
```
!panos-ha-validate-interfaces interfaces="ha1-a,ha2-a,ethernet1/1"
```

**Outputs:**
- PANOS-HA.InterfaceValidation.Hostname - Firewall hostname
- PANOS-HA.InterfaceValidation.AllValid - Boolean indicating if all interfaces exist
- PANOS-HA.InterfaceValidation.ValidatedInterfaces - List of validated interfaces
- PANOS-HA.InterfaceValidation.MissingInterfaces - List of missing interfaces

---

### Panorama Commands

#### panos-panorama-ha-reconfigure

Issues a "revert to running HA state" command to a Panorama peer. Used to re-integrate a peer after maintenance or failure.

**Arguments:** None

**Example:**
```
!panos-panorama-ha-reconfigure
```

---

## Automated Failover Workflow

This integration is designed to support automated failover orchestration workflows. Below is an example workflow for handling FW1/2 failure with FW3 as standby:

### Workflow Steps (XSOAR Playbook)

1. **Trigger**: QRadar SYSLOG event indicating FW1/2 unavailable
2. **Grace Period**: Wait 60 seconds to confirm failure
3. **Validation**: Check QRadar logs to confirm device still down
4. **Network Isolation**: SSH to Cisco switches and shutdown failed FW interfaces
5. **HA Reconfiguration**:
   - Use `panos-ha-disable` to remove failed FW from HA
   - Use `panos-ha-configure` on FW3 to join as passive peer
6. **Network Restoration (Phase 1)**:
   - Un-shutdown HA/cluster interfaces first
   - Use `panos-ha-get-state` to verify FW3 is passive/standby
7. **Network Restoration (Phase 2)**:
   - Un-shutdown data/Internet interfaces
8. **Notification**: Send email with failover status

### Pre-Failover Validation

Before executing automated failover:

```
# Step 1: List available interfaces on FW3
!panos-ha-list-interfaces using="FW3-instance"

# Step 2: Validate required HA interfaces exist
!panos-ha-validate-interfaces using="FW3-instance" interfaces="ha1-a,ha2-a"

# Step 3: Get current HA state
!panos-ha-get-state using="FW3-instance"
```

### Failover Execution

```
# Step 1: Disable HA on failed FW (if accessible)
!panos-ha-disable using="FW1-instance" commit=true

# Step 2: Configure FW3 as passive peer
!panos-ha-configure using="FW3-instance" peer_ip=<Active-FW-IP> ha1_port=ha1-a ha1_ip_address=<IP> ha1_netmask=<Mask> ha2_port=ha2-a ha2_ip_address=<IP> ha2_netmask=<Mask> commit=true

# Step 3: Verify HA state
!panos-ha-get-state using="FW3-instance"
```

## Best Practices

1. **Always validate interfaces** before configuring HA using `panos-ha-validate-interfaces`
2. **Test failover procedures** in a lab environment before implementing in production
3. **Use specific interface names** - consult `panos-ha-list-interfaces` output
4. **Monitor HA synchronization** status after configuration changes
5. **Document your HA topology** including interface mappings and switch connections
6. **Use API keys with minimal required privileges** for production deployments
7. **Implement proper error handling** in playbooks for each failover step

## Troubleshooting

### Interface Validation Failed

**Error:** "HA Configuration Failed: Interface Validation Error"

**Solution:**
1. Run `!panos-ha-list-interfaces` to see all available interfaces
2. Verify interface names match exactly (case-sensitive)
3. Check that interfaces are configured on the device (not just physically present)

### HA State Not Synchronizing

**Cause:** HA interfaces may be down or misconfigured

**Solution:**
1. Check interface status using PAN-OS CLI or GUI
2. Verify HA1 and HA2 links are up
3. Check for network connectivity between HA peers
4. Review HA configuration using `panos-ha-get-config`

### Cannot Commit HA Configuration

**Cause:** Template override or Panorama management

**Solution:**
1. If device is managed by Panorama, configure HA via Panorama templates
2. Use `force` parameter with caution if local override is required
3. Check for existing configuration locks

## Technical Notes

- Most HA operational commands bypass vsys context and operate at the device level
- Interface validation queries the device's network interface configuration
- HA interfaces (ha1-a, ha1-b, ha2-a, ha2-b, ha3) are predefined and always considered available
- Configuration changes require a commit to take effect
- Session synchronization requires HA2 interface configuration

## API Permissions Required

- **Read-only operations**: Superuser (read-only) role
- **Configuration changes**: Superuser role
- **Minimum API version**: PAN-OS 8.0+

## Dependencies

- Docker image: demisto/pan-os-python:1.0.0.4889421
- Python library: pan-os-python
- Supported PAN-OS versions: 8.0 and above
