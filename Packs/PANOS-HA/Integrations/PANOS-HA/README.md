## PAN-OS High Availability (HA) Integration

Manage and orchestrate High Availability features on Palo Alto Networks Firewalls and Panorama. Supports automated failover workflows, HA configuration with interface validation, state management, and disaster recovery operations.

### Commands

| Command | Description |
|---------|-------------|
| panos-ha-get-state | Retrieves the current live HA state of a firewall pair |
| panos-ha-get-config | Retrieves the saved HA configuration from a firewall |
| panos-ha-configure | Configures HA on a firewall with interface validation |
| panos-ha-enable | Enables HA functionality on a firewall |
| panos-ha-disable | Disables HA functionality on a firewall |
| panos-ha-suspend-peer | Suspends a firewall, forcing failover to the peer |
| panos-ha-make-peer-functional | Brings a suspended firewall back to functional state |
| panos-ha-sync-config | Forces configuration synchronization to the passive peer |
| panos-ha-sync-state | Forces session state synchronization to the passive peer |
| panos-ha-list-interfaces | Lists all available interfaces on a firewall |
| panos-ha-validate-interfaces | Validates specified interfaces exist on a firewall |
| panos-panorama-ha-reconfigure | Issues a revert to running HA state command to Panorama |

### panos-ha-get-state

Retrieves the current live HA state of a firewall pair.

#### Base Command

`panos-ha-get-state`

#### Input

There are no input arguments for this command.

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| PANOS-HA.State.enabled | String | Whether HA is enabled |
| PANOS-HA.State.mode | String | The current HA mode |
| PANOS-HA.State.LocalState | String | The HA state of the local device |
| PANOS-HA.State.LocalSerial | String | The serial number of the local device |
| PANOS-HA.State.LocalPriority | String | The priority of the local device |
| PANOS-HA.State.PeerState | String | The HA state of the peer device |
| PANOS-HA.State.PeerSerial | String | The serial number of the peer device |
| PANOS-HA.State.PeerConnStatus | String | The connection status of the peer device |

### panos-ha-configure

Configures HA on a firewall with automatic interface validation.

#### Base Command

`panos-ha-configure`

#### Input

| Argument | Description | Required |
|----------|-------------|----------|
| peer_ip | Peer firewall's primary HA1 control link IP | Required |
| group_id | HA Group ID (1-255). Default: 1 | Optional |
| peer_ip_backup | Peer firewall's backup HA1 control link IP | Optional |
| passive_link_state | Link state of passive device (auto/shutdown). Default: auto | Optional |
| device_priority | Device priority for HA election (0-255). Default: 100 | Optional |
| heartbeat_backup | Enable backup heartbeat monitoring. Default: false | Optional |
| ha1_port | Primary control link interface (e.g., ha1-a) | Optional |
| ha1_ip_address | IP address for HA1 interface | Optional |
| ha1_netmask | Netmask for HA1 interface | Optional |
| ha1_gateway | Gateway for HA1 interface | Optional |
| ha1_backup_port | Backup control link interface | Optional |
| ha1_backup_ip_address | IP address for HA1 backup interface | Optional |
| ha1_backup_netmask | Netmask for HA1 backup interface | Optional |
| ha2_port | Data link interface for session sync | Optional |
| ha2_ip_address | IP address for HA2 interface | Optional |
| ha2_netmask | Netmask for HA2 interface | Optional |
| ha2_backup_port | Backup data link interface | Optional |
| ha2_backup_ip_address | IP address for HA2 backup interface | Optional |
| ha2_backup_netmask | Netmask for HA2 backup interface | Optional |
| state_sync | Enable session synchronization. Default: false | Optional |
| ha2_keepalive | Enable HA2 keep-alive monitoring. Default: false | Optional |
| ha2_keepalive_threshold | Keep-alive threshold in ms (5000-60000). Default: 10000 | Optional |
| ha2_keepalive_action | Action on keep-alive failure. Default: log-only | Optional |
| commit | Commit immediately. Default: false | Optional |

### panos-ha-list-interfaces

Lists all available network interfaces on a firewall.

#### Base Command

`panos-ha-list-interfaces`

#### Input

There are no input arguments for this command.

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| PANOS-HA.AvailableInterfaces.Hostname | String | The hostname of the firewall |
| PANOS-HA.AvailableInterfaces.InterfaceCount | Number | Total number of interfaces found |
| PANOS-HA.AvailableInterfaces.Interfaces | Unknown | List of all available interface names |

### panos-ha-validate-interfaces

Validates that specified interfaces exist on a firewall.

#### Base Command

`panos-ha-validate-interfaces`

#### Input

| Argument | Description | Required |
|----------|-------------|----------|
| interfaces | Comma-separated list of interface names | Required |

#### Context Output

| Path | Type | Description |
|------|------|-------------|
| PANOS-HA.InterfaceValidation.Hostname | String | The hostname of the firewall |
| PANOS-HA.InterfaceValidation.AllValid | Boolean | Whether all interfaces were found |
| PANOS-HA.InterfaceValidation.ValidatedInterfaces | Unknown | List of validated interfaces |
| PANOS-HA.InterfaceValidation.MissingInterfaces | Unknown | List of missing interfaces |
