# PAN-OS High Availability (HA)

This integration manages High Availability features on Palo Alto Networks Firewalls and Panorama appliances from Cortex XSOAR.

---

## Configuration

### Prerequisites

- A Palo Alto Networks Firewall or Panorama appliance with management access.
- An API key with sufficient privileges (Superuser role recommended for configuration changes, Superuser read-only for monitoring).
- Network connectivity from the Cortex XSOAR engine to the device management interface.

### Generating an API Key

Follow the [PAN-OS API Key Generation guide](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key) to create an API key for the integration.

### Parameters

- **Hostname or IP Address**: The management IP or hostname of the PAN-OS device.
- **API Key**: The API key for authentication.
- **Device Type**: Select `Firewall` or `Panorama`. Most commands are firewall-specific.
- **VSYS** (Optional): Specify a virtual system (e.g., `vsys1`). HA operational commands are global and ignore this setting.
- **Trust any certificate**: Enable for self-signed certificates. Not recommended for production.

---

## Supported Modes

- **Active/Passive**: One firewall actively handles traffic while the other is on standby.
- **Panorama HA**: Manage HA state on Panorama management appliances.

---

## Troubleshooting

### Interface Validation Failed

If `panos-ha-configure` fails with an interface validation error, run `!panos-ha-list-interfaces` to see all available interfaces and verify the interface names match exactly (case-sensitive).

### HA State Not Synchronizing

Check that HA1 and HA2 links are up, verify network connectivity between peers, and review the configuration using `!panos-ha-get-config`.

### Cannot Commit HA Configuration

If the device is managed by Panorama, configure HA via Panorama templates. Check for existing configuration locks using the PAN-OS CLI.
