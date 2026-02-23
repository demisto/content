Configure an instance of this integration to manage High Availability (HA) on Palo Alto Networks Firewalls and Panorama.

## Configuration

- **Hostname or IP Address**: The management IP or hostname of the PAN-OS device.
- **API Key**: An API key generated on the PAN-OS device. See [PAN-OS API Key Generation](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key) for instructions.
- **Device Type**: Select `Firewall` or `Panorama`.
- **VSYS**: Optional. Specify a virtual system (e.g., `vsys1`) if applicable.
- **Trust any certificate**: Enable if the device uses a self-signed certificate.

## Permissions

- **Read-only operations** (get-state, get-config, list-interfaces): Superuser (read-only) role
- **Configuration changes** (configure, enable, disable, sync): Superuser role

## Troubleshooting

- If `test-module` fails, verify the hostname, API key, and network connectivity.
- For interface validation errors, use `panos-ha-list-interfaces` to see available interfaces.
- HA operational commands (suspend, functional, sync) bypass vsys context.
