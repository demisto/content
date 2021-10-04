# Ansible Cisco NXOS
Manage Cisco NXOS Switches and Routers directly from XSOAR using SSH.

## Credentials

This integration supports a number of methods of authenticating with the network device:

1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

## Permissions

Whilst possible to use a `Network-Operator` (read-only) role, most commands require read and write access. It is recommended to use `Network-Admin` or appropriately scoped custom role.

## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!nxos-facts`command providing an example `host` as the command argument. This command will connect to the specified network device with the configured credentials in the integration, and if successful output general information about the device.
