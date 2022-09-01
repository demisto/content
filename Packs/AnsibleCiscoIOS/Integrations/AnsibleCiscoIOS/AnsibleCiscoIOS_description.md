# Ansible Cisco IOS
Manage Cisco IOS Switches and Routers directly from XSOAR using SSH.

## Credentials

This integration supports a number of methods of authenticating with the network device:

1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

In addition to the SSH credential, a `enable` password must be also provided.

## Permissions

The user account used for initial SSH login access can be level 1, however the enable password must also be provided.


## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!IOS-facts` command providing an example `host` as the command argument. This command will connect to the specified network device with the configured credentials in the integration, and if successful output general information about the device.