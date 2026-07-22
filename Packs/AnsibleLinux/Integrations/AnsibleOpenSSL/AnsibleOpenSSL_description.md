# Ansible OpenSSL

This integration enables the management of certificates on Linux hosts directly from XSOAR using SSH and Python.

# Requirements
The Linux host(s) being managed requires Python >= 2.6. Different commands will use different underlying Ansible modules, and may have their own unique package requirements. Refer to the individual command documentation for further information.

## Network Requirements
By default, TCP port 22 will be used to initiate a SSH connection to the Linux host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.

## Credentials

This integration supports a number of methods of authenticating with the Linux Host:

1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

## Permissions

Whilst un-privileged Linux user privileges can be used, a SuperUser account is recommended as most commands will require elevated permissions to execute.

## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!openssl-certificate-info` command providing an example `host` and `path` to a certificate as the command argument. This command will connect to the specified host with the configured credentials in the integration, and if successful output information about the certificate at the path.
