# Ansible ACME
This integration lets you manage certificate generation on Linux hosts with a CA supporting the ACME protocol, such as Let’s Encrypt.

## Requirements
This integration requires a linux host to be specified from which the connections to the ACME service will be performed, and where the certificate/key files will be stored.

The Linux host used for ACME interaction requires:
* python >= 2.6
* either openssl or cryptography >= 1.5

## Network Requirements
By default, TCP port 22 will be used to initiate a SSH connection to the Linux host.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.
## Credentials
This integration supports a number of methods of authenticating with the Linux Host:
1. Username & Password entered into the integration
2. Username & Password credential from the XSOAR credential manager
3. Username and SSH Key from the XSOAR credential manager

## Permissions
Normal Linux user privileges are required, a SuperUser account is not required.
ACME Account management operations require access to the ACME account RSA or Elliptic Curve key file on the Linux host used for management to authenticate with the ACME service.

## Privilege Escalation
Ansible can use existing privilege escalation systems to allow a user to execute tasks as another. Different from the user that logged into the machine (remote user). This is done using existing privilege escalation tools, which you probably already use or have configured, like sudo, su, or doas. Use the Integration parameters `Escalate Privileges`, `Privilege Escalation Method`, `Privilege Escalation User`, `Privileges Escalation Password` to configure this.

## Testing
This integration does not support testing from the integration management screen. Instead it is recommended to use the `!acme-inspect`command providing an example `host` as the command argument to connect to a ACME provider like Let's Encrypt. Eg. `!acme-inspect host="123.123.123.123" acme_directory="https://acme-staging-v02.api.letsencrypt.org/directory" acme_version="2" method="directory-only" ` This command will connect to the specified host with the configured credentials in the integration, and if successful output information about the Let's Encrypt ACME directory.

