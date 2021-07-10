# Ansible Microsoft Windows

This integration enables the management of Microsoft Windows hosts directly from XSOAR using WinRM.

WinRM is enabled by default on all Windows Server operating systems since Windows Server 2012 and above, but disabled on all client operating systems like Windows 10, Windows 8 and Windows 7. WinRM can be enabled on Windows client OSes [using Group Policy](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management#configuring-winrm-with-group-policy).

This integration uses NTLM for authentication. This ensures that actual credentials are never sent over the network, instead relying on hashing methods. By default, the initial authentication phase is performed unencrypted over HTTP, after which all communication is encrypted using a symmetric 256-bit key. If it is desired to use HTTPS from the onset, [additional configuration on the Windows host is required](https://docs.microsoft.com/en-US/troubleshoot/windows-client/system-management-components/configure-winrm-for-https). After WinRM is configured for HTTPS, update the port setting on the integration. Any port other than the default 5985 will use HTTPS communication.

## Network Requirements

By default, TCP port 5985 will be used. If WinRM is configured for HTTPS, update the port setting on the integration.

Please also note that the default Windows Firewall Policy (Windows Remote Management (HTTP-In)) allows WinRM connections only from the private networks.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.

## Credentials

A Windows Domain Account is recommended; however local accounts are also supported.
The username syntax can be in Pre-Windows2000 style (domain.local/account) or in newer UPN format (account@domain.local)

## Permissions

While Administrative privileges are not strictly required, WinRM is configured by default to only allow connections from accounts in the local Administrators group.

Non-administrative accounts can be used with WinRM, however most typical server administration tasks require some level of administrative access, so the utility is usually limited.

## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!win-gather-facts`command providing an example `host` as the command argument. This command will connect to the specified host with the configured credentials in the integration, and if successful output general information about the host.