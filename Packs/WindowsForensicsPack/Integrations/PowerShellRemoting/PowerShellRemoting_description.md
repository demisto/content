Installation and configuration for Windows Remote Management to support PowerShell session is a prerequisite step to support this integration
- PowerShell Remote sessions are created over port 5985 (Microsoft Web service management/WinRm). This port needs to be opened from XSOAR to the hosts on the local and Network firewalls.
- Authentication is NTLM based.
- The integration requires a valid user with Administrator permission set on the remote hosts.

For more information, please refer to the following Microsft Article: https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
