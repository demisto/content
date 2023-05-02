## Netmiko SSH module integration

This integration provides ssh-based access to network devices, servers, and other appliances that support this method of configuration. For a complete list of supported platforms, please visit the below URL:

[Netmiko Platforms.md on Github](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md)

## Configuration Parameters

<ul>

<li><i><b>Name</b></i>
- Integration instance name
<li><i><b>Platform</b>  </i>
- The Netmiko-specific platform name</li>
<li><i><b>Hostname</b></i>
- The IP address, Hostname, or FQDN to connect to over SSH</li>
<li><i><b>Port</b></i>
- The port to use for the SSH connection</li>
<li><i><b>Credentials</b></i>
- The credentials should be the same as the Tanium client.</li>
</ul>

<p>

<b>NOTE</b>: Platform names are taken from the supported
[SSH](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md#supported-ssh-device_type-values) or [Telnet](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md#supported-telnet-device_type-values) device type lists on GitHub.
</div>
</p>
  
### SSH Keys

To provide SSH Keys for a login, and for security purposes, this can only be done by using the **credentials** store under *Integrations->Credentials* and placing the private key in the *Certificate* section. This requires from the **-----BEGIN RSA PRIVATE KEY-----** (or equivalent key type) to the **-----END RSA PRIVATE KEY-----** (or equivalent key type).

When you **DO** provide SSH keys in the credentials, the password becomes the password for the SSH key.