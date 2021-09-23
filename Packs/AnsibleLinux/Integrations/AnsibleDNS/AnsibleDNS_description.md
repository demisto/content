# Ansible DNS

This integration enables the management of DNS Records directly from XSOAR using Dynamic DNS Updates from the NSUpdate Ansible Module.

# Requirements
The DNS master server being managed must be configured to accept Dynamic DNS updates using Transaction signatures as described in RFC2845.

## Network Requirements
By default, TCP port 53 will be used to initiate a connection to the server. However UDP and other ports are supported.

The connection will be initiated from the XSOAR engine/server specified in the instance settings.

## Credentials

A TSIG shared secret must be provided during instance configuration. Supported key algorithms are:

* HMAC-MD5.SIG-ALG.REG.INT
* hmac-md5
* hmac-sha1
* hmac-sha224
* hmac-sha256
* hmac-sha384
* hmac-sha512

## Server Configuration Instructions
The following articles describe how to configure TSIG on popular DNS servers/services:
* [BIND9](https://bind9.readthedocs.io/en/v9_16_5/advanced.html#tsig)
* [PowerDNS](https://doc.powerdns.com/authoritative/tsig.html)
* [InfoBlox](https://docs.infoblox.com/display/BloxOneDDI/Configuring+TSIG+Keys)

Note: Microsoft Window DNS Server utilizes the GSS-TSIG protocol which is unsupported by this integration.

## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!dns-nsupdate`command providing an non-existent record to remove using the command argument `state=absent`. As an example `!dns-nsupdate state="absent" record="something-none-existent.example.com."`. This command will connect to the dns server with the configured credentials in the integration, and if successful output that it ran successfully, but changed nothing.
