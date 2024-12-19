This integration enables the management of DNS Records directly from XSOAR using Dynamic DNS Updates from the NSUpdate Ansible Module. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands. This integration functions without any agents or additional software installed on the DNS server.

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

## Configure Ansible DNS in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server Address | DNS Server Address | True |
| DNS Server Port | Use this port when connecting to the Server | True |
| TSIG Key Name | Use TSIG key name to authenticate against DNS \`server' | True |
| TSIG Key Secret | Use TSIG key secret, associated with \`key_name', to authenticate against \`server' | True |
| Key Algorithm | Specify key algorithm used by TSIG Key Secret | True |
| Protocol | Sets the transport protocol \(TCP or UDP\). TCP is the recommended and a more robust option. | True |

## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!dns-nsupdate`command providing an non-existent record to remove using the command argument `state=absent`. As an example `!dns-nsupdate state="absent" record="something-none-existent.example.com."`. This command will connect to the dns server with the configured credentials in the integration, and if successful output that it ran successfully, but changed nothing.

# Idempotence
The action commands in this integration are idempotent. This means that the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

# State Arguement
Some of the commands in this integration take a state argument. These define the desired end state of the object being managed. As a result these commands are able to perform multiple management operations depending on the desired state value. Common state values are:
| **State** | **Result** |
| --- | --- |
| present | Object should exist. If not present, the object will be created with the provided parameters. If present but not with correct parameters, it will be modified to met provided parameters. |
| running | Object should be running not stopped. |
| stopped | Object should be stopped not running. |
| restarted | Object will be restarted. |
| absent | Object should not exist. If it it exists it will be deleted. |

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dns-nsupdate
***
Manage DNS records.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/nsupdate_module.html


#### Base Command

`dns-nsupdate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Manage DNS record. Possible values are: present, absent. Default is present. | Optional | 
| zone | DNS record will be modified on this `zone`. When omitted DNS will be queried to attempt finding the correct zone. Starting with Ansible 2.7 this parameter is optional. | Optional | 
| record | Sets the DNS record to modify. When zone is omitted this has to be absolute (ending with a dot). | Required | 
| type | Sets the record type. Default is A. | Optional | 
| ttl | Sets the record TTL. Default is 3600. | Optional | 
| value | Sets the record value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNS.Nsupdate.changed | string | If module has modified record | 
| DNS.Nsupdate.record | string | DNS record | 
| DNS.Nsupdate.ttl | number | DNS record TTL | 
| DNS.Nsupdate.type | string | DNS record type | 
| DNS.Nsupdate.value | unknown | DNS record value\(s\) | 
| DNS.Nsupdate.zone | string | DNS record zone | 
| DNS.Nsupdate.dns_rc | number | dnspython return code | 
| DNS.Nsupdate.dns_rc_str | string | dnspython return code \(string representation\) | 


#### Command Example
```!dns-nsupdate record=test.example.com. value=123.123.123.123```

#### Context Example
```json
{
    "DNS": {
        "Nsupdate": [
            {
                "changed": true,
                "dns_rc": 0,
                "dns_rc_str": "NOERROR",
                "record": {
                    "record": "test.example.com.",
                    "ttl": 3600,
                    "type": "A",
                    "value": [
                        "123.123.123.123"
                    ],
                    "zone": "example.com."
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * dns_rc: 0
>  * dns_rc_str: NOERROR
>  * ## Record
>    * record: test.example.com.
>    * ttl: 3600
>    * type: A
>    * zone: example.com.
>    * ### Value
>      * 0: 123.123.123.123


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
