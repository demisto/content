<~XSIAM>

In addition to the [HasiCorp Vault Integration](https://xsoar.pan.dev/docs/reference/integrations/hashi-corp-vault), this pack includes *Cortex Data Modeling (XDM) Rules* and *Parsing Rules* for ingesting and normalizing HashiCorp Vault [audit logs](https://support.hashicorp.com/hc/en-us/articles/360001722947-Audit-Device-Notes).

## Configuration

### Configuration on HashiCorp Vault 
 
Run the [audit enable](https://developer.hashicorp.com/vault/docs/commands/audit/enable#audit-enable) command from the Vault server CLI for enabling a [File audit device](https://developer.hashicorp.com/vault/docs/audit/file) to write audit logs to a file. For example: 
```
$ vault audit enable file file_path=/var/log/vault_audit.log
```
See also: 
- [Log file rotation](https://developer.hashicorp.com/vault/docs/audit/file#log-file-rotation).
- [Audit Devices](https://developer.hashicorp.com/vault/docs/audit).
- [Blocked audit devices](https://developer.hashicorp.com/vault/tutorials/monitoring/blocked-audit-devices).


### Configuration on Cortex XSIAM 
  
1. Install the HashiCorp Vault content pack from the Cortex XSIAM marketplace. 
2. Configure an [XDR Collector](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Manage-XDR-Collectors):
   1. Create an XDR Collector installation package as described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Create-an-XDR-Collector-installation-package).
   2. Install the XDR Collector created installation package on the HashiCorp Vault server: 
      - For a *Windows* server see [Install the XDR Collector installation package for Windows](https://docs-cortex.paloaltonetworks.com/r/KkeZwTYbDACMoWxJk0COqg/g4A0gTe8mLEmRNXk9hhsbw).
      - For a *Linux* server see [Install the XDR Collector installation package for Linux](https://docs-cortex.paloaltonetworks.com/r/KkeZwTYbDACMoWxJk0COqg/upKreUev0g1LzaCpxHJIRA). 
   3. Configure an [XDR Collector *Filebeat* profile](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/XDR-Collector-profiles):
      - For a *Windows* server see [Add an XDR Collector profile for Windows](https://docs-cortex.pawloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Add-an-XDR-Collector-profile-for-Windows).
      - For a *Linux* server see [Add an XDR Collector profile for Linux](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Add-an-XDR-Collector-profile-for-Linux).  
      - When configuring the Filebeat YAML Configuration File, use the HashiCorp Vault template as a reference, and customize the *[paths](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html#filestream-input-paths)* parameter in accordance to the path enabled for the [File audit device](https://developer.hashicorp.com/vault/docs/audit/file) on the HashiCorp Vault server: 
           ```
            filebeat.inputs:
            - type: filestream
              enabled: true
              id: hashicorp-vault
              paths:       
                - /var/log/vault_audit.log    # customize as needed 
              processors: 
                - add_fields:       
                    fields:             
                      vendor: hashicorp
                      product: vault
           ```
   4. Apply the configured Filebeat profile to the target HashiCorp Vault server by attaching it to a policy as described on [Apply profiles to collection machine policies](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Apply-profiles-to-collection-machine-policies).
3. Query the collected audit records under the *`hashicorp_vault_raw`* dataset. 
4. 
</~XSIAM>