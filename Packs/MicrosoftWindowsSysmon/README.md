# Microsoft Windows Sysmon
This pack includes Cortex XSIAM content.
<~XSIAM>
 
### XDRC (XDR Collector)
 
To create or configure the Winlogbeat collector, use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).
 
You can configure the vendor and product by replacing [vendor]\_[product]\_raw with *microsoft_sysmon_raw*.
 
When configuring the instance, you should use a YML file that configures the vendor and product, as shown in the below configuration for the Windows Sysmon service.
 
Copy and paste the following in the *Winlogbeat Configuration File* section (inside the relevant profile under the *XDR Collectors Profiles*).
 
 
#### Winlogbeat Configuration File
 
```
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    processors:
    - add_fields:
        fields:
          vendor: microsoft
          product: sysmon
```
  
</~XSIAM>