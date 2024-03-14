# Microsoft Windows Sysmon
 
<~XSIAM>
 
This pack includes Cortex XSIAM content.
 
## Configuration on Server Side
 
1. Open the RUN window and enter: dnsmgmt.msc
2. Right-click the name of the DNS server in the left-hand panel and select **Properties**.
3. In the Debug logging tab, add a check in **Log packets for debugging**
4. Ensure the following are checked: **Outgoing**, **Incoming**, **Queries/Transfers**, **Updates**.
5. For long (detailed) logs, select **Details** and enter the log file path: ```c:\Windows\System32\dns\DNS.log```
    
   *Note: Detailed captures will heavily bloat the logs.*
 
## Collect Events from Vendor
 
In order to use the collector, use the [XDRC (XDR Collector)](#xdrc-xdr-collector) option.
 
 
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