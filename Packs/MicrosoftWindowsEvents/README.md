# Microsoft Windows Logs

This pack includes Cortex XSIAM content.

Notes: 
 - The logs will be stored in the dataset named *microsoft_windows_raw*.
 - The pack currently supports the following data source: **Security (Provider "Microsoft-Windows-Security-*)**, **Firewall**, **System**, **Application** and **Powershell**.

To view logs only from the Windows Event log, apply any of the following filters to your datamodel query:
* `| filter xdm.observer.type="Microsoft-Windows-Security-*"`
* `| filter xdm.observer.type="Microsoft-Windows-TaskScheduler"`
* `| filter xdm.observer.type="Microsoft-Windows-Windows Firewall With Advanced Security"`
* `| filter xdm.event.type="System"`
* `| filter xdm.event.type="Application"`

**Pay Attention**: 
This pack excludes several events for the Sysmon, DNS, ADFS and AMSI Windows services according to the *provider_name* field:
* AD FS Auditing
* Microsoft-Windows-Sysmon
* Microsoft-Windows-DNSServer
* Microsoft-Windows-DNS-Server-Service
* Microsoft-Antimalware-Scan-Interface

Should you wish to collect those logs as well, the installation of the following packs is required:
* Microsoft DNS
* Microsoft Windows AMSI
* Microsoft Windows Sysmon
* Microsoft AD FS Collection

## Collect Events from Vendor

In order to use the collector, you can use one of the following options:       
    - [Broker VM (Windows Event Collector)](#broker-vm-windows-event-collector)   
    - [XDRC (XDR Collector)](#xdrc-xdr-collector)
   


### Broker VM (Windows Event Collector)
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).


To connect and use Windows Event Collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Activate-the-Windows-Event-Collector).


### XDRC (XDR Collector)

To create or configure the Filebeat collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/XDR-Collectors).


As Cortex XSIAM provides a YAML template for Windows Security Event Logs, you can use the following steps to create a collection profile:

 1. In Cortex XSIAM, select **Settings** → **Configurations** → **XDR Collectors** → **Profiles** → **+Add Profile** → **Windows**.
 2. Select **Winlogbeat**, then click **Next**.
 3. Configure the General Information parameters:
   - Profile Name — Specify a unique Profile Name to identify the profile. The name can contain only letters, numbers, or spaces, and must be no more than 30 characters. The name you choose will be visible from the list of profiles when you configure a policy.

   - Add description here — (Optional) Provide additional context for the purpose or business reason that explains why you are creating the profile.

4. You can use one of the following options to collect event logs using the XDR Collectors:
### Option A
1. If you wish to collect only **Security** logs please select the "Windows Security" template located in the **Select Template** drop-down. 
2. After selecting the template press **Add**.

### Option B
#### Creating a customized YAML template
Tailor the XDR collector to your specific needs by creating a custom template that includes all the event types you want to collect.
As an example, In the **Winlogbeat Configuration File** section, add the following YAML template to collect **Security**, **System**, **Application**, and **Microsoft Defender** events:
 ```bash
winlogbeat.event_logs:
- name: Security
    ignore_older: 1h
    id: security-logs
  - name: System
    ignore_older: 1h
    id: system-logs
  - name: Application
    ignore_older: 1h
    id: application-logs
  - name: Microsoft-Windows-Windows Defender
    ignore_older: 1h
    id: defender-logs      
```

**Note:** Control what event types will be collected by adding or removing the "name", "ignore_older", and "id" lines of the specific event type.

5. Press **Create** to save the new template.
