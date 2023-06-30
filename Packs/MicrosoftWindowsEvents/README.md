# Microsoft Windows Logs

This pack includes Cortex XSIAM content.

Notes: 
 - The logs will be stored in the dataset named *microsoft_windows_raw*.
 - The pack currently supports the following data source: "Security".

To view logs only from the Windows Event log, apply the following filter to the datamodel query: *| filter xdm.observer.type="Microsoft-Windows-Security-\*"*


## Collect Events from Vendor

In order to use the collector, you can use one of the following options:
- [Broker VM - Windows Event Collector (Recommended)](#broker-vm)
- [XDRC (XDR Collector)](#xdrc-xdr-collector)
   


### Broker VM (Windows Event Collector)
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).


To connect and use Windows Event Collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Activate-the-Windows-Event-Collector).

### XDRC (XDR Collector)

To create or configure the Filebeat collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/XDR-Collectors).


As Cortex XSIAM provides a YAML template for Windows Security Event Logs, you can use the following steps to create a collection profile:

 1. In Cortex XDR, select **Settings** → **Configurations** → **XDR Collectors** → **Profiles** → **+Add Profile** → **Windows**.
 2. Select **Winlogbeat**, then click **Next**.
 3. Configure the General Information parameters:
   - Profile Name — Specify a unique Profile Name to identify the profile. The name can contain only letters, numbers, or spaces, and must be no more than 30 characters. The name you choose will be visible from the list of profiles when you configure a policy.

   - Add description here — (Optional) Provide additional context for the purpose or business reason that explains why you are creating the profile.

 4. Configure the settings for the profile selected in Step 2. To add the "Windows Security" template, select it and click **Add**.
