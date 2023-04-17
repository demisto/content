## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:
 - [Broker VM](#broker-vm)

In either option, you will need to configure the vendor and product for this specific collector.
### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as vendor<- Cisco
   - product as product<- ASA

### Configure Timestamp on Cisco ASA
The only supported date format is RFC 5424, an example: "2023-04-09T16:30:00Z"

1. Access the Cisco ADSM.
2. Go to Configuration -> logging -> Syslog setup.
3. On Timestamp Format drildown click on the option "RFC 5424(yyyy-MM-ddTHH:mm:ssZ)".
4. Click on the Apply button.

**Note** : If a different timestamp format is used, time extraction and mapping will not be supported.

![Server Screenshot](https://raw.githubusercontent.com/demisto/content/8a2f8a41f73e9d9f4e20693e3b99dc6b75336321/Packs/CiscoASA/docs_imgs/CiscoASDM_timestamp.png)