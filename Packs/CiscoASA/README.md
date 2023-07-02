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


### The supported events on Modeling rules:
The following events are supported by modeling rules (70 events):
- 106001,106006,106007,106014,106015,106017,106020,106021,106100,108004,108005,109201,109207,109210, 110002,110003,111001,111004,111005,111007,111008,111009,111010,113003,113004,113005,113008,113009,113011,113012,113013,113014,113015,113019,113022,113023
- 201010,209006
- 302012,302013,302014,302015,302016,302020,302021,303002,305012,313001,313004,313005,313008,313009,315011
- 405104,410001,419002
- 500004,507003
- 602101,605005,606001,606002,606003,606004,609002,611101,611102,611103
- 710003,710005,713048,713081,713105,713255,717056