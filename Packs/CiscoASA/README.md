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
Supported date format is RFC 5424, an example: "2023-04-09T16:30:00Z" "2023-04-09T16:30:00+07:00"

1. Access the Cisco ADSM.
2. Go to Configuration -> logging -> Syslog setup.
3. On Timestamp Format drildown click on the option "RFC 5424(yyyy-MM-ddTHH:mm:ssZ)".
4. Click on the Apply button.

Another supported date format is "Jul 08 09:14:35 UTC"

**Note** : If a different timestamp format is used, time extraction and mapping will not be supported.

![Server Screenshot](https://raw.githubusercontent.com/demisto/content/8a2f8a41f73e9d9f4e20693e3b99dc6b75336321/Packs/CiscoASA/docs_imgs/CiscoASDM_timestamp.png)


### The supported events on Modeling rules:
The following events are supported by modeling rules (170 events):
- 103001,104001,104002,104004,105001,105002,105003,105004,105005,105006,105007,105008,105009,105043,106001,106006,106007,106014,106015,106016,106017,106020,106021,106023,106023,106100,106102,108004,108005,109201,109207,109210,110002,110003,111001,111004,111005,111007,111008,111009,111010,113003,113004,113005,113008,113009,113010,113011,113012,113013,113014,113015,113019,113022,113023,113039,120003,120005,120006,120007
- 209005,209006,201010
- 302004,302012,302013,302014,302015,302016,302020,302021,303002,305011,305011,305012,313001,313004,313005,313008,313009,315011
- 402117,405104,410001,418001,419002,434002,434004,434004
- 500003,500004,507003
- 602101,605004,605005,606001,606002,606003,606004,609002,611101,611102,611103
- 709003,709004,709006,709008,710003,710005,713048,713081,713105,713255,716001,716002,716038,716039,716058,716059,717056,720010,720024,720025,720027,720028,720029,720032,720037,720039,720040,720046,720062,720063,721002,721003,722003,722010,722011,722012,722022,722023,722028,722032,722033,722034,722035,722036,722037,722041,722051,722055,725001,725002,725003,725006,725007,725016,733100,737005,737013,737015,737017,737034,737036,737037,769005,769007