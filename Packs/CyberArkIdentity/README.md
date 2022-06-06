This Pack includes XSIAM content.

In order to use the collector to collect events from the vendor, you have 2 options to collect events. In either way, you will need to configure the vendor and product for this specific collector.
Broker VM - You will need to use the information described here.
You can configure the specific vendor and product for this instance, by going to the Settings -> Configuration -> Data Broker -> Broker VMs. Right-Click, and select Syslog Collector -> Configure.
When configuring the Syslog Collector, set vendor as vendor, product as product. <- Change this
XDRC (XDR Collector) - You will need to use the information described here.
You can configure the vendor and product by replacing [vendor]_[product]_raw with [vendor]_[product]_raw. <- Change this
When configuring the instance, you should use a yml that configures the vendor and product, like this example for the Microsoft NPS product:

filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - c:\windows\system32\logfiles\*.log
  processors:
    - add_fields:
        fields:
          vendor: msft
          product: nps
