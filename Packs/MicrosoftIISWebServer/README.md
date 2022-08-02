XDRC (XDR Collector)
You will need to use the information described here.
You can configure the vendor and product by replacing [vendor]_[product]raw with [vendor][product]_raw <- Change this When configuring an XDR collector profile, you should use a yml that will be used, among other things, to configure the vendor and product. This example demonstrates how to set it, specifically for the Microsoft IIS webserver product:

filebeat.modules:

- module: iis
  access:
    enabled: true
    var.paths: ["C:/inetpub/logs/LogFiles/*/*.log"]
  error:
    enabled: true
    var.paths: ["C:/Windows/System32/LogFiles/HTTPERR/*.log"]
