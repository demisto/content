# Microsoft NPS
This pack includes XSIAM content 
## Configuration on Server Side
1. Open the NPS console or the NPS Microsoft Management Console (MMC) snap-in.
2. In the console tree, click Accounting.
3. In the details pane, in Log File Properties, click Change Log File Properties. The Log File Properties dialog box opens.
4. In Log File Properties, on the Settings tab, in Log the following information, ensure that you choose to log enough information to achieve your accounting goals. For example, if your logs need to accomplish session correlation, select all checkboxes.
5. In the Logging failure action, select If logging fails, discard connection requests if you want NPS to stop processing Access-Request messages when log files are full or unavailable for some reason. If you want NPS to continue processing connection requests if logging fails, do not select this check box.
6. In the Log File Properties dialog box, click the Log File tab.
7. On the Log File tab, in Directory, type the location where you want to store NPS log files. The default location is the ``` systemroot\System32\LogFiles``` folder.
8. To distinguish between different system logs, create a folder named "NPS" in the mentioned directory `C:\Windows\system32\LogFiles\`. The final path should look as follows `C:\Windows\system32\LogFiles\NPS`
9. In Format, click DTS Compliant. If you prefer, you can instead select a legacy file format, such as ODBC (Legacy) or IAS (Legacy).
10. ODBC and IAS legacy file types contain a subset of the information that NPS sends to its SQL Server database. The DTS Compliant file type's XML format is identical to the XML format that NPS uses to import data into its SQL Server database. Therefore, the DTS Compliant file format provides a more efficient and complete transfer of data into the standard SQL Server database for NPS.
11. In Create a new log file, to configure NPS to start new log files at specified intervals, click the interval that you want to use:
 - For heavy transaction volume and logging activity, click Daily.
 - For lesser transaction volumes and logging activity, click Weekly or Monthly.
 - To store all transactions in one log file, click Never (unlimited file size).
 - To limit the size of each log file, click When the log file reaches this size, and then type a file size, after which a new log is created. The default size is 10 megabytes (MB).
 - If you want NPS to delete old log files to create disk space for new log files when the hard disk is near capacity, ensure that When the disk is full delete older log files are selected. This option is not available, however, if the value of Create a new log file is Never (unlimited file size). Also, if the oldest log file is the current log file, it is not deleted.
## Filebeat Collection
In order to use the collector, you need to use the following option to collect events from the vendor:
- [XDRC (XDR Collector)](#xdrc-xdr-collector)
You will need to configure the vendor and product for this specific collector.
### XDRC (XDR Collector)
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).
You can configure the vendor and product by replacing [vendor]\_[product]\_raw with msft_nps_raw
When configuring the instance, you should use a YAML that configures the vendor and product, just as seen in the below configuration for the Microsoft NPS product.
Copy and paste the below YAML in the "Filebeat Configuration File" section (inside the relevant profile under the "XDR Collectors Profiles").
#### Filebeat Configuration file:
```
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - c:\windows\system32\logfiles\NPS\*.log
  processors:
    - add_fields:
        fields:
          vendor: msft
          product: nps
```
**Please note**: The above configuration uses the default location of the logs. 
In case your linux saves the logs under a different location, you would need to change it in the yaml (under the `paths` field).