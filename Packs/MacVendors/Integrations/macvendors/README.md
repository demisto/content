Query MAC Vendors for vendor names when providing a MAC address.
MAC Vendors maintains a list of vendors provided directly from the IEEE Standards Association and is updated multiple times each day. The IEEE is the registration authority and provides data on over 16,500 registered vendors.

This integration was integrated and tested with the latest verison of MAC Vendors API as of 31st January 2022.

## Configure MAC Vendors in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | No API key is required for up to 1,000 requests per day at 1 request per second. For higher limits, please use an API key. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### macvendors-lookup-mac
***
Resolves a MAC address to a vendor name.


#### Base Command

`macvendors-lookup-mac`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mac | MAC address to lookup. Can be any of the formats;  00-11-22-33-44-55, 00:11:22:33:44:55, 00.11.22.33.44.55, 001122334455, 0011.2233.4455. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MACVendors.mac | string | MAC Address | 
| MACVendors.vendor | string | Vendor Name | 