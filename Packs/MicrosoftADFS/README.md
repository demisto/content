# Microsoft AD FS
​
This pack includes XSIAM content.

​
**Notes:** 
- The logs will be stored in the dataset called *microsoft_adfs_raw*.
- The default content provided in this pack (including Winlogbeat templates) should be used as is.  We cannot support any changes made to this content.

## Configuration on Server Side
#### Validate that AD FS server role is enabled
1. In the **Server Manager**, click **Manage** > **Add Roles and Features**.
2. Click **Server Roles** in the left menu.
3. Validate that **Active Directory Federation Services** is selected and installed.

   ![Server Screenshot](https://raw.githubusercontent.com/demisto/content/cf0db92559e011d96f94ef21912f316f4b250b36/Packs/MicrosoftADFS/doc_imgs/ADFSEnable.png)
4. To enable logging of AD FS, run the following commands in PowerShell with administrative privileges:
   - ***Set-AdfsProperties -LogLevel Basic*** - This command will enable basic logging of AD FS.
   - ***Get-AdfsProperties*** - This command will validate that the *AuditLevel* is set to *Basic*.

    ![Server Screenshot](https://raw.githubusercontent.com/demisto/content/cf0db92559e011d96f94ef21912f316f4b250b36/Packs/MicrosoftADFS/doc_imgs/ADFSCommands.png)
5. Additional validation of the logging can be located at the Windows *Event Viewer*:

   1. Run ***eventvwr.msc*** in the search bar.
   2.  In the left directory tree, select **Applications and Services Logs** and validate that *AD FS* exists and *Admin* logs are located in the folder

    ![Server Screenshot](https://raw.githubusercontent.com/demisto/content/cf0db92559e011d96f94ef21912f316f4b250b36/Packs/MicrosoftADFS/doc_imgs/ADFSEvent-Viewer.png)

## Collect Events from Vendor
Use the following option to collect events from the vendor:
​
- [Broker VM - Windows Event Collector (Recommended)](#broker-vm)
- [XDRC (XDR Collector)](#xdrc-xdr-collector)
​
​
### Broker VM (Windows Event Collector)
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).


To connect and use Windows Event Collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Activate-the-Windows-Event-Collector).

When configuring the Windows Event Collector (WEC), use the following settings in the **Configurations** > **Broker VMs** > **WEC** > **Collection Configuration** section:
- **Source**: "FederationServices Deployment"
- **Min. Event Level**: "Verbose"
- **Event IDs Group**: "All"

![Server Screenshot](https://raw.githubusercontent.com/demisto/content/e02f705471d65a49f8c50115bf2cc828e47a5390/Packs/MicrosoftADFS/doc_imgs/ADFSWEC.png)

### XDRC (XDR Collector)
​
To configure the XDR collector, use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

The AD FS XDR collector template can be found in **Settings** -> **Configurations** -> **XDR Collectors** -> **+Add Profile** -> **Windows** -> **Winlogbeat** -> **Next** -> **Winlogbeat Configuration File**.

**Note:** The AD FS XDR Collector currently supports the following event IDs:
```html
510, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207
```
