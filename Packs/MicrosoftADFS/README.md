# Microsoft AD FS
​
This pack includes XSIAM content.

​
Note: The logs will be stored in the dataset named *microsoft_adfs_raw*.

## Configuration on Server Side
​
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
​
​
### Broker VM (Windows Event Collector)
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).


To connect and use Windows Event Collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Activate-the-Windows-Event-Collector).

When configuring the Windows Event Collector (WEC), please use the following settings in the **Configurations** -> **Broker VMs** -> **WEC** -> **Collection Configuration** section:
- **Source**: "FederationServices Deployment"
- **Min. Event Level**: "Verbose"
- **Event IDs Group**: "All"

![Server Screenshot](https://raw.githubusercontent.com/demisto/content/7fc2db5236a9f40b3b98f061cded684525452578/Packs/MicrosoftADFS/doc_imgs/ADFSWEC.png)