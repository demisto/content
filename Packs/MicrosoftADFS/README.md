# Microsoft AD FS
​
This pack includes XSIAM content.

​
Note: The logs will be stored in the dataset named *microsoft_windows_raw*.

To view logs only from the Windows AD FS, apply the following filter to the datamodel query: *| filter xdm.observer.type="AD FS Auditing"*
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
For the Filebeat collector, use the following option to collect events from the vendor:
​
- [XDRC (XDR Collector)](#xdrc-xdr-collector)
​
You will need to configure the vendor and product for this specific collector.
​
### XDRC (XDR Collector)
​
Use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

​
You can configure the vendor and product by replacing [vendor]\_[product]\_raw with *microsoft_windows_raw*.

​
When configuring the instance, use a yml file that configures the vendor and product, as shown in the configuration below for the Microsoft AD FS product.

​
Copy and paste the following content in the *Filebeat Configuration File* section (inside the relevant profile under the *XDR Collectors Profiles*).
​
#### Filebeat Configuration File
​
```
winlogbeat.event_logs:
  - name: Security
    event_id: 510, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207
    processors:
      - add_fields:
          fields:
            vendor: microsoft
            product: windows
```
​
**Note**: The above configuration uses the default location of the logs. 
