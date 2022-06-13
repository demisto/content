Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

Before you begin, in the [Dropbox app console](https://www.dropbox.com/developers/apps) Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

## Create an app in the Dropbox app console

1. Go to [Dropbox app console](https://www.dropbox.com/developers/apps) and click **Create app**.  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.03.00.png)

2. Give full dropbox access (not just a single folder).  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.03.22.png)

3. From the **Permissions** tab, in the **Sessions** section, select **events.read**.  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.04.11.png)

4. In the **Settings** tab, note the **App key** and the **App secret**.  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.04.34.png)

## Configuration Parameters

**App key and App secret**    
The App key and App secret.

**Vendor name**  
The vendor corresponding to the integration that created the events. This affects the name of the dataset where these events will be inserted `{vendor_product_raw}`.

**Product name**  
The product corresponding to the integration that created the events. This affects the name of the dataset where the events will be inserted `{vendor_product_raw}`.

## Test
Run the ***!dropbox-auth-start*** command from the WarRoom and follow the instructions.