Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

Before you start, you need to create an app [Dropbox app console](https://www.dropbox.com/developers/apps).  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.03.00.png)

After creating the app you need to give full dropbox access (not just a single folder).  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.03.22.png)

Then in the `permissions` tab choose `events.read`.  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.04.11.png)

Then go back to the `settings` tab You're supposed to see an `App key` and `App secret`.  
![Description Image](https://github.com/demisto/content/blob/39cc812da71224a9ea280eae46917fe8fa1d74c4/Packs/Dropbox/doc_files/Screen%20Shot%202022-06-13%20at%2010.04.34.png)

## Configuration Parameters

**App key and App secret**    
The App key and App secret.

**Vendor name**  
The vendor corresponding to the integration that created the events. This affects the name of the dataset where these events will be inserted {vendor_product_raw}.

**Product name**  
The product corresponding to the integration that created the events. This affects the name of the dataset where the events will be inserted {vendor_product_raw}.
