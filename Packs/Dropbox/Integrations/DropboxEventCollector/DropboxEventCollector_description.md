Use the Dropbox Event Collector integration to get Audit and Auth logs from dropbox using REST APIs.

Before you start, you need to create an app [Dropbox app console](https://www.dropbox.com/developers/apps).

After creating the app you need to give full dropbox access (not just a single folder).

Then in the `permissions` tab choose `events.read`.

Then go back to the `settings` tab You're supposed to see an `App key` and `App secret`.

## Configuration Parameters

**App key and App secret**    
The App key and App secret.

**Vendor name**  
The vendor corresponding to the integration that created the events. This affects the name of the dataset where these events will be inserted {vendor_product_raw}.

**Product name**  
The product corresponding to the integration that created the events. This affects the name of the dataset where the events will be inserted {vendor_product_raw}.
