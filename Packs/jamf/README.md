# JAMF
This pack enables you to interact with Jamf Pro which is the product that allows you to manage Apple devices (Mac, iPhone, Apple TV, iPad). It can be used to control
  various configurations via different policies, install and uninstall applications, lock
  devices, perform smart groups searches, and more.

If your computer is lost or stolen, you can remotely lock the computer or erase its contents to ensure the security of sensitive information.

If an application on your Apple device has a security issue, you can check for this app on all your Apple devices and then decide what action to take.

<br/>This pack includes XSIAM content.

### Collect Events from Jamf pro (XSIAM)

We are currently support the retrieval of webhooks events from jamf by using an HTTP Log Collector.
In order to configure the webhooks on jamf's side, please read [this documentation](https://docs.jamf.com/10.31.0/jamf-pro/administrator-guide/Webhooks.html). 

* Pay attention: Timestamp parsing is available for the the Epoch (UNIX) **eventTimestamp** object, under the **webhook** field.

### HTTP Log Collector
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/external-data-ingestion/additional-log-ingestion-methods-for-cortex-xdr/set-up-an-http-log-collector-to-receive-logs).\
You can configure the specific vendor and product for this instance.

**On XSIAM:**
1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source** -> **Custom - HTTP based Collector** -> Click on **Connect Another Instance**, set the Name and Compression as you choose and then please set:
   - Log Format as `JSON`
   - Vendor as `jamf`
   - Product as `pro`
2. Creating a new HTTP Log Collector will allow you to generate a unique token, please save it since it will be used later.
3. Click the 3 dots sign next to the newly created instance and copy the API Url, it will also be used later.
   
**On jamf pro:**\
While creating (or editing) a webhook, please set:
1. **Webhook URL** as the API Url which was copied in section 3 (on the XSIAM side).
2. Under **Authentication Type** choose **Header Authentication** and paste this in the textbox:
`{"Authorization": "UNIQUE_TOKEN_GOES_HERE"}`\
(Please replace the **UNIQUE_TOKEN_GOES_HERE** text with the newly created token mentioned in section 2 on the XSIAM side)
3. **Content Type** as `JSON`
4. **Webhook Event** as the webhook event you wish to collect.



## What does this pack do?
- Run remote commands on a computer or mobile device, such as erase, lock/lost_mode.
- Get various details about devices and users, such as names, IDs, services, applications, hardware, etc.
- Get a list of computers details based on applications.
