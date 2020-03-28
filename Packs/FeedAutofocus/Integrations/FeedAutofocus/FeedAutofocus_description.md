## AutoFocus Feed
Gets Daily Threat Feed and Custom feeds from AutoFocus.

For more information see the [AutoFocus documentation](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-feeds.html).

#### Custom Feed info:
To connect a custom AutoFocus feed you need to provide the Custom Feed URL.

The Custom Feed URL should be in this form:
https://autofocus.paloaltonetworks.com/IOCFeed/{Output_Feed_ID}/{Output_Feed_Name}

#### Sample Feed info:
To connect to a sample AutoFocus feed you need to provide the following parameters:
* Scope Type - Either **public**, **private** or **global**.
* Query - A JSON styled AutoFocus query.
