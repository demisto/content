## AutoFocus Feed
Gets Custom feeds from AutoFocus.
The Daily Feed is deprecated. Use the AutoFocus Daily Feed instead. 

For more information see the [AutoFocus documentation](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-feeds.html).

#### Custom Feed info:
To connect a custom AutoFocus feed you need to provide the Custom Feed URL.

The Custom Feed URL should be in this form:
https://autofocus.paloaltonetworks.com/IOCFeed/{Output_Feed_ID}/{Output_Feed_Name}

#### Samples Feed info:
To connect to a sample AutoFocus feed you need to provide the following parameters:
* Scope Type - Either **public**, **private** or **global**.
* Query - A JSON styled AutoFocus query. For example: 
<pre>
{
  "operator":"all",
  "children":[{
      "field":"sample.create_date",
      "operator":"is in the range",
      "value":["2020-03-01T00:00:00","2020-03-02T23:59:59"]
    }]
}
</pre>
