## Get Your API Key
To get your API key, you need to add an authorization code, and then activate the API.

 ### Add your authorization code
  1. Go to the [Palo Alto Networks support site](https://support.paloaltonetworks.com).
  2. From the left-side navigation menu, select **Assets > Site Licenses**.
  3. Click the **Add Site License** button.
  4. Enter the authorization code.
  
 ### Activate the API
  1. From the **Site Licenses** page, click **Enable**.
  2. Select the API Key link.

  Enter this API key when configuring the AutoFocus integration in Cortex XSOAR.
  For more info on activating the license see [Activating AutoFocus Licenses](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/get-started-with-autofocus/activate-autofocus-licenses.html).

## How to Build a Query 
These instructions explain how to build a query, which you can use as the value for the `query` argument. You can use this argument in the **autofocus-search-samples** and **autofocus-search-sessions** commands.
   1. Go to the [AutoFocus platform](https://autofocus.paloaltonetworks.com/#/samples/global).
   2. From the left-side navigation menu, click **Search**.
   3. From the top navigation bar, click **Advanced...**. 
   3. Build a query by selecting fields operators and relevant values. You can always add an additional condition by 
   selecting the **+** button on the right. For more information on how to use the search editor see [Work with the Search Editor
](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-search/work-with-the-search-editor.html#id791798e0-2277-41b5-a723-383bd0787816_id597cae40-646e-4a2f-acf5-5fe04d9e2cf0).
4. To export the query, click the **>_API** button.
5. Copy the query value  and paste it as the value for the `query` argument for both search commands. For example:
```
{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.create_date","operator":"is after","value":["2019-06-13","2019-06-13"]}]} 
```

## Note for the autofocus-sample-analysis Command
Due to a large amount of dynamic outputs, run the command once to get the fields and the operating system's under HTTP, Coverage, Behavior, Registry, Files, Processes, Connections, and DNS.
