## Get Your API Key
To get your API key, you need to add an authorization code, and they activate the API.

 ### Add your authorization code
  1. Go to the [Palo Alto Networks support site](https://support.paloaltonetworks.com).
  2. Select **Assets > Site Licenses** tab.
  3. Select **Add Site License**.
  4. Enter the authorization code.
  
 ### Activate the API
  1. In **Site Licenses**, select **Enable**.
  2. Select the API Key link.

  Use API key when configuring the integration.
  For more info on activating the license see [Activating AutoFocus Licenses](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/get-started-with-autofocus/activate-autofocus-licenses.html).

## How to Build a Query 
These instructions explain how to build a query for the `query` argument. You can use this argument in the **autofocus-search-samples** and **autofocus-search-sessions** commands.
   1. Go to the [AutoFocus platform](https://autofocus.paloaltonetworks.com/#/samples/global) search screen.
   2. Select the **Advanced...** button on the top right. 
   3. Build a query by selecting fields operators and relevant values. You can always add an additional condition by 
   selecting the **+** button on the right. For more information on how to use the search editor see [Work with the Search Editor
](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-search/work-with-the-search-editor.html#id791798e0-2277-41b5-a723-383bd0787816_id597cae40-646e-4a2f-acf5-5fe04d9e2cf0).
4. To get the query you built, open the API syntax, click the **>_API** button.
5. Copy the query value from the opening curly bracket `{`  until the `,"scope"` parameter and paste it as the value for the `query` argument for both search commands. For example:
```
{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.create_date","operator":"is after","value":["2019-06-13","2019-06-13"]}]}
``` 
## Note for the autofocus-sample-analysis Command
Due to a large amount of dynamic outputs, run the command once to get the fields and the operating system's under HTTP, Coverage, Behavior, Registry, Files, Processes, Connections, and DNS.
