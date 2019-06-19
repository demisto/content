 Step 1: Login and add your authorization code
  1. Visit [PAN support](https://support.paloaltonetworks.com).
  2. Select the Assets > Site Licenses tab.
  3. Select Add Site License.
  4. Enter the authorization code.
  
 Step 2: Activate the API.
  1. Select the Enable action in Site Licenses.
  2. Select the API Key link.

  The API key appears onscreen as shown below. Use this API key when configuring the integration.
  For more info on activating the license visit - [Activating AutoFocus Licenses](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/get-started-with-autofocus/activate-autofocus-licenses.html)

Instructions on building the `query` argument for `autofocus-search-samples` and `autofocus-search-sessions` commands:
   1. Visit [AutoFocus UI](https://autofocus.paloaltonetworks.com/#/samples/global) search screen.
   2. Select the `Advanced...` button on the top right. 
   3. Build your query by choosing fields operators and relevant values. You can always add an additional condition by 
   selecting the `+` button on the right. On more information on how to use the search editor visit - [Work with the Search Editor
](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-search/work-with-the-search-editor.html#id791798e0-2277-41b5-a723-383bd0787816_id597cae40-646e-4a2f-acf5-5fe04d9e2cf0)
4. After building the desired query choose the `>_API` button to open the API syntax.
5. Copy the query value from the `{` and on until the `,"scope"` parameter and paste it as your `query` argument for both search commands. It should look something like this:
```
{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.create_date","operator":"is after","value":["2019-06-13","2019-06-13"]}]}
``` 

Important note regarding `autofocus-sample-anakysis` command: Due to large amount of dynamic outputs, run the command once to get the fields and os's under HTTP,Coverage,Behavior,Registry,Files,Processes,Connections,DNS.
