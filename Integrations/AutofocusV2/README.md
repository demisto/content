Use the AutoFocus v2 integration to contextualize threat intelligence and bring speed, consistency, and precision to threat investigation.

## Use Cases
* Query samples / sessions
* Get sample analysis
* Get session details
* Get tag details
* Get top tags

## Get Your API Key
To get your API key, you need to add an authorization code, and then activate the API.

## Add your authorization code
1. Go to the [Palo Alto Networks support site](https://support.paloaltonetworks.com/).
2. Select **Assets > Site Licenses** tab.
3. Select **Add Site License**.
4. Enter the authorization code.

## Activate the API
1. in **Site Licenses**, select **Enable**.
2. Click the API Key link.

Use the API key when configuring the integration.
For more information on activating the license see [Activating AutoFocus Licenses](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/get-started-with-autofocus/activate-autofocus-licenses.html).

## Configure AutoFocus V2 on Demisto
---

1. Navigate to **Settings** > **Integrations**** > **Servers & Services**.
2. Search for AutoFocus V2.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Example** |
   | ---------             | -----------           | -------            |
   | Name | A meaningful name for the integration instance. | AutoFocus V2_instance_2 |
   |  API Key | Account's private token. | N/A  |
   | Trust any certificate (not secure) | When selected, certificates are not checked. | N/A |
   | Use System Proxy Settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. |  https:/<span>/proxyserver.com |
   | Additional Malicious Verdicts  | A comma-separated list of Palo Alto Networks verdicts to consider as malicious when calculating the DBot score.  | malware,phishing,c2 |


4. Click **Test** to validate the URLs, token, and connection.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Search for samples
---
Searches for samples. To view results run the `autofocus-samples-search-results` command with the returned Af Cookie. The AF Cookie expires 120 seconds after the search completes. Use the query that was created in AutoFocus within playbooks "as-is". To run the command with the query in Demisto, wrap the query in backticks ``. For example:
```
!autofocus-search-samples query=`{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1}]}` scope=Global sort="First Seen (Create Date)" order=Ascending
```

##### Base Command

`autofocus-search-samples`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query for which to retrieve samples. For additional information on how to build your query using the AF GUI, see the detailed description. | Optional | 
| max_results | The number of results to return. | Optional | 
| sort | The field by which to sort the results. | Optional | 
| order | The order of the results. Can be "Ascending" or "Descending". | Optional | 
| scope | The scope of the search. Can be "Private", "Public", or "Global". | Required | 
| file_hash | The MD5, SHA1 or SHA256 hash of the file. | Optional | 
| domain | The domain to search. | Optional | 
| ip | The IP address to search. | Optional | 
| url | The URL to search. | Optional | 
| wildfire_verdict | The WildFire verdict. Can be "Malware", "Grayware", "Benign", or "Phishing". | Optional | 
| first_seen | The date range of the creation date. Format: YYY Y-MM-DDTHH:MM:SS,YYYY-MM-DDTHH:MM:SS where the first date is the beginning and the second is the end. Example: 2019-09-09T00:00:00,2019-09-09T23:01:59 | Optional | 
| last_updated | The date range of the last updated date. Format: YYY Y-MM-DDTHH:MM:SS,YYYY-MM-DDTHH:MM:SS where the first date is the beginning and the second is the end. Example: 2019-09-09T00:00:00,2019-09-09T23:01:59 | Optional | 

### How to Build a Query
1. Go to the [AutoFocus platform](https://autofocus.paloaltonetworks.com/#/samples/global) search screen.
2. Click the **Advanced...** button on the top right.
3. Build a query by selecting the fields operators and relevant values. To add another condition, click the **+** button. For more information on how to use the search editor, see [Work with the Search Editor](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-search/work-with-the-search-editor.html#id791798e0-2277-41b5-a723-383bd0787816_id597cae40-646e-4a2f-acf5-5fe04d9e2cf0).
5. To get the query, open the API syntax, and click the **>_API** button.
Copy the query value from the opening curly bracket `{` until the `,"scope"` parameter, and paste it as the value for the `query` argument for both search commands. For example:
```
{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.create_date","operator":"is after","value":["2019-06-13","2019-06-13"]}]}
```

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SamplesSearch.AFCookie | String | The ID of the search. Use this ID to get search results. The AF Cookie expires 120 seconds after the search completes. | 
| AutoFocus.SamplesSearch.Status | String | The search status. Can be "in progress" or "complete". | 


##### Command Example
```
!autofocus-search-samples query=`{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1}]}` scope=Global sort="First Seen (Create Date)" order=Ascending
```

##### Context Example
```
{
    "AutoFocus.SamplesSearch": {
        "Status": "in progress", 
        "AFCookie": "2-78049b80-9c18-47e7-835e-d31ca8bd48aa+0"
    }
}
```

##### Human Readable Output
##### Search Samples Info:
|AFCookie|Status|
|---|---|
| 2-78049b80-9c18-47e7-835e-d31ca8bd48aa+0 | in progress |


### Search for sessions
---
Searches for sessions. To view the results, run the `autofocus-sessions-search-results` command with the returned AF Cookie. The AF Cookie expires 120 seconds after the search completes.

##### Base Command

`autofocus-search-sessions`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query for which to retrieve samples. For additional information on how to build your query using the AF GUI, see the detailed description section. | Optional | 
| max_results | The maximum number of results to return. The default is 30. | Optional | 
| sort | The field by which to sort the results. | Optional | 
| order | The order of the results. Can be "Ascending" or "Descending". | Optional | 
| file_hash | The MD5, SHA1 or SHA256 hash of the file. | Optional | 
| domain | The domain to search. | Optional | 
| ip | The IP address to search. | Optional | 
| url | The URL to search. | Optional | 
| time_range | The date range in which to search for sessions. Format: YYY Y-MM-DDTHH:MM:SS,YYYY-MM-DDTHH:MM:SS where the first date is the beginning and the second is the end. Example: 2019-09-09T00:00:00,2019-09-09T23:01:59 | Optional | 
| time_after | The date after which to search for sessions. Format: YYYY-MM-DDTHH:MM:SS Example: 2019-09-09T23:01:59 | Optional | 
| time_before | The date before which to search for sessions. Format: YYYY-MM-DDTHH:MM:SS Example: 2019-09-09T23:01:59 | Optional | 

### How to Build a Query
1. Go to the [AutoFocus platform](https://autofocus.paloaltonetworks.com/#/samples/global) search screen.
2. Select the **Advanced...** button on the top right.
3. Build a query by selecting fields operators and relevant values. To add another condition, click the **+** button. For more information on how to use the search editor, see [Work with the Search Editor](https://docs.paloaltonetworks.com/autofocus/autofocus-admin/autofocus-search/work-with-the-search-editor.html#id791798e0-2277-41b5-a723-383bd0787816_id597cae40-646e-4a2f-acf5-5fe04d9e2cf0).
4. To get the query you built, open the API syntax, and click the **>_API** button.
5. Copy the query value from the opening curly bracket `{` until the `,"scope"` parameter, and paste it as the value for the `query` argument for both search commands. For example:
```
{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1},{"field":"sample.create_date","operator":"is after","value":["2019-06-13","2019-06-13"]}]}
```

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SessionsSearch.AFCookie | String | The ID of the search. Use the ID to get search results. The AF Cookie expires 120 seconds after the search completes. | 
| AutoFocus.SessionsSearch.Status | String | The status of the search. Can be "in progress" or "complete". | 


##### Command Example
```
!autofocus-search-sessions query={"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1}]} max_results="30" sort="Application" order="Ascending"
```

##### Context Example
```
{
    "AutoFocus.SessionsSearch": {
        "Status": "in progress", 
        "AFCookie": "2-2d70539d-26af-40d2-b80b-16be60dabbaf+0"
    }
}
```

##### Human Readable Output
##### Search Sessions Info:
|AFCookie|Status|
|---|---|
| 2-2d70539d-26af-40d2-b80b-16be60dabbaf+0 | in progress |


### Get results of a samples search
---
Returns the results of a previous samples search.

##### Base Command

`autofocus-samples-search-results`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| af_cookie | The AF Cookie for retrieving results of previous searches. The AF Cookie expires 120 seconds after the search completes. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SamplesResults.Size | String | The file size in bytes. | 
| AutoFocus.SamplesResults.SHA1 | String | The SHA1 hash of the file. | 
| AutoFocus.SamplesResults.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.SamplesResults.Created | Date | The date that the file was created. | 
| AutoFocus.SamplesResults.Finished | Date | The date the file was finished. | 
| AutoFocus.SamplesResults.Region | String | The region of the sample. | 
| AutoFocus.SamplesResults.FileType | String | The file type. | 
| AutoFocus.SamplesResults.Tags | String | The tags attached to the sample. | 
| AutoFocus.SamplesResults.Verdict | Number | The verdict of the sample. | 
| AutoFocus.SamplesResults.TagGroups | String | The groups of relevant tags. | 
| AutoFocus.SamplesSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| File.Size | Number | The size of the file in bytes. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Type | String | The file type, as determined by libmagic (same as displayed in file entries). | 
| File.Tags | String | The tags of the file. | 


##### Command Example
```
!autofocus-samples-search-results af_cookie=2-c0a49ebb-2fee-4423-9bd3-76004d5878ba+1
```

##### Context Example
```
{
    "File": [
        {
            "SHA256": "55f66d613414b35d46e48b952541403a5b2a5d1a1e3c0bef2bd76607b41400b9", 
            "Type": "PE", 
            "Size": 28832
        },
    ], 
    "AutoFocus.SamplesResults": [
        {
            "tag_groups": [], 
            "update_date": "2013-12-04T16:37:03", 
            "Created": "2011-07-14T19:37:28", 
            "FileType": "PE", 
            "ispublic": 2, 
            "ID": "55f66d613414b35d46e48b952541403a5b2a5d1a1e3c0bef2bd76607b41400b9", 
            "Finished": "2013-12-04T16:37:03", 
            "Size": 28832, 
            "Verdict": 1, 
            "SHA256": "55f66d613414b35d46e48b952541403a5b2a5d1a1e3c0bef2bd76607b41400b9", 
            "Region": [
                "us"
            ], 
            "MD5": "6d34c561e20e76e6b62568d83f39ef1c"
        }
    ], 
    "AutoFocus.SamplesSearch": {
        "Status": "complete", 
        "AFCookie": "2-c0a49ebb-2fee-4423-9bd3-76004d5878ba+1"
    }
}
```

##### Human Readable Output
##### Search Samples Results is complete
|Created|FileType|Finished|ID|MD5|Region|SHA256|Size|Verdict|ispublic|tag_groups|update_date|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2011-07-14T19:37:28 | PE | 2013-12-04T16:37:03 | 55f66d613414b35d46e48b952541403a5b2a5d1a1e3c0bef2bd76607b41400b9 | 6d34c561e20e76e6b62568d83f39ef1c | us | 55f66d613414b35d46e48b952541403a5b2a5d1a1e3c0bef2bd76607b41400b9 | 28832 | 1 | 2 |  | 2013-12-04T16:37:03 |
| 2011-07-14T21:20:31 | PE | 2013-12-04T16:38:03 | 029269655941e1a963916837cd3c6489422b8e75a41c33a87e28bf4af02da7dc | ee4e6d2d64507089fea3768dca417738 | us | 029269655941e1a963916837cd3c6489422b8e75a41c33a87e28bf4af02da7dc | 56832 | 1 | 1 |  | 2013-12-04T16:38:03 |
| 2011-07-14T21:43:14 | PE | 2013-12-04T16:42:23 | 65d664d9101a064209ed4aabd5b..........476f3049070370d09195ffa5d5f | b9d6a5f0bb8..........3129bb9b1cc | us | 65d664d9101a064209ed4aabd5b..........476f3049070370d09195ffa5d5f | 28864 | 1 |  |  | 2013-12-04T16:42:23 |
| 2011-07-14T21:46:15 | PE |  | f1db690de6bf92076a0d1572ba1..........be3a79ec73652b2dacd5d39f016 | dc4c0a463cb..........c48a0853aa3 | us | f1db690de6bf92076a0d1572ba1..........be3a79ec73652b2dacd5d39f016 | 40275 | 1 |  |  |  |
| 2011-07-14T21:46:40 | PE |  | 9dafb74fa01520c6e2868b7aa23..........ac4a09e3deec539077971c11316 | 57920ed8aea..........a6ba2697329 | us | 9dafb74fa01520c6e2868b7aa23..........ac4a09e3deec539077971c11316 | 48715 | 1 |  |  |  |
| 2011-07-14T22:15:04 | PE |  | c8fffb2e737514c551b2d7bcaf8baa459564b059cab1a35a3cec4b3c270d4525 | 3018e99857f31a59e0777396ae634a8f | us | c8fffb2e737514c551b2d7bcaf8baa459564b059cab1a35a3cec4b3c270d4525 | 29568 | 1 | 1 |  |  |
| 2011-07-14T22:16:12 | PE |  | dbd56821ab59d42e384bb1cdb15d334245670fa9fa8a0fffe018534787d484c0 | b9beb39484e6742f8d2a1825429e2ca4 | us | dbd56821ab59d42e384bb1cdb15d334245670fa9fa8a0fffe018534787d484c0 | 108032 | 1 | 1 |  |  |
| 2011-07-14T22:17:19 | PE |  | 8e0ec2363553587ab239423a32e26c003e54531456081b3530efea9e66cfdc03 | f8a96cc4ab8711ea3b960088428d4037 | us | 8e0ec2363553587ab239423a32e26c003e54531456081b3530efea9e66cfdc03 | 59392 | 1 | 1 |  |  |
| 2011-07-14T22:31:39 | PE |  | 74a6cbda34ea96c7eb92abd6e3d..........1f3d86206aa54dda899d2c38086 | 2a6a82dcf9d..........ef1d887bcb1 | us | 74a6cbda34ea96c7eb92abd6e3d..........1f3d86206aa54dda899d2c38086 | 28864 | 1 |  |  |  |
| 2011-07-14T22:49:44 | PE |  | 8bc709e6257f6f4d0f2bc7af2eaa064a527e140152c2512e723c7edb3d91cf48 | f8e21525c6848f45e4ab77aee05f0a28 | us | 8bc709e6257f6f4d0f2bc7af2eaa064a527e140152c2512e723c7edb3d91cf48 | 27480 | 1 | 1 |  |  |
| 2011-07-14T22:55:56 | PE |  | 1ef090562ef527b99873c9a48c33a3d6e7014acc2f8d6c3f801c7b4c988cc013 | 1c66904ecb846da5b1fb2072f9ea6e0e | us | 1ef090562ef527b99873c9a48c33a3d6e7014acc2f8d6c3f801c7b4c988cc013 | 95690 | 1 | 1 |  |  |
| 2011-07-14T22:58:21 | PE |  | e29138070b0da4e10eb33f43c58..........1f25fcf39423e483633326ab866 | cdef57dda70..........9dce45c0afa | us | e29138070b0da4e10eb33f43c58..........1f25fcf39423e483633326ab866 | 28832 | 1 |  |  |  |
| 2011-07-14T22:59:15 | PE |  | 75d5ebc5d1a16d7e742f45f05c4..........7c5a830e6e4fd55b0b4a34a2a57 | fa50281f81d..........290f13ad7ad | us | 75d5ebc5d1a16d7e742f45f05c4..........7c5a830e6e4fd55b0b4a34a2a57 | 28832 | 1 |  |  |  |
| 2011-07-14T23:00:23 | PE |  | 9e6c2e3417e660d825115d41bb8..........9517177bfda4070b62e4217c4a0 | 712c7d922f2..........c3fc1d568f9 | us | 9e6c2e3417e660d825115d41bb8..........9517177bfda4070b62e4217c4a0 | 28832 | 1 |  |  |  |
| 2011-07-14T23:00:48 | PE |  | 6bd5771c35fb9deab8c45cd30fb..........6f812464439b536a05f6a350812 | f1eeb146f69..........161e12cc7f8 | us | 6bd5771c35fb9deab8c45cd30fb..........6f812464439b536a05f6a350812 | 28832 | 1 |  |  |  |
| 2011-07-14T23:15:55 | PE |  | 4aac6fbf433dade622bb9882b637011963afd2fbbd8794910f85c8f35709adb6 | 57e0d672d7dcdcf61a407ac268a9f1b5 | us | 4aac6fbf433dade622bb9882b637011963afd2fbbd8794910f85c8f35709adb6 | 32768 | 1 | 1 |  |  |
| 2011-07-14T23:16:20 | PE |  | 2c4fe22e50d9a4ebce1bd8efa03b5e7eca3f321d17dae7156612979794f01b4b | 8d2da677321861b9d6f3f846f6d8a537 | us | 2c4fe22e50d9a4ebce1bd8efa03b5e7eca3f321d17dae7156612979794f01b4b | 49104 | 1 | 1 |  |  |
| 2011-07-14T23:17:08 | PE |  | 90c3f61bcb7bbc04cf5c65c335d..........c8272ad300a3baabba9ca164b42 | 00a8138a59c..........6bb252f5920 | us | 90c3f61bcb7bbc04cf5c65c335d..........c8272ad300a3baabba9ca164b42 | 19840 | 1 |  |  |  |
| 2011-07-14T23:17:36 | PE |  | a95410b29088657b25dd3fa058b402b57ae3c78bb1ec60ed6efac43f17f6fc00 | d9b602bd50035d6dfc9fc728b2276b4c | us | a95410b29088657b25dd3fa058b402b57ae3c78bb1ec60ed6efac43f17f6fc00 | 391992 | 1 | 1 |  |  |
| 2011-07-14T23:18:01 | PE |  | 1ee9c36474c68b99f7e3aa69f27..........9d5468d50a38c4c559bb9327f80 | 50dfe61f4b4..........10ab8bd51df | us | 1ee9c36474c68b99f7e3aa69f27..........9d5468d50a38c4c559bb9327f80 | 45056 | 1 |  |  |  |
| 2011-07-14T23:18:26 | PE |  | 975d628ecbcf4f96e038d97f6171f0426e608698e7ac2a0509e03b62e7f3205a | 3fe58cf2af09ea99384b6aae41c574c0 | us | 975d628ecbcf4f96e038d97f6171f0426e608698e7ac2a0509e03b62e7f3205a | 36864 | 1 | 1 |  |  |
| 2011-07-14T23:18:52 | PE |  | 6ee81b8bf0a611f35bc64f2ad4c22b9621515d8ffe5bf35d5f93e7581cc47b2c | 78aabe05b2812e602e8e5110f1c4a454 | us | 6ee81b8bf0a611f35bc64f2ad4c22b9621515d8ffe5bf35d5f93e7581cc47b2c | 24576 | 1 | 1 |  |  |
| 2011-07-14T23:19:17 | PE |  | d179777a5c05d7d7a8d62ade0e8106068c891a2d3c08f71190fa3e3932afd0eb | 28e84995a369c69abf74256f5579bec6 | us | d179777a5c05d7d7a8d62ade0e8106068c891a2d3c08f71190fa3e3932afd0eb | 38650 | 1 | 1 |  |  |
| 2011-07-14T23:19:42 | PE |  | 26cc2c929ae1295f0441c1cb3b8..........953183fa41d34543c2305f151ad | f7212a74bce..........56ccd886af0 | us | 26cc2c929ae1295f0441c1cb3b8..........953183fa41d34543c2305f151ad | 25105 | 1 |  |  |  |
| 2011-07-14T23:20:08 | PE |  | 51c968d9d57fb53ea1a2b2330bb64ab52f8f7b7f52174ca3605452874c1fc10b | 53d109380b6756cde27b1635c36afa94 | us | 51c968d9d57fb53ea1a2b2330bb64ab52f8f7b7f52174ca3605452874c1fc10b | 467968 | 1 | 1 |  |  |
| 2011-07-14T23:20:33 | PE |  | fed65eea8eecade252900eb4f5364ecf60c210771c8f1489b8f6213375dfa5bd | 3527bbfaba4d6c900c7e45b23c8b2c1b | us | fed65eea8eecade252900eb4f5364ecf60c210771c8f1489b8f6213375dfa5bd | 14848 | 1 | 1 |  |  |
| 2011-07-14T23:20:59 | PE |  | e19f8e411bf95bdb3413ef1cf2c68bd4688e1f2b9f520d60526a521586803523 | 237a21a936337efbdb04695c8957deee | us | e19f8e411bf95bdb3413ef1cf2c68bd4688e1f2b9f520d60526a521586803523 | 1509364 | 1 | 1 |  |  |
| 2011-07-14T23:21:24 | PE |  | 073ae7b7bdfa68e900f18bd32e652ffc102033838eb0fb6bb2e710c7234a1dec | 70017806596aeb0c0956a1a9b0afdf3b | us | 073ae7b7bdfa68e900f18bd32e652ffc102033838eb0fb6bb2e710c7234a1dec | 30208 | 1 | 1 |  |  |
| 2011-07-14T23:22:40 | PE |  | 268bb4eedaf5a726d07033bb363fdd7961e7a499ea39f44f3b8fd90086a47cd3 | 14909eba6a9f49f87d86993f13b301fa | us | 268bb4eedaf5a726d07033bb363fdd7961e7a499ea39f44f3b8fd90086a47cd3 | 290816 | 1 | 1 |  |  |
| 2011-07-14T23:23:05 | PE |  | 2cd2995e3b567e0c78e687802e8..........f2b98157a7d7ca944422302e758 | bbc0971f93e..........ba03275c4b8 | us | 2cd2995e3b567e0c78e687802e8..........f2b98157a7d7ca944422302e758 | 3072 | 1 |  |  |  |

### Get results of a sessions search
---
Returns the results of a previous session's search.

##### Base Command

`autofocus-sessions-search-results`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| af_cookie | The AF Cookie for retrieving the results of a previous search. The AF Cookie expires 120 seconds after the search completes. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SessionsResults.FileName | String | The name of the file.. | 
| AutoFocus.SessionsResults.ID | String | The ID of the session. Used to get session details. | 
| AutoFocus.SessionsResults.Industry | String | The related industry. | 
| AutoFocus.SessionsResults.Region | String | The regions of the sessions. | 
| AutoFocus.SessionsResults.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.SessionsResults.Seen | Date | The seen date. | 
| AutoFocus.SessionsResults.UploadSource | String | The source of the uploaded sample. | 
| AutoFocus.SessionsResults.FileURL | String | The URL of the file. | 
| AutoFocus.SessionsResults.Tags | String | The relevant tags. | 
| AutoFocus.SessionsSearch.Status | String | The search status. Can be "in progress" or "complete". | 
| File.Name | String | The full file name (including file extension). | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Tags | String | The tags of the file. | 


##### Command Example
```
!autofocus-sessions-search-results af_cookie=2-f2c742b6-a363-4eb9-a313-63a99c376081+0
```

##### Context Example
```
{
    "AutoFocus.SessionsSearch": {
        "Status": "complete", 
        "AFCookie": "2-f2c742b6-a363-4eb9-a313-63a99c376081+0"
    }, 
    "File": [
        {
            "SHA256": "2eb355b54855c7531a811d435b2ff4dc74d377bfed98fd1ad03caa591f5555bd", 
            "Name": "wildfire-test-pe-file.exe", 
            "Tags": [
                "Commodity.WildFireTest"
            ]
        }, 
        {
            "SHA256": "f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38", 
            "Name": "wildfire-test-pe-file (4).exe", 
            "Tags": [
                "Commodity.WildFireTest"
            ]
        }
    ], 
    "AutoFocus.SessionsResults": [
        {
            "tag_groups": [], 
            "Tags": [
                "Commodity.WildFireTest"
            ], 
            "Industry": "High Tech", 
            "FileName": "wildfire-test-pe-file.exe", 
            "ID": "u_56095401643", 
            "UploadSource": "Manual API", 
            "Seen": "2019-12-11T08:52:16", 
            "SHA256": "2eb355b54855c7531a811d435b2ff4dc74d377bfed98fd1ad03caa591f5555bd", 
            "Region": "us"
        }
    ]
}
```

##### Human Readable Output
##### Search Sessions Results is complete
|FileName|ID|Industry|Region|SHA256|Seen|Tags|UploadSource|tag_groups|
|---|---|---|---|---|---|---|---|---|
| wildfire-test-pe-file.exe | u_56095401643 | High Tech | us | 2eb355b54855c7531a811d435b2ff4dc74d377bfed98fd1ad03caa591f5555bd | 2019-12-11T08:52:16 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_49158137853 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-02T11:04:05 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_49159945553 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-02T11:19:21 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_48980717523 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-09-30T23:58:00 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_48980935123 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-01T00:02:36 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_48980770253 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-09-30T23:59:18 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_48980686453 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-09-30T23:57:10 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_49128586383 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-02T08:44:04 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_49129503223 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-02T08:49:24 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_49122514613 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-02T07:39:45 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_49145687573 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-02T09:52:36 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (4).exe | u_49158441703 | High Tech | us | f29192fba1064d582cddc85ef3bcf37fa8e9b7d5faddb3e67d241d472e66ab38 | 2019-10-02T11:06:29 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47517508773 | High Tech | us | cafa7f3adaace43042e5f85328ddf1d6f0d8109e65f7e6c0b87676a9a7479733 | 2019-09-17T01:59:31 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47515984893 | High Tech | us | 4851a140be5af4acf3d85621d99c177fd6e1403e8e93c9cba6037459c802382f | 2019-09-17T01:32:11 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47517298263 | High Tech | us | 5d3725fe649e3a1244fe50cd23b2e558594753d7579c30214da293566d6afa3b | 2019-09-17T01:56:51 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47541182333 | High Tech | us | 51a93620c2c1456081f91bad64e537724a0d93dcf55face4f1d33df9a91486f1 | 2019-09-17T06:05:21 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47518135653 | High Tech | us | b39a6bf99de8dd7e55d22ee0732ea3582536a0615dab86e3d36010fe0d4ecf2a | 2019-09-17T02:04:56 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47516600663 | High Tech | us | 7078f4e2c5d8038bd875e3a6dfd09c9014573c5d3c155f27c3acd1073c05d16f | 2019-09-17T01:46:01 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47561050553 | High Tech | us | c14646114c390027d373cbd5af7d31d952ab6acd86d5157bb174b19792e557f2 | 2019-09-17T08:14:56 | 41453.TestElena,Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47517909453 | High Tech | us | 2499501bebcc6ff59d3f0028f760e0433ee3a9415e916d1278a70c474690869d | 2019-09-17T02:02:46 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file.exe | u_47559447933 | High Tech | us | 12f198c65cbdf49972b7432291dad4d2fae7cbb77a35cda1cc28ab2b83d1e2b5 | 2019-09-17T08:08:39 | Commodity.WildFireTest | Manual API |  |
| https:/<span>/wildfire.paloaltonetworks.com/publicapi/test/pe | u_46060032683 | High Tech | us | 2e40edcf77d95173463ca4bfaf833a6a1860ffa4e7b03c3fded8de08ee2be27f | 2019-09-01T04:34:48 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (2).exe | u_45811064553 | High Tech | us | f27069e200ed14c56b1b91285ea3c061aa0e4ca53d9056fed9cc0c9c3e98e961 | 2019-08-28T21:17:33 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (2).exe | u_45810946733 | High Tech | us | f27069e200ed14c56b1b91285ea3c061aa0e4ca53d9056fed9cc0c9c3e98e961 | 2019-08-28T21:14:17 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (2).exe | u_45810992703 | High Tech | us | f27069e200ed14c56b1b91285ea3c061aa0e4ca53d9056fed9cc0c9c3e98e961 | 2019-08-28T21:15:31 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (2).exe | u_45811012343 | High Tech | us | f27069e200ed14c56b1b91285ea3c061aa0e4ca53d9056fed9cc0c9c3e98e961 | 2019-08-28T21:16:06 | Commodity.WildFireTest | Manual API |  |
| https:/<span>/wildfire.paloaltonetworks.com/publicapi/test/pe | u_45835887733 | High Tech | us | bfdc97ecc0d1e19d17cffe856b33c41883520d7b38daa77af03bb42ef83bc680 | 2019-08-29T05:19:21 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (3).exe | u_45811604063 | High Tech | us | 409eb2fa745b4bd804bb3ebdd48f0107bd9c6471a9447a61f68c1a32c480f0f9 | 2019-08-28T21:32:05 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (3).exe | u_45811375593 | High Tech | us | 409eb2fa745b4bd804bb3ebdd48f0107bd9c6471a9447a61f68c1a32c480f0f9 | 2019-08-28T21:25:36 | Commodity.WildFireTest | Manual API |  |
| wildfire-test-pe-file (3).exe | u_45811208463 | High Tech | us | 409eb2fa745b4bd804bb3ebdd48f0107bd9c6471a9447a61f68c1a32c480f0f9 | 2019-08-28T21:20:56 | Commodity.WildFireTest | Manual API |  |


### Get session details
---
Returns session details by session ID.

##### Base Command

`autofocus-get-session-details`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | The ID of the session. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.Sessions.FileName | String | The name of the file. | 
| AutoFocus.Sessions.ID | String | The ID of the session. | 
| AutoFocus.Sessions.Industry | String | The related industry. | 
| AutoFocus.Sessions.Region | String | The session's regions. | 
| AutoFocus.Sessions.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.Sessions.Seen | Date | The seen date. | 
| AutoFocus.Sessions.UploadSource | String | The source that uploaded the sample. | 
| File.Name | String | The full file name (including file extension). | 
| File.SHA256 | String | The SHA256 hash of the file. | 


##### Command Example
```
!autofocus-get-session-details session_id="u_39605858263"
```

##### Context Example
```
{
    "File": [
        {
            "SHA256": "8d4241654449c63f70dabd83483f8ca8bd8e8e6a8d0679639eb061b3b6dbcfec", 
            "Name": "wildfire-test-apk-file.apk"
        }
    ], 
    "AutoFocus.Sessions": [
        {
            "Industry": "High Tech", 
            "FileName": "wildfire-test-apk-file.apk", 
            "ID": "u_39605858263", 
            "UploadSource": "Manual API", 
            "Seen": "2019-05-29T15:25:26", 
            "SHA256": "8d4241654449c63f70dabd83483f8ca8bd8e8e6a8d0679639eb061b3b6dbcfec", 
            "Region": "us"
        }
    ]
}
```

##### Human Readable Output
##### Session u_39605858263:
|FileName|ID|Industry|Region|SHA256|Seen|UploadSource|
|---|---|---|---|---|---|---|
| wildfire-test-apk-file.apk | u_39605858263 | High Tech | us | 8d4241654449c63f70dabd83483f8ca8bd8e8e6a8d0679639eb061b3b6dbcfec | 2019-05-29T15:25:26 | Manual API |


### Get analysis details
---
Returns properties, behaviors, and activities observed for a sample. Runs the command a single time to get the fields and operating systems under HTTP, Coverage, Behavior, Registry, Files, Processes, Connections, and DNS.

##### Base Command

`autofocus-sample-analysis`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sample_id | The SHA256 hash of the sample to analyze. | Required | 
| os | The analysis environment. Can be "win7", "winxp", "android", "static_analyzer", "mac", or "bare_metal". | Optional | 
| filter_data | Whether to smartly filter the data. If "False", the data returned will not be smartly filtered, and will significantly reduce integration performance. The recommended setting is "True". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.SampleAnalysis.Analysis.Http | Unknown | The HTTP requests made when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Coverage | Unknown | The WildFire signatures that matched the sample. | 
| AutoFocus.SampleAnalysis.Analysis.Behavior | Unknown | The sample behavior: created or modified files, started a process, spawned new processes, modified the registry, or installed browser help objects. | 
| AutoFocus.SampleAnalysis.Analysis.Registry | Unknown | The registry settings and options that showed activity when the sample was executed in the analysis environment. | 
| AutoFocus.SampleAnalysis.Analysis.Files | Unknown | The files that showed activity as a result of the sample being executed. | 
| AutoFocus.SampleAnalysis.Analysis.Processes | Unknown | The processes that showed activity when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Connections | Unknown | The connections to other hosts on the network when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Dns | Unknown | The DNS activity observed when the sample was executed. | 
| AutoFocus.SampleAnalysis.Analysis.Mutex | Unknown | The mutex created when the program's start is listed with the parent process if the sample generates other program threads when executed in the analysis environment. | 


##### Command Example
```
!autofocus-sample-analysis sample_id=dd0d26ceea034b3ae32a4f6a477466ac598ee17f811f88cf14b2c708240fb993
```

##### Context Example
```
{
    "AutoFocus.SampleAnalysis": {
        "ID": "dd0d26ceea034b3ae32a4f6a477466ac598ee17f811f88cf14b2c708240fb993", 
        "Analysis": {
            "Files": {
                "win7": [
                    {
                        "action": " Create ", 
                        "parent_process": "svchost.exe "
                    }, 
                    {
                        "action": " Create ", 
                        "parent_process": "na.exe "
                    }, 
                    {
                        "action": " Create ", 
                        "parent_process": "svchost.exe "
                    }, 
                    {
                        "action": " Create ", 
                        "parent_process": "users\\administrator\\sample.dll:DllInstall "
                    }, 
                    {
                        "action": " Create ", 
                        "parent_process": "users\\administrator\\sample.dll:DllInstall "
                    }
                ], 
                "winxp": []
            }, 
            "Processes": {
                "win7": [
                    {
                        "action": " created ", 
                        "parent_process": "svchost.exe "
                    }, 
                    {
                        "action": " created ", 
                        "parent_process": "services.exe "
                    }, 
                    {
                        "action": " created ", 
                        "parent_process": "TrustedInstaller.exe "
                    }, 
                    {
                        "action": " CreateProcessInternalW ", 
                        "parent_process": "<null> "
                    }
                ], 
                "winxp": [
                    {
                        "action": " created ", 
                        "parent_process": "explorer.exe "
                    }, 
                    {
                        "action": " created ", 
                        "parent_process": "svchost.exe "
                    }, 
                    {
                        "action": " created ", 
                        "parent_process": "winlogon.exe "
                    }
                ]
            }, 
            "Http": {
                "win7": [
                    {
                        "url": " / ", 
                        "host": "sp1.eventincoandhar.info ", 
                        "method": " POST "
                    }, 
                    {
                        "url": " / ", 
                        "host": "sc1.eventincoandhar.info ", 
                        "method": " POST "
                    }, 
                    {
                        "url": " / ", 
                        "host": "www.bbc.com ", 
                        "method": " HEAD "
                    }
                ]
            }, 
            "Coverage": {
                "url_categories": [
                    {
                        "url": "ns-154-b.gandi.net", 
                        "cat": "Computer and Internet Info"
                    }, 
                    {
                        "url": "ns3.fastly.net", 
                        "cat": "Computer and Internet Info"
                    }, 
                    {
                        "url": "aiden.ns.cloudflare.com", 
                        "cat": "Computer and Internet Info"
                    }, 
                    {
                        "url": "b.iana-servers.net", 
                        "cat": "Unknown"
                    }, 
                    {
                        "url": "aningtofrebri.info", 
                        "cat": "Unknown"
                    }
                ], 
                "fileurl_signatures": [], 
                "wildfire_signatures": [], 
                "dns_signatures": [
                    {
                        "create_date": "2016-03-30 07:32:49", 
                        "name": "generic:a.iana-servers.net"
                    }, 
                    {
                        "create_date": "2016-03-30 07:53:34", 
                        "name": "generic:b.iana-servers.net"
                    }, 
                    {
                        "create_date": "2017-12-13 22:55:29", 
                        "name": "Trojan-Downloader.adload:housandry.info"
                    }, 
                    {
                        "create_date": "2017-12-13 22:55:29", 
                        "name": "Trojan-Downloader.adload:whereason.info"
                    }, 
                    {
                        "create_date": "2018-04-07 10:05:16", 
                        "name": "Virus.ramnit:mrsewic.com"
                    }, 
                    {
                        "create_date": "2018-04-07 10:05:16", 
                        "name": "generic:ylsuest.com"
                    }, 
                    {
                        "create_date": "2018-04-07 10:15:23", 
                        "name": "generic:knsemis.com"
                    }, 
                    {
                        "create_date": "2019-02-07 09:00:08", 
                        "name": "Trojan.bsymem:inf2.aningtofrebri.info"
                    }
                ]
            }, 
            "Mutex": {
                "win7": [
                    {
                        "action": " CreateMutexW ", 
                        "process": "msiexec.exe ", 
                        "parameters": " Global\\_MSIExecute"
                    }
                ]
            }, 
            "Registry": {
                "win7": [
                    {
                        "action": " CreateKey ", 
                        "parameters": " HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
                    }, 
                    {
                        "action": " RegSetValueEx ", 
                        "parameters": " HKLM\\SYSTEM\\ControlSet001\\services\\Tcpip\\Parameters\\Interfaces\\{FF885F56-91B0-47CA-837A-F293CA541A1F} "
                    }, 
                    {
                        "action": " RegSetValueEx ", 
                        "parameters": " HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall "
                    }, 
                    {
                        "action": " RegSetValueEx ", 
                        "parameters": " HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{5129CAA8-E24B-2AEE-652F-C652FBF1E9BB} "
                    }, 
                    {
                        "action": " RegSetValueEx ", 
                        "parameters": " HKLM\\SOFTWARE\\Wow6432Node\\$(brand_name) "
                    }
                ], 
                "winxp": [
                    {
                        "action": " SetValueKey ", 
                        "parameters": " HKCU\\SessionInformation\\ProgramCount "
                    }, 
                    {
                        "action": " SetValueKey ", 
                        "parameters": " HKLM\\SOFTWARE\\Microsoft\\WBEM\\CIMOM\\List of event-active namespaces "
                    }, 
                    {
                        "action": " SetValueKey ", 
                        "parameters": " HKLM\\SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\ControlFlags "
                    }, 
                    {
                        "action": " SetValueKey ", 
                        "parameters": " HKLM\\SOFTWARE\\Microsoft\\WZCSVC\\Parameters\\Interfaces\\ActiveSettings "
                    }
                ]
            }, 
            "Behavior": {
                "static_analyzer": [], 
                "win7": [
                    {
                        "risk": "high ", 
                        "behavior": " Connected to a non-standard HTTP port"
                    }, 
                    {
                        "risk": "medium ", 
                        "behavior": " Created or modified a file in the Windows system folder"
                    }, 
                    {
                        "risk": "high ", 
                        "behavior": " Connected to a malicious IP"
                    }, 
                    {
                        "risk": "high ", 
                        "behavior": " Connected to a malicious URL"
                    }
                ], 
                "winxp": [
                    {
                        "risk": "medium ", 
                        "behavior": " Created or modified a file in the Windows system folder"
                    }, 
                    {
                        "risk": "low ", 
                        "behavior": " Started a process from a user folder"
                    }
                ]
            }
        }
    }
}
```

##### Human Readable Output
##### Sample Analysis results for dd0d26ceea034b3ae32a4f6a477466ac598ee17f811f88cf14b2c708240fb993:### Behavior Static Analyzer:
No entries
##### Behavior Win7:
|Behavior|Risk|
|---|---|
|  Connected to a non-standard HTTP port | high  |
|  Created or modified a file in the Windows system folder | medium  |
|  Generated unknown TCP or UDP traffic | medium  |
|  Downloaded an executable | high  |
|  Used a short HTTP header | high  |
|  Used the HTTP POST method | medium  |
|  Initiated a failed HTTP connection | low  |
|  Sent an HTTP response before receiving a request | high  |
|  Generated unknown HTTP traffic | high  |
|  Connected to a malicious domain | high  |
|  Created an executable file in a user folder | low  |
|  Started a process from a user folder | low  |
|  Deleted itself | high  |
|  Registered an OLE control with regsvr32.exe | medium  |
|  Started or stopped a Windows system service | high  |
|  Attempted to determine public IP address via IP-checking website | high  |
|  Connected to a malicious IP | high  |
|  Connected to a malicious URL | high  |
##### Behavior Winxp:
|Behavior|Risk|
|---|---|
|  Created or modified a file in the Windows system folder | medium  |
|  Started a process from a user folder | low  |
##### Processes Win7:
|Action|Parent Process|
|---|---|
|  created  | svchost.exe  |
|  created  | services.exe  |
|  created  | TrustedInstaller.exe  |
|  created  | csrss.exe  |
|  created  | TrustedInstaller.exe  |
|  created  | services.exe  |
|  created  | svchost.exe  |
|  created  | services.exe  |
##### Processes Winxp:
|Action|Parent Process|
|---|---|
|  created  | explorer.exe  |
|  created  | svchost.exe  |
|  created  | winlogon.exe  |
##### Files Win7:

|Action|Parent Process|
|---|---|
|  Create  | svchost.exe  |
|  Create  | na.exe  |
|  Create  | svchost.exe  |
|  Create  | na.exe  |
|  Create  | na.exe  |
|  Create  | na.exe  |
|  Create  | users\administrator\sample.dll:DllInstall  |
|  Create  | users\administrator\sample.dll:DllInstall  |
##### Files Winxp:
No entries
###
33 Registry Win7:

|Action|Parameters|
|---|---|
|  CreateKey  |  HKLM\System\CurrentControlSet\Services\Tcpip\Parameters |
|  SetValueKey  |  HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{5129CAA8-E24B-2AEE-652F-C652FBF1E9BB}\cd77f991  |
|  CreateKey  |  \Registry\Machine\System\CurrentControlSet\Services\RdyBoost\Parameters |
|  CreateKey  |  \Registry\Machine\System\CurrentControlSet\Services\RdyBoost\AttachState |
|  SetValueKey  |  HKLM\COMPONENTS\ServicingStackVersions\6.1.7601.17514 (win7sp1_rtm.101119-1850)  |
|  SetValueKey  |  HKLM\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths\ProgramData\1560740575  |
|  SetValueKey  |  HKLM\SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths\Users\ADMINI~1\AppData\Local\Temp\{F5743266-6DFF-3433-4CE4-56028389CD67}  |
|  RegSetValueEx  |  HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
|  RegSetValueEx  |  HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{5129CAA8-E24B-2AEE-652F-C652FBF1E9BB}  |
|  RegSetValueEx  |  HKLM\SOFTWARE\Wow6432Node\$(brand_name)  |
##### Registry Winxp:
|Action|Parameters|
|---|---|
|  SetValueKey  |  HKCU\SessionInformation\ProgramCount  |
|  SetValueKey  |  HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\List of event-active namespaces  |
|  SetValueKey  |  HKCU\SessionInformation\ProgramCount  |
|  SetValueKey  |  HKLM\SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces\ActiveSettings  |
##### Mutex Win7:
|Action|Parameters|Process|
|---|---|---|
|  CreateMutexW  |  Global\_MSIExecute | msiexec.exe  |
##### Http Win7:
|Host|Method|Url|
|---|---|---|
| sp1.eventincoandhar.info  |  POST  |  /  |
| ip-api.com  |  GET  |  /json  |
| knsemis.com  |  POST  |  /tickets  |
| www.<span>cnn.com  |  HEAD  |  /  |
| www.<span>bbc.com  |  HEAD  |  /  |


### Get tag details
---
Returns details about the given tag.

##### Base Command

`autofocus-tag-details`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | The public tag name. Can be retrieved from the top-tags command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.Tag.TagName | String | The simple name of the tag. | 
| AutoFocus.Tag.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.Tag.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.Tag.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.Tag.TagDefinitionScope | String | The scope of the tag. Can be "public", "private", or "Unit42". | 
| AutoFocus.Tag.CustomerName | String | The organization that created the tag. | 
| AutoFocus.Tag.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.Tag.TagClass | String | The classification of the tag. | 
| AutoFocus.Tag.TagDefinitionStatus | String | The status of the tag definition. Can be "enabled", "disabled", "removing", or "rescoping". | 
| AutoFocus.Tag.TagGroup | String | The tag group of the tag. | 
| AutoFocus.Tag.Description | String | The tag description. | 


##### Command Example
```
!autofocus-tag-details tag_name=490082.Pastebin_Raw
```

##### Context Example
```
{
    "AutoFocus.Tag": {
        "Count": 84674, 
        "Lasthit": "2020-01-02 05:22:18", 
        "CustomerName": "Squadra Solutions", 
        "PublicTagName": "490082.Pastebin_Raw", 
        "TagDefinitionScope": "public", 
        "Source": "Squadra Solutions", 
        "TagDefinitionStatus": "enabled", 
        "TagName": "Pastebin_Raw", 
        "TagClass": "malicious_behavior", 
        "Description": "Malicious actors may post raw code to Pastebin which can then be downloaded for further use or as a C2 channel. Some code are also encoded in base64 for further obfuscation"
    }
}
```

##### Human Readable Output
##### Tag 490082.Pastebin_Raw details:
|Count|Customer Name|Description|Lasthit|Public Tag Name|Source|Tag Class|Tag Definition Scope|Tag Definition Status|Tag Name|
|---|---|---|---|---|---|---|---|---|---|
| 84674 | Squadra Solutions | Malicious actors may post raw code to Pastebin which can then be downloaded for further use or as a C2 channel. Some code are also encoded in base64 for further obfuscation | 2020-01-02 05:22:18 | 490082.Pastebin_Raw | Squadra Solutions | malicious_behavior | public | enabled | Pastebin_Raw |


### Search for the most popular tags
---
Performs a search to identify the most popular tags.

##### Base Command

`autofocus-top-tags-search`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scope | The scope of the search. Can be "industry", "organization", "all", or "global". | Required | 
| class | The tag class. Can be "Malware Family", "Campaign", "Actor", "Exploit", or Malicious Behavior". See **Tag Classes** below for more information.  | Required | 
| private | Whether the tag scope is "private". If "True", the tag scope is private. The default is "False". | Optional | 
| public | Whether the tag scope is "public". If "True", the tag scope is public. The default is "False". | Optional | 
| commodity | Whether the tag scope is "commodity". If "True", the tag scope is commodity. The default is "False". | Optional | 
| unit42 | Whether the tag scope is "Unit42". If "True", the tag scope is unit42. The default is "False". | Optional | 

##### Tag Classes
- Malware Family: group of malware that have shared properties or common functions. 
- Campaign:  targeted attack, which might include several incidents or sets of activities. 
- Actor: individual or group that initiates a campaign using malware families. 
- Exploit: an attack, which takes advantage of a software or network weakness, bug, or vulnerability to manipulate the behavior of the system. 
- Malicious Behavior: behavior that is not specific to a malware family or campaign, but indicates that your system has been compromised.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.TopTagsSearch.AFCookie | String | The ID of the search. Use this ID to get search results. The AF Cookie expires 120 seconds after the search completes. | 
| AutoFocus.TopTagsSearch.Status | String | The status of the search. Can be "in progress" or "complete". | 


##### Command Example
```
!autofocus-top-tags-search scope="all" class="Malicious Behavior" private="True" public="True" commodity="False" unit42="False"
```

##### Context Example
```
{
    "AutoFocus.TopTagsSearch": {
        "Status": "in progress", 
        "AFCookie": "2-1caadf19-2e94-4742-b9cf-da8b2d90988c+0"
    }
}
```

##### Human Readable Output
##### Top tags search Info:
|AFCookie|Status|
|---|---|
| 2-1caadf19-2e94-4742-b9cf-da8b2d90988c+0 | in progress |


### Get results of a top tags search
---
Returns the results of a previous top tags search.

##### Base Command

`autofocus-top-tags-results`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| af_cookie | The AF Cookie for retrieving results of the previous search. The AF Cookie expires 120 seconds after the search completes. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AutoFocus.TopTagsResults.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.TopTagsResults.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.TopTagsResults.TagName | String | The simple name of the tag. | 
| AutoFocus.TopTagsResults.Lasthit | Date | The last encounter date of the tag. | 
| AutoFocus.TopTagsSearch.Status | String | The search status. Can be "in progress" or "complete". | 


##### Command Example
```
!autofocus-top-tags-results af_cookie=2-2190f844-7c0a-42e7-b4be-5f7d83c9b05c+0
```

##### Context Example
```
{
    "AutoFocus.TopTagsSearch": {
        "Status": "in progress", 
        "AFCookie": "2-2190f844-7c0a-42e7-b4be-5f7d83c9b05c+0"
    }, 
    "AutoFocus.TopTagsResults": [
        {
            "Count": 84674, 
            "Lasthit": "2020-01-02 05:22:18", 
            "TagName": "Pastebin_Raw", 
            "PublicTagName": "490082.Pastebin_Raw"
        }, 
        {
            "Count": 25288, 
            "Lasthit": "2020-01-01 18:36:12", 
            "TagName": "ServiceDllUnloadOnStop", 
            "PublicTagName": "46640.ServiceDllUnloadOnStop"
        }, 
        {
            "Count": 20912, 
            "Lasthit": "2020-01-01 16:09:10", 
            "TagName": "hupigon_mutex", 
            "PublicTagName": "104.hupigon_mutex"
        }, 
        {
            "Count": 68694, 
            "Lasthit": "2020-01-01 19:18:09", 
            "TagName": "Modify_ComputerName", 
            "PublicTagName": "490082.Modify_ComputerName"
        }, 
        {
            "Count": 18740, 
            "Lasthit": "2020-01-01 07:09:55", 
            "TagName": "Modify_TermServ_RDP", 
            "PublicTagName": "490082.Modify_TermServ_RDP"
        }, 
        {
            "Count": 53921, 
            "Lasthit": "2020-01-02 00:02:21", 
            "TagName": "Modify_Permission", 
            "PublicTagName": "46640.Modify_Permission"
        }, 
        {
            "Count": 11078, 
            "Lasthit": "2020-01-02 07:40:39", 
            "TagName": "MSOfficeResiliency", 
            "PublicTagName": "490082.MSOfficeResiliency"
        }, 
        {
            "Count": 18857, 
            "Lasthit": "2020-01-01 10:06:58", 
            "TagName": "SecurityProviders_Persistence_LoadDLL", 
            "PublicTagName": "490082.SecurityProviders_Persistence_LoadDLL"
        }, 
        {
            "Count": 100001, 
            "Lasthit": "2019-06-20 12:59:58", 
            "TagName": "Modify_AttachmentManager", 
            "PublicTagName": "490082.Modify_AttachmentManager"
        }, 
        {
            "Count": 15820, 
            "Lasthit": "2020-01-02 07:22:46", 
            "TagName": "Cygwin", 
            "PublicTagName": "490082.Cygwin"
        }, 
        {
            "Count": 7233, 
            "Lasthit": "2019-12-30 12:31:47", 
            "TagName": "SecureCRT", 
            "PublicTagName": "490082.SecureCRT"
        }, 
        {
            "Count": 13855, 
            "Lasthit": "2020-01-02 05:55:01", 
            "TagName": "Add_PKI_Cert_or_CA", 
            "PublicTagName": "490082.Add_PKI_Cert_or_CA"
        }, 
        {
            "Count": 40197, 
            "Lasthit": "2020-01-01 09:17:34", 
            "TagName": "Add_IE_EnhancedSecurityConfig", 
            "PublicTagName": "46640.Add_IE_EnhancedSecurityConfig"
        }, 
        {
            "Count": 35839, 
            "Lasthit": "2020-01-01 06:11:35", 
            "TagName": "WiresharkPCAP_DLL", 
            "PublicTagName": "490082.WiresharkPCAP_DLL"
        }, 
        {
            "Count": 6582, 
            "Lasthit": "2019-12-30 06:28:59", 
            "TagName": "ArdamaxKeyLogger", 
            "PublicTagName": "46640.ArdamaxKeyLogger"
        }, 
        {
            "Count": 26159, 
            "Lasthit": "2019-12-30 15:18:59", 
            "TagName": "Pastebin_Dropper", 
            "PublicTagName": "490082.Pastebin_Dropper"
        }, 
        {
            "Count": 24331, 
            "Lasthit": "2020-01-02 01:04:47", 
            "TagName": "Sandboxie", 
            "PublicTagName": "490082.Sandboxie"
        }, 
        {
            "Count": 6137, 
            "Lasthit": "2020-01-01 17:50:37", 
            "TagName": "FTP_Suspicious", 
            "PublicTagName": "490082.FTP_Suspicious"
        }, 
        {
            "Count": 9793, 
            "Lasthit": "2020-01-02 05:02:33", 
            "TagName": "AppCertDLL_Persistence_LoadDLL", 
            "PublicTagName": "490082.AppCertDLL_Persistence_LoadDLL"
        }, 
        {
            "Count": 2578, 
            "Lasthit": "2020-01-01 21:28:20", 
            "TagName": "MSIEXEC_Web_Install", 
            "PublicTagName": "46640.MSIEXEC_Web_Install"
        }
    ]
}
```

##### Human Readable Output
##### Search Top Tags Results is in progress:
|Count|Lasthit|Public Tag Name|Tag Name|
|---|---|---|---|
| 84674 | 2020-01-02 05:22:18 | 490082.Pastebin_Raw | Pastebin_Raw |
| 25288 | 2020-01-01 18:36:12 | 46640.ServiceDllUnloadOnStop | ServiceDllUnloadOnStop |
| 20912 | 2020-01-01 16:09:10 | 104.hupigon_mutex | hupigon_mutex |
| 68694 | 2020-01-01 19:18:09 | 490082.Modify_ComputerName | Modify_ComputerName |
| 18740 | 2020-01-01 07:09:55 | 490082.Modify_TermServ_RDP | Modify_TermServ_RDP |
| 53921 | 2020-01-02 00:02:21 | 46640.Modify_Permission | Modify_Permission |
| 11078 | 2020-01-02 07:40:39 | 490082.MSOfficeResiliency | MSOfficeResiliency |
| 18857 | 2020-01-01 10:06:58 | 490082.SecurityProviders_Persistence_LoadDLL | SecurityProviders_Persistence_LoadDLL |
| 100001 | 2019-06-20 12:59:58 | 490082.Modify_AttachmentManager | Modify_AttachmentManager |
| 15820 | 2020-01-02 07:22:46 | 490082.Cygwin | Cygwin |
| 7233 | 2019-12-30 12:31:47 | 490082.SecureCRT | SecureCRT |
| 13855 | 2020-01-02 05:55:01 | 490082.Add_PKI_Cert_or_CA | Add_PKI_Cert_or_CA |
| 40197 | 2020-01-01 09:17:34 | 46640.Add_IE_EnhancedSecurityConfig | Add_IE_EnhancedSecurityConfig |
| 35839 | 2020-01-01 06:11:35 | 490082.WiresharkPCAP_DLL | WiresharkPCAP_DLL |
| 6582 | 2019-12-30 06:28:59 | 46640.ArdamaxKeyLogger | ArdamaxKeyLogger |
| 26159 | 2019-12-30 15:18:59 | 490082.Pastebin_Dropper | Pastebin_Dropper |
| 24331 | 2020-01-02 01:04:47 | 490082.Sandboxie | Sandboxie |
| 6137 | 2020-01-01 17:50:37 | 490082.FTP_Suspicious | FTP_Suspicious |
| 9793 | 2020-01-02 05:02:33 | 490082.AppCertDLL_Persistence_LoadDLL | AppCertDLL_Persistence_LoadDLL |
| 2578 | 2020-01-01 21:28:20 | 46640.MSIEXEC_Web_Install | MSIEXEC_Web_Install |


### Get the reputation for an IP address
---
Returns the reputation of an IP address.

##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| IP.Address | String | The IP address. | 
| AutoFocus.IP.IndicatorValue | String | The IP address value. | 
| AutoFocus.IP.IndicatorType | String | The indicator type. | 
| AutoFocus.IP.LatestPanVerdicts | Unknown | The latest verdicts from Palo Alto Networks products. Can be either "PAN_DB" or "WF_SAMPLE"(WildFire). | 
| IP.Malicious.Vendor | String | The vendor that decided the file is malicious. | 
| AutoFocus.IP.Tags.PublicTagName | String | The public name of the tag. This is used as the tag ID. | 
| AutoFocus.IP.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.IP.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.IP.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.IP.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.IP.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.IP.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.IP.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.IP.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.IP.Tags.Description | String | The description of the tag. | 


##### Command Example
```
!ip ip=127.0.0.1 using-brand="AutoFocus V2"
```

##### Context Example
```
{
    "AutoFocus.IP": [
        {
            "SeenBy": [], 
            "LatestPanVerdicts": {
                "PAN_DB": "BENIGN"
            }, 
            "WildfireRelatedSampleVerdictCounts": {}, 
            "IndicatorValue": "127.0.0.1", 
            "IndicatorType": "IPV4_ADDRESS"
        }
    ], 
    "IP": [
        {
            "Address": "127.0.0.1"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "AutoFocus V2", 
            "Indicator": "127.0.0.1", 
            "Score": 1, 
            "Type": "ip"
        }
    ]
}
```

##### Human Readable Output
##### AutoFocus V2 IP reputation for: 127.0.0.1
|Indicatortype|Indicatorvalue|Latestpanverdicts|Seenby|Wildfirerelatedsampleverdictcounts|
|---|---|---|---|---|
| IPV4_ADDRESS | 127.0.0.1 | PAN_DB: BENIGN |  |  |


### Get the reputation of a URL
---
Returns the reputation of a URL.

##### Base Command

`url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| URL.Data | String | The URL address. | 
| AutoFocus.URL.IndicatorValue | String | The URL value. | 
| AutoFocus.URL.IndicatorType | String | The indicator type. | 
| AutoFocus.URL.LatestPanVerdicts | Unknown |The latest verdicts from Palo Alto Networks products. Can be either "PAN_DB" or "WF_SAMPLE"(WildFire). | 
| URL.Malicious.Vendor | String | The vendor that decided the file is malicious. | 
| AutoFocus.URL.Tags.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.URL.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.URL.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.URL.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.URL.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.URL.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.URL.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.URL.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.URL.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.URL.Tags.Description | String | The description of the tag. | 


##### Command Example
```
!url url=www.andromedaa.ir/ir/andromedaa/likebegir/ap.smali/ using-brand="AutoFocus V2"
```

##### Context Example
```
{
    "URL": [
        {
            "Malicious": {
                "Vendor": "AutoFocus V2"
            }, 
            "Data": "www.andromedaa.ir/ir/andromedaa/likebegir/ap.smali/"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "AutoFocus V2", 
            "Indicator": "www.andromedaa.ir/ir/andromedaa/likebegir/ap.smali/", 
            "Score": 3, 
            "Type": "url"
        }
    ], 
    "AutoFocus.URL": [
        {
            "SeenBy": [], 
            "LatestPanVerdicts": {
                "PAN_DB": "MALWARE"
            }, 
            "WildfireRelatedSampleVerdictCounts": {}, 
            "IndicatorValue": "www.andromedaa.ir/ir/andromedaa/likebegir/ap.smali/", 
            "IndicatorType": "URL"
        }
    ]
}
```

##### Human Readable Output
##### AutoFocus V2 URL reputation for: www<span>.andromedaa.ir/ir/andromedaa/likebegir/ap.smali/
|Indicatortype|Indicatorvalue|Latestpanverdicts|Seenby|Wildfirerelatedsampleverdictcounts|
|---|---|---|---|---|
| URL | www<span>.andromedaa.ir/ir/andromedaa/likebegir/ap.smali/ | PAN_DB: MALWARE |  |  |


### Get the reputation of a file
---
Returns the reputation of a file.

##### Base Command

`file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The SHA256 hash of the file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| AutoFocus.File.IndicatorValue | String | The SHA256 hash value of the file. | 
| AutoFocus.File.IndicatorType | String | The indicator type. | 
| AutoFocus.File.LatestPanVerdicts | Unknown | The latest verdicts from Palo Alto Networks products. Can be either "PAN_DB" or "WF_SAMPLE"(WildFire). | 
| File.Malicious.Vendor | String | The vendor that decided the file is malicious. | 
| AutoFocus.File.Tags.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.File.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.File.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.File.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.File.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.File.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.File.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.File.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.File.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.File.Tags.Description | String | The description of the tag. | 


##### Command Example
```
!file file=9040e9fda52931c9472c90ecad5b74295cdb9cf7b68e2b89219700f6a8bff5ac using-brand="AutoFocus V2"
```

##### Context Example
```
{
    "DBotScore": [
        {
            "Vendor": "AutoFocus V2", 
            "Indicator": "9040e9fda52931c9472c90ecad5b74295cdb9cf7b68e2b89219700f6a8bff5ac", 
            "Score": 3, 
            "Type": "file"
        }
    ], 
    "File": [
        {
            "Malicious": {
                "Vendor": "AutoFocus V2"
            }, 
            "SHA256": "9040e9fda52931c9472c90ecad5b74295cdb9cf7b68e2b89219700f6a8bff5ac"
        }
    ], 
    "AutoFocus.File": [
        {
            "SeenBy": [
                "WF_SAMPLE"
            ], 
            "LatestPanVerdicts": {
                "WF_SAMPLE": "MALWARE"
            }, 
            "WildfireRelatedSampleVerdictCounts": "", 
            "IndicatorType": "FILEHASH", 
            "IndicatorValue": "9040e9fda52931c9472c90ecad5b74295cdb9cf7b68e2b89219700f6a8bff5ac", 
            "LastSeen": "2019-12-29T08:52:27.000Z", 
            "FirstSeen": "2019-09-24T06:46:21.000Z"
        }
    ]
}
```

##### Human Readable Output

##### AutoFocus V2 File reputation for: 9040e9fda52931c9472c90ecad5b74295cdb9cf7b68e2b89219700f6a8bff5ac

|Firstseen|Indicatortype|Indicatorvalue|Lastseen|Latestpanverdicts|Seenby|Wildfirerelatedsampleverdictcounts|
|---|---|---|---|---|---|---|
| 2019-09-24T06:46:21.000Z | FILEHASH | 9040e9fda52931c9472c90ecad5b74295cdb9cf7b68e2b89219700f6a8bff5ac | 2019-12-29T08:52:27.000Z | WF_SAMPLE: MALWARE | WF_SAMPLE |  |


### Get the reputation of a domain name
---
Returns the reputation of a domain.

##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to check. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Domain.Name | String | The name of the domain. | 
| AutoFocus.Domain.IndicatorValue | String | The value of the domain. | 
| AutoFocus.Domain.IndicatorType | String | The indicator type. | 
| AutoFocus.Domain.LatestPanVerdicts | Unknown | The latest verdicts from Palo Alto Networks products. Can be either "PAN_DB" or "WF_SAMPLE"(WildFire). | 
| Domain.Malicious.Vendor | String | The vendor that decided the file is malicious. | 
| AutoFocus.Domain.Tags.PublicTagName | String | The public name of the tag. This is used as an ID of the tag. | 
| AutoFocus.Domain.Tags.TagName | String | The simple name of the tag. | 
| AutoFocus.Domain.Tags.CustomerName | String | The organization that created the tag. | 
| AutoFocus.Domain.Tags.Source | String | The organization or individual that discovered the threat that is defined in the tag. | 
| AutoFocus.Domain.Tags.TagDefinitionScopeID | Number | The scope ID of the tag. | 
| AutoFocus.Domain.Tags.TagDefinitionStatusID | Number | The definition status ID of the tag. | 
| AutoFocus.Domain.Tags.TagClassID | Number | The classification ID of the tag. | 
| AutoFocus.Domain.Tags.Count | Number | The number of samples that matched this tag. | 
| AutoFocus.Domain.Tags.Lasthit | Date | The date that the tag was last encountered. | 
| AutoFocus.Domain.Tags.Description | String | The description of the tag. | 
| AutoFocus.Domain.WhoisAdminCountry | String | The country of the domain administrator. | 
| AutoFocus.Domain.WhoisAdminEmail | String | The email address of the domain administrator. | 
| AutoFocus.Domain.WhoisAdminName | String | The name of the domain administrator. | 
| AutoFocus.Domain.WhoisDomainCreationDate | Date | The date that the domain was created. | 
| AutoFocus.Domain.WhoisDomainExpireDate | Date | The date that the domain expires. | 
| AutoFocus.Domain.WhoisDomainUpdateDate | Date | The date that the domain was last updated. | 
| AutoFocus.Domain.WhoisRegistrar | String | The name of the registrar. | 
| AutoFocus.Domain.WhoisRegistrarUrl | String | The email address of the registrar. | 
| AutoFocus.Domain.WhoisRegistrant | String | The name of the registrant. | 


##### Command Example
```
!domain domain=google.com using-brand="AutoFocus V2"
```

##### Context Example
```
{
    "Domain": [
        {
            "Name": "google.com", 
            "WHOIS": {
                "Admin": {
                    "Email": null, 
                    "Name": null
                }, 
                "UpdatedDate": "2018-02-21", 
                "Registrar": {
                    "Name": "MarkMonitor Inc."
                }, 
                "ExpirationDate": "2020-09-14", 
                "CreationDate": "1997-09-15", 
                "Registrant": {
                    "Name": null
                }
            }
        }
    ], 
    "AutoFocus.Domain": [
        {
            "SeenBy": [], 
            "LatestPanVerdicts": {
                "PAN_DB": "BENIGN"
            }, 
            "WhoisAdminName": null, 
            "WhoisDomainExpireDate": "2020-09-14", 
            "WhoisRegistrarUrl": "http://www.markmonitor.com", 
            "WildfireRelatedSampleVerdictCounts": {}, 
            "IndicatorType": "DOMAIN", 
            "WhoisRegistrant": null, 
            "WhoisRegistrar": "MarkMonitor Inc.", 
            "IndicatorValue": "google.com", 
            "WhoisAdminEmail": null, 
            "WhoisDomainCreationDate": "1997-09-15", 
            "WhoisAdminCountry": null, 
            "WhoisDomainUpdateDate": "2018-02-21"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "AutoFocus V2", 
            "Indicator": "google.com", 
            "Score": 1, 
            "Type": "domain"
        }
    ]
}
```

##### Human Readable Output
##### AutoFocus V2 Domain reputation for: google.com
|Indicatortype|Indicatorvalue|Latestpanverdicts|Seenby|Whoisadmincountry|Whoisadminemail|Whoisadminname|Whoisdomaincreationdate|Whoisdomainexpiredate|Whoisdomainupdatedate|Whoisregistrant|Whoisregistrar|Whoisregistrarurl|Wildfirerelatedsampleverdictcounts|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| DOMAIN | google.com | PAN_DB: BENIGN |  |  |  |  | 1997-09-15 | 2020-09-14 | 2018-02-21 |  | MarkMonitor Inc. | http:/<span>/ww<span>w.<span>markmonitor.com |  |
