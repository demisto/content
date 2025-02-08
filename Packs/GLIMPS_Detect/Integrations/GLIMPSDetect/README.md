Use the GLIMPS Detect Integration to send files to GLIMPS Malware and get results from it
This integration was integrated and tested with version 0.2.0 of gdetect client.

## Configure GLIMPS Detect in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Token |  | True |
| URL |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| First Fetch Time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| Fetch Limit | Maximum number of alerts per fetch. Default and recommended is 50 | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gdetect-send
***
send file to gDetect API.


#### Base Command

`gdetect-send`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | EntryID of the file to send. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLIMPS.Gdetect.Send.UUID | string | GLIMPS Detect Binary UUID. | 
| GLIMPS.Gdetect.Send.entryID | string | XSOAR file entryID. | 

#### Command example
```!gdetect-send entryID=1@042262f2-6a12-44da-8e11-74cf4bc67063```
#### Context Example
```json
{
    "GLIMPS": {
        "GDetect": {
            "Send": {
                "entryID": "1@042262f2-6a12-44da-8e11-74cf4bc67063",
                "uuid": "23465d22-3464-39ce-b8b3-bc2ee7d6eecf"
            }
        }
    }
}
```

#### Human Readable Output

>## GLIMPS.GDetect.UUID: 23465d22-3464-39ce-b8b3-bc2ee7d6eecf

### gdetect-get-all
***
get all file analysis from gDetect API.


#### Base Command

`gdetect-get-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | GLIMPS Detect Binary UUID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLIMPS.GDetect.All.uuid | String | Unique analysis identifier | 
| GLIMPS.GDetect.All.sha256 | String | string hex encoded input file SHA256 | 
| GLIMPS.GDetect.All.sha1 | String | string hex encoded input file SHA1 | 
| GLIMPS.GDetect.All.md5 | String | string hex encoded input file MD5 | 
| GLIMPS.GDetect.All.ssdeep | String | string input file SSDeep | 
| GLIMPS.GDetect.All.is_malware | Boolean | analysis result, is a malware or not | 
| GLIMPS.GDetect.All.score | Number | highest score given by probes | 
| GLIMPS.GDetect.All.done | Boolean | is the analysis finished | 
| GLIMPS.GDetect.All.timestamp | Number | timestamp of the start of analysis in milliseconds | 
| GLIMPS.GDetect.All.filetype | String | input file type | 
| GLIMPS.GDetect.All.size | Number | input file size \(in bytes\) | 
| GLIMPS.GDetect.All.filenames | String | list of analysed filename | 
| GLIMPS.GDetect.All.malwares | String | list of malware names found in analysis | 
| GLIMPS.GDetect.All.files | String | array of submission files \(input file and extracted sub-files\) | 
| GLIMPS.GDetect.All.files.sha256 | String | string hex encoded input file SHA256 | 
| GLIMPS.GDetect.All.files.sha1 | String | string hex encoded input file SHA1 | 
| GLIMPS.GDetect.All.files.md5 | String | string hex encoded input file MD5 | 
| GLIMPS.GDetect.All.files.ssdeep | String | string hex encoded input file MD5 | 
| GLIMPS.GDetect.All.files.magic | String | file magic - file type | 
| GLIMPS.GDetect.All.files.size | Number | input file size \(in bytes\) | 
| GLIMPS.GDetect.All.files.is_malware | Boolean | analysis result, is a malware or not | 
| GLIMPS.GDetect.All.files.av_results.av | String | probe name | 
| GLIMPS.GDetect.All.files.av_results.result | String | malware name indicated by probe | 
| GLIMPS.GDetect.All.files.av_results.score | Number | amount of point added by the probe | 
| GLIMPS.GDetect.All.link | String | a link to the analysis in the GLIMPS Malware Expert interface | 
| GLIMPS.GDetect.All.file_count | Number | amount of file in the submission \(input \+ extracted\) | 
| GLIMPS.GDetect.All.duration | Number | duration of the analysis in milliseconds | 
| GLIMPS.GDetect.All.token | String | Authentication token for the lite api | 
| GLIMPS.GDetect.All.threats.filenames | String | list of analysed filename | 
| GLIMPS.GDetect.All.threats | String | Summary of threats found in submission. Each submission file reaching threshold score will add an entry. Entry keys are the SHA256 of files | 
| GLIMPS.GDetect.All.threats.tags | String | Summary of threats found in submission. Each submission file reaching threshold score will add an entry. Entry keys are the SHA256 of files | 
| GLIMPS.GDetect.All.threats.tags.name | String | tag name | 
| GLIMPS.GDetect.All.threats.tags.value | String | tag value | 
| GLIMPS.GDetect.All.threats.score | Number | highest score given by probes | 
| GLIMPS.GDetect.All.threats.magic | String | file magic - file type | 
| GLIMPS.GDetect.All.threats.sha256 | String | string hex encoded input file SHA256 | 
| GLIMPS.GDetect.All.threats.sha1 | String | string hex encoded input file SHA1 | 
| GLIMPS.GDetect.All.threats.md5 | String | string hex encoded input file MD5 | 
| GLIMPS.GDetect.All.threats.ssdeep | String | string input file SSDeep | 
| GLIMPS.GDetect.All.threats.file_size | Number | input file size \(in bytes\) | 
| GLIMPS.GDetect.All.threats.mime | String | file mime type | 
| GLIMPS.GDetect.All.status | Boolean | true =&gt; no error to report, false =&gt; an error occurred | 

#### Command example
```!gdetect-get-all uuid=23465d22-3464-39ce-b8b3-bc2ee7d6eecf```
#### Context Example
```json
{
    "GLIMPS": {
        "GDetect": {
            "All": {
                "uuid": "23465d22-3464-39ce-b8b3-bc2ee7d6eecf",
                "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
                "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
                "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
                "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
                "is_malware": True,
                "score": 4000,
                "done": True,
                "timestamp": 1651157541588,
                "filetype": "exe",
                "size": 219648,
                "filenames": [
                        "sha256"
                ],
                "malwares": [
                    "Win.Ransomware.Buhtrap-9865977-0",
                    "TR/Redcap.ltkcp",
                    "Mal/Behav-010"
                ],
                "files": [
                    {
                        "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
                        "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
                        "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
                        "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
                        "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
                        "av_results": [
                            {
                                "av": "SignatureOyster",
                                "result": "Win.Ransomware.Buhtrap-9865977-0",
                                "score": 1000
                            },
                            {
                                    "av": "SignatureUmbrella",
                                    "result": "TR/Redcap.ltkcp",
                                    "score": 1000
                            },
                            {
                                    "av": "SignatureSophos",
                                    "result": "Mal/Behav-010",
                                    "score": 1000
                            }
                        ],
                        "size": 219648,
                        "is_malware": True
                    },
                    {
                        "sha256": "bd52eb164e64e6316791a8c260689b8ca0bf54440fa629edc05f6d4c301faec",
                        "sha1": "d0333bf36f7bd1bdc1b2110e0a55e608ec378577",
                        "md5": "5edb7d7e63f80d657e975628add89cd3",
                        "ssdeep": "99:JKXtFmZan3KNhTP+5oXlNbAuC5mDDtUEDPUmgXSM:JMFkNhy1qlNkPDDzPcF",
                        "magic": "data",
                        "size": 6144,
                        "is_malware": False
                    },
                    {
                        "sha256": "f9c00d396b73fc4b4d05c518a7c9eddbed35462270d2ae5e31380fe5ca0f0c67",
                        "sha1": "d5cfd73469f053c4ec8cd34d7a81baaf4e6d5068",
                        "md5": "5a58f4825aa4cc6ce9098c20dcc99448",
                        "ssdeep": "98:WuuR8iHj18usiDdeKvg3nbNqCH7FazFT3jCDomhCuorfhHSEdP2pVUVi7P1uH:Q6ijDUsEg0nf5CCo0Cu054VUViCu",
                        "magic": "data",
                        "size": 6144,
                        "is_malware": False
                    }
                ],
                "link": "http://gdetect-instance.lan/expert/en/analysis-redirect/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.J1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiXSwic2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70TPCjClnOp_2_339XqMXk0TbPJhSN2uE",
                "file_count": 3,
                "duration": 8268,
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.J1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiXSwic2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70TPCjClnOp_2_339XqMXk0TbPJhSN2uE",
                "threats": {
                    "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31": {
                        "filenames": [
                            "23465d22-3464-39ce-b8b3-bc2ee7d6eecf"
                        ],
                        "tags": [
                            {
                                "name": "av.virus_name",
                                "value": "Mal/Behav-010"
                            },
                            {
                                "name": "attribution.family",
                                "value": "win_vegalocker_auto"
                            },
                            {
                                "name": "av.virus_name",
                                "value": "win_vegalocker_auto"
                            },
                            {
                                "name": "av.virus_name",
                                "value": "Win.Ransomware.Buhtrap-9865977-0"
                            },
                            {
                                "name": "av.virus_name",
                                "value": "TR/Redcap.ltkcp"
                            }
                        ],
                        "score": 4000,
                        "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
                        "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
                        "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
                        "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
                        "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
                        "file_size": 219648,
                        "mime": "application/x-dosexec"
                    }
                },
                "status": True
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|done|duration|file_count|filenames|filetype|is_malware|link|malwares|md5|score|sha1|sha256|size|ssdeep|status|timestamp|token|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | 8268 | 3 | sha256 | exe | true | https:<span>//</span>gdetect-instance.lan/expert/en/analysis-redirect/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.J1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiXSwic2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70TPCjClnOp_2_339XqMXk0TbPJhSN2uE | Win.Ransomware.Buhtrap-9865977-0,<br/>TTR/Redcap.ltkcp,<br/>Mal/Behav-010 | c24d410c7e7d4b6066e09ceee057fbf9 | 4000 | 2159b8d8b985f32641314220bb24126747b71d13 | 005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31 | 219648 | 6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnGK | true | 1651157541588 | eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.J1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiXSwic2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70TPCjClnOp_2_339XqMXk0TbPJhSN2uE | 23465d22-3464-39ce-b8b3-bc2ee7d6eecf |
>### File
>|sha256|sha1|md5|ssdeep|magic|size|is_malware|
>|---|---|---|---|---|---|---|
>| 005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31 | 2159b8d8b985f32641314220bb24126747b71d13 | c24d410c7e7d4b6066e09ceee057fbf9 | 6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG | E32 executable (GUI) Intel 80386, for MS Windowss | 219648 | true |
>### AV Result for 020dac2b02fd8df13e8782aa3aa85eb28f3dba4193dd5fecacee4905ede8fa6a
>|av|result|score|
>|---|---|---|
>| SignatureOyster | Win.Ransomware.Buhtrap-9865977-0 | 1000 |
>| SignatureUmbrella | TR/Redcap.ltkcp | 1000 |
>| SignatureSophos | Mal/Behav-010 | 1000 |
>### File
>|sha256|sha1|md5|ssdeep|magic|size|is_malware|
>|---|---|---|---|---|---|---|
>| bd52eb164e64e6316791a8c260689b8ca0bf54440fa629edc05f6d4c301faec | d0333bf36f7bd1bdc1b2110e0a55e608ec378577 | 5edb7d7e63f80d657e975628add89cd3 | 99:JKXtFmZan3KNhTP+5oXlNbAuC5mDDtUEDPUmgXSM:JMFkNhy1qlNkPDDzPcF | data | 6144 | false |
>### File
>|sha256|sha1|md5|ssdeep|magic|size|is_malware|
>|---|---|---|---|---|---|---|
>| f9c00d396b73fc4b4d05c518a7c9eddbed35462270d2ae5e31380fe5ca0f0c67 | d5cfd73469f053c4ec8cd34d7a81baaf4e6d5068 | 5a58f4825aa4cc6ce9098c20dcc99448 | 98:WuuR8iHj18usiDdeKvg3nbNqCH7FazFT3jCDomhCuorfhHSEdP2pVUVi7P1uH:Q6ijDUsEg0nf5CCo0Cu054VUViCu | data | 6144 | false |
>### Threat 005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31
>|filenames|score|magic|sha256|sha1|md5|ssdeep|file_size|mime|
>|---|---|---|---|---|---|---|---|---|
>| 23465d22-3464-39ce-b8b3-bc2ee7d6eecf | 4000 | PE32 executable (GUI) Intel 80386, for MS Windows | 005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31 | 2159b8d8b985f32641314220bb24126747b71d13 | c24d410c7e7d4b6066e09ceee057fbf9 | 6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG | 219648 | application/x-dosexec |
>### Tags of threat 005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31
>|name|value|
>|---|---|
>| av.virus_name | Troj/Krypt-DY |
>| attribution.family | win_vegalocker_auto |
>| av.virus_name | win_vegalocker_auto |
>| av.virus_name | Win.Ransomware.Buhtrap-9865977-0 |
>| av.virus_name | TR/Redcap.ltkcp |


### gdetect-get-threats
***
get threats results for file analysis from gDetect API.


#### Base Command

`gdetect-get-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | GLIMPS Detect Binary UUID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GLIMPS.GDetect.Threats.filenames | String | list of analysed filename | 
| GLIMPS.GDetect.Threats.link | String | a link to the analysis in the GLIMPS Malware Expert interface | 
| GLIMPS.GDetect.Threats | String | Summary of threats found in submission. Each submission file reaching threshold score will add an entry. Entry keys are the SHA256 of files | 
| GLIMPS.GDetect.Threats.tags | String | Summary of threats found in submission. Each submission file reaching threshold score will add an entry. Entry keys are the SHA256 of files | 
| GLIMPS.GDetect.Threats.tags.name | String | tag name | 
| GLIMPS.GDetect.Threats.tags.value | String | tag value | 
| GLIMPS.GDetect.Threats.score | Number | highest score given by probes | 
| GLIMPS.GDetect.Threats.magic | String | file magic - file type | 
| GLIMPS.GDetect.Threats.sha256 | String | string hex encoded input file SHA256 | 
| GLIMPS.GDetect.Threats.sha1 | String | string hex encoded input file SHA1 | 
| GLIMPS.GDetect.Threats.md5 | String | string hex encoded input file MD5 | 
| GLIMPS.GDetect.Threats.ssdeep | String | string input file SSDeep | 
| GLIMPS.GDetect.Threats.file_size | Number | input file size \(in bytes\) | 
| GLIMPS.GDetect.Threats.mime | String | file mime type | 

#### Command example
```!gdetect-get-threats uuid=23465d22-3464-39ce-b8b3-bc2ee7d6eecf```
#### Context Example
```json
{
    "GLIMPS": {
        "GDetect": {
            "Threats": {
                "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31": {
                    "filenames": [
                        "23465d22-3464-39ce-b8b3-bc2ee7d6eecf"
                    ],
                    "tags": [
                        {
                            "name": "av.virus_name",
                            "value": "Mal/Behav-010"
                        },
                        {
                            "name": "attribution.family",
                            "value": "win_vegalocker_auto"
                        },
                        {
                            "name": "av.virus_name",
                            "value": "win_vegalocker_auto"
                        },
                        {
                            "name": "av.virus_name",
                            "value": "Win.Ransomware.Buhtrap-9865977-0"
                        },
                        {
                            "name": "av.virus_name",
                            "value": "TR/Redcap.ltkcp"
                        }
                    ],
                    "score": 4000,
                    "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
                    "sha256": "005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31",
                    "sha1": "2159b8d8b985f32641314220bb24126747b71d13",
                    "md5": "c24d410c7e7d4b6066e09ceee057fbf9",
                    "ssdeep": "6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG",
                    "file_size": 219648,
                    "mime": "application/x-dosexec"
                },
                "link": "http://gdetect-instance.lan/expert/en/analysis-redirect/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.J1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiXSwic2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70TPCjClnOp_2_339XqMXk0TbPJhSN2uE",
                "uuid": "23465d22-3464-39ce-b8b3-bc2ee7d6eecf"
            }
        }
    }
}
```

#### Human Readable Output

>### Threat 020dac2b02fd8df13e8782aa3aa85eb28f3dba4193dd5fecacee4905ede8fa6a
>|filenames|score|magic|sha256|sha1|md5|ssdeep|file_size|mime|
>|---|---|---|---|---|---|---|---|---|
>| 23465d22-3464-39ce-b8b3-bc2ee7d6eecf | 4000 | PE32 executable (GUI) Intel 80386, for MS Windows | 005b00d41749f7b0336d4d5fe0402dcfc95ae0df44a2231a89a59919eeb30b31 | 2159b8d8b985f32641314220bb24126747b71d13 | c24d410c7e7d4b6066e09ceee057fbf9 | 6153:KyJE1yd7WHJmcyfjtPWna8DQFu/U3buRKlemZ9DnGAevIhdi++:KU/d7WsvBPWa9DQFu/U3buRKlemZ9DnG | 219648 | application/x-dosexec |
>### Tags of threat 020dac2b02fd8df13e8782aa3aa85eb28f3dba4193dd5fecacee4905ede8fa6a
>|name|value|
>|---|---|
>| av.virus_name | Mal/Behav-010 |
>| attribution.family | win_vegalocker_auto |
>| av.virus_name | win_vegalocker_auto |
>| av.virus_name | Win.Ransomware.Buhtrap-9865977-0 |
>| av.virus_name | TR/Redcap.ltkcp |
>[Link to the analysis in the GLIMPS Malware Expert interface](https://gdetect-instance.lan/expert/en/analysis-redirect/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ6.J1c2VybmFtZSI6ImFwaS10YW8ndWl0ZXN0IiwiZ7JvdXBzIjpbInRhbmd1aXRlc3QiXSwic2lkIjoiN2d6WUNzWDRSNmp6bHlaQzNpZXJLWSIsImV4cCI4MTY1MzgwNzgwOSwiaWF3IjoxNjUxMjE3ODA2fQ.EGk75tKwAq70TPCjClnOp_2_339XqMXk0TbPJhSN2uE)