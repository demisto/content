URLhaus has the goal of sharing malicious URLs that are being used for malware distribution.
This integration was integrated and tested with version xx of URLhaus

## Configure URLhaus on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for URLhaus.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://192.168.0.1) |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Create relationships |  | False |
    | Maximum number of relationships to fetch per indicator | Maximum relationships to display\(Max 1000\). | False |
    | Blacklists appearances threshold |  | False |
    | Compromised (is malicious) |  | False |
    | Number of retries | Determines how many times a command should be retried before raising an error. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### url
***
Retrieves URL information from URLhaus.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | string | The URL. | 
| URL.Malicious.Vendor | string | Vendor that reported the URL as malicious. | 
| URL.Malicious.Description | string | Description of the malicious URL. | 
| URL.Tags | string | A list of tags associated with the queried malware URL. | 
| URL.Relationships | Unknown | A list of Relationships associated with the queried malware URL\(Optional on configurtion\). | 
| URLhaus.URL.ID | String | Unique identifier of the URLhaus database entry. | 
| URLhaus.URL.Status | String | The current status of the URL. | 
| URLhaus.URL.Host | String | The extracted host of the malware URL \(IP address or domain name/FQDN\). | 
| URLhaus.URL.DateAdded | date | Date the URL was added to URLhaus. | 
| URLhaus.URL.Threat | String | The threat corresponding to this malware URL. | 
| URLhaus.URL.Blacklist.Name | String | Name of the block list. | 
| URLhaus.URL.Tags | String | A list of tags associated with the queried malware URL. | 
| URLhaus.URL.Payload.Name | String | Payload file name. | 
| URLhaus.URL.Payload.Type | String | Payload file type. | 
| URLhaus.URL.Payload.MD5 | String | MD5 hash of the HTTP response body \(payload\). | 
| URLhaus.URL.Payload.VT.Result | Number | VirusTotal results for the payload. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URLhaus.URL.Blacklist.Status | String | Status of the URL in the block list. | 
| URLhaus.URL.Payload.VT.Link | String | Link to the VirusTotal report. | 

#### Command example
```!url using-brand=URLhaus url=http://ekamjewels.com/anklet/WQG1/?i=1```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://ekamjewels.com/anklet/WQG1/?i=1",
        "Reliability": "C - Fairly reliable",
        "Score": 2,
        "Type": "url",
        "Vendor": "URLhaus"
    },
    "URL": {
        "Data": "http://ekamjewels.com/anklet/WQG1/?i=1",
        "Relationships": [
            {
                "EntityA": "http://ekamjewels.com/anklet/WQG1/?i=1",
                "EntityAType": "URL",
                "EntityB": "ekamjewels.com",
                "EntityBType": "Domain",
                "Relationship": "hosted-on"
            }
        ],
        "Tags": [
            "doc",
            "emotet",
            "epoch5",
            "heodo",
            "malware_download"
        ]
    },
    "URLhaus": {
        "URL": {
            "Blacklist": [
                {
                    "Name": "spamhaus_dbl",
                    "Status": "not listed"
                },
                {
                    "Name": "surbl",
                    "Status": "not listed"
                }
            ],
            "DateAdded": "2022-01-20T14:11:09",
            "Host": "ekamjewels.com",
            "ID": "1992762",
            "Payload": [
                {
                    "MD5": "716c3aa1e0da98b6e99cadd60363ae7e",
                    "Name": "BC-77388.xlsm",
                    "SHA256": "64c6ba33444e5db3cc9c99613d04fd163ec1971ee5eb90041a17068e37578fc0",
                    "Type": "xls",
                    "VT": null
                },
                {
                    "MD5": "28c162c2ac1be8966682e66d232cc977",
                    "Name": "949_9540.xlsm",
                    "SHA256": "b0e9d2148a1c5ad60a5ccbc0c8b753f7c81e298cac18059db3c3ed66a04d4068",
                    "Type": "xls",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/b0e9d2148a1c5ad60a5ccbc0c8b753f7c81e298cac18059db3c3ed66a04d4068/detection/f-b0e9d21",
                        "Result": 25.86
                    }
                },
                {
                    "MD5": "40a87ae0ee6c9d8647c8ad1b680e0e87",
                    "Name": "JSB-67.xlsm",
                    "SHA256": "4170fd2e1e20be004dc4fb1490bd16ce9bd092ec9d1048e6ac0a63d10c7ba255",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/4170fd2e1e20be004dc4fb1490bd16ce9bd092ec9d1048e6ac0a63d10c7ba255/detection/f-4170fd2",
                        "Result": 30.16
                    }
                },
                {
                    "MD5": "4323e90b4bc4c3754f447763164a3387",
                    "Name": "2370353.xlsm",
                    "SHA256": "9bb2ebea9b5a85ffd22e2f2f97a07e9367ddc5ddcaa086c8903c57212273548b",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/9bb2ebea9b5a85ffd22e2f2f97a07e9367ddc5ddcaa086c8903c57212273548b/detection/f-9bb2ebe",
                        "Result": 35
                    }
                },
                {
                    "MD5": "742f6e804a1c9af4d762e03f1a707b6e",
                    "Name": "677726_182.xlsm",
                    "SHA256": "df43427d915757b0932c26b7029a6f1bd5602383b04d075ce0ad95f40b1c2e19",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "462b51cc9c502f99d6b8791de721d143",
                    "Name": "632_13290.xlsm",
                    "SHA256": "f7f344862e543ce22b540ef4bbab44ac1dbd786c224550cb5ecbee3380403ab7",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/f7f344862e543ce22b540ef4bbab44ac1dbd786c224550cb5ecbee3380403ab7/detection/f-f7f3448",
                        "Result": 34.48
                    }
                },
                {
                    "MD5": "26f97cbc3e5b2b87f0f9efe1bfd0d3cd",
                    "Name": "BA-2012.xlsm",
                    "SHA256": "eee95e3bcd72a2d0932acc8c6e46e6b0a4d95a39ab028da3b0c11e294e0faa89",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/eee95e3bcd72a2d0932acc8c6e46e6b0a4d95a39ab028da3b0c11e294e0faa89/detection/f-eee95e3",
                        "Result": 26.98
                    }
                },
                {
                    "MD5": "113ba77773d87c505faf124c5ca4c161",
                    "Name": "67982_721.xlsm",
                    "SHA256": "733af54ba0a2878f86abc471d5388ac61f838211959a4444ca6307819c4860d7",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/733af54ba0a2878f86abc471d5388ac61f838211959a4444ca6307819c4860d7/detection/f-733af54",
                        "Result": 28.57
                    }
                },
                {
                    "MD5": "cd7a6da12697f937963a4364a85aad3d",
                    "Name": "63-9279.xlsm",
                    "SHA256": "6b4e80411216eff0629dfc0ce6788afc2578e22f48613a0664edb46f621d746a",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/6b4e80411216eff0629dfc0ce6788afc2578e22f48613a0664edb46f621d746a/detection/f-6b4e804",
                        "Result": 29.51
                    }
                },
                {
                    "MD5": "6868995464ecbec8b2538ca6424bf89f",
                    "Name": "E-9101422.xlsm",
                    "SHA256": "4765164204e734a59822149f062f898117d41dbbb26a969800d8fc36e80a9a49",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/4765164204e734a59822149f062f898117d41dbbb26a969800d8fc36e80a9a49/detection/f-4765164",
                        "Result": 27.42
                    }
                },
                {
                    "MD5": "11b212d0230b0c500c3ff5cc7f2c1de0",
                    "Name": "0831900-069.xlsm",
                    "SHA256": "8293affd245bca747939f06a07970c40d349524f0e57a8037bbb78d7b6d04263",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "0b7502fa49459f1a6a45e5d75c6fea7f",
                    "Name": "20194_93355059.xlsm",
                    "SHA256": "8b6c3d1c1c4f0194ac14f20217620719ae9888660cfc5b07fdc42970e6fd377e",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "6b8364305b9e8143bc9378627dc86a13",
                    "Name": "565458_764084.xlsm",
                    "SHA256": "79d21212ede80612cecd2e319424918b3f95dd07e305e99bb3f4941ab60ff2c4",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "5e6f82addbf661520a8cebdc94c576d4",
                    "Name": "48549_28217733.xlsm",
                    "SHA256": "655e69dfaf74c3a34eb02d75f4e51264009fbdbe46a7f535b9e72888bffeaf58",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "091c24760470154fc629ef6287b439ad",
                    "Name": "lbqtc745.xlsm",
                    "SHA256": "345075974a633202c20da7f744cce921ae20061720ea5d27a474adcc15258a56",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "8aa82a5703895c55944d89cf3dfa7473",
                    "Name": "TZTB_9695687.xlsm",
                    "SHA256": "5e0d6d63ac743de0bb942f5367315786752d13884fc04124a4b8f577a3f8bca9",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/5e0d6d63ac743de0bb942f5367315786752d13884fc04124a4b8f577a3f8bca9/detection/f-5e0d6d6",
                        "Result": 24.19
                    }
                },
                {
                    "MD5": "5202e55e479e864ea6d611c9e0403004",
                    "Name": "54357995936345.xlsm",
                    "SHA256": "19b1cb4bcc5006f6fe58960a449aa850117383b7e330f8e58035510f3be23149",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/19b1cb4bcc5006f6fe58960a449aa850117383b7e330f8e58035510f3be23149/detection/f-19b1cb4",
                        "Result": 18.52
                    }
                },
                {
                    "MD5": "02876dcf84a6cb85690c7181f030ce4f",
                    "Name": "XL_91494.xlsm",
                    "SHA256": "c21af06b5a5f866a493669336f0c0d2d4d981faeab18708879be631c5b4f3c55",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "e4294e77f0931e216b6d6f88a570711d",
                    "Name": "LIO_1115263.xlsm",
                    "SHA256": "72053ec5fe9ba65c857235179e8529eec75c3aba924b386ecf41b34729d0935b",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "476cdcf69204ff4712577341b2a94fd2",
                    "Name": "5073455YDHJVZWRCN_744.xlsm",
                    "SHA256": "8a12bb899a8c477155c5aae284050416300acb42d4b3c7da672f8e12bdee8ec4",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/8a12bb899a8c477155c5aae284050416300acb42d4b3c7da672f8e12bdee8ec4/detection/f-8a12bb8",
                        "Result": 22.22
                    }
                },
                {
                    "MD5": "2f7b903ea5ac35e3c0f4ffcceb00879e",
                    "Name": "5621632WYRRSZKB5643.xlsm",
                    "SHA256": "0f5d70d653951694aacfdbae441a87340e2689247cc1dc79852a86d5c8e7dd2b",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "0ab3886fac07f4a3e697059f3754f5c5",
                    "Name": "KME_93.xlsm",
                    "SHA256": "aa778c3fafe2327bc81ba1c4963a5ee8354aeb750a96e8ce5f4d0392df3ddd4a",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "e5c603c3d574376892c74f29649d0be4",
                    "Name": "v_58.xlsm",
                    "SHA256": "442da867e6d871fad0d4e472ef48bd2ca7ac41ef601355875379056453ccf42d",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/442da867e6d871fad0d4e472ef48bd2ca7ac41ef601355875379056453ccf42d/detection/f-442da86",
                        "Result": 23.81
                    }
                },
                {
                    "MD5": "5d7582da050c043976e9e48caa78465b",
                    "Name": "33507_34741.xlsm",
                    "SHA256": "97a52b68f8d7ad41ba580f95749d7d810ce3fab98d8ea92461adfee77cfa9203",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/97a52b68f8d7ad41ba580f95749d7d810ce3fab98d8ea92461adfee77cfa9203/detection/f-97a52b6",
                        "Result": 25.4
                    }
                },
                {
                    "MD5": "0cc88a3cf97c97107753ef0a03738724",
                    "Name": "PMX-26632688.xlsm",
                    "SHA256": "782f99cf1c019d48f827fb6d29e75c842fceea0423bbddd81620697d366bfeee",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/782f99cf1c019d48f827fb6d29e75c842fceea0423bbddd81620697d366bfeee/detection/f-782f99c",
                        "Result": 24.19
                    }
                },
                {
                    "MD5": "a6aca8e1b881dd3bc8333ff146342ebb",
                    "Name": "UIFEH_30255.xlsm",
                    "SHA256": "200e8f491dade178eca83bd109426425ffe7ca9d4baf974a204e3835c56ceb2e",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/200e8f491dade178eca83bd109426425ffe7ca9d4baf974a204e3835c56ceb2e/detection/f-200e8f4",
                        "Result": 21.31
                    }
                },
                {
                    "MD5": "b04d9303595449350d50074dcbf7131c",
                    "Name": "33245-1.xlsm",
                    "SHA256": "aec2322328224504e216bae76697e68ec37167ececb7693615d72235044bf28f",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/aec2322328224504e216bae76697e68ec37167ececb7693615d72235044bf28f/detection/f-aec2322",
                        "Result": 23.81
                    }
                },
                {
                    "MD5": "f810ffd27fcd0ead2df9e06d2510d65c",
                    "Name": "6797254.xlsm",
                    "SHA256": "46dadb348869cda14d38466d791ebf6c906f5ec26cc305fdca50921785f48b20",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/46dadb348869cda14d38466d791ebf6c906f5ec26cc305fdca50921785f48b20/detection/f-46dadb3",
                        "Result": 23.81
                    }
                },
                {
                    "MD5": "4dc46c624c684f6657312500dc4b8a98",
                    "Name": "07212924AGJGPTBBYU05289694.xlsm",
                    "SHA256": "6b010b591c50b68c8101ed6ffe62e903c6501ae17d1b430a904288c1391d4482",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "0bd0bb6e3b99c184dc8b8a58d2b5f58d",
                    "Name": "XO_19811.xlsm",
                    "SHA256": "5eb512924e585833ee9f0111efd74c3e3ced26d8a78db2b71d87bb6c9f684791",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/5eb512924e585833ee9f0111efd74c3e3ced26d8a78db2b71d87bb6c9f684791/detection/f-5eb5129",
                        "Result": 29.51
                    }
                },
                {
                    "MD5": "73f53ef5defbdc91948bde6b2a396553",
                    "Name": "0175646932481825.xlsm",
                    "SHA256": "f3af1bae6675bb7eff796079a60c5a67ec86892f1c09053d2c25fe7d9fcee836",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/f3af1bae6675bb7eff796079a60c5a67ec86892f1c09053d2c25fe7d9fcee836/detection/f-f3af1ba",
                        "Result": 29.03
                    }
                },
                {
                    "MD5": "f453a87f954b2f0fd5458d8de9686751",
                    "Name": "275866_567.xlsm",
                    "SHA256": "b1551887350e6e3d73f1d159a97f121cdb3d5b3d9f151de703c313f247958248",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "185faedc676470df1240fa0b0dc377c2",
                    "Name": "13975200.xlsm",
                    "SHA256": "f3f1542a86bb2d668046714e3987278506d3308023b1cb398efa9573d2da7776",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/f3f1542a86bb2d668046714e3987278506d3308023b1cb398efa9573d2da7776/detection/f-f3f1542",
                        "Result": 23.81
                    }
                },
                {
                    "MD5": "e3d5be98c00a8e3a8d203fa438324b43",
                    "Name": "HF-789038.xlsm",
                    "SHA256": "1bccdaed8a9d03e7c5a5f0ecd9ca25e942077d1be538087e6451cc3030e37b8d",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/1bccdaed8a9d03e7c5a5f0ecd9ca25e942077d1be538087e6451cc3030e37b8d/detection/f-1bccdae",
                        "Result": 30.51
                    }
                },
                {
                    "MD5": "1b3b9885b4613c3a910d6d48bd960e20",
                    "Name": "UMT334701182.xlsm",
                    "SHA256": "7429c9e25f9d5b509f78af97a0f595fac9ce8122ad4788c17087360e06521b2f",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "7ce33aa19156dabe0de21f35d7aebea7",
                    "Name": "912_9650.xlsm",
                    "SHA256": "f48ce531d75c5080dd92c721b92678a75a2be77b9c53d1a33d5539c695d1e614",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/f48ce531d75c5080dd92c721b92678a75a2be77b9c53d1a33d5539c695d1e614/detection/f-f48ce53",
                        "Result": 23.81
                    }
                },
                {
                    "MD5": "9171c3964424a8d3fc7c61e0922e8d2d",
                    "Name": "ONR_4.xlsm",
                    "SHA256": "8ca261137fec414bb9066e12a3b88f3872e87a71d57134c1ee8331a7c0590965",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/8ca261137fec414bb9066e12a3b88f3872e87a71d57134c1ee8331a7c0590965/detection/f-8ca2611",
                        "Result": 22.58
                    }
                },
                {
                    "MD5": "b8422df85fc3c4057c3ab3e44349667a",
                    "Name": "4799332MHQOACHHYP_7.xlsm",
                    "SHA256": "47b55d5918804812bdc25923b93b4d42f3f5fb005f755266aba09ace6d636e20",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "455b85c6d1b14906b00a9ecdc129a425",
                    "Name": "UI_012.xlsm",
                    "SHA256": "54dd7b43faf6af4521533712663354a19b6793199ff1fd6b355828448b1cce66",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/54dd7b43faf6af4521533712663354a19b6793199ff1fd6b355828448b1cce66/detection/f-54dd7b4",
                        "Result": 27.42
                    }
                },
                {
                    "MD5": "41962a58b7c506bdb1b59ce47d3c7f5b",
                    "Name": "JFD-129861.xlsm",
                    "SHA256": "7805fd902552d2c362cec5d35c3ab11be2ecd01d5932757e4f175b5f9d21ba1f",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/7805fd902552d2c362cec5d35c3ab11be2ecd01d5932757e4f175b5f9d21ba1f/detection/f-7805fd9",
                        "Result": 26.98
                    }
                },
                {
                    "MD5": "a5ae387cc6338656ba677717f7d9f77a",
                    "Name": "30011TGXQVUXKMJ_27.xlsm",
                    "SHA256": "8f1383b4d7504257b4e3da2743e895eead15a36132d6bac13452a546fd20bbdb",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/8f1383b4d7504257b4e3da2743e895eead15a36132d6bac13452a546fd20bbdb/detection/f-8f1383b",
                        "Result": 28.57
                    }
                },
                {
                    "MD5": "d706cd9ba00a821f662fb8a1902f997e",
                    "Name": "JLBGK_666.xlsm",
                    "SHA256": "619c3ee3590e414b2de3333ff07b4cb2df3c76fc7512468d4a6499833db70078",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/619c3ee3590e414b2de3333ff07b4cb2df3c76fc7512468d4a6499833db70078/detection/f-619c3ee",
                        "Result": 23.81
                    }
                },
                {
                    "MD5": "e419a3f9fe729a45f3d79b317ea17c0a",
                    "Name": "NECK55.xlsm",
                    "SHA256": "88390a46879f6c9ff67152cbf22d1868e9edb89c0724e1e144a789c73f69b086",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/88390a46879f6c9ff67152cbf22d1868e9edb89c0724e1e144a789c73f69b086/detection/f-88390a4",
                        "Result": 28.57
                    }
                },
                {
                    "MD5": "9246f49ad69cd0c491249372aed3ac9d",
                    "Name": "N8498.xlsm",
                    "SHA256": "1cfe5e523eb76253a7b3270d91f99f4998ab8ad60ec974444451ef69632a0d29",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/1cfe5e523eb76253a7b3270d91f99f4998ab8ad60ec974444451ef69632a0d29/detection/f-1cfe5e5",
                        "Result": 29.03
                    }
                },
                {
                    "MD5": "f4801affba0846a72f829ae6927d038d",
                    "Name": "3655728501.xlsm",
                    "SHA256": "05aeb3fe4bd3f690ebe97d33014d66f3adc9e4a7517507d6df3be40dcbea26d4",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/05aeb3fe4bd3f690ebe97d33014d66f3adc9e4a7517507d6df3be40dcbea26d4/detection/f-05aeb3f",
                        "Result": 26.98
                    }
                },
                {
                    "MD5": "d7d61c64a0bd1e25a4e4b88415ebee80",
                    "Name": "MBAXH-6088.xlsm",
                    "SHA256": "17fec23004233b510f24a66fbfbff83304bf565e4138fa85b44c7b80d9dfcbaf",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/17fec23004233b510f24a66fbfbff83304bf565e4138fa85b44c7b80d9dfcbaf/detection/f-17fec23",
                        "Result": 26.98
                    }
                },
                {
                    "MD5": "9ec4ceba47b6a7f0397f2db8988fa829",
                    "Name": "5713_997.xlsm",
                    "SHA256": "57933fa64877cd7abbc18abd28ab60ac340b94c4f00445e8b98851108d6706e1",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/57933fa64877cd7abbc18abd28ab60ac340b94c4f00445e8b98851108d6706e1/detection/f-57933fa",
                        "Result": 28.57
                    }
                },
                {
                    "MD5": "b203a3e982189bb62745ecc562e28391",
                    "Name": "qxouc-33296.xlsm",
                    "SHA256": "8440eb113e9093c7bb2f228ac7cd77334e4168cbb32dd19d86f2f49cc3466da7",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/8440eb113e9093c7bb2f228ac7cd77334e4168cbb32dd19d86f2f49cc3466da7/detection/f-8440eb1",
                        "Result": 29.51
                    }
                },
                {
                    "MD5": "3b76b89d32efe802283c6a56227e7e25",
                    "Name": "738663949083.xlsm",
                    "SHA256": "42eefcfe7fff0afcdc0bca565d1d1dd9cfaae1167d9d0a9ca49e0389d53ed46d",
                    "Type": "xlsm",
                    "VT": null
                },
                {
                    "MD5": "d5b31c6b64e9d8301335eab74bd9962f",
                    "Name": "590217569-802.xlsm",
                    "SHA256": "a75d803a646fa5cfa41b0489c6de355e62319450b46d41792b4b5b3cd21a0dc3",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/a75d803a646fa5cfa41b0489c6de355e62319450b46d41792b4b5b3cd21a0dc3/detection/f-a75d803",
                        "Result": 29.03
                    }
                },
                {
                    "MD5": "77fdb63f8590bc13dad3be2ef8d3f7cf",
                    "Name": "W48105705.xlsm",
                    "SHA256": "19d1c6a37f4b01531b66ec4b77e6479907d637b4bd18431ace83635eb4d07afa",
                    "Type": "xlsm",
                    "VT": {
                        "Link": "https://www.virustotal.com/gui/file/19d1c6a37f4b01531b66ec4b77e6479907d637b4bd18431ace83635eb4d07afa/detection/f-19d1c6a",
                        "Result": 30.16
                    }
                }
            ],
            "Status": "offline",
            "Tags": [
                "doc",
                "emotet",
                "epoch5",
                "heodo",
                "malware_download"
            ],
            "Threat": "malware_download"
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for http:<span>//</span>ekamjewels.com/anklet/WQG1/?i=1
>|Date added|Description|Status|Threat|URLhaus ID|URLhaus link|
>|---|---|---|---|---|---|
>| 2022-01-20T14:11:09 | The URL is inadctive (offline) and serving no payload | offline | malware_download | 1992762 | https:<span>//</span>urlhaus.abuse.ch/url/1992762/ |


### domain
***
Retrieves domain information from URLhaus.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example, google.com. | 
| Domain.Tags | string | A list of tags associated with the queried malware Domain. | 
| Domain.Relationships | Unknown | A list of Relationships associated with the queried malware Domain\(Optional on configurtion\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URLhaus.Domain.FirstSeen | Date | Date that the IP was seen for the first time \(UTC\). | 
| URLhaus.Domain.Blacklist.Name | String | The status of the domain in different block lists. | 
| URLhaus.Domain.URL | String | URLs observed on this domain. | 
| Domain.Malicious.Vendor | String | Vendor that reported the domain as malicious. | 
| Domain.Malicious.Description | String | Description of the malicious domain. | 
| URLhaus.Domain.Blacklist.Status | String | Status of the URL in the block list. | 

#### Command example
```!domain using-brand=URLhaus domain=reunionesdecabales.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "reunionesdecabales.com",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "domain",
        "Vendor": "URLhaus"
    },
    "Domain": {
        "Name": "reunionesdecabales.com",
        "Relationships": [
            {
                "EntityA": "reunionesdecabales.com",
                "EntityAType": "Domain",
                "EntityB": "http://reunionesdecabales.com:443/wp-content/plugins/wp-roilbask/includes/",
                "EntityBType": "URL",
                "Relationship": "hosts"
            }
        ],
        "Tags": [
            "malware"
        ]
    },
    "URLhaus": {
        "Domain": {
            "Blacklist": {
                "spamhaus_dbl": "abused_legit_malware",
                "surbl": "not listed"
            },
            "FirstSeen": "2022-01-27T12:51:03",
            "URL": [
                {
                    "date_added": "2022-01-28 04:41:03 UTC",
                    "id": "2010874",
                    "larted": "false",
                    "reporter": "Cryptolaemus1",
                    "tags": [
                        "IcedID"
                    ],
                    "takedown_time_seconds": null,
                    "threat": "malware_download",
                    "url": "http://reunionesdecabales.com:443/wp-content/plugins/wp-roilbask/includes/",
                    "url_status": "offline",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/2010874/"
                },
                {
                    "date_added": "2022-01-27 12:51:05 UTC",
                    "id": "2009328",
                    "larted": "true",
                    "reporter": "Cryptolaemus1",
                    "tags": [
                        "bazaloader",
                        "IcedID"
                    ],
                    "takedown_time_seconds": null,
                    "threat": "malware_download",
                    "url": "http://reunionesdecabales.com/wp-content/plugins/wp-roilbask/includes/",
                    "url_status": "online",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/2009328/"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for reunionesdecabales.com
>|Description|First seen|URLhaus link|
>|---|---|---|
>| There is no information about Domain in the blacklist | 2022-01-27T12:51:03 | https:<span>//</span>urlhaus.abuse.ch/host/reunionesdecabales.com/ |


### file
***
Retrieves file information from URLhaus.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | MD5 hash or SHA256 hash of the file to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | File size \(in bytes\). | 
| File.MD5 | String | MD5 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.SSDeep | string | SSDeep of the file. | 
| File.Type | stringd | Type of the file. | 
| File.Relationships | Unknown | A list of Relationships associated with the queried malware file\(Optional on configurtion\). | 
| URLhaus.File.MD5 | String | MD5 hash of the file. | 
| URLhaus.File.SHA256 | String | SHA256 hash of the file. | 
| URLhaus.File.Type | String | File type guessed by URLhaus, for example: .exe, .doc. | 
| URLhaus.File.Size | Number | File size \(in bytes\). | 
| URLhaus.File.Signature | String | Malware family. | 
| URLhaus.File.FirstSeen | Date | Date and time \(UTC\) that URLhaus first saw this file \(payload\). | 
| URLhaus.File.LastSeen | Date | Date and time \(UTC\) that URLhaus last saw this file \(payload\). | 
| URLhaus.File.DownloadLink | String | Location \(URL\) where you can download a copy of this file. | 
| URLhaus.File.VirusTotal.Percent | Number | AV detection \(percentage\), for example: 24.14. | 
| URLhaus.File.VirusTotal.Link | String | Link to the VirusTotal report. | 
| URLhaus.File.URL | Unknown | A list of malware URLs associated with this payload \(max. 100\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example
```!file using-brand=URLhaus file=254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b```
#### Context Example
```json
{
    "DBotScore": {
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)": {
            "Indicator": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
            "Reliability": "C - Fairly reliable",
            "Score": 3,
            "Type": "file",
            "Vendor": "URLhaus"
        }
    },
    "File": {
        "MD5": "a820381c8acf07cfcb4d9b13498db71d",
        "Relationships": [
            {
                "EntityA": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
                "EntityAType": "File",
                "EntityB": "Gozi",
                "EntityBType": "Malware",
                "Relationship": "indicator-of"
            }
        ],
        "SHA256": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
        "SSDeep": "1536:HL8ZkobQKXYG8I9WHVIIVLfldAjoaEgnell/SYkq59L48eKq0P:gnIHVxtsjp5s/7kq59MP0",
        "Size": 125952,
        "Type": "exe"
    },
    "URLhaus": {
        "File": {
            "DownloadLink": "https://urlhaus-api.abuse.ch/v1/download/254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b/",
            "FirstSeen": "2019-01-02T12:42:23",
            "LastSeen": "2019-01-02T13:13:25",
            "MD5": "a820381c8acf07cfcb4d9b13498db71d",
            "SHA256": "254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
            "Signature": "Gozi",
            "Size": 125952,
            "Type": "exe",
            "URL": [
                {
                    "filename": null,
                    "firstseen": "2019-01-02",
                    "lastseen": "2019-01-02",
                    "url": "http://185.189.149.164/adobe_update.exe",
                    "url_id": "100211",
                    "url_status": "offline",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/100211/"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### URLhaus reputation for SHA256 : 254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b
>|First seen|Last seen|MD5|SHA256|Signature|URLhaus link|
>|---|---|---|---|---|---|
>| 2019-01-02T12:42:23 | 2019-01-02T13:13:25 | a820381c8acf07cfcb4d9b13498db71d | 254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b | Gozi | https://urlhaus-api.abuse.ch/v1/download/254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b/ |


### urlhaus-download-sample
***
Downloads a malware sample from URLhaus.


#### Base Command

`urlhaus-download-sample`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | SHA256 hash of the file to download. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Name | string | File name. | 
| File.SSDeep | string | SSDeep hash of the file. | 
| File.EntryID | string | File entry ID. | 
| File.Info | string | File information. | 
| File.Type | string | File type. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.Extension | string | File extension. | 

#### Command example
```!urlhaus-download-sample file=254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b```
#### Human Readable Output

>```
>{
>    "HumanReadable": "No results for SHA256: 254ca6a7a7ef7f17d9884c4a86f88b5d5fd8fe5341c0996eaaf1d4bcb3b2337b",
>    "HumanReadableFormat": "markdown",
>    "Type": 1
>}
>```
