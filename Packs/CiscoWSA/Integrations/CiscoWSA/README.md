Cisco WSA
This integration was integrated and tested with version vSeries-100 of Cisco-WSA

## Configure CiscoWSA in Cortex


| **Parameter** | **Required** |
| --- | --- |
| BASE_URL | True |
| API_KEY | True |
| PORT | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### wsa-get-access-policies
***
Retrieving all access policies


#### Base Command

`wsa-get-access-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| wsa.AccessPolicies | string | Retrieving all access policies | 


#### Command Example
```!wsa-get-access-policies```

#### Context Example
```json
{
    "access_policies": [
        {
            "amw_reputation": {
                "state": "use_global"
            },
            "avc": {
                "state": "use_global"
            },
            "http_rewrite_profile": "use_global",
            "membership": {
                "identification_profiles": [
                    {
                        "profile2": {
                            "auth": "No Authentication"
                        }
                    }
                ],
                "protocols": [
                    {
                        "id_profile": "profile2",
                        "value": [
                            "http",
                            "https",
                            "ftp"
                        ]
                    }
                ]
            },
            "objects": {
                "state": "use_global"
            },
            "policy_description": "",
            "policy_expiry": "",
            "policy_name": "policy2",
            "policy_order": 1,
            "policy_status": "enable",
            "protocols_user_agents": {
                "state": "use_global"
            },
            "url_filtering": {
                "custom_cats": {
                    "use_global": [
                        "SocialURLCategorynader1"
                    ]
                },
                "exception_referred_embedded_content": {
                    "state": "disable"
                },
                "state": "custom",
                "update_cats_action": "use_global",
                "yt_cats": {
                    "use_global": [
                        "Film & Animation",
                        "Autos & Vehicles",
                        "Music",
                        "Pets & Animals",
                        "Sports",
                        "Travel & Events",
                        "Gaming",
                        "People & Blogs",
                        "Comedy",
                        "Entertainment",
                        "News & Politics",
                        "Howto & Style",
                        "Education",
                        "Science & Technology",
                        "Nonprofits & Activism"
                    ]
                }
            }
        },
        {
            "amw_reputation": {
                "state": "use_global"
            },
            "avc": {
                "state": "use_global"
            },
            "http_rewrite_profile": "use_global",
            "membership": {
                "identification_profiles": [
                    {
                        "profile1": {
                            "auth": "No Authentication"
                        }
                    }
                ],
                "protocols": [
                    {
                        "id_profile": "profile1",
                        "value": [
                            "http",
                            "https",
                            "ftp"
                        ]
                    }
                ]
            },
            "objects": {
                "state": "use_global"
            },
            "policy_description": "",
            "policy_expiry": "",
            "policy_name": "policy1",
            "policy_order": 2,
            "policy_status": "enable",
            "protocols_user_agents": {
                "state": "use_global"
            },
            "url_filtering": {
                "custom_cats": {
                    "use_global": [
                        "SocialURLCategorynader1"
                    ]
                },
                "exception_referred_embedded_content": {
                    "state": "disable"
                },
                "state": "custom",
                "update_cats_action": "use_global",
                "yt_cats": {
                    "use_global": [
                        "Film & Animation",
                        "Autos & Vehicles",
                        "Music",
                        "Pets & Animals",
                        "Sports",
                        "Travel & Events",
                        "Gaming",
                        "People & Blogs",
                        "Comedy",
                        "Entertainment",
                        "News & Politics",
                        "Howto & Style",
                        "Education",
                        "Science & Technology",
                        "Nonprofits & Activism"
                    ]
                }
            }
        },
        {
            "amw_reputation": {
                "state": "use_global"
            },
            "avc": {
                "state": "use_global"
            },
            "http_rewrite_profile": "use_global",
            "membership": {
                "identification_profiles": [
                    {
                        "profile2": {
                            "auth": "No Authentication"
                        }
                    }
                ],
                "protocols": [
                    {
                        "id_profile": "profile2",
                        "value": [
                            "http",
                            "https",
                            "ftp"
                        ]
                    }
                ]
            },
            "objects": {
                "state": "use_global"
            },
            "policy_description": "",
            "policy_expiry": "",
            "policy_name": "nader2",
            "policy_order": 3,
            "policy_status": "enable",
            "protocols_user_agents": {
                "state": "use_global"
            },
            "url_filtering": {
                "custom_cats": {
                    "use_global": [
                        "SocialURLCategorynader1"
                    ]
                },
                "exception_referred_embedded_content": {
                    "state": "disable"
                },
                "state": "custom",
                "update_cats_action": "use_global",
                "yt_cats": {
                    "use_global": [
                        "Film & Animation",
                        "Autos & Vehicles",
                        "Music",
                        "Pets & Animals",
                        "Sports",
                        "Travel & Events",
                        "Gaming",
                        "People & Blogs",
                        "Comedy",
                        "Entertainment",
                        "News & Politics",
                        "Howto & Style",
                        "Education",
                        "Science & Technology",
                        "Nonprofits & Activism"
                    ]
                }
            }
        },
        {
            "amw_reputation": {
                "state": "use_global"
            },
            "avc": {
                "state": "use_global"
            },
            "http_rewrite_profile": "use_global",
            "membership": {
                "identification_profiles": [
                    {
                        "profile1": {
                            "auth": "No Authentication"
                        }
                    }
                ],
                "protocols": [
                    {
                        "id_profile": "profile1",
                        "value": [
                            "http",
                            "https",
                            "ftp"
                        ]
                    }
                ]
            },
            "objects": {
                "state": "use_global"
            },
            "policy_description": "",
            "policy_expiry": "",
            "policy_name": "nader1",
            "policy_order": 4,
            "policy_status": "enable",
            "protocols_user_agents": {
                "state": "use_global"
            },
            "url_filtering": {
                "custom_cats": {
                    "use_global": [
                        "SocialURLCategorynader1"
                    ]
                },
                "exception_referred_embedded_content": {
                    "state": "disable"
                },
                "state": "custom",
                "update_cats_action": "use_global",
                "yt_cats": {
                    "use_global": [
                        "Film & Animation",
                        "Autos & Vehicles",
                        "Music",
                        "Pets & Animals",
                        "Sports",
                        "Travel & Events",
                        "Gaming",
                        "People & Blogs",
                        "Comedy",
                        "Entertainment",
                        "News & Politics",
                        "Howto & Style",
                        "Education",
                        "Science & Technology",
                        "Nonprofits & Activism"
                    ]
                }
            }
        },
        {
            "amw_reputation": {
                "cisco_dvs_amw": {
                    "amw_scanning": {
                        "amw_scan_status": "disable",
                        "amw_scanners": {
                            "mcafee": "unavailable",
                            "sophos": "unavailable",
                            "webroot": "unavailable"
                        }
                    },
                    "other_categories": {},
                    "suspect_user_agent_scanning": "scan"
                },
                "web_reputation": {
                    "filtering": "unavailable"
                }
            },
            "avc": {
                "state": "unavailable"
            },
            "http_rewrite_profile": "None",
            "membership": {
                "identification_profiles": [
                    {
                        "_all_": {
                            "auth": "No Authentication"
                        }
                    }
                ]
            },
            "objects": {
                "max_object_size_mb": {
                    "ftp": 0,
                    "http_or_https": 0
                },
                "object_type": {
                    "Archives": {
                        "monitor": [
                            "StuffIt",
                            "BinHex",
                            "LHARC",
                            "ARC",
                            "ARJ"
                        ]
                    },
                    "Document Types": {
                        "monitor": [
                            "PostScript Document (PS)",
                            "OpenOffice Document",
                            "OASIS Open Document Format",
                            "Microsoft Office",
                            "XML Document",
                            "Portable Document Format (PDF)",
                            "FrameMaker Document (FM)",
                            "Rich Text Format (RTF)"
                        ]
                    },
                    "Executable Code": {
                        "monitor": [
                            "UNIX Executable",
                            "Windows Executable",
                            "Java Applet"
                        ]
                    },
                    "Inspectable Archives": {
                        "allow": [
                            "BZIP2",
                            "CPIO",
                            "7zip",
                            "RAR",
                            "LHA",
                            "ZIP Archive",
                            "GZIP",
                            "Compress Archive (Z)",
                            "TAR",
                            "Microsoft CAB"
                        ]
                    },
                    "Installers": {
                        "monitor": [
                            "UNIX/LINUX Packages"
                        ]
                    },
                    "Media": {
                        "monitor": [
                            "Photographic Images",
                            "Video",
                            "Audio"
                        ]
                    },
                    "Miscellaneous": {
                        "monitor": [
                            "Calendar Data"
                        ]
                    },
                    "P2P Metafiles": {
                        "monitor": [
                            "BitTorrent Links (.torrent)"
                        ]
                    },
                    "Web Page Content": {
                        "monitor": [
                            "Images",
                            "Flash"
                        ]
                    }
                },
                "state": "custom"
            },
            "policy_description": "Default settings",
            "policy_expiry": "",
            "policy_name": "global_policy",
            "policy_status": "enable",
            "protocols_user_agents": {
                "allow_connect_ports": [
                    "8080",
                    "21",
                    "443",
                    "563",
                    "4431",
                    "6443",
                    "8443",
                    "20",
                    "6080"
                ],
                "block_custom_user_agents": [],
                "block_protocols": [],
                "state": "custom"
            },
            "url_filtering": {
                "custom_cats": {
                    "exclude": [
                        "SocialURLCategorynader1"
                    ]
                },
                "exception_referred_embedded_content": {
                    "state": "disable"
                },
                "update_cats_action": "least restrictive",
                "yt_cats": {
                    "monitor": [
                        "Film & Animation",
                        "Autos & Vehicles",
                        "Music",
                        "Pets & Animals",
                        "Sports",
                        "Travel & Events",
                        "Gaming",
                        "People & Blogs",
                        "Comedy",
                        "Entertainment",
                        "News & Politics",
                        "Howto & Style",
                        "Education",
                        "Science & Technology",
                        "Nonprofits & Activism"
                    ]
                }
            }
        }
    ]
}
```

#### Human Readable Output

>### Results
>|access_policies|
>|---|
>|  |
>|  |
>|  |
>|  |
>|  |


### wsa-get-domain-map
***
Retrieving the Domain Map Details


#### Base Command

`wsa-get-domain-map`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| wsa.DomainMaps | string | Retrieving the Domain Map Details | 


#### Command Example
```!wsa-get-domain-map```

#### Context Example
```json
{
    "res_code": 400,
    "res_message": "The feature key for https proxy has expired or is unavailable."
}
```

#### Human Readable Output

>### Results
>|res_code|res_message|
>|---|---|
>| 400 | The feature key for https proxy has expired or is unavailable. |


### wsa-get-url-categories
***
Retrieving URL Categories


#### Base Command

`wsa-get-url-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| wsa.UrlCategories | string | Retrieving URL Categories | 


#### Command Example
```!wsa-get-url-categories```

#### Context Example
```json
{
    "custom": [
        "SocialURLCategorynader1"
    ],
    "predefined": null
}
```

#### Human Readable Output

>### Results
>|custom|predefined|
>|---|---|
>| SocialURLCategorynader1 |  |


### wsa-get-identification-profiles
***
Modifying identification profiles


#### Base Command

`wsa-get-identification-profiles`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| wsa.Profiles | string | Retrieving Identification Profiles | 


#### Command Example
```!wsa-get-identification-profiles```

#### Context Example
```json
{
    "identification_profiles": [
        {
            "description": "",
            "identification_method": {},
            "members": {
                "protocols": [
                    "http",
                    "https",
                    "ftp"
                ]
            },
            "order": 1,
            "profile_name": "profile2",
            "status": "enable"
        },
        {
            "description": "",
            "identification_method": {},
            "members": {
                "protocols": [
                    "http",
                    "https",
                    "ftp"
                ]
            },
            "order": 2,
            "profile_name": "profile1",
            "status": "enable"
        },
        {
            "description": "Default settings",
            "identification_method": {},
            "profile_name": "global_identification_profile",
            "status": "enable"
        }
    ]
}
```

#### Human Readable Output

>### Results
>|identification_profiles|
>|---|
>|  |
>|  |
>|  |


### wsa-modify-access-policies
***
Modifying an Access Policy


#### Base Command

`wsa-modify-access-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyname | Name of the policy. Unique identifier of the policy. | Required | 
| profile_name | (profile_name, auth). Use "No Authentication" in case of no authentication required for the specific profile. Empty strings represents "global identification profile". _all_ represents "All identification profiles".  Please  all inputs comma separated. | Required | 
| auth | (profile_name,auth). Use "No Authentication" in case of no authentication required for the specific profile. Empty strings represents "global identification profile". _all_ represents "All identification profiles".  Please  all inputs comma separated. | Required | 
| policy_order | Index of this specific profile in the collection. Its starts from 1. Order of policy in collection of policies. Not applicable for global_policy. | Required | 
| policy_status | Whether profile is enabled or disabled. Possible values: enable, disable. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| wsa.response | string | whether the result indicates if request is success or failure | 


#### Command Example
```!wsa-modify-access-policies policyname=policy1 profile_name=profile1 policy_order=2 policy_status=disable auth="No Authentication"```

#### Context Example
```json
{
    "wsa": {
        "response": "The modifying request has been processed successfully and all the given access policies are updated with the given payload"
    }
}
```

#### Human Readable Output

>### Results
>|wsa|
>|---|
>|  |


### wsa-delete-access-policies
***
Deleting an Access Policy


#### Base Command

`wsa-delete-access-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy. Unique identifier of the policy. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| wsa.response | unknown | whether the result indicates if request is success or failure | 


#### Command Example
```!wsa-delete-access-policies policy_name=policy2```

#### Context Example
```json
{
    "wsa": {
        "response": "The deleting request has been processed successfully and all the given access policies are updated with the given payload"
    }
}
```

#### Human Readable Output

>### Results
>|wsa|
>|---|
>|  |
