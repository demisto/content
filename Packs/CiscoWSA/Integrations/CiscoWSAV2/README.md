Cisco Secure Web Appliance protects your organization by automatically blocking risky sites and testing unknown sites before allowing users to click on them.
This integration was integrated and tested with version 14.0.3-014 of Cisco WSA V2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-cisco-wsa-v2).

## Configure Cisco WSA V2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username | True |
| Password | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-wsa-access-policy-list

***
Retrieve access policies.
Access policies contain allowed/blocked URL categories in the network.

#### Base Command

`cisco-wsa-access-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_names | Policy names to retrieve. | Optional | 
| page | The page number of the results to retrieve.<br/>Minimum value is 1. | Optional | 
| page_size | The number of results per page. The maximum value is 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoWSA.AccessPolicy.policy_expiry | String | Policy expiry date. | 
| CiscoWSA.AccessPolicy.policy_status | String | Policy status. | 
| CiscoWSA.AccessPolicy.policy_name | String | Policy name. | 
| CiscoWSA.AccessPolicy.policy_description | String | Policy description. | 
| CiscoWSA.AccessPolicy.membership | Unknown | Identification Profiles info. | 
| CiscoWSA.AccessPolicy.objects | Unknown | Policy custom objects blocking settings. | 
| CiscoWSA.AccessPolicy.protocols_user_agents | Unknown | Policy protocols and user agents settings. | 
| CiscoWSA.AccessPolicy.http_rewrite_profile | Unknown | Policy HTTP rewrite profile settings. | 
| CiscoWSA.AccessPolicy.avc | Unknown | Application visibility and control. | 
| CiscoWSA.AccessPolicy.url_filtering | Unknown | URL filtering settings. | 
| CiscoWSA.AccessPolicy.amw_reputation | Unknown | Anti-Malware and reputation settings. | 

#### Command example
```!cisco-wsa-access-policy-list page=1 page_size=3```
#### Context Example
```json
{
    "CiscoWSA": {
        "AccessPolicy": {
            "amw_reputation": {
                "adv_malware_protection": {
                    "file_analysis": "enable",
                    "file_reputation": {
                        "monitor": [
                            "Known Malicious and High-Risk Files"
                        ]
                    },
                    "file_reputation_filtering": "enable"
                },
                "cisco_dvs_amw": {
                    "amw_scanning": {
                        "amw_scan_status": "enable"
                    },
                    "malware_categories": {
                        "monitor": [
                            "Trojan Phisher",
                            "Generic Spyware",
                            "Adware",
                            "Browser Helper Object",
                            "Hijacker",
                            "System Monitor",
                            "Trojan Downloader",
                            "Trojan Horse",
                            "Dialer",
                            "Commercial System Monitor",
                            "PUA",
                            "Other Malware",
                            "Virus",
                            "Worm",
                            "Phishing URL"
                        ]
                    },
                    "other_categories": {
                        "block": [
                            "Outbreak Heuristics"
                        ],
                        "monitor": [
                            "Encrypted File",
                            "Unscannable"
                        ]
                    },
                    "suspect_user_agent_scanning": "scan"
                },
                "web_reputation": {
                    "filtering": "enable"
                }
            },
            "avc": {
                "applications": {
                    "Blogging": {
                        "monitor": {
                            "BlogChina": {},
                            "Blogbus": {},
                            "Blogcom": {},
                            "Blogger": {},
                            "Blogster": {},
                            "Bokee": {},
                            "CNBlogs": {},
                            "DianDian": {},
                            "Disqus": {},
                            "Edublogs": {},
                            "FC2 Blog": {},
                            "HatenaBlog": {},
                            "LeiPhone": {},
                            "LiveJournal": {},
                            "LivedoorBlog": {},
                            "Lofter": {},
                            "Medium": {},
                            "Pen.io": {},
                            "SeesaaBlog": {},
                            "Tackk": {},
                            "Tumblr": {},
                            "Wordpress": {},
                            "Youdaonote": {}
                        }
                    },
                    "Collaboration": {
                        "monitor": {
                            "Answers.com": {},
                            "Baike": {},
                            "PBWorks": {},
                            "Pastebin": {},
                            "SogouBaike": {},
                            "Wikihow": {},
                            "Wikipedia": {},
                            "eHow": {}
                        }
                    },
                    "Enterprise Applications": {
                        "monitor": {
                            "Amazon S3": {},
                            "Concur": {},
                            "Microsoft Dynamics CRM": {},
                            "Salesforce": {},
                            "SharePoint": {},
                            "SugarCRM": {}
                        }
                    },
                    "Facebook": {
                        "default_bandwidth_limit": "",
                        "monitor": {
                            "Facebook Applications: Entertainment": {},
                            "Facebook Applications: Games": {},
                            "Facebook Applications: Other": {},
                            "Facebook Applications: Sports": {},
                            "Facebook Applications: Utilities": {},
                            "Facebook Events": {},
                            "Facebook General": {},
                            "Facebook Messages and Chat": {},
                            "Facebook Notes": {},
                            "Facebook Photos and Videos": {}
                        }
                    },
                    "File Sharing": {
                        "monitor": {
                            "115.com": {},
                            "4shared": {},
                            "ADrive": {},
                            "Amazon Cloud Drive": {},
                            "AxiFile": {},
                            "Baiduyun": {},
                            "BitTorrent": {},
                            "Box.net": {},
                            "DBank": {},
                            "Datei.to": {},
                            "DepositFiles": {},
                            "Docin": {},
                            "Dropbox": {},
                            "File Rio": {},
                            "FileDropper": {},
                            "FileFactory": {},
                            "FileHost.ro": {},
                            "FileServe": {},
                            "FileSnack": {},
                            "Filemail": {},
                            "Filer.cx": {},
                            "Fluxiom": {},
                            "HighTail/YouSendIt": {},
                            "ImageBam": {},
                            "Imgur": {},
                            "Issuu": {},
                            "Kuaipan": {},
                            "LeapFile": {},
                            "MediaFire": {},
                            "Megashares": {},
                            "Okurin": {},
                            "PhotoSnack": {},
                            "PutLocker": {},
                            "RayFile": {},
                            "ShareFile": {},
                            "Slideshare": {},
                            "Station8": {},
                            "TYDisk": {},
                            "TransferBigFiles": {},
                            "WeTransfer": {},
                            "Weiyun": {},
                            "Yahoo Box": {},
                            "Yunpan": {},
                            "Zbigz": {},
                            "ZippyShare": {},
                            "cloud.mail.ru": {},
                            "dl free": {},
                            "files.mail.ru": {},
                            "iCloud": {},
                            "sendspace": {}
                        }
                    },
                    "Games": {
                        "monitor": {
                            "Evony": {},
                            "Game Center": {},
                            "Hangame.co.jp": {},
                            "Pogo": {},
                            "Wii": {},
                            "games.mail.ru": {}
                        }
                    },
                    "Google+": {
                        "monitor": {
                            "Google+ General": {},
                            "Google+ Hangouts/Chat": {},
                            "Google+ Photos": {},
                            "Google+ Videos": {}
                        }
                    },
                    "Instant Messaging": {
                        "monitor": {
                            "AirAIM": {},
                            "Baiduhi": {},
                            "CGIIRC": {},
                            "Chatroulette": {},
                            "Google Talk": {},
                            "ILoveIM": {},
                            "Icq2go": {},
                            "Mail.Ru Agent": {},
                            "Mibbit": {},
                            "Sinawebuc": {},
                            "WebQQ": {},
                            "Webfetion": {},
                            "Webwangwang": {},
                            "Wechat_web": {}
                        }
                    },
                    "Internet Utilities": {
                        "monitor": {
                            "Evernote": {},
                            "Google Analytics": {},
                            "Google App Engine": {},
                            "Google Maps": {},
                            "Google Play Books": {},
                            "Google Translate": {},
                            "PlayStore": {},
                            "Yahoo Toolbar": {},
                            "eBay": {},
                            "iOS Maps": {},
                            "iOS Stock": {},
                            "iOS Weather": {}
                        }
                    },
                    "LinkedIn": {
                        "monitor": {
                            "LinkedIn Contacts": {},
                            "LinkedIn General": {},
                            "LinkedIn Inbox": {},
                            "LinkedIn Jobs": {},
                            "LinkedIn Profile": {}
                        }
                    },
                    "Media": {
                        "default_bandwidth_limit": "",
                        "monitor": {
                            "1x.com": {},
                            "500px": {},
                            "56.com": {},
                            "ASF": {},
                            "AcFun": {},
                            "Adnstream": {},
                            "BaoFeng": {},
                            "BaoMiHua": {},
                            "Break": {},
                            "ChaoXing Video": {},
                            "Dailymotion": {},
                            "Deezer": {},
                            "DeviantArt": {},
                            "Earthcam": {},
                            "Flash Video": {},
                            "Flickr": {},
                            "Fotki": {},
                            "FotoThing": {},
                            "FreeeTV": {},
                            "Funshion": {},
                            "Google Play Movie": {},
                            "Google Play Music": {},
                            "Gyao": {},
                            "Hulu": {},
                            "IMDb": {},
                            "ImageShack": {},
                            "Jango": {},
                            "KanKan": {},
                            "Ku6": {},
                            "Last.fm": {},
                            "Letv": {},
                            "Livestream": {},
                            "MPEG": {},
                            "MangoTV": {},
                            "Metacafe": {},
                            "Netflix": {},
                            "Nico Nico Douga": {},
                            "PPS.tv": {},
                            "PPTV": {},
                            "Pandora": {},
                            "Pandora TV": {},
                            "Photobucket": {},
                            "QQMusic": {},
                            "QQvideo": {},
                            "QuickTime": {},
                            "RealMedia": {},
                            "Shutterfly": {},
                            "Silverlight": {},
                            "SmugMug": {},
                            "Sohu Video": {},
                            "SoundCloud": {},
                            "StageVu": {},
                            "TinyPic": {},
                            "Tudou": {},
                            "TwitchTV": {},
                            "Ustream": {},
                            "V1cn": {},
                            "Veoh": {},
                            "Viddler": {},
                            "Vimeo": {},
                            "Winamp Remote": {},
                            "Windows Media": {},
                            "Xiami": {},
                            "YouTube": {},
                            "Youku": {},
                            "iFeng Video": {},
                            "iHeartRadio": {},
                            "iQiyi": {},
                            "m1905.com": {}
                        }
                    },
                    "Myspace": {
                        "monitor": {
                            "Myspace General": {},
                            "Myspace Music": {},
                            "Myspace Photos": {},
                            "Myspace Videos": {}
                        }
                    },
                    "Office Suites": {
                        "monitor": {
                            "Google Calendar": {},
                            "Google Drive": {},
                            "Office 365/OneDrive": {},
                            "ZOHO Docs": {}
                        }
                    },
                    "Presentation / Conferencing": {
                        "monitor": {
                            "JoinMe": {},
                            "TeamViewer": {},
                            "Techinline": {},
                            "Twiddla": {},
                            "Vyew.com": {},
                            "WebEx": {},
                            "eRoom.net": {}
                        }
                    },
                    "Proxies": {
                        "monitor": {
                            "ASProxy": {},
                            "Avoidr": {},
                            "CGIProxy": {},
                            "CamoProxy": {},
                            "CoralCDN": {},
                            "FlyProxy": {},
                            "Glype": {},
                            "Guardster": {},
                            "KProxy": {},
                            "Megaproxy": {},
                            "Other Web Proxy": {},
                            "PHPProxy": {},
                            "Proxono": {},
                            "Socks2HTTP": {},
                            "Suresome": {},
                            "Surrogafier": {},
                            "Vtunnel": {},
                            "Zelune": {}
                        }
                    },
                    "Social Networking": {
                        "monitor": {
                            "51.com": {},
                            "58.com": {},
                            "Ameba": {},
                            "AmebaPigg": {},
                            "Ask.fm": {},
                            "Badoo": {},
                            "BaiSheHui": {},
                            "Baidu Tieba": {},
                            "BaiduZhidao": {},
                            "Baixing": {},
                            "Chan4": {},
                            "Classmates": {},
                            "DaZhiHui": {},
                            "Delicious": {},
                            "Dianping": {},
                            "Digg": {},
                            "Douban": {},
                            "Foursquare": {},
                            "Ganji": {},
                            "Gewara": {},
                            "Google Groups": {},
                            "Gree": {},
                            "HatenaSpace": {},
                            "Howardforums": {},
                            "Instagram": {},
                            "Kaixin001": {},
                            "LivedoorGourmet": {},
                            "Lokalisten": {},
                            "Meetup": {},
                            "MeinVZ": {},
                            "Mixi": {},
                            "Mop.com": {},
                            "Mtime": {},
                            "Netlog": {},
                            "Odnoklassniki.Ru": {},
                            "Pinterest": {},
                            "Pixiv": {},
                            "Plaxo": {},
                            "Plurk": {},
                            "PocoCN": {},
                            "QQzone": {},
                            "Quora": {},
                            "Reddit": {},
                            "RenRen": {},
                            "Scribd": {},
                            "Seesaa": {},
                            "Slashdot": {},
                            "Snapchat": {},
                            "Sohu Weibo": {},
                            "StackOverflow": {},
                            "StayFriends": {},
                            "StumbleUpon": {},
                            "Tencent Weibo": {},
                            "Tianya": {},
                            "Tonghuashun": {},
                            "Toutiao.com": {},
                            "Twitter": {},
                            "Two Channel": {},
                            "VK": {},
                            "Viadeo": {},
                            "Weheartit": {},
                            "Weibo": {},
                            "Wetpaint": {},
                            "Wikia": {},
                            "XING": {},
                            "Yahoo Mobage": {},
                            "Yelp": {},
                            "Zhihu": {},
                            "iFeng": {},
                            "my.mail.ru": {}
                        }
                    },
                    "Software Updates": {
                        "monitor": {
                            "McAfee AutoUpdate": {},
                            "Sophos Update": {},
                            "Symantec Liveupdate": {},
                            "Trendmicro Antivirus Update": {},
                            "Windows Update": {}
                        }
                    },
                    "Webmail": {
                        "monitor": {
                            "189Mail": {},
                            "AOL Mail": {},
                            "Comcast Webmail": {},
                            "Eclipso.de Freemail": {},
                            "ExciteMailJapan": {},
                            "Eyejot": {},
                            "Fastmail": {},
                            "Freenet.de Email": {},
                            "GMX E-Mail": {},
                            "Gmail": {},
                            "Hushmail": {},
                            "Mail.Ru": {},
                            "Mail.com": {},
                            "Mail21cn": {},
                            "NeteaseMail": {},
                            "Outlook.com": {},
                            "QQMail": {},
                            "Rambler-Mail": {},
                            "SinaMail": {},
                            "SohuMail": {},
                            "T-Online.de Email": {},
                            "Tommail": {},
                            "Web.de Freemail": {},
                            "Yahoo Mail": {},
                            "Yandex Mail": {},
                            "ZOHO Mail": {}
                        }
                    },
                    "iTunes": {
                        "monitor": {
                            "iTunes Desktop": {},
                            "iTunes iPad": {},
                            "iTunes iPhone": {},
                            "iTunes iPod": {}
                        }
                    }
                }
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
                "block_custom_mime_types": [],
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
                            "XML Document",
                            "Microsoft Office",
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
                            "CPIO",
                            "7zip",
                            "RAR",
                            "LHA",
                            "GZIP",
                            "ZIP Archive",
                            "TAR",
                            "Microsoft CAB"
                        ],
                        "block": [
                            "BZIP2",
                            "Compress Archive (Z)"
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
                "content_rating": {
                    "status": "disable"
                },
                "custom_cats": {
                    "block": [
                        "test"
                    ],
                    "exclude": [
                        "Adult"
                    ]
                },
                "exception_referred_embedded_content": {
                    "state": "disable"
                },
                "predefined_cats": {
                    "monitor": [
                        "Adult",
                        "Advertisements",
                        "Alcohol",
                        "Animals and Pets",
                        "Arts",
                        "Astrology",
                        "Auctions",
                        "Business and Industry",
                        "Cannabis",
                        "Chat and Instant Messaging",
                        "Cheating and Plagiarism",
                        "Child Abuse Content",
                        "Cloud and Data Centers",
                        "Computer Security",
                        "Computers and Internet",
                        "Conventions, Conferences and Trade Shows",
                        "Cryptocurrency",
                        "Cryptomining",
                        "DIY Projects",
                        "DNS-Tunneling",
                        "Dating",
                        "Digital Postcards",
                        "Dining and Drinking",
                        "DoH and DoT",
                        "Dynamic DNS Provider",
                        "Dynamic and Residential",
                        "Education",
                        "Entertainment",
                        "Extreme",
                        "Fashion",
                        "File Transfer Services",
                        "Filter Avoidance",
                        "Finance",
                        "Freeware and Shareware",
                        "Gambling",
                        "Games",
                        "Government and Law",
                        "Hacking",
                        "Hate Speech",
                        "Health and Medicine",
                        "Humor",
                        "Hunting",
                        "Illegal Activities",
                        "Illegal Downloads",
                        "Illegal Drugs",
                        "Infrastructure and Content Delivery Networks",
                        "Internet Telephony",
                        "Internet of Things",
                        "Job Search",
                        "Lingerie and Swimsuits",
                        "Lotteries",
                        "Military",
                        "Mobile Phones",
                        "Museums",
                        "Nature and Conservation",
                        "News",
                        "Non-governmental Organizations",
                        "Non-sexual Nudity",
                        "Not Actionable",
                        "Online Communities",
                        "Online Document Sharing and Collaboration",
                        "Online Meetings",
                        "Online Storage and Backup",
                        "Online Trading",
                        "Organizational Email",
                        "Paranormal",
                        "Parked Domains",
                        "Peer File Transfer",
                        "Personal Sites",
                        "Personal VPN",
                        "Photo Search and Images",
                        "Politics",
                        "Pornography",
                        "Private IP Addresses as Host",
                        "Professional Networking",
                        "Real Estate",
                        "Recipes and Food",
                        "Reference",
                        "Regional Restricted Sites (Germany)",
                        "Regional Restricted Sites (Great Britain)",
                        "Regional Restricted Sites (Italy)",
                        "Regional Restricted Sites (Poland)",
                        "Religion",
                        "SaaS and B2B",
                        "Safe for Kids",
                        "Science and Technology",
                        "Search Engines and Portals",
                        "Sex Education",
                        "Shopping",
                        "Social Networking",
                        "Social Science",
                        "Society and Culture",
                        "Software Updates",
                        "Sports and Recreation",
                        "Streaming Audio",
                        "Streaming Video",
                        "Terrorism and Violent Extremism",
                        "Tobacco",
                        "Transportation",
                        "Travel",
                        "URL Shorteners",
                        "Weapons",
                        "Web Cache and Archives",
                        "Web Hosting",
                        "Web Page Translation",
                        "Web-based Email"
                    ]
                },
                "safe_search": {
                    "status": "disable"
                },
                "uncategorized_url": "monitor",
                "update_cats_action": "least restrictive",
                "yt_cats": {
                    "block": [
                        "Autos & Vehicles",
                        "Comedy"
                    ],
                    "monitor": [
                        "Music",
                        "Pets & Animals",
                        "Sports",
                        "Travel & Events",
                        "People & Blogs",
                        "Entertainment",
                        "News & Politics",
                        "Howto & Style",
                        "Education",
                        "Science & Technology",
                        "Nonprofits & Activism"
                    ],
                    "warn": [
                        "Film & Animation",
                        "Gaming"
                    ]
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Access Policies
>|Policy Name|Policy Status|Policy Description|
>|---|---|---|
>| global_policy | enable | Default settings |


### cisco-wsa-access-policy-create

***
Create an access policy.
This command enables you to create the access policy object. To define more settings you can use the dependencies commands:
cisco-wsa-access-policy-protocols-user-agents-update (Update the Protocols and User Agents policy for access policy).
cisco-wsa-access-policy-url-filtering-update (Update the URL filtering policy for access policy).
cisco-wsa-access-policy-applications-update (Update the applications policy for access policy. Only applicable for global_policy).
cisco-wsa-access-policy-objects-update (Update the objects policy for access policy).
cisco-wsa-access-policy-anti-malware-update (Update the anti-malware policy for access policy).

#### Base Command

`cisco-wsa-access-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name. | Required | 
| policy_status | Policy status. Possible values are: enable, disable. | Required | 
| policy_description | Policy description. | Optional | 
| policy_order | Index of the policies in the collection. | Required | 
| policy_expiry | Policy expiry date, format yyyy-MM-ddTHH:mm:ssZ, e.g., 2023-02-21T16:16:29Z. | Optional | 
| identification_profiles | Comma-separated list of valid identification profile name. (Dependencies - use cisco-wsa-identification-profiles-list command to get all the identification profiles.). | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-create policy_name=test policy_status=enable policy_description=test policy_order=1 identification_profile_name=global_identification_profile identification_profiles=test7```
#### Human Readable Output

>Created "test" access policy successfully.

### cisco-wsa-access-policy-update

***
Update the access policy.

#### Base Command

`cisco-wsa-access-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name to update. | Required | 
| new_policy_name | New policy name. | Optional | 
| policy_status | Policy status. Possible values are: enable, disable. | Optional | 
| policy_order | Index of policies in the collection. Not applicable for global_policy. | Optional | 
| policy_expiry | Policy expiry date, format yyyy-MM-ddTHH:mm:ssZ, e.g., 2023-02-21T16:16:29Z. | Optional | 
| policy_description | Policy description to update. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-update policy_name=test policy_description=test1```
#### Human Readable Output

>Updated "test" access policy successfully.

### cisco-wsa-access-policy-protocols-user-agents-update

***
Update the Protocols and User Agents policy for access policy.

#### Base Command

`cisco-wsa-access-policy-protocols-user-agents-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name to update. | Required | 
| settings_status | Settings status for the Protocols and User Agents. Possible values are: custom, use_global, disable. Default is custom. | Optional | 
| block_custom_user_agents | Comma-separated list of custom user agents to block, in regular expression format.<br/>Pattern examples:<br/>All Firefox versions: "Mozilla/.* Gecko/.* Firefox/"	<br/>Firefox versions 1.5.x: "Mozilla/.* Gecko/.* Firefox/1\.5"	<br/>All Internet Explorer versions: "Mozilla/.*compatible; MSIE"<br/>Internet Explorer version 5.5: "Mozilla/.*compatible; MSIE 5\.5"<br/>Specific user agent: Mozilla/4.0 (compatible; MSIE 5.5;): "Mozilla/4.0 \(compatible; MSIE 5.5;\)"<br/>Relevant while settings_status is custom. | Optional | 
| allow_connect_ports | Comma-separated list of HTTP connect ports.<br/>HTTP CONNECT enables applications to tunnel outbound traffic over HTTP,<br/>unless the protocol is blocked above.<br/>Traffic tunneled through HTTP CONNECT will not be scanned,<br/>except for SSL ports (specified on Security Services &gt; HTTPS Proxy)<br/>e.g. 1-65535,20,21.<br/>Relevant while settings_status is custom. | Optional | 
| block_protocols | Block network protocols. Relevant while settings_status is custom. Possible values are: ftp, http. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-protocols-user-agents-update policy_name=test block_custom_user_agents=test allow_connect_ports=22,24 block_protocols=http```
#### Human Readable Output

>Updated "test" access policy successfully.

### cisco-wsa-access-policy-url-filtering-update

***
Update the URL filtering policy for access policy.

#### Base Command

`cisco-wsa-access-policy-url-filtering-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name to update. | Required | 
| predefined_categories_action | Predefined categories action. Possible values are: block, monitor, warn. | Optional | 
| predefined_categories | Comma-separated list of predefined categories. (Dependencies - use cisco-wsa-url-categories-list command to get all the custom &amp; predefined categories.). | Optional | 
| youtube_categories_action | YouTube categories action. Possible values are: block, monitor, allow. | Optional | 
| youtube_categories | Comma-separated list of YouTube categories. | Optional | 
| custom_categories_action | Custom categories action. Possible values are: block, monitor, warn. | Optional | 
| custom_categories | Comma-separated list of custom categories. (Dependencies - use cisco-wsa-url-categories-list command to get all the custom &amp; predefined categories.). | Optional | 
| uncategorized_url | Uncategorized URL action. Possible values are: use_global, block, monitor, warn. | Optional | 
| update_categories_action | When predefined URL categories are periodically updated,<br/>new categories may be introduced, or two (or more) existing categories may be merged.<br/>Select whether the most or least restrictive action should be applied in these cases.<br/>For new categories, in Access policies,<br/>most restrictive is always Block and least restrictive is always Monitor.<br/>For merged categories, the most or least restrictive setting will be selected out of the<br/>settings previously assigned.<br/>For instance, if category A was set to Block, and category B was set to Warn,<br/>and the two are merged into category C,<br/>the most restrictive action will be Block and the least restrictive action will be Warn. Possible values are: use_global, most restrictive, least restrictive. | Optional | 
| content_rating_status | When Site Content Rating is enabled, user access to web content rated as adult oriented or<br/>explicit on sites that support content rating will be denied.<br/>Supported sites include Flickr, Craigslist and YouTube.<br/>However, users can still access content on these websites that is not rated as adult oriented or explicit. Possible values are: enable, disable. | Optional | 
| content_rating_action | Action if site setting (content_rating_status) allows adult/explicit content. Possible values are: block, warn. | Optional | 
| safe_search_status | When Safe Search is enabled, non-safe content, including the cached non-safe content<br/>will be blocked from the search result from the following search engines:<br/>Dogpile, Yandex, Google, Yahoo, Bing, WebCrawler, DuckDuckGo, Dailymotion and eBay.<br/>If safe search failed to be enforced on a supported search engine, it will be blocked. Possible values are: enable, disable. | Optional | 
| unsupported_safe_search_engine | Action for search engines that don't support safe search. Possible values are: block, monitor. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-url-filtering-update policy_name=test predefined_categories_action=monitor predefined_categories=Astrology custom_categories_action=block custom_categories=test```
#### Human Readable Output

>Updated "test" access policy successfully.

### cisco-wsa-access-policy-applications-update

***
Update applications policy for access policy. Only applicable for global_policy.

#### Base Command

`cisco-wsa-access-policy-applications-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name to update. | Required | 
| settings_status | Applications settings status. Possible values are: custom, use_global. Default is custom. | Optional | 
| application | Application type to perform the action on. Possible values are: Games, Enterprise Applications, Media, Collaboration, Instant Messaging, Facebook, Social Networking, Internet Utilities, Webmail, Proxies, Presentation / Conferencing, Software Updates, iTunes, Google+, File Sharing, Myspace, Blogging, LinkedIn, Office Suites. | Required | 
| action | Application action. Possible values are: monitor, block. | Required | 
| values | Comma-separated list of application values to perform the action on. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-applications-update policy_name=test application=Blogging action=block values=Blogger```
#### Human Readable Output

>Updated "test" access policy successfully.

### cisco-wsa-access-policy-objects-update

***
Update objects policy for access policy.

#### Base Command

`cisco-wsa-access-policy-objects-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name to update. | Required | 
| object_type | Object type to perform the action on. Possible values are: Executable Code, Web Page Content, Media, P2P Metafiles, Miscellaneous, Document Types, Archives, Installers, Inspectable Archives. | Optional | 
| object_action | Object action.<br/>Note: "inspect" and "allow" actions are only valid when the object type is "Inspectable Archives". Possible values are: monitor, block, allow, inspect. | Optional | 
| object_values | Comma-separated list of object values to perform the action on. | Optional | 
| block_custom_mime_types | Block custom MIME types, e.g., audio/x-mpeg3 or audio/*. | Optional | 
| http_or_https_max_object_size_mb | HTTP/HTTPS maximum download size. | Optional | 
| ftp_max_object_size_mb | FTP maximum download size. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-objects-update policy_name=test object_type=Media object_action=block object_values=Audio http_or_https_max_object_size_mb=30 ftp_max_object_size_mb=20```
#### Human Readable Output

>Updated "test" access policy successfully.

### cisco-wsa-access-policy-anti-malware-update

***
Update the anti-malware policy for access policy.

#### Base Command

`cisco-wsa-access-policy-anti-malware-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name to update. | Required | 
| settings_status | Settings status for the anti-malware. Possible values are: custom, use_global. Default is custom. | Optional | 
| web_reputation_status | Web Reputation Filters will automatically block transactions with a low Web Reputation score.<br/>For transactions with a higher Web Reputation score,<br/>scanning will be performed using the services selected by Adaptive Scanning.<br/>If Web Reputation Filtering is disabled in this policy,<br/>transactions will not be automatically blocked based on low Web Reputation Score.<br/>Blocking of sites that contain malware or other high-risk content is controlled by the additional arguments. Possible values are: enable, disable. | Optional | 
| file_reputation_filtering_status | File Reputation Filters will identify transactions containing known malicious or high-risk files.<br/>Files that are unknown may be forwarded to the cloud for file analysis. Possible values are: enable, disable. | Optional | 
| file_reputation_action | File Reputation action. Possible values are: monitor, block. | Optional | 
| anti_malware_scanning_status | Anti-Malware scanning status. Possible values are: enable, disable. | Optional | 
| suspect_user_agent_scanning | Suspect user agent scanning action.<br/>Required while anti_malware_scanning_status is enabled.<br/>Not relevant while anti_malware_scanning_status is disabled. Possible values are: block, scan, none. | Optional | 
| block_malware_categories | Comma-separated list of malware categories to block. Required while anti_malware_scanning_status is enabled. Not relevant while anti_malware_scanning_status is disabled. Possible values are: Adware, Browser Helper Object, Commercial System Monitor, Dialer, Generic Spyware, Hijacker, Other Malware, Phishing URL, PUA, System Monitor, Trojan Downloader, Trojan Horse, Trojan Phisher, Virus, Worm. | Optional | 
| block_other_categories | Comma-separated list of other categories to block. Required while anti_malware_scanning_status is enabled. Not relevant while anti_malware_scanning_status is disabled. Possible values are: Encrypted File, Outbreak Heuristics, Unscannable. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-anti-malware-update policy_name=test web_reputation_status=enable file_reputation_filtering_status=enable file_reputation_action=block anti_malware_scanning_status=enable suspect_user_agent_scanning=block block_malware_categories=Adware block_other_categories=Unscannable```
#### Human Readable Output

>Updated "test" access policy successfully.

### cisco-wsa-access-policy-delete

***
Delete access policy.

#### Base Command

`cisco-wsa-access-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_names | Comma-separated list of policy names to delete. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-access-policy-delete policy_names=test```
#### Human Readable Output

>Deleted Access policy profiles successfully.

### cisco-wsa-domain-map-list

***
Retrieve domains mapping.
Domain maps are DNS mappings of domain to IP addresses.

#### Base Command

`cisco-wsa-domain-map-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_names | Comma-separated list of domain names to retrieve. | Optional | 
| ip_addresses | Comma-separated list of IP addresses to search for.<br/>This argument will retrieve the domain map record if one of the IP addresses specified is mapped to the domain. . | Optional | 
| page | The page number of the results to retrieve.<br/>Minimum value is 1. | Optional | 
| page_size | The number of results per page. The maximum value is 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoWSA.DomainMap.domain_name | String | Domain name. | 
| CiscoWSA.DomainMap.ip_addresses | String | Mapped IP addresses. | 
| CiscoWSA.DomainMap.order | Number | Index of the domain map in the collection. | 

#### Command example
```!cisco-wsa-domain-map-list limit=5```
#### Context Example
```json
{
    "CiscoWSA": {
        "DomainMap": [
            {
                "IP_addresses": [
                    "19.23.2.23"
                ],
                "domain_name": "ascxcdfdgdfgsfvd",
                "order": 1
            },
            {
                "IP_addresses": [
                    "19.23.2.23"
                ],
                "domain_name": "ascxcdsfvd",
                "order": 2
            },
            {
                "IP_addresses": [
                    "19.23.2.2"
                ],
                "domain_name": "ascxcvd",
                "order": 3
            },
            {
                "IP_addresses": [
                    "19.2.2.2"
                ],
                "domain_name": "asd",
                "order": 4
            },
            {
                "IP_addresses": [],
                "domain_name": "cccc",
                "order": 5
            }
        ]
    }
}
```

#### Human Readable Output

>### Domain Map
>|Domain Name|Ip Addresses|Order|
>|---|---|---|
>| ascxcdfdgdfgsfvd | 19.23.2.23 | 1 |
>| ascxcdsfvd | 19.23.2.23 | 2 |
>| ascxcvd | 19.23.2.2 | 3 |
>| asd | 19.2.2.2 | 4 |
>| cccc |  | 5 |


### cisco-wsa-domain-map-create

***
Create domain mapping for IP addresses.

#### Base Command

`cisco-wsa-domain-map-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | The domain name to create. | Required | 
| order | Index of the domain map in the collection. | Required | 
| ip_addresses | Comma-separated list of IP addresses to map for the domain. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-domain-map-create domain_name=test.com order=1 ip_addresses=1.1.1.1```
#### Human Readable Output

>Domain "test.com" mapping created successfully.

### cisco-wsa-domain-map-update

***
Update the domain map.

#### Base Command

`cisco-wsa-domain-map-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | The domain name to update. | Required | 
| new_domain_name | New domain name. | Optional | 
| order | Index of the domain map in the collection. | Optional | 
| ip_addresses | Comma-separated list of IP addresses to map for the domain.<br/>Updating this will overwrite the existing IP addresses. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-domain-map-update domain_name=test.com new_domain_name=test1.com order=2 ip_addresses=1.1.1.1,2.2.2.2```
#### Human Readable Output

>Domain "test.com" mapping updated successfully.

### cisco-wsa-domain-map-delete

***
Delete domain map.

#### Base Command

`cisco-wsa-domain-map-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_names | Comma-separated list of domain names to delete. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-domain-map-delete domain_names=test1.com```
#### Human Readable Output

>Domain "test1.com" deleted successfully.

### cisco-wsa-identification-profiles-list

***
Retrieve identification profiles.
Identification profiles are classifications of users, defining authentication requirements.

#### Base Command

`cisco-wsa-identification-profiles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_names | Comma-separated list of profile names to retrieve. | Optional | 
| page | The page number of the results to retrieve.<br/>Minimum value is 1. | Optional | 
| page_size | The number of results per page. The maximum value is 100. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoWSA.IdentificationProfile.status | String | Identification Profile status. | 
| CiscoWSA.IdentificationProfile.profile_name | String | Identification Profile name. | 
| CiscoWSA.IdentificationProfile.description | String | Identification Profile description. | 
| CiscoWSA.IdentificationProfile.protocols | String | Identification Profile protocol. | 
| CiscoWSA.IdentificationProfile.order | Number | Identification Profile order in the list. | 
| CiscoWSA.IdentificationProfile.UrlCategories.predefined | String | Identification Profile predefined URL categories. | 
| CiscoWSA.IdentificationProfile.UrlCategories.custom | String | Identification Profile custom URL categories. | 
| CiscoWSA.IdentificationProfile.UrlCategories.uncategorized | String | Identification Profile uncategorized URL categories status. | 
| CiscoWSA.IdentificationProfile.ip | String | Identification Profile IP. | 
| CiscoWSA.IdentificationProfile.proxy_port | String | Identification Profile proxy port. | 
| CiscoWSA.IdentificationProfile.UserAgents.predefined | String | The predefined user-agent. | 
| CiscoWSA.IdentificationProfile.UserAgents.custom | String | User-agent custom. | 

#### Command example
```!cisco-wsa-identification-profiles-list page=1 page_size=2```
#### Context Example
```json
{
    "CiscoWSA": {
        "IdentificationProfile": [
            {
                "description": "Sample description",
                "ip": [
                    "12.2.2.6"
                ],
                "order": 1,
                "profile_name": "hello",
                "protocols": [
                    "http",
                    "https",
                    "ftp"
                ],
                "status": "enable"
            },
            {
                "description": "test",
                "ip": [
                    "10.10.10.10"
                ],
                "order": 2,
                "profile_name": "test123",
                "protocols": [
                    "http",
                    "https",
                    "ftp",
                    "socks"
                ],
                "status": "enable"
            }
        ]
    }
}
```

#### Human Readable Output

>### Identification Profiles
>|Order|Profile Name|Status|Description|Members|
>|---|---|---|---|---|
>| 1 | hello | enable | Sample description | ip: 12.2.2.6<br/>protocols: http,<br/>https,<br/>ftp<br/>proxy_ports: 4000,<br/>5006 |
>| 2 | test123 | enable | test | ip: 10.10.10.10<br/>protocols: http,<br/>https,<br/>ftp,<br/>socks<br/>proxy_ports: 20-200,<br/>966 |


### cisco-wsa-identification-profiles-create

***
Create an identification profile.

#### Base Command

`cisco-wsa-identification-profiles-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | Profile name to create. | Required | 
| status | Status of new identification profile. Possible values are: enable, disable. Default is enable. | Optional | 
| description | Description of new identification profile. | Required | 
| order | Index of the identification profiles in the collection.<br/>Not applicable for global_identification_profile. Default is 1. | Optional | 
| protocols | Comma-separated list of network protocols of identification profile. Possible values are: HTTPS, SOCKS. Default is HTTPS. | Optional | 
| proxy_ports | Comma-separated list of proxy ports.<br/>Membership is defined by proxy port for forward connections,<br/>where certain clients have been configured to use a specific connecting port.<br/>For transparent connections, membership by proxy port applies to the port of the destination URL.<br/>Leave this field blank if membership by connecting proxy port is not needed.<br/>e.g., 22-1000,3331. | Optional | 
| members_by_subnet | Comma-separated list of members by Subnet. e.g., 10.1.1.0,10.1.1.0/24,10.1.1.1-10,2001:420:80:1::5. | Optional | 
| predefined_url_categories | Comma-separated list of URL categories to use as membership criteria.<br/>Leave blank if membership by URL category is not needed.<br/>(Dependencies - use cisco-wsa-url-categories-list command to get all the custom &amp; predefined categories.). | Optional | 
| custom_url_categories | Comma-separated list of URL categories to use as membership criteria.<br/>Leave blank if membership by URL category is not needed.<br/>(Dependencies - use cisco-wsa-url-categories-list command to get all the custom &amp; predefined categories.). | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-identification-profiles-create profile_name=test status=enable description=test protocols=HTTPS order=1```
#### Human Readable Output

>Created identification profile "test" successfully.

### cisco-wsa-identification-profiles-update

***
Update the identification profile. This command rewrites the profile values (does not append). For example, if the proxy_ports is defined as 4000,5000 and you insert proxy_ports=8000, the proxy_ports will be 8000.

#### Base Command

`cisco-wsa-identification-profiles-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_name | Profile name to update. | Required | 
| new_profile_name | New profile name for the identification profile. | Optional | 
| status | Updated the status of the identification profile. Possible values are: enable, disable. | Optional | 
| description | Updated description of the identification profile. | Optional | 
| order | Index of the Identification profile in the collection.<br/>Not applicable for global_identification_profile. | Optional | 
| protocols | Comma-separated list of network protocols of the identification profile. Possible values are: HTTPS, SOCKS. Default is HTTPS. | Optional | 
| proxy_ports | Comma-separated list of proxy ports.<br/>Membership is defined by the proxy port for forward connections,<br/>where certain clients have been configured to use a specific connecting port.<br/>For transparent connections, membership by proxy port applies to the port of the destination URL.<br/>Leave this field blank if membership by connecting proxy port is not needed.<br/>e.g.,  22-1000,3331. | Optional | 
| members_by_subnet | Comma-separated list of members by subnet. e.g., 10.1.1.0,10.1.1.0/24,10.1.1.1-10,2001:420:80:1::5. | Optional | 
| predefined_url_categories | Comma-separated list of URL categories to use as membership criteria.<br/>Leave blank if membership by URL category is not needed.<br/>(Dependencies - use cisco-wsa-url-categories-list command to get all the custom &amp; predefined categories.). | Optional | 
| custom_url_categories | Comma-separated list of URL categories to use as membership criteria.<br/>Leave blank if membership by URL category is not needed.<br/>(Dependencies - use cisco-wsa-url-categories-list command to get all the custom &amp; predefined categories.). | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-identification-profiles-update profile_name=test description=testtest protocols=HTTPS,SOCKS order=2```
#### Human Readable Output

>Updated identification profile "test" successfully.

### cisco-wsa-identification-profiles-delete

***
Delete identification profiles.

#### Base Command

`cisco-wsa-identification-profiles-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_names | Comma-separated list of profile names to delete. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cisco-wsa-identification-profiles-delete profile_names=test```
#### Human Readable Output

>Deleted identification profiles successfully.

### cisco-wsa-url-categories-list

***
Retrieve URL categories of available categories to allow/block in access policies.

#### Base Command

`cisco-wsa-url-categories-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contain | A string that contains the category to search for. | Optional | 
| type | Type of category. Possible values are: custom, predefined. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoWSA.UrlCategory.predefined | String | Predefined URL categories. | 
| CiscoWSA.UrlCategory.custom | String | Custom URL categories. | 

#### Command example
```!cisco-wsa-url-categories-list```
#### Context Example
```json
{
    "CiscoWSA": {
        "UrlCategory": {
            "custom": [
                "test",
                "Adult"
            ],
            "predefined": [
                "Adult",
                "Advertisements",
                "Alcohol",
                "Animals and Pets",
                "Arts",
                "Astrology",
                "Auctions",
                "Business and Industry",
                "Cannabis",
                "Chat and Instant Messaging",
                "Cheating and Plagiarism",
                "Child Abuse Content",
                "Cloud and Data Centers",
                "Computer Security",
                "Computers and Internet",
                "Conventions, Conferences and Trade Shows",
                "Cryptocurrency",
                "Cryptomining",
                "DIY Projects",
                "DNS-Tunneling",
                "Dating",
                "Digital Postcards",
                "Dining and Drinking",
                "DoH and DoT",
                "Dynamic DNS Provider",
                "Dynamic and Residential",
                "Education",
                "Entertainment",
                "Extreme",
                "Fashion",
                "File Transfer Services",
                "Filter Avoidance",
                "Finance",
                "Freeware and Shareware",
                "Gambling",
                "Games",
                "Government and Law",
                "Hacking",
                "Hate Speech",
                "Health and Medicine",
                "Humor",
                "Hunting",
                "Illegal Activities",
                "Illegal Downloads",
                "Illegal Drugs",
                "Infrastructure and Content Delivery Networks",
                "Internet Telephony",
                "Internet of Things",
                "Job Search",
                "Lingerie and Swimsuits",
                "Lotteries",
                "Military",
                "Mobile Phones",
                "Museums",
                "Nature and Conservation",
                "News",
                "Non-governmental Organizations",
                "Non-sexual Nudity",
                "Not Actionable",
                "Online Communities",
                "Online Document Sharing and Collaboration",
                "Online Meetings",
                "Online Storage and Backup",
                "Online Trading",
                "Organizational Email",
                "Paranormal",
                "Parked Domains",
                "Peer File Transfer",
                "Personal Sites",
                "Personal VPN",
                "Photo Search and Images",
                "Politics",
                "Pornography",
                "Private IP Addresses as Host",
                "Professional Networking",
                "Real Estate",
                "Recipes and Food",
                "Reference",
                "Regional Restricted Sites (Germany)",
                "Regional Restricted Sites (Great Britain)",
                "Regional Restricted Sites (Italy)",
                "Regional Restricted Sites (Poland)",
                "Religion",
                "SaaS and B2B",
                "Safe for Kids",
                "Science and Technology",
                "Search Engines and Portals",
                "Sex Education",
                "Shopping",
                "Social Networking",
                "Social Science",
                "Society and Culture",
                "Software Updates",
                "Sports and Recreation",
                "Streaming Audio",
                "Streaming Video",
                "Terrorism and Violent Extremism",
                "Tobacco",
                "Transportation",
                "Travel",
                "URL Shorteners",
                "Weapons",
                "Web Cache and Archives",
                "Web Hosting",
                "Web Page Translation",
                "Web-based Email"
            ]
        }
    }
}
```

#### Human Readable Output

>### URL categories
>|Custom|Predefined|
>|---|---|
>| test,<br/>Adult | Adult,<br/>Advertisements,<br/>Alcohol,<br/>Animals and Pets,<br/>Arts,<br/>Astrology,<br/>Auctions,<br/>Business and Industry,<br/>Cannabis,<br/>Chat and Instant Messaging,<br/>Cheating and Plagiarism,<br/>Child Abuse Content,<br/>Cloud and Data Centers,<br/>Computer Security,<br/>Computers and Internet,<br/>Conventions, Conferences and Trade Shows,<br/>Cryptocurrency,<br/>Cryptomining,<br/>DIY Projects,<br/>DNS-Tunneling,<br/>Dating,<br/>Digital Postcards,<br/>Dining and Drinking,<br/>DoH and DoT,<br/>Dynamic DNS Provider,<br/>Dynamic and Residential,<br/>Education,<br/>Entertainment,<br/>Extreme,<br/>Fashion,<br/>File Transfer Services,<br/>Filter Avoidance,<br/>Finance,<br/>Freeware and Shareware,<br/>Gambling,<br/>Games,<br/>Government and Law,<br/>Hacking,<br/>Hate Speech,<br/>Health and Medicine,<br/>Humor,<br/>Hunting,<br/>Illegal Activities,<br/>Illegal Downloads,<br/>Illegal Drugs,<br/>Infrastructure and Content Delivery Networks,<br/>Internet Telephony,<br/>Internet of Things,<br/>Job Search,<br/>Lingerie and Swimsuits,<br/>Lotteries,<br/>Military,<br/>Mobile Phones,<br/>Museums,<br/>Nature and Conservation,<br/>News,<br/>Non-governmental Organizations,<br/>Non-sexual Nudity,<br/>Not Actionable,<br/>Online Communities,<br/>Online Document Sharing and Collaboration,<br/>Online Meetings,<br/>Online Storage and Backup,<br/>Online Trading,<br/>Organizational Email,<br/>Paranormal,<br/>Parked Domains,<br/>Peer File Transfer,<br/>Personal Sites,<br/>Personal VPN,<br/>Photo Search and Images,<br/>Politics,<br/>Pornography,<br/>Private IP Addresses as Host,<br/>Professional Networking,<br/>Real Estate,<br/>Recipes and Food,<br/>Reference,<br/>Regional Restricted Sites (Germany),<br/>Regional Restricted Sites (Great Britain),<br/>Regional Restricted Sites (Italy),<br/>Regional Restricted Sites (Poland),<br/>Religion,<br/>SaaS and B2B,<br/>Safe for Kids,<br/>Science and Technology,<br/>Search Engines and Portals,<br/>Sex Education,<br/>Shopping,<br/>Social Networking,<br/>Social Science,<br/>Society and Culture,<br/>Software Updates,<br/>Sports and Recreation,<br/>Streaming Audio,<br/>Streaming Video,<br/>Terrorism and Violent Extremism,<br/>Tobacco,<br/>Transportation,<br/>Travel,<br/>URL Shorteners,<br/>Weapons,<br/>Web Cache and Archives,<br/>Web Hosting,<br/>Web Page Translation,<br/>Web-based Email |

