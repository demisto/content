This is Cyware Threat Intelligence eXhange(CTIX) integration which enriches IP/Domain/URL/File Data.
This integration was integrated and tested with version xx of CTIX
## Configure CTIX on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CTIX.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Endpoint URL | True |
| access_id | Access Key | True |
| secret_key | Secret Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP Details.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.IP.tenant_id | string | Tenant ID | 
| CTIX.IP.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.IP.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.IP.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.IP.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.IP.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.IP.intel_grading | string | Intel grading | 
| CTIX.IP.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.IP.indicator_type | string | Threat Data Object type | 
| CTIX.IP.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.IP.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.IP.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.IP.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.IP.source_grading | string | Source Grading | 
| CTIX.IP.name2 | string | Value of the Threat Data Object | 
| CTIX.IP.published_collections | unknown | Published collections | 
| CTIX.IP.published_package_id | unknown | Package ID | 
| CTIX.IP.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.IP.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.IP.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.IP.notification_preference | unknown | Notification preference | 
| CTIX.IP.followed_on | unknown | Followed On | 
| CTIX.IP.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.IP.type | string | Type  of object | 
| CTIX.IP.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.IP.subscriber | unknown | List of Subscribers | 
| CTIX.IP.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.IP.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.IP.object_type | string | Type of object | 
| CTIX.IP.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.IP.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.IP.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.IP.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.IP.asn | string | ASN number of the Threat Data Object | 
| CTIX.IP.registered_domain | string | Registered Domain | 
| CTIX.IP.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.IP.country | string | Geographic details of the Object | 
| CTIX.IP.registrar | string | Registrar | 
| CTIX.IP.file_extension | string | File Extension | 
| CTIX.IP.whitelisted | unknown | List | 
| CTIX.IP.object_description | string | Description of the Threat Data Object. | 
| CTIX.IP.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.IP.is_following | boolean | Boolean Value | 
| CTIX.IP.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.IP.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.IP.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.IP.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.IP.object_description_defang | string | Description of the object. | 
| CTIX.IP.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.IP.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.IP.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!ip ip="151.106.3.179" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "IP": {
            "asn": "AS29066",
            "blocked": true,
            "blocked_on": [
                {
                    "accounts": [
                        {
                            "account_name": "CSOL",
                            "id": "f07cd48e-4fc4-44ba-b9f5-85d0789d0984"
                        }
                    ],
                    "app_id": "d97666c5-0e7e-4e85-9efc-f6d40762b1e3",
                    "title": "CSOL"
                }
            ],
            "blocked_time": 1605682790,
            "country": "France",
            "criticality": 3,
            "custom_score": 0,
            "deprecated": false,
            "deprecated_time": null,
            "domain_tld": null,
            "enhancement_data": {
                "alien_vault_ip_report": {
                    "general": {
                        "accuracy_radius": "200",
                        "area_code": "0",
                        "asn": "AS29066 Host Europe GmbH",
                        "base_indicator": {
                            "access_reason": "",
                            "access_type": "public",
                            "content": "",
                            "description": "",
                            "id": "2261151822",
                            "indicator": "151.106.3.179",
                            "title": "",
                            "type": "IPv4"
                        },
                        "charset": "0",
                        "city": "Strasbourg",
                        "city_data": "True",
                        "continent_code": "EU",
                        "country_code": "FR",
                        "country_code2": "FR",
                        "country_code3": "FRA",
                        "country_name": "France",
                        "dma_code": "0",
                        "flag_title": "France",
                        "flag_url": "/assets/images/flags/fr.png",
                        "indicator": "151.106.3.179",
                        "latitude": "48.5855",
                        "longitude": "7.7418",
                        "postal_code": "67000",
                        "pulse_info": {
                            "count": "7",
                            "pulses": [
                                {
                                    "TLP": "green",
                                    "adversary": "",
                                    "attack_ids": [],
                                    "author": {
                                        "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_91912/resized/80/avatar_2b1b2b88b6.png",
                                        "id": "91912",
                                        "is_following": "False",
                                        "is_subscribed": "False",
                                        "username": "AlessandroFiori"
                                    },
                                    "cloned_from": null,
                                    "comment_count": "0",
                                    "created": "2020-10-04T20:38:01.962000",
                                    "description": "ANIA Collector - Advanced Network Interactive Analysis Collector - Collected from Internet Storm Center IOCs List",
                                    "downvotes_count": "0",
                                    "export_count": "20",
                                    "follower_count": "0",
                                    "groups": [],
                                    "id": "5f7a32a91d75358975505d5f",
                                    "in_group": "False",
                                    "indicator_count": "0",
                                    "indicator_type_counts": {},
                                    "industries": [],
                                    "is_author": "False",
                                    "is_modified": "True",
                                    "is_subscribing": null,
                                    "locked": "False",
                                    "malware_families": [],
                                    "modified": "2020-11-03T20:01:13.206000",
                                    "modified_text": "19 days ago ",
                                    "name": "IOCs - 20201042215 - ANIA Threat Feeds - IP Segment 5",
                                    "public": "1",
                                    "pulse_source": "api",
                                    "references": [],
                                    "related_indicator_is_active": "0",
                                    "related_indicator_type": "IPv4",
                                    "subscriber_count": "220",
                                    "tags": [],
                                    "targeted_countries": [],
                                    "threat_hunter_has_agents": "1",
                                    "threat_hunter_scannable": "False",
                                    "upvotes_count": "0",
                                    "validator_count": "0",
                                    "vote": "0",
                                    "votes_count": "0"
                                },
                                {
                                    "TLP": "green",
                                    "adversary": "",
                                    "attack_ids": [],
                                    "author": {
                                        "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_91912/resized/80/avatar_2b1b2b88b6.png",
                                        "id": "91912",
                                        "is_following": "False",
                                        "is_subscribed": "False",
                                        "username": "AlessandroFiori"
                                    },
                                    "cloned_from": null,
                                    "comment_count": "1",
                                    "created": "2020-11-02T22:09:55.905000",
                                    "description": "ANIA Collector - Advanced Network Interactive Analysis Collector - Collected from Internet Storm Center IOCs List",
                                    "downvotes_count": "0",
                                    "export_count": "16",
                                    "follower_count": "0",
                                    "groups": [],
                                    "id": "5fa083b3b6aa093f35e4818a",
                                    "in_group": "False",
                                    "indicator_count": "24908",
                                    "indicator_type_counts": {
                                        "IPv4": "24908"
                                    },
                                    "industries": [],
                                    "is_author": "False",
                                    "is_modified": "False",
                                    "is_subscribing": null,
                                    "locked": "False",
                                    "malware_families": [],
                                    "modified": "2020-11-02T22:09:55.905000",
                                    "modified_text": "20 days ago ",
                                    "name": "IOCs - 20201122248 - ANIA Threat Feeds - IP Segment 4",
                                    "public": "1",
                                    "pulse_source": "api",
                                    "references": [],
                                    "related_indicator_is_active": "1",
                                    "related_indicator_type": "IPv4",
                                    "subscriber_count": "219",
                                    "tags": [],
                                    "targeted_countries": [],
                                    "threat_hunter_has_agents": "1",
                                    "threat_hunter_scannable": "True",
                                    "upvotes_count": "0",
                                    "validator_count": "0",
                                    "vote": "0",
                                    "votes_count": "0"
                                },
                                {
                                    "TLP": "green",
                                    "adversary": "",
                                    "attack_ids": [],
                                    "author": {
                                        "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_91912/resized/80/avatar_2b1b2b88b6.png",
                                        "id": "91912",
                                        "is_following": "False",
                                        "is_subscribed": "False",
                                        "username": "AlessandroFiori"
                                    },
                                    "cloned_from": null,
                                    "comment_count": "0",
                                    "created": "2020-09-05T23:28:50.987000",
                                    "description": "ANIA Collector - Advanced Network Interactive Analysis Collector - Collected from Internet Storm Center IOCs List",
                                    "downvotes_count": "0",
                                    "export_count": "7",
                                    "follower_count": "0",
                                    "groups": [],
                                    "id": "5f541f32dd29e81a29badba1",
                                    "in_group": "False",
                                    "indicator_count": "0",
                                    "indicator_type_counts": {},
                                    "industries": [],
                                    "is_author": "False",
                                    "is_modified": "True",
                                    "is_subscribing": null,
                                    "locked": "False",
                                    "malware_families": [],
                                    "modified": "2020-10-05T23:02:54.501000",
                                    "modified_text": "48 days ago ",
                                    "name": "IOCs - 202096112 - ANIA Threat Feeds - IP Segment 4",
                                    "public": "1",
                                    "pulse_source": "api",
                                    "references": [],
                                    "related_indicator_is_active": "0",
                                    "related_indicator_type": "IPv4",
                                    "subscriber_count": "220",
                                    "tags": [],
                                    "targeted_countries": [],
                                    "threat_hunter_has_agents": "1",
                                    "threat_hunter_scannable": "False",
                                    "upvotes_count": "0",
                                    "validator_count": "0",
                                    "vote": "0",
                                    "votes_count": "0"
                                },
                                {
                                    "TLP": "green",
                                    "adversary": "",
                                    "attack_ids": [],
                                    "author": {
                                        "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_91912/resized/80/avatar_2b1b2b88b6.png",
                                        "id": "91912",
                                        "is_following": "False",
                                        "is_subscribed": "False",
                                        "username": "AlessandroFiori"
                                    },
                                    "cloned_from": null,
                                    "comment_count": "0",
                                    "created": "2020-07-13T13:09:14.197000",
                                    "description": "ANIA Collector - Advanced Network Interactive Analysis Collector - Collected from Internet Storm Center IOCs List",
                                    "downvotes_count": "0",
                                    "export_count": "3",
                                    "follower_count": "0",
                                    "groups": [],
                                    "id": "5f0c5cfa65bb937709d3a1df",
                                    "in_group": "False",
                                    "indicator_count": "0",
                                    "indicator_type_counts": {},
                                    "industries": [],
                                    "is_author": "False",
                                    "is_modified": "True",
                                    "is_subscribing": null,
                                    "locked": "False",
                                    "malware_families": [],
                                    "modified": "2020-08-12T13:10:50.668000",
                                    "modified_text": "102 days ago ",
                                    "name": "IOCs - 20207131444 - ANIA Threat Feeds - IP Segment 7",
                                    "public": "1",
                                    "pulse_source": "api",
                                    "references": [],
                                    "related_indicator_is_active": "0",
                                    "related_indicator_type": "IPv4",
                                    "subscriber_count": "222",
                                    "tags": [],
                                    "targeted_countries": [],
                                    "threat_hunter_has_agents": "1",
                                    "threat_hunter_scannable": "False",
                                    "upvotes_count": "0",
                                    "validator_count": "0",
                                    "vote": "0",
                                    "votes_count": "0"
                                },
                                {
                                    "TLP": "green",
                                    "adversary": "",
                                    "attack_ids": [],
                                    "author": {
                                        "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_91912/resized/80/avatar_2b1b2b88b6.png",
                                        "id": "91912",
                                        "is_following": "False",
                                        "is_subscribed": "False",
                                        "username": "AlessandroFiori"
                                    },
                                    "cloned_from": null,
                                    "comment_count": "0",
                                    "created": "2020-06-30T18:15:11.879000",
                                    "description": "ANIA Collector - Advanced Network Interactive Analysis Collector - Collected from Internet Storm Center IOCs List",
                                    "downvotes_count": "0",
                                    "export_count": "5",
                                    "follower_count": "0",
                                    "groups": [],
                                    "id": "5efb812f0883a8f2b2fa9946",
                                    "in_group": "False",
                                    "indicator_count": "0",
                                    "indicator_type_counts": {},
                                    "industries": [],
                                    "is_author": "False",
                                    "is_modified": "True",
                                    "is_subscribing": null,
                                    "locked": "False",
                                    "malware_families": [],
                                    "modified": "2020-07-30T18:04:52.150000",
                                    "modified_text": "115 days ago ",
                                    "name": "IOCs - 20206301939 - ANIA Threat Feeds - IP Segment 7",
                                    "public": "1",
                                    "pulse_source": "api",
                                    "references": [],
                                    "related_indicator_is_active": "0",
                                    "related_indicator_type": "IPv4",
                                    "subscriber_count": "221",
                                    "tags": [],
                                    "targeted_countries": [],
                                    "threat_hunter_has_agents": "1",
                                    "threat_hunter_scannable": "False",
                                    "upvotes_count": "0",
                                    "validator_count": "0",
                                    "vote": "0",
                                    "votes_count": "0"
                                },
                                {
                                    "TLP": "green",
                                    "adversary": "",
                                    "attack_ids": [],
                                    "author": {
                                        "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_91912/resized/80/avatar_2b1b2b88b6.png",
                                        "id": "91912",
                                        "is_following": "False",
                                        "is_subscribed": "False",
                                        "username": "AlessandroFiori"
                                    },
                                    "cloned_from": null,
                                    "comment_count": "0",
                                    "created": "2020-05-31T13:31:56.936000",
                                    "description": "ANIA Collector - Advanced Network Interactive Analysis Collector - Collected from Internet Storm Center IOCs List",
                                    "downvotes_count": "0",
                                    "export_count": "8",
                                    "follower_count": "0",
                                    "groups": [],
                                    "id": "5ed3b1ccb9f9baf2e72e2960",
                                    "in_group": "False",
                                    "indicator_count": "0",
                                    "indicator_type_counts": {},
                                    "industries": [],
                                    "is_author": "False",
                                    "is_modified": "True",
                                    "is_subscribing": null,
                                    "locked": "False",
                                    "malware_families": [],
                                    "modified": "2020-06-30T13:03:44.010000",
                                    "modified_text": "145 days ago ",
                                    "name": "IOCs - 20205311518 - ANIA Threat Feeds - IP Segment 5",
                                    "public": "1",
                                    "pulse_source": "api",
                                    "references": [],
                                    "related_indicator_is_active": "0",
                                    "related_indicator_type": "IPv4",
                                    "subscriber_count": "220",
                                    "tags": [],
                                    "targeted_countries": [],
                                    "threat_hunter_has_agents": "1",
                                    "threat_hunter_scannable": "False",
                                    "upvotes_count": "0",
                                    "validator_count": "0",
                                    "vote": "0",
                                    "votes_count": "0"
                                },
                                {
                                    "TLP": "green",
                                    "adversary": "",
                                    "attack_ids": [],
                                    "author": {
                                        "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_91912/resized/80/avatar_2b1b2b88b6.png",
                                        "id": "91912",
                                        "is_following": "False",
                                        "is_subscribed": "False",
                                        "username": "AlessandroFiori"
                                    },
                                    "cloned_from": null,
                                    "comment_count": "0",
                                    "created": "2020-05-30T12:55:03.881000",
                                    "description": "ANIA Collector - Advanced Network Interactive Analysis Collector - Collected from Internet Storm Center IOCs List",
                                    "downvotes_count": "0",
                                    "export_count": "3",
                                    "follower_count": "0",
                                    "groups": [],
                                    "id": "5ed257a78af7274bfc1f92ca",
                                    "in_group": "False",
                                    "indicator_count": "0",
                                    "indicator_type_counts": {},
                                    "industries": [],
                                    "is_author": "False",
                                    "is_modified": "True",
                                    "is_subscribing": null,
                                    "locked": "False",
                                    "malware_families": [],
                                    "modified": "2020-06-29T12:05:01.928000",
                                    "modified_text": "146 days ago ",
                                    "name": "IOCs - 20205301441 - ANIA Threat Feeds - Segment 5",
                                    "public": "1",
                                    "pulse_source": "api",
                                    "references": [],
                                    "related_indicator_is_active": "0",
                                    "related_indicator_type": "IPv4",
                                    "subscriber_count": "221",
                                    "tags": [],
                                    "targeted_countries": [],
                                    "threat_hunter_has_agents": "1",
                                    "threat_hunter_scannable": "False",
                                    "upvotes_count": "0",
                                    "validator_count": "0",
                                    "vote": "0",
                                    "votes_count": "0"
                                }
                            ],
                            "references": [],
                            "related": {
                                "alienvault": {
                                    "adversary": [],
                                    "industries": [],
                                    "malware_families": []
                                },
                                "other": {
                                    "adversary": [],
                                    "industries": [],
                                    "malware_families": []
                                }
                            }
                        },
                        "region": "GES",
                        "reputation": "0",
                        "sections": [
                            "general",
                            "geo",
                            "reputation",
                            "url_list",
                            "passive_dns",
                            "malware",
                            "nids_list",
                            "http_scans"
                        ],
                        "subdivision": "67",
                        "type": "IPv4",
                        "type_title": "IPv4",
                        "whois": "http://whois.domaintools.com/151.106.3.179"
                    },
                    "geo": {
                        "accuracy_radius": "200",
                        "area_code": "0",
                        "asn": "AS29066 Host Europe GmbH",
                        "charset": "0",
                        "city": "Strasbourg",
                        "city_data": "True",
                        "continent_code": "EU",
                        "country_code": "FR",
                        "country_code2": "FR",
                        "country_code3": "FRA",
                        "country_name": "France",
                        "dma_code": "0",
                        "flag_title": "France",
                        "flag_url": "/assets/images/flags/fr.png",
                        "latitude": "48.5855",
                        "longitude": "7.7418",
                        "postal_code": "67000",
                        "region": "GES",
                        "subdivision": "67"
                    },
                    "malware": {
                        "data": [],
                        "next": "https://api.otx.alienvault.com/api/v1/indicators/IPv4/151.106.3.179/malware?page=2",
                        "previous": null,
                        "size": null
                    },
                    "passive_dns": {
                        "count": "0",
                        "passive_dns": []
                    },
                    "reputation": {
                        "reputation": null
                    },
                    "updated": "1606121960",
                    "url_list": {
                        "actual_size": "2",
                        "full_size": "2",
                        "has_next": "False",
                        "limit": "10",
                        "page_num": "1",
                        "paged": "True",
                        "url_list": [
                            {
                                "date": "2020-05-30T12:58:20",
                                "domain": "",
                                "encoded": "https%3A//151.106.3.179",
                                "gsb": [],
                                "hostname": "151.106.3.179",
                                "httpcode": "0",
                                "result": {
                                    "safebrowsing": {
                                        "matches": []
                                    },
                                    "urlworker": {
                                        "http_code": "0"
                                    }
                                },
                                "url": "https://151.106.3.179"
                            },
                            {
                                "date": "2020-05-30T12:56:50",
                                "domain": "",
                                "encoded": "http%3A//151.106.3.179",
                                "gsb": [],
                                "hostname": "151.106.3.179",
                                "httpcode": "0",
                                "result": {
                                    "safebrowsing": {
                                        "matches": []
                                    },
                                    "urlworker": {
                                        "http_code": "0"
                                    }
                                },
                                "url": "http://151.106.3.179"
                            }
                        ]
                    }
                },
                "polyswarm_ip_report": {
                    "artifact_id": "49780005046645569",
                    "assertions": [],
                    "community": "omicron",
                    "country": "US",
                    "created": "2020-11-19T09:29:39.670949",
                    "detections": {
                        "benign": "0",
                        "malicious": "0",
                        "total": "0"
                    },
                    "extended_type": "ASCII text, with no line terminators",
                    "failed": "False",
                    "filename": "151.106.3.179",
                    "first_seen": "2020-11-19T09:29:39.670949",
                    "id": "49780005046645569",
                    "last_scanned": "2020-11-19T09:29:39.670949",
                    "last_seen": "2020-11-19T09:29:39.670949",
                    "md5": "e412fdff19c5a8d9876fe802bd93dec7",
                    "metadata": [
                        {
                            "created": "2020-11-19T09:29:50.745524",
                            "tool": "strings",
                            "tool_metadata": {
                                "domains": [
                                    ""
                                ],
                                "ipv4": [
                                    "151.106.3.179"
                                ],
                                "ipv6": [],
                                "urls": [
                                    "151.106.3.179"
                                ]
                            }
                        },
                        {
                            "created": "2020-11-19T09:29:50.745524",
                            "tool": "hash",
                            "tool_metadata": {
                                "md5": "e412fdff19c5a8d9876fe802bd93dec7",
                                "sha1": "347eb4c0cccb72c36a5d7d8b68b9171315437971",
                                "sha256": "bee069740c0fbfef13bc75c17ecee3f094e9155dbba341d555ca1d959a434ffa",
                                "sha3_256": "44afda8b082be046ac0860790d7fd4f0bf2c25f74cda4bf5a8b0988ef9dc6496",
                                "sha3_512": "9a1f54759c8adaf6836505ec933db9a872892e584762ff8ab02f8564d671cfa36b75385d4ad3f16393aa48e5740c3d96252defdb3c3d1f9ed9260d1d1d5db239",
                                "sha512": "79361f7bb61fc4634b4f7ff7d5b0f73fe926248001a54762e20545299390155cdf9dc872d92abaebccf5aea8f2c885b62210116f45572bef9476936f14e678ad",
                                "ssdeep": "3:JSvo:1",
                                "tlsh": ""
                            }
                        }
                    ],
                    "mimetype": "text/plain",
                    "polyscore": null,
                    "result": null,
                    "sha1": "347eb4c0cccb72c36a5d7d8b68b9171315437971",
                    "sha256": "bee069740c0fbfef13bc75c17ecee3f094e9155dbba341d555ca1d959a434ffa",
                    "size": "13",
                    "type": "URL",
                    "votes": [],
                    "window_closed": "True"
                }
            },
            "file_extension": null,
            "first_seen": 1605676783,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {
                "city": {
                    "city": null,
                    "continent_code": "EU",
                    "continent_name": "Europe",
                    "country_code": "FR",
                    "country_name": "France",
                    "dma_code": null,
                    "latitude": 48.8582,
                    "longitude": 2.3387000000000002,
                    "postal_code": null,
                    "region": null,
                    "time_zone": "Europe/Paris"
                },
                "country": {
                    "country_code": "FR",
                    "country_name": "France"
                }
            },
            "indicator_type": "ipv4-addr",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [
                {
                    "colour_code": null,
                    "created": 1605030281,
                    "created_by": "system@default.tld",
                    "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                    "modified": 1605030281,
                    "modified_by": "system@default.tld",
                    "name": "anomalous-activity"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "3343924e-f422-4b10-9e21-62aa012e559a",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "backdoor"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "502a2bc4-3fc8-4d1a-8910-14c2c83cceab",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "bot"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "60a8fa11-aeba-4fcf-aabb-cee8a07ba4e5",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "dropper"
                },
                {
                    "colour_code": null,
                    "created": 1605772450,
                    "created_by": "system@default.tld",
                    "id": "85c1f11f-0cd6-41a0-b762-2c305bf72985",
                    "modified": 1605772450,
                    "modified_by": "system@default.tld",
                    "name": "anonymization"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "aa5d9110-663b-4b9d-a58f-1e165f484ed3",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "denial-of-service"
                },
                {
                    "colour_code": null,
                    "created": 1605194595,
                    "created_by": "system@default.tld",
                    "id": "ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54",
                    "modified": 1605194595,
                    "modified_by": "system@default.tld",
                    "name": "adware"
                },
                {
                    "colour_code": null,
                    "created": 1605769350,
                    "created_by": "system@default.tld",
                    "id": "cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13",
                    "modified": 1605769350,
                    "modified_by": "system@default.tld",
                    "name": "campaign"
                },
                {
                    "colour_code": null,
                    "created": 1605773317,
                    "created_by": "system@default.tld",
                    "id": "d38744ce-4d25-44ac-a114-9b2d8c72cad1",
                    "modified": 1605773317,
                    "modified_by": "system@default.tld",
                    "name": "activist"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "ef1034b6-558a-46b7-8e4d-8f46510aa4d9",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "ddos"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "f14e5e48-5cce-46d2-af21-4c5d20cd5a90",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "exploit-kit"
                },
                {
                    "colour_code": null,
                    "created": 1605083522,
                    "created_by": "system@default.tld",
                    "id": "f684c479-d6fe-411c-a7e1-3352f68d079e",
                    "modified": 1605083522,
                    "modified_by": "system@default.tld",
                    "name": "label1"
                }
            ],
            "last_seen": 1605894452,
            "name2": "151.106.3.179",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-0e9f4843-4631-47b7-970d-df8c8a5c1fb3",
                "package-62698cfc-fe23-4024-bc39-8af44b175399",
                "package-fba6b33f-0606-4742-ab63-48ab885fab63",
                "package-108a6be6-d4ae-4a9c-b150-8b53ad2181c7"
            ],
            "published_collections": [
                "inbox & polling",
                "adsa",
                "newtestcollection1 - edited"
            ],
            "published_package_id": [
                "d98a3e44-4658-412f-9cf6-bb122e4c2ded",
                "36cf59e3-6c5d-45ea-85d5-2b6b09196e81",
                "7f8a7a2c-8967-4e40-a9bd-0b12bd8a1b1e",
                "0fd5e7ee-d1fd-42fe-836c-8a8b313de47b",
                "6c650167-6d8a-485f-9fc8-68442856ee60",
                "33d28312-733f-4621-8759-6dfa56b3b963"
            ],
            "registered_domain": null,
            "registrar": null,
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 5,
            "score": 72.18,
            "source": [
                "customsource1.x",
                "Import"
            ],
            "source_data": [
                {
                    "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                    "name": "Import"
                },
                {
                    "id": "012072c9-1421-4960-ab01-2bb541596374",
                    "name": "customsource1.x"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--d1d69245-9d54-470a-b01c-62d1929a18bf",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": "AMBER",
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "151.106.3.179",
            "whitelisted": []
        }
    },
    "DBotScore": [
        {
            "Indicator": "151.106.3.179",
            "Score": 3,
            "Type": "ip",
            "Vendor": "CTIX"
        },
        {
            "Indicator": "151.106.3.179",
            "Score": 3,
            "Type": "ip",
            "Vendor": "HelloWorld"
        }
    ],
    "HelloWorld": {
        "IP": {
            "asn": "29066",
            "asn_cidr": "151.106.0.0/19",
            "asn_country_code": "DE",
            "asn_date": "1991-05-30",
            "asn_description": "VELIANET-AS velia.net Internetdienste GmbH, DE",
            "asn_registry": "ripencc",
            "entities": [
                "AA35239-RIPE",
                "FGK-MNT",
                "ORG-AA2321-RIPE",
                "AA35239-RIPE"
            ],
            "ip": "151.106.3.179",
            "network": {
                "cidr": "151.106.3.178/31",
                "country": "FR",
                "end_address": "151.106.3.179",
                "events": [
                    {
                        "action": "last changed",
                        "actor": null,
                        "timestamp": "2019-11-07T12:02:46Z"
                    }
                ],
                "handle": "151.106.3.178 - 151.106.3.179",
                "ip_version": "v4",
                "links": [
                    "https://rdap.db.ripe.net/ip/151.106.3.179",
                    "http://www.ripe.net/data-tools/support/documentation/terms"
                ],
                "name": "VELIANET-FR-ALLENWATCH",
                "notices": [
                    {
                        "description": "This output has been filtered.",
                        "links": null,
                        "title": "Filtered"
                    },
                    {
                        "description": "Objects returned came from source\nRIPE",
                        "links": null,
                        "title": "Source"
                    },
                    {
                        "description": "This is the RIPE Database query service. The objects are in RDAP format.",
                        "links": [
                            "http://www.ripe.net/db/support/db-terms-conditions.pdf"
                        ],
                        "title": "Terms and Conditions"
                    }
                ],
                "parent_handle": "151.106.0.0 - 151.106.31.255",
                "raw": null,
                "remarks": [
                    {
                        "description": "allenwatch",
                        "links": null,
                        "title": null
                    }
                ],
                "start_address": "151.106.3.178",
                "status": null,
                "type": "LEGACY"
            },
            "query": "151.106.3.179",
            "raw": null,
            "score": 91
        }
    },
    "IP": {
        "ASN": "29066",
        "Address": "151.106.3.179",
        "Malicious": {
            "Description": "Hello World returned reputation 91",
            "Vendor": "HelloWorld"
        }
    }
}
```

#### Human Readable Output

>### IP List
>|asn|asn_cidr|asn_country_code|asn_date|asn_description|asn_registry|entities|ip|network|query|raw|score|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 29066 | 151.106.0.0/19 | DE | 1991-05-30 | VELIANET-AS velia.net Internetdienste GmbH, DE | ripencc | AA35239-RIPE,<br/>FGK-MNT,<br/>ORG-AA2321-RIPE,<br/>AA35239-RIPE | 151.106.3.179 | handle: 151.106.3.178 - 151.106.3.179<br/>status: null<br/>remarks: {'title': None, 'description': 'allenwatch', 'links': None}<br/>notices: {'title': 'Filtered', 'description': 'This output has been filtered.', 'links': None},<br/>{'title': 'Source', 'description': 'Objects returned came from source\nRIPE', 'links': None},<br/>{'title': 'Terms and Conditions', 'description': 'This is the RIPE Database query service. The objects are in RDAP format.', 'links': ['http://www.ripe.net/db/support/db-terms-conditions.pdf']}<br/>links: https://rdap.db.ripe.net/ip/151.106.3.179,<br/>http://www.ripe.net/data-tools/support/documentation/terms<br/>events: {'action': 'last changed', 'timestamp': '2019-11-07T12:02:46Z', 'actor': None}<br/>raw: null<br/>start_address: 151.106.3.178<br/>end_address: 151.106.3.179<br/>cidr: 151.106.3.178/31<br/>ip_version: v4<br/>type: LEGACY<br/>name: VELIANET-FR-ALLENWATCH<br/>country: FR<br/>parent_handle: 151.106.0.0 - 151.106.31.255 | 151.106.3.179 |  | 91 |


### domain
***
Return Domain Details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.Domain.tenant_id | string | Tenant ID | 
| CTIX.Domain.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.Domain.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.Domain.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.Domain.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.Domain.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.Domain.intel_grading | string | Intel grading | 
| CTIX.Domain.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.Domain.indicator_type | string | Threat Data Object type | 
| CTIX.Domain.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.Domain.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.Domain.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.Domain.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.Domain.source_grading | string | Source Grading | 
| CTIX.Domain.name2 | string | Value of the Threat Data Object | 
| CTIX.Domain.published_collections | unknown | Published collections | 
| CTIX.Domain.published_package_id | unknown | Package ID | 
| CTIX.Domain.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.Domain.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.Domain.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.Domain.notification_preference | unknown | Notification preference | 
| CTIX.Domain.followed_on | unknown | Followed On | 
| CTIX.Domain.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.Domain.type | string | Type  of object | 
| CTIX.Domain.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.Domain.subscriber | unknown | List of Subscribers | 
| CTIX.Domain.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.Domain.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.Domain.object_type | string | Type of object | 
| CTIX.Domain.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.Domain.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.Domain.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.Domain.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.Domain.asn | string | ASN number of the Threat Data Object | 
| CTIX.Domain.registered_domain | string | Registered Domain | 
| CTIX.Domain.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.Domain.country | string | Geographic details of the Object | 
| CTIX.Domain.registrar | string | Registrar | 
| CTIX.Domain.file_extension | string | File Extension | 
| CTIX.Domain.whitelisted | unknown | List | 
| CTIX.Domain.object_description | string | Description of the Threat Data Object. | 
| CTIX.Domain.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.Domain.is_following | boolean | Boolean Value | 
| CTIX.Domain.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.Domain.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.Domain.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.Domain.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.Domain.object_description_defang | string | Description of the object. | 
| CTIX.Domain.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.Domain.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.Domain.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!domain domain="internal-www.fireeye.com" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "Domain": {
            "asn": null,
            "blocked": false,
            "blocked_on": [],
            "blocked_time": 0,
            "country": null,
            "criticality": 3,
            "custom_score": 0,
            "deprecated": false,
            "deprecated_time": null,
            "domain_tld": ".com",
            "enhancement_data": {},
            "file_extension": null,
            "first_seen": 1605684825,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {},
            "indicator_type": "domain",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [],
            "last_seen": 1605894564,
            "name2": "internal-www.fireeye.com",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-06e9ba89-5333-41f8-ae20-37ba4b179d18",
                "package-ad25ebb2-dff0-45c2-a781-dccabf28b3d4",
                "package-79680487-7738-4183-a92f-10ad34a9d1ed",
                "package-1228890c-098f-499b-bed5-e9be219f3e17",
                "package-afeb002d-cde1-4667-a4e4-097f85569297",
                "package-ee6d91da-780f-4cbe-ad9c-0bb67a24fe3d",
                "package-32f7bc37-f530-45bb-99be-e474fe0ae527",
                "package-23b3230a-20de-442a-91bb-15305f8b26b3",
                "package-857bf97e-6e09-4e1d-907e-d799fdfee6bd",
                "package-39a3ce49-c13e-46e6-9f22-b1988151b697",
                "package-fd70ce85-abac-4411-b552-24c041ca5d79",
                "package-00932fbd-c340-43e4-9918-69c4c2cf5c88",
                "package-129c03b3-51b5-45d2-9b46-0243232e053d",
                "package-98066271-1107-4065-9f18-7a9fd3167571",
                "package-1fed98c5-7e86-4a83-8e5b-90eed5abf858",
                "package-f2465970-4b27-4a11-9499-6f23fdd4b55c",
                "package-b8a06623-315c-4946-aa55-0587c57ecd4e",
                "package-940b043c-3027-46db-95c5-95d0f5480eb0",
                "package-19fc321e-80f1-4576-9954-1b47d5535a08",
                "package-313891ce-f54a-4746-957e-bb60a18d65cf",
                "package-73459611-5cee-4496-bc68-4c868162d8f6",
                "package-cfb212cf-b69e-4a0c-ba53-0f03ca2450dc",
                "package-9b12137d-0572-42b6-bf6a-cd2087f52b62",
                "package-2c7d8a17-3e55-42c7-a0f7-29e4cf43aa45",
                "package-a8d10b33-0933-4289-ada9-6c0a9b5a8368",
                "package-7a85d527-9a99-4802-9d84-15822d156edc",
                "package-7ae458e8-8204-479f-bfe4-aea498c14cab",
                "package-f1150bc6-19fd-420e-a253-5e0b3bb72a3a",
                "package-d1bad4f6-0cc8-4c44-a575-0184b4506df7",
                "package-cbe75657-6af9-4999-a9b1-4f11551239a5",
                "package-933aac87-6ebc-4699-8540-b405424a55d2",
                "package-2a0d00e7-15bc-4a48-9519-b8ae2df0c06b",
                "package-80d20c27-8957-40f2-99bc-131f5bd2f354",
                "package-b455e2f0-5042-45b3-b146-c37cb451aa68",
                "package-dc6d0147-f6a1-4133-92a1-97aa262f98f0",
                "package-86a669a2-c97f-4972-9aca-dae218245b6b",
                "package-0cb91adc-b2c5-4e1c-b026-4052a662e8c0",
                "package-08ed3cbe-6d5b-4a07-a9d6-780e34bb4c6a",
                "package-54b9e065-82a9-4b56-b05a-2ad2c8399e3a",
                "package-06cbbad6-7da1-4172-884e-62ee5dd94737",
                "package-4711dcda-ebec-40e7-bd74-adca99d67dd3",
                "package-89647435-4464-450f-9aa6-bd6859b8df5f",
                "package-3e8655bc-b11e-4c19-b853-9ddf5b2021aa",
                "package-39e6f825-7cbc-41bb-ae95-7a70840470c9",
                "package-d00afa08-8f2c-4d73-b192-1b51ba7f96dd",
                "package-0d2c723c-0b19-4e58-b5e0-a566b1d3b48b",
                "package-0c8f23e2-f84e-4e7e-b3b1-b536fd333549",
                "package-15a5c0eb-bd5c-47a7-9693-8c03ddcc4565",
                "package-6764ed33-3005-4a0f-978e-4d1271ca9394",
                "package-95f84cb8-9f0c-44d3-a89b-7498ae9266c3",
                "package-c697e749-e9cd-4da2-909f-d14b139e393b",
                "package-4e8d8607-d918-482d-a2c1-7ad5d89d1a3f",
                "package-51877a37-3950-4e95-ad6f-d983797132ad",
                "package-82a4093a-1191-486c-b12d-046e4bd92267",
                "package-96cd8098-bab3-46ab-b252-2ca01302975d",
                "package-2e52bc4e-fa99-48c8-8a4f-45db67518eaa",
                "package-41ba400f-ab82-4776-891e-6c50a50cd3cd",
                "package-3d272d52-9fcd-42e9-b304-42112ec127a6",
                "package-20f70a55-68d6-4281-88b9-407f4b1821be",
                "package-8fda3ef0-8537-4b9d-9f2f-da9c5b325921",
                "package-d70e1872-a4aa-4793-a3cc-a7a8d3eda0c1",
                "package-7d229063-95fd-426a-8c06-f2cbc7182174",
                "package-a1efff2f-f565-47ee-8e31-91846ea36abb",
                "package-3656277f-dfc5-45f6-a151-f6bdba20f38c",
                "package-f24fea4a-0caa-4d11-bfed-747a2f94c19d",
                "package-fb12b50f-3865-43ca-af62-3b8ee91bce54",
                "package-4ba75d47-8c2f-4f52-bc0a-5341882905cd",
                "package-4f26c9ad-aa1f-46be-8942-cd286c02d781",
                "package-9735a4b7-de14-455d-aafb-dd47603ec24c",
                "package-39d7b544-3211-41ed-8e6d-7b11f9732a17",
                "package-60cfa6d6-f047-4ea5-935a-fb32c40f32d9",
                "package-c1c11f8f-fe92-419c-888c-6ed7e813384f",
                "package-432e31a8-f843-4232-a352-3a08fed1d1e1",
                "package-56dac033-4b88-41fb-af31-70221f86bb05",
                "package-99c6b231-2251-427b-90a3-f109e1fa7559",
                "package-02aeecf8-6290-4001-b52f-2b141b6c2733",
                "package-a713f6f6-e03f-49ce-a5d0-bbb6f0865579",
                "package-cfcd7320-a31f-450d-a8b1-b5cbe77dc9dd",
                "package-b5efb0e9-8b68-44f6-901e-9132ecfd4583",
                "package-c2dca475-260c-4658-95d6-d2370b582728",
                "package-7b303eba-8491-4b2f-99c3-7f8c36e799c9",
                "package-8cdf035b-58fc-4bbb-949a-ae5858f2d6c8",
                "package-9a330aa5-56e8-4609-9135-3d3ac9176ba9",
                "package-0252a128-7910-47b1-ae27-275ffd2ce226",
                "package-b4e9a247-d58a-4c28-a673-6f0ea140f445",
                "package-8a0702d0-335b-4cb4-a60a-0736b0938143",
                "package-86c48a86-e406-41d6-87ba-cd105d83e29d",
                "package-4f65fccf-d44f-4dec-af93-59c286b4847f",
                "package-1ff0d0d2-3a7a-419c-a08e-5b40f12a7e10",
                "package-7d1a8c35-eb59-4d36-9b4e-52a32d996fbc",
                "package-2a984e83-06e0-462f-b024-549b3ddfef06",
                "package-701902ae-bc05-409a-8b54-6b4d022bb3d7",
                "package-3b5cd69a-c415-4124-a8c8-3938c3855716",
                "package-a1295069-6857-4b23-9617-6b7174702c82",
                "package-ed624398-4778-4b1d-96cb-921728b912b7",
                "package-210b46db-1834-4a89-a094-76eb9a946413",
                "package-d27715fb-1c2e-499a-bb9d-7a36b9356a3a",
                "package-92d79a8a-4ec9-4796-b352-d04aba5232f1",
                "package-8329cdb2-ef9b-48e7-aedd-be96450a2a39",
                "package-01ec48b9-b2fd-44cd-9190-bf0ea736f29d",
                "package-ffc1fb22-1ec6-4ed2-a4fd-7c6eb63e054d"
            ],
            "published_collections": [
                "adsa"
            ],
            "published_package_id": [
                "f90d86f9-4ef2-4ef4-bb00-23098dd0a6fc"
            ],
            "registered_domain": "fireeye.com",
            "registrar": "CSC CORPORATE DOMAINS, INC.",
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 5,
            "score": 70,
            "source": [
                "Import",
                "fire eye"
            ],
            "source_data": [
                {
                    "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                    "name": "Import"
                },
                {
                    "id": "6b38846c-5e08-4872-b91e-60afcb17377d",
                    "name": "fire eye"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--0c4e2d87-0b6c-48c0-ab6a-054e1b2ba3ac",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": "AMBER",
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "internal-www.fireeye.com",
            "whitelisted": []
        }
    },
    "DBotScore": [
        {
            "Indicator": "internal-www.fireeye.com",
            "Score": 2,
            "Type": "domain",
            "Vendor": "CTIX"
        },
        {
            "Indicator": "internal-www.fireeye.com",
            "Score": 1,
            "Type": "domain",
            "Vendor": "HelloWorld"
        }
    ],
    "Domain": {
        "CreationDate": "2003-07-24T18:51:45.000Z",
        "ExpirationDate": "2025-07-24T18:51:45.000Z",
        "Name": "internal-www.fireeye.com",
        "NameServers": [
            "BONNIE.NS.CLOUDFLARE.COM",
            "CHUCK.NS.CLOUDFLARE.COM",
            "bonnie.ns.cloudflare.com",
            "chuck.ns.cloudflare.com"
        ],
        "Organization": "FireEye, Inc.",
        "Registrant": {
            "Country": "US",
            "Email": null,
            "Name": "Host Master",
            "Phone": null
        },
        "Registrar": {
            "AbuseEmail": null,
            "AbusePhone": null,
            "Name": "CSC CORPORATE DOMAINS, INC."
        },
        "UpdatedDate": "2019-11-01T20:11:49.000Z",
        "WHOIS": {
            "CreationDate": "2003-07-24T18:51:45.000Z",
            "ExpirationDate": "2025-07-24T18:51:45.000Z",
            "NameServers": [
                "BONNIE.NS.CLOUDFLARE.COM",
                "CHUCK.NS.CLOUDFLARE.COM",
                "bonnie.ns.cloudflare.com",
                "chuck.ns.cloudflare.com"
            ],
            "Registrant": {
                "Country": "US",
                "Email": null,
                "Name": "Host Master",
                "Phone": null
            },
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "CSC CORPORATE DOMAINS, INC."
            },
            "UpdatedDate": "2019-11-01T20:11:49.000Z"
        }
    },
    "HelloWorld": {
        "Domain": {
            "address": "1440 McCarthy Blvd.",
            "city": "Milpitas",
            "country": "US",
            "creation_date": "2003-07-24T18:51:45.000Z",
            "dnssec": "unsigned",
            "domain": "internal-www.fireeye.com",
            "domain_name": [
                "FIREEYE.COM",
                "fireeye.com"
            ],
            "emails": [
                "domainabuse@cscglobal.com",
                "hostmaster@fireeye.com"
            ],
            "expiration_date": "2025-07-24T18:51:45.000Z",
            "name": "Host Master",
            "name_servers": [
                "BONNIE.NS.CLOUDFLARE.COM",
                "CHUCK.NS.CLOUDFLARE.COM",
                "bonnie.ns.cloudflare.com",
                "chuck.ns.cloudflare.com"
            ],
            "org": "FireEye, Inc.",
            "referral_url": null,
            "registrar": "CSC CORPORATE DOMAINS, INC.",
            "score": 32,
            "state": "CA",
            "status": [
                "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
                "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
                "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
                "clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited",
                "serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited",
                "serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited",
                "serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited"
            ],
            "updated_date": "2019-11-01T20:11:49.000Z",
            "whois_server": "whois.corporatedomains.com",
            "zipcode": "95035"
        }
    }
}
```

#### Human Readable Output

>### Domain List
>|address|city|country|creation_date|dnssec|domain|domain_name|emails|expiration_date|name|name_servers|org|referral_url|registrar|score|state|status|updated_date|whois_server|zipcode|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1440 McCarthy Blvd. | Milpitas | US | 2003-07-24T18:51:45.000Z | unsigned | internal-www.fireeye.com | FIREEYE.COM,<br/>fireeye.com | domainabuse@cscglobal.com,<br/>hostmaster@fireeye.com | 2025-07-24T18:51:45.000Z | Host Master | BONNIE.NS.CLOUDFLARE.COM,<br/>CHUCK.NS.CLOUDFLARE.COM,<br/>bonnie.ns.cloudflare.com,<br/>chuck.ns.cloudflare.com | FireEye, Inc. |  | CSC CORPORATE DOMAINS, INC. | 32 | CA | clientTransferProhibited https://icann.org/epp#clientTransferProhibited,<br/>serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited,<br/>serverTransferProhibited https://icann.org/epp#serverTransferProhibited,<br/>serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited,<br/>clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited,<br/>serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited,<br/>serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited,<br/>serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited | 2019-11-01T20:11:49.000Z | whois.corporatedomains.com | 95035 |


### url
***
Return URL Details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.URL.tenant_id | string | Tenant ID | 
| CTIX.URL.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.URL.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.URL.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.URL.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.URL.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.URL.intel_grading | string | Intel grading | 
| CTIX.URL.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.URL.indicator_type | string | Threat Data Object type | 
| CTIX.URL.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.URL.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.URL.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.URL.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.URL.source_grading | string | Source Grading | 
| CTIX.URL.name2 | string | Value of the Threat Data Object | 
| CTIX.URL.published_collections | unknown | Published collections | 
| CTIX.URL.published_package_id | unknown | Package ID | 
| CTIX.URL.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.URL.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.URL.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.URL.notification_preference | unknown | Notification preference | 
| CTIX.URL.followed_on | unknown | Followed On | 
| CTIX.URL.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.URL.type | string | Type  of object | 
| CTIX.URL.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.URL.subscriber | unknown | List of Subscribers | 
| CTIX.URL.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.URL.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.URL.object_type | string | Type of object | 
| CTIX.URL.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.URL.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.URL.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.URL.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.URL.asn | string | ASN number of the Threat Data Object | 
| CTIX.URL.registered_domain | string | Registered Domain | 
| CTIX.URL.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.URL.country | string | Geographic details of the Object | 
| CTIX.URL.registrar | string | Registrar | 
| CTIX.URL.file_extension | string | File Extension | 
| CTIX.URL.whitelisted | unknown | List | 
| CTIX.URL.object_description | string | Description of the Threat Data Object. | 
| CTIX.URL.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.URL.is_following | boolean | Boolean Value | 
| CTIX.URL.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.URL.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.URL.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.URL.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.URL.object_description_defang | string | Description of the object. | 
| CTIX.URL.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.URL.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.URL.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!url url=" https://covidfake1911.com" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "URL": {
            "asn": null,
            "blocked": false,
            "blocked_on": [],
            "blocked_time": 0,
            "country": null,
            "criticality": 3,
            "custom_score": 0,
            "deprecated": false,
            "deprecated_time": null,
            "domain_tld": ".com",
            "enhancement_data": {},
            "file_extension": null,
            "first_seen": 1605768210,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {},
            "indicator_type": "url",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [
                {
                    "colour_code": null,
                    "created": 1605030281,
                    "created_by": "system@default.tld",
                    "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                    "modified": 1605030281,
                    "modified_by": "system@default.tld",
                    "name": "anomalous-activity"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "3343924e-f422-4b10-9e21-62aa012e559a",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "backdoor"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "502a2bc4-3fc8-4d1a-8910-14c2c83cceab",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "bot"
                },
                {
                    "colour_code": null,
                    "created": 1605772450,
                    "created_by": "system@default.tld",
                    "id": "85c1f11f-0cd6-41a0-b762-2c305bf72985",
                    "modified": 1605772450,
                    "modified_by": "system@default.tld",
                    "name": "anonymization"
                },
                {
                    "colour_code": null,
                    "created": 1605194595,
                    "created_by": "system@default.tld",
                    "id": "ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54",
                    "modified": 1605194595,
                    "modified_by": "system@default.tld",
                    "name": "adware"
                },
                {
                    "colour_code": null,
                    "created": 1605769350,
                    "created_by": "system@default.tld",
                    "id": "cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13",
                    "modified": 1605769350,
                    "modified_by": "system@default.tld",
                    "name": "campaign"
                },
                {
                    "colour_code": null,
                    "created": 1605773317,
                    "created_by": "system@default.tld",
                    "id": "d38744ce-4d25-44ac-a114-9b2d8c72cad1",
                    "modified": 1605773317,
                    "modified_by": "system@default.tld",
                    "name": "activist"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "f14e5e48-5cce-46d2-af21-4c5d20cd5a90",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "exploit-kit"
                },
                {
                    "colour_code": null,
                    "created": 1605083522,
                    "created_by": "system@default.tld",
                    "id": "f684c479-d6fe-411c-a7e1-3352f68d079e",
                    "modified": 1605083522,
                    "modified_by": "system@default.tld",
                    "name": "label1"
                }
            ],
            "last_seen": 1605894588,
            "name2": "https://covidfake1911.com",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe",
                "package-63f2228a-7037-4e56-a3df-23644ba3be64"
            ],
            "published_collections": [
                "inbox & polling",
                "adsa",
                "newtestcollection1 - edited"
            ],
            "published_package_id": [
                "5df96375-1e0d-494b-870f-3f029d5cc565",
                "bbb62de5-f71f-4ca9-81b7-c4e94e3640cf",
                "96c58eb5-5784-4de5-8aa7-b4292525914c"
            ],
            "registered_domain": "covidfake1911.com",
            "registrar": null,
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [
                    {
                        "custom_score": 0,
                        "deprecated": false,
                        "first_seen": 1605768210,
                        "id": "indicator--1a4e6b89-93cb-46e2-88c2-0a6e0be08ed7",
                        "intel_grading": null,
                        "labels": [
                            {
                                "colour_code": null,
                                "created": 1605030281,
                                "created_by": "system@default.tld",
                                "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                                "modified": 1605030281,
                                "modified_by": "system@default.tld",
                                "name": "anomalous-activity"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "3343924e-f422-4b10-9e21-62aa012e559a",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "backdoor"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "502a2bc4-3fc8-4d1a-8910-14c2c83cceab",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "bot"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "60a8fa11-aeba-4fcf-aabb-cee8a07ba4e5",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "dropper"
                            },
                            {
                                "colour_code": null,
                                "created": 1605772450,
                                "created_by": "system@default.tld",
                                "id": "85c1f11f-0cd6-41a0-b762-2c305bf72985",
                                "modified": 1605772450,
                                "modified_by": "system@default.tld",
                                "name": "anonymization"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "aa5d9110-663b-4b9d-a58f-1e165f484ed3",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "denial-of-service"
                            },
                            {
                                "colour_code": null,
                                "created": 1605194595,
                                "created_by": "system@default.tld",
                                "id": "ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54",
                                "modified": 1605194595,
                                "modified_by": "system@default.tld",
                                "name": "adware"
                            },
                            {
                                "colour_code": null,
                                "created": 1605769350,
                                "created_by": "system@default.tld",
                                "id": "cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13",
                                "modified": 1605769350,
                                "modified_by": "system@default.tld",
                                "name": "campaign"
                            },
                            {
                                "colour_code": null,
                                "created": 1605773317,
                                "created_by": "system@default.tld",
                                "id": "d38744ce-4d25-44ac-a114-9b2d8c72cad1",
                                "modified": 1605773317,
                                "modified_by": "system@default.tld",
                                "name": "activist"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "ef1034b6-558a-46b7-8e4d-8f46510aa4d9",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "ddos"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "f14e5e48-5cce-46d2-af21-4c5d20cd5a90",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "exploit-kit"
                            },
                            {
                                "colour_code": null,
                                "created": 1605083522,
                                "created_by": "system@default.tld",
                                "id": "f684c479-d6fe-411c-a7e1-3352f68d079e",
                                "modified": 1605083522,
                                "modified_by": "system@default.tld",
                                "name": "label1"
                            }
                        ],
                        "last_seen": 1605894588,
                        "name2": "97.40.19.11",
                        "object_description": "",
                        "object_description_defang": "",
                        "object_type": "indicator",
                        "package_id": [
                            "package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe",
                            "package-63f2228a-7037-4e56-a3df-23644ba3be64"
                        ],
                        "published_collections": [
                            "inbox & polling",
                            "newtestcollection1 - edited",
                            "adsa"
                        ],
                        "published_package_id": [
                            "5df96375-1e0d-494b-870f-3f029d5cc565",
                            "bbb62de5-f71f-4ca9-81b7-c4e94e3640cf",
                            "96c58eb5-5784-4de5-8aa7-b4292525914c"
                        ],
                        "source": [
                            "customsource1.x",
                            "Import"
                        ],
                        "source_data": [
                            {
                                "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                                "name": "Import"
                            },
                            {
                                "id": "012072c9-1421-4960-ab01-2bb541596374",
                                "name": "customsource1.x"
                            }
                        ],
                        "source_grading": null,
                        "stix_object_id": "indicator--1a4e6b89-93cb-46e2-88c2-0a6e0be08ed7",
                        "subscriber": [],
                        "tlp_data": "GREEN",
                        "type": "Indicator"
                    },
                    {
                        "custom_score": 0,
                        "deprecated": false,
                        "first_seen": 1605768210,
                        "id": "indicator--48cb83e0-f26b-40c5-bb63-b2ce73454bed",
                        "intel_grading": null,
                        "labels": [
                            {
                                "colour_code": null,
                                "created": 1605030281,
                                "created_by": "system@default.tld",
                                "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                                "modified": 1605030281,
                                "modified_by": "system@default.tld",
                                "name": "anomalous-activity"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "3343924e-f422-4b10-9e21-62aa012e559a",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "backdoor"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "502a2bc4-3fc8-4d1a-8910-14c2c83cceab",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "bot"
                            },
                            {
                                "colour_code": null,
                                "created": 1605772450,
                                "created_by": "system@default.tld",
                                "id": "85c1f11f-0cd6-41a0-b762-2c305bf72985",
                                "modified": 1605772450,
                                "modified_by": "system@default.tld",
                                "name": "anonymization"
                            },
                            {
                                "colour_code": null,
                                "created": 1605194595,
                                "created_by": "system@default.tld",
                                "id": "ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54",
                                "modified": 1605194595,
                                "modified_by": "system@default.tld",
                                "name": "adware"
                            },
                            {
                                "colour_code": null,
                                "created": 1605769350,
                                "created_by": "system@default.tld",
                                "id": "cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13",
                                "modified": 1605769350,
                                "modified_by": "system@default.tld",
                                "name": "campaign"
                            },
                            {
                                "colour_code": null,
                                "created": 1605773317,
                                "created_by": "system@default.tld",
                                "id": "d38744ce-4d25-44ac-a114-9b2d8c72cad1",
                                "modified": 1605773317,
                                "modified_by": "system@default.tld",
                                "name": "activist"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "f14e5e48-5cce-46d2-af21-4c5d20cd5a90",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "exploit-kit"
                            },
                            {
                                "colour_code": null,
                                "created": 1605083522,
                                "created_by": "system@default.tld",
                                "id": "f684c479-d6fe-411c-a7e1-3352f68d079e",
                                "modified": 1605083522,
                                "modified_by": "system@default.tld",
                                "name": "label1"
                            }
                        ],
                        "last_seen": 1605894588,
                        "name2": "https://evil1911.com",
                        "object_description": "",
                        "object_description_defang": "",
                        "object_type": "indicator",
                        "package_id": [
                            "package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe",
                            "package-63f2228a-7037-4e56-a3df-23644ba3be64"
                        ],
                        "published_collections": [
                            "inbox & polling",
                            "newtestcollection1 - edited",
                            "adsa"
                        ],
                        "published_package_id": [
                            "5df96375-1e0d-494b-870f-3f029d5cc565",
                            "bbb62de5-f71f-4ca9-81b7-c4e94e3640cf",
                            "96c58eb5-5784-4de5-8aa7-b4292525914c"
                        ],
                        "source": [
                            "customsource1.x",
                            "Import"
                        ],
                        "source_data": [
                            {
                                "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                                "name": "Import"
                            },
                            {
                                "id": "012072c9-1421-4960-ab01-2bb541596374",
                                "name": "customsource1.x"
                            }
                        ],
                        "source_grading": null,
                        "stix_object_id": "indicator--48cb83e0-f26b-40c5-bb63-b2ce73454bed",
                        "subscriber": [],
                        "tlp_data": "GREEN",
                        "type": "Indicator"
                    },
                    {
                        "custom_score": 0,
                        "deprecated": false,
                        "first_seen": 1605768210,
                        "id": "indicator--62b8f466-71ac-4bfd-ae57-713045eef87e",
                        "intel_grading": null,
                        "labels": [
                            {
                                "colour_code": null,
                                "created": 1605030281,
                                "created_by": "system@default.tld",
                                "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                                "modified": 1605030281,
                                "modified_by": "system@default.tld",
                                "name": "anomalous-activity"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "3343924e-f422-4b10-9e21-62aa012e559a",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "backdoor"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "502a2bc4-3fc8-4d1a-8910-14c2c83cceab",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "bot"
                            },
                            {
                                "colour_code": null,
                                "created": 1605772450,
                                "created_by": "system@default.tld",
                                "id": "85c1f11f-0cd6-41a0-b762-2c305bf72985",
                                "modified": 1605772450,
                                "modified_by": "system@default.tld",
                                "name": "anonymization"
                            },
                            {
                                "colour_code": null,
                                "created": 1605194595,
                                "created_by": "system@default.tld",
                                "id": "ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54",
                                "modified": 1605194595,
                                "modified_by": "system@default.tld",
                                "name": "adware"
                            },
                            {
                                "colour_code": null,
                                "created": 1605769350,
                                "created_by": "system@default.tld",
                                "id": "cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13",
                                "modified": 1605769350,
                                "modified_by": "system@default.tld",
                                "name": "campaign"
                            },
                            {
                                "colour_code": null,
                                "created": 1605773317,
                                "created_by": "system@default.tld",
                                "id": "d38744ce-4d25-44ac-a114-9b2d8c72cad1",
                                "modified": 1605773317,
                                "modified_by": "system@default.tld",
                                "name": "activist"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "f14e5e48-5cce-46d2-af21-4c5d20cd5a90",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "exploit-kit"
                            },
                            {
                                "colour_code": null,
                                "created": 1605083522,
                                "created_by": "system@default.tld",
                                "id": "f684c479-d6fe-411c-a7e1-3352f68d079e",
                                "modified": 1605083522,
                                "modified_by": "system@default.tld",
                                "name": "label1"
                            }
                        ],
                        "last_seen": 1605894588,
                        "name2": "evil1911.com",
                        "object_description": "",
                        "object_description_defang": "",
                        "object_type": "indicator",
                        "package_id": [
                            "package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe",
                            "package-63f2228a-7037-4e56-a3df-23644ba3be64"
                        ],
                        "published_collections": [
                            "inbox & polling",
                            "newtestcollection1 - edited",
                            "adsa"
                        ],
                        "published_package_id": [
                            "5df96375-1e0d-494b-870f-3f029d5cc565",
                            "bbb62de5-f71f-4ca9-81b7-c4e94e3640cf",
                            "96c58eb5-5784-4de5-8aa7-b4292525914c"
                        ],
                        "source": [
                            "customsource1.x",
                            "Import"
                        ],
                        "source_data": [
                            {
                                "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                                "name": "Import"
                            },
                            {
                                "id": "012072c9-1421-4960-ab01-2bb541596374",
                                "name": "customsource1.x"
                            }
                        ],
                        "source_grading": null,
                        "stix_object_id": "indicator--62b8f466-71ac-4bfd-ae57-713045eef87e",
                        "subscriber": [],
                        "tlp_data": "GREEN",
                        "type": "Indicator"
                    },
                    {
                        "custom_score": 0,
                        "deprecated": false,
                        "first_seen": 1605768210,
                        "id": "indicator--d5245159-7ac2-4cbf-9f43-b71b74f24367",
                        "intel_grading": null,
                        "labels": [
                            {
                                "colour_code": null,
                                "created": 1605030281,
                                "created_by": "system@default.tld",
                                "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                                "modified": 1605030281,
                                "modified_by": "system@default.tld",
                                "name": "anomalous-activity"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "3343924e-f422-4b10-9e21-62aa012e559a",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "backdoor"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "502a2bc4-3fc8-4d1a-8910-14c2c83cceab",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "bot"
                            },
                            {
                                "colour_code": null,
                                "created": 1605772450,
                                "created_by": "system@default.tld",
                                "id": "85c1f11f-0cd6-41a0-b762-2c305bf72985",
                                "modified": 1605772450,
                                "modified_by": "system@default.tld",
                                "name": "anonymization"
                            },
                            {
                                "colour_code": null,
                                "created": 1605194595,
                                "created_by": "system@default.tld",
                                "id": "ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54",
                                "modified": 1605194595,
                                "modified_by": "system@default.tld",
                                "name": "adware"
                            },
                            {
                                "colour_code": null,
                                "created": 1605769350,
                                "created_by": "system@default.tld",
                                "id": "cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13",
                                "modified": 1605769350,
                                "modified_by": "system@default.tld",
                                "name": "campaign"
                            },
                            {
                                "colour_code": null,
                                "created": 1605773317,
                                "created_by": "system@default.tld",
                                "id": "d38744ce-4d25-44ac-a114-9b2d8c72cad1",
                                "modified": 1605773317,
                                "modified_by": "system@default.tld",
                                "name": "activist"
                            },
                            {
                                "colour_code": null,
                                "created": 1605589246,
                                "created_by": "system@default.tld",
                                "id": "f14e5e48-5cce-46d2-af21-4c5d20cd5a90",
                                "modified": 1605589246,
                                "modified_by": "system@default.tld",
                                "name": "exploit-kit"
                            },
                            {
                                "colour_code": null,
                                "created": 1605083522,
                                "created_by": "system@default.tld",
                                "id": "f684c479-d6fe-411c-a7e1-3352f68d079e",
                                "modified": 1605083522,
                                "modified_by": "system@default.tld",
                                "name": "label1"
                            }
                        ],
                        "last_seen": 1605894588,
                        "name2": "800e075ca6e74d896d693f155cf71911",
                        "object_description": "",
                        "object_description_defang": "",
                        "object_type": "indicator",
                        "package_id": [
                            "package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe",
                            "package-63f2228a-7037-4e56-a3df-23644ba3be64"
                        ],
                        "published_collections": [
                            "inbox & polling",
                            "newtestcollection1 - edited",
                            "adsa"
                        ],
                        "published_package_id": [
                            "5df96375-1e0d-494b-870f-3f029d5cc565",
                            "bbb62de5-f71f-4ca9-81b7-c4e94e3640cf",
                            "96c58eb5-5784-4de5-8aa7-b4292525914c"
                        ],
                        "source": [
                            "customsource1.x",
                            "Import"
                        ],
                        "source_data": [
                            {
                                "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                                "name": "Import"
                            },
                            {
                                "id": "012072c9-1421-4960-ab01-2bb541596374",
                                "name": "customsource1.x"
                            }
                        ],
                        "source_grading": null,
                        "stix_object_id": "indicator--d5245159-7ac2-4cbf-9f43-b71b74f24367",
                        "subscriber": [],
                        "tlp_data": "GREEN",
                        "type": "Indicator"
                    }
                ],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 5,
            "score": 58.18,
            "source": [
                "customsource1.x",
                "Import"
            ],
            "source_data": [
                {
                    "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                    "name": "Import"
                },
                {
                    "id": "012072c9-1421-4960-ab01-2bb541596374",
                    "name": "customsource1.x"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--70414571-660b-4360-b064-f0cf58caf903",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": "GREEN",
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "https://covidfake1911.com",
            "whitelisted": []
        }
    },
    "DBotScore": {
        "Indicator": "https://covidfake1911.com",
        "Score": 2,
        "Type": "url",
        "Vendor": "CTIX"
    },
    "URL": {
        "Data": "https://covidfake1911.com"
    }
}
```

#### Human Readable Output

>### URL List
>|blocked|blocked_time|criticality|custom_score|deprecated|domain_tld|first_seen|indicator_type|is_false_positive|is_following|labels|last_seen|name2|object_type|package_id|published_collections|published_package_id|registered_domain|related_fields|reviewed|reviewed_time|risk_severity|score|source|source_data|stix_object_id|tenant_id|tlp_data|type|under_review|under_reviewed_time|value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 0 | 3 | 0.0 | false | .com | 1605768210 | url | false | false | {'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281},<br/>{'id': '3343924e-f422-4b10-9e21-62aa012e559a', 'name': 'backdoor', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246},<br/>{'id': '502a2bc4-3fc8-4d1a-8910-14c2c83cceab', 'name': 'bot', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246},<br/>{'id': '85c1f11f-0cd6-41a0-b762-2c305bf72985', 'name': 'anonymization', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605772450, 'modified_by': 'system@default.tld', 'modified': 1605772450},<br/>{'id': 'ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54', 'name': 'adware', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605194595, 'modified_by': 'system@default.tld', 'modified': 1605194595},<br/>{'id': 'cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13', 'name': 'campaign', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605769350, 'modified_by': 'system@default.tld', 'modified': 1605769350},<br/>{'id': 'd38744ce-4d25-44ac-a114-9b2d8c72cad1', 'name': 'activist', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605773317, 'modified_by': 'system@default.tld', 'modified': 1605773317},<br/>{'id': 'f14e5e48-5cce-46d2-af21-4c5d20cd5a90', 'name': 'exploit-kit', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246},<br/>{'id': 'f684c479-d6fe-411c-a7e1-3352f68d079e', 'name': 'label1', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605083522, 'modified_by': 'system@default.tld', 'modified': 1605083522} | 1605894588 | https://covidfake1911.com | indicator | package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe,<br/>package-63f2228a-7037-4e56-a3df-23644ba3be64 | inbox & polling,<br/>adsa,<br/>newtestcollection1 - edited | 5df96375-1e0d-494b-870f-3f029d5cc565,<br/>bbb62de5-f71f-4ca9-81b7-c4e94e3640cf,<br/>96c58eb5-5784-4de5-8aa7-b4292525914c | covidfake1911.com | attack_pattern: <br/>campaign: <br/>intrusion_set: <br/>malware: <br/>threat_actor: <br/>tool: <br/>indicator: {'id': 'indicator--1a4e6b89-93cb-46e2-88c2-0a6e0be08ed7', 'stix_object_id': 'indicator--1a4e6b89-93cb-46e2-88c2-0a6e0be08ed7', 'first_seen': 1605768210, 'last_seen': 1605894588, 'name2': '97.40.19.11', 'source_grading': None, 'intel_grading': None, 'source': ['customsource1.x', 'Import'], 'published_collections': ['inbox & polling', 'newtestcollection1 - edited', 'adsa'], 'published_package_id': ['5df96375-1e0d-494b-870f-3f029d5cc565', 'bbb62de5-f71f-4ca9-81b7-c4e94e3640cf', '96c58eb5-5784-4de5-8aa7-b4292525914c'], 'package_id': ['package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe', 'package-63f2228a-7037-4e56-a3df-23644ba3be64'], 'labels': [{'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281}, {'id': '3343924e-f422-4b10-9e21-62aa012e559a', 'name': 'backdoor', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '502a2bc4-3fc8-4d1a-8910-14c2c83cceab', 'name': 'bot', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '60a8fa11-aeba-4fcf-aabb-cee8a07ba4e5', 'name': 'dropper', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '85c1f11f-0cd6-41a0-b762-2c305bf72985', 'name': 'anonymization', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605772450, 'modified_by': 'system@default.tld', 'modified': 1605772450}, {'id': 'aa5d9110-663b-4b9d-a58f-1e165f484ed3', 'name': 'denial-of-service', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': 'ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54', 'name': 'adware', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605194595, 'modified_by': 'system@default.tld', 'modified': 1605194595}, {'id': 'cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13', 'name': 'campaign', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605769350, 'modified_by': 'system@default.tld', 'modified': 1605769350}, {'id': 'd38744ce-4d25-44ac-a114-9b2d8c72cad1', 'name': 'activist', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605773317, 'modified_by': 'system@default.tld', 'modified': 1605773317}, {'id': 'ef1034b6-558a-46b7-8e4d-8f46510aa4d9', 'name': 'ddos', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': 'f14e5e48-5cce-46d2-af21-4c5d20cd5a90', 'name': 'exploit-kit', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': 'f684c479-d6fe-411c-a7e1-3352f68d079e', 'name': 'label1', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605083522, 'modified_by': 'system@default.tld', 'modified': 1605083522}], 'object_description': '', 'custom_score': 0.0, 'tlp_data': 'GREEN', 'subscriber': [], 'object_description_defang': '', 'object_type': 'indicator', 'type': 'Indicator', 'source_data': [{'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'}, {'name': 'customsource1.x', 'id': '012072c9-1421-4960-ab01-2bb541596374'}], 'deprecated': False},<br/>{'id': 'indicator--48cb83e0-f26b-40c5-bb63-b2ce73454bed', 'stix_object_id': 'indicator--48cb83e0-f26b-40c5-bb63-b2ce73454bed', 'first_seen': 1605768210, 'last_seen': 1605894588, 'name2': 'https://evil1911.com', 'source_grading': None, 'intel_grading': None, 'source': ['customsource1.x', 'Import'], 'published_collections': ['inbox & polling', 'newtestcollection1 - edited', 'adsa'], 'published_package_id': ['5df96375-1e0d-494b-870f-3f029d5cc565', 'bbb62de5-f71f-4ca9-81b7-c4e94e3640cf', '96c58eb5-5784-4de5-8aa7-b4292525914c'], 'package_id': ['package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe', 'package-63f2228a-7037-4e56-a3df-23644ba3be64'], 'labels': [{'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281}, {'id': '3343924e-f422-4b10-9e21-62aa012e559a', 'name': 'backdoor', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '502a2bc4-3fc8-4d1a-8910-14c2c83cceab', 'name': 'bot', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '85c1f11f-0cd6-41a0-b762-2c305bf72985', 'name': 'anonymization', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605772450, 'modified_by': 'system@default.tld', 'modified': 1605772450}, {'id': 'ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54', 'name': 'adware', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605194595, 'modified_by': 'system@default.tld', 'modified': 1605194595}, {'id': 'cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13', 'name': 'campaign', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605769350, 'modified_by': 'system@default.tld', 'modified': 1605769350}, {'id': 'd38744ce-4d25-44ac-a114-9b2d8c72cad1', 'name': 'activist', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605773317, 'modified_by': 'system@default.tld', 'modified': 1605773317}, {'id': 'f14e5e48-5cce-46d2-af21-4c5d20cd5a90', 'name': 'exploit-kit', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': 'f684c479-d6fe-411c-a7e1-3352f68d079e', 'name': 'label1', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605083522, 'modified_by': 'system@default.tld', 'modified': 1605083522}], 'object_description': '', 'custom_score': 0.0, 'tlp_data': 'GREEN', 'subscriber': [], 'object_description_defang': '', 'object_type': 'indicator', 'type': 'Indicator', 'source_data': [{'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'}, {'name': 'customsource1.x', 'id': '012072c9-1421-4960-ab01-2bb541596374'}], 'deprecated': False},<br/>{'id': 'indicator--62b8f466-71ac-4bfd-ae57-713045eef87e', 'stix_object_id': 'indicator--62b8f466-71ac-4bfd-ae57-713045eef87e', 'first_seen': 1605768210, 'last_seen': 1605894588, 'name2': 'evil1911.com', 'source_grading': None, 'intel_grading': None, 'source': ['customsource1.x', 'Import'], 'published_collections': ['inbox & polling', 'newtestcollection1 - edited', 'adsa'], 'published_package_id': ['5df96375-1e0d-494b-870f-3f029d5cc565', 'bbb62de5-f71f-4ca9-81b7-c4e94e3640cf', '96c58eb5-5784-4de5-8aa7-b4292525914c'], 'package_id': ['package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe', 'package-63f2228a-7037-4e56-a3df-23644ba3be64'], 'labels': [{'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281}, {'id': '3343924e-f422-4b10-9e21-62aa012e559a', 'name': 'backdoor', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '502a2bc4-3fc8-4d1a-8910-14c2c83cceab', 'name': 'bot', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '85c1f11f-0cd6-41a0-b762-2c305bf72985', 'name': 'anonymization', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605772450, 'modified_by': 'system@default.tld', 'modified': 1605772450}, {'id': 'ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54', 'name': 'adware', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605194595, 'modified_by': 'system@default.tld', 'modified': 1605194595}, {'id': 'cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13', 'name': 'campaign', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605769350, 'modified_by': 'system@default.tld', 'modified': 1605769350}, {'id': 'd38744ce-4d25-44ac-a114-9b2d8c72cad1', 'name': 'activist', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605773317, 'modified_by': 'system@default.tld', 'modified': 1605773317}, {'id': 'f14e5e48-5cce-46d2-af21-4c5d20cd5a90', 'name': 'exploit-kit', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': 'f684c479-d6fe-411c-a7e1-3352f68d079e', 'name': 'label1', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605083522, 'modified_by': 'system@default.tld', 'modified': 1605083522}], 'object_description': '', 'custom_score': 0.0, 'tlp_data': 'GREEN', 'subscriber': [], 'object_description_defang': '', 'object_type': 'indicator', 'type': 'Indicator', 'source_data': [{'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'}, {'name': 'customsource1.x', 'id': '012072c9-1421-4960-ab01-2bb541596374'}], 'deprecated': False},<br/>{'id': 'indicator--d5245159-7ac2-4cbf-9f43-b71b74f24367', 'stix_object_id': 'indicator--d5245159-7ac2-4cbf-9f43-b71b74f24367', 'first_seen': 1605768210, 'last_seen': 1605894588, 'name2': '800e075ca6e74d896d693f155cf71911', 'source_grading': None, 'intel_grading': None, 'source': ['customsource1.x', 'Import'], 'published_collections': ['inbox & polling', 'newtestcollection1 - edited', 'adsa'], 'published_package_id': ['5df96375-1e0d-494b-870f-3f029d5cc565', 'bbb62de5-f71f-4ca9-81b7-c4e94e3640cf', '96c58eb5-5784-4de5-8aa7-b4292525914c'], 'package_id': ['package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe', 'package-63f2228a-7037-4e56-a3df-23644ba3be64'], 'labels': [{'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281}, {'id': '3343924e-f422-4b10-9e21-62aa012e559a', 'name': 'backdoor', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '502a2bc4-3fc8-4d1a-8910-14c2c83cceab', 'name': 'bot', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': '85c1f11f-0cd6-41a0-b762-2c305bf72985', 'name': 'anonymization', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605772450, 'modified_by': 'system@default.tld', 'modified': 1605772450}, {'id': 'ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54', 'name': 'adware', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605194595, 'modified_by': 'system@default.tld', 'modified': 1605194595}, {'id': 'cd4d5ef2-9fd8-4fd4-977d-a1b3145eaa13', 'name': 'campaign', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605769350, 'modified_by': 'system@default.tld', 'modified': 1605769350}, {'id': 'd38744ce-4d25-44ac-a114-9b2d8c72cad1', 'name': 'activist', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605773317, 'modified_by': 'system@default.tld', 'modified': 1605773317}, {'id': 'f14e5e48-5cce-46d2-af21-4c5d20cd5a90', 'name': 'exploit-kit', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246}, {'id': 'f684c479-d6fe-411c-a7e1-3352f68d079e', 'name': 'label1', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605083522, 'modified_by': 'system@default.tld', 'modified': 1605083522}], 'object_description': '', 'custom_score': 0.0, 'tlp_data': 'GREEN', 'subscriber': [], 'object_description_defang': '', 'object_type': 'indicator', 'type': 'Indicator', 'source_data': [{'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'}, {'name': 'customsource1.x', 'id': '012072c9-1421-4960-ab01-2bb541596374'}], 'deprecated': False}<br/>ttp: <br/>kill_chain_phases: <br/>course_of_action:  | false | 0 | 5 | 58.18 | customsource1.x,<br/>Import | {'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'},<br/>{'name': 'customsource1.x', 'id': '012072c9-1421-4960-ab01-2bb541596374'} | indicator--70414571-660b-4360-b064-f0cf58caf903 | 0a834138-cc59-4107-aa69-46e6080f06af | GREEN | Indicator | false | 0 | https://covidfake1911.com |


### file
***
Return File Details.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of Files. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The full file name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.File.tenant_id | string | Tenant ID | 
| CTIX.File.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.File.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.File.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.File.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.File.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.File.intel_grading | string | Intel grading | 
| CTIX.File.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.File.indicator_type | string | Threat Data Object type | 
| CTIX.File.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.File.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.File.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.File.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.File.source_grading | string | Source Grading | 
| CTIX.File.name2 | string | Value of the Threat Data Object | 
| CTIX.File.published_collections | unknown | Published collections | 
| CTIX.File.published_package_id | unknown | Package ID | 
| CTIX.File.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.File.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.File.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.File.notification_preference | unknown | Notification preference | 
| CTIX.File.followed_on | unknown | Followed On | 
| CTIX.File.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.File.type | string | Type  of object | 
| CTIX.File.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.File.subscriber | unknown | List of Subscribers | 
| CTIX.File.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.File.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.File.object_type | string | Type of object | 
| CTIX.File.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.File.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.File.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.File.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.File.asn | string | ASN number of the Threat Data Object | 
| CTIX.File.registered_domain | string | Registered Domain | 
| CTIX.File.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.File.country | string | Geographic details of the Object | 
| CTIX.File.registrar | string | Registrar | 
| CTIX.File.file_extension | string | File Extension | 
| CTIX.File.whitelisted | unknown | List | 
| CTIX.File.object_description | string | Description of the Threat Data Object. | 
| CTIX.File.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.File.is_following | boolean | Boolean Value | 
| CTIX.File.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.File.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.File.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.File.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.File.object_description_defang | string | Description of the object. | 
| CTIX.File.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.File.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.File.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!file file="4ebb2b00a11f9361cf3757e96f14ad4b" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "File": {
            "asn": null,
            "blocked": false,
            "blocked_on": [],
            "blocked_time": 0,
            "country": null,
            "criticality": 3,
            "custom_score": 0,
            "deprecated": true,
            "deprecated_time": 1588854933,
            "domain_tld": null,
            "enhancement_data": {},
            "file_extension": null,
            "first_seen": 1586262933,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {},
            "indicator_type": "MD5",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [
                {
                    "colour_code": null,
                    "created": 1605030281,
                    "created_by": "system@default.tld",
                    "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                    "modified": 1605030281,
                    "modified_by": "system@default.tld",
                    "name": "anomalous-activity"
                },
                {
                    "colour_code": null,
                    "created": 1605772450,
                    "created_by": "system@default.tld",
                    "id": "85c1f11f-0cd6-41a0-b762-2c305bf72985",
                    "modified": 1605772450,
                    "modified_by": "system@default.tld",
                    "name": "anonymization"
                },
                {
                    "colour_code": null,
                    "created": 1605772450,
                    "created_by": "system@default.tld",
                    "id": "9dafe666-9c26-4d11-bc3a-d72ad2dcc136",
                    "modified": 1605772450,
                    "modified_by": "system@default.tld",
                    "name": "benign"
                },
                {
                    "colour_code": null,
                    "created": 1605194595,
                    "created_by": "system@default.tld",
                    "id": "ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54",
                    "modified": 1605194595,
                    "modified_by": "system@default.tld",
                    "name": "adware"
                },
                {
                    "colour_code": null,
                    "created": 1605773317,
                    "created_by": "system@default.tld",
                    "id": "d38744ce-4d25-44ac-a114-9b2d8c72cad1",
                    "modified": 1605773317,
                    "modified_by": "system@default.tld",
                    "name": "activist"
                },
                {
                    "colour_code": null,
                    "created": 1605589246,
                    "created_by": "system@default.tld",
                    "id": "f14e5e48-5cce-46d2-af21-4c5d20cd5a90",
                    "modified": 1605589246,
                    "modified_by": "system@default.tld",
                    "name": "exploit-kit"
                },
                {
                    "colour_code": null,
                    "created": 1605083522,
                    "created_by": "system@default.tld",
                    "id": "f684c479-d6fe-411c-a7e1-3352f68d079e",
                    "modified": 1605083522,
                    "modified_by": "system@default.tld",
                    "name": "label1"
                }
            ],
            "last_seen": 1605791028,
            "name2": "4ebb2b00a11f9361cf3757e96f14ad4b",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-d54892d8-b495-4331-b361-17ffbeacdaed",
                "bundle--87151b50-31a4-4f0a-9f5f-282b0f1d1285",
                "package-09be25b9-5d6b-4320-b512-4dc0e088f434"
            ],
            "published_collections": [
                "newtestcollection1 - edited",
                "adsa"
            ],
            "published_package_id": [
                "1557df73-68b4-485b-9821-e3036e5fb7a4",
                "a1eb2b29-fed4-4635-8e5c-a74f4339b8ab"
            ],
            "registered_domain": null,
            "registrar": null,
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 5,
            "score": 50,
            "source": [
                "Import"
            ],
            "source_data": [
                {
                    "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                    "name": "Import"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--2e35588f-cde1-4492-a720-ab0aee7fafaa",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": null,
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "4ebb2b00a11f9361cf3757e96f14ad4b",
            "whitelisted": []
        }
    },
    "DBotScore": {
        "Indicator": "4ebb2b00a11f9361cf3757e96f14ad4b",
        "Score": 2,
        "Type": "file",
        "Vendor": "CTIX"
    },
    "File": {
        "Name": "4ebb2b00a11f9361cf3757e96f14ad4b"
    }
}
```

#### Human Readable Output

>### File List
>|blocked|blocked_time|criticality|custom_score|deprecated|deprecated_time|first_seen|indicator_type|is_false_positive|is_following|labels|last_seen|name2|object_type|package_id|published_collections|published_package_id|related_fields|reviewed|reviewed_time|risk_severity|score|source|source_data|stix_object_id|tenant_id|type|under_review|under_reviewed_time|value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 0 | 3 | 0.0 | true | 1588854933 | 1586262933 | MD5 | false | false | {'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281},<br/>{'id': '85c1f11f-0cd6-41a0-b762-2c305bf72985', 'name': 'anonymization', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605772450, 'modified_by': 'system@default.tld', 'modified': 1605772450},<br/>{'id': '9dafe666-9c26-4d11-bc3a-d72ad2dcc136', 'name': 'benign', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605772450, 'modified_by': 'system@default.tld', 'modified': 1605772450},<br/>{'id': 'ba0b6eaf-f5ae-44d7-ab91-f189a76e8b54', 'name': 'adware', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605194595, 'modified_by': 'system@default.tld', 'modified': 1605194595},<br/>{'id': 'd38744ce-4d25-44ac-a114-9b2d8c72cad1', 'name': 'activist', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605773317, 'modified_by': 'system@default.tld', 'modified': 1605773317},<br/>{'id': 'f14e5e48-5cce-46d2-af21-4c5d20cd5a90', 'name': 'exploit-kit', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605589246, 'modified_by': 'system@default.tld', 'modified': 1605589246},<br/>{'id': 'f684c479-d6fe-411c-a7e1-3352f68d079e', 'name': 'label1', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605083522, 'modified_by': 'system@default.tld', 'modified': 1605083522} | 1605791028 | 4ebb2b00a11f9361cf3757e96f14ad4b | indicator | package-d54892d8-b495-4331-b361-17ffbeacdaed,<br/>bundle--87151b50-31a4-4f0a-9f5f-282b0f1d1285,<br/>package-09be25b9-5d6b-4320-b512-4dc0e088f434 | newtestcollection1 - edited,<br/>adsa | 1557df73-68b4-485b-9821-e3036e5fb7a4,<br/>a1eb2b29-fed4-4635-8e5c-a74f4339b8ab | attack_pattern: <br/>campaign: <br/>intrusion_set: <br/>malware: <br/>threat_actor: <br/>tool: <br/>indicator: <br/>ttp: <br/>kill_chain_phases: <br/>course_of_action:  | false | 0 | 5 | 50.0 | Import | {'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'} | indicator--2e35588f-cde1-4492-a720-ab0aee7fafaa | 0a834138-cc59-4107-aa69-46e6080f06af | Indicator | false | 0 | 4ebb2b00a11f9361cf3757e96f14ad4b |

