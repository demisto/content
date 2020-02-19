import demistomock as demisto
from CommonServerPython import *
import pytest
import sdv
import lxml

CIDR_INDICATORS = '''
{
   "iocs":[
      {
         "id":"9891",
         "version":1,
         "modified":"2020-02-19T17:45:07.468975+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"09c8f0ad-bbb7-4b20-81f7-3b440a3274c4",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-19T17:45:07.433422+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"AWS Feed.AWS Feed_instance_1",
               "entryId":"",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-19T17:45:07.468974+02:00",
         "indicator_type":"CIDR",
         "value":"18.163.0.0/16",
         "sourceInstances":[
            "AWS Feed_instance_1"
         ],
         "sourceBrands":[
            "AWS Feed"
         ],
         "investigationIDs":[

         ],
         "lastSeen":"0001-01-01T00:00:00Z",
         "firstSeen":"0001-01-01T00:00:00Z",
         "lastSeenEntryID":"API",
         "firstSeenEntryID":"API",
         "score":1,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "moduleToFeedMap":{
            "5a39582b-cf1c-4abc-8cb6-336924f8621f":{
               "reliability":"A - Completely reliable",
               "fetchTime":"2020-02-19T17:45:06+02:00",
               "sourceBrand":"AWS Feed",
               "sourceInstance":"AWS Feed_instance_1",
               "moduleId":"5a39582b-cf1c-4abc-8cb6-336924f8621f",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":1,
               "classifierVersion":1,
               "feedConfig":{
                  "feed":true,
                  "feedBypassExclusionList":null,
                  "feedExpirationInterval":null,
                  "feedExpirationPolicy":"indicatorType",
                  "feedFetchInterval":"240",
                  "feedReliability":"A - Completely reliable",
                  "feedReputation":"Good",
                  "insecure":true,
                  "proxy":false,
                  "regions":null,
                  "sub_feeds":[
                     "AMAZON"
                  ]
               },
               "type":"CIDR",
               "value":"18.163.0.0/16",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"2020-02-19T17:45:06+02:00",
               "ExpirationSource":{
                  "setTime":"2020-02-19T17:45:07.42224+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"AWS Feed",
                  "instance":"AWS Feed_instance_1",
                  "moduleId":"5a39582b-cf1c-4abc-8cb6-336924f8621f",
                  "expirationPolicy":"indicatorType",
                  "expirationInterval":10080
               },
               "rawJSON":null,
               "isEnrichment":false
            }
         },
         "isShared":false,
         "expiration":"2020-02-26T17:45:08.373351+02:00",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"active",
         "expirationSource":{
            "setTime":"2020-02-19T17:45:07.42224+02:00",
            "source":"indicatorType",
            "user":"",
            "brand":"AWS Feed",
            "instance":"AWS Feed_instance_1",
            "moduleId":"5a39582b-cf1c-4abc-8cb6-336924f8621f",
            "expirationPolicy":"indicatorType",
            "expirationInterval":10080
         },
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-19T17:45:07.468974+02:00",
         "lastReputationRun":"0001-01-01T00:00:00Z",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-19T17:45:06+02:00"
      },
      {
         "id":"9890",
         "version":1,
         "modified":"2020-02-19T17:45:07.468949+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"6c032ab1-09fa-474e-8879-50d8eb953bdc",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-19T17:45:07.4384+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"AWS Feed.AWS Feed_instance_1",
               "entryId":"",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-19T17:45:07.468948+02:00",
         "indicator_type":"CIDR",
         "value":"52.94.216.0/21",
         "sourceInstances":[
            "AWS Feed_instance_1"
         ],
         "sourceBrands":[
            "AWS Feed"
         ],
         "investigationIDs":[

         ],
         "lastSeen":"0001-01-01T00:00:00Z",
         "firstSeen":"0001-01-01T00:00:00Z",
         "lastSeenEntryID":"API",
         "firstSeenEntryID":"API",
         "score":1,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "moduleToFeedMap":{
            "5a39582b-cf1c-4abc-8cb6-336924f8621f":{
               "reliability":"A - Completely reliable",
               "fetchTime":"2020-02-19T17:45:06+02:00",
               "sourceBrand":"AWS Feed",
               "sourceInstance":"AWS Feed_instance_1",
               "moduleId":"5a39582b-cf1c-4abc-8cb6-336924f8621f",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":1,
               "classifierVersion":1,
               "feedConfig":{
                  "feed":true,
                  "feedBypassExclusionList":null,
                  "feedExpirationInterval":null,
                  "feedExpirationPolicy":"indicatorType",
                  "feedFetchInterval":"240",
                  "feedReliability":"A - Completely reliable",
                  "feedReputation":"Good",
                  "insecure":true,
                  "proxy":false,
                  "regions":null,
                  "sub_feeds":[
                     "AMAZON"
                  ]
               },
               "type":"CIDR",
               "value":"52.94.216.0/21",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"2020-02-19T17:45:06+02:00",
               "ExpirationSource":{
                  "setTime":"2020-02-19T17:45:07.425709+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"AWS Feed",
                  "instance":"AWS Feed_instance_1",
                  "moduleId":"5a39582b-cf1c-4abc-8cb6-336924f8621f",
                  "expirationPolicy":"indicatorType",
                  "expirationInterval":10080
               },
               "rawJSON":null,
               "isEnrichment":false
            }
         },
         "isShared":false,
         "expiration":"2020-02-26T17:45:08.373351+02:00",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"active",
         "expirationSource":{
            "setTime":"2020-02-19T17:45:07.425709+02:00",
            "source":"indicatorType",
            "user":"",
            "brand":"AWS Feed",
            "instance":"AWS Feed_instance_1",
            "moduleId":"5a39582b-cf1c-4abc-8cb6-336924f8621f",
            "expirationPolicy":"indicatorType",
            "expirationInterval":10080
         },
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-19T17:45:07.468948+02:00",
         "lastReputationRun":"0001-01-01T00:00:00Z",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-19T17:45:06+02:00"
      }
   ],
   "total":2
}
'''


EMAIL_INDICATORS = '''
{
   "iocs":[
      {
         "id":"7764",
         "version":2,
         "modified":"2020-02-12T17:43:42.045543+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"65230a6f-7dec-45cc-8f92-e4caeac27c3a",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-12T17:40:09.777799+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@947",
               "entryId":"2@947",
               "category":"Sighting"
            },
            {
               "id":"b37352a3-aa2d-46a6-8610-c2097a227d62",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:40:24.227588+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@951",
               "entryId":"2@951",
               "category":"Sighting"
            },
            {
               "id":"dc0ef1df-9e38-4f76-850e-935b0d787e12",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:40:41.053436+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@953",
               "entryId":"2@953",
               "category":"Sighting"
            },
            {
               "id":"1806b936-347b-4297-8f4c-efa9260417ea",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:40:55.797155+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@955",
               "entryId":"2@955",
               "category":"Sighting"
            },
            {
               "id":"7e0a6102-7e9d-4fb1-8a20-fb75b2e8a12c",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:43:07.379107+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@974",
               "entryId":"2@974",
               "category":"Sighting"
            },
            {
               "id":"87af294f-7dc4-4b3f-8812-60ead453be94",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:43:10.612282+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@978",
               "entryId":"2@978",
               "category":"Sighting"
            },
            {
               "id":"1ee77c0b-4d5e-4e2b-8482-3aaf4caa81a4",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:43:12.32195+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@980",
               "entryId":"2@980",
               "category":"Sighting"
            },
            {
               "id":"5da6e357-971d-40ca-8004-f3df04a93b2a",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:43:13.995733+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@982",
               "entryId":"2@982",
               "category":"Sighting"
            },
            {
               "id":"4e66240f-ca40-40b8-81e8-f3e504682364",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:43:33.723306+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@998",
               "entryId":"2@998",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-12T17:42:11.48852+02:00",
         "indicator_type":"Email",
         "value":"ubuntu-appindicators@ubuntu.com",
         "source":"DBot",
         "investigationIDs":[
            "947",
            "951",
            "953",
            "955",
            "974",
            "978",
            "980",
            "982",
            "998"
         ],
         "lastSeen":"2020-02-12T17:43:42.044887+02:00",
         "firstSeen":"2020-02-12T17:42:11.248928+02:00",
         "lastSeenEntryID":"3@998",
         "firstSeenEntryID":"2@947",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"",
         "expirationSource":null,
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-12T17:43:42.044887+02:00",
         "lastReputationRun":"2020-02-12T17:40:01.09759+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"0001-01-01T00:00:00Z"
      },
      {
         "id":"7763",
         "version":1,
         "modified":"2020-02-12T17:42:11.488503+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"fdff9821-7cfd-44d0-8ace-d3603f510dc9",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-12T17:39:44.81983+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@943",
               "entryId":"2@943",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-12T17:42:11.488501+02:00",
         "indicator_type":"Email",
         "value":"ubuntu-dock@ubuntu.com",
         "source":"DBot",
         "investigationIDs":[
            "943"
         ],
         "lastSeen":"2020-02-12T17:42:11.248927+02:00",
         "firstSeen":"2020-02-12T17:42:11.248927+02:00",
         "lastSeenEntryID":"3@943",
         "firstSeenEntryID":"2@943",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"",
         "expirationSource":null,
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-12T17:42:11.248927+02:00",
         "lastReputationRun":"2020-02-12T17:39:08.969055+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"0001-01-01T00:00:00Z"
      }
   ],
   "total":2
}
'''

URL_INDICATORS = '''
{
   "iocs":[
      {
         "id":"7760",
         "version":3,
         "modified":"2020-02-13T10:38:58.302248+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"7bab5aed-1c8b-4b12-8664-a7c4efa35b45",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-12T17:34:31.186684+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@938",
               "entryId":"2@938",
               "category":"Sighting"
            },
            {
               "id":"b2204eac-c633-4d93-85fa-e6906ff56aff",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-13T10:38:42.229545+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@1102",
               "entryId":"2@1102",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-12T17:34:37.288857+02:00",
         "indicator_type":"URL",
         "value":"http://www.rsyslog.com/e/2359",
         "sourceInstances":[
            "Recorded Future",
            "CrowdStrike"
         ],
         "sourceBrands":[
            "Recorded Future",
            "CrowdStrike"
         ],
         "investigationIDs":[
            "938",
            "1102"
         ],
         "lastSeen":"2020-02-13T10:38:58.301185+02:00",
         "firstSeen":"2020-02-12T17:34:37.186588+02:00",
         "lastSeenEntryID":"3@1102",
         "firstSeenEntryID":"2@938",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":{
            "id":"http://www.rsyslog.com/e/2359",
            "version":11,
            "modified":"2020-02-13T10:37:39.596172+02:00",
            "sortValues":null,
            "scores":{
               "CrowdStrike":{
                  "score":0,
                  "content":"## Falcon Intel URL reputation for: http://www.rsyslog.com/e/2359No result found",
                  "contentFormat":"markdown",
                  "timestamp":"2020-02-13T10:37:39.59616+02:00",
                  "scoreChangeTimestamp":"2020-02-12T17:34:13.584595+02:00",
                  "isTypedIndicator":false,
                  "type":"url",
                  "context":{
                     "DBotScore":{
                        "Indicator":"http://www.rsyslog.com/e/2359",
                        "Score":0,
                        "Type":"url",
                        "Vendor":"CrowdStrike"
                     }
                  }
               },
               "Recorded Future":{
                  "score":0,
                  "content":"No records found",
                  "contentFormat":"markdown",
                  "timestamp":"2020-02-13T10:37:39.59616+02:00",
                  "scoreChangeTimestamp":"2020-02-12T17:34:13.336656+02:00",
                  "isTypedIndicator":false,
                  "type":"url",
                  "context":{
                     "DBotScore":{
                        "Indicator":"http://www.rsyslog.com/e/2359",
                        "Score":0,
                        "Type":"url",
                        "Vendor":"Recorded Future"
                     }
                  }
               }
            }
         },
         "moduleToFeedMap":{
            "CrowdStrike":{
               "reliability":"A+ - 3rd party enrichment",
               "fetchTime":"2020-02-13T10:36:25.393603+02:00",
               "sourceBrand":"CrowdStrike",
               "sourceInstance":"CrowdStrike",
               "moduleId":"CrowdStrike",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":0,
               "classifierVersion":0,
               "feedConfig":null,
               "type":"url",
               "value":"http://www.rsyslog.com/e/2359",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"0001-01-01T00:00:00Z",
               "ExpirationSource":{
                  "setTime":"2020-02-13T10:38:46.18103+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"CrowdStrike",
                  "instance":"CrowdStrike",
                  "moduleId":"CrowdStrike",
                  "expirationPolicy":"never",
                  "expirationInterval":0
               },
               "rawJSON":null,
               "isEnrichment":true
            },
            "Recorded Future":{
               "reliability":"A+ - 3rd party enrichment",
               "fetchTime":"2020-02-12T17:34:38.954801+02:00",
               "sourceBrand":"Recorded Future",
               "sourceInstance":"Recorded Future",
               "moduleId":"Recorded Future",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":0,
               "classifierVersion":0,
               "feedConfig":null,
               "type":"url",
               "value":"http://www.rsyslog.com/e/2359",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"0001-01-01T00:00:00Z",
               "ExpirationSource":{
                  "setTime":"2020-02-13T10:38:46.181056+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"Recorded Future",
                  "instance":"Recorded Future",
                  "moduleId":"Recorded Future",
                  "expirationPolicy":"never",
                  "expirationInterval":0
               },
               "rawJSON":null,
               "isEnrichment":true
            }
         },
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"active",
         "expirationSource":{
            "setTime":"2020-02-13T10:38:46.18103+02:00",
            "source":"indicatorType",
            "user":"",
            "brand":"CrowdStrike",
            "instance":"CrowdStrike",
            "moduleId":"CrowdStrike",
            "expirationPolicy":"never",
            "expirationInterval":0
         },
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-13T10:38:58.301185+02:00",
         "lastReputationRun":"2020-02-13T10:36:25.421552+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-13T10:36:25.393603+02:00"
      }
   ],
   "total":1
}
'''

IP_INDICATORS = '''
{
   "iocs":[
      {
         "id":"7848",
         "version":1,
         "modified":"2020-02-13T18:45:38.997926+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"ed7e9c36-f48f-4f65-8955-ec5319008fa7",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-13T18:45:38.959505+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"Bambenek Consulting Feed.Bambenek Consulting Feed_instance_1",
               "entryId":"",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-13T18:45:38.997925+02:00",
         "indicator_type":"IP",
         "value":"52.218.100.20",
         "sourceInstances":[
            "Bambenek Consulting Feed_instance_1"
         ],
         "sourceBrands":[
            "Bambenek Consulting Feed"
         ],
         "investigationIDs":[

         ],
         "lastSeen":"0001-01-01T00:00:00Z",
         "firstSeen":"0001-01-01T00:00:00Z",
         "lastSeenEntryID":"API",
         "firstSeenEntryID":"API",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "moduleToFeedMap":{
            "6ef54f17-c26a-4571-8b8d-14923772fcca":{
               "reliability":"F - Reliability cannot be judged",
               "fetchTime":"2020-02-13T18:45:35+02:00",
               "sourceBrand":"Bambenek Consulting Feed",
               "sourceInstance":"Bambenek Consulting Feed_instance_1",
               "moduleId":"6ef54f17-c26a-4571-8b8d-14923772fcca",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":0,
               "classifierVersion":0,
               "feedConfig":null,
               "type":"IP",
               "value":"52.218.100.20",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"2020-02-13T18:45:35+02:00",
               "ExpirationSource":{
                  "setTime":"2020-02-13T18:45:38.946695+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"Bambenek Consulting Feed",
                  "instance":"Bambenek Consulting Feed_instance_1",
                  "moduleId":"6ef54f17-c26a-4571-8b8d-14923772fcca",
                  "expirationPolicy":"never",
                  "expirationInterval":0
               },
               "rawJSON":null,
               "isEnrichment":false
            }
         },
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"active",
         "expirationSource":{
            "setTime":"2020-02-13T18:45:38.946695+02:00",
            "source":"indicatorType",
            "user":"",
            "brand":"Bambenek Consulting Feed",
            "instance":"Bambenek Consulting Feed_instance_1",
            "moduleId":"6ef54f17-c26a-4571-8b8d-14923772fcca",
            "expirationPolicy":"never",
            "expirationInterval":0
         },
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-13T18:45:38.997925+02:00",
         "lastReputationRun":"0001-01-01T00:00:00Z",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-13T18:45:35+02:00"
      },
      {
         "id":"7847",
         "version":1,
         "modified":"2020-02-13T18:45:38.997907+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"0546083d-1292-4772-843c-59848cf6b219",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-13T18:45:38.959472+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"Bambenek Consulting Feed.Bambenek Consulting Feed_instance_1",
               "entryId":"",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-13T18:45:38.997905+02:00",
         "indicator_type":"IP",
         "value":"52.218.101.252",
         "sourceInstances":[
            "Bambenek Consulting Feed_instance_1"
         ],
         "sourceBrands":[
            "Bambenek Consulting Feed"
         ],
         "investigationIDs":[

         ],
         "lastSeen":"0001-01-01T00:00:00Z",
         "firstSeen":"0001-01-01T00:00:00Z",
         "lastSeenEntryID":"API",
         "firstSeenEntryID":"API",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":null,
         "moduleToFeedMap":{
            "6ef54f17-c26a-4571-8b8d-14923772fcca":{
               "reliability":"F - Reliability cannot be judged",
               "fetchTime":"2020-02-13T18:45:35+02:00",
               "sourceBrand":"Bambenek Consulting Feed",
               "sourceInstance":"Bambenek Consulting Feed_instance_1",
               "moduleId":"6ef54f17-c26a-4571-8b8d-14923772fcca",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":0,
               "classifierVersion":0,
               "feedConfig":null,
               "type":"IP",
               "value":"52.218.101.252",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"2020-02-13T18:45:35+02:00",
               "ExpirationSource":{
                  "setTime":"2020-02-13T18:45:38.946689+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"Bambenek Consulting Feed",
                  "instance":"Bambenek Consulting Feed_instance_1",
                  "moduleId":"6ef54f17-c26a-4571-8b8d-14923772fcca",
                  "expirationPolicy":"never",
                  "expirationInterval":0
               },
               "rawJSON":null,
               "isEnrichment":false
            }
         },
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"active",
         "expirationSource":{
            "setTime":"2020-02-13T18:45:38.946689+02:00",
            "source":"indicatorType",
            "user":"",
            "brand":"Bambenek Consulting Feed",
            "instance":"Bambenek Consulting Feed_instance_1",
            "moduleId":"6ef54f17-c26a-4571-8b8d-14923772fcca",
            "expirationPolicy":"never",
            "expirationInterval":0
         },
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-13T18:45:38.997905+02:00",
         "lastReputationRun":"0001-01-01T00:00:00Z",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-13T18:45:35+02:00"
      }],
   "total":2
}
'''

DOMAIN_INDICATORS = '''
{
   "iocs":[
      {
         "id":"7757",
         "version":6,
         "modified":"2020-02-13T10:38:58.301271+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"9b7908ac-b962-489a-8987-38d736d7b168",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-12T17:31:38.59569+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@919",
               "entryId":"2@919",
               "category":"Sighting"
            },
            {
               "id":"20753f82-b0a2-4ad7-8f68-65ac29d01386",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:31:41.381995+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@926",
               "entryId":"2@926",
               "category":"Sighting"
            },
            {
               "id":"d4a6e3cf-2101-4981-8d5d-32d3484ca459",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:31:44.376091+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@918",
               "entryId":"2@918",
               "category":"Sighting"
            },
            {
               "id":"a1c589c6-19ce-4a4f-8056-41579c1cf676",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:34:28.054123+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@937",
               "entryId":"2@937",
               "category":"Sighting"
            },
            {
               "id":"859ae56d-90ef-4941-8c3c-ae55066c23b5",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:34:31.186347+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@938",
               "entryId":"2@938",
               "category":"Sighting"
            },
            {
               "id":"c6fb60fc-a536-4646-8e36-64731411c2bb",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-12T17:34:33.934353+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@936",
               "entryId":"2@936",
               "category":"Sighting"
            },
            {
               "id":"baf9253d-563e-49f2-8303-0664bb0b950a",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-13T10:38:31.958697+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@1090",
               "entryId":"2@1090",
               "category":"Sighting"
            },
            {
               "id":"c33c0bd3-b3d1-4a00-82e1-32f4af387260",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-13T10:38:34.473717+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@1089",
               "entryId":"2@1089",
               "category":"Sighting"
            },
            {
               "id":"a8da2b08-d82c-42f2-869e-95c0dd08f637",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Sighted",
               "user":"@DBot",
               "created":"2020-02-13T10:38:42.229181+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"2@1102",
               "entryId":"2@1102",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-12T17:31:51.156216+02:00",
         "indicator_type":"Domain",
         "value":"www.rsyslog.com",
         "sourceInstances":[
            "CrowdStrike",
            "Recorded Future",
            "VirusTotal"
         ],
         "sourceBrands":[
            "CrowdStrike",
            "Recorded Future",
            "VirusTotal"
         ],
         "investigationIDs":[
            "919",
            "926",
            "918",
            "937",
            "938",
            "936",
            "1090",
            "1089",
            "1102"
         ],
         "lastSeen":"2020-02-13T10:38:58.301185+02:00",
         "firstSeen":"2020-02-12T17:31:51.050588+02:00",
         "lastSeenEntryID":"3@1102",
         "firstSeenEntryID":"2@919",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":{
            "id":"www.rsyslog.com",
            "version":51,
            "modified":"2020-02-13T10:37:36.860596+02:00",
            "sortValues":null,
            "scores":{
               "CrowdStrike":{
                  "score":0,
                  "content":"## Falcon Intel domain reputation for: www.rsyslog.comNo result found",
                  "contentFormat":"markdown",
                  "timestamp":"2020-02-13T10:37:36.860462+02:00",
                  "scoreChangeTimestamp":"2020-02-12T17:31:16.235822+02:00",
                  "isTypedIndicator":false,
                  "type":"domain",
                  "context":{
                     "DBotScore":{
                        "Indicator":"www.rsyslog.com",
                        "Score":0,
                        "Type":"domain",
                        "Vendor":"CrowdStrike"
                     }
                  }
               },
               "VirusTotal":{
                  "score":1,
                  "content":"## VirusTotal Domain Reputation for: www.rsyslog.com#### Domain categories:"
                  "contentFormat":"markdown",
                  "timestamp":"2020-02-13T10:37:27.561946+02:00",
                  "scoreChangeTimestamp":"2020-02-12T17:34:08.122567+02:00",
                  "isTypedIndicator":false,
                  "type":"domain",
                  "context":{
                     "DBotScore":{
                        "Indicator":"www.rsyslog.com",
                        "Score":1,
                        "Type":"domain",
                        "Vendor":"VirusTotal"
                     },
                     "Domain(val.Name && val.Name === obj.Name)":{
                        "Name":"www.rsyslog.com",
                        "VirusTotal":{
                           "CommunicatingHashes":[

                           ],
                           "DetectedURLs":[

                           ],
                           "DownloadedHashes":[

                           ],
                           "ReferrerHashes":[
                              {
                                 "date":"2019-08-06 00:59:47",
                                 "positives":2,
                                 "sha256":"0fa5c3a084fc10e62e09dff22950a7c62e6e76a686721f626a6d8fd52bc0bfc6",
                                 "total":72
                              }
                           ],
                           "Resolutions":[
                              {
                                 "ip_address":"138.201.116.127",
                                 "last_resolved":"2019-02-06 12:33:31"
                              },
                              {
                                 "ip_address":"159.69.223.59",
                                 "last_resolved":"2019-12-07 01:47:11"
                              },
                              {
                                 "ip_address":"176.9.39.152",
                                 "last_resolved":"2013-10-16 00:00:00"
                              }
                           ],
                           "Subdomains":[
                              "download.rsyslog.com",
                              "wiki.rsyslog.com",
                              "build.rsyslog.com",
                              "docker.rsyslog.com",
                              "debian.rsyslog.com",
                              "cookbook.rsyslog.com"
                           ],
                           "UnAVDetectedCommunicatingHashes":[

                           ],
                           "UnAVDetectedDownloadedHashes":[
                              {
                                 "date":"2019-11-12 17:59:29",
                                 "positives":0,
                                 "sha256":"e1f4776b1c62ad7220f4d624a89a96b0c3d4738006899356eaaef0f1f91ee104",
                                 "total":72
                              }
                           ],
                           "Whois":"Admin City: REDACTED FOR PRIVACYAdmin Country: REDACTED FOR PRIVACYAdmin"
                        }
                     }
                  }
               }
            }
         },
         "moduleToFeedMap":{
            "CrowdStrike":{
               "reliability":"A+ - 3rd party enrichment",
               "fetchTime":"2020-02-13T10:36:23.258397+02:00",
               "sourceBrand":"CrowdStrike",
               "sourceInstance":"CrowdStrike",
               "moduleId":"CrowdStrike",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":0,
               "classifierVersion":0,
               "feedConfig":null,
               "type":"domain",
               "value":"www.rsyslog.com",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"0001-01-01T00:00:00Z",
               "ExpirationSource":{
                  "setTime":"2020-02-13T10:38:46.180821+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"CrowdStrike",
                  "instance":"CrowdStrike",
                  "moduleId":"CrowdStrike",
                  "expirationPolicy":"never",
                  "expirationInterval":0
               },
               "rawJSON":null,
               "isEnrichment":true
            },
            "Recorded Future":{
               "reliability":"A+ - 3rd party enrichment",
               "fetchTime":"2020-02-12T17:34:45.710333+02:00",
               "sourceBrand":"Recorded Future",
               "sourceInstance":"Recorded Future",
               "moduleId":"Recorded Future",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":0,
               "classifierVersion":0,
               "feedConfig":null,
               "type":"domain",
               "value":"www.rsyslog.com",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"0001-01-01T00:00:00Z",
               "ExpirationSource":{
                  "setTime":"2020-02-13T10:38:46.180795+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"Recorded Future",
                  "instance":"Recorded Future",
                  "moduleId":"Recorded Future",
                  "expirationPolicy":"never",
                  "expirationInterval":0
               },
               "rawJSON":null,
               "isEnrichment":true
            },
            "VirusTotal":{
               "reliability":"A+ - 3rd party enrichment",
               "fetchTime":"2020-02-12T17:34:08.689561+02:00",
               "sourceBrand":"VirusTotal",
               "sourceInstance":"VirusTotal",
               "moduleId":"VirusTotal",
               "expirationPolicy":"indicatorType",
               "expirationInterval":0,
               "bypassExclusionList":false,
               "score":1,
               "classifierVersion":0,
               "feedConfig":null,
               "type":"domain",
               "value":"www.rsyslog.com",
               "timestamp":"0001-01-01T00:00:00Z",
               "fields":null,
               "modifiedTime":"0001-01-01T00:00:00Z",
               "ExpirationSource":{
                  "setTime":"2020-02-13T10:38:46.180766+02:00",
                  "source":"indicatorType",
                  "user":"",
                  "brand":"VirusTotal",
                  "instance":"VirusTotal",
                  "moduleId":"VirusTotal",
                  "expirationPolicy":"never",
                  "expirationInterval":0
               },
               "rawJSON":null,
               "isEnrichment":true
            }
         },
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"active",
         "expirationSource":{
            "setTime":"2020-02-13T10:38:46.180821+02:00",
            "source":"indicatorType",
            "user":"",
            "brand":"CrowdStrike",
            "instance":"CrowdStrike",
            "moduleId":"CrowdStrike",
            "expirationPolicy":"never",
            "expirationInterval":0
         },
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-13T10:38:58.301185+02:00",
         "lastReputationRun":"2020-02-13T10:36:23.278024+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"2020-02-13T10:36:23.258397+02:00"
      }
   ],
   "total":2
}
'''

FILE_INDICATORS = '''
{
   "iocs":[
      {
         "id":"9892",
         "version":1,
         "modified":"2020-02-19T21:06:50.554056+02:00",
         "sortValues":null,
         "comments":[
            {
               "id":"78ebd257-e159-4cd3-8bb5-390afebcc1c6",
               "version":0,
               "modified":"0001-01-01T00:00:00Z",
               "sortValues":null,
               "content":"Created",
               "user":"@DBot",
               "created":"2020-02-19T21:06:50.535091+02:00",
               "type":"IndicatorCommentTimeLine",
               "source":"560@909",
               "entryId":"560@909",
               "category":"Sighting"
            }
         ],
         "account":"",
         "timestamp":"2020-02-19T21:06:50.554042+02:00",
         "indicator_type":"File MD5",
         "value":"86d96212bfe35ed590aa4f7ace76bb51",
         "source":"DBot",
         "investigationIDs":[
            "909"
         ],
         "lastSeen":"2020-02-19T21:06:50.552883+02:00",
         "firstSeen":"2020-02-19T21:06:50.552884+02:00",
         "lastSeenEntryID":"560@909",
         "firstSeenEntryID":"560@909",
         "score":0,
         "manualScore":false,
         "manualSetTime":"0001-01-01T00:00:00Z",
         "insightCache":{
            "id":"86d96212bfe35ed590aa4f7ace76bb51",
            "version":1,
            "modified":"2020-02-19T21:06:48.209783+02:00",
            "sortValues":null,
            "scores":{
               "CrowdStrike":{
                  "score":0,
                  "content":"## Falcon Intel file reputation for: 86d96212bfe35ed590aa4f7ace76bb51No result found",
                  "contentFormat":"markdown",
                  "timestamp":"2020-02-19T21:06:48.209763+02:00",
                  "scoreChangeTimestamp":"2020-02-19T21:06:48.209763+02:00",
                  "isTypedIndicator":false,
                  "type":"hash",
                  "context":{
                     "DBotScore":{
                        "Indicator":"86d96212bfe35ed590aa4f7ace76bb51",
                        "Score":0,
                        "Type":"hash",
                        "Vendor":"CrowdStrike"
                     }
                  }
               }
            }
         },
         "isShared":false,
         "expiration":"0001-01-01T00:00:00Z",
         "manualExpirationTime":"0001-01-01T00:00:00Z",
         "expirationStatus":"",
         "expirationSource":null,
         "deletedFeedFetchTime":"0001-01-01T00:00:00Z",
         "calculatedTime":"2020-02-19T21:06:50.552883+02:00",
         "lastReputationRun":"2020-02-19T21:06:48.225845+02:00",
         "comment":"",
         "manuallyEditedFields":null,
         "modifiedTime":"0001-01-01T00:00:00Z"
      }
   ],
   "total":1
}
'''

INDICATOR_QUERY = 'type:IP and sourceBrands:"Bambenek Consulting Feed" and createdTime:>"2020-02-10T11:32:32 +0000" and' \
                  ' createdTime:<="2020-02-20T11:32:32 +0000"'


def test_find_indicators_by_time_frame(mocker):
    import datetime
    import pytz
    from TAXIIServer import find_indicators_by_time_frame

    def find_indicators(indicator_query):
        if indicator_query == INDICATOR_QUERY:
            return 'yep'
        return 'nope'

    # Set
    mocker.patch('TAXIIServer.find_indicators_loop', side_effect=find_indicators)
    mocker.patch.object(demisto, 'info')

    begin_date = datetime.datetime(2020, 2, 10, 11, 32, 32, 644224, tzinfo=pytz.utc)
    end_date = datetime.datetime(2020, 2, 20, 11, 32, 32, 644224, tzinfo=pytz.utc)

    # Arrange
    result = find_indicators_by_time_frame('type:IP and sourceBrands:"Bambenek Consulting Feed"', begin_date, end_date)

    # Assert
    assert result == 'yep'


def test_find_indicators_loop(mocker):
    from TAXIIServer import find_indicators_loop

    # Set
    mocker.patch.object(demisto, 'searchIndicators', return_value=json.loads(IP_INDICATORS))

    # Arrange
    indicators = find_indicators_loop('q')

    # Assert
    assert len(indicators) == 2
    assert indicators[0]['value'] == '52.218.100.20'
    assert indicators[1]['value'] == '52.218.101.252'


@pytest.mark.parametrize('indicator',
                         [json.loads(IP_INDICATORS)['iocs'][0], json.loads(URL_INDICATORS)['iocs'][0],
                          json.loads(EMAIL_INDICATORS)['iocs'][0], json.loads(CIDR_INDICATORS)['iocs'][0],
                          json.loads(DOMAIN_INDICATORS)['iocs'][0],
                          json.loads(FILE_INDICATORS)['iocs'][0]])
def test_validate_indicators(indicator):
    from TAXIIServer import get_stix_indicator, NAMESPACE_URI, NAMESPACE

    # Arrange
    stix_indicator = get_stix_indicator(indicator)
    stix_xml = stix_indicator.to_xml(ns_dict={NAMESPACE_URI: NAMESPACE})
    xml_file = lxml.etree.fromstring(stix_xml)
    tree = lxml.etree.ElementTree(xml_file)

    # Assert
    assert sdv.validate_xml(tree)
