Gathers PerimeterX related data
This integration was integrated and tested with version xx of BotDefender
## Configure BotDefender on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BotDefender.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| apikey | API Key | True |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Gets the PerimeterX DBotScore decision for a particular IP


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The custom parameter value or IP address for which the report is requested | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | Bad IP address | 
| IP.Malicious.Vendor | String | For malicious IPs, the vendor that made the decision | 
| IP.Malicious.Description | String | For malicious IPs, the reason that the vendor made the decision | 
| DBotScore.Indicator | String | The indicator that was tested | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


#### Command Example
```!ip ip="5.79.76.181"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "5.79.76.181",
        "Score": 3,
        "Type": "ip",
        "Vendor": "PerimeterX"
    },
    "IP": {
        "Address": "5.79.76.181",
        "Malicious": {
            "Description": "Something random from PerimeterX for now enjoy!",
            "Vendor": "PerimeterX"
        }
    },
    "PerimeterX": {
        "catpchaSolves": 200,
        "ipClassifications": [
            {
                "class": "Bad Reputation",
                "name": "Bad Reputation"
            },
            {
                "class": "SharedIPs",
                "name": "Shared IPs"
            },
            {
                "class": "DataCenter",
                "name": "TAG DCIP"
            }
        ],
        "maxRiskScore": 100,
        "pageTypeDistributions": [
            {
                "count": 1228,
                "pageType": "Login"
            },
            {
                "count": 739,
                "pageType": "Scraping"
            },
            {
                "count": 139,
                "pageType": "Checkout"
            }
        ],
        "topBlockedURLPaths": [
            {
                "blockedURLPath": "/",
                "count": 1404
            },
            {
                "blockedURLPath": "/cgi-bin/way-board.cgi",
                "count": 702
            },
            {
                "blockedURLPath": "/loginok/light.cgi",
                "count": 702
            }
        ],
        "topIncidentTypes": [
            {
                "count": 2106,
                "incidentType": "Spoof"
            },
            {
                "count": 702,
                "incidentType": "Bot Behavior"
            }
        ],
        "topURLPaths": [
            {
                "count": 3315,
                "urlPath": "/favicon.ico"
            },
            {
                "count": 3253,
                "urlPath": "/favicon.png"
            },
            {
                "count": 3212,
                "urlPath": "/"
            },
            {
                "count": 1228,
                "urlPath": "/loginok/light.cgi"
            },
            {
                "count": 1222,
                "urlPath": "/cgi-bin/way-board.cgi"
            },
            {
                "count": 205,
                "urlPath": "/phpmyadmin/"
            },
            {
                "count": 139,
                "urlPath": "-"
            },
            {
                "count": 82,
                "urlPath": "/images/icons/favicon.ico"
            },
            {
                "count": 48,
                "urlPath": "/test.php"
            }
        ],
        "topUserAgents": [
            {
                "count": 84,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36"
            },
            {
                "count": 80,
                "userAgentName": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
            },
            {
                "count": 78,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36 OPR/53.0.2907.99"
            },
            {
                "count": 76,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36 OPR/54.0.2952.64 (Edition Yx)"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36 OPR/54.0.2952.51"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36"
            }
        ],
        "trafficOverTime": []
    }
}
```

#### Human Readable Output

>[<IP object at 0x7f31335e0e80>]

### perimeterx-get-investigate-details
***
Gets the PerimeterX related details for a particular IP


#### Base Command

`perimeterx-get-investigate-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | The custom parameter value or IP address for which the report is requested | Optional | 
| search_type | The field to search against for the query (socket_ip, true_ip, name) | Optional | 
| report_type | Determines the particular report to query for (investigate) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PerimeterX.topUserAgents.userAgentName | String | The user agent string | 
| PerimeterX.topUserAgents.count | Number | The number of requests seen using this user agent string | 
| PerimeterX.topURLPaths.urlPath | String | Path portion of the full URL | 
| PerimeterX.topURLPaths.count | Number | The number of requests made to this path | 
| PerimeterX.topBlockedURLPaths.blockedURLPath | String | Path portion of the full blocked URL | 
| PerimeterX.topBlockedURLPaths.count | Number | The number of requests blocked on this path | 
| PerimeterX.topIncidentTypes.incidentType | String | Incident type for queried item | 
| PerimeterX.topIncidentTypes.count | Number | The number of requests categorized for the incident type | 
| PerimeterX.catpchaSolves | Number | Total number of captchas solved by queried item | 
| PerimeterX.pageTypeDistributions.pageType | String | Page type name | 
| PerimeterX.pageTypeDistributions.count | Number | Count of requests classified under the page type | 
| PerimeterX.maxRiskScore | Number | Maximum risk score observed by PerimeterX | 
| PerimeterX.ipClassifications.class | String | Class associated with the IP classification type | 
| PerimeterX.ipClassifications.name | String | Name associated with the IP classification | 
| IP.Address | String | Bad IP address | 
| IP.Malicious.Vendor | String | For malicious IPs, the vendor that made the decision | 
| IP.Malicious.Description | String | For malicious IPs, the reason that the vendor made the decision | 
| DBotScore.Indicator | String | The indicator that was tested | 
| DBotScore.Type | String | The indicator type | 
| DBotScore.Vendor | String | The vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


#### Command Example
```!perimeterx-get-investigate-details search_type="true_ip" search_term="5.79.76.181"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "5.79.76.181",
        "Score": 3,
        "Type": "ip",
        "Vendor": "PerimeterX"
    },
    "IP": {
        "Address": "5.79.76.181",
        "Malicious": {
            "Description": "Something random from PerimeterX for now enjoy!",
            "Vendor": "PerimeterX"
        }
    },
    "PerimeterX": {
        "catpchaSolves": 200,
        "ipClassifications": [
            {
                "class": "Bad Reputation",
                "name": "Bad Reputation"
            },
            {
                "class": "SharedIPs",
                "name": "Shared IPs"
            },
            {
                "class": "DataCenter",
                "name": "TAG DCIP"
            }
        ],
        "maxRiskScore": 100,
        "pageTypeDistributions": [
            {
                "count": 1228,
                "pageType": "Login"
            },
            {
                "count": 739,
                "pageType": "Scraping"
            },
            {
                "count": 139,
                "pageType": "Checkout"
            }
        ],
        "topBlockedURLPaths": [
            {
                "blockedURLPath": "/",
                "count": 1404
            },
            {
                "blockedURLPath": "/cgi-bin/way-board.cgi",
                "count": 702
            },
            {
                "blockedURLPath": "/loginok/light.cgi",
                "count": 702
            }
        ],
        "topIncidentTypes": [
            {
                "count": 2106,
                "incidentType": "Spoof"
            },
            {
                "count": 702,
                "incidentType": "Bot Behavior"
            }
        ],
        "topURLPaths": [
            {
                "count": 3315,
                "urlPath": "/favicon.ico"
            },
            {
                "count": 3253,
                "urlPath": "/favicon.png"
            },
            {
                "count": 3212,
                "urlPath": "/"
            },
            {
                "count": 1228,
                "urlPath": "/loginok/light.cgi"
            },
            {
                "count": 1222,
                "urlPath": "/cgi-bin/way-board.cgi"
            },
            {
                "count": 205,
                "urlPath": "/phpmyadmin/"
            },
            {
                "count": 139,
                "urlPath": "-"
            },
            {
                "count": 82,
                "urlPath": "/images/icons/favicon.ico"
            },
            {
                "count": 48,
                "urlPath": "/test.php"
            }
        ],
        "topUserAgents": [
            {
                "count": 84,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36"
            },
            {
                "count": 80,
                "userAgentName": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
            },
            {
                "count": 78,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36 OPR/53.0.2907.99"
            },
            {
                "count": 76,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36 OPR/54.0.2952.64 (Edition Yx)"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36 OPR/54.0.2952.51"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2"
            },
            {
                "count": 72,
                "userAgentName": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36"
            }
        ],
        "trafficOverTime": []
    }
}
```

#### Human Readable Output

>{'topUserAgents': [{'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 84}, {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36', 'count': 80}, {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36 OPR/53.0.2907.99', 'count': 78}, {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36 OPR/54.0.2952.64 (Edition Yx)', 'count': 76}, {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36 OPR/54.0.2952.51', 'count': 72}, {'userAgentName': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36', 'count': 72}, {'userAgentName': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'count': 72}, {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36', 'count': 72}, {'userAgentName': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36 Kinza/4.7.2', 'count': 72}, {'userAgentName': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36', 'count': 72}], 'topURLPaths': [{'urlPath': '/favicon.ico', 'count': 3315}, {'urlPath': '/favicon.png', 'count': 3253}, {'urlPath': '/', 'count': 3212}, {'urlPath': '/loginok/light.cgi', 'count': 1228}, {'urlPath': '/cgi-bin/way-board.cgi', 'count': 1222}, {'urlPath': '/phpmyadmin/', 'count': 205}, {'urlPath': '-', 'count': 139}, {'urlPath': '/images/icons/favicon.ico', 'count': 82}, {'urlPath': '/test.php', 'count': 48}], 'topBlockedURLPaths': [{'blockedURLPath': '/', 'count': 1404}, {'blockedURLPath': '/cgi-bin/way-board.cgi', 'count': 702}, {'blockedURLPath': '/loginok/light.cgi', 'count': 702}], 'topIncidentTypes': [{'incidentType': 'Spoof', 'count': 2106}, {'incidentType': 'Bot Behavior', 'count': 702}], 'catpchaSolves': 200, 'trafficOverTime': [], 'pageTypeDistributions': [{'pageType': 'Login', 'count': 1228}, {'pageType': 'Scraping', 'count': 739}, {'pageType': 'Checkout', 'count': 139}], 'maxRiskScore': 100, 'ipClassifications': [{'class': 'Bad Reputation', 'name': 'Bad Reputation'}, {'class': 'SharedIPs', 'name': 'Shared IPs'}, {'class': 'DataCenter', 'name': 'TAG DCIP'}]}
