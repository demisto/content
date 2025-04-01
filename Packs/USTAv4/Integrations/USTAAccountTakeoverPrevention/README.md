USTA Account Takeover Prevention is designed to collect compromised credentials sourced from stealer malware attacks, helping organizations identify potential account takeovers and enhance their security posture. Provided by PRODAFT.
This integration was integrated and tested with version 4.1.0 of USTA Account Takeover Prevention.

## Configure USTA Account Takeover Prevention on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for USTA Account Takeover Prevention.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Fetch incidents by status |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | First Fetch Time | The time range to consider for the initial data fetch. Warning: Fetching a large time range may cause performance issues\! | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### usta-atp-search-username

***
Search for compromised credentials by username

#### Base Command

`usta-atp-search-username`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to search. | Required | 
| page_size | Number of result that should appear on each page. | Optional | 
| page | 1-indexed page number to get a particular page of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| USTA.AccountTakeoverPrevention.id | Number | The ID of the alert | 
| USTA.AccountTakeoverPrevention.username | String | The username of the compromised credential | 
| USTA.AccountTakeoverPrevention.password | String | The password of the compromised credential | 
| USTA.AccountTakeoverPrevention.url | String | The URL of the compromised credential | 
| USTA.AccountTakeoverPrevention.is_corporate | Boolean | Whether the compromised credential is corporate | 
| USTA.AccountTakeoverPrevention.created | String | The creation date of the compromised credential | 
| USTA.AccountTakeoverPrevention.victim_detail.ip | String | The IP address of the victim | 
| USTA.AccountTakeoverPrevention.victim_detail.country | String | The country of the victim | 
| USTA.AccountTakeoverPrevention.victim_detail.phone_number | String | The phone number of the victim | 
| USTA.AccountTakeoverPrevention.victim_detail.computer_name | String | The computer name of the victim computer | 
| USTA.AccountTakeoverPrevention.victim_detail.victim_os | String | The OS of the victim computer | 
| USTA.AccountTakeoverPrevention.victim_detail.language | String | The language of the victim computer | 
| USTA.AccountTakeoverPrevention.victim_detail.memory | String | The memory of the victim computer | 
| USTA.AccountTakeoverPrevention.victim_detail.cpu | String | The CPU of the victim computer | 
| USTA.AccountTakeoverPrevention.victim_detail.gpu | String | The GPU of the victim computer | 
| USTA.AccountTakeoverPrevention.victim_detail.malware | String | The family of the malware that infected the victim computer | 
| USTA.AccountTakeoverPrevention.victim_detail.infection_date | String | The infection date of the victim computer | 

### Command Example

```!usta-atp-search-username username=user123456 page_size=1 page=1```

### Context Example

```json
{
    "USTA" : {
        "AccountTakeoverPrevention": [
            {
                "id": 1234567,
                "status": "open",
                "username": "user123456",
                "password": "******",
                
                "url": "https://example.com/login",
                "is_corporate": "False",                
                "created": "2024-11-18T00:00:00.000000Z",
                "victim_detail": {
                    "username": "anonymous",
                    "ip": "0.0.0.0",
                    "country": "Unknown",
                    "phone_number": "N/A",
                    "computer_name": "DESKTOP-XXXXX",
                    "victim_os": "OS x64",
                    "language": "N/A",
                    "memory": "XXXX MB",
                    "cpu": "Generic CPU",
                    "gpu": "Generic GPU",
                    "malware": "Unknown",
                    "infection_date": "N/A",
                    "created": "2024-11-18T00:00:00.000000Z"
                }
            }
        ]
    }
}
```