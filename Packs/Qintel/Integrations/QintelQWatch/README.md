Qintel's QWatch system contains credentials obtained from dump sites, hacker collaboratives, and command and control infrastructures of eCrime- and APT-related malware. With this integration, users can fetch exposure alerts as incidents and discover exposed credentials associated with their organization.
This integration was integrated and tested with version 1.1.6 of QWatch

## Configure QintelQWatch in Cortex


| **Parameter** | **Required** |
| --- | --- |
| QWatch API URL (optional) | False |
| Qintel Credentials | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch incidents | False |
| Fetch plaintext passwords | False |
| Limit number of records per fetch | False |
| First fetch time | False |
| Incidents Fetch Interval | False |
| Default Incident Severity | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### qintel-qwatch-exposures
***
Search QWatch for exposed credentials


#### Base Command

`qintel-qwatch-exposures`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email to search. | Optional | 
| domain | Domain to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Qintel.QWatch.Exposures | String | QWatch Exposure Records | 


#### Command Example
```!qintel-qwatch-exposures email=test@example.local```

#### Context Example
```json
{
    "Qintel": {
        "QWatch": {
            "Exposures": [
                {
                    "email": "test@example.local",
                    "firstseen": "2020-03-25 09:38:40",
                    "lastseen": "2021-02-05 04:35:33",
                    "loaded": "2021-02-05 04:35:33",
                    "password": "SuperSecretPassword",
                    "source": "combo-BigComboList"
                },
                {
                    "email": "test@example.local",
                    "firstseen": "2020-03-25 09:38:40",
                    "lastseen": "2021-02-05 04:35:33",
                    "loaded": "2020-08-10 02:10:11",
                    "password": "SuperSecretPassword",
                    "source": "dump-example.local"
                },
                {
                    "email": "test@example.local",
                    "firstseen": "2020-03-25 09:38:40",
                    "lastseen": "2021-02-05 04:35:33",
                    "loaded": "2020-03-25 09:38:40",
                    "password": "SuperSecretPassword",
                    "source": "malware-evilbot_March_22_2020"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Qintel QWatch exposures for: test@example.local
>
>|Email|Password|Source|Loaded|First Seen|Last Seen|
>|---|---|---|---|---|---|
>| test@example.local | SuperSecretPassword | combo-BigComboList | 2021-02-05 04:35:33 | 2020-03-25 09:38:40 | 2021-02-05 04:35:33 |
>| test@example.local | SuperSecretPassword | dump-example.local | 2020-08-10 02:10:11 | 2020-03-25 09:38:40 | 2021-02-05 04:35:33 |
>| test@example.local | SuperSecretPassword | malware-evilbot_March_22_2020 | 2020-03-25 09:38:40 | 2020-03-25 09:38:40 | 2021-02-05 04:35:33 |
