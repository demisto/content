Query the ja3er API for MD5 hashes of JA3 fingerprints.

## Configure Ja3er in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ja3-search
***
Search for "User-Agents" matching an MD5 hash of a JA3 fingerprint.


#### Base Command

`ja3-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| JA3 | MD5 hash of the JA3 fingerprint. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JA3.Count | Number | Number of times seen | 
| JA3.Last_seen | Date | Last seen date | 
| JA3.User-Agent | String | User-Agent | 


#### Command Example
```!ja3-search JA3=dda20ec0e6a8d4279860```

#### Context Example
```json
{
    "JA3": {
        "dda20ec0e6a8d4279860": [
            {
                "Count": 45,
                "Last_seen": "2020-12-03 19:19:15",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.60 Safari/537.36"
            },
            {
                "Count": 32,
                "Last_seen": "2021-02-11 20:41:53",
                "User-Agent": "PostmanRuntime/7.26.8"
            },
            {
                "Count": 22,
                "Last_seen": "2020-07-14 10:18:18",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36"
            }
        ]
    }
}
```

#### Human Readable Output

>### Search results for dda20ec0e6a8d4279860
>|Count|Last_seen|User-Agent|
>|---|---|---|
>| 45 | 2020-12-03 19:19:15 | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.60 Safari/537.36 |
>| 32 | 2021-02-11 20:41:53 | PostmanRuntime/7.26.8 |
>| 22 | 2020-07-14 10:18:18 | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36 |
