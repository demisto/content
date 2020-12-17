BitcoinAbuse.com is a public database of bitcoin addresses used by hackers and criminals.
This integration was integrated and tested with version xx of BitcoinAbuse.
Supported Cortex XSOAR versions: 5.5.0 and later.

## Configure BitcoinAbuse on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BitcoinAbuse.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | incidentType | Incident type | False |
    | feed | Fetch indicators | False |
    | api_key | API Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | initial_fetch_interval | First Fetch Time | True |
    | feedReputation | Indicator Reputation | False |
    | feedReliability | Source Reliability | True |
    | feedExpirationPolicy |  | False |
    | feedFetchInterval | Feed Fetch Interval | False |
    | limit |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fetch-indicators
***
fetches indicators from BitcoinAbuse API


#### Base Command

`fetch-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### bitcoin-report-address
***
Reports an abuser to Bitcoin Abuse API. abuse_type_other field is required when abuse_type is other


#### Base Command

`bitcoin-report-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | address of the abuser. | Required | 
| abuser | information of the abuser. | Required | 
| description | description of the abusement. | Optional | 
| abuse_type | type of abuse made. abuse_type_other field is required when abuse_type is other . Possible values are: ransomware, darknet market, bitcoin tumbler, blackmail scam, sextortion, other. | Required | 
| abuse_type_other | description of abuse type, abuse_type_other field is required when abuse_type is other. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!bitcoin-report-address address=1FTJfkSLXj3JoWpW2ZKjk7FdWcTepWGQUC abuser=abuser@abuse.net abuse_type="bitcoin tumbler" description="this is a description of the abuse"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Bitcoin address 1FTJfkSLXj3JoWpW2ZKjk7FdWcTepWGQUC by abuse bitcoin user abuser@abuse.net was reported to BitcoinAbuse API
