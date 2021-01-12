BitcoinAbuse.com is a public database of bitcoin addresses used by hackers and criminals.
Supported Cortex XSOAR versions: 5.5.0 and later.

## Get Your API Key
In order to use Bitcoin Abuse service, you need to get your API key.
The API key is free and can be achieved by doing the following:
1. Navigate to https://www.bitcoinabuse.com and click on "Register" on top right corner of your screen.
2. Fill in your details (Name, Email, Password, etc...)
3. After your account have been set, go to Settings, and click on "API" section.
4. Give your API token a name, and click on "Create", a screen containing your generated API key
will appear.

## Configure BitcoinAbuse on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BitcoinAbuse.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | feed | Fetch indicators | False |
    | api_key | API Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | initial_fetch_interval | First Fetch Time | True |
    | feedReputation | Indicator Reputation | False |
    | feedReliability | Source Reliability | True |
    | feedExpirationPolicy |  | False |
    | tlp_color | Traffic Light Protocol Color | False |
    | feedFetchInterval | Feed Fetch Interval | False |
    | feedExpirationInterval |  | False |
    | feedBypassExclusionList | Bypass exclusion list | False |
    | feedTags | Tags | False |

4. Click **Test** to validate the URLs, token, and connection.
## Fetching indicators
#### Initial Fetch
When configuring an integration instance, you will be required to enter the first fetch parameter which will set the timeframe to pull Indicators in the first fetch, Two options are available:

- 30 Days - Indicators recorded in the last 30 days (updates every Sunday between 2am-3am UTC.)
- Forever - All recorded indicators (updates every 15th of the month between 2am-3am UTC.)


Note: 
- Whenever Forever is selected, in order to bring as much data as possible in the first fetch, we merge the Forever CSV together the 30 Days CSV file to avoid missing as much data as possible.
- Restrictions will be that any data reported between Sunday  (after 30 Days file update) to the day of the first fetch
will not be fetched

#### Each fetch after the initial fetch 
Each fetch after the initial fetch will return indicators reported on the previous day (updates once a day between 2am-3am UTC). Therefore, fetching more than once a day will not have any effect.

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bitcoinabuse-report-address
***
Reports an abuser to Bitcoin Abuse service. 'abuse_type_other' field is required when 'abuse_type' is other


#### Base Command

`bitcoinabuse-report-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | Address of the abuser. | Required | 
| abuser | Information about the abuser. | Required | 
| description | Description of the abuse. | Optional | 
| abuse_type | Type of abuse. The "abuse_type_other" field is required when the value of the "abuse_type" field is "other". Possible values are "ransomware", "darknet market", "bitcoin tumber", "blackmail scam", "sextortion", and "other". Possible values are: ransomware, darknet market, bitcoin tumbler, blackmail scam, sextortion, other. | Required | 
| abuse_type_other | Description of the abuse type. The "abuse_type_other" field is required when the value of the "abuse_type" field is "other". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!bitcoinabuse-report-address address=abcde12345 abuser=abuser@abuse.net abuse_type="bitcoin tumbler" description="this is a description of the abuse"```


#### Human Readable Output

>Bitcoin address abcde12345 by abuse bitcoin user abuser@abuse.net was reported to BitcoinAbuse API
