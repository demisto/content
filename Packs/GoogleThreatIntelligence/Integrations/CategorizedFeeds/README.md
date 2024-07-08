Use this feed integration to fetch Google Threat Intelligence Feeds matches. It processes the latest finished job retrieving its matches based on the limit parameter (40 by default) in every fetch until there are no more matches for that job.

## Configure Google Threat Intelligence Feeds on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Threat Intelligence Feeds.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key (leave empty. Fill in the API key in the password field.) |  | True |
    | API Key |  | True |
    | Feed type |  | True |
    | Limit | Limit of indicators to fetch from retrohunt job results. | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Tags | Supports CSV values. | False |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gti-feed-get-indicators
***
Gets the matches from the latest feed.

### gti-feed-reset-fetch-indicators
***
Reset the last threat feed.



#### Base Command

`gti-feed-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 40. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gti-feed-get-indicators```
```!gti-feed-get-indicators limit=10```

#### Human Readable Output

### Indicators from Google Threat Intelligence Feeds:
|Sha256|Filetype|
|---|---|---|
| 80db033dfe2b4e966d46a4ceed36e20b98a13891ce364a1308b90da7ad694cf3 | ELF |
| 6717c568e623551e600d315c7d1d634824a6f4b16e8aedfa298aefe7155313ff | ELF |
| 2c02a593ac714f9bac876d0a3c056384e0038505515d0c8472aa00ea36a6abb2 | ELF |
| e658b64650153c2207a76b2ee390b0fef04712d0da1d75a9eae25e4be596071a | ELF |
| 5ec2e17f25e800825ec5ed592c73303f840fa33cce2c8c4a4e7b6556798ffda0 | ELF |
| 771ba05ca9321dc723fc66b995c1d79a969330fc4242da6737cff1b364f978c8 | ELF |
| 4e3fac63a8b027788a10fd0191adf3ad59b2111324e1aa4eb4441723793c1b11 | ELF |
| ff1bdaf789643c6b934c9a9593fea82912d5974ba6ca0fd8dbf42db09ba82925 | ELF |
| 4371874f35538dc7d3b1d50df8cd0e8ad0744441ed487deb0d7a18a4a4373fea | ELF |

