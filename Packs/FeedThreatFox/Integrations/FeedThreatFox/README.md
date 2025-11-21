ThreatFox is a platform from abuse.ch and Spamhaus dedicated to sharing indicators of compromise (IOCs) associated with malware, with the infosec community, AV vendors and cyber threat intelligence providers.
For more information visit: https://threatfox.abuse.ch/

#### Create an Auth Key for abuse.ch
>
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.

## Configure ThreatFox Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Auth Key | Auth Key for authentication with abuse.ch  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch indicators |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Indicator Expiration Method | The method to be used to expire indicators from this feed. Default: indicatorType | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Feed Fetch Interval (in days) |  | False |
| Return IOCs with Ports | If selected, IP indicators will include a tag with the port value | False |
| Confidence Threshold |  | False |
| Create relationship | If selected, indicators will be created with relationships | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threatfox-get-indicators

***
Retrieves indicators from the ThreatFox API.

#### Base Command

`threatfox-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | Indicator value to search for | Optional |
| id | Indicator ID to search for. | Optional |
| hash | Hash to search for. | Optional |
| tag | Tag to search by. For available tag options, please refer to the API documentation- https://threatfox.abuse.ch/api/. | Optional |
| malware | Malware to search by. For available malware options, please refer to the API documentation- https://threatfox.abuse.ch/api/. | Optional |
| limit | Maximum indicators to search for. Available only when searching by 'malware' or 'tag'. Default is 50. Max is 1000. | Optional |

#### Context Output

There is no context output for this command.

#### Create an API Key

1. Sign up for an abuse.ch account by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
2. Once you've logged in to abuse.ch, add at least one more way to log in. This helps ensure you can always access abuse.ch platforms, even if one of your login methods stops working.
3. Click the **Save profile** button. In the **Optional** section, you can now create an Auth-Key. This is your personal authentication key that you can use to query any abuse.ch APIs.

If you already have a profile, you only need to follow step 3. There’s nothing further to do for your authentication set up.
