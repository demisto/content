Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with Dridex, Emotet (aka Heodo), TrickBot, QakBot (aka QuakBot / Qbot) and BazarLoader (aka BazarBackdoor).
For more information, visit: https://feodotracker.abuse.ch/

#### Create an Auth Key for abuse.ch
>
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.

## Configure Feodo Tracker IP Blocklist Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Auth Key | Auth Key for authentication with abuse.ch  | True |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Create relationships |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### feodotracker-ipblocklist-get-indicators

***
Gets the feed indicators.

#### Base Command

`feodotracker-ipblocklist-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. Default is 50. | Optional |

#### Context Output

There is no context output for this command.
