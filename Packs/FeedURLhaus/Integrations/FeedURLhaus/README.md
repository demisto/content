URLhaus is a platform from abuse.ch and Spamhaus dedicated to sharing malicious URLs that are being used for malware distribution.
For more information, visit: https://urlhaus.abuse.ch/

Fetch indicators from URLhaus api
=======

Fetch indicators from the URLhaus API.


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Auth Key | The abuse.ch Auth-Key used to download the URLhaus export. | True |
| Tags | Supports CSV values. | False |
|  |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Fetch indicators |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
|  |  | False |
| Feed Fetch Interval | The abuse.ch URLhaus export dump is regenerated every 5 minutes. The minimum interval is 5 minutes; instances configured with a lower value must be updated to 5 or more after upgrading. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


#### Create an Auth Key for abuse.ch
>
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.

## Commands

You can execute these commands in a playbook.

### urlhaus-get-indicators

***
Manual command to fetch events and display them.