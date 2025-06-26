URLhaus is a platform from abuse.ch and Spamhaus dedicated to sharing malicious URLs that are being used for malware distribution.
For more information, visit: https://urlhaus.abuse.ch/

Fetch indicators from URLhaus api
=======

Fetch indicators from the URLhaus API.

| **Parameter**        | **Description**                                                                            | **Required** |
|----------------------|--------------------------------------------------------------------------------------------|--------------|
| Auth Key | Auth Key for authentication with abuse.ch  | True |
| Fetches indicators   | Check tofetch indicators                                                                   | True         |
| Indicator Reputation | The type of reputation for the indicator                                                   | True         |
| Feed Source          | The type of data we want to get from the api                                               | True         |
| Traffic Light Protocol Color               | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. | True         |
| Indicator Expiration Method              | The indicator expiration method                                                            | True         |
| Source Reliability             | The reliability of the feed                                                                | True         |
| Feed Fetch Interval    | The time interval to fetch indicators from the api                                         | True         |
| Trust any certificate    | Weather or not to trust any certificate                                                    | True         |
| Use system proxy settings   | If you want to use proxy for the integration                                               | True         |

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
