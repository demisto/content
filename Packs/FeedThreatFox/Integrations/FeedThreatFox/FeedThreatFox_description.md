## ThreatFox Feed Integration Help

ThreatFox is a free platform from abuse.ch with the goal of sharing indicators of compromise (IOCs) associated with malware with the infosec community, AV vendors and threat intelligence providers.

The ThreatFox Feed allows users to fetch indicators from ThreatFox.

Note, the fetch interval must be a whole number of days: 1, 2, 3, 4, 5, 6, or 7.
Please note that the fetch indicators process will automatically skip any indicators of type SHA3, and these will not be retrieved or processed by the integration.

A manual command is also available to retrieve indicators from ThreatFox as needed and should be used with caution.
For more details, refer to the ThreatFox documentation: <https://threatfox.abuse.ch/api/>

#### Create the required Auth Key for abuse.ch
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.