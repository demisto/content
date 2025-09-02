## Overview

The SSL Blacklist (SSLBL) is a project of abuse.ch with the goal of detecting malicious SSL connections, by identifying and blacklisting SSL certificates used by botnet C&C servers.
For more information, visit: https://sslbl.abuse.ch/

---

Use the abuse.ch SSL Blacklist feed integration to fetch indicators from the feed.

## Configure abuse.ch SSL Blacklist Feed on Cortex XSOAR

---

#### Create a required Auth Key for abuse.ch
>
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.

### Configure Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for abuse.ch SSL Blacklist Feed.
3. Click __Add instance__ to create and configure a new integration instance.

    * __Auth Key__: Enter the Auth-Key generated from your abuse.ch profile.
    * __Name__: a textual name for the integration instance.
    * __Services__: Services of abuse.ch SSL Blacklist to fetch indicators from:
        * https://sslbl.abuse.ch/blacklist/sslipblacklist.csv.
        * https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv.
        * https://sslbl.abuse.ch/blacklist/sslblacklist.csv.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Source Reliability__: Reliability of the feed.  
    * __Traffic Light Protocol Color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp
    * __Skip Exclusion List__: When selected, the exclusion list is ignored for indicators from
    this feed. This means that if an indicator from this feed is on the exclusion
    list, the indicator might still be added to the system.
    * __Indicator reputation__: Indicators from this integration instance will be marked with this
    reputation.
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
