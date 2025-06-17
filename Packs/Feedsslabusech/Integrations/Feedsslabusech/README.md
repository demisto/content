## Overview

---

Use the abuse.ch SSL Blacklist feed integration to fetch indicators from the feed.

## Configure abuse.ch SSL Blacklist Feed on Cortex XSOAR

---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for abuse.ch SSL Blacklist Feed.
3. Click __Add instance__ to create and configure a new integration instance.
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

#### Create an API Key
1. Sign up for an abuse.ch account by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
2. Once you've logged in to abuse.ch, add at least one more way to log in. This helps ensure you can always access abuse.ch platforms, even if one of your login methods stops working.
3. Click the **Save profile** button. In the **Optional** section, you can now create an Auth-Key. This is your personal authentication key that you can use to query any abuse.ch APIs.

If you already have a profile, you only need to follow step 3. There’s nothing further to do for your authentication set up.
