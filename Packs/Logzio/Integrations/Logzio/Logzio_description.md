If incident fetching is enabled, the integration runs a command to import new Logz.io security events as incidents every minute. A Logz.io  security event is logged whenever a security rule is triggered in Logz.io Cloud SIEM.

**A few notes:**

* Incidents that occurred immediately before the fetch are excluded. This is to allow sufficient indexing and processing time. (There is a 3 minute buffer.)

* Results are sorted by date ascending (earliest first).


### Details for the Logz.io integration panel
---

1. **Fetches incidents** - If enabled, the integration will fetch security events from Logz.io, according to the configurations set below. If disabled, the integration provides Logz.io commands without automatic incident fetching.”

2. **API token for Logz.io Security account** - To get the token, log into you Security account and access this [link](https://app.logz.io/#/dashboard/settings/api-tokens).

3. **API token for Logz.io Operations account** - To get the token, log into you Operations account and access this [link](https://app.logz.io/#/dashboard/settings/api-tokens).

4. **Region code of your Logz.io account** - To identify your region code, follow the instructions under “How do I find my Region” [here](https://docs.logz.io/user-guide/accounts/account-region.html)

5. **Filter by rule name** - You can test your filter on [this page](https://app.logz.io/#/dashboard/security/rules/rule-definitions?). Make sure you’re logged into your Logz.io Security account.

6. **Filter by rule severity** - You can test your filter on [this page](https://app.logz.io/#/dashboard/security/rules/rule-definitions?). Make sure you’re logged into your Logz.io Security account.
    
7. **First fetch time range** - Fetches rules that triggered before the integration was established. This is a one-time retroactive fetch. Valid format:  <number> <time unit> in minutes/hours/months/years. E.g., 12 hours, 7 days (with a space).

8. **Max. number of incidents fetched per run** - The maximum number of incidents returned per query is configurable, but capped at 50.  

  