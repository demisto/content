
Integrate with Logz.io Cloud SIEM to automatically remediate security incidents identified by Logz.io and increase observability into incident details. The integration allows Demisto users to automatically remediate incidents identified by Logz.io Cloud SIEM using Demisto Playbooks.
In addition, users can query Logz.io directly from Demisto to investigate open questions or retrieve the logs responsible for triggering security rules. 


## Prerequisites 

1. Logz.io Cloud SIEM 

    You’ll need to have a Logz.io Cloud SIEM add-on. If you need to add it, please contact  support@logz.io 
  
2. API Tokens 

    You’ll need to create API Tokens for the relevant Logz.io accounts. Keep in mind that API tokens are specific to account ID. Your Logz.io Operations accounts and associated Security account have separate API Tokens. 

## How to configure the Logz.io integration from Demisto 

1. In Demisto, click Settings > Integrations and search for Logz.io. Click the cogswheel to configure a new instance. 

2. Fill in the Logz.io integration panel in Demisto:

    1. **Fetches incidents** - Enable this field if you want this integration to fetch triggered rules from Logz.io. If enabled, Demisto runs a command to import new incidents every minute based on the filtering configurations defined below. The maximum number of incidents returned per query is set to 50, and sorting is done by Date ascending (earliest first). 

    2. API token for Logz.io Security account - To get the token, log into you Security account and access this [link](https://app.logz.io/#/dashboard/settings/general).

    3. API token for Logz.io Operations account - To get the token, log into you Operations account and access this [link](https://app.logz.io/#/dashboard/settings/general).

    4. Region code of your Logz.io account - To identify your region code, follow the instructions under “How do I find my Region” [here](https://docs.logz.io/user-guide/accounts/account-region.html)

    5. Filter on rule names (Lucene syntax) - Rule names are found on [this page](https://app.logz.io/#/dashboard/security/rules/rule-definitions?). Make sure you’re logged into your Logz.io Security account.

    6. Filter by rule severity - Rule severity is listed on [this page](https://app.logz.io/#/dashboard/security/rules/rule-definitions?). Make sure you’re logged into your Logz.io Security account.
    
    7. First-time retroactive fetch - Fetches rules that triggered before the integration was established. This is a one-time retroactive fetch. 
    Valid format:  <number> <time unit> in minutes/hours/months/years. E.g., 12 hours, 7 days (with a space).

## Playbooks

Logz.io provides a sample playbook to get you started. You can add as many playbooks as you’ll need to keep increasing your security. 
