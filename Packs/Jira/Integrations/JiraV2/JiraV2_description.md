For fetching incidents, please update the query param according to [JQL documentation](https://confluence.atlassian.com/jiracoreserver073/advanced-searching-861257209.html)
Update the project you want to fetch from, using:  `project = soc AND status = open`.
This will fetch all tickets in your system (including past tickets) that are in Open status and in project soc. After the first run, it will create incidents only for new tickets.

When creating Jira issues through XSOAR, using the mirroring function, make sure that you exclude those issues when fetching incidents. To exclude these issues, tag the relevant issues with a dedicated label and exclude that label from the JQL query (Labels!=).

If you wish the first run to start from a specific time, use "Issue index to start fetching incidents from" param.

Fetching incidents by creation time (using the Created field), instead of using IDs, is done by checking the "Use created field to fetch incidents" checkbox.

You can authenticate using one of the following methods:

##### 1. Basic Authentication:
As of June 2019, Basic authentication with passwords for Jira is no longer supported, please use basic authentication using API Token or use OAuth 1.0. To use basic authentication, follow [this tutorial](https://confluence.atlassian.com/cloud/api-tokens-938839638.html) to get the API token.

##### 2. OAuth1.0:
To use OAuth1.0 follow [this tutorial](https://developer.atlassian.com/cloud/jira/platform/jira-rest-api-oauth-authentication/) to get the Access Token. Authorizing using OAuth1.0, requires Access Token, Private Key, and Consumer Key. 

##### 3. Private Access Token
To use a Private Access Token, please follow [this tutorial](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html) to obtain your Access Tokens. Authorizing using a PAT requires the Access Token only.
Insert the generated token in the `Access Token` field.