For fetching incidents, please update the query param according to [JQL documentation](https://confluence.atlassian.com/jiracoreserver073/advanced-searching-861257209.html)
Update the project you want to fetch from, using:  `project = soc AND status = open`.
This will fetch all tickets in your system (including past tickets) that are in Open status and in project soc. After the first run, it will create incidents only for new tickets.

If you wish the first run to start from a specific time, use "Issue index to start fetching incidents from" param.

Fetching incidents by creation time (using the Created field), instead of using IDs, is done by checking the "Use created field to fetch incidents" checkbox.

To use OAuth1.0 follow [this tutorial](https://developer.atlassian.com/cloud/jira/platform/jira-rest-api-oauth-authentication/) to get the Access Token. Authorizing using OAuth1.0, requires Access Token, Private Key and Consumer Key. To use basic authentication, follow [this tutorial](https://confluence.atlassian.com/cloud/api-tokens-938839638.html) to get the API token.

As of June 2019, Basic authentication with passwords for Jira is no longer supported, please use an API Token or OAuth 1.0