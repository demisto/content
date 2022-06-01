# Authorization

SecurityScorecard has two types of API keys used to authorize API calls:

- Regular user.
- Bot user.

If you have an administrator account, it's recommended to use Bot User instead, as it lets you generate many API keys.

## Generate API key for Regular user

1. Sign into [SecurityScorecard](https://platform.securityscorecard.io/#/start)
2. Go to [My Settings](https://platform.securityscorecard.io/#/my-settings/api)
3. Under the *API Access* section, click on Generate new API token

## Generate API key for Bot user

1. Sign into [SecurityScorecard](https://platform.securityscorecard.io/#/start)
2. Go to [My Settings > Users](https://platform.securityscorecard.io/#/my-settings/users)
3. Click *Add User*
4. After creating the user, click on *create token*.

See the [Getting Started section](https://securityscorecard.readme.io/docs/getting-started) for more information.

## Update Interval

SecurityScorecard scores are updated on a daily basis. Therefore it's recommended to leave the Incidents Fetch Interval configuration to 1 day.
