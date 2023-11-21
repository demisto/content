## Stamus Security Platform Integration Help

### Introduction

This integration connect XSOAR with Stamus Security Platform (SSP). It allows XSOAR
to fetch Declaration of Compromises from SSP and to enrich events with metadata and
Host Insights information.

### API key generation

To access the REST-API, a user first need to generate a unique token associated to its account. The API accesses are made on the behalf of a given user.

To do that, login to SCS and go under your account settings from the top right of the header’s menu.

From the left side panel, under User Settings, select Edit Token.

If you already generated a token for this account, it will be presented in the Token field, otherwise this field will be empty.

In both cases, to generate a new token, simply click the Regenerate button at the bottom of the page and you should see the Token field updated with a hash value such as 3064d9deadbeef36436daba5531e105123ec0fee.

### Setting up the Integration

To set up the integration you need to specify the base address of the server like `https://scs.my.org/` and the API keys.

Additional options are available such as `Don't Trust any certificate (not secure)` that you need to check if a
recognized certificate as not been deployed on the Stamus Central Server.