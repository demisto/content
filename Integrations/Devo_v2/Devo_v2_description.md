## Configure API Credentials
To configure an instance of the integration in Demisto, you will need to provide a Devo apiv2 OAuth token with `*.**`
permissions for the time being if you want the fetch incidents to work correctly. Otherwise only grant access to particular
tables but `siem.logtrust.alert.info` is used when fetching alerts.

If writing back to Devo make sure to also create a set of TLS credentials.

### Get your Demisto OAuth Token
1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __Authentication Tokens__.
3. If a token for Demisto has not already been  created, Click __CREATE NEW TOKEN__
  * Create the Token with `*.**` table permissions as an `apiv2` token.
4. Note the generated `Token`

### Get your Demisto Writer Credentials
1. Login to your Devo domain with a user with the ability to create security credentials.
2. Navigate to __Administration__ > __Credentials__ > __X.509 Certificates__.
3. Click `NEW CERTIFICATE` if you do not already have a set of keys for Demisto.
4. Download the following files:
  * `Certificate`
  * `Private Key`
  * `CHAIN CA`

## Setting Up an Instance
1. Name
  - Identifiable name of the instance you wish to create
2. Query Server Endpoint
  - APIv2 Devo query endpoint. Additional information found here: [Devo API Ref](https://docs.devo.com/confluence/ndt/api-reference/rest-api)
3. Oauth Token
  - APIv2 Oauth token with `*.**` table query access permissions
4. Writer relay to connect to
  - In Devo: Navigate to __Administration__ > __Relays__
  - Look for the relay named `central` with type `Secure`.
  - Use the `Address` for that given relay, we assume port __443__ so please omit, e.g. `us.elb.relay.logtrust.net`
5. Writer JSON Credentials
  - From the Writer Credentials that were downloaded please format them into JSON as follows:
  ```
  {
    "key": "contents of key file formatted as a single line string",
    "crt": "contents of certificate file formatted as a single line string",
    "chain": "contents of chain file formatted as a single line string"
  }
  ```
6. Devo base domain
  - This is the base web UI URL that you use to interact with Devo. If you login to `us.devo.com` -> `https://us.devo.com/welcome`
7. Fetches incidents
  - Check this box if you would like for the plugin to pull in Devo alerts as incidents. Please refer to `Fetch incident alert filter` and
    `Deduplication parameters JSON` for advanced configuration
8. Incident type
  - Demisto incident type to create all incidents as.
9. Fetch incidents alert filter
  - If you would like a subset of your alerts to only show up in Demisto please use this filtering.
  ```
  {
      "type": <"AND" | "OR">,
      "filters" : [
        {"key": <String Devo Column Name>, "operator": <Devo Linq Operator>, "value": <string>},
        {"key": <String Devo Column Name>, "operator": <Devo Linq Operator>, "value": <string>},
        ...
        {"key": <String Devo Column Name>, "operator": <Devo Linq Operator>, "value": <string>}
      ]
  }
  ```
  - Currently supports the following operators: `=`, `/=`, `>`, `<`, `>=`, `<=`, `->`, `and`, `or`, '->'
  - Please refer to [LINQ Operations Ref](https://docs.devo.com/confluence/ndt/searching-data/building-a-query/operations-reference)
10. Deduplication parameters JSON (BETA)
  - If you have some alerts that you only want to run 1 playbook on for a given time period with a cooldown please use this.
  ```
  {
      "cooldown": <int seconds cooldown for each type of alert>
  }
  ```
  - Uses the `context` column to group all alerts so all alerts that get processed by this will share the same cooldown.
  - This is a Beta feature so please use with caution as we will make usability enhancements.
11. Use system proxy settings
  - Uses the proxy on the system.
