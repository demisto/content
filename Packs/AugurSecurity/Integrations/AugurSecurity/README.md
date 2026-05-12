Leverage Augur's preemptive threat intelligence for actionable data against persistent threat actors.  Augur Security return a list which could include IP addresses, domains, URLs, and hash indicators which are updated daily.

## Configure Augur Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Augur Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The Augur access token is required to interact with Augur's API.  Please obtain the access token by contacting support@augursecurity.com | True |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Incremental Feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. As the determination if the indicator is new or modified happens on the 3rd-party vendor's side, and only indicators that are new or modified are sent to Cortex XSOAR, all indicators coming from these feeds are labeled new or modified. | False |
    | Feed Fetch Interval | The frequency of fetching the feed.  Default is daily. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) | Should the api request trust a any SSL cert. | False |
    | Use system proxy settings | Should the api request use the system's proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### augur-get-indicators

***
Get daily indicators from Augur.

#### Base Command

`augur-get-daily-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 100k. Default is 100000. | Optional |
| offset | The index of the first indicator to fetch. Default is 0. | Optional |

#### Context Output

The indicators will be insert into the XSOAR's indicator table.

### augur-get-file-hash-context

***
Get threat context of a file hash from the Augur API.

#### Base Command

`augur-get-file-hash-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The hash string to send. Available hash type are md5, sha1 and sha256 | Required |

#### Context Output

The return will be a json data structure containing threat context like categories, identifiers, reporting feeds.

### augur-get-host-context

***
Get threat context of a host name from the Augur API.

#### Base Command

`augur-get-host-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | The host string to send. | Required |

#### Context Output

The return will be a json data structure containing threat context like categories, identifiers, reporting feeds.

### augur-get-ip-context

***
Get threat context of a ipv4 address from the Augur API.

#### Base Command

`augur-get-ip-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The ipv4 address to send. | Required |

#### Context Output

The return will be a json data structure containing threat context like categories, identifiers, reporting feeds.
