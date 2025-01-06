Cloudflare WAF integration allows customers to manage firewall rules, filters, and IP-lists. It also allows to retrieve zones list for each account.
This integration was integrated and tested with version 4 of CloudflareWAF

## Configure Cloudflare WAF in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| User Token |  | True |
| Password |  | True |
| Account ID | Account identifier. | True |
| Password |  | True |
| Default Zone ID | The domain identifier. Zone ID can be override when executing commands.The domain identifier. Zone ID can be override when executing commands. | False |
| Password |  | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cloudflare-waf-firewall-rule-create
***
Create a new firewall rule that create new filter or use an exist filter.


#### Base Command

`cloudflare-waf-firewall-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The rule action. Possible values are: block, challenge, js_challenge, managed_challenge, allow, log, bypass. | Required | 
| filter_id | Identifier of an existing filter. Required if filter_expression is unspecified. | Optional | 
| filter_expression | Filter expression when creating a filter for a new rule. Required if filter_id is unspecified. Expression example: "(ip.src eq 120.2.2.8) or (ip.src in $list_name)". For syntax explanations and more examples: https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/. | Optional |
| products | Comma separated list of products to bypass for a request when the bypass action is used. Valid values: zoneLockdown, uaBlock, bic, hot, securityLevel, rateLimit, waf. Possible values are: zoneLockdown, uaBlock, bic, hot, securityLevel, rateLimit, waf. | Optional | 
| priority | The priority of the rule to allow control of processing order. A lower number indicates high priority. If not provided, any rules with a priority will be sequenced before those without.<br/>min value: 0.<br/>max value: 2147483647. | Optional | 
| paused | Whether this firewall rule is currently paused. Possible values are: True, False. | Optional | 
| description | A description of the rule to help identify it. | Optional | 
| ref | Short reference tag to quickly select related rules. | Optional | 
| zone_id | Zone identifier. The initialization will override the value set in the instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.FirewallRule.id | String | Firewall rule ID. | 
| CloudflareWAF.FirewallRule.priority | unknown | The priority of the rule to allow control of processing order. | 
| CloudflareWAF.FirewallRule.action | unknown | The action of the rule. | 
| CloudflareWAF.FirewallRule.products | unknown | List of products to bypass for a request when the bypass action is used. | 
| CloudflareWAF.FirewallRule.paused | Boolean | Whether this firewall rule is currently paused. | 
| CloudflareWAF.FirewallRule.description | String | A description of the rule to help identify it. | 
| CloudflareWAF.FirewallRule.ref | String | Short reference tag to quickly select related rules. | 

#### Command example
```!cloudflare-waf-firewall-rule-create action=allow filter_expression="(ip.src eq 120.2.2.8)"```
#### Context Example
```json
{
    "CloudflareWAF": {
        "FirewallRule": {
            "action": "allow",
            "created_on": "2022-05-02T08:00:59Z",
            "filter": {
                "expression": "(ip.src eq 120.2.2.8)",
                "id": "2e740a75f2904b8e8df8e4fb36de1563",
                "paused": false
            },
            "id": "8da08f6f0c214e378e7847e420ec7965",
            "index": 4,
            "modified_on": "2022-05-02T08:00:59Z",
            "paused": false
        }
    }
}
```

#### Human Readable Output

>### Firewall rule was successfully created.
>|Id|Action|Filter Id|Filter Expression|Products|Priority|Paused|Description|Ref|
>|---|---|---|---|---|---|---|---|---|
>| 8da08f6f0c214e378e7847e420ec7965 | allow | 2e740a75f2904b8e8df8e4fb36de1563 | (ip.src eq 120.2.2.8) |  |  | false |  |  |


### cloudflare-waf-firewall-rule-update
***
Update firewall rule by the specified rule ID. Can update rule action, paused, description, priority, products and ref. Can not update or delete rule filter, ONLY add a new filter.


#### Base Command

`cloudflare-waf-firewall-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Firewall Rule identifier. . | Required | 
| action | The exist rule action or the new rule action to set. Possible values are: block, challenge, js_challenge, managed_challenge, allow, log, bypass. | Required | 
| filter_id | The ID of the exist rule filter or the ID of the new filter to set. | Required | 
| products | List of products to bypass for a request when the bypass action is used (comma separated list). Valid values: zoneLockdown, uaBlock, bic, hot, securityLevel, rateLimit, waf. Possible values are: zoneLockdown, uaBlock, bic, hot, securityLevel, rateLimit, waf. | Optional | 
| priority | The priority of the rule to allow control of processing order. A lower number indicates high priority. If not provided, any rules with a priority will be sequenced before those without.<br/>min value: 0.<br/>max value: 2147483647. | Optional | 
| paused | Whether this firewall rule is currently paused. Possible values are: true, false. | Optional | 
| description | A description of the rule to help identify it. | Optional | 
| ref | Short reference tag to quickly select related rules. | Optional | 
| zone_id | Zone identifier. The initialization will override the value set in the instance. | Optional | 


#### Context Output

There is no context output for this command.
### cloudflare-waf-firewall-rule-delete
***
Delete firewall rule by the specified rule ID.


#### Base Command

`cloudflare-waf-firewall-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Firewall Rule identifier. . | Required | 
| zone_id | Zone identifier. The initialization will override the value set in the instance. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cloudflare-waf-firewall-rule-delete id="93657f595665493bbfcf3664edfca130"```
#### Human Readable Output

>Firewall rule 93657f595665493bbfcf3664edfca130 was successfully deleted.

### cloudflare-waf-firewall-rule-list
***
List of firewall rules or details of individual rule by ID.


#### Base Command

`cloudflare-waf-firewall-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Firewall Rule identifier. . | Optional | 
| action | The rule action. Possible values are: block, challenge, js_challenge, managed_challenge, allow, log, bypass. | Optional | 
| paused | Whether this firewall rule is currently paused. Possible values are: true, false. | Optional | 
| description | A description of the rule to help identify it. | Optional | 
| page | Page number of paginated results.<br/>min value: 1. | Optional | 
| page_size | Number of firewall rules per page. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. | Optional | 
| limit | The maximum number of records to retrieve. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. Default is 50. | Optional | 
| zone_id | Zone identifier. The initialization will override the value set in the instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.FirewallRule.id | String | Firewall Rule identifier.  | 
| CloudflareWAF.FirewallRule.action | String | The rule action. | 
| CloudflareWAF.FirewallRule.paused | Boolean | Whether this firewall rule is currently paused. | 
| CloudflareWAF.FirewallRule.description | String | Rule description. | 
| CloudflareWAF.FirewallRule.Filter.id | String | Rule filter id. | 
| CloudflareWAF.FirewallRule.Filter.expression | String | Rule filter expression. | 
| CloudflareWAF.FirewallRule.Filter.paused | Boolean | Whether this rule filter is currently paused. | 
| CloudflareWAF.FirewallRule.Filter.description | String | Description of the rule filter. | 
| CloudflareWAF.FirewallRule.Filter.ref | String | Short reference tag. | 

#### Command example
```!cloudflare-waf-firewall-rule-list```
#### Context Example
```json
{
    "CloudflareWAF": {
        "FirewallRule": [
            {
                "action": "block",
                "description": null,
                "filter_expression": "(cf.client.bot)",
                "filter_id": "2aafaaea87da44ffa0929c115d2bebfc",
                "id": "47c7b26db654427d98235705abfcf32e",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            },
            {
                "action": "block",
                "description": null,
                "filter_expression": "(ip.src eq 120.2.2.8)",
                "filter_id": "a8e2887c7e484e0d84b0571e1e1ecc4a",
                "id": "de4fba698eb347f59e202306b46880a5",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            },
            {
                "action": "block",
                "description": null,
                "filter_expression": "(ip.src eq 120.2.2.8)",
                "filter_id": "c092787d60b54f06b270ab4cb22edd54",
                "id": "c643071e10694fecb194c95d80c64706",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            },
            {
                "action": "block",
                "description": null,
                "filter_expression": "(ip.src eq 120.2.2.8)",
                "filter_id": "3d6ea4fe88614d3c99d9f11da5b84b62",
                "id": "45a16a6ed90349db851eda214188f47a",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            }
        ]
    }
}
```

#### Human Readable Output

>### Firewall rule list
>Showing 4 rows out of 4.
>|Id|Action|Paused|Description|Filter Id|Filter Expression|
>|---|---|---|---|---|---|
>| 47c7b26db654427d98235705abfcf32e | block | false |  | 2aafaaea87da44ffa0929c115d2bebfc | (cf.client.bot) |
>| de4fba698eb347f59e202306b46880a5 | block | false |  | a8e2887c7e484e0d84b0571e1e1ecc4a | (ip.src eq 120.2.2.8) |
>| c643071e10694fecb194c95d80c64706 | block | false |  | c092787d60b54f06b270ab4cb22edd54 | (ip.src eq 120.2.2.8) |
>| 45a16a6ed90349db851eda214188f47a | block | false |  | 3d6ea4fe88614d3c99d9f11da5b84b62 | (ip.src eq 120.2.2.8) |


### cloudflare-waf-filter-create
***
Create a new filter which can be added to a firewall rule.


#### Base Command

`cloudflare-waf-filter-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| expression | The filter expression to be used. Expression example: "(ip.src eq 120.2.2.8) or (ip.src in $list_name)". For syntax explanations and more examples: https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/. | Required |
| ref | Short reference tag to quickly select related rules. | Optional | 
| paused | Whether this filter is currently paused. Possible values are: true, false. | Optional | 
| description | A note that you can use to describe the purpose of the filter. | Optional | 
| zone_id | Zone identifier. The initialization will override the value set in the instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.Filter.id | String | Filter identifier. | 
| CloudflareWAF.Filter.expression | String | The filter expression to be used. | 
| CloudflareWAF.Filter.paused | Boolean | Whether this filter is currently paused. | 
| CloudflareWAF.Filter.description | String | A note that describe the purpose of the filter. | 
| CloudflareWAF.Filter.ref | String | Short reference tag to quickly select related rules. | 

#### Command example
```!cloudflare-waf-filter-create expression="(ip.src eq 120.2.2.8)"```
#### Context Example
```json
{
    "CloudflareWAF": {
        "Filter": [
            {
                "expression": "(ip.src eq 120.2.2.8)",
                "id": "02f3f01de4644c31a048d4b837145162",
                "paused": false
            },
            {
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            }
        ]
    }
}
```

#### Human Readable Output

>### Filter was successfully created.
>|Id|Expression|Paused|Description|Ref|
>|---|---|---|---|---|
>| 02f3f01de4644c31a048d4b837145162 | (ip.src eq 120.2.2.8) | false |  |  |
>|  |  |  |  |  |


### cloudflare-waf-filter-update
***
Update filter by the specified filter ID.


#### Base Command

`cloudflare-waf-filter-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Filter identifier.  . Possible values are: . | Required | 
| expression | The filter expression to be used. Expression example: "(ip.src eq 120.2.2.8) or (ip.src in $list_name)". | Required |
| ref | Short reference tag to quickly select related rules. | Optional | 
| paused | Whether this filter is currently paused. Possible values are: true, false. | Optional | 
| description | A note that you can use to describe the purpose of the filter. | Optional | 
| zone_id | Zone identifier. The initialization will override the value set in the instance. | Optional | 


#### Context Output

There is no context output for this command.
### cloudflare-waf-filter-delete
***
Delete an exist filter (Note that a filter linked to firewall rule cannot be deleted).


#### Base Command

`cloudflare-waf-filter-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_id | The filter ID. | Required | 
| zone_id | Zone identifier. The initialization will override the value set in the instance. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cloudflare-waf-filter-delete filter_id="c8bf98553afd4522bde108f600d8a794"```
#### Human Readable Output

>Filter c8bf98553afd4522bde108f600d8a794 was successfully deleted.

### cloudflare-waf-filter-list
***
List filters.


#### Base Command

`cloudflare-waf-filter-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Filter identifier. . | Optional | 
| expression | The filter expression to be used. | Optional | 
| ref | Short reference tag to quickly select related rules. | Optional | 
| paused | Whether this filter is currently paused. Possible values are: true, false. | Optional | 
| description | A note that you can use to describe the purpose of the filter. | Optional | 
| page | Page number of paginated results.<br/>min value: 1. | Optional | 
| page_size | Number of filter based firewall rules per page. The argument accepts values ​​divided by 5.<br/>Minimum value 5.<br/>Maximum value 100.<br/>For example: 5,10,15. | Optional | 
| limit | The maximum number of records to retrieve. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. Default is 50. | Optional | 
| zone_id | Zone identifier. If provided, it will override the value set in the instance. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.Filter.id | String | Filter identifier.  | 
| CloudflareWAF.Filter.expression | String | The filter expression. | 
| CloudflareWAF.Filter.description | String | Description of the filter purpose. | 
| CloudflareWAF.Filter.paused | Boolean | Whether this filter is currently paused. | 
| CloudflareWAF.Filter.ref | String | Short reference tag. | 

#### Command example
```!cloudflare-waf-filter-list```
#### Context Example
```json
{
    "CloudflareWAF": {
        "Filter": [
            {
                "expression": "(ip.src eq 120.2.2.8)",
                "id": "c092787d60b54f06b270ab4cb22edd54",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            },
            {
                "expression": "(ip.src eq 120.2.2.8)",
                "id": "cdbbc2fc50d84e07bec72e213642d293",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            },
            {
                "expression": "(ip.src eq 120.2.2.8)",
                "id": "dc6eb4ff230648ecabf7c3f0c159d3b5",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            },
            {
                "expression": "(ip.src eq 120.2.2.8)",
                "id": "2c18e08324b345feade9003b68fc5762",
                "paused": false,
                "zone_id": "e18cd14b21c8282bec11cabec5c4dbf9"
            }
        ]
    }
}
```

#### Human Readable Output

>### Filter list
>Showing 50 rows out of 93.
>|Id|Expression|Ref|Description|Paused|
>|---|---|---|---|---|
>| c092787d60b54f06b270ab4cb22edd54 | (ip.src eq 120.2.2.8) |  |  | false |
>| 3b997e7e24bd48598870f02560e26044 | (ip.src eq 120.2.2.8) |  |  | false |
>| 3d6ea4fe88614d3c99d9f11da5b84b62 | (ip.src eq 120.2.2.8) |  |  | false |
>| f368d129d8fa4c97ad62fd4024bf63f9 | (ip.src eq 120.2.2.8) |  |  | false |


### cloudflare-waf-zone-list
***
List all account zones.


#### Base Command

`cloudflare-waf-zone-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| match | Whether to match all search requirements or at least one (any). Possible values are: any, all. Default is all. | Optional | 
| name | A domain name. | Optional | 
| account_name | Account name. | Optional | 
| account_id | Account identifier tag. | Optional | 
| status | Status of the zone. Possible values are: active, pending, initializing, moved, deleted, deactivated, read only. | Optional | 
| order | Field to order zones by. Possible values are: name, status, account.id, account.name. | Optional | 
| direction | Direction to order zones. Possible values are: asc, desc. | Optional | 
| page | Page number of paginated results. Default value: 1, min value: 1. | Optional | 
| page_size | Number of zones per page. The argument accepts values ​​divided by 5.<br/>Minimum value 5.<br/>Maximum value 100.<br/>For example: 5,10,15. | Optional | 
| limit | The maximum number of records to retrieve. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.Zone.success | Boolean | The status of the request \(true or false\). | 
| CloudflareWAF.Zone.id | String | The zone ID.  | 
| CloudflareWAF.Zone.name | String | A domain name. | 
| CloudflareWAF.Zone.development_mode | Integer | Development mode. | 
| CloudflareWAF.Zone.original_name_servers | Data | Original name servers. | 
| CloudflareWAF.Zone.original_registrar | String | Original registrar. | 
| CloudflareWAF.Zone.original_dnshost | String | Original DNS host. | 
| CloudflareWAF.Zone.created_on | Date | Zone created date. | 
| CloudflareWAF.Zone.modified_on | Date | Zone modified date. | 
| CloudflareWAF.Zone.activated_on | Date | Zone activated date. | 
| CloudflareWAF.Zone.status | String | Status of the zone. | 
| CloudflareWAF.Zone.paused | Boolean | Whether this zone is currently paused. | 
| CloudflareWAF.Zone.type | String | Short reference tag. | 
| CloudflareWAF.Zone.permissions | Data | List of zone permissions. | 
| CloudflareWAF.Zone.Account | Data | Account details. | 
| CloudflareWAF.Zone.owner | Data | The zone owner details. | 
| CloudflareWAF.Zone.name_servers | Data | Zone servers names. | 

#### Command example
```!cloudflare-waf-zone-list```
#### Context Example
```json
{
    "CloudflareWAF": {
        "Zone": [
            {
                "account": {
                    "id": "67fb88dc5eb69bd55969cea954c75cea",
                    "name": "email@email.com"
                },
                "activated_on": "2021-12-08T07:54:43.676430Z",
                "created_on": "2021-12-01T12:50:43.250444Z",
                "development_mode": 0,
                "id": "d185f37563270905ae2e587e5bc6c9dd",
                "meta": {
                    "custom_certificate_quota": 0,
                    "multiple_railguns_allowed": false,
                    "page_rule_quota": 30,
                    "phishing_detected": false,
                    "step": 2
                },
                "modified_on": "2021-12-08T07:54:43.676430Z",
                "name": "fortresscyber.io",
                "name_servers": [
                    "earl.ns.cloudflare.com",
                    "monroe.ns.cloudflare.com"
                ],
                "original_dnshost": null,
                "original_name_servers": [
                    "ns-669.awsdns-19.net",
                    "ns-1219.awsdns-24.org",
                    "ns-64.awsdns-08.com",
                    "ns-1907.awsdns-46.co.uk"
                ],
                "original_registrar": "namecheap, inc. (id: 1068)",
                "owner": {
                    "email": "email@email.com",
                    "id": "b295c6a5f2897c4f1a1c42ebeeb079",
                    "type": "user"
                },
                "paused": false,
                "permissions": [
                    "#access:edit",
                    "#access:read",
                    "#analytics:read",
                    "#app:edit",
                    "#auditlogs:read",
                    "#billing:read",
                    "#cache_purge:edit",
                    "#dns_records:edit",
                    "#dns_records:read",
                    "#healthchecks:edit",
                    "#healthchecks:read",
                    "#lb:edit",
                    "#lb:read",
                    "#legal:read",
                    "#logs:edit",
                    "#logs:read",
                    "#member:read",
                    "#organization:edit",
                    "#organization:read",
                    "#ssl:edit",
                    "#ssl:read",
                    "#stream:edit",
                    "#stream:read",
                    "#subscription:edit",
                    "#subscription:read",
                    "#teams:edit",
                    "#teams:read",
                    "#teams:report",
                    "#waf:edit",
                    "#waf:read",
                    "#waitingroom:edit",
                    "#waitingroom:read",
                    "#webhooks:edit",
                    "#webhooks:read",
                    "#worker:edit",
                    "#worker:read",
                    "#zaraz:edit",
                    "#zaraz:read",
                    "#zone:edit",
                    "#zone:read",
                    "#zone_settings:edit",
                    "#zone_settings:read"
                ],
                "plan": {
                    "can_subscribe": false,
                    "currency": "USD",
                    "externally_managed": false,
                    "frequency": "",
                    "id": "a577b510288e82b26486fd1df47000ec",
                    "is_subscribed": true,
                    "legacy_discount": false,
                    "legacy_id": "pro",
                    "name": "Pro Website",
                    "price": 0
                },
                "status": "active",
                "type": "full"
            },
            {
                "account": {
                    "id": "67fb88dc5eb69bd55969cea954c75cea",
                    "name": "email@email.com"
                },
                "activated_on": "2022-01-30T11:04:53.255562Z",
                "created_on": "2022-01-30T10:47:46.393968Z",
                "development_mode": 0,
                "id": "e0fb31cf064ac5fc55377bf9e16d40ee",
                "meta": {
                    "custom_certificate_quota": 0,
                    "multiple_railguns_allowed": false,
                    "page_rule_quota": 3,
                    "phishing_detected": false,
                    "step": 2
                },
                "modified_on": "2022-01-30T11:04:53.255562Z",
                "name": "stronghold.services",
                "name_servers": [
                    "earl.ns.cloudflare.com",
                    "monroe.ns.cloudflare.com"
                ],
                "original_dnshost": null,
                "original_name_servers": [
                    "dns1.registrar-servers.com",
                    "dns2.registrar-servers.com"
                ],
                "original_registrar": "namecheap, inc. (id: 1068)",
                "owner": {
                    "email": "email@email.com",
                    "id": "b295c6a5f2897c4f1a1c42ebeeb079",
                    "type": "user"
                },
                "paused": false,
                "permissions": [
                    "#access:edit",
                    "#access:read",
                    "#analytics:read",
                    "#app:edit",
                    "#auditlogs:read",
                    "#billing:read",
                    "#cache_purge:edit",
                    "#dns_records:edit",
                    "#dns_records:read",
                    "#healthchecks:edit",
                    "#healthchecks:read",
                    "#lb:edit",
                    "#lb:read",
                    "#legal:read",
                    "#logs:edit",
                    "#logs:read",
                    "#member:read",
                    "#organization:edit",
                    "#organization:read",
                    "#ssl:edit",
                    "#ssl:read",
                    "#stream:edit",
                    "#stream:read",
                    "#subscription:edit",
                    "#subscription:read",
                    "#teams:edit",
                    "#teams:read",
                    "#teams:report",
                    "#waf:edit",
                    "#waf:read",
                    "#waitingroom:edit",
                    "#waitingroom:read",
                    "#webhooks:edit",
                    "#webhooks:read",
                    "#worker:edit",
                    "#worker:read",
                    "#zaraz:edit",
                    "#zaraz:read",
                    "#zone:edit",
                    "#zone:read",
                    "#zone_settings:edit",
                    "#zone_settings:read"
                ],
                "plan": {
                    "can_subscribe": false,
                    "currency": "USD",
                    "externally_managed": false,
                    "frequency": "",
                    "id": "0feeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "is_subscribed": false,
                    "legacy_discount": false,
                    "legacy_id": "free",
                    "name": "Free Website",
                    "price": 0
                },
                "status": "active",
                "type": "full"
            }
        ]
    }
}
```

#### Human Readable Output

>### Zone list
>Showing 2 rows out of 2
>|Name|Account Name|Status|Account Id|Direction|
>|---|---|---|---|---|
>| fortresscyber.io |  | active |  |  |
>| stronghold.services |  | active |  |  |


### cloudflare-waf-ip-list-create
***
Create a new IP-list. An IP-list is a list that includes IP addresses and CIDR. IP-list is used in the filter expression.


#### Base Command

`cloudflare-waf-ip-list-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the list (used in filter expressions). | Required | 
| description | A note that can be used to annotate the List. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.IpList.id | String | The list ID.  | 
| CloudflareWAF.IpList.name | String | The name of the list. | 
| CloudflareWAF.IpList.description | String | A note that annotate the List. | 
| CloudflareWAF.IpList.kind | String | The kind of values in the List. | 
| CloudflareWAF.IpList.num_items | Integer | Number of list items. | 
| CloudflareWAF.IpList.num_referencing_filters | Integer | Number of referencing filters to the list. | 
| CloudflareWAF.IpList.created_on | Date | List created date. | 
| CloudflareWAF.IpList.modified_on | Date | List modified date. | 

### cloudflare-waf-ip-list-delete
***
Delete IP-list by the specified list ID.


#### Base Command

`cloudflare-waf-ip-list-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The list ID. . | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cloudflare-waf-ip-list-delete id="dd7e3f1f5edf4591acb22f20da320b8f"	```
#### Human Readable Output

>IP list dd7e3f1f5edf4591acb22f20da320b8f was successfully deleted

### cloudflare-waf-ip-lists-list
***
List IP-lists.


#### Base Command

`cloudflare-waf-ip-lists-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Retrieve details for an individual list Id. | Optional | 
| page | Page number of paginated results.<br/>Default value: 1, min value: 1. | Optional | 
| page_size | Number of IP-list per page. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. | Optional | 
| limit | The maximum number of records to retrieve. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.IpList.id | String | The list ID.  | 
| CloudflareWAF.IpList.name | String | The list name. | 
| CloudflareWAF.IpList.description | String | List description. | 
| CloudflareWAF.IpList.kind | String | List kind \(ip\\redirect\). | 
| CloudflareWAF.IpList.num_items | unknown | Number of list items. | 
| CloudflareWAF.IpList.num_referencing_filters | unknown | Number of referencing filters to the list. | 

#### Command example
```!cloudflare-waf-ip-lists-list```
#### Context Example
```json
{
    "CloudflareWAF": {
        "IpList": [
            {
                "created_on": "2022-04-10T09:42:13Z",
                "id": "e6efdc37cf7d41f2860a3fd448c68df8",
                "kind": "ip",
                "modified_on": "2022-04-27T13:39:44Z",
                "name": "my_first_list1",
                "num_items": 8,
                "num_referencing_filters": 1
            },
            {
                "created_on": "2022-03-29T14:53:15Z",
                "id": "82963f46e892446e99ae3ff9fe1b6524",
                "kind": "ip",
                "modified_on": "2022-04-27T13:39:32Z",
                "name": "my_first_list",
                "num_items": 1,
                "num_referencing_filters": 1
            },
            {
                "created_on": "2022-04-27T13:36:54Z",
                "id": "617290bdb0674696a20af4cdf4677f4e",
                "kind": "ip",
                "modified_on": "2022-04-27T13:36:54Z",
                "name": "new_new",
                "num_items": 0,
                "num_referencing_filters": 0
            },
            {
                "created_on": "2022-04-27T13:12:13Z",
                "id": "8af3465383434fc3ab6283d07406699f",
                "kind": "ip",
                "modified_on": "2022-04-27T13:12:13Z",
                "name": "my_new_and_last_list",
                "num_items": 0,
                "num_referencing_filters": 0
            },
            {
                "created_on": "2022-04-26T13:54:32Z",
                "id": "c0388c7c007d497ea37a21555aff49d2",
                "kind": "ip",
                "modified_on": "2022-04-27T12:35:09Z",
                "name": "list_name",
                "num_items": 1,
                "num_referencing_filters": 0
            },
            {
                "created_on": "2022-04-27T10:46:47Z",
                "id": "71934eec8ce34a85b57509a60f9ae57c",
                "kind": "ip",
                "modified_on": "2022-04-27T10:49:52Z",
                "name": "playbook_list",
                "num_items": 0,
                "num_referencing_filters": 0
            },
            {
                "created_on": "2022-04-27T10:08:53Z",
                "id": "8e9773d982fb4dbfb198f8078d22f4f6",
                "kind": "ip",
                "modified_on": "2022-04-27T10:08:53Z",
                "name": "list_name2",
                "num_items": 0,
                "num_referencing_filters": 0
            },
            {
                "created_on": "2022-04-26T08:25:48Z",
                "id": "8667dc96872c44ebabd7559594e92372",
                "kind": "ip",
                "modified_on": "2022-04-26T08:55:54Z",
                "name": "demo_list2",
                "num_items": 1,
                "num_referencing_filters": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### IP lists list
>Showing 8 rows out of 8.
>|Id|Name|Kind|Num Items|Num Referencing Filters|Created On|Modified On|
>|---|---|---|---|---|---|---|
>| e6efdc37cf7d41f2860a3fd448c68df8 | my_first_list1 | ip | 8 | 1 | 2022-04-10T09:42:13Z | 2022-04-27T13:39:44Z |
>| 82963f46e892446e99ae3ff9fe1b6524 | my_first_list | ip | 1 | 1 | 2022-03-29T14:53:15Z | 2022-04-27T13:39:32Z |
>| 617290bdb0674696a20af4cdf4677f4e | new_new | ip | 0 | 0 | 2022-04-27T13:36:54Z | 2022-04-27T13:36:54Z |
>| 8af3465383434fc3ab6283d07406699f | my_new_and_last_list | ip | 0 | 0 | 2022-04-27T13:12:13Z | 2022-04-27T13:12:13Z |
>| c0388c7c007d497ea37a21555aff49d2 | list_name | ip | 1 | 0 | 2022-04-26T13:54:32Z | 2022-04-27T12:35:09Z |
>| 71934eec8ce34a85b57509a60f9ae57c | playbook_list | ip | 0 | 0 | 2022-04-27T10:46:47Z | 2022-04-27T10:49:52Z |
>| 8e9773d982fb4dbfb198f8078d22f4f6 | list_name2 | ip | 0 | 0 | 2022-04-27T10:08:53Z | 2022-04-27T10:08:53Z |
>| 8667dc96872c44ebabd7559594e92372 | demo_list2 | ip | 1 | 1 | 2022-04-26T08:25:48Z | 2022-04-26T08:55:54Z |


### cloudflare-waf-ip-list-item-create
***
Create new items for exist IP-list. 


#### Base Command

`cloudflare-waf-ip-list-item-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the list to insert the new items. Possible values are: . | Required | 
| items | The new items to be added (comma separated IP addresses). | Required | 
| polling | Use Cortex XSOAR built-in polling to retrieve the result when it's ready. Default is False. Possible values are: true, false. Default is True. | Optional | 
| interval | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 30. Default is 10. | Optional |
| timeout | Indicates the time in seconds until the polling sequence timeouts. Default is 60. Default is 60. | Optional | 
| operation_id | The ID of the pipeline run to retrieve when polling argument is true. Intended for use by the Polling process and does not need to be provided by the user. | Optional | 


#### Context Output

There is no context output for this command.
### cloudflare-waf-ip-list-item-update
***
Replace the IP-list items with a new items


#### Base Command

`cloudflare-waf-ip-list-item-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The list ID. | Required | 
| items | The new items. | Required | 
| polling | Use Cortex XSOAR built-in polling to retrieve the result when it's ready. Default is False. Possible values are: true, false. Default is True. | Optional | 
| interval | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 30. Default is 10. | Optional |
| timeout | Indicates the time in seconds until the polling sequence timeouts. Default is 60. Default is 60. | Optional | 
| operation_id | The ID of the pipeline run to retrieve when polling argument is true. Intended for use by the Polling process and does not need to be provided by the user. | Optional | 


#### Context Output

There is no context output for this command.
### cloudflare-waf-ip-list-item-delete
***
Delete item of a IP-list by the specified list ID and list item.


#### Base Command

`cloudflare-waf-ip-list-item-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The list ID. | Required | 
| items_id | The items ID to be delete. | Required | 
| polling | Use Cortex XSOAR built-in polling to retrieve the result when it's ready. Default is False. Possible values are: true, false. Default is True. | Optional | 
| interval | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 30. Default is 10. | Optional |
| timeout | Indicates the time in seconds until the polling sequence timeouts. Default is 60. Default is 60. | Optional | 
| operation_id | The ID of the pipeline run to retrieve when polling argument is true. Intended for use by the Polling process and does not need to be provided by the user. | Optional | 


#### Context Output

There is no context output for this command.
### cloudflare-waf-ip-list-item-list
***
List all items in the List or details of individual item by ID.


#### Base Command

`cloudflare-waf-ip-list-item-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The list ID. | Required | 
| item_id | Retrieve details for an individual item Id. | Optional | 
| page | Page number of paginated results.<br/>Default value: 1, min value: 1. | Optional | 
| page_size | Number of zones per page. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. | Optional | 
| limit | The maximum number of records to retrieve. The argument accepts values ​​divided by 5. Minimum value 5. Maximum value 100. For example: 5,10,15. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloudflareWAF.IpListItem.items | Unknown | The list items. | 
| CloudflareWAF.IpListItem.list_id | String | The list ID. | 

#### Command example
```!cloudflare-waf-ip-list-item-list list_id="e6efdc37cf7d41f2860a3fd448c68df8"```
#### Context Example
```json
{
    "CloudflareWAF": {
        "IpListItem": {
            "items": [
                {
                    "created_on": "2022-04-26T10:58:55Z",
                    "id": "b3016f6529274bbd8086a4ac0be07822",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-26T10:59:24Z"
                },
                {
                    "created_on": "2022-04-25T13:01:32Z",
                    "id": "e5a81036d2c549dba90460c6b5745495",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-25T13:01:32Z"
                },
                {
                    "created_on": "2022-04-25T13:12:09Z",
                    "id": "93d34d1f299a46659fe61fa2165d38a3",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-25T13:12:09Z"
                },
                {
                    "created_on": "2022-04-25T12:45:50Z",
                    "id": "748c3ae947ca49d3aada448d233838e0",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-25T12:46:05Z"
                },
                {
                    "created_on": "2022-04-25T12:45:50Z",
                    "id": "ceea4f5b3e124a72a9aed4a779ce8dcb",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-25T12:46:05Z"
                },
                {
                    "created_on": "2022-04-25T12:45:50Z",
                    "id": "eab6abfa0d754c629a9bce69ab3cc5fb",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-25T12:46:05Z"
                },
                {
                    "created_on": "2022-04-25T12:45:50Z",
                    "id": "eccdf2f286804a988850accbaaeaa462",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-25T12:46:05Z"
                },
                {
                    "created_on": "2022-04-25T12:45:50Z",
                    "id": "d3b69c4d7bc34384a7448498dd8d9b45",
                    "ip": "120.2.2.8",
                    "modified_on": "2022-04-25T12:46:05Z"
                }
            ],
            "list_id": "e6efdc37cf7d41f2860a3fd448c68df8"
        }
    }
}
```

#### Human Readable Output

>### ip-list e6efdc37cf7d41f2860a3fd448c68df8
>Showing 8 rows out of 8.
>|Id|Ip|Created On|Modified On|
>|---|---|---|---|
>| b3016f6529274bbd8086a4ac0be07822 | 120.2.2.8 | 2022-04-26T10:58:55Z | 2022-04-26T10:59:24Z |
>| e5a81036d2c549dba90460c6b5745495 | 120.2.2.8 | 2022-04-25T13:01:32Z | 2022-04-25T13:01:32Z |
>| 93d34d1f299a46659fe61fa2165d38a3 | 120.2.2.8 | 2022-04-25T13:12:09Z | 2022-04-25T13:12:09Z |
>| 748c3ae947ca49d3aada448d233838e0 | 120.2.2.8 | 2022-04-25T12:45:50Z | 2022-04-25T12:46:05Z |
>| ceea4f5b3e124a72a9aed4a779ce8dcb | 120.2.2.8 | 2022-04-25T12:45:50Z | 2022-04-25T12:46:05Z |
>| eab6abfa0d754c629a9bce69ab3cc5fb | 120.2.2.8 | 2022-04-25T12:45:50Z | 2022-04-25T12:46:05Z |
>| eccdf2f286804a988850accbaaeaa462 | 120.2.2.8 | 2022-04-25T12:45:50Z | 2022-04-25T12:46:05Z |
>| d3b69c4d7bc34384a7448498dd8d9b45 | 120.2.2.8 | 2022-04-25T12:45:50Z | 2022-04-25T12:46:05Z |
