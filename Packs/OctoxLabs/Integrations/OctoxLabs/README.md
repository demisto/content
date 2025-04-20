Octox Labs Cyber Security Asset Management platform
This integration was integrated and tested with version 4.5.0 of OctoxLabs

## Configure OctoxLabs in Cortex



| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| IP | Your Octox Labs Platform IP | True |
| API Key | Your Octox Labs API Key. \(https://github.com/octoxlabs/py-octoxlabs\#getting-started\) | True |
| HTTPS Proxy | Your HTTPS Proxy URL | False |
| No Verify | Don't Verify SSL | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### octoxlabs-get-adapters

***
Fetch octoxlabs all adapters

#### Base Command

`octoxlabs-get-adapters`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Adapters.count | Number | Adapters count |
| OctoxLabs.Adapters.results.id | Number | Adapter id |
| OctoxLabs.Adapters.results.name | String | Adapter name |
| OctoxLabs.Adapters.results.slug | String | Adapter slug |
| OctoxLabs.Adapters.results.description | String | Adapter description |
| OctoxLabs.Adapters.results.groups | Unknown | List&lt;string&gt; Adapter groups |
| OctoxLabs.Adapters.results.beta | Boolean | Adapter is beta? |
| OctoxLabs.Adapters.results.status | Number | Adapter status |
| OctoxLabs.Adapters.results.hr_status | String | Adapter human readable status |

### octoxlabs-get-connections

***
Fetch octoxlabs connections

#### Base Command

`octoxlabs-get-connections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Connections.count | Number | Connections count |
| OctoxLabs.Connections.results.id | Number | Connection id |
| OctoxLabs.Connections.results.adapter_id | Number | Connection adapter id |
| OctoxLabs.Connections.results.adapter_name | String | Connection adapter name |
| OctoxLabs.Connections.results.name | String | Connection name |
| OctoxLabs.Connections.results.status | Boolean | Connection status |
| OctoxLabs.Connections.results.description | String | Connection description |
| OctoxLabs.Connections.results.enabled | Boolean | Connection is enabled? |

### octoxlabs-get-discoveries

***
Fetch octoxlabs discoveries

#### Base Command

`octoxlabs-get-discoveries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Discoveries.count | Number | Total discovery count |
| OctoxLabs.Discoveries.results.id | Number | Discovery id |
| OctoxLabs.Discoveries.results.start_time | String | Discovery start time |
| OctoxLabs.Discoveries.results.end_time | String | Discovery end time |
| OctoxLabs.Discoveries.results.status | Number | Discovery status |
| OctoxLabs.Discoveries.results.hr_status | String | Discovery human readable status |
| OctoxLabs.Discoveries.results.progress | Number | Discovery progress |

### octoxlabs-get-last-discovery

***
Get last success discovery

#### Base Command

`octoxlabs-get-last-discovery`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Discovery.id | Number | Last discovery id |
| OctoxLabs.Discovery.start_time | String | Last discovery start time |
| OctoxLabs.Discovery.end_time | String | Last discovery end time |
| OctoxLabs.Discovery.status | Number | Last discovery status |
| OctoxLabs.Discovery.hr_status | String | Last discovery human readable status |
| OctoxLabs.Discovery.progress | Number | Last discovery progress |

### octoxlabs-search-devices

***
Search in your devices

#### Base Command

`octoxlabs-search-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional |
| fields | Fields. | Optional |
| page | Page. | Optional |
| size | Size. | Optional |
| discovery_id | Specific Discovery Id. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Devices.count | Number | Total devices count |
| OctoxLabs.Devices.results | Unknown | List&lt;Dict&gt; Device information |

### octoxlabs-get-device

***
Fetch your device

#### Base Command

`octoxlabs-get-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Your device hostname. | Required |
| discovery_id | Your device at specific discovery. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Device | Unknown | &lt;Dict&gt; Octoxlabs Device |

### octoxlabs-get-queries

***
Fetch your queries

#### Base Command

`octoxlabs-get-queries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Query list page. | Optional |
| search | Search text. | Optional |
| size | Query list size. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Queries.count | Number | Queries count |
| OctoxLabs.Queries.results.id | Number | Query id |
| OctoxLabs.Queries.results.name | String | Query name |
| OctoxLabs.Queries.results.text | String | Query text |
| OctoxLabs.Queries.results.tags | Unknown | List&lt;str&gt; Query tags |
| OctoxLabs.Queries.results.count | Number | Query device count |
| OctoxLabs.Queries.results.is_public | Boolean | Query is public? |
| OctoxLabs.Queries.results.created_at | String | Query created at |
| OctoxLabs.Queries.results.updated_at | String | Query updated at |
| OctoxLabs.Queries.results.username | String | Query creator |
| OctoxLabs.Queries.results.is_temporary | Boolean | Query is temporary |

### octoxlabs-get-query-by-id

***
Fetch your queries by id

#### Base Command

`octoxlabs-get-query-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | Query id. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Queries.results.id | Number | Query id |
| OctoxLabs.Queries.results.name | String | Query name |
| OctoxLabs.Queries.results.text | String | Query text |
| OctoxLabs.Queries.results.tags | Unknown | List&lt;str&gt; Query tags |
| OctoxLabs.Queries.results.count | Number | Query device count |
| OctoxLabs.Queries.results.is_public | Boolean | Query is public? |
| OctoxLabs.Queries.results.created_at | String | Query created at |
| OctoxLabs.Queries.results.updated_at | String | Query updated at |
| OctoxLabs.Queries.results.username | String | Query creator |
| OctoxLabs.Queries.results.is_temporary | Boolean | Query is temporary |

### octoxlabs-get-query-by-name

***
Fetch your queries by id

#### Base Command

`octoxlabs-get-query-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_name | Query name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Queries.results.id | Number | Query id |
| OctoxLabs.Queries.results.name | String | Query name |
| OctoxLabs.Queries.results.text | String | Query text |
| OctoxLabs.Queries.results.tags | Unknown | List&lt;str&gt; Query tags |
| OctoxLabs.Queries.results.count | Number | Query device count |
| OctoxLabs.Queries.results.is_public | Boolean | Query is public? |
| OctoxLabs.Queries.results.created_at | String | Query created at |
| OctoxLabs.Queries.results.updated_at | String | Query updated at |
| OctoxLabs.Queries.results.username | String | Query creator |
| OctoxLabs.Queries.results.is_temporary | Boolean | Query is temporary |

### octoxlabs-get-user-by-username

***
Fetch your Users by username

#### Base Command

`octoxlabs-get-user-by-username`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | User username. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.User.results.id | Number | User id. | 
| OctoxLabs.User.results.email | String | User email. | 
| OctoxLabs.User.results.username | String | User username. | 
| OctoxLabs.User.results.name | String | User name. | 
| OctoxLabs.User.results.first_name | String | User first name | 
| OctoxLabs.User.results.last_name | String | User last name | 
| OctoxLabs.User.results.is_active | Boolean | User is active | 
| OctoxLabs.User.results.is_ldap | Boolean | User is ldap | 
| OctoxLabs.Users.results.groups | Unknown | List&lt;Dict&gt; User groups | 

### octoxlabs-get-groups

***
Fetch your Groups

#### Base Command

`octoxlabs-get-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Group list page. | Optional | 
| search | Search text. | Optional | 
| size | Group list size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Groups.count | Number | Groups count. | 
| OctoxLabs.Groups.results.id | Number | Group id. | 
| OctoxLabs.Groups.results.name | String | Group name. | 
| OctoxLabs.Groups.results.users_count | Number | Group users count. | 

### octoxlabs-get-companies

***
Fetch your Companies

#### Base Command

`octoxlabs-get-companies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Company list page. | Optional | 
| search | Search text. | Optional | 
| size | Company list size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Companies.count | Number | Companies count. | 
| OctoxLabs.Companies.results.id | Number | Company id. | 
| OctoxLabs.Companies.results.name | String | Company name. | 
| OctoxLabs.Companies.results.domain | String | Company domain. | 
| OctoxLabs.Companies.results.is_active | Boolean | Company is active. | 

### octoxlabs-get-domain-by-domain-name

***
Fetch your Domain by Domain name.

#### Base Command

`octoxlabs-get-domain-by-domain-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | Domain name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Domain.results.id | Number | Domain id. | 
| OctoxLabs.Domain.results.domain | String | Domain domain. | 
| OctoxLabs.Domain.results.tenant_name | String | Domain tenant name. | 
| OctoxLabs.Domain.results.tenant | Number | Domain tenant. | 

### octoxlabs-get-company-by-id

***
Fetch your Company by id.

#### Base Command

`octoxlabs-get-company-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_id | Company id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Company.results.id | Number | Company id. | 
| OctoxLabs.Company.results.name | String | Company name. | 
| OctoxLabs.Company.results.domain | String | Company domain. | 
| OctoxLabs.Company.results.is_active | Boolean | Company is active. | 

### octoxlabs-get-permissions

***
Fetch your Permissions

#### Base Command

`octoxlabs-get-permissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Permission list page. | Optional | 
| search | Search text. | Optional | 
| size | Permission list size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Permissions.count | Number | Permissions count. | 
| OctoxLabs.Permissions.results.id | Number | Permission id. | 
| OctoxLabs.Permissions.results.name | String | Permission name. | 
| OctoxLabs.Permissions.results.app | String | Permission app. | 

### octoxlabs-get-domains

***
Fetch your Domains

#### Base Command

`octoxlabs-get-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Domain list page. | Optional | 
| search | Search text. | Optional | 
| size | Domain list size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Domains.count | Number | Domains count. | 
| OctoxLabs.Domains.results.id | Number | Domain id. | 
| OctoxLabs.Domains.results.domain | String | Domain domain. | 
| OctoxLabs.Domains.results.tenant_name | String | Domain tenant name. | 
| OctoxLabs.Domains.results.tenant | Number | Domain tenant. | 

### octoxlabs-get-domain-by-id

***
Fetch your Domain by id.

#### Base Command

`octoxlabs-get-domain-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | Domain id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Domain.results.id | Number | Domain id. | 
| OctoxLabs.Domain.results.domain | String | Domain domain. | 
| OctoxLabs.Domain.results.tenant_name | String | Domain tenant name. | 
| OctoxLabs.Domain.results.tenant | Number | Domain tenant. | 

### octoxlabs-get-company-by-name

***
Fetch your Company by name.

#### Base Command

`octoxlabs-get-company-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| company_name | Company name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Company.count | Number | Companies count. | 
| OctoxLabs.Company.results.id | Number | Company id. | 
| OctoxLabs.Company.results.name | String | Company name. | 
| OctoxLabs.Company.results.domain | String | Company domain. | 
| OctoxLabs.Company.results.is_active | Boolean | Company is active. | 

### octoxlabs-get-users

***
Fetch your Users

#### Base Command

`octoxlabs-get-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | User list page. | Optional | 
| search | Search text. | Optional | 
| size | User list size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Users.count | Number | Users count. | 
| OctoxLabs.Users.results.id | Number | User id. | 
| OctoxLabs.Users.results.email | String | User email. | 
| OctoxLabs.Users.results.username | String | User username. | 
| OctoxLabs.Users.results.name | String | User name. | 
| OctoxLabs.Users.results.first_name | String | User first name | 
| OctoxLabs.Users.results.last_name | String | User last name | 
| OctoxLabs.Users.results.is_active | Boolean | User is active | 
| OctoxLabs.Users.results.is_ldap | Boolean | User is ldap | 
| OctoxLabs.Users.results.groups | Unknown | List&lt;Dict&gt; User groups | 

### octoxlabs-get-user-by-id

***
Fetch your User by id

#### Base Command

`octoxlabs-get-user-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.User.results.id | Number | User id. | 
| OctoxLabs.User.results.email | String | User email. | 
| OctoxLabs.User.results.username | String | User username. | 
| OctoxLabs.User.results.name | String | User name. | 
| OctoxLabs.User.results.first_name | String | User first name | 
| OctoxLabs.User.results.last_name | String | User last name | 
| OctoxLabs.User.results.is_active | Boolean | User is active | 
| OctoxLabs.User.results.is_ldap | Boolean | User is ldap | 
| OctoxLabs.User.results.groups | Unknown | List&lt;Dict&gt; User groups | 
### octoxlabs-search-scroll-users

***
Search in your users.

#### Base Command

`octoxlabs-search-scroll-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| fields | Fields. | Optional | 
| size | Size. (Default: 50). | Optional | 
| discovery_id | Specific Discovery Id. | Optional | 
| scroll_id | Specific Scroll Id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.ScrolledUsers.count | Number | Total users count. | 
| OctoxLabs.ScrolledUsers.scroll_id | String | Specific Scroll Id | 
| OctoxLabs.ScrolledUsers.results | Unknown | List Users information. | 

### octoxlabs-get-application-detail

***
Fetch your application.

#### Base Command

`octoxlabs-get-application-detail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | Your application id. | Required | 
| discovery_id | Your device at specific discovery. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Application | Unknown | &lt;Dict&gt; Octoxlabs Application. | 

### octoxlabs-search-scroll-avm

***
Search in your AVM.

#### Base Command

`octoxlabs-search-scroll-avm`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| size | Size. | Optional | 
| discovery_id | Specific Discovery Id. | Optional | 
| scroll_id | Specific Scroll Id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.ScrolledAVM.count | Number | Total vulnerabilities count. | 
| OctoxLabs.ScrolledAVM.scroll_id | String | Specific Scroll Id | 
| OctoxLabs.ScrolledAVM.results | Unknown | List Vulnerability information. | 

### octoxlabs-search-scroll-devices

***
Search in your devices.

#### Base Command

`octoxlabs-search-scroll-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| fields | Fields. | Optional | 
| size | Size. (Default: 50). | Optional | 
| discovery_id | Specific Discovery Id. | Optional | 
| scroll_id | Specific Scroll Id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.ScrolledDevices.count | Number | Total devices count. | 
| OctoxLabs.ScrolledDevices.scroll_id | String | Specific Scroll Id | 
| OctoxLabs.ScrolledDevices.results | Unknown | List Device information. | 

### octoxlabs-search-applications

***
Search in your Applications

#### Base Command

`octoxlabs-search-applications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| fields | Fields. | Optional | 
| page | Page. (Default: 1). | Optional | 
| size | Size. (Default: 50). | Optional | 
| discovery_id | Specific Discovery Id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.Applications.count | Number | Total applications count. | 
| OctoxLabs.Applications.results | Unknown | List Application information. | 

### octoxlabs-search-avm

***
Search in your AVM

#### Base Command

`octoxlabs-search-avm`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| fields | Fields. | Optional | 
| page | Page. (Default: 1). | Optional | 
| size | Size. (Default: 50). | Optional | 
| discovery_id | Specific Discovery Id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.AVM.count | Number | Total vulnerabilities count. | 
| OctoxLabs.AVM.results | Unknown | List Vulnerability information. | 

### octoxlabs-search-scroll-applications

***
Search in your applications.

#### Base Command

`octoxlabs-search-scroll-applications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| fields | Fields. | Optional | 
| size | Size. (Default: 50). | Optional | 
| discovery_id | Specific Discovery Id. | Optional | 
| scroll_id | Specific Scroll Id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.ScrolledApplications.count | Number | Total applications count. | 
| OctoxLabs.ScrolledApplications.scroll_id | String | Specific Scroll Id | 
| OctoxLabs.ScrolledApplications.results | Unknown | List Application information. | 

### octoxlabs-get-user-inventory-detail

***
Fetch your user.

#### Base Command

`octoxlabs-get-user-inventory-detail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Your user username. | Required | 
| discovery_id | Your device at specific discovery. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.UserInv | Unknown | &lt;Dict&gt; Octoxlabs User. | 

### octoxlabs-search-users-inventory

***
Search in your User Inventory.

#### Base Command

`octoxlabs-search-users-inventory`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| fields | Fields. | Optional | 
| page | Page. (Default: 1). | Optional | 
| size | Size. (Default: 50). | Optional | 
| discovery_id | Specific Discovery Id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OctoxLabs.UserInventory.count | Number | Total users count. | 
| OctoxLabs.UserInventory.results | Unknown | List User information. | 

