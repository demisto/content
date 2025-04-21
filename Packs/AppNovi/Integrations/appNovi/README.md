Search across meshed network, security, and business data in appNovi to make efficient informed security decisions for risk management and incident response. Gain immediate intelligence on assets, visualize risk and threats across your network, and undertake interactive investigations across the network to reduce MTTR for incident response. 

This integration was integrated and tested with appNovi v2.0

## Configure appNovi in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Full URL of appNovi instance API. |  | True |
| API Token | appNovi token URL for authentication | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### search-appnovi-components
***
Search for Components by name or value


#### Base Command

`search-appnovi-components`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | The string to use to search for Components. | Required | 
| max_results | Number of results. Default is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| appnovi.components.name | String | Name of thing | 
| appnovi.components.coll | String | Collection containing thing | 
| appnovi.components.u._id | String | appNovi Database ID. | 
| appnovi.components.u._key | String | appNovi Database Key. | 
| appnovi.components.u.identity.company | String | Company ID | 
| appnovi.components.u.identity.type | String | Thing type | 
| appnovi.components.u.identity.value | String | Thing name | 
| appnovi.components.u.identity.datacenter | String | Datacenter ID | 
| appnovi.components.u.identity.domain | String | Domain ID | 
| appnovi.components.u.lastSeen | Date | Time thing was last seen. | 
| appnovi.components.u.source | Date | This is information about the source of the entity. | 
| appnovi.components.u.userProperties | String | These are the custom properties of the entity. | 
| appnovi.components.connections | Number | Number of connections. | 
| appnovi.time | Number | Query time \(for diagnostics\) | 

### search-appnovi-connected
***
Search for Components connected to supplied identity


#### Base Command

`search-appnovi-connected`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | appNovi identifier key-value or use key "_id" when searching via appNovi ID. | Required | 
| category | Optional category of components to return. Possible values are: BaseComponent, Identity, IPAddress, Interface, Server, Storage, Hypervisor, CloudInfra, CloudService, NetworkInfra, Cluster, Container, MessageQueue, Vulnerability, CVE, Employee, Client, Software, Policy, Databases. | Optional | 
| type | Optional type of components to return. Possible values are: genericcomponent, genericmetadata, rdns, user, machine, iamrole, iamuser, ip, ipv4, ipv6, mac, eni, interface, vmwarevm, ec2, azurevm, vm, server, physical, s3, datastore, bucket, storage, esx, vcenter, hypervisor, vpc, subscription, account, resourcegroup, region, availabilityzone, autoscalinggroup, elasticloadbalancer, org, folder, project, vnet, rds, ecr, lambda, redshift, dynamodbtable, router, firewall, switch, loadbalancer, proxy, middleware, kubernetes, aks, eks, swarm, mesos, nomad, docker, containerd, messagetopic, messageserver, vulnerability, cve, employee, contractor, desktop, laptop, pc, vdi, mobile, client, software, ami, securitygroup, iampolicy, column, database, table, view. | Optional | 
| max_results | Number of results. Default is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| appnovi._key | String | appNovi database key | 
| appnovi._id | String | appNovi database ID. | 
| appnovi.category | String | appNovi Category \(e.g. Interface, Server\) | 
| appnovi.firstSeen | Date | When was this Thing first seen? | 
| appnovi.identity.company | String | Company ID | 
| appnovi.identity.datacenter | String | Datacenter ID | 
| appnovi.identity.domain | String | Domain ID | 
| appnovi.identity.type | String | Thing type | 
| appnovi.identity.value | String | Identity value | 
| appnovi.lastSeen | Date | Last time thing was seen | 
| appnovi.name | String | Name of entity. | 
| appnovi.source | Unknown | This is information about the source of the entity. | 
| appnovi.userProperties | String | These are the custom properties of the entity. | 
| appnovi.applications | String | List of applications | 

### search-appnovi-cve
***
Search for servers with matching CVE


#### Base Command

`search-appnovi-cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | CVE e.g. "CVE-2017-0143". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| appnovi._key | String | appNovi database key | 
| appnovi._id | String | appNovi database ID. | 
| appnovi.category | String | appNovi Category \(e.g. Interface, Server\) | 
| appnovi.firstSeen | Date | When was this Thing first seen? | 
| appnovi.identity.company | String | Company ID | 
| appnovi.identity.datacenter | String | Datacenter ID | 
| appnovi.identity.domain | String | Domain ID | 
| appnovi.identity.type | String | Thing type | 
| appnovi.identity.value | String | Identity value | 
| appnovi.lastSeen | Date | Last time thing was seen | 
| appnovi.name | String | Name of entity. | 
| appnovi.source | Unknown | This is information about the source of the entity. | 
| appnovi.userProperties | String | These are the custom properties of the entity. | 
| appnovi.applications | String | List of applications | 

### search-appnovi-component-property
***
Search for Components by property and value


#### Base Command

`search-appnovi-component-property`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| property | Name of property. | Required | 
| value | Value of property. | Required | 
| max_results | Number of results. Default is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| appnovi.components.name | String | Name of thing | 
| appnovi.components.coll | String | Collection containing thing | 
| appnovi.components.u._id | String | appNovi Database ID. | 
| appnovi.components.u._key | String | appNovi Database Key. | 
| appnovi.components.u.identity.company | String | Company ID | 
| appnovi.components.u.identity.type | String | Thing type | 
| appnovi.components.u.identity.value | String | Thing name | 
| appnovi.components.u.identity.datacenter | String | Datacenter ID | 
| appnovi.components.u.identity.domain | String | Domain ID | 
| appnovi.components.u.lastSeen | Date | Time thing was last seen. | 
| appnovi.components.u.source | Date | This is information about the source of the entity. | 
| appnovi.components.u.userProperties | String | These are the custom properties of the entity. | 
| appnovi.components.connections | Number | Number of connections. | 
| appnovi.time | Number | Query time \(for diagnostics\) | 

### search-appnovi-server-by-ip
***
Search for servers using IP address


#### Base Command

`search-appnovi-server-by-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Server IP to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| appnovi._key | String | appNovi database key | 
| appnovi._id | String | appNovi database ID. | 
| appnovi.category | String | appNovi Category \(e.g. Interface, Server\) | 
| appnovi.firstSeen | Date | When was this Thing first seen? | 
| appnovi.identity.company | String | Company ID | 
| appnovi.identity.datacenter | String | Datacenter ID | 
| appnovi.identity.domain | String | Domain ID | 
| appnovi.identity.type | String | Thing type | 
| appnovi.identity.value | String | Identity value | 
| appnovi.lastSeen | Date | Last time thing was seen | 
| appnovi.name | String | Name of entity. | 
| appnovi.source | Unknown | This is information about the source of the entity. | 
| appnovi.userProperties | String | These are the custom properties of the entity. | 
| appnovi.applications | String | List of applications | 