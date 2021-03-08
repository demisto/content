USTA is an Cyber Intelligence Platform that responds directly and effectively to today's complex cyber threats. 
This integration was integrated and tested with version xx of USTA
## Configure USTA on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for USTA.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://usta.prodaft.com/api/) |  | True |
    | API Key | You can reach out your access token : https://usta.prodaft.com/\#/api-documents | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### usta-get-malicious-urls
***
You can get malicious URLs with this command


#### Base Command

`usta-get-malicious-urls`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Format type of the returned result. Possible values are: json, stix, stix2, txt. Default is json. | Optional | 
| url | Filtering by URL Address. | Optional | 
| is_domain | You can search only those with or without domain name registration. Possible values are: true, false. Default is true. | Optional | 
| url_type | Filtering by malicious type. | Optional | 
| tag | Filtering by tags. Example: tag=Keitaro. | Optional | 
| start | Starting date. | Optional | 
| end | End Date. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-get-malware-hashs
***
You can get malware hashs with this command


#### Base Command

`usta-get-malware-hashs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Format type of the returned result. Possible values are: json, stix, stix2. Default is json. | Optional | 
| md5 | Filtering by md5. | Optional | 
| sha1 | Filtering by sha1. | Optional | 
| tag | Filtering by tags. Example: tag=Keitaro. | Optional | 
| start | Starting Date. | Optional | 
| end | End Date. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-get-phishing-sites
***
You can get phishing sites with this command


#### Base Command

`usta-get-phishing-sites`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Filtering by status. Possible values are: open, close, in_progress, out_of_scope, passive. | Optional | 
| source | Filtering by source(URL). | Optional | 
| page | Paginiation. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-get-identity-leaks
***
With the Identity Leak API, you can access the hashed version of the credentials added to the platform.SHA256(MD5(Identity_Number))


#### Base Command

`usta-get-identity-leaks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | Staring Date. | Optional | 
| end | End Date. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-get-stolen-client-accounts
***
You can access stolen customer accounts via Stolen-Client-accounts API.


#### Base Command

`usta-get-stolen-client-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Filtering by username. | Optional | 
| password | Filtering by password. | Optional | 
| source | It allows to filter the stolen customer accounts detected according to the source.Available values : malware, phishing_site, data_leak, clients. Possible values are: malware, phishing_site, data_leak, clients. | Optional | 
| start | Starting Date. | Optional | 
| end | End Date. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-get-domain
***
If you want to get more detailed information about malicious domain names, you can use this command.


#### Base Command

`usta-get-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Search with domain name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-get-ip-address
***
If you want to get more detailed information about specific IP Address, you can use this command.


#### Base Command

`usta-get-ip-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | Search with IP Address. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-send-referrer-url
***
You can search about the accuracy of the urls referring to your company's websites.


#### Base Command

`usta-send-referrer-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | URL Value. Example: http://www.google3.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-search-specific-identity-leaks
***
With this command, you can search specific identity number that hashed in leaks 


#### Base Command

`usta-search-specific-identity-leaks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity_number | Search with this identity number. You can search all identity number with "," . | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### usta-close-incident
***
You can close the notifications in the status of "In Progress" or "Open", which are currently opened to your institution, via API.


#### Base Command

`usta-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Incident ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


