IRONSCALES, a self-learning email security platform integration


## Configure Ironscales in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://appapi.ironscales.com) | True |
| API Key | True |
| Company Id | True |
| Scopes (e.g. "company.all") | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch incidents | False |
| Incident type | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ironscales-get-incident
***
Get incident data by ID.


#### Base Command

`ironscales-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 
| company_id | Company ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ironscales.Incident.incident_id | string | Incident id. | 
| Ironscales.Incident.attachments | string | Email attachments | 
| Ironscales.Incident.banner_displayed | string | Email banners. | 
| Ironscales.Incident.classification | string | Current classification\(FP,Phishing,Spam,Report\). | 
| Ironscales.Incident.company_id | string | Company ID. | 
| Ironscales.Incident.company_name | string | Company name. | 
| Ironscales.Incident.federation | string | Federation data. | 
| Ironscales.Incident.first_reported_by | string | First reporter. | 
| Ironscales.Incident.first_reported_date | string | Reported date. | 
| Ironscales.Incident.links | string | Links. | 
| Ironscales.Incident.mail_server | string | Mail server. | 
| Ironscales.Incident.reply_to | string | Reply to. | 
| Ironscales.Incident.reports | string | Reports data. | 
| Ironscales.Incident.sender_email | string | Sender email. | 
| Ironscales.Incident.sender_is_internal | boolean |  | 
| Ironscales.Incident.sender_reputation | string | Sender reputation. | 
| Ironscales.Incident.spf_result | unknown |  | 
| Ironscales.Incident.themis_proba | number | Themis proba. | 
| Ironscales.Incident.themis_verdict | string | Themis verdict. | 


### ironscales-classify-incident
***
Classify incident by ID.


#### Base Command

`ironscales-classify-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Optional | 
| classification | Classification. Possible values are: Attack, Spam, False Positive. | Optional | 
| prev_classification | Current incident classification. Possible values are: Attack, Spam, False Positive, Report. | Optional | 
| email | Your Email Address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ironscales.classifyincident | boolean | Classification succeeded | 


### ironscales-get-open-incidents
***
Get open incident ids.


#### Base Command

`ironscales-get-open-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ironscales.OpenIncidents.incident_ids | unknown | List of open incidents IDs. | 
