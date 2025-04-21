Use the Inventa integration to generate DSAR reports within Inventa instance and retrieve DSAR data for the XSOAR
This integration was integrated and tested with version 2.8.0 of Inventa

## Configure 1Touch.io's Inventa Connector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your Inventa server URL |  | True |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### inventa-get-datasubjects
***
Get Data Subject full details


#### Base Command

`inventa-get-datasubjects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| national_id | National ID of a PII. | Optional | 
| passport_number | Passport Number of a PII. | Optional | 
| driver_license | Driver's License of a PII. | Optional | 
| tax_id | Tax ID of a PII. | Optional | 
| cc_number | Credit Card Number of a PII. | Optional | 
| given_name | Given Name of a PII. | Optional | 
| surname | Surname of a PII. | Optional | 
| full_name | Full Name of a PII. | Optional | 
| vehicle_number | Vehicle Number of a PII. | Optional | 
| phone_number | Phone Number of a PII. | Optional | 
| birthday | Birthday of a PII. | Optional | 
| city | City of Resdence of a PII. | Optional | 
| street_address | Street Address of a PII. | Optional | 
Please note that all the arguments are optional, but they form a constraint which determines extraction of the right PII. 
Following combinations are treated as constraints:
* national_id
* passport_number
* driver_license
* tax_id
* cc_number
* given_name + vehicle_number
* given_name + phone_number
* given_name + surname + birthday
* given_name + surname + city + street_address
* full_name + birthday
* full_name + city + street_address


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DataSubjects.dataSubjects.id | String | ID of a Data Subject | 
| Inventa.DataSubjects.dataSubjects.piis.id | String | ID of an Entity Type for the PII | 
| Inventa.DataSubjects.dataSubjects.piis.piiEntityType | String | Entity Type name for the PII | 
| Inventa.DataSubjects.dataSubjects.piis.piiEntityValue | String | Value of an Entity Type for the PII | 
| Inventa.DataSubjects.dataSubjects.piis.piiEntityValueNew | String | New Value of an Entity Type for the PII | 
| Inventa.DataSubjects.dataSubjects.piis.action | String | Action of an Entity Type for the PII | 
| Inventa.DataSubjects.total | String | Total number of PII Entities found for the PII | 


#### Command Examples
```
!inventa-get-datasubjects national_id=12345678
!inventa-get-datasubjects passport_number=AB123456
!inventa-get-datasubjects driver_license=DL456789
!inventa-get-datasubjects tax_id=1234567890
!inventa-get-datasubjects cc_number=1234567890123456
!inventa-get-datasubjects given_name=john vehicle_number=AB456CD
!inventa-get-datasubjects given_name=john phone_number=1234567890
!inventa-get-datasubjects given_name=john surname=smith birthday=01/20/86
!inventa-get-datasubjects given_name=john surname=smith city=vancouver street_address="main square 1"
!inventa-get-datasubjects full_name="john smith" birthday=01/20/86
!inventa-get-datasubjects full_name="john smith" city=vancouver street_address="main square 1"
 ```







### inventa-get-sources
***
Retrieves data sources' details containing info about data subject


#### Base Command

`inventa-get-sources`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datasubject_id | ID of a datasubject within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.Sources.sources.id | String | Id of a source containing info about data subject |
| Inventa.Sources.sources.applianceName | String | Data sources conteining info related to a PII |
| Inventa.Sources.sources.timestamp | String | Timestamp of a source containing info about data subject |
| Inventa.Sources.sources.keyType | String | KeyType of a source containing info about data subject |
| Inventa.Sources.sources.path | String | Path of a source containing info about data subject |
| Inventa.Sources.sources.url | String | URL of a source containing info about data subject |
| Inventa.Sources.sources.hostname | String | Hostname of a source containing info about data subject |
| Inventa.Sources.sources.dbName | String | DB name of a source containing info about data subject |
| Inventa.Sources.sources.vendor | String | Vendor of a source containing info about data subject |
| Inventa.Sources.sources.type | String | Type of a source containing info about data subject |
| Inventa.Sources.sources.context | String | Additional info on a source containing info about data subject |
| Inventa.Sources.sources.entityTypes | String | Types of sensitive data stored in a source containing info about data subject |


#### Command Example
```!inventa-get-sources datasubject_id=123asd123```



### inventa-get-sources-piis
***
Retrieves PII entities stored in data sources related to datasubject


#### Base Command

`inventa-get-sources-piis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datasubject_id | ID of a datasubject within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.Sources.piis | String | PII entity types in sources |  


#### Command Example
```!inventa-get-sources-piis datasubject_id=123asd123```




### inventa-get-dsar-transactions
***
Retrieves data transactions' details containing info about data subject


#### Base Command

`inventa-get-dsar-transactions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | ID of a DSAR ticket within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DSAR.Transactions.transactions | String | List of data transactions | 


#### Command Example
```!inventa-get-dsar-transactions ticket_id=3```




### inventa-get-dsar-files
***
Retrieves details of files contatining info about data subject


#### Base Command

`inventa-get-dsar-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | ID of a DSAR ticket within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DSAR.Files.files | String | List of files containing info about data subject | 


#### Command Example
```!inventa-get-dsar-files ticket_id=3```




### inventa-get-dsar-databases
***
Retrieves list of databases and tables containing info about data subject


#### Base Command

`inventa-get-dsar-databases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | ID of a DSAR ticket within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DSAR.DataBases.databases | String | List of datatables containing info about data subject | 


#### Command Example
```!inventa-get-dsar-databases ticket_id=3```




### inventa-get-datasubject-details
***
Get datasubject name and email


#### Base Command

`inventa-get-datasubject-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | ID of a DSAR ticket within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DataSubject.name | String | Name of a data subject | 
| Inventa.DataSubject.email | String | Email address of a data subject | 


#### Command Example
```!inventa-get-datasubject-details ticket_id = 3```




### inventa-get-dsar-dataassets
***
Retrieves list of data assets containing info about data subject


#### Base Command

`inventa-get-dsar-dataassets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | ID of a DSAR ticket within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DSAR.DataAssets.dataAssets | String | List of data assets containing info about data subject | 


#### Command Example
```inventa-get-dsar-dataassets ticket_id=3```




### inventa-get-dsar-piis
***
Get list of PII categories related to the data subject


#### Base Command

`inventa-get-dsar-piis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | ID of a DSAR ticket within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DSAR.piis | String | List of PII categories related to data subject | 


#### Command Example
```!inventa-get-dsar-piis ticket_id=3```




### inventa-get-entities
***
Retrieves list of PII entities described in Inventa


#### Base Command

`inventa-get-entities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.Entities.entity | String | List of PII entities described in Inventa | 


#### Command Example
```!inventa-get-entities```




### inventa-get-datasubject-id-from-ticket
***
Retrieves ID of a data subject from Inventa's DSAR ticket


#### Base Command

`inventa-get-datasubject-id-from-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | ID of a DSAR ticket within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DataSubjects.datasubject_id | String | ID of a data subject within Inventa | 


#### Command Example
```!inventa-get-datasubject-id-from-ticket ticket_id=3```




### inventa-get-datasubject-id
***
Retrieves ID of a data subject from passed constraints


#### Base Command

`inventa-get-datasubject-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| national_id | National ID of a PII. | Optional | 
| passport_number | Passport Number of a PII. | Optional | 
| driver_license | Driver's License of a PII. | Optional | 
| tax_id | Tax ID of a PII. | Optional | 
| cc_number | Credit Card Number of a PII. | Optional | 
| given_name | Given Name of a PII. | Optional | 
| surname | Surname of a PII. | Optional | 
| full_name | Full Name of a PII. | Optional | 
| vehicle_number | Vehicle Number of a PII. | Optional | 
| phone_number | Phone Number of a PII. | Optional | 
| birthday | Birthday of a PII. | Optional | 
| city | City of Resdence of a PII. | Optional | 
| street_address | Street Address of a PII. | Optional | 
Please note that all the arguments are optional, but they form a constraint which determines extraction of the right PII. 
Following combinations are treated as constraints:
* national_id
* passport_number
* driver_license
* tax_id
* cc_number
* given_name + vehicle_number
* given_name + phone_number
* given_name + surname + birthday
* given_name + surname + city + street_address
* full_name + birthday
* full_name + city + street_address

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DataSubjects.datasubject_id | String | ID of a data subject within Inventa | 


#### Command Example
```
!inventa-get-datasubjects national_id=12345678
!inventa-get-datasubjects passport_number=AB123456
!inventa-get-datasubjects driver_license=DL456789
!inventa-get-datasubjects tax_id=1234567890
!inventa-get-datasubjects cc_number=1234567890123456
!inventa-get-datasubjects given_name=john vehicle_number=AB456CD
!inventa-get-datasubjects given_name=john phone_number=1234567890
!inventa-get-datasubjects given_name=john surname=smith birthday=01/20/86
!inventa-get-datasubjects given_name=john surname=smith city=vancouver street_address="main square 1"
!inventa-get-datasubjects full_name="john smith" birthday=01/20/86
!inventa-get-datasubjects full_name="john smith" city=vancouver street_address="main square 1"
```




### inventa-create-ticket
***
Creates Inventa ticket


#### Base Command

`inventa-create-ticket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reason | Reason for DSAR report. | Required | 
| datasubject_id | ID of a data subject within Inventa. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.DataSubjects.Ticket.ticket_id | String | ID of a DSAR ticket, created within Inventa | 


#### Command Example
```!inventa-create-ticket reason="test reason" datasubject_id=123asd456789```





### inventa-validate-incident-inputs
***
Validates Incident inputs


#### Base Command

`inventa-validate-incident-inputs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Inventa.Incident.validated | Boolean | Whether inputs are valid | 


#### Command Example
```!inventa-validate-incident-inputs```


