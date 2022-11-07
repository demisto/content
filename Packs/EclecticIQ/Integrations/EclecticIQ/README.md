Note: Support for this Pack will be moved to the Partner on NOV, 01, 2022
# EclecticIQ Cortex XSOAR User Manual
## Introduction
### EclecticIQ Platform
* EclecticIQ platform is a Threat Intelligence Platform (TIP) that sits at the center of an organization’s Cyber Threat Intelligence practice, collecting intelligence from open sources, commercial suppliers, and industry partnerships into a single workspace.
* Using EclecticIQ Platform, intelligence analysts can deliver actionable intelligence and support detection, prevention, and incident response through existing security infrastructure. This approach improves security operations and leadership through a comprehensive yet cost-effective system.
* EclecticIQ Platform is uniquely designed to improve an organization’s security posture and intelligence analysts' efficiency, speed, accuracy, and capacity, allowing organizations to continue operations unimpeded by cyber threats.

### EclecticIQ Cortex App
* Get the EIQ data in Cortex XSOAR by integrating both using API Key and URL of EclecticIQ.
* Using scripts
  * Create a command to get the lookup observables
  * Create a command to create observables 
  * Create a command to create sighting for EIQ data in the EIQ platform.

### Prerequisites
* EIQ will provide access to APIs 

### Installation of Cortex XSOAR
* For downloading the Cortex XSOAR fill up the partner form by using this link  [https://www.google.com/url?q=https://start.paloaltonetworks.com/sign-up-for-community-edition.html&sa=D&source=docs&ust=1661255332217603&usg=AOvVaw0bHAEbEMQbqeJs6EoiMi7I] and submit.
* In an email (from 	dbot@demisto.work), get an installation script and a free license will be sent by Palo Alto Networks.

##### Follow the below instructions after receiving the email
1. Run the chmod +x demisto.sh command to convert the .sh file to an executable file
2. Execute the .sh file, by running the following command-sudo ./demisto.sh 
3. Accept the EULA and add the information when prompted
    i. The Server HTTPS port (default is 443)
    ii. If you want to use Elasticsearch, enter the Elasticsearch details, such as the URL, timeout, etc
    iii. Type the name of the Admin user (default is admin)
    iv. Type the password (default is admin)
4. Confirm that the Cortex XSOAR server status is active, by running the command- systemctl status demisto
    i. f the server is not active, run the following command to start the server-systemctl start demisto 
    ii. Confirm that the Docker service status is active, by running the command- systemctl status docker
    iii. In a web browser, go to the https://serverURL:port to verify that Cortex XSOAR was successfully installed
5. Add the license when you open Cortex XSOAR for the first time

## Working
The user needs to perform the following after Cortex XSOAR installation.
#### Steps to upload the Integration
1. Login to Cortex XSOAR
![image](/Packs/EclecticIQ/doc_files/1.png)
2. Go to settings (left-hand side down corner) and click on it
3. Click on the Upload integration icon (right-hand side up corner) 
![image](/Packs/EclecticIQ/doc_files/2.png)
4. Select the file and it will be uploaded
5. Click on the Save icon (beside the Save Version button)
![image](/Packs/EclecticIQ/doc_files/3.png)

#### Steps to Add instance to the Integration
1. Login to Cortex XSOAR
2. Go to settings (left-hand side down corner) and click on it
3. Go to Integrations 
4. Search for the uploaded integration by entering the integration name in the given search field on the Settings page
![image](/Packs/EclecticIQ/doc_files/4.png)
5. Click on "Add instance" (right-hand side)
6. Pass the valid API key
![image](/Packs/EclecticIQ/doc_files/5.png)
7. Click on the "Test" button and get a success message
8. Click on the "Save & exit" button
![image](/Packs/EclecticIQ/doc_files/6.png)

#### Steps to create Incident
1. Login to Cortex XSOAR
2. Go to "Incidents" (left-hand side down) and click on it
3. Click on the "New Incident" button (right-hand side)
![image](/Packs/EclecticIQ/doc_files/7.png)
4. New Incident page will be displayed
5. Enter the Incident Name and required details
![image](/Packs/EclecticIQ/doc_files/8.png)
6. Click on the "Create New Incident" button

##  1. Command Line Interface(CLI)
### lookup observables
* For lookup observables, the user has to execute the lookup observables command in the CLI
* Below arguments will be passed along with the lookup observables command
  * Type:Type of value to search (ipv4,ipv6,domain,uri,email,hash-md5,hash-sha1,hash-sha256,hash-sha512)
  * Value: Value of the entity to search
* Once the command is executed,
  * If successful, the “Command executed successfully” message will be displayed in the war room with data, and the observables found will be added in the context of the incident
  * If unsuccessful, the failure message will be displayed in the war room
 

#### Steps to execute the lookup_observables command
1. Login to Cortex XSOAR
2. Go to "Incidents" (left-hand side down) and click on it
3. Click on the created Incident from the Table
![image](/Packs/EclecticIQ/doc_files/9.png)
4. Click on War room
![image](/Packs/EclecticIQ/doc_files/10.png)
5. Pass the command in CLI and press enter button
![image](/Packs/EclecticIQ/doc_files/11.png)
6. User gets the success message
7. Output Data will be stored in Context Data, to view the that click on a button(i.e, right shoulder button) that is beside the "Actions" button 
8. Click on "Context Data" to view the stored Output Data
![image](/Packs/EclecticIQ/doc_files/12.png)

## Command
```http
 lookup_observables
```
## 1.1 Get the reputation of an IP address observable
Gets the reputation of an IP address observable.
### Base command
```http
  ip
```

### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |IPv4 to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output
| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  ip ipv4=172.168.156.115
```
##### Human Readable Output
#### EclecticIQ observable reputation - 172.168.156.115 
|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`low`	|creationofsighting|	{'type': 'ipv4', 'value': '172.168.156.115, 'classification': 'low'}|   |   |	2022-08-25T04:50:56+00:00|sighting|

## 1.2 Get the reputation of an IP address observable
Gets the reputation of an IP address observable.

### Base command
```http
  ip
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |IPv6 to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output

| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  ip ipv6=2001:0000:3238:DFE1:0063:0000:0000:FEFB
```
##### Human Readable Output
#### EclecticIQ observable reputation - 2001:0000:3238:DFE1:0063:0000:0000:FEFB
|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`unknown`	|             |{'type': 'ipv6', 'value': '2001:0000:3238:DFE1:0063:0000:0000:FEFB', 'classification': 'low'}|   |   |	2022-08-19T06:56:40.755381+00:00|

## 1.3 Get the reputation of an email observable
Gets the reputation of an email observable.

### Base command
```http
  email
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |Email address observable to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output

| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  email email=abc@gmail.com
```
##### Human Readable Output
#### EclecticIQ observable reputation - abc@gmail.com
|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`medium`	|   Splunk created Sighting.  |{'type': 'email', 'value': 'abc@gmail.com', 'classification': 'unknown'}|   |   |	2022-07-26T18:00:58.623610+00:00| Sighting of : abc@gmail.com|

## 1.4 Get the reputation of a domain observable
Gets the reputation of a domain observable.

### Base command
```http
  domain
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |Domain observable to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output

| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  domain domain=abcd1.com
```
##### Human Readable Output
#### EclecticIQ observable reputation - abcd1.com

|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`unknown`	|     |{'type': 'domain', 'value': 'abcd1.com', 'classification': 'low'}|   |   |	2022-08-29T09:47:12.280914+00:00| |


## 1.5 Get the reputation of hash-md5 observable
Gets the reputation of hash-md5 observable.

### Base command
```http
   hash-md5
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   | hash-md5 observable to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output

| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  hash hash-md5=e5dadf6524624f79c3127e247f04b541
```
##### Human Readable Output
#### EclecticIQ observable reputation - e5dadf6524624f79c3127e247f04b541

|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`low`	| sighting    |{'type': 'hash-md5', 'value': 'e5dadf6524624f79c3127e247f04b541', 'classification': 'unknown'}|   |   |	2022-08-26T08:06:11+00:00| |

## 1.6 Get the reputation of hash-sha1 observable
Gets the reputation of hash-sha1 observable.

### Base command
```http
   hash-sha1
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   | hash-sha1 observable to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 

### Context Output

| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  hash hash-sha1=2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
```
##### Human Readable Output
#### EclecticIQ observable reputation - 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed

|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`unknown`	|    |{'type': 'hash-sha1', 'value': '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed', 'classification': 'medium'}|   |   |	2022-08-26T07:54:37.838123+00:00| |

## 1.7 Get the reputation of hash-sha256 observable
Gets the reputation of hash-sha256 observable.

### Base command
```http
   hash-sha256
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   | hash-sha256 observable to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output

| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  hash hash-sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```
##### Human Readable Output
#### EclecticIQ observable reputation - ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`unknown`	|    |{'type': 'hash-sha256', 'value': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'classification': 'medium'}|   |   |	2022-08-26T07:56:38.310292+00:00| |

## 1.8 Get the reputation of hash-sha512 observable
Gets the reputation of hash-sha512 observable.

### Base command
```http
   hash-sha512
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   | hash-sha512 observable to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output

| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  hash hash-sha512=3b7fc7cc370707c1df045c35342f3d64ea7076abd84f8a8c046a7cca2b85901689f3cf4bdc1f5fc232a60456cb9d2f48702bf8f8f1064f9bcc7d70edad9f860e
```
##### Human Readable Output
#### EclecticIQ observable reputation - 3b7fc7cc370707c1df045c35342f3d64ea7076abd84f8a8c046a7cca2b85901689f3cf4bdc1f5fc232a60456cb9d2f48702bf8f8f1064f9bcc7d70edad9f860e

|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`unknown`	|    |{'type': 'hash-sha512', 'value': '3b7fc7cc370707c1df045c35342f3d64ea7076abd84f8a8c046a7cca2b85901689f3cf4bdc1f5fc232a60456cb9d2f48702bf8f8f1064f9bcc7d70edad9f860e', 'classification': 'medium'}|   |   |2022-08-26T07:52:30.565542+00:00| |

## 1.9 Get the reputation of an uri observable
Gets the reputation of uri observable.

### Base command
```http
   uri
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   | uri observable to get the reputation of |
| `value`         | `string`       | Required   |  Value of the entity to search |
 
### Context Output
| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `EclecticIQ.Entity.ID`       | `string`     | EclecticIQ  Entity ID|
| `EclecticIQ.Entity.confidence`       | `string`     | EclecticIQ Entity confidence|
| `EclecticIQ.Entity.observables`       | `string`     | EclecticIQ Entity related observables|
| `EclecticIQ.Entity.threat_start_time`       | `date`     | EclecticIQ Threat start time|
| `EclecticIQ.Entity.title`       | `string`     | EclecticIQ Entity Title|

### Command example
```http
  uri uri=https://goo.com
```
##### Human Readable Output
#### EclecticIQ observable reputation - https://goo.com

|confidence	|description|	observables|	source_name|	tags	|threat_start_time|title| 
|:--------     |:-------     |------|------|---------|--------|------|
|`unknown`	|    |{'type': 'uri', 'value': 'https://goo.com', 'classification': 'medium'}|   |   |2022-08-29T10:36:18.733576+00:00| |

### Create Observable
* To create observables, the user has to execute the create observables command in the CLI
* Below arguments will be passed along with the create observables command
  * Types:Type of observable (ipv4,ipv6,domain,Uri,email,hash-md5,hash-sha1,hash-sha256,hash-sha512)
  * Value: Value of the observable
  * Maliciousness: Maliciousness of the observable unknown, safe, low, medium, high
* Once the command is executed,
  * If successful, the “observable created successfully” message will be displayed in the war room with data
  * If unsuccessful, the failure message will be displayed in the war room

#### Steps to execute the create_observable command
1. Login to Cortex XSOAR
2. Go to "Incidents" (left-hand side down) and click on it
3. Click on the created Incident from the Table
4. Click on War room
5. Pass the command in CLI and press enter button
![image](/Packs/EclecticIQ/doc_files/13.png)
6. User gets the success message
7. Output Data will be stored in Context Data, to view the that click on a button(i.e, right shoulder button) that is beside the "Actions" button 
8. Click on "Context Data" to view the stored Output Data
![image](/Packs/EclecticIQ/doc_files/14.png)

### Base command
```http
  create_observable
```

### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |Type of the observable from (ipv4,ipv6,domain,uri,email,hash-md5,hash-sha1,hash-sha256,hash-sha512) |
| `value`         | `string`       | Required   | Value of the type of observable |
|`maliciousness`|        `string`  |Required  | Maliciousness of the observable from (unknown, safe, low, medium, high)|
 
### Context Output
| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `Observable.data.created_at`       | `date`     | Observable creation date|
| `Observable.data.id`      | `string`     | EclecticIQ  Entity ID|
| `Observable.data.last_updated_at` | `date`    |Observable last updated date|
| `Observable.data.maliciousness`       | `string`     | Maliciousness confidence level|
| `Observable.data.type`        | `string`     | Type of observable|
| `Observable.data.value`  |`string`| Value of the observable|

### Command example
```http
  ip ipv4=172.168.156.115
```
##### Human Readable Output
#### Observables created successfully…!!
|confidence	|description|
| :--------     | :-------     |
|`maliciousness`	|low|
|`type`|	ipv4|
|`value`|	172.168.156.115|

### Create Sighting
* For create sighting, the user has to execute the create sighting command in the CLI 
* Below arguments will be passed along with the create sighting command
  * Type:Type of the sighting (ipv4,ipv6,domain,Uri,email,hash-md5,hash-sha1,hash-sha256,hash-sha512)
  * Value: Value of the sighting
  * Title: Title of the sighting 
  * Description: Description of the sighting
  * Confidence: Confidence of the sighting from low, high, medium, unknown
  * Tags: Tags attached with the sighting
* Once the command is executed to create sightings,
  * If successful, the “sighting created successfully” message will be displayed in the war room with data
  * If unsuccessful, then the failure message will be displayed in the war room

#### Steps to execute the create_sighting command
1. Login to Cortex XSOAR
2. Go to "Incidents" (left-hand side) and click on it
3. Click on the created Incident from the Table
4. Click on War room
5. Pass the command in CLI and press enter button
![image](/Packs/EclecticIQ/doc_files/15.png)
6. User gets the success message
7. Output Data will be stored in Context Data, to view the that click on a button(i.e, right shoulder button) that is beside the "Actions" button 
8. Click on "Context Data" to view the stored Output Data
![image](/Packs/EclecticIQ/doc_files/16.png)

### Base command
```http
  create_sighting
```
### Input
| Argument Name |Type            | Required   | Description | 
| :--------     | :-------       | :----------|--------     | 
| `type`        | `string`       | Required   |Type of the sighting from (ipv4,ipv6,domain,uri,email,hash-md5,hash-sha1,hash-sha256,hash-sha512) |
| `value`         | `string`       | Required   | Value of the sighting  |
|`title`|        `string`  |Required  | Title of the sighting |
|`description`| `string`|Required|Description of the sighting|
|`Confidence`|`string`|Required| Confidence of the sighting from (low,high,medium,unknown)|
|`Tags`|`string`|Required| tags attached with the sighting|
 
### Context Output
| Path          |  Type        | Description      |
| :--------     | :-------     |------|
| `Sighting.data.created_at`       | `date`     | Observable creation date|
| `Sighting.data.estimated_threat_start_time`      | `string`     | EclecticIQ  Entity ID|
| `Sighting.data.last_updated_at` | `date`    |Observable last updated date|
| `Sighting.data.title`       | `string`     | Maliciousness confidence level|

### Command example
```http
  ip ipv4=172.168.156.115
```
##### Human Readable Output
#### !sighting created for- 172.168.156.115
|confidence	|description|
| :--------     | :-------     |
|`Type`	|ipv4  |
|`confidence_level`| low|
|`description`|	creationofsighting|
|`tags`|	XSOARsighting|
|`title`|	sighting|
|`value`|	172.168.156.115|

##  2. Playbook
### lookup observables
#### Steps to create the Playbook for lookup_observables
1. Login to Cortex XSOAR
2. Go to Playbook (left-hand side) and click on  it
3. Click on the New Playbook button (right-hand side up corner)
![image](/Packs/EclecticIQ/doc_files/17.png)
4. Enter the Playbook Name and click on Save
![image](/Packs/EclecticIQ/doc_files/18.png)
5. Go to EclecticIQ and expand it (which is displayed under Task Library-Automation)
![image](/Packs/EclecticIQ/doc_files/19.png)
6. Click on the "Add" button to add the lookup observables command to Playbook
![image](/Packs/EclecticIQ/doc_files/20.png)
7. Pass the inputs: type and value
![image](/Packs/EclecticIQ/doc_files/21.png)
8. Click on Ok
9. Connect "Playbook Triggered" to the "lookup_observables" task
10. Click on "Save Playbook"
![image](/Packs/EclecticIQ/doc_files/22.png)
11. Go to "Incidents" (left-hand side) and click on it
12. Click on the created Incident from the Table
13. Click on Work Plan
14. Search the Playbook from the Default dropdown and click on that
![image](/Packs/EclecticIQ/doc_files/23.png)
15. Click on the "Yes I know what I am doing" button
![image](/Packs/EclecticIQ/doc_files/24.png)
16. Playbook will Run and user gets a success message
![image](/Packs/EclecticIQ/doc_files/25.png)
17. Click on a button(i.e, right shoulder button) that is beside the "Actions" button 
![image](/Packs/EclecticIQ/doc_files/26.png)
18. Click on "Context Data" to view the output of the Playbook
![image](/Packs/EclecticIQ/doc_files/27.png)

### Create Observable
#### Steps to create the Playbook for create_observable
1. Login to Cortex XSOAR
2. Go to Playbook (left-hand side) and click on  it
3. Click on the New Playbook button (right-hand side up corner)
4. Enter the Playbook Name and click on Save
5. Go to EclecticIQ and expand it (which is displayed under Task Library-Automation)
6. Click on the "Add" button to add the Create Observable command to Playbook
7. Pass the inputs: type, value, and maliciousness
8. Click on Ok
9. Connect "Playbook Triggered" to "cretae_observable" task
10. Click on "Save Playbook"
11. Go to "Incidents" (left-hand side) and click on it
12. Click on the created Incident from the Table
13. Click on Work Plan
14. Search the Playbook from the Default dropdown
15. Click on the "Yes I know what I am doing" button
16. Playbook will Run and get a success message
![image](/Packs/EclecticIQ/doc_files/28.png)
17. Click on a button(i.e, right shoulder button) that is beside the "Actions" button 
![image](/Packs/EclecticIQ/doc_files/29.png)
18. Click on "Context Data" to view the output of the Playbook
![image](/Packs/EclecticIQ/doc_files/30.png)

### Create Sighting
#### Steps to create the Playbook for create_sighting
1. Login to Cortex XSOAR
2. Go to Playbook (left-hand side) and click on  it
3. Click on the New Playbook button (right-hand side up corner)
4. Enter the Playbook Name and click on Save
5. Go to EclecticIQ and expand it (which is displayed under Task Library-Automation)
6. Click on the "Add" button to add the Create Sighting command to Playbook
7. Pass the inputs:value,description,title,tags,type and confidence_level
![image](/Packs/EclecticIQ/doc_files/31.png)
8. Click on Ok
9. Connect "Playbook Triggered" to the "create_sighting" task
10. Click on "Save Playbook"
![image](/Packs/EclecticIQ/doc_files/32.png)
11. Go to "Incidents" (left-hand side) and click on it
12. Click on the created Incident from the Table
13. Click on Work Plan
14. Search the Playbook from the Default dropdown
15. Click on the "Yes I know what I am doing" button
16. Playbook will Run and get a success message
![image](/Packs/EclecticIQ/doc_files/33.png)
17. Click on a button(i.e, right shoulder button) that is beside the "Actions" button 
18. Click on "Context Data" to view the output of the Playbook
![image](/Packs/EclecticIQ/doc_files/34.png)
