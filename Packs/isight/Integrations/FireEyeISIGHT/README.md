
### ip

***
basic search reports by ip

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | ip to search by. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 
| IP.Address | unknown | The IP address | 
| Report.ID | unknown | Report ID | 
| Report.title | unknown | Report title | 
| Report.publishDate | unknown | Report publish date | 
| Report.intelligenceType | unknown | Report intelligence type \(overview, vulnerability, malware, threat\) | 
### domain

***
basic search reports by domain.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | domain to search by. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 
| Domain.Name | unknown | The domain name. | 
| Report.ID | unknown | Report ID | 
| Report.title | unknown | Report title | 
| Report.publishDate | unknown | Report publish date | 
| Report.intelligenceType | unknown | Report intelligence type \(overview, vulnerability, malware, threat\) | 
### file

***
basic search file report by md5/sha1. NOTE - specify only one of md5/sha1 arguments

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | md5 or sha1 to search by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | unknown | The indicator we tested | 
| DBotScore.Type | unknown | The type of the indicator | 
| DBotScore.Vendor | unknown | Vendor used to calculate the score | 
| DBotScore.Score | unknown | The actual score | 
| Report.ID | unknown | Report ID | 
| Report.title | unknown | Report title | 
| Report.publishDate | unknown | Report publish date | 
| Report.intelligenceType | unknown | Report intelligence type \(overview, vulnerability, malware, threat\) | 
### isight-get-report

***
Get specific report

#### Base Command

`isight-get-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reportID | Report ID to search by. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Report.ID | unknown | Report ID | 
| Report.title | unknown | Report title | 
| Report.publishDate | unknown | Report publish date | 
| Report.intelligenceType | unknown | Report intelligence type \(overview, vulnerability, malware, threat\) | 
| Report.audience | unknown | Report audience | 
| Report.ThreatScape | unknown | Report threat scape | 
| Report.operatingSystems | unknown | Report operating systems | 
| Report.riskRating | unknown | Report risk rating | 
| Report.version | unknown | Report version | 
| Report.tagSection | unknown | Report tag section | 
### isight-submit-file

***
Submission of malware and other files for community sharing

#### Base Command

`isight-submit-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | entry-id of the file to submit (e.g. 41@18). | Required | 
| description | file description. | Required | 
| type | Type of the given file. Possible values are: malware, other. | Required | 

#### Context Output

There is no context output for this command.