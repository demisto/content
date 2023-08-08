
### mxtoolbox

***
Run any supported command on the mxtoolbox API

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`mxtoolbox`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command | The command you want to execute. Possible values are: mx, a, dns, spf, txt, soa, ptr, blacklist, smtp, tcp, http, https, ping, trace. | Required | 
| data | The data to query. | Required | 
| additionalParams | Any additional query parameters you want to add. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MXToolbox.Passed | unknown | Successful results | 
| MXToolbox.Failed | unknown | Query failures | 
| MXToolbox.Errors | unknown | Query errors | 
| MXToolbox.Warnings | unknown | Warning for query | 
| MXToolbox.Information | unknown | Additional information regarding the query | 
| MXToolbox.MultiInformation | unknown | Additional multi-information | 
| MXToolbox.Transcript | unknown | Query transcript | 
