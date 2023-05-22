Parses the output from the !SSLVerifierV2 automation into a markdown table and separate context key . 

This automation uses the SSLVerifierV2 key by default, but a custom context key can be specified in the event extend-context is used with the SSLVerifierV2 automation. 

Option to specify whether to output certificates with an expiring, warning, or good status (or all at once). 

Option to specify whether or not to output the generated tables to the war room. 



## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| SSLVerifierKey | The key from context containing the SSLVerifier Data \(Defaults to SSLVerifier\) |
| StatusType | The status of certificate to extract \(good \(&amp;gt; 180 days\), warning \(&amp;lt;=180 days and &amp;gt; 90 days\), expiring \(&amp;lt;= 90 days\)\) |
| OutputToWarRoom | Output the resulting tables to the war room? Default: true |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SSLReport.Expiring | Certificates expiring in &amp;lt;= 90 days | unknown |
| SSLReport.Good | Certificates expiring in &amp;gt; 180 days | Unknown |
| SSLReport.Warning | Certificates expiring in &amp;gt; 90 days and &amp;lt;= 180 days | Unknown |
