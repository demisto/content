Generates a certificate signing request for fulfillment by an organization certification authority (CA)

Output is the request.csr file placed directly into context under a "File" object. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, Certificates |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| cn | Cert Common Name \(Mandatory\) |
| email | Cert Owner Email Address |
| org | Cert Organization |
| orgUnit | Cert Organizational Unit |
| country | Cert Country |
| state | Cert State |
| locality | Cert Locality \(City\) |
| OutputToWarRoom | Output CSR text to war room? \(Default: False\) |

## Outputs
---
There are no outputs for this script.
