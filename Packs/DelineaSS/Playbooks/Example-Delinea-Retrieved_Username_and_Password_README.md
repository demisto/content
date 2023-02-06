Example for usage integration REST API   for Delinea Secret Server. Methods retrieved username and password form secret.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Delinea

### Scripts
* PrintErrorEntry

### Commands
* delinea-secret-username-get
* delinea-secret-search-name
* delinea-secret-password-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| name | Secret name field for search credentials | ${incident.details} | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Delinea.Secret.Username | Retrived username from secret. | string |
| Delinea.Secret.Password | Retrived password from secret  | string |

## Playbook Image
---
There are no images for this playbook.