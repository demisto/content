This playbook enriches ServiceNow CMDB data related to exposure issues by using provided indicators such as IPs, hostnames, and FQDNs.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* ServiceNow CMDB Search

### Integrations

* ServiceNow v2

### Scripts

* ContextSetup

### Commands

* servicenow-query-users

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IPv4 | IPv4 address |  | Optional |
| IPv6 | IPv6 address |  | Optional |
| HostName | Hostname |  | Optional |
| FQDN | Fully Qualified Domain Name |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| vmassetownerunrankedraw | potential asset/remediation owners | unknown |

## Playbook Image

---

![Cortex EM - ServiceNow CMDB](../doc_files/Cortex_EM_-_ServiceNow_CMDB.png)
