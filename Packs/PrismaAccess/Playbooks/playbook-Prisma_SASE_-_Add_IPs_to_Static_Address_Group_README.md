This playbook appends a Static Address Group with provided IPs. 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Prisma SASE - Create Address Object

### Integrations

* PrismaSASE

### Scripts

This playbook does not use any scripts.

### Commands

* prisma-sase-address-group-list
* prisma-sase-candidate-config-push
* prisma-sase-address-group-update

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TSGID | Tenant services group ID. If not provided, the tsg_id integration parameter will be used as the default. |  | Optional |
| AutoCommit | Possible Values:<br/>True -&amp;gt; Will commit and push configuration.<br/>False -&amp;gt; Manual push will be required.<br/>Else --&amp;gt; Will ignore the push section and continue the playbook. |  | Optional |
| IP | A comma-separated list of IP addresses. |  | Optional |
| AddressGroupName | The address group name to be appanded. |  | Optional |
| Folder | The configuration folder group setting.<br/>The default value is 'Shared'. | Shared | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaSase.AddressGroup | The root context key for Prisma SASE integration output. | unknown |
| PrismaSase.AddressGroup.id | The address group ID. | unknown |
| PrismaSase.AddressGroup.name | The address group name. | unknown |
| PrismaSase.AddressGroup.description | The address group description. | unknown |
| PrismaSase.AddressGroup.addresses | The address group addresses. | unknown |
| PrismaSase.AddressGroup.dynamic_filter | The address group filter. | unknown |
| PrismaSase | The root context key for Prisma SASE integration output. | unknown |
| PrismaSase.Address | Created address object. | unknown |
| PrismaSase.Address.description | Address description. | unknown |
| PrismaSase.Address.folder | Address folder. | unknown |
| PrismaSase.Address.id | Address ID. | unknown |
| PrismaSase.Address.type | Address type. | unknown |
| PrismaSase.Address.address_value | Address value. | unknown |
| PrismaSase.Address.name | Address name. | unknown |
| PrismaSase.CandidateConfig | Configuration job object. | unknown |
| PrismaSase.CandidateConfig.job_id | Configuration job ID. | unknown |
| PrismaSase.CandidateConfig.result | The configuration push result, e.g. OK, FAIL. | unknown |
| PrismaSase.CandidateConfig.details | The configuration push details. | unknown |
| PrismaSase.AddressGroup.folder | The address group folder. | unknown |

## Playbook Image

---

![Prisma SASE - Add IPs to Static Address Group](../doc_files/Prisma_SASE_-_Add_IPs_to_Static_Address_Group.png)
