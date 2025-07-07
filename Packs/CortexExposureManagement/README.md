The **Cortex Exposure Management** pack is supported by the Exposure Management module of Cortex XSIAM.

[Cortex XSIAM](https://www.paloaltonetworks.com/cortex/cortex-xsiam) is a new approach to security operations that drives dramatically better security outcomes by closely integrating and automating the capabilities and processes of a modern security operations center (SOC). 

By leveraging the vulnerability detection capabilities present in many of the core and optional Cortex XSIAM add-ons, Cortex XSIAM is able to help organizations make sense of their vulnerability posture and take mitigating actions. 

This pack aims to further augment these platform capabilities by providing powerful automation content to aid in the enrichment and response of exposure issues, by providing playbooks and scripts to stitch together relevant investigation details such as the remediation owner and offer appropriate mitigation options to defenders.


## What does this pack do?

This pack contains all of the integrations, automations, and playbooks necessary to fully automate the investigation, remediation, verification, and reporting on ASM risks within Cortex Xpanse Expander and Cortex XSIAM. Currently our pack:

- Enriches services, assets, and alerts based on out-of-the-box integrations with sources like CMDBs, Cloud Service Providers, VM solutions, and more.
- Remediates RdpServer/SshServer Attack Surface Rules when present on AWS EC2 Instance.

## What is included in this pack?

The main Cortex Exposure Management playbook is the `Cortex EM - Exposure Issue` playbook. This playbook contains a set of sub-playbooks, which support many different remediation ownership paths that can be taken depending on the types of configured integrations and issue source.

- Playbooks
  - [Cortex EM - Exposure Issue](#cortex-em---exposure-issue)
  - [Cortex EM - ServiceNow CMDB](#cortex-em---servicenow-cmdb)
  - [Cortex EM - Remediation](#cortex-em---remediation)


### Playbooks

#### Cortex EM - Exposure Issue

A playbook that handles exposure issues by enriching assets to find potential asset owners.

![Cortex EM - Exposure Issue](doc_files/Cortex_EM_-_Exposure_Issue.png)

#### Cortex EM - ServiceNow CMDB

A playbook that when given provided indicators (IPs, Hostnames, FQDNs, etc.), enriches ServiceNow CMDB information relevant to exposure issues.

![Cortex EM - ServiceNow CMDB](doc_files/Cortex_EM_-_ServiceNow_CMDB.png)

#### Cortex EM - Remediation

A playbook handles remediation of exposure issues.

![Cortex EM - Remediation](doc_files/Cortex_EM_-_Remediation.png)
