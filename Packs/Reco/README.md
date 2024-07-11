# Reco
Reco is an identity-first SaaS security solution. 
It empowers organizations with full visibility into every app, identity, and their actions to seamlessly prioritize and control risks in the SaaS ecosystem. Their AI-based graph technology connects in minutes and provides immediate value to security teams to continuously discover all SaaS applications including sanctioned and unsanctioned apps, associated identities from both humans and machines, their permission level, and actions. Reco uses advanced analytics around persona, actions, interactions and relationships to other users, and then alerts on exposure from misconfigurations, over-permission users, compromised accounts, and risky user behavior. This comprehensive picture is generated continuously using the Reco Identities Interaction Graph and empowers security teams to take swift action to effectively prioritize their most critical points of risk.
Reco helps organizations secure the identities and data of core SaaS applications including Salesforce, Microsoft 365 (including SharePoint, Teams, and OneDrive), Google Workspace, Workday, ServiceNow, Slack, Zoom, Okta, Monday.com, NetApp, Wiz, GitLab, Confluence, and Box.
The Reco and Palo Alto Networks Cortex XSOAR integration empower organizations to automate SaaS threat detection and remediation workflows for enhanced protection. Reco integrates with over 985 Cortex XSOAR content packs, the market’s leading SOAR platform. 


##### What does this pack do?
• Assess over 100 configuration rules unified across SaaS applications.  
• Access Reco data risk alerts
• Trigger automatic remediation flows to discover SaaS misconfigurations
• Seamlessly integrate alerts into Cortex XSOAR's incident management system
• Leverage prebuilt playbooks within Cortex XSOAR to automate the entire process of identifying and remediating SaaS misconfigurations and data exposure risks


#### Benefits to organizations: 
• Gain better visibility into potential SaaS misconfigurations and take proactive measures to mitigate them
• Streamline threat detection, automate remediation workflows, and fortify your organization's security posture.
• Investigate and respond to critical alerts promptly and effectively
• Reduce manual effort, accelerating incident response, and improving overall security posture 
• Enforce user-data centric security policies and embrace new SaaS applications at a faster rate
• Adhere to compliance requirements


#### Integrations
- Supported commands to query Reco platform:
- ***update-reco-incident-timeline*** - Update Reco incident timeline
- ***resolve-visibility-event*** - Resolve Reco visibility event
- ***reco-get-risky-users*** - Get risky users
- ***reco-add-risky-user-label*** - Add risky user
- ***reco-get-assets-user-has-access-to*** - Get assets user has access to (optional to get only sensitive assets)
- **reco-add-leaving-org-user-label** - Add leaving org user label in Reco
- **reco-get-sensitive-assets-by-name** - Get sensitive assets by name (optional to search by regex)
- **reco-get-sensitive-assets-by-id** - Get sensitive assets by file id
- **reco-get-files-shared-with-3rd-parties** - Get 3rd parties list with access to files
- **reco-get-3rd-parties-accessible-to-data-list** - Get files shared with 3rd parties
- **reco-get-sensitive-assets-with-public-link** - Get sensitive assets publicly exposed
- **reco-get-user-context-by-email-address** - Get user context by email address
- **reco-get-private-email-list-with-access** - Get private email list with access


For more information on Reco, please visit www.reco.ai
